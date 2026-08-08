from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mac_overrides.phone_risk_runtime import PhoneRiskStore, account_fingerprint


class PhoneRiskStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "phone_risk_markers.json"
        self.clock = 1000.0
        self.store = PhoneRiskStore(
            self.path,
            now_fn=lambda: self.clock,
            quarantine_threshold=3,
            quarantine_seconds=60,
            isolation_threshold=6,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_marker_persists_by_hash_across_store_recreation(self):
        email = "Risk.User@Example.test"
        first = self.store.mark(
            email,
            reason_code="oauth_session_invalid",
            stage="phone_submitting",
        )

        recreated = PhoneRiskStore(self.path, now_fn=lambda: self.clock)
        persisted = recreated.status(email.lower())
        raw = self.path.read_text(encoding="utf-8")

        self.assertTrue(first["active"])
        self.assertEqual(persisted["count"], 1)
        self.assertIn(account_fingerprint(email), raw)
        self.assertNotIn(email.lower(), raw.lower())
        self.assertNotIn("Risk.User", raw)

    def test_repeated_marker_keeps_first_time_and_updates_latest_reason(self):
        self.store.mark("user@example.test", reason_code="oauth_session_invalid")
        self.clock = 1010.0
        row = self.store.mark(
            "user@example.test",
            reason_code="phone_flow_mfa_regressed",
            stage="sms_verifying",
        )

        self.assertEqual(row["count"], 2)
        self.assertEqual(row["first_at"], 1000.0)
        self.assertEqual(row["last_at"], 1010.0)
        self.assertEqual(row["reason_code"], "phone_flow_mfa_regressed")
        self.assertEqual(row["stage"], "sms_verifying")

    def test_clear_preserves_history_but_disables_retry_mode(self):
        self.store.mark("user@example.test")
        self.clock = 1030.0
        cleared = self.store.clear("user@example.test")

        self.assertFalse(cleared["active"])
        self.assertEqual(cleared["cleared_at"], 1030.0)
        self.assertFalse(self.store.is_active("user@example.test"))
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(len(payload["items"]), 1)

    def test_malformed_rows_and_unknown_fields_are_not_republished(self):
        email = "safe@example.test"
        fingerprint = account_fingerprint(email)
        self.path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "items": {
                        "plain@example.test": {"password": "mailbox-secret"},
                        fingerprint: {
                            "active": "false",
                            "reason_code": "oauth_session_invalid private-token",
                            "count": "not-a-number",
                            "first_at": "invalid",
                            "last_at": -1,
                            "stage": "phone_submitting?oauth=private-state",
                            "phone": "+15550001111",
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        status = self.store.status(email)
        self.store.mark(email, reason_code="oauth_session_invalid", stage="sms_verifying")
        persisted = self.path.read_text(encoding="utf-8")

        self.assertFalse(status["active"])
        self.assertEqual(status["count"], 0)
        self.assertEqual(status["reason_code"], "auth_session_invalid")
        self.assertEqual(status["stage"], "phone_submitting")
        self.assertNotIn("plain@example.test", persisted)
        self.assertNotIn("mailbox-secret", persisted)
        self.assertNotIn("private-token", persisted)
        self.assertNotIn("private-state", persisted)
        self.assertNotIn("+15550001111", persisted)
        payload = json.loads(persisted)
        self.assertEqual(set(payload["items"]), {fingerprint})
        self.assertEqual(
            set(payload["items"][fingerprint]),
            {
                "active",
                "reason_code",
                "count",
                "first_at",
                "last_at",
                "stage",
            },
        )

    def test_threshold_quarantines_before_the_next_paid_sms_allocation(self):
        email = "quarantine@example.test"

        first = self.store.mark(email)
        second = self.store.mark(email)
        self.assertFalse(first["blocked"])
        self.assertFalse(second["blocked"])

        self.clock = 1010.0
        third = self.store.mark(email, stage="sms_verifying")

        self.assertTrue(third["blocked"])
        self.assertTrue(third["quarantined"])
        self.assertFalse(third["isolated"])
        self.assertFalse(third["sms_allowed"])
        self.assertEqual(third["blocked_until"], 1070.0)
        self.assertTrue(self.store.should_skip_sms(email))
        self.assertEqual(self.store.status(email)["cooldown_remaining"], 60)

        self.clock = 1070.0
        expired = self.store.decision(email)
        self.assertFalse(expired["blocked"])
        self.assertFalse(expired["quarantined"])
        self.assertTrue(expired["sms_allowed"])

    def test_quarantine_is_rearmed_when_a_new_failure_arrives_after_cooldown(self):
        email = "rearm@example.test"
        for _ in range(3):
            self.store.mark(email)
        self.clock = 1061.0
        self.assertFalse(self.store.should_skip_sms(email))

        row = self.store.mark(email)

        self.assertEqual(row["count"], 4)
        self.assertTrue(row["quarantined"])
        self.assertEqual(row["blocked_until"], 1121.0)

    def test_hard_threshold_isolates_even_after_cooldown(self):
        email = "isolated@example.test"
        for _ in range(6):
            row = self.store.mark(email)

        self.assertTrue(row["isolated"])
        self.assertTrue(row["blocked"])
        self.assertEqual(row["cooldown_remaining"], 0)

        self.clock = 10_000.0
        still_isolated = self.store.decision(email)
        self.assertTrue(still_isolated["isolated"])
        self.assertTrue(still_isolated["blocked"])
        self.assertTrue(self.store.should_skip_sms(email))

        cleared = self.store.clear(email)
        self.assertFalse(cleared["active"])
        self.assertFalse(cleared["isolated"])
        self.assertFalse(self.store.should_skip_sms(email))

    def test_legacy_high_count_row_is_isolated_without_requiring_migration(self):
        email = "legacy-risk@example.test"
        fingerprint = account_fingerprint(email)
        self.path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "items": {
                        fingerprint: {
                            "active": True,
                            "reason_code": "oauth_session_invalid",
                            "count": 15,
                            "first_at": 100.0,
                            "last_at": 990.0,
                            "stage": "phone_submitting",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        status = self.store.status(email)

        self.assertTrue(status["active"])
        self.assertTrue(status["isolated"])
        self.assertTrue(status["blocked"])
        self.assertFalse(status["sms_allowed"])
        self.assertTrue(self.store.should_skip_sms(email))

        # Merely reading an old file must not rewrite it or expose the email.
        raw = self.path.read_text(encoding="utf-8")
        self.assertIn(fingerprint, raw)
        self.assertNotIn(email, raw)
        self.assertNotIn("blocked_until", raw)

    def test_policy_fields_are_sanitized_and_secrets_are_dropped(self):
        email = "optional-fields@example.test"
        fingerprint = account_fingerprint(email)
        self.path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "items": {
                        fingerprint: {
                            "active": True,
                            "reason_code": "oauth_session_invalid",
                            "count": 3,
                            "first_at": 1000,
                            "last_at": 1000,
                            "stage": "phone_submitting",
                            "blocked_until": "not-a-time",
                            "isolated": True,
                            "password": "mailbox-secret",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        status = self.store.status(email)

        self.assertTrue(status["isolated"])
        self.assertTrue(status["blocked"])
        self.assertEqual(status["blocked_until"], 0.0)
        self.assertNotIn("password", status)

        self.store.mark(email)
        persisted = self.path.read_text(encoding="utf-8")
        self.assertNotIn("mailbox-secret", persisted)
        self.assertNotIn("password", persisted)


if __name__ == "__main__":
    unittest.main()
