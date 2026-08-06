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
        self.store = PhoneRiskStore(self.path, now_fn=lambda: self.clock)

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


if __name__ == "__main__":
    unittest.main()
