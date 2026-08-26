from __future__ import annotations

import unittest

from mac_overrides.free_notifications import summarize_free_batch


class FreeNotificationSummaryTests(unittest.TestCase):
    def test_summary_is_deduplicated_and_credential_free(self) -> None:
        tasks = [
            {
                "task_id": "free-batch-1",
                "row_id": "row-a",
                "created_at": 10,
                "email": "alice@example.test",
                "status": "twofa_pending",
                "incident_id": "LOG-20260827-ABC123",
                "result": {
                    "access_token": "access-token-private",
                    "password": "password-private",
                    "totp_secret": "totp-secret-private",
                },
                "mailbox_url": "https://mail.example.test/latest?auth_code=mail-private",
                "timing": {
                    "elapsed_ms": 1200,
                    "slowest_node": {
                        "code": "free_email_otp_wait",
                        "label": "等待 Free 邮箱验证码",
                        "duration_ms": 900,
                    },
                },
            },
            # A retry continuation for the same row replaces the historical
            # pending result in the aggregate rather than double-counting it.
            {
                "task_id": "free-batch-1-retry",
                "row_id": "row-a",
                "created_at": 11,
                "retry_of": "free-batch-1",
                "retry_attempt": 1,
                "email": "alice@example.test",
                "status": "success",
                "incident_id": "LOG-20260827-DEF456",
                "timing": {"elapsed_ms": 300, "slowest_node": {"code": "free_twofa_activate", "label": "激活 Free 账号 2FA", "duration_ms": 250}},
            },
        ]

        summary = summarize_free_batch(tasks, batch_id="free-20260827-test")

        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["success"], 1)
        self.assertEqual(summary["twofa_pending"], 0)
        self.assertEqual(summary["duration_ms"], 300)
        self.assertEqual(summary["emails"], ["a***@example.test"])
        self.assertEqual(summary["incident_ids"], ["LOG-20260827-DEF456"])
        serialized = repr(summary)
        for secret in ("access-token-private", "password-private", "totp-secret-private", "mail-private"):
            self.assertNotIn(secret, serialized)

    def test_summary_rejects_unsafe_batch_and_incident_values(self) -> None:
        summary = summarize_free_batch(
            [{
                "row_id": "row-a",
                "email": "not-an-email",
                "status": "failed",
                "incident_id": "LOG-unsafe\nsecret",
            }],
            batch_id="free batch\nsecret",
        )

        self.assertEqual(summary["batch_id"], "")
        self.assertEqual(summary["incident_ids"], [])
        self.assertEqual(summary["emails"], ["<邮箱>"])

    def test_summary_uses_batch_wall_clock_duration_for_concurrent_tasks(self) -> None:
        summary = summarize_free_batch(
            [
                {"row_id": "row-a", "email": "a@example.test", "status": "success", "created_at": 100, "timing": {"started_at": 100, "finished_at": 112, "elapsed_ms": 12000}},
                {"row_id": "row-b", "email": "b@example.test", "status": "success", "created_at": 100, "timing": {"started_at": 100, "finished_at": 110, "elapsed_ms": 10000}},
            ],
            batch_id="free-batch-wall",
        )
        self.assertEqual(summary["duration_ms"], 12000)
        self.assertEqual(summary["duration_seconds"], 12.0)


if __name__ == "__main__":
    unittest.main()
