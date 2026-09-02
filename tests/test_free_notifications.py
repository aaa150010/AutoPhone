from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mac_overrides.free_notifications import (
    FreeBatchNotificationAdapter,
    summarize_free_batch,
)


class FreeNotificationSummaryTests(unittest.TestCase):
    def test_batch_email_names_camoufox_chain(self) -> None:
        sent: list[object] = []

        class FakeSender:
            def __init__(self, _config: object) -> None:
                self._settings = SimpleNamespace(
                    sender="notifier@example.test",
                    recipients=("ops@example.test",),
                )

            def _send_message(self, message: object) -> None:
                sent.append(message)

        config = {
            "enabled": True,
            "username": "notifier@example.test",
            "password": "smtp-secret",
            "sender": "notifier@example.test",
            "recipients": ["ops@example.test"],
        }
        with patch("mac_overrides.free_notifications.SmtpNotificationSender", FakeSender):
            adapter = FreeBatchNotificationAdapter(lambda: config)
            self.assertTrue(
                adapter.submit(
                    [{"row_id": "row-camoufox", "driver": "camoufox", "status": "success"}],
                    batch_id="free-camoufox-email",
                )
            )
            queue = adapter._queue
            self.assertIsNotNone(queue)
            assert queue is not None
            self.assertTrue(queue.wait_until_idle(timeout=2))
            adapter.close()

        self.assertEqual(len(sent), 1)
        message = sent[0]
        self.assertEqual(
            message["Subject"],
            "[GPT 注册中心][Camoufox] Free 注册汇总",
        )
        body = message.get_content()
        self.assertIn("结果：成功 1 ｜ 失败 0 ｜ 共 1 个", body)
        self.assertIn("链路：Camoufox", body)
        self.assertNotIn("free-camoufox-email", message.as_string())
        self.assertNotIn("邮箱：", body)
        self.assertNotIn("自动接码机", message.as_string())

    def test_summary_identifies_free_driver_and_chain(self) -> None:
        protocol = summarize_free_batch(
            [{"row_id": "row-protocol", "driver": "protocol", "status": "success"}],
            batch_id="free-protocol-batch",
        )
        camoufox = summarize_free_batch(
            [{"row_id": "row-camoufox", "driver": "camoufox", "status": "success"}],
            batch_id="free-camoufox-batch",
        )

        self.assertEqual(protocol["driver"], "protocol")
        self.assertEqual(protocol["chain"], "协议")
        self.assertEqual(protocol["drivers"], ["protocol"])
        self.assertEqual(camoufox["driver"], "camoufox")
        self.assertEqual(camoufox["chain"], "Camoufox")

    def test_summary_does_not_guess_unsupported_or_missing_driver(self) -> None:
        summary = summarize_free_batch(
            [
                {"row_id": "row-a", "driver": "roxybrowser", "status": "success"},
                {"row_id": "row-b", "status": "failed"},
            ],
            batch_id="free-unknown-driver",
        )

        self.assertEqual(summary["driver"], "unknown")
        self.assertEqual(summary["drivers"], ["unknown"])
        self.assertEqual(summary["chain"], "未知链路")

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
