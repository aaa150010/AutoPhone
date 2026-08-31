from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mac_overrides.free_failure_runtime import (
    sanitize_public_progress,
    sanitize_public_timing,
)
from mac_overrides.free_register_runtime import FreeMailboxPool, FreeRegisterManager


class FreePublicProjectionSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-free-public-")
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_progress_projection_keeps_legacy_fields_and_drops_nested_secrets(self) -> None:
        raw = {
            "stage": "free_email_otp_wait",
            "stage_started_at": 123,
            "stage_duration_ms": 456,
            "total_elapsed_ms": 789,
            "email": "private@example.test",
            "mailbox_url": "https://api798.com/get_code?email=private%40example.test&auth_code=private-code",
            "details": {
                "access_token": "access-private",
                "cookie": "cookie-private",
                "otp": "123456",
            },
            "timing": {
                "started_at": 100,
                "elapsed_ms": 200,
                "stages": [{
                    "code": "free_email_otp_wait",
                    "label": "等待 Free 邮箱验证码",
                    "duration_ms": 200,
                    "visits": 1,
                    "token": "nested-token",
                    "details": {"mailbox_url": "https://mail.test/private"},
                }],
                "substeps": [{
                    "key": "free_email_otp_wait:mailbox_poll_scan",
                    "stage_code": "free_email_otp_wait",
                    "stage_label": "等待 Free 邮箱验证码",
                    "code": "mailbox_poll_scan",
                    "label": "轮询邮箱",
                    "duration_ms": 10,
                    "visits": 2,
                    "response": "token=should-drop",
                }],
            },
        }

        projected = sanitize_public_progress(raw)
        serialized = json.dumps(projected, ensure_ascii=False)
        for secret in (
            "private@example.test",
            "api798.com/get_code",
            "private-code",
            "access-private",
            "cookie-private",
            "123456",
            "nested-token",
            "https://mail.test/private",
            "should-drop",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(projected["stage"], "free_email_otp_wait")
        self.assertEqual(projected["stage_started_at"], 123)
        self.assertEqual(projected["stage_duration_ms"], 456)
        self.assertEqual(projected["total_elapsed_ms"], 789)
        self.assertEqual(projected["timing"]["stages"][0]["code"], "free_email_otp_wait")
        self.assertNotIn("token", projected["timing"]["stages"][0])

    def test_manager_public_task_sanitizes_provider_and_persisted_progress(self) -> None:
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks = {
            "free-public-progress-secret": {
                "task_id": "free-public-progress-secret",
                "status": "running",
                "email": "private@example.test",
                "progress": {
                    "code": "free_oauth_session",
                    "label": "Free OAuth 会话",
                    "entered_at": 100,
                    "finished_at": None,
                    "metadata": {"refresh_token": "refresh-private"},
                },
                "timing": {
                    "started_at": 100,
                    "elapsed_ms": 10,
                    "debug": "https://mail.test/private?token=private",
                },
            },
        }
        projected = manager.public_tasks()[0]
        serialized = json.dumps(projected, ensure_ascii=False)
        self.assertNotIn("private@example.test", serialized)
        self.assertNotIn("refresh-private", serialized)
        self.assertNotIn("mail.test/private", serialized)
        self.assertNotIn("private", serialized)
        self.assertEqual(projected["progress"]["code"], "free_oauth_session")
        self.assertEqual(projected["progress"]["entered_at"], 100)
        self.assertEqual(projected["timing"]["elapsed_ms"], 10)
        self.assertNotIn("debug", projected["timing"])

    def test_mailbox_public_rows_sanitize_progress_payload(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text(
            "private@example.test----https://api798.com/get_code?email=private%40example.test&auth_code=private-code\n"
        )
        row_id = pool.entries()[0].row_id
        pool.update(
            row_id,
            progress={
                "stage": "free_email_otp_wait",
                "stage_duration_ms": 12,
                "token": "row-token-private",
                "nested": {"mailbox_url": "https://mail.test/private"},
            },
        )
        projected = pool.public_rows()[0]
        serialized = json.dumps(projected, ensure_ascii=False)
        self.assertNotIn("row-token-private", serialized)
        self.assertNotIn("mail.test/private", serialized)
        self.assertEqual(projected["progress"]["stage"], "free_email_otp_wait")
        self.assertEqual(projected["progress"]["stage_duration_ms"], 12)

    def test_timing_projection_rejects_unknown_and_nonfinite_values(self) -> None:
        projected = sanitize_public_timing({
            "started_at": float("nan"),
            "elapsed_seconds": float("inf"),
            "stages": [{"code": "free_oauth_session", "duration_ms": 7, "secret": "x"}],
            "unknown": {"access_token": "x"},
        })
        self.assertNotIn("started_at", projected)
        self.assertNotIn("elapsed_seconds", projected)
        self.assertNotIn("unknown", projected)
        self.assertEqual(projected["stages"][0]["duration_ms"], 7)
        self.assertNotIn("secret", projected["stages"][0])

    def test_mailbox_projection_type_checks_persisted_scalars(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("safe@example.test----https://mail.example.test/code\n")
        row_id = pool.entries()[0].row_id
        pool.update(
            row_id,
            status="https://evil.example/status?token=private",
            stage="Bearer private-token",
            batch_id="https://evil.example/batch",
            driver={"token": "private-token"},
            proxy_fingerprint="socks5://user:password@proxy.example:1080",
            proxy_id="https://evil.example/proxy",
            proxy_scheme="javascript",
            proxy_country="US",
            proxy_group="legacy",
        )
        pool.save_result(
            row_id,
            {
                "plan_check_status": "Bearer private-token",
                "plan_check_task_id": "https://evil.example/task?token=private",
                "plan_checked_at": "not-a-timestamp",
                "plan_retry_after_until": float("nan"),
                "plan_http_status": 999,
                "live_check_status": {"token": "private-token"},
                "live_check_mode": "https://evil.example/mode",
                "live_check_task_id": "https://evil.example/live",
                "live_checked_at": "Bearer private-token",
                "live_check_http_status": "503",
                "live_check_token_refreshed": "false",
                "twofa_status": "https://evil.example/2fa",
                "has_active_subscription": "false",
                "plus_trial_eligible": "true",
            },
        )

        projected = pool.public_rows()[0]
        serialized = json.dumps(projected, ensure_ascii=False)
        for secret in (
            "private-token",
            "evil.example",
            "password@proxy.example",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(projected["status"], "available")
        self.assertEqual(projected["stage"], "")
        self.assertEqual(projected["batch_id"], "")
        self.assertEqual(projected["driver"], "")
        self.assertEqual(projected["proxy_id"], "")
        self.assertEqual(projected["proxy_scheme"], "")
        self.assertEqual(projected["proxy_country"], "")
        self.assertEqual(projected["proxy_group"], "")
        self.assertEqual(projected["plan_http_status"], None)
        self.assertEqual(projected["live_check_http_status"], 503)
        self.assertFalse(projected["live_check_token_refreshed"])
        self.assertFalse(projected["has_active_subscription"])
        self.assertTrue(projected["plus_trial_eligible"])

    def test_task_projection_filters_custom_manual_broker_payload(self) -> None:
        class MaliciousBroker:
            def public(self, _task_id):
                return {
                    "input_kind": "email_otp",
                    "generation": "2",
                    "opened_at": 10,
                    "deadline_at": 20,
                    "can_submit": "false",
                    "capabilities": ["submit", "https://evil.example/?token=private"],
                    "mailbox_url": "https://evil.example/?token=private",
                    "access_token": "private-token",
                }

        manager = FreeRegisterManager(self.data_dir, manual_broker=MaliciousBroker())
        manager._tasks = {
            "projection-task": {
                "task_id": "projection-task",
                "status": "running",
                "batch_id": "https://evil.example/batch?token=private",
                "stage": "Bearer private-token",
                "driver": {"token": "private-token"},
                "proxy_id": "https://evil.example/proxy",
                "proxy_scheme": "javascript",
                "created_at": "not-a-number",
                "result": {
                    "twofa_status": "false",
                    "plan_check_status": "https://evil.example/status",
                    "plan_http_status": "700",
                    "has_active_subscription": "false",
                },
            },
        }

        projected = manager.public_tasks()[0]
        serialized = json.dumps(projected, ensure_ascii=False)
        self.assertNotIn("private-token", serialized)
        self.assertNotIn("evil.example", serialized)
        self.assertEqual(projected["batch_id"], "")
        self.assertEqual(projected["stage"], "")
        self.assertEqual(projected["proxy_id"], "")
        self.assertEqual(projected["proxy_scheme"], "")
        self.assertEqual(projected["manual_verification"]["input_kind"], "email_otp")
        self.assertEqual(projected["manual_verification"]["generation"], 2)
        self.assertEqual(projected["manual_verification"]["can_submit"], False)
        self.assertNotIn("mailbox_url", projected["manual_verification"])
        self.assertEqual(projected["result"]["twofa_status"], "false")
        self.assertEqual(projected["result"]["plan_http_status"], None)


if __name__ == "__main__":
    unittest.main()
