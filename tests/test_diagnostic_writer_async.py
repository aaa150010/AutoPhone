"""Async batched diagnostic writer contract tests."""

from __future__ import annotations

import re
from pathlib import Path
import tempfile
import unittest

from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.diagnostic_writer import LogContext
from mac_overrides.diagnostic_writer_async import AsyncDiagnosticWriter


class AsyncDiagnosticWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-async-writer-")
        self.root = Path(self.temp_dir.name)
        self.store = DiagnosticStore(self.root / "diagnostics")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _writer(self, **kwargs) -> AsyncDiagnosticWriter:
        return AsyncDiagnosticWriter(
            self.store,
            context=LogContext(chain="free", workflow="register", driver="camoufox"),
            flush_interval=0.05,
            **kwargs,
        )

    def test_record_returns_stable_task_incident_before_flush(self) -> None:
        writer = self._writer()
        try:
            first = writer.record({
                "task_id": "task-a", "node_code": "free_oauth_session",
                "node_label": "Free OAuth 会话", "outcome": "success",
                "message": "任务开始", "subject_ref": "a@example.test",
            })
            second = writer.record({
                "task_id": "task-a", "node_code": "free_email_otp_wait",
                "node_label": "等待 Free 邮箱验证码", "outcome": "error",
                "message": "验证码超时",
                "failure": {"error_code": "otp_timeout", "retryable": True},
                "subject_ref": "a@example.test",
            })
            self.assertEqual(first, second)
            self.assertRegex(first, r"^LOG-\d{8}-[A-Z0-9]{8}$")
        finally:
            writer.close()

    def test_flush_persists_grouped_events_with_verified_chain(self) -> None:
        writer = self._writer()
        try:
            incident = writer.record({
                "task_id": "task-b", "node_code": "free_oauth_session",
                "node_label": "Free OAuth 会话", "outcome": "success",
                "message": "任务开始", "subject_ref": "b@example.test",
            })
            writer.record({
                "task_id": "task-b", "node_code": "free_email_otp_wait",
                "node_label": "等待 Free 邮箱验证码", "outcome": "error",
                "message": "验证码超时",
                "failure": {"error_code": "otp_timeout", "retryable": True},
                "subject_ref": "b@example.test",
            })
            self.assertEqual(writer.flush(), 2)
            payload = self.store.incident(incident)
            self.assertIsNotNone(payload)
            self.assertEqual(len(payload["events"]), 2)
            self.assertEqual(payload["integrity_status"], "verified")
            self.assertEqual(payload["first_node_code"], "free_email_otp_wait")
            self.assertEqual(payload["first_error_code"], "otp_timeout")
            # Display-safe email shapes persist verbatim by design; the raw
            # subject is stored only as the HMAC fingerprint.
            self.assertEqual(payload["subject_display"], "b@example.test")
            for event in payload["events"]:
                self.assertTrue(re.fullmatch(r"[0-9a-f]{32}", str(event["subject_ref"])))
        finally:
            writer.close()

    def test_separate_tasks_get_separate_incidents(self) -> None:
        writer = self._writer()
        try:
            first = writer.record({
                "task_id": "task-c1", "node_code": "free_oauth_session",
                "outcome": "success", "message": "一", "subject_ref": "c1@example.test",
            })
            second = writer.record({
                "task_id": "task-c2", "node_code": "free_oauth_session",
                "outcome": "success", "message": "二", "subject_ref": "c2@example.test",
            })
            self.assertNotEqual(first, second)
            writer.flush()
            self.assertEqual(len(self.store.incident(first)["events"]), 1)
            self.assertEqual(len(self.store.incident(second)["events"]), 1)
        finally:
            writer.close()

    def test_explicit_incident_hint_is_honored(self) -> None:
        writer = self._writer()
        try:
            hint = "LOG-20260101-AAAA1111"
            self.assertTrue(self.store.reserve_incident(hint))
            returned = writer.record({
                "task_id": "task-d", "incident_id": hint,
                "node_code": "free_twofa_activate", "outcome": "error",
                "message": "重试失败",
                "failure": {"error_code": "free_twofa_activate_failed"},
            })
            self.assertEqual(returned, hint)
            writer.flush()
            self.assertEqual(len(self.store.incident(hint)["events"]), 1)
        finally:
            writer.close()

    def test_redaction_happens_before_enqueue(self) -> None:
        seen: list[dict] = []
        writer = self._writer()
        try:
            original = writer.store.record

            def spy(fields):
                seen.append(dict(fields))
                return original(fields)

            writer.store.record = spy
            writer.record({
                "task_id": "task-e", "node_code": "free_email_otp_wait",
                "outcome": "error", "message": "code=123456",
                "subject_ref": "private@example.test",
                "failure": {"error_code": "otp_timeout"},
            })
            writer.flush()
            self.assertEqual(len(seen), 1)
            # The raw subject must be replaced by the fingerprint on the
            # queued projection; the OTP code text must be redacted too.
            self.assertNotIn("private@example.test", str(seen[0].get("subject_ref", "")))
            self.assertNotIn("private@example.test", str(seen[0].get("message", "")))
            self.assertNotIn("123456", str(seen[0].get("message", "")))
            self.assertTrue(re.fullmatch(r"[0-9a-f]{32}", str(seen[0].get("subject_ref_fingerprint", ""))))
        finally:
            writer.close()

    def test_forget_task_binds_new_incident_for_next_run(self) -> None:
        writer = self._writer()
        try:
            first = writer.record({
                "task_id": "task-f", "node_code": "free_oauth_session",
                "outcome": "success", "message": "第一次",
            })
            writer.forget_task("task-f")
            second = writer.record({
                "task_id": "task-f", "node_code": "free_oauth_session",
                "outcome": "success", "message": "第二次",
            })
            self.assertNotEqual(first, second)
            writer.flush()
        finally:
            writer.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
