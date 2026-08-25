from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from mac_overrides.diagnostic_store import DiagnosticStore


class DiagnosticStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-diagnostics-")
        self.store = DiagnosticStore(Path(self.temp_dir.name))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_task_events_share_an_incident_and_keep_first_failure(self) -> None:
        incident_id = self.store.record({
            "level": "info", "outcome": "started", "task_id": "T001-a",
            "chain": "free", "driver": "protocol", "node_code": "free_run_start",
            "message": "started",
        })
        self.assertTrue(incident_id)
        same = self.store.record({
            "level": "error", "outcome": "error", "task_id": "T001-a",
            "chain": "free", "driver": "protocol", "node_code": "free_email_otp_wait",
            "node_label": "等待 Free 邮箱验证码", "message": "token=private email=a@example.test",
            "failure": {"error_code": "email_code_timeout", "retryable": True},
        })
        self.assertEqual(same, incident_id)
        incident = self.store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["first_node_code"], "free_email_otp_wait")
        self.assertEqual(len(incident["events"]), 2)
        self.assertEqual(incident["integrity_status"], "verified")
        self.assertNotIn("private", self.store.export([incident_id], "markdown"))
        self.assertNotIn("a@example.test", self.store.export([incident_id], "json"))

    def test_strict_transport_redaction(self) -> None:
        incident_id = self.store.record({
            "level": "error", "outcome": "error", "task_id": "redact",
            "node_code": "oauth", "message": "Authorization: Bearer abcdef123456 user=a@example.test phone=13800138000",
        })
        content = self.store.export([incident_id], "json")
        self.assertNotIn("abcdef123456", content)
        self.assertNotIn("a@example.test", content)
        self.assertNotIn("13800138000", content)

    def test_search_by_email_uses_hmac_and_delete_does_not_touch_business_data(self) -> None:
        incident_id = self.store.record({
            "level": "error", "outcome": "error", "task_id": "free-task-1",
            "chain": "free", "driver": "camoufox", "email": "A@example.test",
            "node_code": "free_camoufox_signup", "message": "signup failed",
        })
        self.assertEqual(self.store.search({"subject": "a@example.test"})[0]["incident_id"], incident_id)
        self.assertEqual(self.store.delete([incident_id]), 1)
        self.assertIsNone(self.store.incident(incident_id))
        self.assertEqual(self.store.health()["incidents"], 0)

    def test_date_search_and_terminal_cleanup_keep_failure_status(self) -> None:
        incident_id = self.store.record({
            "event_id": "date-failure", "level": "error", "outcome": "error", "task_id": "date-task",
            "occurred_at": "2026-08-25T08:00:00Z", "node_code": "oauth_callback",
            "failure": {"http_status": 401, "provider_code": "invalid_session"},
        })
        self.store.record({
            "event_id": "date-cleanup", "level": "info", "outcome": "info", "task_id": "date-task",
            "occurred_at": "2026-08-25T08:00:01Z", "node_code": "browser_cleanup",
        })
        result = self.store.incident(incident_id)
        assert result is not None
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.store.search({"date": "2026-08-25"})[0]["incident_id"], incident_id)
        self.assertIn("401", self.store.export([incident_id], "json"))

    def test_clear_all_only_clears_diagnostic_index(self) -> None:
        self.store.record({"level": "error", "outcome": "error", "task_id": "T1", "node_code": "unexpected", "message": "x"})
        self.store.record({"level": "error", "outcome": "error", "task_id": "T2", "node_code": "unexpected", "message": "y"})
        self.assertEqual(self.store.clear(), 2)
        self.assertEqual(self.store.health()["incidents"], 0)
        self.assertTrue(Path(self.temp_dir.name).exists())

    def test_new_batch_gets_new_incident_but_repeated_event_is_idempotent(self) -> None:
        first = self.store.record({
            "event_id": "event-1", "task_id": "same-task", "batch_id": "batch-1",
            "level": "error", "outcome": "error", "node_code": "email_otp",
        })
        self.assertEqual(self.store.record({
            "event_id": "event-1", "task_id": "same-task", "batch_id": "batch-1",
            "level": "error", "outcome": "error", "node_code": "email_otp",
        }), first)
        second = self.store.record({
            "event_id": "event-2", "task_id": "same-task", "batch_id": "batch-2",
            "level": "error", "outcome": "error", "node_code": "email_otp_retry",
        })
        self.assertNotEqual(first, second)
        self.assertEqual(self.store.incident(first)["event_count"], 1)

    def test_cleanup_failure_does_not_replace_business_root_cause_and_tamper_is_detected(self) -> None:
        incident_id = self.store.record({
            "event_id": "business", "task_id": "task-cleanup", "batch_id": "batch",
            "level": "error", "outcome": "error", "node_code": "oauth_callback",
            "node_label": "OAuth 回调",
        })
        self.store.record({
            "event_id": "cleanup", "task_id": "task-cleanup", "batch_id": "batch",
            "level": "error", "outcome": "error", "node_code": "browser_cleanup",
            "node_label": "浏览器清理",
        })
        self.assertEqual(self.store.incident(incident_id)["first_node_code"], "oauth_callback")
        with self.store._connection() as db:
            db.execute("UPDATE diagnostic_events SET node_label='被篡改' WHERE event_id='business'")
        self.assertEqual(self.store.incident(incident_id)["integrity_status"], "failed")

    def test_deleted_incident_id_is_tombstoned(self) -> None:
        incident_id = self.store.record({"event_id": "tombstone", "level": "error", "outcome": "error", "node_code": "x"})
        self.assertEqual(self.store.delete([incident_id]), 1)
        replacement = self.store.record({"event_id": "replacement", "level": "error", "outcome": "error", "node_code": "x"})
        self.assertNotEqual(incident_id, replacement)

    def test_retention_prunes_events_and_old_incident_summaries_without_reusing_ids(self) -> None:
        store = DiagnosticStore(Path(self.temp_dir.name) / "retention", event_retention_days=1, incident_retention_days=2)
        incident_id = store.record({
            "event_id": "old-event", "level": "error", "outcome": "error", "task_id": "old-task",
            "occurred_at": "2020-01-01T00:00:00Z", "node_code": "old_node",
        })
        result = store.prune(now="2090-01-04T00:00:00Z")
        self.assertEqual(result["events"], 1)
        self.assertEqual(result["incidents"], 1)
        self.assertIsNone(store.incident(incident_id))
        replacement = store.record({"event_id": "new-event", "level": "error", "outcome": "error", "node_code": "old_node"})
        self.assertNotEqual(incident_id, replacement)


if __name__ == "__main__":
    unittest.main()
