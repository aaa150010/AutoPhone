from __future__ import annotations

import json
import threading
import unittest

from mac_overrides.mailbox_batch_operations import (
    MailboxBatchOperationManager,
    MailboxOperationAlreadyRunning,
)


class MailboxBatchOperationManagerTests(unittest.TestCase):
    def test_background_worker_chunks_bindings_and_exposes_only_aggregates(self):
        manager = MailboxBatchOperationManager(chunk_size=5)
        started = threading.Event()
        release = threading.Event()
        calls = []
        rows = [
            {
                "row_id": f"row-{index}",
                "line_no": index + 1,
                "email": f"private-{index}@example.test",
                "password": "password-secret",
            }
            for index in range(12)
        ]

        def worker(payload):
            calls.append(payload)
            if len(calls) == 1:
                started.set()
                self.assertTrue(release.wait(2))
            return {
                "ok": True,
                "queried": len(payload["rows"]),
                "failed": 0,
                "skipped": 0,
                "results": [{"access_token": "must-not-be-retained"}],
            }

        operation, created = manager.start("quota", rows, worker)
        self.assertTrue(created)
        self.assertTrue(started.wait(1))
        self.assertEqual(operation["status"], "running")
        self.assertEqual(operation["total"], 12)
        serialized = json.dumps(manager.snapshot())
        self.assertNotIn("private-", serialized)
        self.assertNotIn("password-secret", serialized)
        self.assertNotIn("must-not-be-retained", serialized)

        release.set()
        completed = manager.wait(operation["job_id"], 2)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["completed"], 12)
        self.assertEqual(completed["succeeded"], 12)
        self.assertEqual([len(call["rows"]) for call in calls], [5, 5, 2])
        self.assertEqual(
            set().union(*(item.keys() for call in calls for item in call["rows"])),
            {"row_id", "line_no"},
        )

    def test_row_callback_advances_progress_before_chunk_worker_returns(self):
        manager = MailboxBatchOperationManager(chunk_size=5)
        first_completed = threading.Event()
        release_second = threading.Event()
        rows = [
            {"row_id": "row-one", "line_no": 1},
            {"row_id": "row-two", "line_no": 2},
        ]

        def worker(payload):
            callback = payload["_on_row_completed"]
            callback({
                **payload["rows"][0],
                "status": "ok",
                "queried_at": 101,
                "quota_5h": {"remaining_percent": 75, "queried_at": 101},
                "quota_7d": None,
            })
            callback({**payload["rows"][0], "status": "error"})
            first_completed.set()
            self.assertTrue(release_second.wait(2))
            callback({
                **payload["rows"][1],
                "status": "error",
                "code": "openai_quota_network_error",
                "error": "无法连接当前显式代理 private@example.test bearer-secret",
                "queried_at": 102,
            })
            return {"ok": True, "queried": 2, "failed": 0, "skipped": 0}

        operation, _created = manager.start("quota", rows, worker)
        self.assertTrue(first_completed.wait(1))
        running = manager.snapshot()
        self.assertEqual(running["status"], "running")
        self.assertEqual(running["completed"], 1)
        self.assertEqual(running["row_updates"], [{
            "row_id": "row-one",
            "line_no": 1,
            "quota_status": "ok",
            "quota_queried_at": 101,
            "quota_5h": {"remaining_percent": 75, "limit_window_seconds": None, "reset_at": None, "reset_after_seconds": None, "queried_at": 101},
            "quota_7d": None,
            "quota_error": "",
        }])

        release_second.set()
        completed = manager.wait(operation["job_id"], 2)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["completed"], 2)
        self.assertEqual(completed["succeeded"], 2)
        serialized = json.dumps(completed)
        self.assertNotIn("private@example.test", serialized)
        self.assertNotIn("bearer-secret", serialized)
        self.assertEqual(completed["row_updates"][1]["quota_status"], "error")
        self.assertEqual(
            completed["row_updates"][1]["quota_error"],
            "查询 OpenAI 额度失败：无法连接当前显式代理",
        )
        completed["row_updates"][0]["quota_5h"]["remaining_percent"] = 1
        self.assertEqual(manager.snapshot()["row_updates"][0]["quota_5h"]["remaining_percent"], 75)

    def test_quota_row_errors_keep_safe_specific_network_and_http_causes(self):
        manager = MailboxBatchOperationManager()
        rows = [
            {"row_id": "row-dns", "line_no": 1},
            {"row_id": "row-auth", "line_no": 2},
        ]

        def worker(payload):
            callback = payload["_on_row_completed"]
            callback({
                **payload["rows"][0],
                "status": "error",
                "code": "openai_quota_network_error",
                "error": "OpenAI 域名 DNS 解析失败 private-password",
            })
            callback({
                **payload["rows"][1],
                "status": "error",
                "code": "openai_quota_unauthorized",
                "error": "Bearer private-access-token",
            })
            return {"ok": True, "queried": 2, "failed": 2, "skipped": 0}

        operation, _created = manager.start("quota", rows, worker)
        completed = manager.wait(operation["job_id"], 2)

        self.assertEqual(
            completed["row_updates"][0]["quota_error"],
            "查询 OpenAI 额度失败：OpenAI 域名 DNS 解析失败",
        )
        self.assertEqual(
            completed["row_updates"][1]["quota_error"],
            "查询 OpenAI 额度失败：OpenAI OAuth Token 已失效，需要重新运行账号",
        )
        self.assertNotIn("private-password", json.dumps(completed))
        self.assertNotIn("private-access-token", json.dumps(completed))

    def test_quota_chunks_delete_deactivated_mailboxes_immediately(self):
        manager = MailboxBatchOperationManager(chunk_size=2)
        rows = [
            {"row_id": f"row-{index}", "line_no": index + 1}
            for index in range(5)
        ]
        calls = []

        def worker(payload):
            calls.append(payload)
            detected = [payload["rows"][0]]
            return {
                "ok": True,
                "queried": 0,
                "failed": len(payload["rows"]),
                "skipped": 0,
                "deactivated_rows": detected,
                "deactivated_detected": len(detected),
                "deactivated_deleted": len(detected),
            }

        operation, _created = manager.start("quota", rows, worker)
        completed = manager.wait(operation["job_id"], 2)

        self.assertEqual(completed["deactivated_deleted"], 3)
        self.assertTrue(all("_defer_deactivated_delete" not in call for call in calls))
        self.assertTrue(all("_pending_deactivated_rows" not in call for call in calls))

    def test_openai_row_updates_are_redacted_and_bound_to_exact_source_row(self):
        manager = MailboxBatchOperationManager()

        def worker(payload):
            callback = payload["_on_row_completed"]
            callback({
                "row_id": "row-one",
                "line_no": 999,
                "sub2_status": {"kind": "healthy", "status_code": 200},
            })
            callback({
                **payload["rows"][0],
                "sub2_status": {
                    "kind": "unauthorized",
                    "status_code": 401,
                    "tested_at": 123,
                    "summary": "access-secret private@example.test",
                },
                "document": {"access_token": "access-secret"},
            })
            return {"ok": True, "tested": 1, "healthy": 0, "failed": 1}

        operation, _created = manager.start(
            "openai_test",
            [{"row_id": "row-one", "line_no": 1}],
            worker,
        )
        completed = manager.wait(operation["job_id"], 2)
        self.assertEqual(completed["completed"], 1)
        self.assertEqual(len(completed["row_updates"]), 1)
        update = completed["row_updates"][0]
        self.assertEqual((update["row_id"], update["line_no"]), ("row-one", 1))
        self.assertEqual(update["sub2_status"]["status_code"], 401)
        self.assertTrue(update["sub2_status"]["needs_rerun"])
        serialized = json.dumps(completed)
        self.assertNotIn("access-secret", serialized)
        self.assertNotIn("private@example.test", serialized)

    def test_openai_test_chunks_delete_deactivated_mailboxes_immediately(self):
        manager = MailboxBatchOperationManager(chunk_size=2)
        rows = [
            {"row_id": f"row-{index}", "line_no": index + 1}
            for index in range(5)
        ]
        calls = []

        def worker(payload):
            calls.append(payload)
            detected = [payload["rows"][0]]
            return {
                "ok": True,
                "tested": len(payload["rows"]),
                "healthy": 0,
                "failed": len(payload["rows"]),
                "deactivated_rows": detected,
                "deactivated_deleted": len(detected),
            }

        operation, _created = manager.start("openai_test", rows, worker)
        completed = manager.wait(operation["job_id"], 2)

        self.assertEqual(completed["deactivated_deleted"], 3)
        self.assertTrue(all("_defer_deactivated_delete" not in call for call in calls))
        self.assertTrue(all("_pending_deactivated_rows" not in call for call in calls))

    def test_openai_unauthorized_rows_are_counted_as_failures(self):
        manager = MailboxBatchOperationManager()

        operation, _created = manager.start(
            "openai_test",
            [{"row_id": "row-one", "line_no": 1}],
            lambda _payload: {
                "ok": True,
                "tested": 1,
                "healthy": 0,
                "failed": 1,
                "test_failures": 0,
            },
        )

        completed = manager.wait(operation["job_id"], 2)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["failed"], 1)

    def test_duplicate_start_is_idempotent_and_other_batches_are_rejected(self):
        manager = MailboxBatchOperationManager()
        started = threading.Event()
        release = threading.Event()
        rows = [{"row_id": "row-a", "line_no": 1}]

        def worker(_payload):
            started.set()
            release.wait(2)
            return {"ok": True, "tested": 1, "healthy": 1}

        first, created = manager.start("openai_test", rows, worker)
        self.assertTrue(created)
        self.assertTrue(started.wait(1))
        duplicate, duplicate_created = manager.start("openai_test", rows, worker)
        self.assertFalse(duplicate_created)
        self.assertEqual(duplicate["job_id"], first["job_id"])
        with self.assertRaises(MailboxOperationAlreadyRunning):
            manager.start("quota", rows, worker)
        release.set()
        manager.wait(first["job_id"], 2)

    def test_created_at_strictly_increases_when_clock_is_equal_or_moves_backward(self):
        now = [100.0]
        manager = MailboxBatchOperationManager(now_fn=lambda: now[0])
        rows = [{"row_id": "row-a", "line_no": 1}]
        worker = lambda _payload: {"ok": True, "queried": 1}

        first, _created = manager.start("quota", rows, worker)
        manager.wait(first["job_id"], 2)
        now[0] = 99.0
        second, _created = manager.start("quota", rows, worker)
        completed = manager.wait(second["job_id"], 2)

        self.assertGreater(second["created_at"], first["created_at"])
        self.assertGreaterEqual(completed["updated_at"], second["created_at"])
        self.assertGreaterEqual(completed["finished_at"], second["created_at"])

    def test_worker_failure_is_redacted_and_terminal_snapshot_expires(self):
        now = [100.0]
        manager = MailboxBatchOperationManager(
            terminal_ttl_seconds=10,
            now_fn=lambda: now[0],
        )

        def worker(_payload):
            raise RuntimeError("access-secret refresh-secret private@example.test")

        operation, _created = manager.start(
            "quota",
            [{"row_id": "row-a", "line_no": 1}],
            worker,
        )
        failed = manager.wait(operation["job_id"], 2)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["node_code"], "mailbox_batch_operation")
        serialized = json.dumps(failed)
        self.assertNotIn("access-secret", serialized)
        self.assertNotIn("refresh-secret", serialized)
        self.assertNotIn("private@example.test", serialized)

        failed["error"] = "modified"
        self.assertNotEqual(manager.snapshot()["error"], "modified")
        now[0] += 11
        self.assertIsNone(manager.snapshot())


if __name__ == "__main__":
    unittest.main()
