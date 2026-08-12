from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mac_overrides.mailbox_result_index import MailboxResultIndex


class MailboxResultIndexTests(unittest.TestCase):
    @staticmethod
    def _write(path: Path, *, email: str, created_at: int, status: str = "success") -> None:
        path.write_text(json.dumps({
            "email": email,
            "status": status,
            "created_at": created_at,
            "task_id": f"task-{created_at}",
            "result": {
                "sub2api_account_id": f"sub2-{created_at}",
                "access_token": f"private-access-{created_at}",
                "chatgpt_account_id": f"openai-{created_at}",
            },
        }), encoding="utf-8")

    def test_unchanged_files_are_not_reparsed_and_metrics_are_credential_free(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index in range(248):
                self._write(
                    root / f"result-{index:03d}.json",
                    email=f"mailbox-{index}@example.test",
                    created_at=index + 1,
                )
            indexer = MailboxResultIndex()

            first = indexer.snapshot(root)
            second = indexer.snapshot(root)

        self.assertEqual(len(first.latest_results), 248)
        self.assertEqual(first.metrics["files_read"], 248)
        self.assertEqual(second.metrics["files_read"], 0)
        self.assertEqual(second.metrics["cache_hits"], 248)
        serialized = json.dumps(second.metrics)
        self.assertNotIn("example.test", serialized)
        self.assertNotIn("private-access", serialized)

    def test_changed_and_deleted_files_update_the_snapshot_incrementally(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first_path = root / "first.json"
            second_path = root / "second.json"
            self._write(first_path, email="first@example.test", created_at=1)
            self._write(second_path, email="second@example.test", created_at=2)
            indexer = MailboxResultIndex()
            indexer.snapshot(root)

            self._write(first_path, email="first@example.test", created_at=1000, status="failed")
            second_path.unlink()
            updated = indexer.snapshot(root)

        self.assertEqual(updated.metrics["files_read"], 1)
        self.assertEqual(set(updated.latest_results), {"first@example.test"})
        self.assertEqual(updated.latest_results["first@example.test"]["status"], "failed")
        self.assertEqual(updated.latest_sub2_accounts, {})

    def test_disabled_switch_reparses_every_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._write(root / "one.json", email="one@example.test", created_at=1)
            indexer = MailboxResultIndex()

            with patch("mac_overrides.mailbox_result_index._read_document", wraps=__import__(
                "mac_overrides.mailbox_result_index",
                fromlist=["_read_document"],
            )._read_document) as reader:
                indexer.snapshot(root, enabled=False)
                indexer.snapshot(root, enabled=False)

        self.assertEqual(reader.call_count, 2)

    def test_scan_error_temporarily_rolls_back_to_full_scans(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._write(root / "one.json", email="one@example.test", created_at=1)
            clock = 1000.0
            indexer = MailboxResultIndex(now_fn=lambda: clock)

            original_signature = indexer._signature
            calls = 0

            def fail_once(path):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError("private scan path")
                return original_signature(path)

            with patch.object(indexer, "_signature", side_effect=fail_once):
                failed_over = indexer.snapshot(root)
            during_rollback = indexer.snapshot(root)

        self.assertEqual(set(failed_over.latest_results), {"one@example.test"})
        self.assertTrue(failed_over.metrics["rollback_active"])
        self.assertEqual(
            failed_over.metrics["rollback_reason"],
            "result_directory_scan_failed",
        )
        self.assertFalse(during_rollback.metrics["cache_active"])
        self.assertTrue(during_rollback.metrics["rollback_active"])
        self.assertEqual(during_rollback.metrics["files_read"], 1)
        self.assertNotIn("private scan path", json.dumps(failed_over.metrics))


if __name__ == "__main__":
    unittest.main()
