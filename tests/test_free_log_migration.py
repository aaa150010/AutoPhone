from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.free_log_migration import cleanup_legacy_logs, MIGRATION_KEY


class FreeLogMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-log-cleanup-")
        self.root = Path(self.temp_dir.name) / "free_register"
        self.root.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_cleanup_deletes_only_legacy_json_and_is_idempotent(self) -> None:
        (self.root / "logs.json").write_text("[]", encoding="utf-8")
        task_dir = self.root / "task_logs"
        task_dir.mkdir()
        (task_dir / "abc.json").write_text("[]", encoding="utf-8")
        (task_dir / "keep.txt").write_text("keep", encoding="utf-8")
        (self.root / "free_mailbox_state.json").write_text(
            json.dumps({"rows": {"mail": {"status": "available"}}}),
            encoding="utf-8",
        )
        result = cleanup_legacy_logs(self.root)
        self.assertFalse(result.failed)
        self.assertEqual(result.deleted, 2)
        self.assertTrue(result.marker_written)
        self.assertFalse((self.root / "logs.json").exists())
        self.assertFalse((task_dir / "abc.json").exists())
        self.assertTrue((task_dir / "keep.txt").exists())
        self.assertTrue((self.root / "free_mailbox_state.json").exists())

        again = cleanup_legacy_logs(self.root)
        self.assertTrue(again.already_done)
        self.assertEqual(again.deleted, 0)

        connection = sqlite3.connect(self.root / "free_register.sqlite3")
        try:
            row = connection.execute(
                "SELECT value FROM storage_meta WHERE key=?", (MIGRATION_KEY,)
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(row[0], "1")

    def test_dry_run_does_not_delete_or_write_marker(self) -> None:
        path = self.root / "logs.json"
        path.write_text("[]", encoding="utf-8")
        result = cleanup_legacy_logs(self.root, dry_run=True)
        self.assertFalse(result.failed)
        self.assertEqual(result.skipped, 1)
        self.assertTrue(path.exists())
        self.assertFalse((self.root / "free_register.sqlite3").exists())

    def test_symlink_is_not_removed(self) -> None:
        target = self.root / "outside.json"
        target.write_text("[]", encoding="utf-8")
        link = self.root / "logs.json"
        link.symlink_to(target)
        result = cleanup_legacy_logs(self.root)
        self.assertFalse(result.failed)
        self.assertEqual(result.skipped, 1)
        self.assertFalse(result.marker_written)
        self.assertTrue(link.is_symlink())
        self.assertTrue(target.exists())

    def test_symlink_does_not_mark_complete_and_retry_after_replacement(self) -> None:
        target = self.root / "outside.json"
        target.write_text("[]", encoding="utf-8")
        link = self.root / "logs.json"
        link.symlink_to(target)

        first = cleanup_legacy_logs(self.root)

        self.assertFalse(first.failed)
        self.assertEqual(first.skipped, 1)
        self.assertFalse(first.marker_written)
        self.assertFalse((self.root / "free_register.sqlite3").exists())

        # Once the operator replaces the unsafe link with a regular legacy
        # file, a subsequent invocation must perform the pending cleanup.
        link.unlink()
        link.write_text("[]", encoding="utf-8")
        second = cleanup_legacy_logs(self.root)

        self.assertFalse(second.failed)
        self.assertEqual(second.deleted, 1)
        self.assertTrue(second.marker_written)
        self.assertFalse(link.exists())
        self.assertTrue(cleanup_legacy_logs(self.root).already_done)

    def test_symlink_task_directory_is_not_followed(self) -> None:
        outside = Path(self.temp_dir.name) / "outside-task-logs"
        outside.mkdir()
        outside_file = outside / "must-keep.json"
        outside_file.write_text("[]", encoding="utf-8")
        (self.root / "task_logs").symlink_to(outside, target_is_directory=True)

        result = cleanup_legacy_logs(self.root)

        self.assertFalse(result.failed)
        self.assertEqual(result.deleted, 0)
        self.assertEqual(result.skipped, 1)
        self.assertTrue(outside_file.exists())
        self.assertTrue((self.root / "task_logs").is_symlink())

    def test_task_directory_inspection_failure_does_not_mark_complete(self) -> None:
        task_dir = self.root / "task_logs"
        task_dir.mkdir()
        (task_dir / "legacy.json").write_text("[]", encoding="utf-8")

        with patch.object(Path, "iterdir", side_effect=PermissionError("denied")):
            result = cleanup_legacy_logs(self.root)

        self.assertTrue(result.failed)
        self.assertEqual(result.error_type, "PermissionError")
        self.assertFalse(result.marker_written)
        self.assertFalse((self.root / "free_register.sqlite3").exists())
        self.assertTrue((task_dir / "legacy.json").exists())

    def test_broken_json_symlink_does_not_mark_complete(self) -> None:
        task_dir = self.root / "task_logs"
        task_dir.mkdir()
        link = task_dir / "missing.json"
        link.symlink_to(self.root / "missing-target.json")

        result = cleanup_legacy_logs(self.root)

        self.assertFalse(result.failed)
        self.assertEqual(result.skipped, 1)
        self.assertFalse(result.marker_written)
        self.assertTrue(link.is_symlink())
        self.assertFalse((self.root / "free_register.sqlite3").exists())

    def test_rejects_non_isolated_directory(self) -> None:
        with self.assertRaises(ValueError):
            cleanup_legacy_logs(self.root.parent)

    def test_rejects_symlinked_cleanup_root(self) -> None:
        outside = Path(self.temp_dir.name) / "external-free-register"
        outside.mkdir()
        legacy = outside / "logs.json"
        legacy.write_text("[]", encoding="utf-8")
        self.root.rmdir()
        link = Path(self.temp_dir.name) / "free_register"
        link.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(ValueError):
            cleanup_legacy_logs(link)
        self.assertTrue(legacy.exists())

    def test_cleanup_failure_emits_structured_system_event_when_store_is_given(self) -> None:
        path = self.root / "logs.json"
        path.write_text("[]", encoding="utf-8")
        diagnostics = DiagnosticStore(self.root / "diagnostics")
        with patch.object(Path, "unlink", side_effect=OSError("permission denied")):
            result = cleanup_legacy_logs(self.root, diagnostic_store=diagnostics)
        self.assertTrue(result.failed)
        incidents = diagnostics.search({"node_code": "free_log_cleanup"})
        self.assertEqual(len(incidents), 1)
        detail = diagnostics.incident(incidents[0]["incident_id"])
        assert detail is not None
        # Cleanup is an associated system event, never the business root
        # cause. Its structured failure remains available on the timeline.
        self.assertEqual(detail["first_error_code"], "")
        self.assertEqual(
            detail["events"][0]["failure"]["error_code"],
            "free_log_cleanup_failed",
        )
        self.assertNotIn(str(self.root), str(detail))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
