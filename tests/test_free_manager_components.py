from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.free_register.manager import build_manager_components
from mac_overrides.free_register_runtime import FreeRegisterManager
from mac_overrides.free_storage import FreeSQLiteStore
from mac_overrides.free_storage_adapters import build_free_storage_adapters


class FreeManagerDiagnosticsIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-manager-")
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_diagnostic_backed_manager_uses_structured_logs_and_cleans_legacy_files(self) -> None:
        free_root = self.root / "free_register"
        free_root.mkdir()
        (free_root / "logs.json").write_text("[]", encoding="utf-8")
        task_dir = free_root / "task_logs"
        task_dir.mkdir()
        (task_dir / "task.json").write_text("[]", encoding="utf-8")
        diagnostics = DiagnosticStore(self.root / "diagnostics")

        manager = FreeRegisterManager(free_root, diagnostic_store=diagnostics)
        self.assertFalse((free_root / "logs.json").exists())
        self.assertFalse((free_root / "task_logs" / "task.json").exists())
        self.assertFalse(manager.log_store.legacy_projection)
        self.assertTrue(manager.log_store.legacy_cleanup_result.marker_written)

        manager._log(
            "结构化阶段日志",
            "info",
            task_id="free-manager-task",
            node_code="free_entry",
            node_label="进入 Free",
        )
        self.assertFalse((free_root / "logs.json").exists())
        events = diagnostics.search({"task_id": "free-manager-task"})
        self.assertEqual(len(events), 1)
        self.assertEqual(
            manager.log_store.snapshot("free-manager-task")[0]["node_code"],
            "free_entry",
        )

    def test_component_builder_passes_diagnostic_store_to_cleanup_and_writer(self) -> None:
        free_root = self.root / "free_register"
        free_root.mkdir()
        (free_root / "logs.json").write_text("[]", encoding="utf-8")
        diagnostics = DiagnosticStore(self.root / "diagnostics")

        components = build_manager_components(free_root, diagnostic_store=diagnostics)
        self.assertIs(components.diagnostic_writer.store, diagnostics)
        self.assertEqual(components.log_cleanup.deleted, 1)
        self.assertFalse((free_root / "logs.json").exists())

    def test_package_exports_legacy_manager_lazily(self) -> None:
        import mac_overrides.free_register as package

        self.assertIs(package.FreeRegisterManager, FreeRegisterManager)
        self.assertIn("FreeRegisterManager", dir(package))
        namespace: dict[str, object] = {}
        exec("from mac_overrides.free_register import *", namespace)
        self.assertIs(namespace["FreeRegisterManager"], FreeRegisterManager)

    def test_component_builder_does_not_clean_through_symlinked_root(self) -> None:
        external_parent = self.root / "external"
        external_parent.mkdir()
        target = external_parent / "free_register"
        target.mkdir()
        protected = target / "logs.json"
        protected.write_text("[]", encoding="utf-8")
        lexical_root = self.root / "free_register"
        lexical_root.symlink_to(target, target_is_directory=True)

        diagnostics = DiagnosticStore(self.root / "diagnostics")
        components = build_manager_components(lexical_root, diagnostic_store=diagnostics)

        self.assertTrue(components.log_cleanup["failed"])
        self.assertEqual(components.log_cleanup["error_type"], "ValueError")
        self.assertTrue(protected.exists())

    def test_manager_without_diagnostics_keeps_legacy_callback_storage(self) -> None:
        manager = FreeRegisterManager(self.root)
        manager._log("旧兼容日志", "info")
        self.assertTrue(manager.log_store.legacy_projection)
        self.assertTrue((self.root / "logs.json").exists())

    def test_free_register_manager_uses_shared_sqlite_adapters_and_syncs_revision(self) -> None:
        free_root = self.root / "free_register"
        free_root.mkdir()
        adapters = build_free_storage_adapters(free_root)
        manager = FreeRegisterManager(free_root, storage_adapters=adapters)

        self.assertIs(manager.storage, adapters.storage)
        self.assertIs(manager.pool, adapters.mailboxes)
        self.assertIs(manager.proxies, adapters.proxies)
        self.assertIs(manager.task_store, adapters.tasks)
        self.assertIsNotNone(manager.task_repository)
        self.assertEqual(manager.storage.path.name, "free_register.sqlite3")

        task = {"task_id": "sqlite-task", "status": "queued", "stage": "initial"}
        manager._tasks["sqlite-task"] = task
        self.assertTrue(manager._save_tasks_safely("集成测试首写"))
        first_revision = int(task["revision"])
        self.assertEqual(first_revision, 0)

        task["status"] = "running"
        task["stage"] = "transport"
        self.assertTrue(manager._save_tasks_safely("集成测试二写"))
        self.assertGreater(int(task["revision"]), first_revision)
        persisted = FreeSQLiteStore(free_root).get_task("sqlite-task")
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted["status"], "running")
        self.assertEqual(int(persisted["revision"]), int(task["revision"]))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
