from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time
import unittest

from mac_overrides.free_register_runtime import FreeRegisterManager
from mac_overrides.free_storage import (
    FreeSQLiteStore,
    ManagerOwnerConflict,
)
from mac_overrides.free_storage_adapters import build_free_storage_adapters


class FreeManagerOwnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="gptphone-free-owner-")
        self.root = Path(self.tempdir.name) / "free_register"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_owner_is_exclusive_and_epoch_fences_stale_writer(self) -> None:
        store = FreeSQLiteStore(self.root)
        first = store.acquire_manager_owner("manager-a", pid=os.getpid())

        with self.assertRaises(ManagerOwnerConflict):
            store.acquire_manager_owner("manager-b", pid=os.getpid())

        self.assertTrue(store.manager_owner_is_current("manager-a", first["epoch"]))
        self.assertFalse(store.renew_manager_owner("manager-a", first["epoch"] + 1))

        # Simulate a dead process after the TTL.  The replacement receives a
        # new epoch, so callbacks from the stale process cannot renew/release
        # the new owner's fence.
        second = store.acquire_manager_owner(
            "manager-b",
            pid=999_999_999,
            now=time.time() + 120,
        )
        self.assertGreater(second["epoch"], first["epoch"])
        self.assertFalse(store.manager_owner_is_current("manager-a", first["epoch"]))
        self.assertFalse(store.release_manager_owner("manager-a", first["epoch"]))
        self.assertTrue(store.manager_owner_is_current("manager-b", second["epoch"]))

    def test_live_owner_prevents_recovery_rewrite_on_new_manager(self) -> None:
        adapters = build_free_storage_adapters(self.root)
        adapters.tasks.save(
            {
                "active-task": {
                    "task_id": "active-task",
                    "status": "running",
                    "row_id": "row-active",
                    "batch_id": "batch-old",
                }
            }
        )
        owner = adapters.storage.acquire_manager_owner(
            "old-manager", pid=os.getpid()
        )

        manager = FreeRegisterManager(
            self.root,
            storage_adapters=adapters,
            runner=lambda *_args, **_kwargs: {},
        )

        self.assertTrue(manager._runtime_fenced)
        self.assertEqual(manager._tasks["active-task"]["status"], "running")
        durable = adapters.storage.get_task("active-task")
        self.assertIsNotNone(durable)
        self.assertEqual(durable["status"], "running")
        self.assertTrue(adapters.storage.manager_owner_is_current("old-manager", owner["epoch"]))

    def test_stale_manager_cannot_save_after_takeover(self) -> None:
        adapters = build_free_storage_adapters(self.root)
        manager = FreeRegisterManager(
            self.root,
            storage_adapters=adapters,
            runner=lambda *_args, **_kwargs: {},
        )
        manager._acquire_runtime_owner()
        manager._tasks["fenced-task"] = {
            "task_id": "fenced-task",
            "status": "running",
            "row_id": "row-fenced",
        }
        self.assertTrue(manager._save_tasks_safely("initial owner save"))
        old_epoch = manager._manager_owner_epoch

        replacement = adapters.storage.acquire_manager_owner(
            "replacement-manager",
            pid=999_999_999,
            now=time.time() + 120,
        )
        self.assertGreater(replacement["epoch"], old_epoch)
        manager._tasks["fenced-task"]["status"] = "failed"
        self.assertFalse(manager._save_tasks_safely("stale callback"))
        durable = adapters.storage.get_task("fenced-task")
        self.assertIsNotNone(durable)
        self.assertEqual(durable["status"], "running")


if __name__ == "__main__":
    unittest.main()
