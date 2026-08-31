from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from mac_overrides.free_register.task_repository import (
    FreeTaskRepository,
    TaskConflictError,
)
from mac_overrides.free_storage import FreeSQLiteStore


class FreeTaskRepositoryTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="free-task-repository-")
        self.root = Path(self.tempdir.name)
        self.storage = FreeSQLiteStore(self.root)
        self.repository = FreeTaskRepository(self.root, storage=self.storage)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_transition_is_atomic_and_preserves_existing_payload(self) -> None:
        self.repository.create(
            {
                "task_id": "task-atomic",
                "status": "queued",
                "stage": "entry",
                "progress": {"completed": 0},
            }
        )

        transition = self.repository.transition(
            "task-atomic",
            "running",
            expected_revision=0,
            expected_statuses=("queued",),
            updates={"attempt": 1},
        )

        self.assertEqual(transition.previous_status, "queued")
        self.assertEqual(transition.status, "running")
        self.assertEqual(transition.revision, 1)
        persisted = self.storage.get_task("task-atomic")
        self.assertIsNotNone(persisted)
        assert persisted is not None
        self.assertEqual(persisted["status"], "running")
        self.assertEqual(persisted["payload"]["stage"], "entry")
        self.assertEqual(persisted["payload"]["progress"], {"completed": 0})
        self.assertEqual(persisted["payload"]["attempt"], 1)

    def test_transition_rejects_status_race_inside_store_transaction(self) -> None:
        self.repository.create(
            {"task_id": "task-race", "status": "queued", "stage": "entry"}
        )
        stale = self.repository.get("task-race")
        self.assertIsNotNone(stale)
        assert stale is not None

        # Another worker advances the task after the caller's snapshot.  The
        # repository must enforce expected_statuses in the same transaction as
        # the write; a stale get/save pair would incorrectly accept this.
        changed = self.storage.transition_task(
            "task-race",
            "queued",
            "running",
            payload_patch={"worker": "other"},
            expected_revision=stale.revision,
        )
        self.assertIsNotNone(changed)

        original_get = self.repository.get
        self.repository.get = lambda _task_id: copy.deepcopy(stale)  # type: ignore[method-assign]
        try:
            with self.assertRaises(TaskConflictError):
                self.repository.transition(
                    "task-race",
                    "success",
                    expected_revision=1,
                    expected_statuses=("queued",),
                    updates={"worker": "stale"},
                )
        finally:
            self.repository.get = original_get  # type: ignore[method-assign]

        current = self.storage.get_task("task-race")
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current["status"], "running")
        self.assertEqual(current["payload"]["worker"], "other")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
