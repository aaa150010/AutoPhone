from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from mac_overrides.mailbox_priority_runtime import (
    LEASE_OWNER_FIELD,
    MailboxNextBatchPriorityStore,
    release_owned_batch_leases,
    reserve_available_batch,
)


class FakeAtomicPool:
    def __init__(self, entries):
        self.entries = list(entries)
        self.state = {"items": {}}
        self.update_calls = 0

    def _update(self, callback):
        self.update_calls += 1
        return callback(self.state, self.entries)

    def _item(self, state, entry):
        return state["items"].setdefault(
            entry.source_row,
            {"status": "available", "history": []},
        )

    @staticmethod
    def _history(item, reason):
        item["history"].append(reason)


class FailingAtomicPool(FakeAtomicPool):
    def _update(self, callback):
        self.update_calls += 1
        callback(self.state, self.entries)
        raise OSError("pool state fsync failed")


class MailboxNextBatchPriorityStoreTests(unittest.TestCase):
    def test_active_run_imports_are_fifo_first_in_next_batch_then_consumed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = MailboxNextBatchPriorityStore(root, now=lambda: 100)
            previous_failures = [
                SimpleNamespace(source_row=f"failed-{index}")
                for index in range(1, 51)
            ]
            imported = [f"new-{index}" for index in range(1, 21)]
            imported_entries = [SimpleNamespace(source_row=row) for row in imported]

            self.assertEqual(store.mark_imported(imported[:8]), 8)
            self.assertEqual(store.mark_imported(imported[8:]), 12)
            ordered = store.prioritize(previous_failures + imported_entries)

            self.assertEqual([item.source_row for item in ordered[:20]], imported)
            self.assertEqual(
                [item.source_row for item in ordered[20:]],
                [item.source_row for item in previous_failures],
            )
            for entry in ordered[:20]:
                self.assertTrue(store.consume(entry.source_row))
            self.assertEqual(store.snapshot()["pending"], 0)

    def test_priority_survives_restart_and_supports_any_import_count(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = MailboxNextBatchPriorityStore(root, now=lambda: 200)
            first.mark_imported(["new-a", "new-b", "new-c"])

            recovered = MailboxNextBatchPriorityStore(root, now=lambda: 300)
            entries = [
                SimpleNamespace(source_row="old-returned"),
                SimpleNamespace(source_row="new-c"),
                SimpleNamespace(source_row="new-a"),
                SimpleNamespace(source_row="new-b"),
            ]
            ordered = recovered.prioritize(entries)

            self.assertEqual(
                [item.source_row for item in ordered],
                ["new-a", "new-b", "new-c", "old-returned"],
            )
            recovered.consume("new-a")
            again = MailboxNextBatchPriorityStore(root)
            self.assertEqual(again.snapshot()["pending"], 2)

    def test_prune_removes_deleted_rows_without_storing_source_content(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = MailboxNextBatchPriorityStore(root)
            store.mark_imported(["private@example.test----secret", "kept-row"])

            self.assertEqual(store.prune(["kept-row"]), 1)

            payload = store.path.read_text(encoding="utf-8")
            self.assertNotIn("private@example.test", payload)
            self.assertNotIn("secret", payload)
            self.assertEqual(store.snapshot()["pending"], 1)

    def test_atomic_batch_callback_sees_exact_members_before_any_lease_mutation(self):
        entries = [SimpleNamespace(source_row=f"row-{index}") for index in range(1, 6)]
        pool = FakeAtomicPool(entries)
        snapshots = []

        selected = reserve_available_batch(
            pool,
            3,
            before_reserve=lambda chosen: snapshots.append(
                (
                    [entry.source_row for entry in chosen],
                    [
                        pool._item(pool.state, entry)["status"]
                        for entry in chosen
                    ],
                )
            ),
        )

        self.assertEqual(
            snapshots,
            [(["row-1", "row-2", "row-3"], ["available"] * 3)],
        )
        self.assertEqual([entry.source_row for entry in selected], ["row-1", "row-2", "row-3"])
        self.assertEqual(
            [pool._item(pool.state, entry)["status"] for entry in selected],
            ["leased"] * 3,
        )
        self.assertEqual(
            [pool._item(pool.state, entry)["history"] for entry in selected],
            [["leased"]] * 3,
        )

    def test_atomic_batch_does_not_lease_when_manifest_begin_fails(self):
        entries = [SimpleNamespace(source_row=f"row-{index}") for index in range(1, 4)]
        pool = FakeAtomicPool(entries)

        with self.assertRaisesRegex(RuntimeError, "manifest unavailable"):
            reserve_available_batch(
                pool,
                2,
                before_reserve=lambda _chosen: (_ for _ in ()).throw(
                    RuntimeError("manifest unavailable")
                ),
            )

        self.assertEqual(
            [pool._item(pool.state, entry)["status"] for entry in entries],
            ["available"] * 3,
        )

    def test_pool_commit_failure_notifies_manifest_rollback(self):
        entries = [SimpleNamespace(source_row=f"row-{index}") for index in range(1, 4)]
        pool = FailingAtomicPool(entries)
        events = []

        with self.assertRaisesRegex(OSError, "pool state fsync failed"):
            reserve_available_batch(
                pool,
                2,
                before_reserve=lambda chosen: events.append(
                    ("prepared", [entry.source_row for entry in chosen])
                ),
                on_reserve_failed=lambda chosen, _error: events.append(
                    ("rolled_back", [entry.source_row for entry in chosen])
                ),
            )

        self.assertEqual(
            events,
            [
                ("prepared", ["row-1", "row-2"]),
                ("rolled_back", ["row-1", "row-2"]),
            ],
        )

    def test_manifest_commit_failure_releases_just_committed_owned_leases(self):
        entries = [
            SimpleNamespace(source_row=f"row-{index}", line_no=index)
            for index in range(1, 4)
        ]
        pool = FakeAtomicPool(entries)
        rolled_back = []

        with self.assertRaisesRegex(OSError, "manifest commit failed"):
            reserve_available_batch(
                pool,
                2,
                lease_owner_batch_id="batch-commit-failed",
                after_reserve=lambda _chosen: (_ for _ in ()).throw(
                    OSError("manifest commit failed")
                ),
                on_reserve_failed=lambda chosen, _error: rolled_back.extend(chosen),
            )

        self.assertEqual(rolled_back, entries[:2])
        self.assertEqual(
            [pool._item(pool.state, entry)["status"] for entry in entries],
            ["available", "available", "available"],
        )

    def test_restart_releases_only_exact_rows_still_owned_by_interrupted_batch(self):
        entries = [
            SimpleNamespace(source_row="same@example.test----first", line_no=1),
            SimpleNamespace(source_row="same@example.test----second", line_no=2),
            SimpleNamespace(source_row="other@example.test----third", line_no=3),
        ]
        pool = FakeAtomicPool(entries)
        reserve_available_batch(pool, 2, lease_owner_batch_id="batch-interrupted")
        members = [
            {
                "row_id": hashlib.sha256(entry.source_row.encode()).hexdigest(),
                "line_no": entry.line_no,
            }
            for entry in entries[:2]
        ]

        result = release_owned_batch_leases(
            pool,
            "batch-interrupted",
            members,
            now=lambda: 500,
        )

        self.assertEqual(result["released"], 2)
        self.assertEqual(pool.update_calls, 2)
        self.assertEqual(
            [pool._item(pool.state, entry)["status"] for entry in entries],
            ["available", "available", "available"],
        )
        self.assertEqual(pool._item(pool.state, entries[0])[LEASE_OWNER_FIELD], "")

    def test_restart_does_not_release_released_row_released_to_a_new_batch(self):
        entry = SimpleNamespace(source_row="owner@example.test----secret", line_no=7)
        pool = FakeAtomicPool([entry])
        reserve_available_batch(pool, 1, lease_owner_batch_id="batch-old")
        pool._item(pool.state, entry)[LEASE_OWNER_FIELD] = "batch-new"
        member = {
            "row_id": hashlib.sha256(entry.source_row.encode()).hexdigest(),
            "line_no": 7,
        }

        result = release_owned_batch_leases(pool, "batch-old", [member])

        self.assertEqual(result["released"], 0)
        self.assertEqual(result["ownership_mismatch"], 1)
        self.assertEqual(pool._item(pool.state, entry)["status"], "leased")

    def test_restart_requires_row_fingerprint_and_line_number_to_match(self):
        entry = SimpleNamespace(source_row="exact@example.test----secret", line_no=4)
        pool = FakeAtomicPool([entry])
        reserve_available_batch(pool, 1, lease_owner_batch_id="batch-exact")
        wrong_line = {
            "row_id": hashlib.sha256(entry.source_row.encode()).hexdigest(),
            "line_no": 5,
        }

        result = release_owned_batch_leases(pool, "batch-exact", [wrong_line])

        self.assertEqual(result["released"], 0)
        self.assertEqual(result["missing"], 1)
        self.assertEqual(pool._item(pool.state, entry)["status"], "leased")


if __name__ == "__main__":
    unittest.main()
