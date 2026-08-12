from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mac_overrides.run_batch_runtime import RunBatchManifestStore


def settings(root: Path, batch_id: str, *, target: int) -> dict:
    return {
        "batch_id": batch_id,
        "batch_started_at": 1_785_824_800,
        "run_mode": "register",
        "target_count": target,
        "results_dir": str(root / "results"),
    }


def members(count: int) -> list[dict]:
    return [
        {
            "task_id": f"T{ordinal:03d}-batch",
            "ordinal": ordinal,
            "row_id": "",
            "line_no": ordinal,
        }
        for ordinal in range(1, count + 1)
    ]


def result_file(root: Path, batch_id: str, ordinal: int, status: str = "success") -> None:
    target = root / "results" / f"T{ordinal:03d}-batch_result.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "task_id": f"T{ordinal:03d}-batch",
                "batch_id": batch_id,
                "status": status,
                "result": {"batch_id": batch_id},
            }
        ),
        encoding="utf-8",
    )


class RunBatchManifestStoreTests(unittest.TestCase):
    def test_active_batch_appends_arbitrary_members_and_expands_target_atomically(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = RunBatchManifestStore(root, recover_pending=False, now=lambda: 180)
            store.begin(settings(root, "batch-append", target=1), target=1, members=members(1))

            store.append_members("batch-append", members(5)[1:])
            batch = store.get("batch-append")

            self.assertEqual(batch["target"], 5)
            self.assertEqual(batch["counts"]["target"], 5)
            self.assertEqual(batch["counts"]["reserved"], 4)
            self.assertEqual([item["ordinal"] for item in batch["members"]], [1, 2, 3, 4, 5])
            self.assertEqual({item["status"] for item in batch["members"][1:]}, {"queued"})

    def test_prepared_manifest_can_be_committed_or_removed_without_fake_results(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = RunBatchManifestStore(root, recover_pending=False, now=lambda: 150)
            prepared = settings(root, "batch-prepared", target=2)

            store.prepare(prepared, target=2, members=members(2))
            self.assertEqual(store.get("batch-prepared")["status"], "preparing")
            store.rollback_prepared("batch-prepared")

            with self.assertRaises(KeyError):
                store.get("batch-prepared")
            self.assertFalse((root / "results").exists())

            store.prepare(prepared, target=2, members=members(2))
            committed = store.commit_prepared("batch-prepared")
            self.assertEqual(committed["status"], "active")

    def test_arbitrary_target_is_one_shared_batch_and_never_persists_credentials(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = RunBatchManifestStore(root, recover_pending=False, now=lambda: 200)
            config = settings(root, "batch-seven", target=7)
            store.begin(config, target=7, members=members(7))
            for ordinal in range(1, 8):
                task_id = f"T{ordinal:03d}-batch"
                store.reserve(
                    "batch-seven",
                    task_id,
                    row_identity=f"private-{ordinal}@example.test----password-{ordinal}",
                    line_no=ordinal,
                )
                store.mark_started(task_id)
                result_file(root, "batch-seven", ordinal)

            batch = store.finalize("batch-seven")

            self.assertEqual(batch["batch_id"], "batch-seven")
            self.assertEqual(batch["batch_started_at"], 1_785_824_800)
            self.assertEqual(batch["counts"]["target"], 7)
            self.assertEqual(batch["counts"]["persisted"], 7)
            self.assertEqual(batch["counts"]["success"], 7)
            self.assertEqual(batch["counts"]["missing"], 0)
            self.assertEqual(
                [item["ordinal"] for item in batch["members"]],
                list(range(1, 8)),
            )
            persisted = store.manifest_path.read_text(encoding="utf-8")
            self.assertNotIn("@example.test", persisted)
            self.assertNotIn("password", persisted)

    def test_hundred_member_manifest_reconciles_two_missing_results(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = RunBatchManifestStore(root, recover_pending=False, now=lambda: 300)
            config = settings(root, "batch-one-hundred", target=100)
            store.begin(config, target=100, members=members(100))
            for ordinal in range(1, 101):
                store.reserve(
                    "batch-one-hundred",
                    f"T{ordinal:03d}-batch",
                    row_identity=f"mailbox-row-{ordinal}",
                )
                if ordinal <= 98:
                    result_file(root, "batch-one-hundred", ordinal)

            batch = store.finalize("batch-one-hundred")

            self.assertEqual(batch["counts"]["target"], 100)
            self.assertEqual(batch["counts"]["reserved"], 100)
            self.assertEqual(batch["counts"]["terminal"], 100)
            self.assertEqual(batch["counts"]["persisted"], 100)
            self.assertEqual(batch["counts"]["success"], 98)
            self.assertEqual(batch["counts"]["failed"], 2)
            self.assertEqual(batch["counts"]["missing"], 2)
            missing = [item for item in batch["members"] if item["reconciled_missing"]]
            self.assertEqual([item["ordinal"] for item in missing], [99, 100])
            synthetic = json.loads(
                (root / "results" / "T099-batch_batch_recovery.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(synthetic["batch_id"], "batch-one-hundred")
            self.assertEqual(synthetic["ordinal"], 99)
            self.assertEqual(
                synthetic["failure"]["node_code"],
                "batch_member_missing_terminal",
            )

    def test_finalize_is_idempotent_after_batch_is_complete(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = []
            store = RunBatchManifestStore(
                root,
                recover_pending=False,
                now=lambda: 350,
                log_fn=lambda message, level: logs.append((message, level)),
            )
            config = settings(root, "batch-idempotent", target=1)
            store.begin(config, target=1, members=members(1))
            result_file(root, "batch-idempotent", 1)

            first = store.finalize("batch-idempotent")
            second = store.finalize("batch-idempotent")

            self.assertEqual(second, first)
            self.assertEqual(len(logs), 1)

    def test_restart_recovers_active_batch_and_preserves_member_identity(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            lease_releases = []
            first = RunBatchManifestStore(root, recover_pending=False, now=lambda: 400)
            config = settings(root, "batch-restart", target=3)
            first.begin(config, target=3, members=members(3))
            first.reserve("batch-restart", "T001-batch", row_identity="row-one")
            first.mark_started("T001-batch")
            result_file(root, "batch-restart", 1)

            recovered = RunBatchManifestStore(
                root,
                recover_pending=True,
                now=lambda: 500,
                lease_releaser=lambda batch_id, rows: (
                    lease_releases.append((batch_id, [dict(row) for row in rows]))
                    or {"released": 1, "ownership_mismatch": 0}
                ),
            )
            batch = recovered.get("batch-restart")

            self.assertEqual(len(lease_releases), 1)
            self.assertEqual(lease_releases[0][0], "batch-restart")
            self.assertEqual(len(lease_releases[0][1]), 3)
            self.assertEqual(batch["status"], "complete")
            self.assertEqual(batch["counts"]["target"], 3)
            self.assertEqual(batch["counts"]["success"], 1)
            self.assertEqual(batch["counts"]["failed"], 2)
            self.assertEqual(batch["counts"]["missing"], 2)
            self.assertEqual(
                [item["task_id"] for item in batch["members"]],
                ["T001-batch", "T002-batch", "T003-batch"],
            )
            reloaded = RunBatchManifestStore(root, recover_pending=False)
            self.assertEqual(
                reloaded.get("batch-restart")["counts"],
                batch["counts"],
            )

    def test_restart_passes_private_custom_pool_paths_to_new_releaser_signature(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            custom_pool = root / "custom" / "accounts.txt"
            custom_state = root / "custom" / "accounts-state.json"
            config = settings(root, "batch-custom-pool", target=1)
            config.update(pool_path=str(custom_pool), state_path=str(custom_state))
            first = RunBatchManifestStore(root, recover_pending=False, now=lambda: 450)
            first.begin(config, target=1, members=members(1))
            calls = []

            recovered = RunBatchManifestStore(
                root,
                recover_pending=True,
                now=lambda: 500,
                lease_releaser=lambda batch_id, rows, *, pool_path, state_path: calls.append(
                    (batch_id, len(list(rows)), pool_path, state_path)
                ) or {"released": 0, "ownership_mismatch": 0},
            )

            self.assertEqual(
                calls,
                [
                    (
                        "batch-custom-pool",
                        1,
                        str(custom_pool.resolve()),
                        str(custom_state.resolve()),
                    )
                ],
            )
            public = recovered.get("batch-custom-pool")
            self.assertNotIn("pool_path", public)
            self.assertNotIn("state_path", public)
            persisted = json.loads(recovered.manifest_path.read_text(encoding="utf-8"))
            stored = persisted["batches"][0]
            self.assertIn("pool_path", stored)
            self.assertIn("state_path", stored)

    def test_restart_discards_prepared_batch_after_releasing_commit_window_leases(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = RunBatchManifestStore(root, recover_pending=False, now=lambda: 455)
            first.prepare(
                settings(root, "batch-commit-window", target=1),
                target=1,
                members=members(1),
            )
            calls = []

            recovered = RunBatchManifestStore(
                root,
                recover_pending=True,
                now=lambda: 500,
                lease_releaser=lambda batch_id, rows: calls.append(
                    (batch_id, len(list(rows)))
                ) or {"released": 1, "ownership_mismatch": 0},
            )

            self.assertEqual(calls, [("batch-commit-window", 1)])
            with self.assertRaises(KeyError):
                recovered.get("batch-commit-window")
            self.assertEqual(recovered.records(), [])

    def test_restart_keeps_legacy_two_argument_lease_releaser_compatible(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = RunBatchManifestStore(root, recover_pending=False, now=lambda: 460)
            first.begin(settings(root, "batch-legacy-releaser", target=1), target=1, members=members(1))
            calls = []

            RunBatchManifestStore(
                root,
                recover_pending=True,
                now=lambda: 500,
                lease_releaser=lambda batch_id, rows: calls.append(
                    (batch_id, len(list(rows)))
                ) or {"released": 0, "ownership_mismatch": 0},
            )

            self.assertEqual(calls, [("batch-legacy-releaser", 1)])

    def test_latest_failed_bindings_come_from_manifest_members(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = RunBatchManifestStore(root, recover_pending=False, now=lambda: 600)
            rows = members(2)
            rows[0]["row_id"] = "a" * 64
            rows[1]["row_id"] = "b" * 64
            config = settings(root, "batch-filter", target=2)
            store.begin(config, target=2, members=rows)
            store.reserve("batch-filter", "T001-batch", row_identity="a" * 64, line_no=1)
            store.reserve("batch-filter", "T002-batch", row_identity="b" * 64, line_no=2)
            result_file(root, "batch-filter", 1, "success")
            result_file(root, "batch-filter", 2, "retryable_infra")
            store.finalize("batch-filter")

            failed = store.latest_row_bindings(failed_only=True)

            self.assertEqual(len(failed), 1)
            self.assertEqual(failed[0]["row_id"], "b" * 64)
            self.assertEqual(failed[0]["batch_id"], "batch-filter")


if __name__ == "__main__":
    unittest.main()
