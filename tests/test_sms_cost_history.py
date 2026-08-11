import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import mac_overrides.sms_cost_history as sms_cost_history
from mac_overrides.sms_cost_history import (
    INCREMENTAL_ENVIRONMENT_VARIABLE,
    SmsCostHistoryIndex,
    attach_task_sms_cost,
    note_persisted_result,
    with_historical_sms_cost,
)


class SmsCostHistoryIndexTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = TemporaryDirectory()
        self.data_dir = Path(self.tempdir.name)
        self.results_dir = self.data_dir / "results"
        self.results_dir.mkdir()
        (self.data_dir / "settings.json").write_text(
            json.dumps({"results_dir": str(self.results_dir)}),
            encoding="utf-8",
        )
        self.index = SmsCostHistoryIndex(
            self.data_dir,
            reconcile_seconds=0,
            incremental_enabled=True,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def write_result(self, name, value):
        path = self.results_dir / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_aggregates_nested_legacy_and_explicit_zero_costs(self):
        self.write_result("nested.json", {"task_id": "T1", "result": {"sms_cost_cny": 1.25}})
        self.write_result("legacy.json", {"task_id": "T2", "sms_cost_cny": 0.75})
        self.write_result("zero.json", {"task_id": "T3", "result": {"sms_cost_cny": 0}})
        self.write_result("none.json", {"task_id": "T4", "result": {"sms_cost_cny": None}})
        self.write_result("negative.json", {"task_id": "T5", "result": {"sms_cost_cny": -1}})
        self.write_result("invalid.json", {"task_id": "T6", "result": {"sms_cost_cny": "nan"}})
        (self.results_dir / "broken.json").write_text("not-json", encoding="utf-8")

        self.assertEqual(
            self.index.snapshot(),
            {"account_count": 3, "total_cny": 2.0, "average_cny": 0.6667},
        )

    def test_latest_document_for_duplicate_task_wins(self):
        self.write_result(
            "older.json",
            {"task_id": "same", "created_at": 10, "result": {"sms_cost_cny": 1}},
        )
        self.write_result(
            "newer.json",
            {"task_id": "same", "created_at": 20, "result": {"sms_cost_cny": 2}},
        )

        self.assertEqual(self.index.snapshot()["total_cny"], 2.0)
        self.assertEqual(self.index.snapshot()["account_count"], 1)

    def test_same_email_in_distinct_tasks_counts_each_settlement(self):
        self.write_result(
            "first.json",
            {"task_id": "T1", "email": "same@example.test", "result": {"sms_cost_cny": 1}},
        )
        self.write_result(
            "second.json",
            {"task_id": "T2", "email": "same@example.test", "result": {"sms_cost_cny": 2}},
        )

        self.assertEqual(self.index.snapshot(), {
            "account_count": 2,
            "total_cny": 3.0,
            "average_cny": 1.5,
        })

    def test_incrementally_observes_updates_and_deletes(self):
        path = self.write_result("task.json", {"task_id": "T1", "result": {"sms_cost_cny": 1}})
        self.assertEqual(self.index.snapshot()["total_cny"], 1.0)

        path.write_text(
            json.dumps({"task_id": "T1", "result": {"sms_cost_cny": 2.5}}),
            encoding="utf-8",
        )
        self.index.record_path(path)
        self.assertEqual(self.index.snapshot()["total_cny"], 2.5)

        path.unlink()
        self.index.reconcile()
        self.assertEqual(self.index.snapshot(), {"account_count": 0, "total_cny": 0, "average_cny": 0})

    def test_repeated_public_snapshots_never_rescan_history(self):
        self.write_result("task.json", {"task_id": "T1", "result": {"sms_cost_cny": 1}})
        expected = self.index.snapshot()

        def unexpected_reconcile():
            raise AssertionError("public polling must not reconcile the results directory")

        self.index.reconcile = unexpected_reconcile
        self.assertEqual(self.index.snapshot(), expected)
        self.assertEqual(self.index.snapshot(), expected)

    def test_reconcile_reparses_only_changed_files(self):
        first = self.write_result("first.json", {"task_id": "T1", "result": {"sms_cost_cny": 1}})
        self.write_result("second.json", {"task_id": "T2", "result": {"sms_cost_cny": 2}})
        self.index.snapshot()
        parsed = []
        original_read = self.index._read_result

        def tracked_read(path, signature):
            parsed.append(path.name)
            return original_read(path, signature)

        self.index._read_result = tracked_read
        first.write_text(
            json.dumps({"task_id": "T1", "result": {"sms_cost_cny": 4}}),
            encoding="utf-8",
        )
        self.index.reconcile()

        self.assertEqual(parsed, ["first.json"])
        self.assertEqual(self.index.snapshot()["total_cny"], 6.0)

    def test_reconcile_does_not_reparse_unchanged_damaged_file(self):
        damaged = self.results_dir / "damaged.json"
        damaged.write_text("not-json", encoding="utf-8")
        self.index.snapshot()
        parsed = []
        original_read = self.index._read_result

        def tracked_read(path, signature):
            parsed.append(path.name)
            return original_read(path, signature)

        self.index._read_result = tracked_read
        self.index.reconcile()

        self.assertEqual(parsed, [])
        self.assertEqual(self.index.metrics()["tracked_files"], 1)

    def test_switches_to_custom_results_directory(self):
        self.write_result("old.json", {"task_id": "old", "result": {"sms_cost_cny": 1}})
        self.assertEqual(self.index.snapshot()["total_cny"], 1.0)
        custom = self.data_dir / "custom-results"
        custom.mkdir()
        (custom / "new.json").write_text(
            json.dumps({"task_id": "new", "result": {"sms_cost_cny": 3}}),
            encoding="utf-8",
        )
        (self.data_dir / "settings.json").write_text(
            json.dumps({"results_dir": str(custom)}),
            encoding="utf-8",
        )

        self.assertEqual(self.index.snapshot(), {"account_count": 1, "total_cny": 3.0, "average_cny": 3.0})

    def test_task_cost_attachment_preserves_existing_policy(self):
        class Ledger:
            def summary(self, task_id, exchange):
                self.called = (task_id, exchange)
                return {"sms_cost_cny": 1.2, "sms_cost_usd": 0.18, "sms_order_outcomes": []}

        ledger = Ledger()
        result = {}
        exchange = object()
        attach_task_sms_cost(result, "T1", ledger, exchange)

        self.assertEqual(ledger.called, ("T1", exchange))
        self.assertEqual(result["sms_cost_cny"], 1.2)

    def test_public_summary_includes_history_without_replacing_batch_fields(self):
        self.write_result("task.json", {"task_id": "T1", "result": {"sms_cost_cny": 1.5}})

        summary = with_historical_sms_cost({"success": 4, "sms_cost_cny": 0.5}, self.data_dir)

        self.assertEqual(summary["success"], 4)
        self.assertEqual(summary["sms_cost_cny"], 0.5)
        self.assertEqual(summary["sms_cost_history"], {
            "account_count": 1,
            "total_cny": 1.5,
            "average_cny": 1.5,
        })

    def test_incremental_mode_is_enabled_by_default_and_parses_false_values(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(SmsCostHistoryIndex(self.data_dir).incremental_enabled)
        for value in ("0", "false", "FALSE", "no", "off"):
            with self.subTest(value=value), patch.dict(
                os.environ,
                {INCREMENTAL_ENVIRONMENT_VARIABLE: value},
                clear=True,
            ):
                self.assertFalse(SmsCostHistoryIndex(self.data_dir).incremental_enabled)

    def test_disabled_incremental_mode_reconciles_every_snapshot(self):
        index = SmsCostHistoryIndex(
            self.data_dir,
            reconcile_seconds=30,
            incremental_enabled=False,
        )
        path = self.write_result("task.json", {"task_id": "T1", "result": {"sms_cost_cny": 1}})
        self.assertEqual(index.snapshot()["total_cny"], 1.0)

        path.write_text(
            json.dumps({"task_id": "T1", "result": {"sms_cost_cny": 4}}),
            encoding="utf-8",
        )

        self.assertEqual(index.snapshot()["total_cny"], 4.0)
        self.assertEqual(index.metrics()["reconcile_count"], 2)
        self.assertEqual(index.metrics()["rollback_reason"], "environment_disabled")

    def test_metrics_are_credential_free_stable_scalars(self):
        self.write_result(
            "private-task.json",
            {
                "task_id": "secret-task-id",
                "email": "secret@example.test",
                "result": {"sms_cost_cny": 1},
            },
        )
        self.index.snapshot()

        metrics = self.index.metrics()

        self.assertEqual(set(metrics), {
            "incremental_enabled",
            "initialized",
            "tracked_files",
            "tracked_tasks",
            "account_count",
            "reconcile_count",
            "changed_files",
            "last_reconcile_seconds",
            "consecutive_reconcile_failures",
            "rollback_reason",
        })
        self.assertTrue(all(isinstance(value, (bool, int, float, str)) for value in metrics.values()))
        self.assertNotIn("secret", json.dumps(metrics))

    def test_persist_notification_failure_never_escapes(self):
        with patch.object(
            sms_cost_history,
            "result_json_path",
            side_effect=RuntimeError("persistence metric failure"),
        ):
            self.assertIsNone(note_persisted_result(self.data_dir, {}, "T1", "secret@example.test"))


if __name__ == "__main__":
    unittest.main()
