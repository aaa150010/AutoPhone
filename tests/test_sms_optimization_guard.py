from __future__ import annotations

import unittest
from pathlib import Path
import tempfile

from mac_overrides.sms_optimization_guard import SmsOptimizationGuard


class SmsOptimizationGuardTests(unittest.TestCase):
    @staticmethod
    def observe_window(guard, *, successes=100, result=None):
        for index in range(100):
            status = "success" if index < successes else "failed"
            guard.observe_task(f"task-{index}", status, result or {})

    def test_success_rate_below_known_baseline_disables_quality_optimization(self):
        guard = SmsOptimizationGuard()
        guard.begin_run(True)

        self.observe_window(guard, successes=81)

        snapshot = guard.snapshot()
        self.assertTrue(snapshot["disabled"])
        self.assertEqual(snapshot["reason"], "success_rate_below_819")
        self.assertFalse(guard.is_enabled(True))

    def test_rolling_window_spans_batches_and_requires_manual_reset_after_shutdown(self):
        guard = SmsOptimizationGuard()
        guard.begin_run(True)
        for index in range(60):
            guard.observe_task(f"first-{index}", "success" if index < 50 else "failed")
        guard.begin_run(True)
        for index in range(40):
            guard.observe_task(f"second-{index}", "success" if index < 31 else "failed")

        self.assertEqual(guard.snapshot()["observed_tasks"], 100)
        self.assertTrue(guard.snapshot()["disabled"])
        guard.begin_run(True)
        self.assertFalse(guard.is_enabled(True))

        guard.begin_run(False)
        self.assertTrue(guard.is_enabled(True))
        guard.begin_run(True)
        self.assertTrue(guard.is_enabled(True))
        self.assertEqual(guard.snapshot()["observed_tasks"], 0)

    def test_confirmed_late_code_losses_require_explicit_evidence(self):
        guard = SmsOptimizationGuard()
        guard.begin_run(True)
        self.observe_window(guard)

        self.assertIsNone(guard.observe_confirmed_late_code_loss("missing-task"))
        self.assertIsNone(guard.observe_confirmed_late_code_loss("task-1"))
        event = guard.observe_confirmed_late_code_loss("task-2")

        self.assertEqual(event["reasons"], ["two_confirmed_late_code_losses"])
        self.assertTrue(guard.snapshot()["disabled"])
        self.assertFalse(guard.snapshot()["late_code_loss_auto_detection_available"])

    def test_cancellation_rate_needs_an_explicit_reference_baseline(self):
        guard = SmsOptimizationGuard()
        guard.begin_run(True, baseline={"cancellation_rate": 0.01})
        for index in range(100):
            outcome = "cancelled" if index < 2 else "completed"
            guard.observe_task(
                f"task-{index}",
                "success",
                {"sms_order_outcomes": [{"status": outcome}]},
            )

        self.assertEqual(guard.snapshot()["reason"], "cancellation_rate_increased")

    def test_cost_per_success_uses_ledger_cost_and_explicit_baseline(self):
        guard = SmsOptimizationGuard()
        guard.begin_run(True, baseline={"cost_per_success_usd": 0.10})
        self.observe_window(guard, result={"sms_cost_usd": 0.111})

        self.assertEqual(
            guard.snapshot()["reason"],
            "cost_per_success_above_110_percent",
        )

    def test_duplicate_orders_need_explicit_provider_reconciliation_metric(self):
        guard = SmsOptimizationGuard()
        guard.begin_run(True, baseline={"duplicate_order_rate": 0.01})
        for index in range(100):
            guard.observe_task(
                f"task-{index}",
                "success",
                {
                    "sms_order_outcomes": [{"status": "completed"}],
                    "sms_duplicate_orders": 1 if index < 2 else 0,
                },
            )

        self.assertEqual(guard.snapshot()["reason"], "duplicate_order_rate_increased")

    def test_manual_baseline_window_persists_only_aggregate_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            collector = SmsOptimizationGuard(baseline_path=path)
            collector.begin_run(False)
            self.observe_window(
                collector,
                result={
                    "sms_cost_usd": 0.10,
                    "sms_order_outcomes": [{"status": "cancelled"}],
                    "sms_duplicate_orders": 0,
                },
            )
            restored = SmsOptimizationGuard(baseline_path=path)
            restored.begin_run(True)

            self.assertTrue(restored.snapshot()["cancellation_baseline_available"])
            self.assertTrue(restored.snapshot()["duplicate_baseline_available"])
            self.assertTrue(restored.snapshot()["cost_baseline_available"])
            self.assertNotIn("task-", path.read_text(encoding="utf-8"))

    def test_automatic_shutdown_persists_across_process_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            first = SmsOptimizationGuard(baseline_path=baseline)
            first.begin_run(True)
            self.observe_window(first, successes=81)

            restored = SmsOptimizationGuard(baseline_path=baseline)
            restored.begin_run(True)

            self.assertFalse(restored.is_enabled(True))
            self.assertEqual(restored.snapshot()["reason"], "success_rate_below_819")
            state_text = (Path(directory) / "sms_optimization_state.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("task-", state_text)

            restored.begin_run(False)
            reset = SmsOptimizationGuard(baseline_path=baseline)
            reset.begin_run(True)
            self.assertTrue(reset.is_enabled(True))

    def test_rolling_risk_metrics_survive_restart_without_raw_task_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            first = SmsOptimizationGuard(baseline_path=baseline, window_size=3)
            first.begin_run(True)
            first.observe_task(
                "private-task-1",
                "success",
                {
                    "sms_cost_usd": 0.12,
                    "sms_order_outcomes": [{"status": "cancelled"}],
                    "sms_duplicate_orders": 1,
                },
            )
            first.observe_confirmed_late_code_loss("private-task-1")

            restored = SmsOptimizationGuard(baseline_path=baseline, window_size=3)
            restored.begin_run(True)
            metrics = restored.snapshot()["metrics"]

            self.assertEqual(metrics["window_tasks"], 1)
            self.assertEqual(metrics["cancelled_orders"], 1)
            self.assertEqual(metrics["duplicate_orders"], 1)
            self.assertEqual(metrics["confirmed_late_code_losses"], 1)
            self.assertEqual(metrics["cost_per_success_usd"], 0.12)
            state_text = (Path(directory) / "sms_optimization_state.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("private-task-1", state_text)
            self.assertNotIn("@", state_text)

    def test_manual_baseline_window_accumulates_across_disabled_batches(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            collector = SmsOptimizationGuard(baseline_path=path)
            collector.begin_run(False)
            for index in range(60):
                collector.observe_task(
                    f"first-{index}",
                    "success",
                    {"sms_cost_usd": 0.10, "sms_order_outcomes": [{"status": "completed"}]},
                )
            collector.begin_run(False)
            for index in range(40):
                collector.observe_task(
                    f"second-{index}",
                    "success",
                    {"sms_cost_usd": 0.10, "sms_order_outcomes": [{"status": "completed"}]},
                )

            self.assertTrue(path.exists())
            self.assertEqual(collector.snapshot()["observed_tasks"], 100)

    def test_seen_task_hashes_are_bounded_to_the_rolling_window(self):
        guard = SmsOptimizationGuard(window_size=2)
        guard.begin_run(True)
        for task_id in ("one", "two", "three"):
            guard.observe_task(task_id, "success")

        self.assertEqual(len(guard.samples), 2)
        self.assertEqual(len(guard.seen_tasks), 2)

    def test_manual_feature_switch_always_wins_and_snapshot_has_no_task_identity(self):
        guard = SmsOptimizationGuard()
        guard.begin_run(False)
        self.observe_window(guard, successes=0)

        self.assertTrue(guard.is_enabled(True))
        self.assertFalse(guard.is_enabled(False))
        snapshot = str(guard.snapshot())
        self.assertNotIn("task-", snapshot)


if __name__ == "__main__":
    unittest.main()
