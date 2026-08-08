from __future__ import annotations

import json
import threading
import time
import unittest

from mac_overrides.adaptive_concurrency import AdaptiveConcurrencyGate


class FakeClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class AdaptiveConcurrencyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.events: list[dict] = []
        self.gate = AdaptiveConcurrencyGate(
            5,
            ceiling=8,
            now_fn=self.clock,
            on_change=self.events.append,
        )

    def make_burst_gate(self, **values):
        values.setdefault("ceiling", 12)
        values.setdefault("restore_ceiling", 8)
        values.setdefault("now_fn", self.clock)
        values.setdefault("on_change", self.events.append)
        gate = AdaptiveConcurrencyGate(8, **values)
        with gate.condition:
            gate.waiting = 1
        return gate

    def test_six_clean_successes_restore_one_slot_up_to_ceiling(self):
        for stage in range(3):
            self.clock.value += 60
            for index in range(6):
                self.gate.report_success(f"task-{stage}-{index}")

        self.assertEqual(self.gate.snapshot()["limit"], 8)
        self.assertEqual(self.gate.snapshot()["peak_limit"], 8)
        self.assertEqual([event["new_limit"] for event in self.events], [6, 7, 8])

        for index in range(18, 30):
            self.gate.report_success(f"task-{index}")
        self.assertEqual(self.gate.snapshot()["limit"], 8)

    def test_two_distinct_pressure_events_degrade_and_pause(self):
        self.assertEqual(self.gate.report_pressure("task-a", "node_timeout"), 5)
        self.assertEqual(self.gate.report_pressure("task-b", "protocol_pressure"), 4)

        snapshot = self.gate.snapshot()
        self.assertTrue(snapshot["paused"])
        self.assertEqual(snapshot["pause_remaining_seconds"], 15)
        self.assertEqual(snapshot["degradations"], 1)
        self.assertEqual(self.events[-1]["kind"], "degraded")

        self.clock.value += 16
        self.assertFalse(self.gate.snapshot()["paused"])

    def test_successes_cannot_restore_until_pressure_window_is_clear(self):
        self.gate.report_pressure("task-a", "node_timeout")
        self.gate.report_pressure("task-b", "protocol_pressure")
        self.clock.value += 16
        for index in range(6):
            self.gate.report_success(f"early-success-{index}")
        self.assertEqual(self.gate.snapshot()["limit"], 4)
        self.assertEqual(self.gate.snapshot()["success_streak"], 0)

        self.clock.value += 45
        for index in range(6):
            self.gate.report_success(f"healthy-success-{index}")
        self.assertEqual(self.gate.snapshot()["limit"], 5)

    def test_pressure_is_deduplicated_by_task_and_node(self):
        self.gate.report_pressure("task-a", "node_timeout")
        self.gate.report_pressure("task-a", "node_timeout")
        self.assertEqual(self.gate.snapshot()["pressure_count"], 1)
        self.assertEqual(self.gate.snapshot()["limit"], 5)

        self.gate.report_pressure("task-a", "node_proxy")
        self.assertEqual(self.gate.snapshot()["limit"], 4)

    def test_duplicate_regular_pressure_refreshes_quiet_window_without_counting(self):
        gate = self.make_burst_gate()
        gate.report_pressure("same-task", "node_timeout")
        self.clock.value += 61

        gate.report_pressure("same-task", "node_timeout")
        self.clock.value += 1
        for index in range(4):
            gate.report_account_banned(f"blocked-banned-{index}")

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["pressure_count"], 1)
        self.assertEqual(snapshot["degradations"], 0)
        self.assertEqual(snapshot["limit"], 8)
        self.assertEqual(snapshot["seconds_since_pressure"], 1)
        self.assertEqual(snapshot["recent_account_banned"], 0)

        self.clock.value += 60
        for index in range(4):
            gate.report_account_banned(f"healthy-banned-{index}")
        self.assertEqual(gate.snapshot()["limit"], 10)

    def test_duplicate_immediate_pressure_refreshes_cooldown_without_redegrading(self):
        gate = self.make_burst_gate()
        gate.report_pressure("same-task", "oauth_rate_limit", immediate=True)
        self.clock.value += 61
        for index in range(6):
            gate.report_success(f"healthy-success-{index}")
        self.assertEqual(gate.snapshot()["limit"], 8)

        gate.report_pressure("same-task", "oauth_rate_limit", immediate=True)
        self.clock.value += 1
        for index in range(4):
            gate.report_account_banned(f"blocked-banned-{index}")

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["pressure_count"], 1)
        self.assertEqual(snapshot["degradations"], 1)
        self.assertEqual(snapshot["limit"], 8)
        self.assertFalse(snapshot["paused"])
        self.assertEqual(snapshot["seconds_since_pressure"], 1)
        self.assertEqual(snapshot["recent_account_banned"], 0)

    def test_pressure_window_and_minimum_are_enforced(self):
        self.gate.report_pressure("old", "node_timeout")
        self.clock.value += 61
        self.gate.report_pressure("new", "node_timeout")
        self.assertEqual(self.gate.snapshot()["limit"], 5)

        for index in range(12):
            self.gate.report_pressure(f"task-{index}", f"node-{index}")
            self.clock.value += 1
        self.assertEqual(self.gate.snapshot()["limit"], 1)

    def test_business_failure_resets_success_streak_without_pressure(self):
        for index in range(5):
            self.gate.report_success(f"success-{index}")
        self.gate.report_failure("business-failure")
        self.gate.report_success("success-after-failure")

        self.assertEqual(self.gate.snapshot()["limit"], 5)
        self.assertEqual(self.gate.snapshot()["success_streak"], 1)

    def test_waiting_acquire_wakes_on_stop(self):
        stopped = threading.Event()
        entered = threading.Event()
        errors: list[str] = []
        gate = AdaptiveConcurrencyGate(1, ceiling=1)

        first_release = threading.Event()

        def first_worker():
            with gate.acquire():
                entered.set()
                first_release.wait(2)

        def second_worker():
            try:
                with gate.acquire(stop_event=stopped):
                    pass
            except RuntimeError as exc:
                errors.append(str(exc))

        first = threading.Thread(target=first_worker)
        second = threading.Thread(target=second_worker)
        first.start()
        self.assertTrue(entered.wait(1))
        second.start()
        deadline = time.time() + 1
        while gate.snapshot()["waiting"] < 1 and time.time() < deadline:
            time.sleep(0.01)

        stopped.set()
        gate.wake_all()
        second.join(1)
        first_release.set()
        first.join(1)

        self.assertEqual(errors, ["task_stopped"])
        self.assertEqual(gate.snapshot()["active"], 0)

    def test_wait_time_can_include_executor_queue_delay(self):
        observed: list[float] = []
        self.clock.value = 125

        with self.gate.acquire(queued_at=100, on_wait=observed.append):
            pass

        self.assertEqual(observed, [25])
        self.assertEqual(self.gate.snapshot()["total_wait_seconds"], 25)

    def test_restore_ceiling_defaults_to_ceiling_and_does_not_enable_burst(self):
        gate = AdaptiveConcurrencyGate(8, ceiling=12, now_fn=self.clock)
        with gate.condition:
            gate.waiting = 1

        for index in range(8):
            gate.report_account_banned(f"banned-{index}")

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["restore_ceiling"], 12)
        self.assertFalse(snapshot["burst_enabled"])
        self.assertEqual(snapshot["limit"], 8)
        self.assertEqual(snapshot["burst_promotions"], 0)

    def test_four_then_eight_banned_tasks_raise_limit_to_ten_then_twelve(self):
        gate = self.make_burst_gate()

        for index in range(3):
            self.assertEqual(gate.report_account_banned(f"banned-{index}"), 8)
        self.assertEqual(gate.report_account_banned("banned-3"), 10)
        for index in range(4, 7):
            self.assertEqual(gate.report_account_banned(f"banned-{index}"), 10)
        self.assertEqual(gate.report_account_banned("banned-7"), 12)

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 12)
        self.assertEqual(snapshot["peak_limit"], 12)
        self.assertEqual(snapshot["failure_count"], 8)
        self.assertEqual(snapshot["burst_promotions"], 2)
        self.assertEqual(snapshot["burst_remaining_seconds"], 90)
        self.assertEqual(
            [event["kind"] for event in self.events],
            ["burst_activated", "burst_activated"],
        )
        self.assertEqual(
            [(event["old_limit"], event["new_limit"]) for event in self.events],
            [(8, 10), (10, 12)],
        )
        self.assertTrue(all(event["hold_seconds"] == 90 for event in self.events))

    def test_registered_executor_backlog_keeps_second_promotion_eligible(self):
        gate = self.make_burst_gate()
        with gate.condition:
            gate.waiting = 0
        gate.register_pending(12)

        for index in range(8):
            gate.report_account_banned(f"backlog-banned-{index}")

        self.assertEqual(gate.snapshot()["limit"], 12)

        gate.discard_pending(12)
        self.clock.value += 90
        self.assertEqual(gate.snapshot()["limit"], 8)
        for index in range(4):
            gate.report_account_banned(f"drained-banned-{index}")
        self.assertEqual(gate.snapshot()["limit"], 8)

    def test_duplicate_banned_task_is_counted_once(self):
        gate = self.make_burst_gate()

        gate.report_account_banned("same-task")
        gate.report_account_banned("same-task")
        gate.report_account_banned("other-1")
        gate.report_account_banned("other-2")

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 8)
        self.assertEqual(snapshot["recent_account_banned"], 3)
        self.assertEqual(snapshot["failure_count"], 3)

        gate.report_account_banned("other-3")
        self.assertEqual(gate.snapshot()["limit"], 10)

    def test_burst_requires_waiting_work_and_restore_ceiling(self):
        gate = self.make_burst_gate()
        with gate.condition:
            gate.waiting = 0
        for index in range(4):
            gate.report_account_banned(f"not-waiting-{index}")
        self.assertEqual(gate.snapshot()["recent_account_banned"], 0)

        with gate.condition:
            gate.waiting = 1
        gate.report_pressure("pressure", "oauth", immediate=True)
        self.clock.value += 61
        for index in range(4):
            gate.report_account_banned(f"degraded-{index}")

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 7)
        self.assertEqual(snapshot["recent_account_banned"], 0)

    def test_banned_window_and_pressure_quiet_window_are_enforced(self):
        gate = self.make_burst_gate()
        for index in range(3):
            gate.report_account_banned(f"old-banned-{index}")
        self.clock.value += 91
        gate.report_account_banned("fresh-banned-0")
        self.assertEqual(gate.snapshot()["recent_account_banned"], 1)
        for index in range(1, 4):
            gate.report_account_banned(f"fresh-banned-{index}")
        self.assertEqual(gate.snapshot()["limit"], 10)

        gate.report_pressure("pressure", "node_timeout")
        self.clock.value += 60
        for index in range(4):
            gate.report_account_banned(f"too-early-{index}")
        self.assertEqual(gate.snapshot()["limit"], 10)
        self.assertEqual(gate.snapshot()["recent_account_banned"], 0)

        self.clock.value += 1
        for index in range(4):
            gate.report_account_banned(f"after-cooldown-{index}")
        self.assertEqual(gate.snapshot()["limit"], 12)

    def test_ceiling_event_renews_hold_and_lazy_expiry_returns_to_restore_ceiling(self):
        gate = self.make_burst_gate()
        for index in range(8):
            gate.report_account_banned(f"banned-{index}")
        self.assertEqual(gate.snapshot()["limit"], 12)

        self.clock.value += 80
        with gate.condition:
            gate.waiting = 0
        gate.report_account_banned("renew-hold")
        self.assertEqual(gate.snapshot()["burst_remaining_seconds"], 90)
        self.clock.value += 89
        self.assertEqual(gate.snapshot()["limit"], 12)
        self.clock.value += 1

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 8)
        self.assertFalse(snapshot["burst_active"])
        self.assertEqual(snapshot["burst_expirations"], 1)
        self.assertEqual(self.events[-1]["kind"], "burst_expired")

    def test_lazy_expiry_never_raises_an_already_degraded_limit(self):
        gate = self.make_burst_gate()
        for index in range(4):
            gate.report_account_banned(f"banned-{index}")
        with gate.condition:
            gate.limit = 7
        self.clock.value += 90

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 7)
        self.assertEqual(snapshot["burst_expirations"], 0)

    def test_success_restoration_stops_at_restore_ceiling(self):
        gate = AdaptiveConcurrencyGate(
            7,
            ceiling=12,
            restore_ceiling=8,
            restore_successes=1,
            now_fn=self.clock,
        )

        self.clock.value += 60
        self.assertEqual(gate.report_success("success-0"), 8)
        for index in range(1, 10):
            gate.report_success(f"success-{index}")

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 8)
        self.assertEqual(snapshot["peak_limit"], 8)
        self.assertEqual(snapshot["restorations"], 1)

    def test_first_regular_pressure_does_not_revoke_burst(self):
        gate = self.make_burst_gate()
        for index in range(4):
            gate.report_account_banned(f"banned-{index}")
        self.events.clear()

        self.assertEqual(gate.report_pressure("pressure-a", "node_timeout"), 10)
        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 10)
        self.assertTrue(snapshot["burst_active"])
        self.assertEqual(snapshot["recent_pressure_events"], 1)
        self.assertEqual(snapshot["burst_revocations"], 0)
        self.assertEqual(self.events, [])

    def test_second_regular_pressure_revokes_burst_and_pauses_at_restore_ceiling(self):
        gate = self.make_burst_gate()
        for index in range(4):
            gate.report_account_banned(f"banned-{index}")
        self.events.clear()

        gate.report_pressure("pressure-a", "node_timeout")
        self.assertEqual(gate.report_pressure("pressure-b", "protocol_pressure"), 8)

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 8)
        self.assertTrue(snapshot["paused"])
        self.assertFalse(snapshot["burst_active"])
        self.assertEqual(snapshot["burst_revocations"], 1)
        self.assertEqual(snapshot["degradations"], 0)
        self.assertEqual(
            [event["kind"] for event in self.events],
            ["burst_revoked"],
        )
        self.assertEqual(
            [(event["old_limit"], event["new_limit"]) for event in self.events],
            [(10, 8)],
        )
        self.assertEqual(self.events[0]["pause_seconds"], 15)

    def test_immediate_pressure_revokes_burst_on_first_event(self):
        gate = self.make_burst_gate()
        for index in range(8):
            gate.report_account_banned(f"banned-{index}")
        self.events.clear()

        self.assertEqual(
            gate.report_pressure("strong", "oauth_rate_limit", immediate=True),
            8,
        )

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 8)
        self.assertTrue(snapshot["paused"])
        self.assertEqual(snapshot["recent_pressure_events"], 0)
        self.assertEqual(snapshot["pressure_count"], 1)
        self.assertEqual(
            [event["kind"] for event in self.events],
            ["burst_revoked"],
        )
        self.assertEqual(
            (self.events[0]["old_limit"], self.events[0]["new_limit"]),
            (12, 8),
        )
        self.assertEqual(self.events[0]["reason"], "infrastructure_pressure_immediate")
        self.assertEqual(self.events[0]["pause_seconds"], 15)

    def test_conservative_adaptive_limit_resets_to_base_on_immediate_pressure(self):
        gate = AdaptiveConcurrencyGate(
            8,
            ceiling=10,
            restore_ceiling=10,
            immediate_reset_limit=8,
            now_fn=self.clock,
            on_change=self.events.append,
        )
        for stage in range(2):
            self.clock.value += 60
            for index in range(6):
                gate.report_success(f"success-{stage}-{index}")
        self.assertEqual(gate.snapshot()["limit"], 10)

        self.assertEqual(
            gate.report_pressure("pressure", "protocol_pressure", immediate=True),
            8,
        )
        snapshot = gate.snapshot()
        self.assertEqual(snapshot["limit"], 8)
        self.assertTrue(snapshot["paused"])
        self.assertEqual((self.events[-1]["old_limit"], self.events[-1]["new_limit"]), (10, 8))

    def test_fixed_compatibility_gate_ignores_adaptive_pressure(self):
        gate = AdaptiveConcurrencyGate(
            8,
            ceiling=8,
            restore_ceiling=8,
            minimum=8,
            adaptive_enabled=False,
            now_fn=self.clock,
        )

        gate.report_pressure("pressure-a", "node_timeout")
        self.assertEqual(gate.report_pressure("pressure-b", "protocol_pressure"), 8)

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["base"], 8)
        self.assertEqual(snapshot["limit"], 8)
        self.assertFalse(snapshot["paused"])
        self.assertEqual(snapshot["pressure_count"], 0)

    def test_emfile_incident_caps_once_and_recovers_directly_to_baseline(self):
        gate = AdaptiveConcurrencyGate(
            8,
            ceiling=10,
            restore_ceiling=10,
            minimum=4,
            now_fn=self.clock,
            on_change=self.events.append,
        )

        self.assertEqual(gate.report_resource_exhaustion("task-a", "resource_fd_exhausted"), 4)
        self.assertEqual(gate.report_resource_exhaustion("task-b", "resource_fd_exhausted"), 4)
        self.assertEqual(gate.snapshot()["pressure_count"], 1)
        self.assertEqual([event["kind"] for event in self.events], ["resource_exhausted"])

        gate.observe_resource_ratio(0.59)
        self.clock.value += 60
        self.assertEqual(gate.observe_resource_ratio(0.59), 8)
        self.assertFalse(gate.snapshot()["resource_incident"])
        self.assertEqual(self.events[-1]["kind"], "resource_recovered")

    def test_fd_ratio_thresholds_return_to_eight_then_cap_four(self):
        gate = AdaptiveConcurrencyGate(
            8,
            ceiling=10,
            restore_ceiling=10,
            minimum=4,
            now_fn=self.clock,
            on_change=self.events.append,
        )
        gate.limit = 10

        self.assertEqual(gate.observe_resource_ratio(0.70), 8)
        self.assertEqual(gate.snapshot()["last_reason"], "fd_usage_above_70_percent")
        self.assertEqual(gate.observe_resource_ratio(0.80), 4)
        snapshot = gate.snapshot()
        self.assertTrue(snapshot["paused"])
        self.assertEqual(snapshot["resource_incident_level"], 2)
        self.assertEqual(snapshot["pressure_count"], 1)

    def test_restore_can_require_real_backlog(self):
        gate = AdaptiveConcurrencyGate(
            8,
            ceiling=10,
            restore_ceiling=10,
            require_backlog_for_restore=True,
            now_fn=self.clock,
        )
        self.clock.value += 60
        for index in range(6):
            gate.report_success(f"idle-{index}")
        self.assertEqual(gate.snapshot()["limit"], 8)

        gate.register_pending(1)
        for index in range(6):
            gate.report_success(f"queued-{index}")
        self.assertEqual(gate.snapshot()["limit"], 9)

    def test_same_pressure_key_can_upgrade_to_immediate_once(self):
        gate = self.make_burst_gate()
        for index in range(4):
            gate.report_account_banned(f"banned-{index}")
        self.events.clear()

        gate.report_pressure("same", "node_sentinel")
        self.assertEqual(
            gate.report_pressure("same", "node_sentinel", immediate=True),
            8,
        )
        gate.report_pressure("same", "node_sentinel", immediate=True)

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["pressure_count"], 2)
        self.assertEqual(snapshot["degradations"], 0)
        self.assertEqual(snapshot["limit"], 8)
        self.assertEqual(
            [event["kind"] for event in self.events],
            ["burst_revoked"],
        )

    def test_burst_capacity_wakes_a_real_waiting_worker(self):
        gate = AdaptiveConcurrencyGate(
            1,
            ceiling=2,
            restore_ceiling=1,
            banned_burst_threshold=1,
        )
        first_entered = threading.Event()
        second_entered = threading.Event()
        release = threading.Event()

        def worker(entered):
            with gate.acquire():
                entered.set()
                release.wait(2)

        first = threading.Thread(target=worker, args=(first_entered,))
        second = threading.Thread(target=worker, args=(second_entered,))
        first.start()
        self.assertTrue(first_entered.wait(1))
        second.start()
        deadline = time.time() + 1
        while gate.snapshot()["waiting"] != 1 and time.time() < deadline:
            time.sleep(0.01)

        gate.report_account_banned("quick-terminal")
        self.assertTrue(second_entered.wait(1))
        self.assertEqual(gate.snapshot()["active"], 2)

        release.set()
        first.join(1)
        second.join(1)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(gate.snapshot()["active"], 0)

    def test_change_callback_can_read_snapshot_without_deadlock(self):
        callback_finished = threading.Event()
        callback_snapshots: list[dict] = []
        gate = None

        def on_change(_event):
            callback_snapshots.append(gate.snapshot())
            callback_finished.set()

        gate = AdaptiveConcurrencyGate(
            8,
            ceiling=12,
            restore_ceiling=8,
            now_fn=self.clock,
            on_change=on_change,
        )
        with gate.condition:
            gate.waiting = 1
        for index in range(3):
            gate.report_account_banned(f"banned-{index}")

        reporter = threading.Thread(
            target=gate.report_account_banned,
            args=("banned-3",),
        )
        reporter.start()
        reporter.join(1)

        self.assertFalse(reporter.is_alive())
        self.assertTrue(callback_finished.is_set())
        self.assertEqual(callback_snapshots[-1]["limit"], 10)

    def test_snapshot_contains_only_redacted_scalar_burst_metrics(self):
        gate = self.make_burst_gate()
        gate.report_account_banned("private-account-id")
        gate.report_pressure("private-task-id", "oauth_proxy")

        serialized = json.dumps(gate.snapshot(), sort_keys=True)
        serialized_events = json.dumps(self.events, sort_keys=True)
        self.assertNotIn("private-account-id", serialized)
        self.assertNotIn("private-task-id", serialized)
        self.assertNotIn("oauth_proxy", serialized)
        self.assertNotIn("private-account-id", serialized_events)
        self.assertNotIn("private-task-id", serialized_events)
        self.assertNotIn("oauth_proxy", serialized_events)
        self.assertIn('"restore_ceiling": 8', serialized)
        self.assertIn('"burst_enabled": true', serialized)


if __name__ == "__main__":
    unittest.main()
