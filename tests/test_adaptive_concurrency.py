from __future__ import annotations

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

    def test_six_clean_successes_restore_one_slot_up_to_ceiling(self):
        for index in range(18):
            self.gate.report_success(f"task-{index}")

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


if __name__ == "__main__":
    unittest.main()
