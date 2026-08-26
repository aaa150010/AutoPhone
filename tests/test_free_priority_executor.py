from __future__ import annotations

import threading
import time
import unittest

from mac_overrides.free_priority_executor import PriorityExecutor


class FreePriorityExecutorTests(unittest.TestCase):
    def test_retry_moves_ahead_of_waiting_ordinary_work(self) -> None:
        executor = PriorityExecutor(1, thread_name_prefix="priority-test")
        entered = threading.Event()
        release = threading.Event()
        order: list[str] = []

        def blocker() -> None:
            entered.set()
            release.wait(2)
            order.append("active")

        first = executor.submit(blocker, priority=10)
        self.assertTrue(entered.wait(1))
        ordinary = executor.submit(lambda: order.append("ordinary"), priority=10)
        retry = executor.submit(lambda: order.append("retry"), priority=0)
        release.set()
        first.result(timeout=2)
        retry.result(timeout=2)
        ordinary.result(timeout=2)
        executor.shutdown()
        self.assertEqual(order, ["active", "retry", "ordinary"])

    def test_worker_ceiling_is_shared_by_all_priorities(self) -> None:
        executor = PriorityExecutor(3, thread_name_prefix="ceiling-test")
        release = threading.Event()
        lock = threading.Lock()
        active = 0
        peak = 0

        def work() -> None:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            release.wait(2)
            with lock:
                active -= 1

        futures = [
            executor.submit(work, priority=0 if index % 2 else 10)
            for index in range(8)
        ]
        deadline = time.time() + 1
        while peak < 3 and time.time() < deadline:
            time.sleep(0.01)
        release.set()
        for future in futures:
            future.result(timeout=2)
        executor.shutdown()
        self.assertEqual(peak, 3)


if __name__ == "__main__":
    unittest.main()
