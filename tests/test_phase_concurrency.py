from __future__ import annotations

import threading
import time
import unittest

from mac_overrides.phase_concurrency import AdjustablePhaseGate


class AdjustablePhaseGateTests(unittest.TestCase):
    def test_capacity_changes_preserve_active_accounting(self):
        gate = AdjustablePhaseGate(8, ceiling=10)
        gate.acquire()
        gate.acquire()

        self.assertEqual(gate.set_capacity(10, reason="healthy_promotion"), 10)
        self.assertEqual(gate.status()["active"], 2)
        self.assertEqual(gate.set_capacity(4, reason="resource_fd_exhausted"), 4)
        self.assertEqual(gate.status()["active"], 2)

        gate.release()
        gate.release()
        self.assertEqual(gate.status()["active"], 0)
        self.assertEqual(gate.status()["last_reason"], "resource_fd_exhausted")

    def test_stop_wakes_a_waiting_phase(self):
        gate = AdjustablePhaseGate(1)
        gate.acquire()
        stop = threading.Event()
        observed: list[str] = []

        def wait() -> None:
            try:
                gate.acquire(stop)
            except RuntimeError as exc:
                observed.append(str(exc))

        worker = threading.Thread(target=wait)
        worker.start()
        deadline = time.time() + 1
        while gate.status()["waiting"] != 1 and time.time() < deadline:
            time.sleep(0.01)
        stop.set()
        with gate.condition:
            gate.condition.notify_all()
        worker.join(1)
        gate.release()

        self.assertEqual(observed, ["task_stopped"])
        self.assertEqual(gate.status()["waiting"], 0)

    def test_pause_state_is_public_and_credential_free(self):
        clock = [100.0]
        gate = AdjustablePhaseGate(8, ceiling=10, now_fn=lambda: clock[0])
        gate.set_capacity(
            4,
            pause_seconds=15,
            reason="resource_fd_exhausted",
        )
        snapshot = gate.status()
        self.assertTrue(snapshot["paused"])
        self.assertEqual(snapshot["pause_remaining_seconds"], 15)
        self.assertEqual(snapshot["last_reason"], "resource_fd_exhausted")


if __name__ == "__main__":
    unittest.main()
