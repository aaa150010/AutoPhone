from __future__ import annotations

from contextlib import contextmanager
import threading
import unittest

from mac_overrides.inflight_pipeline_runtime import (
    call_with_protocol_lease,
    optimization_active,
    protocol_session_scope,
)


class _Gate:
    def __init__(self) -> None:
        self.calls = 0
        self.active = 0

    def snapshot(self):
        return {"optimized": True}

    @contextmanager
    def acquire(self, *_args, **_kwargs):
        self.calls += 1
        self.active += 1
        try:
            yield
        finally:
            self.active -= 1


class InflightPipelineRuntimeTests(unittest.TestCase):
    def test_staged_session_scope_does_not_hold_protocol_lease(self):
        gate = _Gate()
        with protocol_session_scope(
            staged=True,
            gate=gate,
            proxy="proxy",
            stop_event=threading.Event(),
        ):
            self.assertEqual(gate.calls, 0)
        self.assertEqual(gate.active, 0)

    def test_staged_requests_each_acquire_a_short_protocol_lease(self):
        gate = _Gate()
        results = [
            call_with_protocol_lease(
                lambda index=index: index,
                staged=True,
                gate=gate,
                proxy="proxy",
                stop_event=threading.Event(),
                success_fn=lambda value: value >= 0,
            )
            for index in range(3)
        ]
        self.assertEqual(results, [0, 1, 2])
        self.assertEqual(gate.calls, 3)
        self.assertEqual(gate.active, 0)

    def test_disabled_path_does_not_add_request_leases(self):
        gate = _Gate()
        result = call_with_protocol_lease(
            lambda: "ok",
            staged=False,
            gate=gate,
            proxy="proxy",
            stop_event=threading.Event(),
        )
        self.assertEqual(result, "ok")
        self.assertEqual(gate.calls, 0)
        self.assertFalse(optimization_active(None))


if __name__ == "__main__":
    unittest.main()
