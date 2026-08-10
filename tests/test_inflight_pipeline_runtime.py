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


class _PauseAwareGate(_Gate):
    def __init__(self) -> None:
        super().__init__()
        self.events = []

    def wait_until_resumed(self, proxy, **kwargs):
        self.events.append(("wait", proxy, kwargs))
        return "proxy-key"


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

    def test_non_staged_request_waits_without_taking_nested_capacity(self):
        gate = _PauseAwareGate()
        stop_event = threading.Event()
        observed = []
        result = call_with_protocol_lease(
            lambda: gate.events.append(("callback",)) or "ok",
            staged=False,
            gate=gate,
            proxy="proxy",
            stop_event=stop_event,
            success_fn=lambda value: value == "ok",
            on_result=lambda value, succeeded: observed.append((value, succeeded)),
        )

        self.assertEqual(result, "ok")
        self.assertEqual(gate.calls, 0)
        self.assertEqual(gate.events[0][0:2], ("wait", "proxy"))
        self.assertIs(gate.events[0][2]["stop_event"], stop_event)
        self.assertEqual(gate.events[1], ("callback",))
        self.assertEqual(observed, [("ok", True)])

    def test_non_staged_request_reports_failure_before_propagating_it(self):
        gate = _PauseAwareGate()
        observed = []

        with self.assertRaisesRegex(RuntimeError, "TLS failed"):
            call_with_protocol_lease(
                lambda: (_ for _ in ()).throw(RuntimeError("TLS failed")),
                staged=False,
                gate=gate,
                proxy="proxy",
                stop_event=threading.Event(),
                on_result=lambda value, succeeded: observed.append((value, succeeded)),
            )

        self.assertEqual(len(observed), 1)
        self.assertIsInstance(observed[0][0], RuntimeError)
        self.assertFalse(observed[0][1])

    def test_staged_request_mode_survives_capacity_suspension(self):
        class SuspendedGate(_Gate):
            def snapshot(self):
                return {"optimized": False, "staged": True, "suspended": True}

        self.assertTrue(optimization_active(SuspendedGate()))


if __name__ == "__main__":
    unittest.main()
