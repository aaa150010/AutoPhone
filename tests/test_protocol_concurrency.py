from __future__ import annotations

from types import SimpleNamespace
import threading
import time
import unittest

from mac_overrides import inflight_pipeline_runtime
from mac_overrides.protocol_concurrency import (
    ProxyProtocolGate,
    TransportProtocolCoordinator,
    is_http_429_error,
    is_protocol_pressure_error,
)


class _Connectivity:
    def __init__(self, failure_decision=None) -> None:
        self.failure_decision = failure_decision or {}

    def report_success(self, _origin):
        return {"kind": "healthy"}

    def report_failure(self, _origin, _value):
        return dict(self.failure_decision)


class _InflightGate:
    def __init__(self, *, suspended=False, staged=True) -> None:
        self.suspended = suspended
        self.staged = staged
        self.resume_calls = 0
        self.session_invalidation_calls = 0

    def snapshot(self):
        return {"staged": self.staged}

    def resume(self):
        self.resume_calls += 1
        self.suspended = False

    def suspend(self, _reason):
        self.suspended = True

    def report_session_invalidation(self):
        self.session_invalidation_calls += 1


def _coordinator(gate, connectivity, inflight):
    return TransportProtocolCoordinator(
        gate=gate,
        inflight_pipeline=SimpleNamespace(),
        success_fn=bool,
        task_id_getter=lambda _transport: "",
        task_context_getter=lambda: "",
        main_chain_source=lambda *_args: (True, None),
        rate_limited_failure=lambda _value: False,
        report_task_pressure=lambda *_args, **_kwargs: None,
        connectivity_getter=lambda: connectivity,
        inflight_gate_getter=lambda: inflight,
        activity_observer=lambda: None,
        segment_observer=lambda *_args: None,
    )


class ProtocolConcurrencyTests(unittest.TestCase):
    def test_known_non_429_http_status_overrides_pressure_words(self):
        self.assertFalse(is_http_429_error({
            "status_code": 403,
            "error": "rate limit policy denied",
        }))
        self.assertFalse(is_protocol_pressure_error({
            "status_code": 400,
            "error": "TLS handshake failed",
        }))
        self.assertFalse(is_protocol_pressure_error(
            "HTTP 403: connection closed by policy"
        ))
        self.assertFalse(is_protocol_pressure_error(
            "HTTP/1.1 403 connection closed by policy"
        ))
        self.assertFalse(is_http_429_error(
            "HTTP status: 403 rate limit policy denied"
        ))
        self.assertTrue(is_http_429_error({
            "status_code": 429,
            "error": "request rejected",
        }))

    def test_session_invalidation_permanently_rolls_back_inflight_admission(self):
        gate = ProxyProtocolGate(default_limit=8, launch_interval_seconds=0)
        inflight = _InflightGate()
        coordinator = _coordinator(gate, _Connectivity(), inflight)
        transport = SimpleNamespace(config={"proxy": "proxy-a"}, proxy="proxy-a")

        coordinator.record_result(
            transport,
            {"error": {"code": "oauth_session_invalid"}},
            False,
        )

        self.assertEqual(inflight.session_invalidation_calls, 1)

    def test_late_request_result_from_old_proxy_or_incident_is_ignored(self):
        class Connectivity(_Connectivity):
            def __init__(self):
                super().__init__()
                self.condition = threading.Condition(threading.RLock())
                self.proxy_fingerprint = ""
                self.event_id = ""
                self.failures = []
                self.successes = []
                self.advance_event_on_failure = False

            def snapshot(self):
                return {
                    "proxy_fingerprint": self.proxy_fingerprint,
                    "event_id": self.event_id,
                }

            def report_failure(self, origin, value):
                self.failures.append((origin, value))
                if self.advance_event_on_failure:
                    self.event_id = "event-http-new"
                    return {
                        "kind": "other",
                        "action": "ignored",
                        "reason_code": "openai_http_response",
                    }
                return {"kind": "ignored", "action": "ignored"}

            def report_success(self, origin):
                self.successes.append(origin)
                return {"kind": "healthy", "action": "healthy"}

        connectivity = Connectivity()
        gate = ProxyProtocolGate(default_limit=8, launch_interval_seconds=0)
        inflight = _InflightGate()
        coordinator = _coordinator(gate, connectivity, inflight)
        coordinator.inflight_pipeline = inflight_pipeline_runtime
        transport = SimpleNamespace(
            config={"run_mode": "register", "proxy": "proxy-a"},
            proxy="proxy-a",
        )
        connectivity.proxy_fingerprint = coordinator._proxy_fingerprint("proxy-a")

        def switch_proxy_then_fail():
            connectivity.proxy_fingerprint = coordinator._proxy_fingerprint("proxy-b")
            return False

        self.assertFalse(coordinator.call(transport, switch_proxy_then_fail))
        self.assertEqual(connectivity.failures, [])

        connectivity.proxy_fingerprint = coordinator._proxy_fingerprint("proxy-a")

        def switch_proxy_then_expire_session():
            connectivity.proxy_fingerprint = coordinator._proxy_fingerprint("proxy-b")
            raise RuntimeError("oauth_session_invalid")

        with self.assertRaisesRegex(RuntimeError, "oauth_session_invalid"):
            coordinator.call(transport, switch_proxy_then_expire_session)
        self.assertEqual(inflight.session_invalidation_calls, 0)

        connectivity.proxy_fingerprint = coordinator._proxy_fingerprint("proxy-a")
        connectivity.event_id = "event-old"

        def start_new_incident_then_succeed():
            connectivity.event_id = "event-new"
            return True

        self.assertTrue(coordinator.call(transport, start_new_incident_then_succeed))
        self.assertEqual(connectivity.successes, [])

        connectivity.event_id = "event-http-old"
        connectivity.advance_event_on_failure = True
        self.assertFalse(coordinator.call(transport, lambda: False))
        self.assertEqual(len(connectivity.failures), 1)
        self.assertEqual(connectivity.successes, [])

    def test_outage_is_applied_before_the_protocol_slot_is_released(self):
        class InspectingGate(ProxyProtocolGate):
            def __init__(self):
                super().__init__(default_limit=1, launch_interval_seconds=0)
                self.active_when_paused = []

            def pause_connectivity(self, proxy, **kwargs):
                self.active_when_paused.append(self.snapshot(proxy)["active"])
                return super().pause_connectivity(proxy, **kwargs)

        gate = InspectingGate()
        gate.begin_run(1, healthy_ceiling=1)
        connectivity = _Connectivity({
            "kind": "connectivity_failure",
            "action": "pause",
            "reason_code": "proxy_connect_failed",
        })
        coordinator = _coordinator(gate, connectivity, _InflightGate())
        coordinator.inflight_pipeline = inflight_pipeline_runtime
        transport = SimpleNamespace(
            config={"run_mode": "register", "proxy": "proxy-a"},
            proxy="proxy-a",
        )

        with self.assertRaisesRegex(RuntimeError, "proxy connect failed"):
            coordinator.call_origin(
                transport,
                "auth.openai.com",
                lambda: (_ for _ in ()).throw(RuntimeError("proxy connect failed")),
                success_fn=bool,
            )

        self.assertEqual(gate.active_when_paused, [1])

    def test_non_staged_429_pauses_next_request_without_nested_capacity(self):
        class Connectivity(_Connectivity):
            def report_failure(self, _origin, value):
                if "429" in str(value):
                    return {"kind": "rate_limited"}
                return {"kind": "ignored"}

        gate = ProxyProtocolGate(default_limit=1, launch_interval_seconds=0)
        gate.begin_run(1, healthy_ceiling=1)
        coordinator = _coordinator(gate, Connectivity(), _InflightGate())
        coordinator.inflight_pipeline = inflight_pipeline_runtime
        stop_event = threading.Event()
        transport = SimpleNamespace(
            config={
                "run_mode": "relogin",
                "proxy": "proxy-a",
                "_stop_requested": stop_event,
            },
            proxy="proxy-a",
        )
        callback_ran = threading.Event()
        errors = []

        with gate.acquire("proxy-a"):
            with self.assertRaisesRegex(RuntimeError, "HTTP 429"):
                coordinator.call(
                    transport,
                    lambda: (_ for _ in ()).throw(RuntimeError("HTTP 429")),
                )

            def next_request():
                try:
                    coordinator.call(transport, lambda: callback_ran.set())
                except Exception as exc:
                    errors.append(str(exc))

            worker = threading.Thread(target=next_request)
            worker.start()
            deadline = time.monotonic() + 1.0
            while gate.snapshot("proxy-a")["waiting"] < 1 and time.monotonic() < deadline:
                time.sleep(0.005)

            self.assertEqual(gate.snapshot("proxy-a")["active"], 1)
            self.assertFalse(callback_ran.is_set())
            stop_event.set()
            gate.wake_all()
            worker.join(timeout=1.0)

            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, ["task_stopped"])

        self.assertEqual(gate.snapshot("proxy-a")["active"], 0)

    def test_pause_only_wait_does_not_take_nested_capacity(self):
        gate = ProxyProtocolGate(default_limit=1, launch_interval_seconds=0)
        gate.begin_run(1, healthy_ceiling=1)
        callback_active = []
        callback_ran = threading.Event()

        with gate.acquire("proxy-a"):
            gate.pause_connectivity("proxy-a")

            def wait_then_run():
                gate.wait_until_resumed("proxy-a")
                callback_active.append(gate.snapshot("proxy-a")["active"])
                callback_ran.set()

            worker = threading.Thread(target=wait_then_run)
            worker.start()
            deadline = time.monotonic() + 1.0
            while gate.snapshot("proxy-a")["waiting"] < 1 and time.monotonic() < deadline:
                time.sleep(0.005)

            self.assertFalse(callback_ran.is_set())
            self.assertEqual(gate.snapshot("proxy-a")["active"], 1)
            gate.resume_connectivity("proxy-a")
            worker.join(timeout=1.0)

            self.assertFalse(worker.is_alive())
            self.assertEqual(callback_active, [1])

        self.assertEqual(gate.snapshot("proxy-a")["active"], 0)

    def test_pause_only_wait_remains_cancellable(self):
        gate = ProxyProtocolGate(default_limit=1, launch_interval_seconds=0)
        gate.pause_connectivity("proxy-a")
        stop_event = threading.Event()
        errors = []

        def wait_for_resume():
            try:
                gate.wait_until_resumed("proxy-a", stop_event=stop_event)
            except Exception as exc:
                errors.append(str(exc))

        worker = threading.Thread(target=wait_for_resume)
        worker.start()
        deadline = time.monotonic() + 1.0
        while gate.snapshot("proxy-a")["waiting"] < 1 and time.monotonic() < deadline:
            time.sleep(0.005)
        stop_event.set()
        gate.wake_all()
        worker.join(timeout=1.0)

        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, ["task_stopped"])
        self.assertEqual(gate.snapshot("proxy-a")["waiting"], 0)

    def test_equal_ceiling_emits_recovery_qualified_event_and_resumes_inflight(self):
        gate = ProxyProtocolGate(default_limit=8, launch_interval_seconds=0)
        gate.begin_run(8, healthy_ceiling=8)
        gate.guard_expansion("proxy-a")
        inflight = _InflightGate(suspended=True)
        coordinator = _coordinator(gate, _Connectivity(), inflight)
        events = []

        for _ in range(5):
            coordinator.observe_main_chain_outcome(
                None,
                succeeded=True,
                task_id="task-a",
                proxy="proxy-a",
                on_limit_change=events.append,
            )

        self.assertTrue(inflight.suspended)
        self.assertEqual(events, [])

        coordinator.observe_main_chain_outcome(
            None,
            succeeded=True,
            task_id="task-a",
            proxy="proxy-a",
            on_limit_change=events.append,
        )

        self.assertFalse(inflight.suspended)
        self.assertEqual(inflight.resume_calls, 1)
        self.assertEqual(
            events,
            [
                {
                    "kind": "recovery_qualified",
                    "old_limit": 8,
                    "new_limit": 8,
                    "ceiling": 8,
                    "baseline": 8,
                    "recovery_qualified": True,
                    "proxy_key": gate.key("proxy-a"),
                }
            ],
        )
        self.assertFalse(gate.snapshot("proxy-a")["recovery_required"])

    def test_higher_ceiling_still_ramps_one_slot_per_six_successes(self):
        gate = ProxyProtocolGate(default_limit=8, launch_interval_seconds=0)
        gate.begin_run(8, healthy_ceiling=12)
        events = []

        for _ in range(24):
            gate.report("proxy-a", success=True, on_limit_change=events.append)

        self.assertEqual(gate.snapshot("proxy-a")["limit"], 12)
        self.assertEqual(
            [(event["old_limit"], event["new_limit"]) for event in events],
            [(8, 9), (9, 10), (10, 11), (11, 12)],
        )
        self.assertTrue(all(event["kind"] == "restored" for event in events))
        self.assertTrue(all(not event["recovery_qualified"] for event in events))

    def test_low_baseline_is_preserved_and_can_ramp_to_fifteen(self):
        gate = ProxyProtocolGate(default_limit=5, launch_interval_seconds=0)
        gate.begin_run(5, healthy_ceiling=15)

        self.assertEqual(gate.snapshot("proxy-a")["baseline"], 5)
        for _index in range(60):
            gate.report("proxy-a", success=True)

        snapshot = gate.snapshot("proxy-a")
        self.assertEqual((snapshot["baseline"], snapshot["limit"]), (5, 15))

    def test_connection_errors_never_reduce_below_the_configured_baseline(self):
        gate = ProxyProtocolGate(default_limit=8, launch_interval_seconds=0)
        gate.begin_run(8, healthy_ceiling=12)

        for _index in range(20):
            gate.report("proxy-a", "TLS connection reset")

        self.assertEqual(gate.snapshot("proxy-a")["limit"], 8)

    def test_connectivity_recovery_does_not_clear_active_http_429_cooldown(self):
        clock = [100.0]
        gate = ProxyProtocolGate(
            default_limit=8,
            now_fn=lambda: clock[0],
            launch_interval_seconds=0,
        )
        gate.begin_run(8, healthy_ceiling=12)

        gate.pause_connectivity("proxy-a")
        gate.apply_http_429("proxy-a", cooldown_seconds=30)
        gate.resume_connectivity("proxy-a")

        snapshot = gate.snapshot("proxy-a")
        self.assertTrue(snapshot["paused"])
        self.assertEqual(snapshot["pause_reason"], "http_429")
        self.assertEqual(snapshot["pause_remaining_seconds"], 30)
        self.assertTrue(snapshot["sticky_baseline"])

        clock[0] += 31
        self.assertFalse(gate.snapshot("proxy-a")["paused"])
        for _index in range(24):
            gate.report("proxy-a", success=True)
        self.assertEqual(gate.snapshot("proxy-a")["limit"], 8)

    def test_outage_during_http_429_cooldown_remains_paused_after_cooldown(self):
        clock = [100.0]
        gate = ProxyProtocolGate(
            default_limit=8,
            now_fn=lambda: clock[0],
            launch_interval_seconds=0,
        )
        gate.begin_run(8, healthy_ceiling=12)
        gate.apply_http_429("proxy-a", cooldown_seconds=30)
        coordinator = _coordinator(
            gate,
            _Connectivity(
                {
                    "kind": "connectivity_failure",
                    "action": "pause",
                    "reason_code": "proxy_connect_failed",
                }
            ),
            _InflightGate(),
        )

        coordinator.observe_connectivity_result(
            "auth.openai.com",
            RuntimeError("proxy connect failed"),
            proxy="proxy-a",
        )
        clock[0] += 31

        snapshot = gate.snapshot("proxy-a")
        self.assertTrue(snapshot["paused"])
        self.assertEqual(snapshot["pause_reason"], "openai_connectivity_outage")
        self.assertEqual(snapshot["pause_remaining_seconds"], 0)

        gate.resume_connectivity("proxy-a")
        self.assertFalse(gate.snapshot("proxy-a")["paused"])

    def test_inherited_outage_does_not_count_as_a_new_batch_incident(self):
        gate = ProxyProtocolGate(default_limit=8, launch_interval_seconds=0)
        gate.begin_run(8, healthy_ceiling=12)
        connectivity = SimpleNamespace(
            condition=threading.Condition(threading.RLock()),
            snapshot=lambda: {"paused": True, "status": "outage"},
        )
        coordinator = _coordinator(gate, connectivity, _InflightGate())

        coordinator.synchronize_connectivity_pause(
            "proxy-a",
            _InflightGate(),
        )
        gate.resume_connectivity("proxy-a")
        gate.pause_connectivity("proxy-a")
        self.assertFalse(gate.snapshot("proxy-a")["sticky_baseline"])

        gate.resume_connectivity("proxy-a")
        gate.pause_connectivity("proxy-a")
        self.assertTrue(gate.snapshot("proxy-a")["sticky_baseline"])


if __name__ == "__main__":
    unittest.main()
