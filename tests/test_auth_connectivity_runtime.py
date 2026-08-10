from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from mac_overrides.auth_connectivity_runtime import (
    AUTH_ORIGIN,
    KIND_CONNECTIVITY,
    KIND_OTHER,
    KIND_RATE_LIMITED,
    OpenAIAuthConnectivityRuntime,
    SENTINEL_ORIGIN,
    STATUS_HEALTHY,
    STATUS_OUTAGE,
    STATUS_RECOVERING,
    classify_openai_connectivity_failure,
    proxy_fingerprint,
)


PRIVATE_PROXY = "http://private-user:private-password@127.0.0.1:7897"


class FakeClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class FakeThread:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.started = False

    def start(self) -> None:
        self.started = True

    def is_alive(self) -> bool:
        return self.started


class AuthConnectivityRuntimeTests(unittest.TestCase):
    def make_runtime(self, **kwargs):
        kwargs.setdefault("proxy", PRIVATE_PROXY)
        kwargs.setdefault("auto_start_worker", False)
        kwargs.setdefault("id_factory", lambda: "event0001")
        return OpenAIAuthConnectivityRuntime(**kwargs)

    def trigger_outage(self, runtime, origin=AUTH_ORIGIN):
        first = runtime.observe_failure(origin, "curl: (35) TLS handshake failed")
        second = runtime.observe_failure(origin, "curl: (56) remote disconnected")
        self.assertEqual(first["action"], "cancel_expansion")
        self.assertEqual(second["action"], "pause")

    def test_classifier_separates_connectivity_rate_limit_and_business_errors(self):
        class Response429:
            status_code = 429

        class RateLimitError(RuntimeError):
            response = Response429()

        for value in (
            "ProxyError: unable to connect to proxy",
            "SSLError: TLS handshake failed",
            "ConnectTimeout: connection timed out",
            "curl: (56) remote end closed connection",
            "curl: (7) failed to connect",
        ):
            self.assertEqual(
                classify_openai_connectivity_failure(value).kind,
                KIND_CONNECTIVITY,
            )
        self.assertEqual(
            classify_openai_connectivity_failure(RateLimitError()).kind,
            KIND_RATE_LIMITED,
        )
        self.assertEqual(
            classify_openai_connectivity_failure("HTTP 429 too many requests").kind,
            KIND_RATE_LIMITED,
        )
        for value in (
            "HTTP 403: connection closed",
            "HTTPStatusError: 403 connection closed",
            "status_code=403 connection reset",
        ):
            self.assertEqual(
                classify_openai_connectivity_failure(value).reason_code,
                "openai_http_response",
            )
        for value in (
            {"status_code": 401},
            "account banned",
            "incorrect password",
            "sentinel challenge rejected",
        ):
            self.assertEqual(
                classify_openai_connectivity_failure(value).kind,
                KIND_OTHER,
            )

    def test_threshold_is_per_origin_with_a_sixty_second_window(self):
        clock = FakeClock()
        runtime = self.make_runtime(now_fn=clock)

        auth = runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        sentinel = runtime.observe_failure(SENTINEL_ORIGIN, "TLS handshake failed")
        self.assertEqual(auth["action"], "cancel_expansion")
        self.assertEqual(sentinel["action"], "cancel_expansion")
        self.assertFalse(runtime.snapshot()["paused"])

        clock.advance(61)
        expired = runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        self.assertEqual(expired["action"], "cancel_expansion")
        self.assertFalse(runtime.snapshot()["paused"])
        runtime.observe_success(AUTH_ORIGIN)
        confirmed = runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        self.assertEqual(confirmed["action"], "cancel_expansion")

    def test_only_allowed_openai_origins_can_trigger_an_outage(self):
        runtime = self.make_runtime()
        for _ in range(3):
            decision = runtime.observe_failure(
                "sms-provider.example.com", "ProxyError: failed to connect"
            )
        self.assertEqual(decision["action"], "ignored")
        self.assertFalse(runtime.snapshot()["paused"])

        for value in ({"status": 429}, {"status": 403}, "incorrect password"):
            runtime.observe_failure(AUTH_ORIGIN, value)
        self.assertFalse(runtime.snapshot()["paused"])

    def test_outage_pauses_and_callbacks_are_deduplicated_and_redacted(self):
        outages = []
        runtime = self.make_runtime(on_outage=outages.append)
        self.trigger_outage(runtime)
        runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")

        snapshot = runtime.snapshot()
        self.assertEqual(snapshot["status"], STATUS_OUTAGE)
        self.assertTrue(snapshot["paused"])
        self.assertEqual(snapshot["pause_reason"], "openai_auth_connectivity_outage")
        self.assertEqual(len(outages), 1)
        self.assertEqual(outages[0]["event_id"], "event0001")
        self.assertEqual(outages[0]["proxy_fingerprint"], proxy_fingerprint(PRIVATE_PROXY))
        self.assertNotIn(PRIVATE_PROXY, str(outages))
        self.assertNotIn("private-password", str(outages))

    def test_two_complete_parallel_probe_rounds_recover(self):
        clock = FakeClock()
        outcomes = {
            AUTH_ORIGIN: [204, 302],
            SENTINEL_ORIGIN: [404, 200],
        }
        calls = []
        recoveries = []

        def probe(origin, proxy, timeout):
            calls.append((origin, proxy, timeout))
            return outcomes[origin].pop(0)

        runtime = self.make_runtime(
            now_fn=clock,
            probe_fn=probe,
            on_recovery=recoveries.append,
        )
        self.trigger_outage(runtime)
        clock.advance(10)
        first = runtime.run_probe_round()
        self.assertEqual(first["status"], STATUS_RECOVERING)
        self.assertTrue(runtime.snapshot()["paused"])
        self.assertEqual(first["successful_rounds"], 1)

        clock.advance(10)
        second = runtime.run_probe_round()
        self.assertTrue(second["recovered"])
        self.assertEqual(second["status"], STATUS_HEALTHY)
        self.assertFalse(runtime.snapshot()["paused"])
        self.assertEqual(len(recoveries), 1)
        self.assertEqual({row[0] for row in calls}, {AUTH_ORIGIN, SENTINEL_ORIGIN})
        self.assertTrue(all(row[1] == PRIVATE_PROXY and row[2] == 5 for row in calls))

    def test_incomplete_probe_round_resets_recovery_progress(self):
        clock = FakeClock()
        rounds = iter(
            [
                {AUTH_ORIGIN: 204, SENTINEL_ORIGIN: 404},
                {AUTH_ORIGIN: 204, SENTINEL_ORIGIN: 429},
                {AUTH_ORIGIN: 204, SENTINEL_ORIGIN: 404},
                {AUTH_ORIGIN: 204, SENTINEL_ORIGIN: 404},
            ]
        )
        current = {}
        lock = threading.Lock()

        def probe(origin, _proxy, _timeout):
            with lock:
                if not current:
                    current.update(next(rounds))
                value = current.pop(origin)
            return value

        runtime = self.make_runtime(now_fn=clock, probe_fn=probe)
        self.trigger_outage(runtime)
        self.assertEqual(runtime.run_probe_round()["successful_rounds"], 1)
        failed = runtime.run_probe_round()
        self.assertFalse(failed["successful"])
        self.assertEqual(failed["successful_rounds"], 0)
        self.assertEqual(runtime.run_probe_round()["successful_rounds"], 1)
        self.assertTrue(runtime.run_probe_round()["recovered"])

    def test_real_failure_invalidates_an_inflight_recovery_probe(self):
        probe_started = threading.Condition()
        release_probe = threading.Event()
        probe_calls = 0

        def probe(_origin, _proxy, _timeout):
            nonlocal probe_calls
            with probe_started:
                probe_calls += 1
                probe_started.notify_all()
            release_probe.wait(timeout=1)
            return 204

        runtime = self.make_runtime(probe_fn=probe)
        self.trigger_outage(runtime)
        reports = []
        runner = threading.Thread(target=lambda: reports.append(runtime.run_probe_round()))
        runner.start()
        with probe_started:
            self.assertTrue(probe_started.wait_for(lambda: probe_calls == 2, timeout=1))

        failed = runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        self.assertEqual(failed["action"], "already_paused")
        self.assertEqual(runtime.snapshot()["probe_successful_rounds"], 0)
        release_probe.set()
        runner.join(timeout=1)

        self.assertFalse(runner.is_alive())
        self.assertFalse(reports[0]["complete"])
        self.assertEqual(runtime.snapshot()["status"], STATUS_OUTAGE)

    def test_real_failure_breaks_consecutive_probe_success(self):
        runtime = self.make_runtime(probe_fn=lambda *_args: 204)
        self.trigger_outage(runtime)
        self.assertEqual(runtime.run_probe_round()["successful_rounds"], 1)

        runtime.observe_failure(SENTINEL_ORIGIN, "connection reset")
        snapshot = runtime.snapshot()
        self.assertEqual(snapshot["status"], STATUS_OUTAGE)
        self.assertEqual(snapshot["probe_successful_rounds"], 0)
        self.assertEqual(runtime.run_probe_round()["successful_rounds"], 1)
        self.assertTrue(runtime.run_probe_round()["recovered"])

    def test_default_probe_disables_environment_auth_and_redirects(self):
        sessions = []

        class Cookies:
            cleared = False

            def clear(self):
                self.cleared = True

        class Response:
            status_code = 302

        class Session:
            def __init__(self):
                self.trust_env = True
                self.cookies = Cookies()
                self.calls = []
                self.closed = False
                sessions.append(self)

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                return Response()

            def close(self):
                self.closed = True

        runtime = self.make_runtime(session_factory=Session)
        result = runtime._probe_endpoint(AUTH_ORIGIN)

        self.assertTrue(result.reachable)
        self.assertFalse(sessions[0].trust_env)
        self.assertTrue(sessions[0].cookies.cleared)
        self.assertTrue(sessions[0].closed)
        url, kwargs = sessions[0].calls[0]
        self.assertEqual(url, "https://auth.openai.com/")
        self.assertEqual(kwargs["timeout"], 5)
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(
            kwargs["proxies"], {"http": PRIVATE_PROXY, "https": PRIVATE_PROXY}
        )
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertNotIn("Cookie", kwargs["headers"])

    def test_probe_session_construction_failure_is_a_retryable_round_failure(self):
        def fail_session():
            raise RuntimeError("proxy-password-must-not-escape")

        runtime = self.make_runtime(session_factory=fail_session)
        self.trigger_outage(runtime)
        report = runtime.run_probe_round()

        self.assertTrue(report["complete"])
        self.assertFalse(report["successful"])
        self.assertEqual(runtime.snapshot()["status"], STATUS_OUTAGE)
        self.assertNotIn("proxy-password-must-not-escape", str(report))

    def test_probe_close_failure_does_not_escape_or_replace_result(self):
        class Response:
            status_code = 204

        class Session:
            def get(self, _url, **_kwargs):
                return Response()

            def close(self):
                raise RuntimeError("proxy-password-must-not-escape")

        runtime = self.make_runtime(session_factory=Session)
        result = runtime._probe_endpoint(AUTH_ORIGIN)

        self.assertTrue(result.reachable)
        self.assertEqual(result.status_code, 204)

    def test_probe_endpoint_uses_the_proxy_captured_for_its_round(self):
        calls = []
        runtime = self.make_runtime(
            probe_fn=lambda origin, proxy, timeout: calls.append(
                (origin, proxy, timeout)
            ) or 204
        )
        runtime.configure_proxy("http://127.0.0.1:9999")

        result = runtime._probe_endpoint(AUTH_ORIGIN, PRIVATE_PROXY)

        self.assertTrue(result.reachable)
        self.assertEqual(calls, [(AUTH_ORIGIN, PRIVATE_PROXY, 5.0)])

    def test_stale_probe_generation_cannot_recover_a_new_same_proxy_outage(self):
        first_proxy = PRIVATE_PROXY
        second_proxy = "http://127.0.0.1:9999"
        started = threading.Condition()
        release = threading.Event()
        calls = []
        event_ids = iter(("event0001", "event0002"))

        def probe(origin, proxy, _timeout):
            with started:
                calls.append((origin, proxy))
                started.notify_all()
            release.wait(timeout=1)
            return 204

        runtime = self.make_runtime(probe_fn=probe, id_factory=lambda: next(event_ids))
        self.trigger_outage(runtime)
        reports = []
        runner = threading.Thread(target=lambda: reports.append(runtime.run_probe_round()))
        runner.start()
        with started:
            self.assertTrue(started.wait_for(lambda: len(calls) == 2, timeout=1))

        runtime.configure_proxy(second_proxy)
        runtime.configure_proxy(first_proxy)
        self.trigger_outage(runtime)
        release.set()
        runner.join(timeout=1)

        self.assertFalse(runner.is_alive())
        self.assertEqual({proxy for _origin, proxy in calls}, {first_proxy})
        self.assertEqual(reports[0]["complete"], False)
        snapshot = runtime.snapshot()
        self.assertEqual(snapshot["event_id"], "event0002")
        self.assertEqual(snapshot["status"], STATUS_OUTAGE)
        self.assertEqual(snapshot["probe_successful_rounds"], 0)

    def test_success_and_recovery_clear_historical_affected_origins(self):
        recoveries = []
        runtime = self.make_runtime(
            probe_fn=lambda *_args: 204,
            on_recovery=recoveries.append,
        )
        runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        runtime.observe_success(AUTH_ORIGIN)
        self.trigger_outage(runtime, SENTINEL_ORIGIN)
        self.assertEqual(runtime.snapshot()["affected_origins"], [SENTINEL_ORIGIN])

        runtime.run_probe_round()
        runtime.run_probe_round()
        self.assertEqual(recoveries[0]["affected_origins"], [SENTINEL_ORIGIN])
        self.assertEqual(runtime.snapshot()["affected_origins"], [])

        runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        self.assertEqual(runtime.snapshot()["affected_origins"], [AUTH_ORIGIN])

    def test_state_is_atomic_private_safe_and_restores_same_proxy_outage(self):
        outages = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openai_auth_connectivity.json"
            first = self.make_runtime(state_path=path, on_outage=outages.append)
            self.trigger_outage(first)

            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(PRIVATE_PROXY, text)
            self.assertNotIn("private-user", text)
            self.assertNotIn("private-password", text)
            payload = json.loads(text)
            self.assertEqual(payload["proxy_fingerprint"], proxy_fingerprint(PRIVATE_PROXY))

            restored = self.make_runtime(state_path=path, on_outage=outages.append)
            self.assertTrue(restored.snapshot()["paused"])
            self.assertEqual(len(outages), 1)

            changed = restored.configure_proxy("http://127.0.0.1:9999")
            self.assertTrue(changed)
            self.assertFalse(restored.snapshot()["paused"])
            self.assertEqual(restored.snapshot()["status"], "unknown")

    def test_restored_next_probe_time_is_bounded_to_one_interval(self):
        clock = FakeClock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openai_auth_connectivity.json"
            path.write_text(
                json.dumps(
                    {
                        "status": STATUS_OUTAGE,
                        "reason_code": "openai_tls_connection_failure",
                        "event_id": "event0001",
                        "revision": 7,
                        "proxy_fingerprint": proxy_fingerprint(PRIVATE_PROXY),
                        "detected_at": clock(),
                        "next_probe_at": 9_999_999_999,
                        "affected_origins": [AUTH_ORIGIN],
                    }
                ),
                encoding="utf-8",
            )

            runtime = self.make_runtime(state_path=path, now_fn=clock)
            self.assertLessEqual(
                runtime.snapshot()["next_probe_at"],
                clock() + runtime.probe_interval_seconds,
            )

    def test_corrupt_state_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openai_auth_connectivity.json"
            path.write_text("{not-json private-password", encoding="utf-8")
            runtime = self.make_runtime(state_path=path)
            snapshot = runtime.snapshot()
            self.assertEqual(snapshot["status"], "unknown")
            self.assertFalse(snapshot["paused"])

    def test_worker_thread_is_injected_and_started_on_outage(self):
        threads = []

        def factory(**kwargs):
            thread = FakeThread(**kwargs)
            threads.append(thread)
            return thread

        runtime = OpenAIAuthConnectivityRuntime(
            proxy=PRIVATE_PROXY,
            auto_start_worker=True,
            thread_factory=factory,
            id_factory=lambda: "event0001",
        )
        self.trigger_outage(runtime)
        self.assertEqual(len(threads), 1)
        self.assertTrue(threads[0].started)
        self.assertEqual(threads[0].kwargs["name"], "openai-auth-connectivity-probe")

    def test_exiting_worker_hands_a_new_outage_to_a_replacement(self):
        class HandoffRuntime(OpenAIAuthConnectivityRuntime):
            def __init__(self, **kwargs):
                self.worker_count = 0
                self.first_exiting = threading.Event()
                self.allow_first_cleanup = threading.Event()
                self.replacement_finished = threading.Event()
                super().__init__(**kwargs)

            def _probe_worker(self):
                worker = threading.current_thread()
                self.worker_count += 1
                if self.worker_count == 1:
                    self.first_exiting.set()
                    self.allow_first_cleanup.wait(timeout=1)
                else:
                    self.close()
                    self.replacement_finished.set()
                self._finish_probe_worker(worker)

        runtime = HandoffRuntime(
            proxy=PRIVATE_PROXY,
            auto_start_worker=True,
            id_factory=lambda: "event0001",
        )
        self.trigger_outage(runtime)
        self.assertTrue(runtime.first_exiting.wait(timeout=1))
        self.assertFalse(runtime.start_probe_worker())

        runtime.allow_first_cleanup.set()
        self.assertTrue(runtime.replacement_finished.wait(timeout=1))
        self.assertEqual(runtime.worker_count, 2)

    def test_waiters_resume_on_recovery_and_stop_can_cancel(self):
        runtime = self.make_runtime(probe_fn=lambda *_args: True)
        self.trigger_outage(runtime)
        stopped = threading.Event()
        results = []

        waiter = threading.Thread(
            target=lambda: results.append(runtime.wait_until_available(stop_event=stopped))
        )
        waiter.start()
        time.sleep(0.02)
        stopped.set()
        runtime.wake_waiters()
        waiter.join(timeout=1)
        self.assertEqual(results, [False])

        recovered = []
        waiter = threading.Thread(target=lambda: recovered.append(runtime.wait_until_available()))
        waiter.start()
        time.sleep(0.02)
        runtime.run_probe_round()
        runtime.run_probe_round()
        waiter.join(timeout=1)
        self.assertEqual(recovered, [True])

    def test_callback_failure_does_not_escape_or_repeat(self):
        calls = []

        def broken(payload):
            calls.append(payload["event_id"])
            raise RuntimeError("smtp unavailable private-password")

        runtime = self.make_runtime(on_outage=broken)
        self.trigger_outage(runtime)
        runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        self.assertEqual(calls, ["event0001"])

    def test_disabling_guard_is_a_callback_barrier(self):
        callback_started = threading.Event()
        release_callback = threading.Event()
        disable_finished = threading.Event()

        def outage(_payload):
            callback_started.set()
            release_callback.wait(timeout=1)

        runtime = self.make_runtime(on_outage=outage)
        runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        failure = threading.Thread(
            target=lambda: runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        )
        failure.start()
        self.assertTrue(callback_started.wait(timeout=1))

        disabler = threading.Thread(
            target=lambda: (runtime.set_enabled(False), disable_finished.set())
        )
        disabler.start()
        self.assertFalse(disable_finished.wait(timeout=0.05))
        release_callback.set()
        failure.join(timeout=1)
        disabler.join(timeout=1)

        self.assertTrue(disable_finished.is_set())
        snapshot = runtime.snapshot()
        self.assertFalse(snapshot["enabled"])
        self.assertFalse(snapshot["paused"])

    def test_failure_rechecks_enabled_after_waiting_for_state_lock(self):
        classified = threading.Event()
        decisions = []

        class Failure:
            def __str__(self):
                classified.set()
                return "TLS handshake failed"

        runtime = self.make_runtime()
        runtime.observe_failure(AUTH_ORIGIN, "TLS handshake failed")
        runtime._callback_lock.acquire()
        try:
            observer = threading.Thread(
                target=lambda: decisions.append(runtime.observe_failure(AUTH_ORIGIN, Failure()))
            )
            observer.start()
            self.assertTrue(classified.wait(timeout=1))
            runtime.set_enabled(False)
        finally:
            runtime._callback_lock.release()
        observer.join(timeout=1)

        self.assertEqual(decisions[0]["action"], "ignored")
        self.assertFalse(runtime.snapshot()["paused"])


if __name__ == "__main__":
    unittest.main()
