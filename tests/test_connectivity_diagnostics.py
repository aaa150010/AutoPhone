from __future__ import annotations

import unittest

from mac_overrides.connectivity_diagnostics import OpenAIConnectivityDiagnostics


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _Session:
    trust_env = True

    def __init__(self, outcomes, calls) -> None:
        self.outcomes = outcomes
        self.calls = calls
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        outcome = self.outcomes[url]
        if isinstance(outcome, BaseException):
            raise outcome
        return _Response(outcome)

    def close(self):
        self.closed = True


class ConnectivityDiagnosticsTests(unittest.TestCase):
    def make_runtime(self, outcomes, node_bridge):
        calls = []
        sessions = []

        def factory():
            session = _Session(outcomes, calls)
            sessions.append(session)
            return session

        runtime = OpenAIConnectivityDiagnostics(
            config_getter=lambda: {
                "proxy": "http://user:private-password@127.0.0.1:7897",
                "node_timeout": 90,
                "codex_node_runner": "/safe/runner.js",
            },
            node_bridge=node_bridge,
            session_factory=factory,
            now_fn=lambda: 1_700_000_000,
        )
        return runtime, calls, sessions

    def test_success_tests_both_origins_and_real_sentinel_without_returning_token(self):
        bridge_calls = []
        runtime, calls, sessions = self.make_runtime(
            {
                "https://auth.openai.com/": 302,
                "https://sentinel.openai.com/": 404,
            },
            lambda **kwargs: bridge_calls.append(kwargs) or {
                "ok": True,
                "token_generated": True,
                "token": "must-not-escape",
            },
        )

        result = runtime.run()

        self.assertEqual(result["overall"], "healthy")
        self.assertEqual([row["origin"] for row in result["network"]], [
            "auth.openai.com", "sentinel.openai.com",
        ])
        self.assertTrue(result["sentinel"]["ok"])
        self.assertNotIn("must-not-escape", repr(result))
        self.assertEqual(bridge_calls[0]["timeout"], 45)
        self.assertTrue(all(session.closed for session in sessions))
        self.assertTrue(all(call[1]["allow_redirects"] is False for call in calls))

    def test_network_failure_is_specific_redacted_and_skips_sentinel(self):
        bridge_calls = []
        runtime, _calls, _sessions = self.make_runtime(
            {
                "https://auth.openai.com/": 302,
                "https://sentinel.openai.com/": RuntimeError(
                    "Unable to connect to proxy private-password"
                ),
            },
            lambda **kwargs: bridge_calls.append(kwargs) or {},
        )

        result = runtime.run()
        sentinel_origin = result["network"][1]

        self.assertEqual(result["overall"], "failed")
        self.assertEqual(sentinel_origin["reason_code"], "proxy_connection_failed")
        self.assertNotIn("private-password", repr(result))
        self.assertFalse(result["sentinel"]["attempted"])
        self.assertEqual(bridge_calls, [])

    def test_rate_limit_is_reachable_but_degraded_and_skips_sentinel(self):
        bridge_calls = []
        runtime, _calls, _sessions = self.make_runtime(
            {
                "https://auth.openai.com/": 302,
                "https://sentinel.openai.com/": 429,
            },
            lambda **kwargs: bridge_calls.append(kwargs) or {},
        )

        result = runtime.run()
        sentinel_origin = result["network"][1]

        self.assertEqual(result["overall"], "degraded")
        self.assertTrue(sentinel_origin["reachable"])
        self.assertFalse(sentinel_origin["service_available"])
        self.assertEqual(sentinel_origin["service_status"], "rate_limited")
        self.assertEqual(sentinel_origin["reason_code"], "http_429")
        self.assertIn("限流", result["sentinel"]["public_message"])
        self.assertEqual(bridge_calls, [])

    def test_upstream_503_is_reachable_but_degraded_and_skips_sentinel(self):
        bridge_calls = []
        runtime, _calls, _sessions = self.make_runtime(
            {
                "https://auth.openai.com/": 302,
                "https://sentinel.openai.com/": 503,
            },
            lambda **kwargs: bridge_calls.append(kwargs) or {},
        )

        result = runtime.run()
        sentinel_origin = result["network"][1]

        self.assertEqual(result["overall"], "degraded")
        self.assertTrue(sentinel_origin["reachable"])
        self.assertEqual(sentinel_origin["service_status"], "upstream_error")
        self.assertEqual(sentinel_origin["reason_code"], "http_5xx")
        self.assertIn("服务异常", result["sentinel"]["public_message"])
        self.assertEqual(bridge_calls, [])


if __name__ == "__main__":
    unittest.main()
