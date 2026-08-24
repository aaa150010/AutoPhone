from __future__ import annotations

import unittest

from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.free_roxy_runtime import RoxyBrowserClient


class _Response:
    status_code = 200
    text = ""

    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value


class _OpenTimeoutSession:
    """Roxy starts the Profile but times out before returning /browser/open."""

    def __init__(self):
        self.headers = {}
        self.calls = []
        self.connection_checks = 0

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if url.endswith("/browser/connection_info"):
            self.connection_checks += 1
            if self.connection_checks == 1:
                return _Response({"code": 0, "data": []})
            return _Response({"code": 0, "data": [{
                "dirId": "42",
                "http": "127.0.0.1:9222",
                "driver": "/opt/roxy/chromedriver",
            }]})
        if url.endswith("/browser/open"):
            raise TimeoutError("ReadTimeout while waiting for Roxy open response")
        return _Response({"code": 0})


class _StructuredOpenErrorSession:
    def __init__(self, status: int):
        self.headers = {}
        self.calls = []
        self.connection_checks = 0
        self.open_error = FreeRegisterError(
            "free_roxy_api",
            "调用 RoxyBrowser API",
            f"RoxyBrowser API 返回 HTTP {status}",
            retryable=status in {429, 500, 502, 503, 504},
            provider_status=status,
            error_code="roxy_open_rate_limited" if status == 429 else "roxy_open_upstream_busy",
            provider_code="window_rate_limit" if status == 429 else "upstream_busy",
            diagnostic=f"provider_status={status}; response=redacted",
            action_hint="等待 RoxyBrowser API 恢复后重试",
        )

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if url.endswith("/browser/connection_info"):
            self.connection_checks += 1
            return _Response({"code": 0, "data": []})
        if url.endswith("/browser/open"):
            raise self.open_error
        return _Response({"code": 0})


class _ConnectionInfoHttpErrorSession:
    def __init__(self, status: int = 403):
        self.headers = {}
        self.calls = []
        self.status = status

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if url.endswith("/browser/connection_info"):
            return _ResponseWithError(
                self.status,
                {
                    "error": {"code": "profile_access_denied"},
                    "provider_code": "workspace_auth_failed",
                    "message": "authorization detail must not be copied",
                },
            )
        return _Response({"code": 0, "data": {}})


class _ResponseWithError:
    def __init__(self, status: int, value):
        self.status_code = status
        self.value = value
        self.text = "redacted response body"

    def json(self):
        return self.value


class _StructuredPayloadErrorSession:
    def __init__(self):
        self.headers = {}

    def request(self, _method, _url, **_kwargs):
        return _Response({
            "code": 1001,
            "error": {
                "error_code": "profile_not_ready",
                "message": "secret response detail must not be copied",
            },
            "provider_code": "profile_bootstrap_pending",
        })


class FreeRoxyOpenReconciliationTests(unittest.TestCase):
    def test_http_error_keeps_provider_codes_without_response_body(self):
        session = _ConnectionInfoHttpErrorSession()
        client = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000", "api_retries": 1}, session=session)

        with self.assertRaises(FreeRegisterError) as raised:
            client.request("GET", "/browser/connection_info", retries=1)

        failure = raised.exception
        self.assertEqual(failure.node_code, "free_roxy_api")
        self.assertEqual(failure.error_code, "free_roxy_api_http")
        self.assertEqual(failure.provider_status, 403)
        self.assertEqual(failure.provider_code, "workspace_auth_failed")
        self.assertIn("error_code=profile_access_denied", failure.diagnostic)
        self.assertNotIn("authorization detail", failure.diagnostic)
        self.assertNotIn("redacted response body", str(failure))

    def test_connection_info_http_error_is_not_treated_as_startup_race(self):
        session = _ConnectionInfoHttpErrorSession(429)
        client = RoxyBrowserClient({
            "api_base": "http://127.0.0.1:50000",
            "api_retries": 1,
            "open_connection_timeout": 0.1,
        }, session=session)

        with self.assertRaises(FreeRegisterError) as raised:
            client.open_profile("42")

        self.assertEqual(raised.exception.provider_status, 429)
        self.assertEqual(
            [url.rsplit("/", 1)[-1] for _method, url, _body in session.calls],
            ["connection_info"],
        )

    def test_structured_api_error_keeps_codes_without_raw_payload(self):
        client = RoxyBrowserClient(
            {"api_base": "http://127.0.0.1:50000", "api_retries": 1},
            session=_StructuredPayloadErrorSession(),
        )

        with self.assertRaises(FreeRegisterError) as raised:
            client.request("GET", "/browser/connection_info", retries=1)

        failure = raised.exception
        self.assertEqual(failure.error_code, "free_roxy_api_response")
        self.assertEqual(failure.provider_code, "profile_bootstrap_pending")
        self.assertIn("error_code=profile_not_ready", failure.diagnostic)
        self.assertNotIn("secret response detail", str(failure))

    def test_timeout_adopts_connection_without_duplicate_open(self):
        session = _OpenTimeoutSession()
        client = RoxyBrowserClient({
            "api_base": "http://127.0.0.1:50000",
            "workspace_id": "w",
            "api_retries": 1,
            "headless": True,
        }, session=session)

        opened = client.open_profile("42")

        self.assertEqual(opened.debugger_address, "127.0.0.1:9222")
        self.assertTrue(opened.connection_reused)
        self.assertEqual(
            [url.rsplit("/", 1)[-1] for _method, url, _body in session.calls],
            ["connection_info", "open", "connection_info"],
        )
        self.assertEqual(
            sum(url.endswith("/browser/open") for _method, url, _body in session.calls),
            1,
        )

    def test_explicit_429_preserves_failure_without_connection_reconciliation(self):
        session = _StructuredOpenErrorSession(429)
        client = RoxyBrowserClient({
            "api_base": "http://127.0.0.1:50000",
            "workspace_id": "w",
            "api_retries": 1,
            "open_connection_timeout": 0.1,
        }, session=session)

        with self.assertRaises(FreeRegisterError) as raised:
            client.open_profile("42")

        failure = raised.exception
        self.assertIs(failure, session.open_error)
        self.assertEqual(failure.node_code, "free_roxy_api")
        self.assertEqual(failure.error_code, "roxy_open_rate_limited")
        self.assertEqual(failure.provider_status, 429)
        self.assertEqual(failure.provider_code, "window_rate_limit")
        self.assertEqual(failure.diagnostic, "provider_status=429; response=redacted")
        self.assertEqual(failure.action_hint, "等待 RoxyBrowser API 恢复后重试")
        self.assertEqual(session.connection_checks, 1)
        self.assertEqual(
            [url.rsplit("/", 1)[-1] for _method, url, _body in session.calls],
            ["connection_info", "open"],
        )

    def test_explicit_403_is_not_treated_as_an_ambiguous_open(self):
        session = _StructuredOpenErrorSession(403)
        client = RoxyBrowserClient({
            "api_base": "http://127.0.0.1:50000",
            "workspace_id": "w",
            "api_retries": 1,
            "open_connection_timeout": 0.1,
        }, session=session)

        with self.assertRaises(FreeRegisterError) as raised:
            client.open_profile("42")

        self.assertIs(raised.exception, session.open_error)
        self.assertEqual(session.connection_checks, 1)
        self.assertEqual(
            sum(url.endswith("/browser/open") for _method, url, _body in session.calls),
            1,
        )

    def test_503_reconciliation_failure_keeps_provider_diagnostics(self):
        session = _StructuredOpenErrorSession(503)
        client = RoxyBrowserClient({
            "api_base": "http://127.0.0.1:50000",
            "workspace_id": "w",
            "api_retries": 1,
            "open_connection_timeout": 0.1,
        }, session=session)

        with self.assertRaises(FreeRegisterError) as raised:
            client.open_profile("42")

        failure = raised.exception
        self.assertEqual(failure.node_code, "free_roxy_open")
        self.assertEqual(failure.error_code, "roxy_open_upstream_busy")
        self.assertEqual(failure.provider_status, 503)
        self.assertEqual(failure.provider_code, "upstream_busy")
        self.assertIn("provider_status=503; response=redacted", failure.diagnostic)
        self.assertIn("connection_info_reconciliation_timeout=", failure.diagnostic)
        self.assertEqual(failure.action_hint, "等待 RoxyBrowser API 恢复后重试")
        self.assertGreater(session.connection_checks, 1)
        self.assertEqual(
            sum(url.endswith("/browser/open") for _method, url, _body in session.calls),
            1,
        )


if __name__ == "__main__":
    unittest.main()
