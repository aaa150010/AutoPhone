from __future__ import annotations

import unittest

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


class FreeRoxyOpenReconciliationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
