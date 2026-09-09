from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlsplit

from mac_overrides.remail_api import RemailApiError, RemailClient, remail_order_suffix, remail_order_value


class _Response:
    status = 200

    def __init__(self, value):
        self._raw = json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._raw


class RemailApiTests(unittest.TestCase):
    def test_orders_uses_documented_cursor_query_and_maps_legacy_aliases(self):
        requests = []

        def opener(request, timeout):
            requests.append((request, timeout))
            return _Response({"items": [], "total": 0, "hasNext": False, "limit": 100})

        client = RemailClient(api_key="rk-test", opener=opener)
        client.orders(page=2, page_size=100, after_id=42)

        query = parse_qs(urlsplit(requests[0][0].full_url).query)
        self.assertEqual(query["afterId"], ["42"])
        self.assertEqual(query["limit"], ["100"])
        self.assertEqual(query["serviceMode"], ["purchase"])
        self.assertNotIn("page", query)
        self.assertNotIn("page_size", query)

    def test_order_value_accepts_wrapped_detail_and_direct_order(self):
        wrapped = remail_order_value({"order": {"orderNo": "R-1", "productType": "icloud"}})
        direct = remail_order_value({"orderNo": "R-2", "deliveryEmail": "user@outlook.com"})
        self.assertEqual(wrapped, {"orderNo": "R-1", "productType": "icloud"})
        self.assertEqual(direct, {"orderNo": "R-2", "deliveryEmail": "user@outlook.com"})

    def test_create_order_maps_bare_product_type_to_documented_suffix(self):
        requests = []

        def opener(request, timeout):
            requests.append((request, timeout))
            return _Response({"orderNo": "R-3", "status": "pending_payment"})

        client = RemailClient(api_key="rk-test", opener=opener)
        client.create_order(2, "icloud")
        client.create_order_batch(2, "gmail", 3)
        client.create_order(2, "icloud.com")

        bodies = [json.loads(requests[i][0].data) for i in range(3)]
        self.assertEqual(bodies[0]["emailSuffix"], "icloud.com")
        self.assertEqual(bodies[1]["emailSuffix"], "gmail.com")
        self.assertEqual(bodies[2]["emailSuffix"], "icloud.com")

    def test_order_suffix_passthrough_for_exact_and_special_values(self):
        self.assertEqual(remail_order_suffix("outlook.com"), "outlook.com")
        self.assertEqual(remail_order_suffix("gmail_variant"), "gmail_variant")
        self.assertEqual(remail_order_suffix("domain"), "domain")
        self.assertEqual(remail_order_suffix(""), "")

    def test_default_path_uses_persistent_session_without_host_proxy(self):
        sessions = []

        class _FakeResponse:
            status_code = 200
            url = "https://remail.aishop6.com/v1/pickup?email=x"
            reason = "OK"
            headers = {}
            content = b"{}"

        class _FakeSession:
            def __init__(self):
                self.trust_env = True
                self.calls = []
                sessions.append(self)

            def request(self, method, url, **kwargs):
                self.calls.append((method, url, kwargs))
                return _FakeResponse()

        def factory():
            return _FakeSession()

        client = RemailClient(api_key="rk-test", session_factory=factory)
        client.pickup("user@outlook.com", "token-1")
        client.pickup("user@outlook.com", "token-1")

        self.assertEqual(len(sessions), 1)
        self.assertFalse(sessions[0].trust_env)
        self.assertEqual(len(sessions[0].calls), 2)
        method, url, kwargs = sessions[0].calls[0]
        self.assertEqual(method, "GET")
        self.assertIn("email=user%40outlook.com", url)
        self.assertEqual(kwargs["headers"]["Accept"], "application/json")
        self.assertTrue(kwargs["allow_redirects"])

    def test_session_http_error_keeps_pickup_error_mapping(self):
        class _FakeResponse:
            status_code = 410
            url = "https://remail.aishop6.com/v1/pickup"
            reason = "Gone"
            headers = {}
            content = b""

        class _FakeSession:
            def request(self, method, url, **kwargs):
                return _FakeResponse()

        client = RemailClient(api_key="rk-test", session_factory=_FakeSession)
        with self.assertRaises(RemailApiError) as raised:
            client.pickup("user@outlook.com", "token")
        # A >=400 status surfaces as HTTPError inside the opener, matching
        # the historic urlopen mapping for pickup reads.
        self.assertEqual(raised.exception.code, "remail_pickup_http_error")
        self.assertEqual(raised.exception.status, 410)

    def test_session_network_error_keeps_pickup_network_code(self):
        import requests as _requests

        class _FakeSession:
            def request(self, method, url, **kwargs):
                raise _requests.ConnectionError("boom")

        client = RemailClient(api_key="rk-test", session_factory=_FakeSession)
        with self.assertRaises(RemailApiError) as raised:
            client.pickup("user@outlook.com", "token")
        self.assertEqual(raised.exception.code, "remail_pickup_network")
        self.assertEqual(raised.exception.status, 0)

    def test_custom_opener_path_still_takes_precedence(self):
        requests_seen = []

        def opener(request, timeout):
            requests_seen.append(request)
            return _Response({"items": []})

        client = RemailClient(api_key="rk-test", opener=opener, session_factory=lambda: (_ for _ in ()).throw(AssertionError("session must not be created")))
        client.orders()

        self.assertEqual(len(requests_seen), 1)


if __name__ == "__main__":
    unittest.main()
