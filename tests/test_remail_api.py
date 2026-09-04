from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlsplit

from mac_overrides.remail_api import RemailClient, remail_order_value


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


if __name__ == "__main__":
    unittest.main()
