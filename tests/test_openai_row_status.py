from __future__ import annotations

import unittest

from mac_overrides.openai_row_status import (
    resolve_openai_status,
    resolve_quota_status,
    row_status_key,
)


class OpenAIRowStatusTests(unittest.TestCase):
    def test_account_binding_never_falls_back_to_stale_row_test_status(self):
        row_key = row_status_key("stable-row")
        values = {
            "account-id": {"kind": "untested", "label": "凭据已更新，待复测"},
            row_key: {
                "kind": "unauthorized",
                "status_code": 401,
                "label": "401 Token失效",
            },
        }

        status = resolve_openai_status(
            values.get,
            openai_account_id="account-id",
            row_id="stable-row",
            allow_row_fallback=True,
        )

        self.assertEqual(status["kind"], "untested")
        self.assertEqual(status["label"], "凭据已更新，待复测")

    def test_account_binding_never_falls_back_to_stale_row_quota(self):
        row_key = row_status_key("stable-row")
        values = {
            row_key: {
                "status": "error",
                "code": "openai_quota_account_id_missing",
                "error": "旧错误",
            },
        }

        status = resolve_quota_status(
            values.get,
            account_id="new-account-id",
            row_id="stable-row",
            allow_row_fallback=True,
        )

        self.assertEqual(status, {})

    def test_row_fallback_is_used_without_an_account_binding(self):
        row_key = row_status_key("stable-row")
        values = {
            row_key: {
                "status": "error",
                "code": "openai_quota_account_id_missing",
                "error": "缺少 account id",
            },
        }

        status = resolve_quota_status(
            values.get,
            row_id="stable-row",
            allow_row_fallback=True,
        )

        self.assertEqual(status["status"], "error")
        self.assertEqual(status["code"], "openai_quota_account_id_missing")


if __name__ == "__main__":
    unittest.main()
