"""Focused tests for tail-failure salvage in completed_result_state."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from mac_overrides.free_failure_runtime import completed_result_state
except ImportError:  # pragma: no cover - direct mac_overrides execution
    from free_failure_runtime import completed_result_state  # type: ignore[no-redef]


def _token_result():
    return {
        "access_token": "tok-1",
        "has_access_token": True,
        "plan_type": "free",
        "twofa_status": "enabled",
        "password_status": "enabled",
    }


def _plan_failure():
    return {
        "node_code": "free_plan_check",
        "node_label": "查询 Free 套餐资格",
        "error_code": "free_plan_accounts_http_failed",
        "public_message": "套餐接口返回 HTTP 503",
        "technical_summary": "套餐接口返回 HTTP 503",
        "retryable": True,
        "http_status": 503,
    }


class SalvageTailFailureTest(unittest.TestCase):
    def test_session_refresh_failure_with_token_is_salvaged_to_success(self):
        status, payload, failure = completed_result_state(
            _token_result(),
            post_registration_failure={
                "node_code": "free_codex_refresh",
                "node_label": "刷新 Codex 会话",
                "error_code": "free_codex_refresh_failed",
                "public_message": "Codex 会话刷新失败",
                "retryable": True,
            },
        )
        self.assertEqual(status, "success")
        self.assertIsNone(failure)
        self.assertNotIn("failure", payload)
        salvage = payload.get("salvage_failure")
        self.assertIsInstance(salvage, dict)
        self.assertEqual(salvage["node_code"], "free_codex_refresh")
        self.assertEqual(payload["access_token"], "tok-1")

    def test_plan_failure_keeps_partial_success_semantics(self):
        # Plan failures have a dedicated retry path (plan re-check / live
        # check) and their failure identity must stay visible across task,
        # mailbox and restart stores.  Salvage must not swallow them.
        status, payload, failure = completed_result_state(
            _token_result(), post_registration_failure=_plan_failure(),
        )
        self.assertEqual(status, "partial_success")
        self.assertIsNotNone(failure)
        self.assertEqual(failure["node_code"], "free_plan_check")
        self.assertNotIn("salvage_failure", payload)

    def test_missing_token_keeps_partial_success(self):
        result = _token_result()
        result["access_token"] = ""
        result["has_access_token"] = False
        status, payload, failure = completed_result_state(
            result, post_registration_failure=_plan_failure(),
        )
        self.assertEqual(status, "partial_success")
        self.assertIsNotNone(failure)
        self.assertNotIn("salvage_failure", payload)

    def test_non_tail_failure_is_never_salvaged(self):
        status, payload, failure = completed_result_state(
            _token_result(),
            post_registration_failure={
                "node_code": "free_oauth_session",
                "node_label": "Free OAuth 会话",
                "error_code": "oauth_bootstrap_html",
                "public_message": "OAuth 授权返回无法识别的 HTML",
                "retryable": True,
            },
        )
        self.assertEqual(status, "partial_success")
        self.assertIsNotNone(failure)
        self.assertNotIn("salvage_failure", payload)

    def test_tail_node_by_error_code_salvages(self):
        status, payload, failure = completed_result_state(
            _token_result(),
            post_registration_failure={
                "node_code": "free_tail_check",
                "error_code": "free_session_refresh",
                "public_message": "Session 刷新失败",
                "retryable": True,
            },
        )
        self.assertEqual(status, "success")
        self.assertEqual(payload["salvage_failure"]["error_code"], "free_session_refresh")

    def test_twofa_pending_keeps_priority_over_salvage(self):
        result = _token_result()
        result["twofa_status"] = "pending"
        result["twofa_error"] = "激活失败"
        status, payload, failure = completed_result_state(
            result, post_registration_failure=_plan_failure(),
        )
        self.assertEqual(status, "twofa_pending")
        self.assertNotIn("salvage_failure", payload)

    def test_clean_success_path_unchanged(self):
        status, payload, failure = completed_result_state(_token_result())
        self.assertEqual(status, "success")
        self.assertIsNone(failure)
        self.assertNotIn("salvage_failure", payload)


if __name__ == "__main__":
    unittest.main()
