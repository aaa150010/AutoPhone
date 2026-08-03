from __future__ import annotations

import unittest

from mac_overrides.error_observability import (
    ACCOUNT_BANNED_MESSAGE,
    classify_failure,
    format_failure_log,
    public_failure,
    sanitize_failure_detail,
)


class ErrorObservabilityTests(unittest.TestCase):
    def test_callback_and_token_failures_have_distinct_nodes(self):
        callback = classify_failure(error="oauth_callback_missing_code: callback missing code")
        token = classify_failure(
            {"phase2_error": "sub2_exchange_failed: OPENAI_OAUTH_SESSION_NOT_FOUND"},
            "授权或上传未完成",
        )

        self.assertEqual(callback["node_code"], "finalizing_callback")
        self.assertEqual(callback["error_code"], "oauth_callback_failed")
        self.assertIn("OAuth 回调", callback["public_message"])
        self.assertEqual(token["node_code"], "finalizing_token")
        self.assertEqual(token["error_code"], "sub2_exchange_failed")
        self.assertIn("SUB2 OAuth 会话", token["public_message"])
        self.assertNotIn("授权或上传未完成", token["public_message"])

    def test_known_pipeline_markers_are_attributed_to_actionable_nodes(self):
        cases = (
            ("SUB2 generate-auth-url failed: HTTP 502", "oauth_session"),
            ("node_sentinel_failed: node bridge timeout", "oauth_create_node"),
            ("mailbox_imap_error: AUTHENTICATE failed", "email_login"),
            ("password_verify_failed: incorrect password", "email_password"),
            ("email_otp_timeout", "email_code_waiting"),
            ("email_otp_failed: invalid authorization step", "email_code_verifying"),
            ("getNumber failed: no_numbers", "phone_acquiring"),
            ("phone_send_rejected: unsupported_country_region_territory", "phone_submitting"),
            ("sms_timeout while wait_code", "sms_waiting"),
            ("verify_phone_otp failed", "sms_verifying"),
            ("create_account_profile_failed", "finalizing_profile"),
            ("sub2_upload_failed: remote_verified=false", "finalizing_upload"),
        )

        for error, expected in cases:
            with self.subTest(error=error):
                failure = classify_failure(error=error)
                self.assertEqual(failure["node_code"], expected)
                self.assertTrue(failure["public_message"].startswith(failure["node_label"]))

    def test_last_success_event_points_at_the_operation_that_can_fail_next(self):
        after_chat_requirements = classify_failure(
            {
                "technical_error": "curl: (35) TLS connect error",
                "codex_chain_events": [{"state": "CHAT_REQUIREMENTS_READY"}],
            },
        )
        after_callback = classify_failure(
            {"codex_chain_events": [{"state": "CALLBACK_RECEIVED"}]},
            "授权或上传未完成",
        )
        after_token = classify_failure(
            {"codex_chain_events": [{"state": "TOKEN_EXCHANGED"}]},
            "授权或上传未完成",
        )

        self.assertEqual(after_chat_requirements["node_code"], "oauth_authorize_node")
        self.assertEqual(after_callback["node_code"], "finalizing_token")
        self.assertEqual(after_token["node_code"], "finalizing_upload")
        self.assertIn("服务端未返回错误详情", after_callback["public_message"])

    def test_current_progress_is_used_for_unexpected_exceptions(self):
        failure = classify_failure(
            error=RuntimeError("connection reset without provider payload"),
            progress={"code": "email_login", "label": "登录邮箱"},
        )

        self.assertEqual(failure["node_code"], "email_login")
        self.assertEqual(failure["error_code"], "email_login_failed")
        self.assertIn("connection reset", failure["technical_summary"])

    def test_sms_route_and_key_pool_exhaustion_remain_distinguishable(self):
        routes = classify_failure(error="sms_smart_no_candidate")
        keys = classify_failure(
            error="sms_key_pool_temporarily_unavailable: SMS Key 暂时不可用"
        )

        self.assertEqual(routes["node_code"], "phone_acquiring")
        self.assertEqual(routes["error_code"], "sms_route_pool_exhausted")
        self.assertIn("候选线路", routes["public_message"])
        self.assertEqual(keys["node_code"], "phone_acquiring")
        self.assertEqual(keys["error_code"], "sms_key_pool_temporarily_unavailable")
        self.assertIn("SMS Key", keys["public_message"])

    def test_account_banned_message_remains_exact(self):
        failure = classify_failure(
            {"error": {"code": "account_banned", "message": "account has been banned"}},
            status="account_banned",
        )

        self.assertEqual(failure["node_code"], "account_banned")
        self.assertEqual(failure["public_message"], ACCOUNT_BANNED_MESSAGE)
        self.assertFalse(failure["retryable"])

    def test_sanitizer_removes_all_credential_classes_but_keeps_safe_status(self):
        secrets = ("mail-pass", "TOTPSECRET", "client-visible-secret")
        raw = (
            "HTTP 401 error_code=invalid_grant "
            "url=https://auth.example.test/callback?code=oauth-code&state=oauth-state "
            "access_token=access-secret refresh_token=refresh-secret id_token=eyJabcdefghijk.abcdefghijk.abcdefghijk "
            "password=mail-pass client_id=client-visible-secret totp=TOTPSECRET "
            "cookie=session-cookie user@example.test +8613812345678 sms_code=123456"
        )

        safe = sanitize_failure_detail(raw, secrets=secrets)

        for secret in (
            "oauth-code",
            "oauth-state",
            "access-secret",
            "refresh-secret",
            "eyJabcdefghijk",
            "mail-pass",
            "client-visible-secret",
            "TOTPSECRET",
            "session-cookie",
            "user@example.test",
            "+8613812345678",
            "123456",
        ):
            self.assertNotIn(secret, safe)
        self.assertIn("HTTP 401", safe)
        self.assertIn("error_code=invalid_grant", safe)
        self.assertIn("https://auth.example.test/callback", safe)
        self.assertNotIn("?", safe)

        json_body = sanitize_failure_detail(
            '{"error":{"code":"invalid_grant","message":"session expired"},'
            '"access_token":"body-token","unrelated_private_field":"private-value"}'
        )
        self.assertIn("invalid_grant", json_body)
        self.assertIn("session expired", json_body)
        self.assertNotIn("body-token", json_body)
        self.assertNotIn("private-value", json_body)

    def test_public_failure_drops_unknown_fields_and_formats_log(self):
        value = {
            "node_code": "finalizing_token",
            "node_label": "untrusted",
            "error_code": "invalid_grant",
            "public_message": "交换 OAuth Token失败：服务端拒绝请求",
            "technical_summary": "HTTP 400 error_code=invalid_grant",
            "retryable": True,
            "http_status": 400,
            "access_token": "must-not-leak",
        }

        public = public_failure(value)
        serialized = repr(public)

        self.assertIsNotNone(public)
        self.assertEqual(public["node_label"], "交换 OAuth Token")
        self.assertNotIn("access_token", public)
        self.assertNotIn("must-not-leak", serialized)
        self.assertEqual(
            format_failure_log("T001-abcd", public),
            "T001-abcd [交换 OAuth Token/finalizing_token] 交换 OAuth Token失败：服务端拒绝请求",
        )


if __name__ == "__main__":
    unittest.main()
