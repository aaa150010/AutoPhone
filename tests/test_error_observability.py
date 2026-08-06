from __future__ import annotations

import unittest

from mac_overrides.error_observability import (
    ACCOUNT_BANNED_MESSAGE,
    classify_failure,
    format_failure_log,
    format_node_retry_log,
    is_node_retry_log,
    public_failure,
    sanitize_failure_detail,
)


class ErrorObservabilityTests(unittest.TestCase):
    def test_sanitizer_does_not_expand_existing_mask_placeholders(self):
        self.assertEqual(
            sanitize_failure_detail(
                "masked=*** existing=******** secret=real-secret",
                secrets=("***", "********", "real-secret"),
            ),
            "masked=*** existing=******** secret=********",
        )

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
            ("email_otp_send_failed: HTTP 429", "email_code_waiting"),
            ("email_otp_timeout", "email_code_waiting"),
            ("email_otp_failed: invalid authorization step", "email_code_verifying"),
            ("getNumber failed: no_numbers", "phone_acquiring"),
            ("phone_send_rejected: unsupported_country_region_territory", "phone_submitting"),
            ("sms_timeout while wait_code", "sms_waiting"),
            ("phone_otp_empty", "sms_waiting"),
            ("verify_phone_otp failed", "sms_verifying"),
            ("create_account_profile_failed", "finalizing_profile"),
            ("sub2_upload_failed: remote_verified=false", "finalizing_upload"),
        )

        for error, expected in cases:
            with self.subTest(error=error):
                failure = classify_failure(error=error)
                self.assertEqual(failure["node_code"], expected)
                self.assertTrue(failure["public_message"].startswith(failure["node_label"]))

        send_failure = classify_failure(error="email_otp_send_failed: HTTP 429")
        self.assertEqual(send_failure["error_code"], "email_otp_send_failed")
        self.assertIn("发送接口失败", send_failure["public_message"])

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

    def test_phone_context_failure_is_not_reported_as_openai_number_rejection(self):
        failure = classify_failure(
            error="auth_context_page_mismatch: 当前登录页面不是手机号验证页面",
            progress={"code": "phone_acquiring"},
        )

        self.assertEqual(failure["node_code"], "phone_submitting")
        self.assertEqual(failure["error_code"], "auth_context_page_mismatch")
        self.assertIn("页面上下文无效", failure["public_message"])
        self.assertNotIn("OpenAI 拒绝当前号码", failure["public_message"])

    def test_session_invalid_keeps_the_stage_where_it_surfaced(self):
        for stage, expected_node, risk_signal in (
            ("phone_submitting", "phone_submitting", True),
            ("sms_verifying", "sms_verifying", True),
            ("oauth_authorize_node", "oauth_authorize_node", False),
        ):
            with self.subTest(stage=stage):
                failure = classify_failure(
                    error="oauth_session_invalid: sign-in session is no longer valid",
                    progress={"code": stage},
                )

                self.assertEqual(failure["node_code"], expected_node)
                self.assertEqual(failure["error_code"], "oauth_session_invalid")
                self.assertIn("OpenAI 登录会话已失效", failure["public_message"])
                self.assertEqual("疑似手机号阶段风控" in failure["public_message"], risk_signal)
                self.assertTrue(failure["retryable"])

        phone_failure = classify_failure(
            error="oauth_session_invalid: sign-in session is no longer valid",
            progress={"code": "phone_submitting"},
        )
        self.assertIn("提交接码号码失败", phone_failure["public_message"])

    def test_relogin_phone_requirement_is_stable_and_not_retryable(self):
        failure = classify_failure(
            error=(
                "relogin_phone_required: 重登进入手机号验证页面，"
                "已停止且未调用接码平台"
            ),
            progress={"code": "phone_acquiring"},
        )

        self.assertEqual(failure["node_code"], "phone_acquiring")
        self.assertEqual(failure["error_code"], "relogin_phone_required")
        self.assertFalse(failure["retryable"])
        self.assertIn("重登进入手机号验证页面", failure["public_message"])
        self.assertIn("未调用接码平台", failure["public_message"])

    def test_forced_whatsapp_is_attributed_to_phone_submission(self):
        failure = classify_failure(
            error="phone_channel_mismatch: requested=sms actual=whatsapp",
            progress={"code": "phone_submitting"},
        )

        self.assertEqual(failure["node_code"], "phone_submitting")
        self.assertEqual(failure["error_code"], "phone_channel_mismatch")
        self.assertIn("非短信渠道", failure["public_message"])

    def test_sms_route_and_key_pool_exhaustion_remain_distinguishable(self):
        routes = classify_failure(error="sms_smart_no_candidate")
        platforms = classify_failure(
            error="sms_provider_pool_unavailable: herosms: NO_NUMBERS"
        )
        keys = classify_failure(
            error="sms_key_pool_temporarily_unavailable: SMS Key 暂时不可用"
        )

        self.assertEqual(routes["node_code"], "phone_acquiring")
        self.assertEqual(routes["error_code"], "sms_route_pool_exhausted")
        self.assertIn("候选线路", routes["public_message"])
        self.assertEqual(platforms["node_code"], "phone_acquiring")
        self.assertEqual(platforms["error_code"], "sms_provider_pool_unavailable")
        self.assertIn("接码平台", platforms["public_message"])
        self.assertIn("herosms", platforms["technical_summary"])
        self.assertEqual(keys["node_code"], "phone_acquiring")
        self.assertEqual(keys["error_code"], "sms_key_pool_temporarily_unavailable")
        self.assertIn("SMS Key", keys["public_message"])

    def test_sub2_existing_account_update_failure_keeps_upload_node(self):
        failure = classify_failure(
            error="sub2_update_existing_failed: SUB2 原账号更新失败（HTTP 500）"
        )

        self.assertEqual(failure["node_code"], "finalizing_upload")
        self.assertEqual(failure["error_code"], "sub2_update_existing_failed")
        self.assertEqual(failure["http_status"], 500)
        self.assertIn("原账号更新", failure["public_message"])

    def test_relogin_failure_retryability_matches_whole_chain_policy(self):
        terminal = (
            "mfa_otp_failed: invalid code",
            "mfa_otp_failed: invalid code after connection reset",
            "oauth_callback_state_mismatch: invalid_state",
            "sub2_update_existing_failed: HTTP 500",
            "sub2_update_identity_verification_failed",
        )
        transient = (
            "curl: (35) TLS connect error",
            "remote end closed connection without response",
            "connection timed out after 30001 milliseconds",
            "HTTP 429 too many requests",
        )

        for error in terminal:
            with self.subTest(error=error):
                failure = classify_failure(
                    {"run_mode": "relogin", "error": error},
                    error,
                )
                self.assertFalse(failure["retryable"])
        for error in transient:
            with self.subTest(error=error):
                failure = classify_failure(
                    {"run_mode": "relogin", "error": error},
                    error,
                )
                self.assertTrue(failure["retryable"])

    def test_sub2_update_failures_keep_their_exact_stable_codes(self):
        cases = (
            "relogin_sub2_binding_missing",
            "sub2_update_binding_missing",
            "sub2_update_config_missing",
            "sub2_update_token_incomplete",
            "sub2_update_prepare_failed",
            "sub2_update_target_missing",
            "sub2_update_binding_mismatch",
            "sub2_update_existing_failed",
            "sub2_update_verification_failed",
            "sub2_update_group_verification_failed",
            "sub2_update_identity_verification_failed",
        )

        for code in cases:
            with self.subTest(code=code):
                failure = classify_failure(error=f"{code}: provider detail")
                self.assertEqual(failure["node_code"], "finalizing_upload")
                self.assertEqual(failure["error_code"], code)

    def test_account_banned_message_remains_exact(self):
        failure = classify_failure(
            {"error": {"code": "account_banned", "message": "account has been banned"}},
            status="account_banned",
        )

        self.assertEqual(failure["node_code"], "account_banned")
        self.assertEqual(failure["public_message"], ACCOUNT_BANNED_MESSAGE)
        self.assertFalse(failure["retryable"])

    def test_curl_56_is_a_retryable_remote_disconnect(self):
        failure = classify_failure(
            error="Failed to perform, curl: (56) Connection closed abruptly"
        )

        self.assertEqual(failure["node_code"], "oauth_authorize_node")
        self.assertEqual(failure["error_code"], "remote_disconnected")
        self.assertTrue(failure["retryable"])
        self.assertIn("远端或代理", failure["public_message"])

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

    def test_node_retry_is_not_formatted_as_terminal_failure(self):
        detail = "[SentinelRunner] token 生成失败，重试 flow=chat-requirements"

        self.assertTrue(is_node_retry_log(detail))
        message = format_node_retry_log("T001-abcd", detail)
        self.assertIn("正在自动重试", message)
        self.assertIn("Sentinel token 生成未成功", message)
        self.assertNotIn("失败：Node/Sentinel 授权桥接初始化失败", message)

    def test_node_terminal_causes_remain_specific_and_redacted(self):
        cases = (
            ("node_sentinel_failed: node bridge timeout", "node_sentinel_timeout", "超时"),
            ("node_sentinel_failed: Unable to connect to proxy", "node_proxy_failed", "显式代理"),
            ("node_sentinel_failed: TLS connect error", "node_tls_failed", "TLS"),
            ("node_sentinel_failed: node executable not found", "node_runtime_missing", "Node.js"),
            ("node_sentinel_failed: token generation failed", "node_sentinel_token_failed", "token"),
        )
        for detail, code, phrase in cases:
            with self.subTest(detail=detail):
                failure = classify_failure(error=detail)
                self.assertEqual(failure["error_code"], code)
                self.assertIn(phrase, failure["public_message"])
                self.assertNotIn("access_token", failure["public_message"])

    def test_node_failure_during_mfa_is_attributed_to_email_verification(self):
        failure = classify_failure(
            {
                "technical_error": (
                    "mfa_otp_failed: node_sentinel_failed:mfa_otp_verify: "
                    "node_bridge_timeout"
                ),
                "codex_chain_events": [
                    {"state": "SENTINEL_READY"},
                    {"state": "PASSWORD_VERIFIED"},
                    {"state": "MFA_OTP_REQUIRED"},
                    {
                        "state": "FAILED",
                        "detail": (
                            "mfa_otp_failed: node_sentinel_failed:mfa_otp_verify: "
                            "node_bridge_timeout"
                        ),
                    },
                ],
            }
        )

        self.assertEqual(failure["node_code"], "email_code_verifying")
        self.assertEqual(failure["error_code"], "node_sentinel_timeout")
        self.assertIn("Node/Sentinel 请求超时", failure["public_message"])
        self.assertNotIn("初始化 Node/Sentinel失败", failure["public_message"])

    def test_sms_provider_network_failures_never_become_oauth_failures(self):
        for error, expected_code in (
            ("sms_provider_ready_failed: ProxyError", "sms_provider_ready_failed"),
            ("sms_provider_poll_failed: TLS connection reset", "sms_provider_poll_failed"),
            ("sms_activation_replaced: stale poll", "sms_activation_replaced"),
            ("sms_timeout: no code", "sms_timeout"),
        ):
            with self.subTest(error=error):
                failure = classify_failure(error=error)
                self.assertEqual(failure["node_code"], "sms_waiting")
                self.assertEqual(failure["error_code"], expected_code)

    def test_empty_phone_otp_is_distinct_from_two_round_provider_timeout(self):
        failure = classify_failure(error="phone_otp_empty")

        self.assertEqual(failure["node_code"], "sms_waiting")
        self.assertEqual(failure["error_code"], "sms_no_code")
        self.assertIn("本次等待未返回", failure["public_message"])
        self.assertNotIn("两轮", failure["public_message"])


if __name__ == "__main__":
    unittest.main()
