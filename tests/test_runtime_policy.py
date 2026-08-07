from __future__ import annotations

from http.client import RemoteDisconnected
import json
import unittest

from mac_overrides.runtime_policy import (
    ACCOUNT_BANNED_MESSAGE,
    AccountBannedError,
    call_with_transient_pre_auth_retry,
    is_account_banned_failure,
    is_explicit_account_banned,
    is_relogin_transient_failure,
    should_retry_expired_sub2_session,
    transient_pre_auth_error_code,
)


class RuntimePolicyTests(unittest.TestCase):
    def test_recognizes_only_explicit_account_terminal_markers(self):
        terminal_values = (
            {"error": {"code": "account_banned"}},
            {"error_code": "ACCOUNT_DEACTIVATED"},
            {"reason": "user_deleted"},
            {"error": {"type": "account_suspended"}},
            {"message": "Your account has been suspended."},
            {"detail": "This account was deleted or deactivated."},
            {"error_message": "账号已被封禁"},
            {"error_message": "账号被封禁"},
            {"error_message": "账号被停用"},
            AccountBannedError("private diagnostic"),
        )
        for value in terminal_values:
            with self.subTest(value=value):
                self.assertTrue(is_explicit_account_banned(value))

    def test_does_not_treat_generic_phone_or_access_errors_as_account_banned(self):
        ordinary_values = (
            {"_status": 403, "error": "forbidden"},
            {"error": {"code": "phone_rejected", "message": "phone rejected"}},
            {"error": {"code": "unsupported_country", "message": "region restriction"}},
            "status=403 phone rejected",
            "This request was suspended while the server restarted",
        )
        for value in ordinary_values:
            with self.subTest(value=value):
                self.assertFalse(is_explicit_account_banned(value))

    def test_account_banned_failure_accepts_public_terminal_message(self):
        self.assertTrue(is_account_banned_failure({}, ACCOUNT_BANNED_MESSAGE))

    def test_retries_expired_sub2_session_after_phone_verification(self):
        result = {
            "error": "sub2_exchange_failed: session not found or expired",
            "codex_chain_events": [{"state": "PHONE_OTP_VERIFIED"}],
        }
        self.assertTrue(should_retry_expired_sub2_session(result))

    def test_retries_expired_sub2_session_after_callback(self):
        result = {
            "phase2_error": "sub2_exchange_failed: sub2_session_expired",
            "codex_chain_events": [{"state": "CALLBACK_RECEIVED"}],
        }
        self.assertTrue(should_retry_expired_sub2_session(result))

    def test_retries_expired_sub2_session_from_structured_reason(self):
        result = {
            "error": "sub2_exchange_failed: OPENAI_OAUTH_SESSION_NOT_FOUND",
            "codex_chain_events": [{"state": "PHONE_OTP_VERIFIED"}],
        }
        self.assertTrue(should_retry_expired_sub2_session(result))

    def test_matches_failure_and_expiry_across_result_fields(self):
        result = {
            "error": "sub2_exchange_failed",
            "local_oauth_exchange_error": "OPENAI_OAUTH_SESSION_NOT_FOUND",
            "codex_chain_events": [{"state": "CALLBACK_RECEIVED"}],
        }
        self.assertTrue(should_retry_expired_sub2_session(result))

    def test_does_not_retry_before_phone_is_verified(self):
        result = {
            "error": "sub2_exchange_failed: session not found or expired",
            "codex_chain_events": [{"state": "PHONE_OTP_SENT"}],
        }
        self.assertFalse(should_retry_expired_sub2_session(result))

    def test_does_not_retry_other_sub2_failures(self):
        result = {
            "error": "sub2_exchange_failed: invalid response",
            "codex_chain_events": [{"state": "PHONE_OTP_VERIFIED"}],
        }
        self.assertFalse(should_retry_expired_sub2_session(result))

    def test_rejects_unstructured_results(self):
        self.assertFalse(should_retry_expired_sub2_session(None))
        self.assertFalse(should_retry_expired_sub2_session("expired"))

    def test_classifies_only_narrow_transient_pre_auth_network_errors(self):
        disconnected = ConnectionError("request failed")
        disconnected.__cause__ = RemoteDisconnected("remote end closed connection without response")
        invalid_json = json.JSONDecodeError("Expecting value", "", 0)

        self.assertEqual(transient_pre_auth_error_code(disconnected), "remote_disconnected")
        self.assertEqual(transient_pre_auth_error_code(invalid_json), "invalid_json_response")
        self.assertEqual(
            transient_pre_auth_error_code("curl: (35) TLS connect error"),
            "tls_connection_failed",
        )
        self.assertEqual(
            transient_pre_auth_error_code("connection timed out after 30001 milliseconds"),
            "connection_timeout",
        )
        self.assertEqual(transient_pre_auth_error_code("HTTP 403 connection closed"), "")
        self.assertEqual(transient_pre_auth_error_code(ValueError("invalid password")), "")

    def test_mapping_client_status_fields_block_transient_retry(self):
        markers = (
            "remote end closed connection without response",
            "curl: (35) TLS connect error",
            "connection timed out after 30001 milliseconds",
        )
        for field in ("_status", "status", "status_code", "http_status"):
            for status in (401, 403):
                for marker in markers:
                    with self.subTest(field=field, status=status, marker=marker):
                        self.assertEqual(
                            transient_pre_auth_error_code({field: status, "error": marker}),
                            "",
                        )

        nested = {
            "response": {"http_status": "403"},
            "error": "remote end closed connection without response",
        }
        self.assertEqual(transient_pre_auth_error_code(nested), "")

    def test_mapping_408_and_425_keep_transient_classification(self):
        self.assertEqual(
            transient_pre_auth_error_code(
                {"_status": 408, "error": "connection timed out after 30001 milliseconds"}
            ),
            "connection_timeout",
        )
        self.assertEqual(
            transient_pre_auth_error_code(
                {"response": {"status_code": "425"}, "error": "connection reset"}
            ),
            "remote_disconnected",
        )

    def test_mapping_server_error_keeps_transient_classification(self):
        self.assertEqual(
            transient_pre_auth_error_code(
                {"_status": 502, "error": "upstream connect error: connection reset"}
            ),
            "remote_disconnected",
        )

    def test_relogin_whole_chain_retry_allows_transient_or_session_reset_failures(self):
        retryable = (
            {"error": "curl: (35) TLS connect error"},
            {"error": "remote end closed connection without response"},
            {"error": "connection timed out after 30001 milliseconds"},
            {"_status": 429, "error": "too many requests"},
            {"error": "mfa_otp_failed: Invalid authorization step."},
            {"code": "mfa_authorization_step_expired"},
        )
        terminal = (
            {"error": "password_verify_failed: invalid password"},
            {"error": "mfa_otp_failed: invalid code"},
            {"error": "oauth_callback_state_mismatch: invalid_state"},
            {"error": "account_deactivated"},
            {"error": "relogin_phone_required"},
            {"_status": 401, "error": "connection reset"},
        )

        for value in retryable:
            with self.subTest(value=value):
                self.assertTrue(is_relogin_transient_failure(value))
        for value in terminal:
            with self.subTest(value=value):
                self.assertFalse(is_relogin_transient_failure(value))

    def test_retry_runner_does_not_retry_mapping_http_403(self):
        calls = []

        def operation():
            calls.append("call")
            return {"_status": 403, "error": "curl: (35) TLS connect error"}

        result = call_with_transient_pre_auth_retry(
            operation,
            attempts=2,
            retry_result=True,
            sleep_fn=lambda _delay: None,
        )

        self.assertEqual(result["_status"], 403)
        self.assertEqual(calls, ["call"])

    def test_transient_call_retries_once_with_injected_delay_and_callback(self):
        calls = []
        retries = []
        delays = []

        def operation():
            calls.append("call")
            if len(calls) == 1:
                raise RemoteDisconnected("remote end closed connection without response")
            return "ok"

        value = call_with_transient_pre_auth_retry(
            operation,
            attempts=2,
            delay_seconds=0.25,
            on_retry=lambda *args: retries.append(args),
            sleep_fn=delays.append,
        )

        self.assertEqual(value, "ok")
        self.assertEqual(len(calls), 2)
        self.assertEqual(retries, [("remote_disconnected", 2, 2, 0.25)])
        self.assertEqual(delays, [0.25])

    def test_transient_error_result_retries_without_raising(self):
        calls = []

        def operation():
            calls.append("call")
            if len(calls) == 1:
                return {"_status": 0, "error": "curl: (35) TLS connect error"}
            return {"_status": 200, "page": {"type": "login"}}

        result = call_with_transient_pre_auth_retry(
            operation,
            attempts=2,
            retry_result=True,
            sleep_fn=lambda _delay: None,
        )

        self.assertEqual(result["_status"], 200)
        self.assertEqual(calls, ["call", "call"])

    def test_retry_code_allowlist_can_fail_fast_on_long_timeouts(self):
        calls = []

        def operation():
            calls.append("call")
            raise TimeoutError("connection timed out after 60000 milliseconds")

        with self.assertRaises(TimeoutError):
            call_with_transient_pre_auth_retry(
                operation,
                attempts=2,
                retry_codes=frozenset({"remote_disconnected", "invalid_json_response"}),
                sleep_fn=lambda _delay: None,
            )
        self.assertEqual(calls, ["call"])

    def test_success_result_text_does_not_trigger_a_retry(self):
        calls = []

        def operation():
            calls.append("call")
            return {"_status": 200, "page": {"notice": "previous connection timeout"}}

        result = call_with_transient_pre_auth_retry(
            operation,
            attempts=2,
            retry_result=True,
            sleep_fn=lambda _delay: None,
        )

        self.assertEqual(result["_status"], 200)
        self.assertEqual(calls, ["call"])

    def test_transient_call_does_not_retry_permanent_or_stopped_failures(self):
        permanent_calls = []

        def permanent():
            permanent_calls.append("call")
            raise RuntimeError("HTTP 401 invalid credentials")

        with self.assertRaisesRegex(RuntimeError, "invalid credentials"):
            call_with_transient_pre_auth_retry(
                permanent,
                attempts=2,
                sleep_fn=lambda _delay: None,
            )
        self.assertEqual(permanent_calls, ["call"])

        stopped_calls = []

        def stopped():
            stopped_calls.append("call")
            raise RemoteDisconnected("remote end closed connection without response")

        with self.assertRaises(RemoteDisconnected):
            call_with_transient_pre_auth_retry(
                stopped,
                attempts=2,
                stop_requested=lambda: True,
                sleep_fn=lambda _delay: None,
            )
        self.assertEqual(stopped_calls, ["call"])


if __name__ == "__main__":
    unittest.main()
