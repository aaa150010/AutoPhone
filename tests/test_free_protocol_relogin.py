"""Focused contract tests for the shared pure-protocol re-login core."""

from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch

from mac_overrides.free_protocol_relogin import (
    ProtocolReloginDeactivated,
    is_deactivated_response,
    protocol_relogin_proxy,
    run_protocol_relogin,
)
from mac_overrides.free_register_common import FreeRegisterError


def _fake_chain_modules(transport):
    runner_module = types.ModuleType("codex_chain_runner")
    runner_module.build_oauth_url = lambda **_kwargs: ("https://oauth.example/start", "verifier", "state")
    oauth_module = types.ModuleType("codex_oauth_chain")
    oauth_module.parse_oauth_url = lambda _url: {"client_id": "client", "redirect_uri": "http://localhost"}
    oauth_module.RealNodeSentinelProvider = lambda **_kwargs: object()
    oauth_module.RealCodexTransport = lambda *args, **kwargs: transport
    oauth_module._page_type = lambda response: response.get("page_type", "")
    oauth_module._continue_url = lambda response: response.get("continue_url", "")
    oauth_module._is_success_response = lambda response: response.get("ok", True)
    return {"codex_chain_runner": runner_module, "codex_oauth_chain": oauth_module}


class FakeOtp:
    def __init__(self, calls: list, code: str = "123456"):
        self._calls = calls
        self._code = code

    def mark_sent(self):
        self._calls.append("mark_sent")

    def wait_code(self, _email):
        self._calls.append("wait_code")
        return self._code

    def close(self):
        self._calls.append("otp_close")


class FakeSession:
    def __init__(self, calls: list):
        self._calls = calls

    def close(self):
        self._calls.append("session_close")


class ProtocolReloginTests(unittest.TestCase):

    def _run(self, transport, calls: list, context: dict, *, config: dict | None = None) -> dict:
        transport.session = FakeSession(calls)
        with patch.dict(sys.modules, _fake_chain_modules(transport)):
            return run_protocol_relogin(
                context,
                config or {},
                proxy="http://127.0.0.1:8080",
                otp=FakeOtp(calls),
                log_fn=lambda message, level="info": calls.append(f"log:{message}"),
                stage_fn=lambda code: calls.append(f"stage:{code}"),
            )

    def test_email_otp_login_returns_token_and_closes_resources(self):
        calls: list = []

        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                calls.append("start")
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                calls.append("submit")
                return {"page_type": "email_otp_verification", "continue_url": "https://auth.example/otp"}

            def send_email_otp(self, _url):
                calls.append("send")
                return {"ok": True}

            def verify_email_otp(self, code):
                calls.append(f"verify:{code}")
                return {"page_type": "continue", "continue_url": "https://chatgpt.example/callback"}

            def complete_chatgpt_callback(self, _url):
                calls.append("callback")
                return {"page_type": "done"}

            def chatgpt_access_token(self):
                calls.append("token")
                return "fresh-token"

            def close(self):
                calls.append("transport_close")

        outcome = self._run(
            FakeTransport(), calls,
            {"email": "user@example.test", "password": "", "totp_secret": ""},
        )

        self.assertEqual(outcome["access_token"], "fresh-token")
        self.assertEqual(
            calls[:8],
            ["start", "mark_sent", "submit", "mark_sent", "send", "stage:email_otp",
             "wait_code", "verify:123456"],
        )
        self.assertIn("otp_close", calls)
        self.assertIn("transport_close", calls)
        self.assertIn("session_close", calls)

    def test_password_login_submits_saved_password_on_login_page(self):
        calls: list = []

        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                calls.append("start")
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                calls.append("submit")
                return {"page_type": "password", "location": "https://auth.openai.com/log-in/password"}

            def verify_password(self, password):
                calls.append(f"password:{password}")
                return {"page_type": "continue", "continue_url": "https://chatgpt.example/callback"}

            def complete_chatgpt_callback(self, _url):
                calls.append("callback")
                return {"page_type": "done"}

            def chatgpt_access_token(self):
                calls.append("token")
                return "password-token"

            def close(self):
                calls.append("transport_close")

        outcome = self._run(
            FakeTransport(), calls,
            {"email": "user@example.test", "password": "saved-pass", "totp_secret": ""},
        )

        self.assertEqual(outcome["access_token"], "password-token")
        self.assertIn("password:saved-pass", calls)
        self.assertNotIn("wait_code", calls)

    def test_mfa_login_uses_totp_code_from_saved_secret(self):
        calls: list = []

        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                calls.append("start")
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                calls.append("submit")
                return {"page_type": "mfa_otp"}

            def verify_mfa_otp(self, code):
                calls.append(f"mfa:{code}")
                return {"page_type": "continue", "continue_url": "https://chatgpt.example/callback"}

            def complete_chatgpt_callback(self, _url):
                calls.append("callback")
                return {"page_type": "done"}

            def chatgpt_access_token(self):
                calls.append("token")
                return "mfa-token"

            def close(self):
                calls.append("transport_close")

        outcome = self._run(
            FakeTransport(), calls,
            {"email": "user@example.test", "password": "", "totp_secret": "JBSWY3DPEHPK3PXP"},
        )

        self.assertEqual(outcome["access_token"], "mfa-token")
        mfa_codes = [item for item in calls if item.startswith("mfa:")]
        self.assertEqual(len(mfa_codes), 1)
        self.assertEqual(len(mfa_codes[0].split(":")[1]), 6)
        self.assertIn("stage:mfa", calls)

    def test_mfa_page_without_saved_secret_fails_without_bypass(self):
        calls: list = []

        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                return {"page_type": "mfa_otp"}

            def close(self):
                pass

        with self.assertRaises(FreeRegisterError) as ctx:
            self._run(
                FakeTransport(), calls,
                {"email": "user@example.test", "password": "", "totp_secret": ""},
            )
        self.assertEqual(ctx.exception.error_code, "free_live_mfa_failed")

    def test_deactivated_identifier_raises_dedicated_exception(self):
        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                return {"error_code": "account_deactivated"}

            def close(self):
                pass

        with patch.dict(sys.modules, _fake_chain_modules(FakeTransport())):
            with self.assertRaises(ProtocolReloginDeactivated):
                run_protocol_relogin(
                    {"email": "user@example.test", "password": "", "totp_secret": ""},
                    {},
                    proxy="http://127.0.0.1:8080",
                    otp=FakeOtp([]),
                    log_fn=lambda *_args, **_kwargs: None,
                    stage_fn=lambda _code: None,
                )

    def test_post_login_receives_transport_and_token(self):
        calls: list = []

        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                return {"page_type": "email_otp_verification", "continue_url": "https://auth.example/otp"}

            def send_email_otp(self, _url):
                return {"ok": True}

            def verify_email_otp(self, _code):
                return {"page_type": "continue", "continue_url": "https://chatgpt.example/callback"}

            def complete_chatgpt_callback(self, _url):
                return {"page_type": "done"}

            def chatgpt_access_token(self):
                return "post-token"

            def close(self):
                calls.append("transport_close")

        def post_login(transport, token):
            calls.append(f"post:{token}:{type(transport).__name__}")
            return {"status": "live", "access_token": token}

        transport = FakeTransport()
        transport.session = FakeSession(calls)
        with patch.dict(sys.modules, _fake_chain_modules(transport)):
            outcome = run_protocol_relogin(
                {"email": "user@example.test", "password": "", "totp_secret": ""},
                {},
                proxy="http://127.0.0.1:8080",
                otp=FakeOtp(calls),
                log_fn=lambda *_args, **_kwargs: None,
                stage_fn=lambda _code: None,
                post_login=post_login,
            )

        self.assertEqual(outcome["status"], "live")
        self.assertTrue(any(item.startswith("post:post-token:") for item in calls))
        self.assertIn("transport_close", calls)

    def test_html_login_password_page_uses_saved_password(self):
        calls: list = []

        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                return {"page_type": "login_password"}

            def verify_password(self, password):
                calls.append(f"password:{password}")
                return {"page_type": "continue", "continue_url": "https://chatgpt.example/callback"}

            def complete_chatgpt_callback(self, _url):
                return {"page_type": "done"}

            def chatgpt_access_token(self):
                return "html-password-token"

            def close(self):
                pass

        outcome = self._run(
            FakeTransport(), calls,
            {"email": "user@example.test", "password": "saved-pass", "totp_secret": ""},
        )

        self.assertEqual(outcome["access_token"], "html-password-token")
        self.assertIn("password:saved-pass", calls)
        self.assertNotIn("wait_code", calls)

    def test_html_mfa_challenge_posts_totp_to_challenge_endpoint(self):
        calls: list = []

        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                return {"page_type": "login_password"}

            def verify_password(self, _password):
                return {
                    "_url": "https://auth.openai.com/mfa-challenge/abc123",
                    "error": "",
                }

            def _post_auth_json(self, path, payload, **kwargs):
                calls.append((path, dict(payload), kwargs.get("flow"), kwargs.get("referer")))
                return {"page_type": "continue", "continue_url": "https://chatgpt.example/callback"}

            def complete_chatgpt_callback(self, _url):
                return {"page_type": "done"}

            def chatgpt_access_token(self):
                return "totp-token"

            def close(self):
                pass

        outcome = self._run(
            FakeTransport(), calls,
            {"email": "user@example.test", "password": "saved-pass", "totp_secret": "JBSWY3DPEHPK3PXP"},
        )

        self.assertEqual(outcome["access_token"], "totp-token")
        mfa_calls = [item for item in calls if isinstance(item, tuple)]
        self.assertEqual(len(mfa_calls), 1)
        path, payload, flow, referer = mfa_calls[0]
        self.assertEqual(path, "/api/accounts/mfa/verify")
        self.assertEqual(payload["type"], "totp")
        self.assertEqual(payload["id"], "abc123")
        self.assertEqual(flow, "mfa_verify")
        self.assertIn("mfa-challenge", referer)

    def test_rate_limited_login_step_maps_to_retryable_rate_limit(self):
        class FakeTransport:
            def start_chatgpt_signup_authorize(self, _email):
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                return {"_status": 429, "error": {"message": "Too many requests. Please try again later."}}

            def close(self):
                pass

        with patch.dict(sys.modules, _fake_chain_modules(FakeTransport())):
            with self.assertRaises(FreeRegisterError) as ctx:
                run_protocol_relogin(
                    {"email": "user@example.test", "password": "", "totp_secret": ""},
                    {},
                    proxy="http://127.0.0.1:8080",
                    otp=FakeOtp([]),
                    log_fn=lambda *_args, **_kwargs: None,
                    stage_fn=lambda _code: None,
                )
        self.assertEqual(ctx.exception.error_code, "free_plan_relogin_rate_limited")
        self.assertTrue(ctx.exception.retryable)

    def test_proxy_helper_rejects_unusable_proxy(self):
        with self.assertRaises(FreeRegisterError):
            protocol_relogin_proxy("", {})

    def test_deactivated_classifier_matches_explicit_payloads(self):
        self.assertTrue(is_deactivated_response({"error_code": "account_deactivated"}))
        self.assertFalse(is_deactivated_response({"error_code": "free_proxy_pool_empty"}))


if __name__ == "__main__":
    unittest.main()
