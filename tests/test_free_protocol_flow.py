from __future__ import annotations

import sys
from types import ModuleType
import unittest

from mac_overrides.free_protocol_flow import _is_security_page, run_free_protocol_flow
from mac_overrides.free_protocol_runtime import resolve_auth_impersonates
from mac_overrides.free_register_common import FreeRegisterError


def _install_chain_helpers():
    module = ModuleType("codex_oauth_chain")
    module._is_success_response = lambda value: isinstance(value, dict) and 200 <= int(value.get("_status") or 0) < 300
    module._page_type = lambda value: str((value.get("page") or {}).get("type") or "") if isinstance(value, dict) else ""
    module._continue_url = lambda value: str(value.get("continue_url") or "") if isinstance(value, dict) else ""
    module._error_text = lambda value: str(value.get("error") or "") if isinstance(value, dict) else str(value or "")
    module._is_session_invalid_error = lambda value: "sign-in session is no longer valid" in str(value or "").lower()
    return module


class _Otp:
    def __init__(self, code="123456"):
        self.code = code
        self.prepared = []
        self.sent = []

    def prepare(self, stage, **_kwargs):
        self.prepared.append(stage)

    def mark_sent(self, stage):
        self.sent.append(stage)

    def wait_code(self, _email, stage_code=None, **_kwargs):
        return self.code


class _ForceOtp(_Otp):
    def prepare(self, stage, *, force_snapshot=False):
        self.prepared.append((stage, bool(force_snapshot)))


class _StageAwareOtp(_ForceOtp):
    def __init__(self, code="123456"):
        super().__init__(code)
        self.service = type("Service", (), {"current_stage": ""})()

    def prepare(self, stage, *, force_snapshot=False):
        self.prepared.append((stage, bool(force_snapshot)))
        self.service.current_stage = stage


class _Transport:
    def __init__(self, *, start=None, email=None, callback=None, exchange=None):
        self.start_response = start or {"_status": 200, "page": {"type": "login"}}
        self.email_response = email or {"_status": 200, "page": {"type": "email_otp_verification"}, "continue_url": "/verify"}
        self.callback_response = callback
        self.exchange_response = exchange
        self.sentinel_provider = type("Sentinel", (), {"reset": lambda self, *_args: None})()
        self.calls = []
        self.callback_args = None
        self.exchange_args = None

    def initiate_oauth(self, _url):
        self.calls.append("initiate_oauth")
        return self.start_response

    def submit_email_identifier(self, _email):
        self.calls.append("submit_email_identifier")
        return self.email_response

    def verify_email_otp(self, _code):
        self.calls.append("verify_email_otp")
        return {"_status": 200, "page": {"type": "profile"}, "continue_url": "/about-you"}

    def create_account_profile(self, _name, _birthdate):
        self.calls.append("create_account_profile")
        return {"_status": 200, "page": {"type": "consent"}, "continue_url": "/callback"}

    def follow_continue_until_code(self, continue_url, oauth_params):
        self.calls.append("follow_continue_until_code")
        self.callback_args = (continue_url, dict(oauth_params))
        return self.callback_response or (
            "http://localhost:1455/auth/callback?code=authorization-code&state="
            + str(oauth_params.get("state") or "")
        )

    def exchange_code(self, code, code_verifier, client_id, redirect_uri, account_email):
        self.calls.append("exchange_code")
        self.exchange_args = (code, code_verifier, client_id, redirect_uri, account_email)
        if self.exchange_response is not None:
            return self.exchange_response
        return {
            "access_token": "access-token-private",
            "refresh_token": "refresh-token-private",
            "id_token": "id-token-private",
            "email": account_email,
        }


def _oauth_context(*, state="state-private", code_verifier="verifier-private"):
    return {
        "url": "https://auth.example.test/authorize?client_id=client-private&state=" + state,
        "state": state,
        "code_verifier": code_verifier,
        "client_id": "client-private",
        "redirect_uri": "http://localhost:1455/auth/callback",
        "params": {
            "client_id": "client-private",
            "state": state,
            "redirect_uri": "http://localhost:1455/auth/callback",
        },
    }


def _run(transport, *, otp=None, transport_factory=None, oauth_context_factory=None, **kwargs):
    return run_free_protocol_flow(
        transport,
        transport_factory=transport_factory,
        oauth_context_factory=oauth_context_factory,
        oauth_context=_oauth_context(),
        email="user@example.test",
        otp_provider=otp or _Otp(),
        task_id="test-task",
        stage=kwargs.pop("stage", lambda *_args: None),
        **kwargs,
    )


class FreeProtocolFlowTests(unittest.TestCase):
    def setUp(self):
        self.original = sys.modules.get("codex_oauth_chain")
        sys.modules["codex_oauth_chain"] = _install_chain_helpers()

    def tearDown(self):
        if self.original is None:
            sys.modules.pop("codex_oauth_chain", None)
        else:
            sys.modules["codex_oauth_chain"] = self.original

    def test_mfa_challenge_is_not_misclassified_as_security_page(self):
        self.assertFalse(_is_security_page({"page": {"type": "mfa_challenge"}}))
        self.assertTrue(_is_security_page({"page": {"type": "security_challenge"}}))
        self.assertTrue(_is_security_page({"url": "https://auth.openai.com/cdn-cgi/challenge-platform/start"}))

    def test_oauth_start_uses_reference_fingerprint_order_without_truncation(self):
        self.assertEqual(
            resolve_auth_impersonates({}),
            ["chrome", "chrome136", "chrome133a", "safari15_3", "safari17_0"],
        )
        self.assertEqual(
            resolve_auth_impersonates({"auth_impersonates": ["chrome136", "safari17_0"]}),
            ["chrome136", "safari17_0"],
        )

    def test_protocol_uses_authorize_continue_and_reaches_token_only_after_callback(self):
        transport = _Transport()
        otp = _Otp()
        stages = []
        result, _ = _run(transport, otp=otp, stage=lambda _task, code: stages.append(code))
        self.assertTrue(result["registration_completed"])
        self.assertEqual(transport.calls, [
            "initiate_oauth", "submit_email_identifier", "verify_email_otp",
            "create_account_profile", "follow_continue_until_code", "exchange_code",
        ])
        self.assertIn("free_email_otp_wait", stages)
        self.assertNotIn("register_user", transport.calls)
        self.assertEqual(transport.callback_args[1]["state"], "state-private")
        self.assertEqual(transport.exchange_args, (
            "authorization-code",
            "verifier-private",
            "client-private",
            "http://localhost:1455/auth/callback",
            "user@example.test",
        ))

    def test_callback_without_code_stops_before_token_exchange(self):
        transport = _Transport(callback="http://localhost:1455/auth/callback?state=state-private")
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(raised.exception.error_code, "oauth_callback_missing_code")
        self.assertEqual(transport.calls[-1], "follow_continue_until_code")
        self.assertNotIn("exchange_code", transport.calls)

    def test_callback_state_mismatch_stops_before_token_exchange(self):
        transport = _Transport(
            callback="http://localhost:1455/auth/callback?code=authorization-code&state=other-state",
        )
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(raised.exception.error_code, "oauth_callback_state_mismatch")
        self.assertNotIn("exchange_code", transport.calls)

    def test_token_exchange_failure_is_attributed_to_token_stage(self):
        transport = _Transport(exchange={"_status": 400, "error": "invalid_grant"})
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(raised.exception.node_code, "free_access_token")
        self.assertEqual(raised.exception.error_code, "token_exchange_failed")
        self.assertIn("exchange_code", transport.calls)
        self.assertEqual(raised.exception.provider_status, 400)

    def test_access_token_only_exchange_remains_a_valid_completed_result(self):
        transport = _Transport(exchange={"_status": 200, "access_token": "access-token-private"})
        result, _ = _run(transport)
        self.assertTrue(result["registration_completed"])
        self.assertEqual(result["access_token"], "access-token-private")

    def test_invalid_session_rebuilds_once_without_changing_email_or_proxy(self):
        first = _Transport(email={"_status": 400, "error": "Your sign-in session is no longer valid."})
        second = _Transport()
        created = []

        def factory():
            created.append(second)
            return second

        result, active = _run(first, transport_factory=factory)
        self.assertIs(active, second)
        self.assertEqual(result["oauth_session_rebuilds"], 1)
        self.assertEqual(len(created), 1)
        self.assertEqual(first.calls, ["initiate_oauth", "submit_email_identifier"])

    def test_html_bootstrap_is_rebuilt_once_but_challenge_stops(self):
        html = _Transport(start={"_status": 200, "_content_type": "text/html", "_body_summary": "login"})
        good = _Transport()
        result, _ = _run(html, transport_factory=lambda: good)
        self.assertEqual(result["oauth_session_rebuilds"], 1)

        challenge = _Transport(start={"_status": 200, "_content_type": "text/html", "_body_summary": "Cloudflare challenge"})
        with self.assertRaises(FreeRegisterError) as raised:
            _run(challenge, transport_factory=lambda: self.fail("challenge must not rebuild"))
        self.assertEqual(raised.exception.error_code, "free_oauth_security_challenge")

    def test_html_body_challenge_is_classified_without_logging_body(self):
        challenge = _Transport(start={
            "_status": 200,
            "_content_type": "text/html",
            "_body": "<html><title>Just a moment</title>Cloudflare checking your browser</html>",
        })
        with self.assertRaises(FreeRegisterError) as raised:
            _run(challenge, transport_factory=lambda: self.fail("challenge must not rebuild"))
        self.assertEqual(raised.exception.error_code, "free_oauth_security_challenge")
        self.assertNotIn("Cloudflare", str(raised.exception))

    def test_rebuild_refreshes_mailbox_baseline(self):
        first = _Transport(email={"_status": 400, "error": "Your sign-in session is no longer valid."})
        second = _Transport()
        otp = _ForceOtp()
        _run(first, transport_factory=lambda: second, otp=otp)
        self.assertIn(("free_email_otp_wait", False), otp.prepared)
        self.assertIn(("free_email_otp_wait", True), otp.prepared)

    def test_generic_password_page_is_not_guessed_as_login(self):
        transport = _Transport(
            email={"_status": 200, "page": {"type": "password"}, "continue_url": "/password"},
        )
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(raised.exception.error_code, "free_password_context_unknown")
        self.assertNotIn("verify_password", transport.calls)

    def test_otp_phase_change_forces_a_new_baseline(self):
        otp = _StageAwareOtp()
        transport = _Transport(
            email={"_status": 200, "page": {"type": "mfa_challenge"}, "continue_url": "/mfa"},
        )
        with self.assertRaises(FreeRegisterError):
            _run(transport, otp=otp)
        self.assertIn(("free_email_otp_wait", False), otp.prepared)
        self.assertIn(("free_existing_login_otp", True), otp.prepared)

    def test_password_to_otp_to_profile_is_processed_as_a_loop(self):
        class PasswordThenOtp(_Transport):
            def __init__(self):
                super().__init__(email={"_status": 200, "page": {"type": "login_password"}, "continue_url": "/log-in/password"})
                self._otp_count = 0

            def verify_password(self, _password):
                self.calls.append("verify_password")
                return {"_status": 200, "page": {"type": "mfa_otp"}, "continue_url": "/mfa"}

            def send_mfa_otp(self, _url=""):
                self.calls.append("send_mfa_otp")
                return {"_status": 200, "page": {"type": "mfa_otp"}, "continue_url": "/mfa"}

            def verify_mfa_otp(self, _code):
                self.calls.append("verify_mfa_otp")
                self._otp_count += 1
                return {"_status": 200, "page": {"type": "profile"}, "continue_url": "/about-you"}

        transport = PasswordThenOtp()
        result, _ = _run(transport)
        self.assertTrue(result["registration_completed"])
        self.assertIn("verify_password", transport.calls)
        self.assertIn("verify_mfa_otp", transport.calls)

    def test_transport_exception_keeps_the_active_node(self):
        class BrokenEmailTransport(_Transport):
            def submit_email_identifier(self, _email):
                raise TimeoutError("private upstream detail")

        with self.assertRaises(FreeRegisterError) as raised:
            _run(BrokenEmailTransport())
        self.assertEqual(raised.exception.node_code, "free_email_identifier")
        self.assertEqual(raised.exception.error_code, "free_email_identifier_transport_failed")

    def test_profile_navigation_failure_stops_before_profile_submission(self):
        class BrokenProfileNavigation(_Transport):
            def visit_continue(self, _url, _referer):
                self.calls.append("visit_continue")
                return {"_status": 503, "error": "temporary unavailable"}

        transport = BrokenProfileNavigation()
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(raised.exception.node_code, "free_account_create")
        self.assertNotIn("create_account_profile", transport.calls)


if __name__ == "__main__":
    unittest.main()
