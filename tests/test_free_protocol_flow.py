from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
import unittest

from mac_overrides.free_protocol_flow import (
    _is_security_page,
    _status,
    _wait_and_validate_email_otp,
    run_free_protocol_flow,
)
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
        self.sentinel_flows = []
        self.sentinel_provider = type(
            "Sentinel",
            (),
            {"reset": lambda _self, flow="": self.sentinel_flows.append(flow)},
        )()
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

    def send_email_otp(self, _url=""):
        self.calls.append("send_email_otp")
        return {"_status": 200, "page": {"type": "email_otp_verification"}, "continue_url": "/verify"}

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
        self.assertEqual(transport.sentinel_flows, [
            "oauth_authorize",
            "authorize_continue",
            "authorize_continue",
            "oauth_create_account",
            "oauth_callback",
            "oauth_token_exchange",
        ])

    def test_email_page_type_aliases_use_the_same_url_mailbox_verification_path(self):
        for page_type in (
            "email_otp",
            "email_otp_send",
            "email_otp_verification",
            "email_verification",
            "email_code_verification",
            "passwordless_email_otp",
        ):
            with self.subTest(page_type=page_type):
                transport = _Transport(
                    email={"_status": 200, "page": {"type": page_type}, "continue_url": "/verify"},
                )
                result, _ = _run(transport)
                self.assertTrue(result["registration_completed"])
                self.assertIn("verify_email_otp", transport.calls)

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

    def test_callback_error_and_wrong_redirect_stop_before_token_exchange(self):
        for callback, error_code in (
            ("http://localhost:1455/auth/callback?error=access_denied&error_description=denied", "oauth_callback_provider_error"),
            ("https://attacker.example/callback?code=authorization-code&state=state-private", "oauth_callback_redirect_mismatch"),
        ):
            with self.subTest(error_code=error_code):
                transport = _Transport(callback=callback)
                with self.assertRaises(FreeRegisterError) as raised:
                    _run(transport)
                self.assertEqual(raised.exception.error_code, error_code)
                self.assertNotIn("exchange_code", transport.calls)

    def test_token_exchange_failure_is_attributed_to_token_stage(self):
        transport = _Transport(exchange={"_status": 400, "error": "invalid_grant"})
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(raised.exception.node_code, "free_access_token")
        self.assertEqual(raised.exception.error_code, "token_exchange_failed")
        self.assertIn("exchange_code", transport.calls)
        self.assertEqual(raised.exception.provider_status, 400)

    def test_token_exchange_string_false_and_zero_status_are_preserved(self):
        transport = _Transport(exchange={"_status": 0, "ok": "false", "error_code": "invalid_grant"})
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(_status(transport.exchange_response), 0)
        self.assertEqual(raised.exception.provider_status, 0)
        self.assertEqual(raised.exception.provider_code, "invalid_grant")

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

    def test_session_rebuild_keeps_original_pkce_context(self):
        first = _Transport(email={"_status": 400, "error": "Your sign-in session is no longer valid."})
        second = _Transport()
        context_factory_calls = []

        def context_factory():
            context_factory_calls.append(True)
            return _oauth_context(state="new-state-must-not-be-used", code_verifier="new-verifier-must-not-be-used")

        result, active = _run(
            first,
            transport_factory=lambda: second,
            oauth_context_factory=context_factory,
        )
        self.assertIs(active, second)
        self.assertEqual(result["oauth_session_rebuilds"], 1)
        self.assertEqual(context_factory_calls, [])
        self.assertEqual(second.callback_args[1]["state"], "state-private")
        self.assertEqual(second.exchange_args[1], "verifier-private")

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

    def test_otp_waits_three_rounds_and_uses_two_controlled_resends(self):
        class ThreeRoundOtp(_ForceOtp):
            def __init__(self):
                super().__init__()
                self.waits = 0
                self.events = []

                class State:
                    active = False

                    def finish_request(inner_self):
                        self.events.append("finish")
                        inner_self.active = False

                self.service = SimpleNamespace(current_stage="", state=State())

            def prepare(self, stage, *, force_snapshot=False):
                self.prepared.append((stage, bool(force_snapshot)))
                self.events.append(f"prepare:{bool(force_snapshot)}")
                self.service.current_stage = stage
                self.service.state.active = True

            def mark_sent(self, stage):
                self.sent.append(stage)
                self.events.append("mark")

            def wait_code(self, _email, stage_code=None, resend_fn=None, **_kwargs):
                self.waits += 1
                if self.waits < 3 and callable(resend_fn):
                    resend_fn()
                if self.waits < 3:
                    raise FreeRegisterError(
                        str(stage_code or "free_email_otp_wait"),
                        "等待 Free 邮箱验证码",
                        "邮箱验证码等待超时",
                        retryable=True,
                        error_code="free_email_otp_wait_mailbox_code_timeout",
                    )
                return self.code

        otp = ThreeRoundOtp()

        class EventTransport(_Transport):
            def send_email_otp(self, _url=""):
                otp.events.append("send")
                return super().send_email_otp(_url)

        transport = EventTransport()
        result, _ = _run(transport, otp=otp)
        self.assertTrue(result["registration_completed"])
        self.assertEqual(otp.waits, 3)
        self.assertEqual(transport.calls.count("send_email_otp"), 2)
        self.assertEqual(otp.prepared.count(("free_email_otp_wait", True)), 2)
        send_positions = [index for index, event in enumerate(otp.events) if event == "send"]
        self.assertEqual(len(send_positions), 2)
        for index in send_positions:
            self.assertEqual(otp.events[index - 3:index], ["finish", "prepare:True", "mark"])

    def test_otp_resend_budget_survives_oauth_session_rebuild(self):
        class ResendThenRebuildOtp(_Otp):
            def __init__(self):
                super().__init__()
                self.resend_available = []

            def wait_code(self, _email, stage_code=None, resend_fn=None, **_kwargs):
                self.resend_available.append(callable(resend_fn))
                if callable(resend_fn):
                    resend_fn()
                return self.code

        class InvalidDuringOtp(_Transport):
            def verify_email_otp(self, _code):
                self.calls.append("verify_email_otp")
                return {"_status": 400, "error": "Your sign-in session is no longer valid."}

        first = InvalidDuringOtp()
        second = _Transport()
        otp = ResendThenRebuildOtp()
        result, active = _run(first, otp=otp, transport_factory=lambda: second)
        self.assertIs(active, second)
        self.assertEqual(result["oauth_session_rebuilds"], 1)
        self.assertEqual(otp.resend_available, [True, True])
        self.assertEqual(first.calls.count("send_email_otp"), 1)
        self.assertEqual(second.calls.count("send_email_otp"), 1)

    def test_phone_page_stops_without_calling_any_sms_method(self):
        class PhoneTransport(_Transport):
            def __init__(self):
                super().__init__(email={"_status": 200, "page": {"type": "phone_verification"}})
                self.phone_calls = 0

            def send_phone_number_otp(self, *_args, **_kwargs):
                self.phone_calls += 1
                raise AssertionError("Free protocol must not consume a phone provider")

        transport = PhoneTransport()
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(raised.exception.node_code, "free_phone_required")
        self.assertEqual(transport.phone_calls, 0)

    def test_existing_login_password_page_switches_directly_to_email_otp(self):
        class PasswordThenOtp(_Transport):
            def __init__(self):
                super().__init__(email={"_status": 200, "page": {"type": "login_password"}, "continue_url": "/log-in/password"})

            def verify_password(self, _password):
                raise AssertionError("已有账号不应提交统一注册密码")

            def verify_email_otp(self, _code):
                self.calls.append("verify_email_otp")
                return {"_status": 200, "page": {"type": "consent"}, "continue_url": "/callback"}

        transport = PasswordThenOtp()
        result, _ = _run(transport)
        self.assertTrue(result["registration_completed"])
        self.assertEqual(result["account_flow"], "existing_login")
        self.assertNotIn("verify_password", transport.calls)
        self.assertEqual(transport.calls.count("send_email_otp"), 1)
        self.assertEqual(transport.calls.count("verify_email_otp"), 1)

    def test_existing_account_email_login_uses_password_verify_sentinel(self):
        class ExistingEmailFallback(_Transport):
            def __init__(self):
                super().__init__(email={
                    "_status": 200,
                    "page": {"type": "login_password"},
                    "continue_url": "/log-in/password",
                })

            def verify_password(self, _password):
                raise AssertionError("已有账号不应提交统一注册密码")

            def verify_email_otp(self, _code):
                self.calls.append("verify_email_otp")
                return {"_status": 200, "page": {"type": "consent"}, "continue_url": "/callback"}

        transport = ExistingEmailFallback()
        result, _ = _run(transport)
        self.assertTrue(result["registration_completed"])
        self.assertEqual(result["account_flow"], "existing_login")
        self.assertNotIn("password", result)
        self.assertNotIn("verify_password", transport.calls)
        self.assertEqual(transport.calls.count("send_email_otp"), 1)
        password_flows = [
            flow for flow in transport.sentinel_flows
            if flow == "password_verify"
        ]
        self.assertEqual(len(password_flows), 2)

    def test_existing_account_email_send_failure_keeps_otp_node(self):
        class FailedEmailSend(_Transport):
            def __init__(self):
                super().__init__(email={
                    "_status": 200, "page": {"type": "login_password"},
                    "continue_url": "/log-in/password",
                })

            def verify_password(self, _password):
                raise AssertionError("已有账号不应提交统一注册密码")

            def send_email_otp(self, _url=""):
                self.calls.append("send_email_otp")
                return {"_status": 503, "error": "email send unavailable", "error_code": "otp_send_unavailable"}

        transport = FailedEmailSend()
        with self.assertRaises(FreeRegisterError) as raised:
            _run(transport)
        self.assertEqual(raised.exception.node_code, "free_existing_login_otp")
        self.assertEqual(raised.exception.error_code, "free_existing_login_otp_send_failed")
        self.assertEqual(raised.exception.provider_code, "otp_send_unavailable")
        self.assertEqual(transport.calls.count("send_email_otp"), 1)
        self.assertNotIn("verify_password", transport.calls)

    def test_generic_otp_uses_existing_account_context_and_never_returns_password(self):
        class ExistingOtp(_Transport):
            def __init__(self):
                super().__init__(email={
                    "_status": 200, "page": {"type": "email_otp"},
                    "flow": "existing_login", "continue_url": "/verify",
                })

            def verify_email_otp(self, _code):
                self.calls.append("verify_email_otp")
                return {"_status": 200, "page": {"type": "consent"}, "continue_url": "/callback"}

        otp = _StageAwareOtp()
        transport = ExistingOtp()
        stages = []
        result, _ = _run(transport, otp=otp, stage=lambda _task, code: stages.append(code))
        self.assertEqual(result["account_flow"], "existing_login")
        self.assertNotIn("password", result)
        self.assertIn(("free_existing_login_otp", False), otp.prepared)
        self.assertIn("password_verify", transport.sentinel_flows)
        self.assertIn("free_existing_login_otp", stages)
        self.assertNotIn("free_email_otp_validate", stages)

    def test_existing_identifier_otp_keeps_the_pre_submit_mailbox_baseline(self):
        class ActiveState:
            def __init__(self):
                self.active = False

            def finish_request(self):
                self.active = False

        class BaselineOtp:
            def __init__(self):
                self.service = type(
                    "Service",
                    (),
                    {"current_stage": "", "state": ActiveState()},
                )()
                self.mail_identity = "old-message"
                self.baseline_identity = ""
                self.prepared = []

            def prepare(self, stage, *, force_snapshot=False):
                self.service.current_stage = stage
                self.prepared.append((stage, bool(force_snapshot)))
                if self.service.state.active:
                    return
                self.baseline_identity = self.mail_identity
                self.service.state.active = True

            def mark_sent(self, stage):
                self.service.current_stage = stage

            def wait_code(self, _email, stage_code=None, **_kwargs):
                if self.mail_identity == self.baseline_identity:
                    raise AssertionError("刚到的新邮件被错误纳入第二次基线")
                return "123456"

        otp = BaselineOtp()

        class ExistingOtp(_Transport):
            def submit_email_identifier(self, _email):
                self.calls.append("submit_email_identifier")
                otp.mail_identity = "new-message"
                return {
                    "_status": 200,
                    "page": {"type": "email_otp"},
                    "flow": "existing_login",
                    "continue_url": "/verify",
                }

            def verify_email_otp(self, _code):
                self.calls.append("verify_email_otp")
                return {"_status": 200, "page": {"type": "consent"}, "continue_url": "/callback"}

        result, _ = _run(ExistingOtp(), otp=otp)

        self.assertTrue(result["registration_completed"])
        self.assertEqual(otp.baseline_identity, "old-message")
        self.assertIn(("free_existing_login_otp", False), otp.prepared)

    def test_passwordless_send_security_challenge_stops_before_mailbox_wait(self):
        class ChallengeFallback(_Transport):
            def __init__(self):
                super().__init__(email={
                    "_status": 200, "page": {"type": "login_password"},
                    "continue_url": "/log-in/password",
                })

            def verify_password(self, _password):
                raise AssertionError("已有账号不应提交统一注册密码")

            def send_email_otp(self, _url=""):
                self.calls.append("send_email_otp")
                return {"_status": 200, "page": {"type": "security_challenge"}, "error_code": "risk_hold"}

        with self.assertRaises(FreeRegisterError) as raised:
            _run(ChallengeFallback())
        self.assertEqual(raised.exception.error_code, "free_oauth_security_challenge")
        self.assertEqual(raised.exception.provider_code, "risk_hold")

    def test_failed_resend_does_not_consume_budget_and_internal_typeerror_is_not_retried(self):
        class ResendOtp(_Otp):
            def wait_code(self, _email, stage_code=None, resend_fn=None, **_kwargs):
                resend_fn()
                raise AssertionError("resend should fail first")

        class FailedSend(_Transport):
            def send_email_otp(self, _url=""):
                raise TimeoutError("send failed")

        budget = {"used": 0}
        with self.assertRaises(FreeRegisterError):
            _wait_and_validate_email_otp(
                FailedSend(), ResendOtp(), "user@example.test",
                {"_status": 200, "page": {"type": "email_otp"}, "continue_url": "/verify"},
                task_id="test-task", stage=lambda *_args: None, log=None,
                resend_budget=budget,
            )
        self.assertEqual(budget["used"], 0)

        class BrokenOtp(_Otp):
            def wait_code(self, _email, stage_code=None, resend_fn=None, stop_requested=None):
                raise TypeError("provider internal bug")

        with self.assertRaisesRegex(TypeError, "provider internal bug"):
            _wait_and_validate_email_otp(
                _Transport(), BrokenOtp(), "user@example.test",
                {"_status": 200, "page": {"type": "email_otp"}, "continue_url": "/verify"},
                task_id="test-task", stage=lambda *_args: None, log=None,
            )

        class LegacyOtp(_Otp):
            def wait_code(self, _email):
                return self.code

        result, _ = _run(_Transport(), otp=LegacyOtp())
        self.assertTrue(result["registration_completed"])

    def test_second_session_failure_preserves_real_node_and_metadata(self):
        first = _Transport(email={"_status": 400, "error": "Your sign-in session is no longer valid."})

        class InvalidOtp(_Transport):
            def verify_email_otp(self, _code):
                self.calls.append("verify_email_otp")
                return {
                    "_status": 440, "error": "Your sign-in session is no longer valid.",
                    "error_code": "session_expired", "page": {"type": "email_otp"},
                    "continue_url": "https://user:pass@auth.example.test/verify?secret=value",
                    "_content_type": "application/json",
                }

        with self.assertRaises(FreeRegisterError) as raised:
            _run(first, transport_factory=InvalidOtp)
        exc = raised.exception
        self.assertEqual(exc.node_code, "free_email_otp_validate")
        self.assertEqual(exc.error_code, "oauth_session_invalid")
        self.assertEqual(exc.provider_status, 440)
        self.assertEqual(exc.provider_code, "session_expired")
        self.assertEqual(exc.page_type, "email_otp")
        self.assertEqual(exc.safe_page, "https://auth.example.test/verify")
        self.assertEqual(exc.session_rebuilds, 1)

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
