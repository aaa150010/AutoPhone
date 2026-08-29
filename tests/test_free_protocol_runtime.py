from __future__ import annotations

import sys
import threading
from types import ModuleType, SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import unittest
from unittest.mock import patch

from mac_overrides import free_protocol_runtime as runtime


class _Session:
    next_id = 0

    def __init__(self):
        type(self).next_id += 1
        self.identity = type(self).next_id
        self.closed = False
        self.cookies = _Cookies()
        self.proxies = {}
        self.trust_env = True
        self.verify = False
        self.timeout = 30

    def close(self):
        self.closed = True


class _Cookies:
    def __init__(self):
        self.values = []
        self.jar = []

    def set(self, name, value, **kwargs):
        self.values.append((name, value, dict(kwargs)))

    def update(self, other):
        self.values.extend(list(getattr(other, "values", [])))


class _Sentinel:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.fingerprint = kwargs.get("fingerprint") if isinstance(kwargs.get("fingerprint"), dict) else {}
        self.flows = []
        type(self).instances.append(self)

    def reset(self, flow=""):
        self.flows.append(flow)


class _Transport:
    instances = []
    phone_calls = 0

    def __init__(self, config, *, oauth_params, proxy, sentinel_provider, device_id, log_fn):
        self.config = config
        self.oauth_params = dict(oauth_params)
        self.proxy = proxy
        self.sentinel_provider = sentinel_provider
        self.device_id = device_id
        self.log_fn = log_fn
        self.session = _Session()
        self.initial_session = self.session
        self.initial_session.cookies.set("constructor-cookie", "preserved", domain="auth.openai.com", path="/")
        self.initial_session.proxies = {"http": proxy, "https": proxy}
        self.chatgpt_signup_done = False
        self.initiate_sessions = []
        self.new_session_impersonates = []
        type(self).instances.append(self)

    def _new_session(self, impersonate="chrome"):
        self.new_session_impersonates.append(impersonate)
        return _Session()

    def initiate_oauth(self, _url):
        before = self.session
        if not self.chatgpt_signup_done:
            self.session = _Session()
        self.initiate_sessions.append((before, self.session))
        return {"_status": 200, "page": {"type": "login"}}

    def send_phone_number_otp(self, *_args, **_kwargs):
        type(self).phone_calls += 1
        raise AssertionError("Free protocol must not use a phone provider")


class _Otp:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _Response:
    def __init__(self, status, data=None):
        self.status_code = status
        self.data = data if isinstance(data, dict) else {}

    def json(self):
        return dict(self.data)


class _Manager(runtime.FreeProtocolMixin):
    @classmethod
    def resolve_node_runner(cls, _config=None):
        return "/private/tmp/fake-sentinel-runner.js"

    @staticmethod
    def _instrument_transport(_transport, _task_id, _stage):
        return None

    def _plan_check(self, _transport, _token):
        return "free", False


def _fake_modules(build_calls):
    chain_runner = ModuleType("codex_chain_runner")

    def build_oauth_url(**kwargs):
        build_calls.append(dict(kwargs))
        return (
            "https://auth.example.test/authorize?client_id=client-private&state=state-private",
            "state-private",
            "verifier-private",
        )

    chain_runner.build_oauth_url = build_oauth_url
    oauth_chain = ModuleType("codex_oauth_chain")
    oauth_chain.parse_oauth_url = lambda _url: {
        "client_id": "client-private",
        "state": "state-private",
        "redirect_uri": "http://localhost:1455/auth/callback",
    }
    oauth_chain.RealNodeSentinelProvider = _Sentinel
    oauth_chain.RealCodexTransport = _Transport
    return {"codex_chain_runner": chain_runner, "codex_oauth_chain": oauth_chain}


def _task():
    return {
        "task_id": "protocol-task-1",
        "row_id": "mailbox-row-1",
        "email": "user@example.test",
        "mailbox_url": "https://mail.example.test/inbox?key=private",
        "proxy": "socks5h://user:pass@proxy.example.test:1080",
        "proxy_fingerprint": "proxy-fingerprint",
        "proxy_country": "US",
        "exit_ip": "198.51.100.8",
        "device_id": "fixed-device-id",
    }


def _result():
    return {
        "ok": True,
        "registration_completed": True,
        "oauth_callback_completed": True,
        "access_token": "access-token-private",
    }


class FreeProtocolRuntimeTests(unittest.TestCase):
    def setUp(self):
        _Sentinel.instances = []
        _Transport.instances = []
        _Transport.phone_calls = 0
        _Session.next_id = 0

    def test_reference_profile_reuses_warmed_sessions_and_rewarms_rebuild(self):
        build_calls = []
        preflight_sessions = []
        warmup_sessions = []
        authenticated_sessions = []
        contexts = []
        stages = []
        bootstrap_order = []
        otp = _Otp()

        def preflight(transport, *_args, **_kwargs):
            bootstrap_order.append("preflight")
            preflight_sessions.append(transport.session)
            return {"checks": ["chatgpt-login", "auth-login", "sentinel-frame"]}

        def anonymous(transport, *_args, **_kwargs):
            bootstrap_order.append("warmup")
            warmup_sessions.append(transport.session)
            return {"enabled": True}

        def authenticated(transport, *_args, **_kwargs):
            authenticated_sessions.append(transport.session)
            return {"enabled": True, "ok": True}

        def run_flow(transport, *, transport_factory, oauth_context, **_kwargs):
            contexts.append(dict(oauth_context))
            transport.initiate_oauth(oauth_context["url"])
            rebuilt = transport_factory()
            contexts.append({"params": dict(rebuilt.oauth_params)})
            rebuilt.initiate_oauth(oauth_context["url"])
            return _result(), rebuilt

        with (
            patch.dict(sys.modules, _fake_modules(build_calls)),
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=otp),
            patch.object(runtime, "_network_preflight", side_effect=preflight),
            patch.object(runtime, "_anonymous_warmup", side_effect=anonymous),
            patch.object(
                runtime,
                "_exit_geo_profile",
                side_effect=lambda *_args, **_kwargs: (bootstrap_order.append("geo") or {"country": "JP", "timezone": "Asia/Tokyo"}),
            ),
            patch.object(runtime, "_authenticated_warmup", side_effect=authenticated),
            patch.object(runtime, "run_free_protocol_flow", side_effect=run_flow),
        ):
            result = _Manager()._run_protocol(
                _task(),
                {"auto_set_2fa": False, "email_code_timeout": 30},
                threading.Event(),
                lambda _task_id, code: stages.append(code),
                lambda *_args, **_kwargs: None,
            )

        self.assertEqual(result["twofa_status"], "disabled")
        self.assertEqual(len(build_calls), 1)
        self.assertEqual(build_calls[0]["screen_hint"], "login_or_signup")
        self.assertEqual(build_calls[0]["login_hint"], _task()["email"])
        self.assertEqual(build_calls[0]["prompt"], "login")
        self.assertIn("prompt=login", contexts[0]["url"])
        self.assertIn("ext-oai-did=fixed-device-id", contexts[0]["url"])
        self.assertRegex(contexts[0]["url"], r"auth_session_logging_id=[0-9a-f-]{36}")
        self.assertEqual(len(_Transport.instances), 2)
        self.assertEqual(preflight_sessions, [item.session for item in _Transport.instances])
        self.assertEqual(warmup_sessions, preflight_sessions)
        self.assertEqual(bootstrap_order[:3], ["preflight", "warmup", "preflight"])
        self.assertEqual(authenticated_sessions, [_Transport.instances[-1].session])
        for transport in _Transport.instances:
            self.assertTrue(transport._gptphone_reference_session_prepared)
            self.assertIs(transport.initiate_sessions[0][0], transport.initiate_sessions[0][1])
            self.assertEqual(transport.oauth_params["state"], "state-private")
            self.assertEqual(transport.device_id, "fixed-device-id")
            self.assertEqual(transport.proxy, _task()["proxy"])
            self.assertEqual(transport.new_session_impersonates, ["chrome146"])
            self.assertEqual(transport.chatgpt_impersonate, "chrome146")
            self.assertTrue(transport.initial_session.closed)
            self.assertFalse(transport.session.trust_env)
            self.assertTrue(transport.session.verify)
            self.assertEqual(transport.session.proxies["https"], _task()["proxy"])
            self.assertTrue(any(item[0] == "constructor-cookie" for item in transport.session.cookies.values))
            self.assertEqual(transport.config["sentinel_version"], "20260219f9f6")
            self.assertEqual(transport.config["protocol"]["sentinel_version"], "20260219f9f6")
        self.assertEqual(contexts[0]["code_verifier"], "verifier-private")
        self.assertEqual(contexts[1]["params"]["state"], "state-private")
        self.assertEqual(len(_Sentinel.instances), 2)
        for sentinel in _Sentinel.instances:
            self.assertEqual(sentinel.fingerprint["country"], "US")
            self.assertEqual(sentinel.fingerprint["accept_language"], "en-US,en;q=0.9")
            self.assertEqual(sentinel.fingerprint["timezone_iana"], "America/Los_Angeles")
            self.assertEqual(sentinel.fingerprint["timezone_name"], "America/Los_Angeles")
            self.assertEqual(sentinel.fingerprint["timezone_offset_minutes"], -420)
            self.assertEqual(sentinel.fingerprint["chrome_major"], "149")
            self.assertEqual(sentinel.fingerprint["navigator_platform"], "MacIntel")
            self.assertEqual(sentinel.fingerprint["sec_ch_ua_mobile"], "?0")
        self.assertEqual(
            _Sentinel.instances[0].fingerprint["datadog_trace_id"],
            _Sentinel.instances[1].fingerprint["datadog_trace_id"],
        )
        self.assertEqual(
            _Sentinel.instances[0].fingerprint["traceparent"],
            _Sentinel.instances[1].fingerprint["traceparent"],
        )
        self.assertIn("free_authenticated_warmup", stages)
        self.assertEqual(_Transport.phone_calls, 0)
        self.assertTrue(otp.closed)

    def test_reference_fingerprint_matches_chrome149_macos_locales(self):
        expected = {
            "US": ("en-US", "en-US,en;q=0.9", "America/Los_Angeles", {-480, -420}),
            "JP": ("ja-JP", "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7", "Asia/Tokyo", {540}),
            "GB": ("en-GB", "en-GB,en-US;q=0.9,en;q=0.8", "Europe/London", {0, 60}),
        }
        for country, (language, accept_language, timezone_name, offsets) in expected.items():
            with self.subTest(country=country):
                fingerprint = runtime._reference_fingerprint({}, {"proxy_country": country})
                self.assertIn("Chrome/149.0.0.0", fingerprint["user_agent"])
                self.assertEqual(fingerprint["navigator_language"], language)
                self.assertEqual(fingerprint["accept_language"], accept_language)
                self.assertEqual(fingerprint["timezone_iana"], timezone_name)
                self.assertIn(fingerprint["timezone_offset_minutes"], offsets)
                self.assertEqual(fingerprint["navigator_platform"], "MacIntel")
                self.assertEqual(fingerprint["navigator_vendor"], "Google Inc.")
                self.assertEqual(fingerprint["user_agent_data_platform"], "macOS")
                self.assertTrue(fingerprint["send_client_hints"])
                self.assertEqual(fingerprint["sec_ch_ua_mobile"], "?0")
                self.assertEqual(fingerprint["sentinel_version"], "20260219f9f6")
                trace_id = int(fingerprint["datadog_trace_id"])
                parent_id = int(fingerprint["datadog_parent_id"])
                self.assertEqual(
                    fingerprint["traceparent"],
                    f"00-{trace_id:032x}-{parent_id:016x}-01",
                )
        custom = runtime._reference_fingerprint(
            {"protocol": {"sentinel_version": "custom-version"}},
            {"proxy_country": "US"},
        )
        self.assertEqual(custom["sentinel_version"], "custom-version")
        self.assertTrue(custom["script_src_samples"][-1].endswith("/custom-version/sdk.js"))

    def test_reference_http_session_keeps_test_double_without_factory_compatible(self):
        session = SimpleNamespace(trust_env=True, verify=False, proxies={})
        transport = SimpleNamespace(
            session=session,
            proxy="socks5h://user:pass@proxy.example.test:1080",
        )

        runtime._prepare_reference_http_session(transport)

        self.assertIs(transport.session, session)
        self.assertFalse(session.trust_env)
        self.assertTrue(session.verify)
        self.assertEqual(session.proxies["https"], transport.proxy)
        self.assertEqual(transport.chatgpt_impersonate, "chrome146")

    def test_reference_http_session_factory_failure_has_stable_redacted_node(self):
        class BrokenTransport:
            session = SimpleNamespace()

            @staticmethod
            def _new_session(*_args, **_kwargs):
                raise RuntimeError("proxy-password-private")

        with self.assertRaises(runtime.FreeRegisterError) as raised:
            runtime._prepare_reference_http_session(BrokenTransport())

        self.assertEqual(raised.exception.node_code, "free_protocol_preflight")
        self.assertEqual(raised.exception.error_code, "free_protocol_tls_session_failed")
        self.assertNotIn("proxy-password-private", str(raised.exception))

        empty = SimpleNamespace(session=SimpleNamespace(), _new_session=lambda *_args, **_kwargs: None)
        with self.assertRaises(runtime.FreeRegisterError) as missing:
            runtime._prepare_reference_http_session(empty)
        self.assertEqual(missing.exception.error_code, "free_protocol_tls_session_missing")

    def test_invalid_geo_timezone_preserves_existing_timezone_profile(self):
        fingerprint = {
            "timezone_iana": "America/New_York",
            "timezone_name": "America/New_York",
            "timezone_offset_minutes": -300,
        }
        runtime._apply_geo_fingerprint(
            fingerprint,
            {"country": "US", "timezone": "Invalid/Timezone"},
        )
        self.assertEqual(fingerprint["timezone_iana"], "America/New_York")
        self.assertEqual(fingerprint["timezone_name"], "America/New_York")
        self.assertEqual(fingerprint["timezone_offset_minutes"], -300)

    def test_legacy_profile_skips_reference_bootstrap_and_fingerprint(self):
        build_calls = []
        otp = _Otp()

        def run_flow(transport, *, oauth_context, **_kwargs):
            transport.initiate_oauth(oauth_context["url"])
            return _result(), transport

        with (
            patch.dict(sys.modules, _fake_modules(build_calls)),
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=otp),
            patch.object(runtime, "_network_preflight", side_effect=AssertionError("legacy preflight")),
            patch.object(runtime, "_anonymous_warmup", side_effect=AssertionError("legacy anonymous warmup")),
            patch.object(runtime, "_exit_geo_profile", side_effect=AssertionError("legacy geo")),
            patch.object(runtime, "_authenticated_warmup", side_effect=AssertionError("legacy auth warmup")),
            patch.object(runtime, "run_free_protocol_flow", side_effect=run_flow),
        ):
            result = _Manager()._run_protocol(
                _task(),
                {"flow_profile": "legacy", "auto_set_2fa": False},
                threading.Event(),
                lambda *_args: None,
                lambda *_args, **_kwargs: None,
            )

        self.assertEqual(result["twofa_status"], "disabled")
        self.assertEqual(len(build_calls), 1)
        self.assertEqual(len(_Sentinel.instances), 1)
        self.assertNotIn("fingerprint", _Sentinel.instances[0].kwargs)
        transport = _Transport.instances[0]
        self.assertFalse(hasattr(transport, "_gptphone_reference_session_prepared"))
        self.assertIsNot(transport.initiate_sessions[0][0], transport.initiate_sessions[0][1])
        self.assertFalse(transport.config["run_chatgpt_signup_phase"])
        self.assertEqual(_Transport.phone_calls, 0)

    def test_existing_account_result_never_gets_fixed_password_or_credential(self):
        build_calls = []
        otp = _Otp()

        def run_flow(transport, **_kwargs):
            return {**_result(), "account_flow": "existing_login"}, transport

        with (
            patch.dict(sys.modules, _fake_modules(build_calls)),
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=otp),
            patch.object(runtime, "run_free_protocol_flow", side_effect=run_flow),
        ):
            result = _Manager()._run_protocol(
                _task(), {"flow_profile": "legacy", "auto_set_2fa": False},
                threading.Event(), lambda *_args: None, lambda *_args, **_kwargs: None,
            )

        self.assertEqual(result["account_flow"], "existing_login")
        self.assertNotIn("password", result)
        self.assertNotIn("credential_line", result)

    def test_plan_failure_is_structured_and_signup_keeps_password(self):
        class FailPlanManager(_Manager):
            def _plan_check(self, _transport, _token):
                raise runtime.FreeRegisterError(
                    "free_plan_check", "查询 Free 套餐资格", "套餐接口返回 HTTP 429",
                    provider_status=429, provider_code="rate_limit",
                    error_code="free_plan_accounts_http_failed",
                    action_hint="稍后重新测活",
                )

        build_calls = []
        otp = _Otp()

        def run_flow(transport, **_kwargs):
            return {**_result(), "account_flow": "signup", "password": runtime.FIXED_PASSWORD}, transport

        with (
            patch.dict(sys.modules, _fake_modules(build_calls)),
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=otp),
            patch.object(runtime, "run_free_protocol_flow", side_effect=run_flow),
        ):
            result = FailPlanManager()._run_protocol(
                _task(), {"flow_profile": "legacy", "auto_set_2fa": False},
                threading.Event(), lambda *_args: None, lambda *_args, **_kwargs: None,
            )

        self.assertEqual(result["password"], runtime.FIXED_PASSWORD)
        failure = result["plan_failure"]
        self.assertEqual(failure["node_code"], "free_plan_check")
        self.assertEqual(failure["error_code"], "free_plan_accounts_http_failed")
        self.assertEqual(failure["http_status"], 429)
        self.assertEqual(failure["provider_code"], "rate_limit")
        self.assertEqual(failure["action_hint"], "稍后重新测活")

    def test_plan_check_uses_exit_timezone_and_preserves_provider_status(self):
        class Session:
            def __init__(self):
                self.urls = []

            def get(self, url, **_kwargs):
                self.urls.append(url)
                return _Response(503, {"error": {"code": "upstream_busy"}})

        session = Session()
        transport = SimpleNamespace(
            session=session,
            _gptphone_timezone_offset_minutes=540,
            sentinel_provider=SimpleNamespace(fingerprint={"timezone_offset_minutes": -300}),
        )
        with self.assertRaises(runtime.FreeRegisterError) as raised:
            runtime.FreeProtocolMixin._plan_check(_Manager(), transport, "token-private")
        self.assertIn("timezone_offset_min=540", session.urls[0])
        self.assertEqual(raised.exception.provider_status, 503)
        self.assertEqual(raised.exception.provider_code, "upstream_busy")

    def test_twofa_failures_keep_exact_subnode_and_provider_fields(self):
        class SendFailureTransport:
            device_id = "device"
            session = SimpleNamespace()

            @staticmethod
            def send_mfa_otp(_url):
                return {"_status": 429, "error_code": "otp_rate_limit"}

            @staticmethod
            def verify_mfa_otp(_code):
                return {"_status": 200}

        with self.assertRaises(runtime.FreeTwoFaPending) as raised:
            _Manager()._enroll_twofa(
                SendFailureTransport(), "token-private", _task(), runtime.FIXED_PASSWORD,
                {}, _Otp(), lambda *_args: None,
            )
        pending = raised.exception
        self.assertEqual(pending.node_code, "free_twofa_otp_send")
        self.assertEqual(pending.error_code, "free_twofa_otp_send_failed")
        self.assertEqual(pending.provider_status, 429)
        self.assertEqual(pending.provider_code, "otp_rate_limit")

        class OtpFailure:
            @staticmethod
            def mark_sent(_stage):
                return None

            @staticmethod
            def wait_code(_email, **_kwargs):
                raise runtime.FreeRegisterError(
                    "free_twofa_enroll", "等待 Free 账号 2FA 邮箱验证码", "邮箱等待超时",
                    provider_status=504, error_code="mailbox_timeout",
                )

        class SentTransport(SendFailureTransport):
            @staticmethod
            def send_mfa_otp(_url):
                return {"_status": 200}

        with self.assertRaises(runtime.FreeTwoFaPending) as raised:
            _Manager()._enroll_twofa(
                SentTransport(), "token-private", _task(), runtime.FIXED_PASSWORD,
                {}, OtpFailure(), lambda *_args: None,
            )
        self.assertEqual(raised.exception.node_code, "free_twofa_otp_validate")
        self.assertEqual(raised.exception.error_code, "free_twofa_otp_validate_failed")
        self.assertEqual(raised.exception.provider_status, 504)

    def test_twofa_enroll_and_activate_failures_keep_their_own_nodes(self):
        class Session:
            def __init__(self, responses):
                self.responses = list(responses)

            def post(self, *_args, **_kwargs):
                return self.responses.pop(0)

        enroll_transport = SimpleNamespace(
            session=Session([_Response(503, {"error": {"code": "enroll_busy"}})]),
            device_id="device",
        )
        with self.assertRaises(runtime.FreeTwoFaPending) as raised:
            _Manager()._enroll_twofa(
                enroll_transport, "token-private", _task(), runtime.FIXED_PASSWORD,
                {}, _Otp(), lambda *_args: None,
            )
        self.assertEqual(raised.exception.node_code, "free_twofa_enroll")
        self.assertEqual(raised.exception.provider_status, 503)
        self.assertEqual(raised.exception.provider_code, "enroll_busy")

        activate_transport = SimpleNamespace(
            session=Session([
                _Response(200, {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session"}),
                _Response(409, {"error": {"code": "already_active"}}),
            ]),
            device_id="device",
        )
        with self.assertRaises(runtime.FreeTwoFaPending) as raised:
            _Manager()._enroll_twofa(
                activate_transport, "token-private", _task(), runtime.FIXED_PASSWORD,
                {}, _Otp(), lambda *_args: None,
            )
        self.assertEqual(raised.exception.node_code, "free_twofa_activate")
        self.assertEqual(raised.exception.provider_status, 409)
        self.assertEqual(raised.exception.provider_code, "already_active")

    def test_twofa_retry_converges_when_server_already_enabled(self):
        class Otp:
            @staticmethod
            def mark_sent(*_args, **_kwargs):
                return None

            @staticmethod
            def wait_code(_email, **_kwargs):
                return "123456"

        class Session:
            def __init__(self):
                self.posts = []

            def get(self, url, **_kwargs):
                self.posts.append(("get", url))
                return _Response(200, {"mfa_enabled": True, "factors": {"totp": [{"factor_type": "totp"}]}})

            def post(self, url, **_kwargs):
                self.posts.append(("post", url))
                return _Response(AssertionError("enrollment must not be repeated"), {})

        class Transport:
            def __init__(self):
                self.session = Session()
                self.device_id = "device"

            @staticmethod
            def send_mfa_otp(_url):
                return {"_status": 200}

            @staticmethod
            def verify_mfa_otp(_code):
                return {"_status": 200}

        result = _Manager()._enroll_twofa(
            Transport(), "token-private", _task(), runtime.FIXED_PASSWORD,
            {}, Otp(), lambda *_args: None,
        )
        self.assertEqual(result, {"twofa_status": "enabled"})

    def test_twofa_activation_dropped_response_converges_from_mfa_status(self):
        class Otp:
            @staticmethod
            def mark_sent(*_args, **_kwargs):
                return None

            @staticmethod
            def wait_code(_email, **_kwargs):
                return "123456"

        class Session:
            def __init__(self):
                self.status_reads = 0

            def get(self, _url, **_kwargs):
                self.status_reads += 1
                enabled = self.status_reads > 1
                return _Response(200, {"mfa_enabled": enabled, "factors": {"totp": ([{"factor_type": "totp"}] if enabled else [])}})

            def post(self, url, **_kwargs):
                if url.endswith("/mfa/enroll"):
                    return _Response(200, {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session"})
                return _Response(503, {"error": {"code": "response_lost"}})

        class Transport:
            def __init__(self):
                self.session = Session()
                self.device_id = "device"

            @staticmethod
            def send_mfa_otp(_url):
                return {"_status": 200}

            @staticmethod
            def verify_mfa_otp(_code):
                return {"_status": 200}

        result = _Manager()._enroll_twofa(
            Transport(), "token-private", _task(), runtime.FIXED_PASSWORD,
            {}, Otp(), lambda *_args: None,
        )
        self.assertEqual(result["twofa_status"], "enabled")
        self.assertEqual(result["totp_secret"], "JBSWY3DPEHPK3PXP")

    def test_twofa_reauth_follows_callback_and_uses_fresh_session_token(self):
        class Otp:
            @staticmethod
            def prepare(*_args, **_kwargs):
                return None

            @staticmethod
            def mark_sent(*_args, **_kwargs):
                return None

            @staticmethod
            def wait_code(_email, **_kwargs):
                return "123456"

        class Session:
            def __init__(self):
                self.posts = []

            def post(self, url, **kwargs):
                self.posts.append((url, kwargs))
                if url.endswith("/mfa/enroll"):
                    return _Response(200, {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session"})
                return _Response(200, {"success": True})

        class Transport:
            def __init__(self):
                self.session = Session()
                self.device_id = "device"
                self.callbacks = []

            def send_mfa_otp(self, _url):
                return {"_status": 200}

            def verify_mfa_otp(self, _code):
                return {"_status": 200, "continue_url": "https://auth.example.test/continue"}

            def complete_chatgpt_callback(self, url):
                self.callbacks.append(url)
                return {"_status": 200}

            def chatgpt_access_token(self):
                return "fresh-session-token"

        transport = Transport()
        result = _Manager()._enroll_twofa(
            transport, "stale-session-token", _task(), runtime.FIXED_PASSWORD,
            {}, Otp(), lambda *_args: None,
        )
        self.assertEqual(result["twofa_status"], "enabled")
        self.assertEqual(transport.callbacks, ["https://auth.example.test/continue"])
        self.assertEqual(transport.session.posts[0][1]["headers"]["authorization"], "Bearer fresh-session-token")
        self.assertEqual(transport.session.posts[1][1]["headers"]["authorization"], "Bearer fresh-session-token")

    def test_twofa_protocol_uses_nextauth_reauthentication_before_enroll(self):
        class Otp:
            def __init__(self):
                self.calls = []

            def prepare(self, *args, **kwargs):
                self.calls.append(("prepare", args, kwargs))

            def mark_sent(self, *args, **kwargs):
                self.calls.append(("mark_sent", args, kwargs))

            def wait_code(self, _email, **kwargs):
                self.calls.append(("wait_code", kwargs))
                return "123456"

        class Session:
            def __init__(self):
                self.events = []

            def get(self, url, **kwargs):
                self.events.append(("get", url, kwargs))
                if url.endswith("/api/auth/csrf"):
                    return _Response(200, {"csrfToken": "csrf-private"})
                return _Response(200, {})

            def post(self, url, **kwargs):
                self.events.append(("post", url, kwargs))
                if "/api/auth/signin/openai?" in url:
                    return _Response(200, {"url": "https://auth.openai.com/authorize/private"})
                if url.endswith("/mfa/enroll"):
                    return _Response(200, {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session"})
                return _Response(200, {"success": True})

        class Transport:
            def __init__(self):
                self.session = Session()
                self.device_id = "device"
                self.post_auth_calls = []

            def _post_auth_json(self, path, payload, **kwargs):
                self.post_auth_calls.append((path, payload, kwargs))
                return {"_status": 200, "continue_url": "https://auth.openai.com/callback/private"}

            def chatgpt_access_token(self):
                return "fresh-session-token"

        otp = Otp()
        transport = Transport()
        result = _Manager()._enroll_twofa(
            transport, "stale-session-token", _task(), runtime.FIXED_PASSWORD,
            {}, otp, lambda *_args: None,
        )
        self.assertEqual(result["twofa_status"], "enabled")
        self.assertEqual(transport.post_auth_calls[0][0], "/api/accounts/email-otp/validate")
        self.assertEqual(transport.post_auth_calls[0][1], {"code": "123456"})
        self.assertEqual(transport.session.events[0][0:2], ("get", "https://chatgpt.com/api/auth/csrf"))
        self.assertIn("reauth=password", transport.session.events[1][1])
        signin_query = parse_qs(urlsplit(transport.session.events[1][1]).query)
        self.assertEqual(signin_query["ext-oai-did"], ["device"])
        self.assertEqual(transport.session.events[2][1], "https://auth.openai.com/authorize/private")
        self.assertEqual(transport.session.events[3][1], "https://auth.openai.com/callback/private")
        for event in transport.session.events[2:4]:
            navigation_headers = event[2]["headers"]
            self.assertEqual(navigation_headers["sec-fetch-mode"], "navigate")
            self.assertEqual(navigation_headers["sec-fetch-dest"], "document")
            self.assertIn("text/html", navigation_headers["accept"])
            self.assertNotIn("origin", {str(key).casefold() for key in navigation_headers})
            self.assertNotIn("authorization", {str(key).casefold() for key in navigation_headers})
        self.assertEqual(transport.session.events[-2][2]["headers"]["authorization"], "Bearer fresh-session-token")

    def test_twofa_retry_clears_stale_failure_without_inventing_password(self):
        build_calls = []
        manager = _Manager()
        manager.pool = SimpleNamespace(result=lambda _row_id: {
            "access_token": "token-private", "account_flow": "existing_login",
            "failure": {"node_code": "free_twofa_activate"},
            "twofa_failure": {"node_code": "free_twofa_activate"},
            "twofa_error": "old failure", "error": "old failure",
        })
        with (
            patch.dict(sys.modules, _fake_modules(build_calls)),
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=_Otp()),
            patch.object(_Manager, "_enroll_twofa", return_value={
                "twofa_status": "enabled", "totp_secret": "JBSWY3DPEHPK3PXP",
            }),
        ):
            result = manager._run_protocol(
                _task(), {"flow_profile": "legacy"}, threading.Event(),
                lambda *_args: None, lambda *_args, **_kwargs: None, twofa_retry=True,
            )

        self.assertEqual(result["twofa_status"], "enabled")
        for key in ("failure", "twofa_failure", "twofa_error", "error", "password", "credential_line"):
            self.assertNotIn(key, result)


if __name__ == "__main__":
    unittest.main()
