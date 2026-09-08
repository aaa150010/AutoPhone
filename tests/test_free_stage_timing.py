"""Focused tests for protocol preflight/warmup/prelude per-step timing."""

from __future__ import annotations
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from mac_overrides.free_protocol_bootstrap import anonymous_warmup, network_preflight
    from mac_overrides.free_timing import FREE_TIMING_SUBSTEPS
except ImportError:  # pragma: no cover - direct mac_overrides execution
    from free_protocol_bootstrap import (  # type: ignore[no-redef]
        anonymous_warmup,
        network_preflight,
    )
    from free_timing import FREE_TIMING_SUBSTEPS  # type: ignore[no-redef]

try:
    from mac_overrides.free_autoregister_protocol import (
        _prelude_timing,
        _run_reference_chatgpt_prelude,
        _timed,
    )
except ImportError:  # pragma: no cover - direct mac_overrides execution
    from free_autoregister_protocol import (  # type: ignore[no-redef]
        _prelude_timing,
        _run_reference_chatgpt_prelude,
        _timed,
    )


class _Response:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {"content-type": "text/html"}
        self.content = text.encode()

    def json(self):
        return {}


class _Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.cookies = type("Jar", (), {"jar": []})()
        self.headers = {}

    def get(self, url, **kwargs):
        item = self.responses.pop(0) if self.responses else _Response()
        if isinstance(item, Exception):
            raise item
        return item

    def post(self, *args, **kwargs):
        return self.get(*args, **kwargs)


class _Transport:
    def __init__(self, session):
        self.session = session
        self.device_id = "device"

    def _headers_for_url(self, url, referer=""):
        return {"referer": referer}


class _NoopLog:
    def __call__(self, *args, **kwargs):
        pass


class TimingCallbackTests(unittest.TestCase):
    def test_preflight_emits_per_step_timings(self):
        samples = []
        config = {"_timing_substep": lambda stage, code, ms, outcome="success": samples.append((stage, code, ms, outcome))}
        session = _Session([_Response(), _Response(), _Response(200, "sentinel")])
        network_preflight(_Transport(session), config, log=_NoopLog())
        codes = [code for _stage, code, _ms, _outcome in samples]
        self.assertEqual(codes, ["preflight_login_fetch", "preflight_auth_fetch", "preflight_sentinel_frame"])
        for _stage, _code, ms, _outcome in samples:
            self.assertGreaterEqual(ms, 0)

    def test_warmup_emits_per_step_timings(self):
        samples = []
        config = {"_timing_substep": lambda stage, code, ms, outcome="success": samples.append((stage, code, ms, outcome))}
        session = _Session([_Response(), _Response(), _Response()])
        anonymous_warmup(_Transport(session), config, log=_NoopLog())
        codes = [code for _stage, code, _ms, _outcome in samples]
        self.assertEqual(codes, ["warmup_anon_check", "warmup_anon_me", "warmup_anon_models"])

    def test_timing_failure_never_breaks_preflight(self):
        def bad_timing(*_args, **_kwargs):
            raise RuntimeError("nope")

        config = {"_timing_substep": bad_timing}
        session = _Session([_Response(), _Response(), _Response(200, "sentinel")])
        result = network_preflight(_Transport(session), config, log=_NoopLog())
        self.assertEqual(result["checks"], ["chatgpt-login", "auth-login", "sentinel-frame"])

    def test_new_substeps_are_registered(self):
        for code in (
            "preflight_login_fetch", "preflight_auth_fetch", "preflight_sentinel_frame",
            "warmup_anon_check", "warmup_anon_me", "warmup_anon_models",
            "prelude_providers_fetch", "prelude_csrf_fetch", "prelude_signin_fetch",
            "prelude_authorize_navigate", "email_identifier_submit",
        ):
            self.assertIn(code, FREE_TIMING_SUBSTEPS)

    def test_prelude_timing_helpers(self):
        self.assertIsNone(_prelude_timing(None))
        self.assertIsNone(_prelude_timing({}))
        callback = lambda *args: None
        self.assertIs(_prelude_timing({"_timing_substep": callback}), callback)
        _timed(time.monotonic() - 0.01, callback, "free_oauth_session", "prelude_csrf_fetch")
        _timed(time.monotonic(), None, "free_oauth_session", "prelude_csrf_fetch")


class _PreludeSession:
    def __init__(self):
        self.gets = 0
        self.posts = 0

    def get(self, *args, **kwargs):
        self.gets += 1
        return _Response(200, "")

    def post(self, *args, **kwargs):
        self.posts += 1
        return _Response(200, '{"url": "https://auth.openai.com/authorize?x=1"}')


class _PreludeTransport:
    def __init__(self):
        self.session = _PreludeSession()
        self.device_id = "device"
        self._post_count = 0

    def _chatgpt_json_get(self, path, **kwargs):
        if path == "/api/auth/csrf":
            return {"csrfToken": "tok", "_status": 200}
        if path == "/api/auth/providers":
            return {"_status": 200}
        return {"_status": 200}

    def _headers(self, name, referer):
        return {}

    def _gptphone_auth_session_logging_id(self):
        return ""

    def _gptphone_json_response(self, response):
        # The signin POST carries the NextAuth authorize URL in its body.
        self._post_count += 1
        if self._post_count == 1:
            return {"url": "https://auth.openai.com/authorize?client_id=x&state=s", "_status": 200}
        return {"_status": 200, "_url": "https://auth.openai.com/log-in"}


class PreludeTimingTests(unittest.TestCase):
    def test_prelude_emits_csrf_signin_authorize_timings(self):
        samples = []
        config = {"_timing_substep": lambda stage, code, ms, outcome="success": samples.append(code)}
        _run_reference_chatgpt_prelude(_PreludeTransport(), "a@example.test", config=config)
        self.assertIn("prelude_csrf_fetch", samples)
        self.assertIn("prelude_signin_fetch", samples)
        self.assertIn("prelude_authorize_navigate", samples)
        # Providers is emitted by run_autoregister_prelude, not here.
        self.assertNotIn("prelude_providers_fetch", samples)


if __name__ == "__main__":
    unittest.main()
