from __future__ import annotations

from urllib.parse import parse_qs, urlsplit
import unittest

from mac_overrides.free_autoregister_protocol import run_autoregister_prelude
from mac_overrides.free_register_common import FreeRegisterError


class _Transport:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else {"_status": 200, "url": "https://auth.openai.com/log-in"}
        self.error = error
        self.calls = []

    def start_chatgpt_signup_authorize(self, email):
        self.calls.append(email)
        if self.error is not None:
            raise self.error
        return self.response


class AutoRegisterPreludeTests(unittest.TestCase):
    def test_runs_reference_prelude_and_marks_transport(self):
        transport = _Transport()
        stages = []
        logs = []
        result = run_autoregister_prelude(
            transport,
            "user@example.test",
            task_id="task-1",
            stage=lambda task_id, code: stages.append((task_id, code)),
            log=lambda message, level="info": logs.append((message, level)),
        )
        self.assertEqual(transport.calls, ["user@example.test"])
        self.assertEqual(result["_status"], 200)
        self.assertTrue(transport._gptphone_autoregister_prelude)
        self.assertEqual(stages, [("task-1", "free_oauth_session")])
        self.assertTrue(any("AutoRegister" in message for message, _level in logs))

    def test_does_not_call_register_user_or_fail_for_legacy_transport(self):
        class Legacy:
            def register_user(self, *_args):
                raise AssertionError("legacy user/register must not be called")

        self.assertIsNone(run_autoregister_prelude(Legacy(), "user@example.test"))

    def test_provider_failure_keeps_oauth_node_and_redacts_detail(self):
        transport = _Transport({"_status": 429, "error": {"code": "rate_limit_exceeded"}})
        with self.assertRaises(FreeRegisterError) as raised:
            run_autoregister_prelude(transport, "user@example.test")
        self.assertEqual(raised.exception.node_code, "free_oauth_session")
        self.assertEqual(raised.exception.provider_status, 429)
        self.assertEqual(raised.exception.provider_code, "rate_limit_exceeded")
        self.assertEqual(raised.exception.error_code, "free_autoregister_prelude_failed")

    def test_real_transport_uses_reference_signin_shape_and_reaches_otp_page(self):
        class Response:
            def __init__(self, *, payload=None, url="", status=200, content_type="application/json"):
                self.payload = payload or {}
                self.url = url
                self.status_code = status
                self.headers = {"content-type": content_type}

            def json(self):
                return self.payload

        class Session:
            def __init__(self, events):
                self.calls = []
                self.events = events

            def get(self, url, **kwargs):
                self.calls.append(("GET", url, kwargs))
                self.events.append(("GET", urlsplit(url).path))
                return Response(
                    url="https://auth.openai.com/email-verification",
                    content_type="text/html",
                )

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs))
                self.events.append(("POST", urlsplit(url).path))
                return Response(payload={"url": "https://auth.openai.com/authorize?state=state"})

        class RealLike:
            def __init__(self):
                self.events = []
                self.session = Session(self.events)
                self.device_id = "device-private"
                self._gptphone_auth_session_logging_id = "auth-log-private"
                self.get_calls = []

            def start_chatgpt_signup_authorize(self, _email):
                raise AssertionError("the maintained reference prelude should be used")

            def _chatgpt_json_get(self, path, **kwargs):
                self.get_calls.append((path, kwargs))
                self.events.append(("GET", path))
                return {"_status": 200, "csrfToken": "csrf-private"}

        transport = RealLike()
        result = run_autoregister_prelude(transport, "user@example.test")
        self.assertEqual(result["url"], "https://auth.openai.com/email-verification")
        self.assertEqual(result["page"]["type"], "email_otp_verification")
        self.assertEqual(result["continue_url"], "https://auth.openai.com/email-verification")
        self.assertTrue(result["_gptphone_autoregister_prelude"])
        self.assertEqual([path for path, _kwargs in transport.get_calls], [
            "/api/auth/providers",
            "/api/auth/csrf",
        ])
        self.assertEqual(transport.events, [
            ("GET", "/api/auth/providers"),
            ("GET", "/api/auth/csrf"),
            ("POST", "/api/auth/signin/openai"),
            ("GET", "/authorize"),
        ])
        signin = next(item for item in transport.session.calls if item[0] == "POST")
        query = parse_qs(urlsplit(signin[1]).query)
        self.assertEqual(query["ext-passkey-client-capabilities"], ["11111"])
        self.assertEqual(query["screen_hint"], ["login_or_signup"])
        self.assertIn("callbackUrl=https%3A%2F%2Fchatgpt.com%2F", signin[2]["data"])


if __name__ == "__main__":
    unittest.main()
