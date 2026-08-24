from __future__ import annotations

import unittest
from unittest.mock import patch

from mac_overrides.free_protocol_security import (
    is_security_challenge,
    response_search_text,
    wait_for_security_challenge,
)


class _Session:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0) if self.responses else {
            "_status": 403,
            "page": {"type": "security_challenge"},
        }


class _Transport:
    def __init__(self, *, responses=None, hook=None):
        self.session = _Session(responses)
        self.config = {"protocol": {"security_challenge_wait_seconds": 2}}
        self.hook = hook

    def _headers(self, *_args):
        return {"user-agent": "test-agent"}

    def wait_for_security_challenge(self, response, **kwargs):
        if self.hook is None:
            return response
        return self.hook(response, **kwargs)


class _RawResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    url = "https://auth.openai.com/log-in"
    text = "{}"


class FreeProtocolSecurityTests(unittest.TestCase):
    def test_mapping_challenge_summary_is_bounded_and_mfa_is_not_security(self):
        payload = {"page": {"type": "security_challenge"}, "_body": "Just a moment"}
        self.assertTrue(is_security_challenge(payload))
        self.assertIn("Just a moment", response_search_text(payload))
        self.assertFalse(is_security_challenge({"page": {"type": "mfa_challenge"}}))

    def test_same_transport_hook_can_clear_challenge_without_session_poll(self):
        calls = []

        def clear(response, **kwargs):
            calls.append((response, kwargs))
            return {"_status": 200, "page": {"type": "email_otp"}}

        transport = _Transport(hook=clear)
        challenge = {"_status": 403, "page": {"type": "security_challenge"}}
        result = wait_for_security_challenge(transport, challenge, method="submit_email_identifier")
        self.assertEqual(result["page"]["type"], "email_otp")
        self.assertEqual(len(calls), 1)
        self.assertFalse(transport.session.calls)
        self.assertLessEqual(calls[0][1]["timeout"], 60)

    def test_without_session_hook_returns_original_challenge_without_sleeping(self):
        class NoSession:
            config = {"protocol": {"security_challenge_wait_seconds": 60}}

        challenge = {"_status": 403, "page": {"type": "security_challenge"}}
        with patch("mac_overrides.free_protocol_security.time.sleep") as sleep:
            result = wait_for_security_challenge(NoSession(), challenge)
        self.assertIs(result, challenge)
        sleep.assert_not_called()

    def test_session_poll_normalizes_raw_response_before_returning_to_flow(self):
        transport = _Transport(responses=[_RawResponse()])
        transport.wait_for_security_challenge = None
        transport._json_response = lambda _response: {
            "_status": 200,
            "page": {"type": "login"},
            "url": "https://auth.openai.com/log-in",
        }
        challenge = {"_status": 403, "page": {"type": "security_challenge"}}
        with patch("mac_overrides.free_protocol_security.time.sleep", return_value=None):
            result = wait_for_security_challenge(transport, challenge, method="initiate_oauth")
        self.assertEqual(result["page"]["type"], "login")
        self.assertEqual(len(transport.session.calls), 1)

    def test_session_poll_keeps_challenge_when_raw_response_has_no_converter(self):
        transport = _Transport(responses=[_RawResponse()])
        transport.wait_for_security_challenge = None
        challenge = {"_status": 403, "page": {"type": "security_challenge"}}
        with patch("mac_overrides.free_protocol_security.time.sleep", return_value=None):
            result = wait_for_security_challenge(transport, challenge, method="initiate_oauth")
        self.assertIs(result, challenge)
        self.assertEqual(len(transport.session.calls), 1)

    def test_session_poll_keeps_challenge_for_bare_text_without_converter(self):
        transport = _Transport(responses=["{}"])
        transport.wait_for_security_challenge = None
        challenge = {"_status": 403, "page": {"type": "security_challenge"}}
        with patch("mac_overrides.free_protocol_security.time.sleep", return_value=None):
            result = wait_for_security_challenge(transport, challenge, method="initiate_oauth")
        self.assertIs(result, challenge)
        self.assertEqual(len(transport.session.calls), 1)

    def test_api_challenge_uses_login_document_for_same_session_poll(self):
        transport = _Transport(responses=[{"_status": 200, "page": {"type": "login"}}])
        transport.wait_for_security_challenge = None
        challenge = {
            "_status": 403,
            "page": {
                "type": "security_challenge",
                "continue_url": "https://auth.openai.com/api/accounts/authorize/continue?state=private",
            },
        }
        with patch("mac_overrides.free_protocol_security.time.sleep", return_value=None):
            result = wait_for_security_challenge(transport, challenge, method="authorize_continue")
        self.assertEqual(result["page"]["type"], "login")
        self.assertEqual(transport.session.calls[0][0], "https://auth.openai.com/log-in")


if __name__ == "__main__":
    unittest.main()
