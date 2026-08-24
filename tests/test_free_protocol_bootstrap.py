from __future__ import annotations

from types import SimpleNamespace
import unittest

from mac_overrides.free_protocol_bootstrap import (
    anonymous_warmup,
    authenticated_warmup,
    exit_geo_profile,
    network_preflight,
    prepare_reference_session,
)
from mac_overrides.free_register_common import FreeRegisterError


class _Response:
    def __init__(self, status: int, payload=None, *, content_type: str = "application/json", text: str = ""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.headers = {"content-type": content_type}
        self.text = text
        self.content = text.encode("utf-8")

    def json(self):
        return self._payload


class _Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.cookies = _Cookies()
        self.trust_env = True

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


class _Transport:
    def __init__(self, responses):
        self.session = _Session(responses)
        self.device_id = "device-private"
        self._gptphone_reference_fingerprint = {
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/136",
            "accept_language": "en-US,en;q=0.9",
            "sec_ch_ua": '"Google Chrome";v="136"',
            "sec_ch_ua_platform": '"macOS"',
        }

    @staticmethod
    def _headers_for_url(_url, referer=""):
        return {"accept": "*/*", "referer": referer}


class _JsonTransport(_Transport):
    def _headers(self, flow, referer):
        return {
            "user-agent": "stale-windows-profile",
            "accept": "application/json",
            "flow": flow,
            "referer": referer,
        }


class _Cookies:
    def __init__(self):
        self.jar = []
        self.values = []

    def set(self, name, value, **kwargs):
        self.values.append((name, value, kwargs))


class FreeProtocolBootstrapTests(unittest.TestCase):
    def test_reference_session_sets_oai_device_cookie_and_browser_navigation_headers(self):
        transport = _Transport([])
        prepare_reference_session(transport)

        self.assertEqual(len(transport.session.cookies.values), 3)
        self.assertEqual(
            {item[2]["domain"] for item in transport.session.cookies.values},
            {"chatgpt.com", "auth.openai.com", "sentinel.openai.com"},
        )
        self.assertTrue(all(item[0:2] == ("oai-did", "device-private") for item in transport.session.cookies.values))
        headers = transport._headers_for_url("https://auth.openai.com/log-in", "https://chatgpt.com/login")
        # ``_headers_for_url`` itself is the recovered method; bootstrap's
        # public request helper applies the reference navigation envelope.
        from mac_overrides.free_protocol_bootstrap import _headers
        headers = _headers(transport, "https://auth.openai.com/log-in", "https://chatgpt.com/login")
        self.assertEqual(headers["sec-fetch-site"], "cross-site")
        self.assertEqual(headers["sec-fetch-mode"], "navigate")
        self.assertEqual(headers["sec-fetch-dest"], "document")
        self.assertEqual(headers["sec-fetch-user"], "?1")
        self.assertIn("application/xhtml+xml", headers["accept"])
        self.assertEqual(headers["user-agent"], transport._gptphone_reference_fingerprint["user_agent"])

    def test_reference_session_wraps_json_headers_without_losing_flow_or_referer(self):
        transport = _JsonTransport([])
        prepare_reference_session(transport)
        headers = transport._headers("authorize_continue", "https://auth.openai.com/log-in")
        self.assertEqual(headers["flow"], "authorize_continue")
        self.assertEqual(headers["referer"], "https://auth.openai.com/log-in")
        self.assertEqual(headers["user-agent"], transport._gptphone_reference_fingerprint["user_agent"])
        self.assertEqual(headers["accept"], "application/json")

    def test_reference_session_upgrades_recovered_oauth_get_headers(self):
        transport = _Transport([_Response(200)])
        prepare_reference_session(transport)
        transport.session.get(
            "https://auth.openai.com/api/accounts/authorize?client_id=client-private",
            headers={"accept": "text/html"},
        )
        headers = transport.session.calls[-1][1]["headers"]
        self.assertEqual(headers["user-agent"], transport._gptphone_reference_fingerprint["user_agent"])
        self.assertEqual(headers["referer"], "https://chatgpt.com/")
        self.assertEqual(headers["sec-fetch-mode"], "navigate")
        self.assertEqual(headers["sec-fetch-dest"], "document")

    def test_reference_session_keeps_sentinel_frame_as_navigation(self):
        transport = _Transport([_Response(200)])
        prepare_reference_session(transport)
        transport.session.get(
            "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=test",
            headers={"referer": "https://auth.openai.com/log-in"},
        )
        headers = transport.session.calls[-1][1]["headers"]
        self.assertEqual(headers["sec-fetch-mode"], "navigate")
        self.assertEqual(headers["sec-fetch-dest"], "document")

    def test_rebuilt_transport_gets_the_same_cookie_and_header_policy(self):
        first = _JsonTransport([])
        second = _JsonTransport([])
        profile = dict(first._gptphone_reference_fingerprint)
        prepare_reference_session(first, profile)
        prepare_reference_session(second, profile)
        self.assertEqual(first._headers("authorize_continue", "https://auth.openai.com/log-in"), second._headers("authorize_continue", "https://auth.openai.com/log-in"))
        self.assertEqual(
            [item[2]["domain"] for item in first.session.cookies.values],
            [item[2]["domain"] for item in second.session.cookies.values],
        )

    def test_status_zero_is_a_preflight_failure_with_stable_node(self):
        transport = _Transport([_Response(0)])
        with self.assertRaises(FreeRegisterError) as raised:
            network_preflight(
                transport,
                {"protocol": {"network_preflight_retries": 1}},
            )
        self.assertEqual(raised.exception.node_code, "free_protocol_preflight")
        self.assertEqual(raised.exception.node_label, "协议网络预检")
        self.assertEqual(raised.exception.provider_status, 0)
        self.assertEqual(raised.exception.error_code, "free_protocol_preflight_http")
        self.assertFalse(transport.session.trust_env)

    def test_preflight_stops_on_http_200_cloudflare_challenge_without_logging_body(self):
        secret = "challenge-private-marker"
        transport = _Transport([_Response(
            200,
            content_type="text/html; charset=utf-8",
            text=f"<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/{secret}'></script></html>",
        )])
        events = []

        with self.assertRaises(FreeRegisterError) as raised:
            network_preflight(
                transport,
                {"protocol": {"network_preflight_retries": 3}},
                log=lambda message, level="info", **fields: events.append((message, level, fields)),
            )

        self.assertEqual(raised.exception.node_code, "free_oauth_security_challenge")
        self.assertEqual(raised.exception.error_code, "free_oauth_security_challenge")
        self.assertEqual(raised.exception.provider_status, 200)
        self.assertEqual(raised.exception.page_type, "security_challenge")
        self.assertEqual(raised.exception.content_type, "text/html")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(len(transport.session.calls), 1)
        self.assertNotIn(secret, str(events))
        self.assertNotIn(secret, str(raised.exception))

    def test_preflight_accepts_expected_login_html_without_challenge_markers(self):
        transport = _Transport([
            _Response(200, content_type="text/html", text="<html><title>Log in</title></html>"),
            _Response(200, content_type="text/html", text="<html><title>OpenAI Login</title></html>"),
            _Response(200, content_type="text/html", text="<html><body>sentinel frame</body></html>"),
        ])

        result = network_preflight(
            transport,
            {"protocol": {"network_preflight_retries": 1}},
        )

        self.assertEqual(result["checks"], ["chatgpt-login", "auth-login", "sentinel-frame"])
        self.assertEqual(len(transport.session.calls), 3)

    def test_authenticated_warmup_does_not_report_status_zero_as_success(self):
        events = []
        transport = _Transport([_Response(200), _Response(0)])
        result = authenticated_warmup(
            transport,
            {},
            "token-private",
            log=lambda message, level="info", **fields: events.append((message, level, fields)),
        )
        self.assertFalse(result["ok"])
        self.assertEqual([item["ok"] for item in result["checks"]], [True, False])
        self.assertEqual(events[-1][2]["outcome"], "partial")
        self.assertNotIn("token-private", str(events))

    def test_anonymous_warmup_uses_its_own_node_and_partial_status(self):
        events = []
        transport = _Transport([_Response(200), _Response(0), _Response(302)])
        result = anonymous_warmup(
            transport,
            {},
            log=lambda message, level="info", **fields: events.append((message, level, fields)),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(events[-1][2]["outcome"], "partial")
        self.assertTrue(all(
            fields.get("node_code") == "free_protocol_warmup"
            for _message, _level, fields in events
        ))

    def test_geo_probe_rejects_non_http_success_before_parsing_json(self):
        transport = _Transport([_Response(503, {"country": "US"})])
        result = exit_geo_profile(
            transport,
            {"protocol": {"geo_probe_url": "https://geo.example.test/json"}},
        )
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
