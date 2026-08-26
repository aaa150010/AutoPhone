from __future__ import annotations

import os
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.free_proxy_chatgpt import probe_chatgpt_login


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _FakeSession:
    instances: list["_FakeSession"] = []
    response = _FakeResponse(200)

    def __init__(self, **kwargs):
        self.init_kwargs = dict(kwargs)
        self.proxies = {}
        self.trust_env = True
        self.get_calls: list[tuple[str, dict[str, object], dict[str, str], bool, dict[str, str]]] = []
        self.closed = False
        self.constructor_environment = {
            name: os.environ.get(name)
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
        }
        type(self).instances.append(self)

    def get(self, url: str, **kwargs):
        self.get_calls.append(
            (url, dict(kwargs), dict(self.proxies), self.trust_env, {
                name: os.environ.get(name)
                for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
            })
        )
        return type(self).response

    def close(self) -> None:
        self.closed = True


def _curl_module() -> ModuleType:
    module = ModuleType("curl_cffi")
    module.requests = SimpleNamespace(Session=_FakeSession)
    return module


class FreeProxyChatgptTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeSession.instances.clear()
        _FakeSession.response = _FakeResponse(200)

    def _probe(self, proxy: str = "socks5://probe-user:probe-password@proxy.example.test:8000") -> int:
        return probe_chatgpt_login(proxy)

    def test_probe_uses_reference_navigation_identity_and_remote_dns(self) -> None:
        names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
        original = {name: os.environ.get(name) for name in names}
        inherited = {name: f"http://inherited-{name.lower()}.invalid" for name in names}
        try:
            os.environ.update(inherited)
            with patch.dict(sys.modules, {"curl_cffi": _curl_module()}):
                self.assertEqual(self._probe(), 200)
            self.assertEqual(
                {name: os.environ.get(name) for name in names},
                inherited,
            )
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        session = _FakeSession.instances[-1]
        self.assertEqual(session.init_kwargs, {"impersonate": "chrome146", "verify": True})
        self.assertEqual(session.proxies, {
            "http": "socks5://probe-user:probe-password@proxy.example.test:8000",
            "https": "socks5://probe-user:probe-password@proxy.example.test:8000",
        })
        self.assertFalse(session.trust_env)
        self.assertEqual(session.constructor_environment, {
            "HTTP_PROXY": None,
            "HTTPS_PROXY": None,
            "ALL_PROXY": None,
        })
        url, kwargs, _proxies, trust_env, request_environment = session.get_calls[-1]
        self.assertEqual(url, "https://chatgpt.com/login")
        self.assertFalse(trust_env)
        self.assertEqual(request_environment, {
            "HTTP_PROXY": None,
            "HTTPS_PROXY": None,
            "ALL_PROXY": None,
        })
        headers = kwargs["headers"]
        self.assertIsInstance(headers, dict)
        self.assertIn("application/xhtml+xml", headers["accept"])
        self.assertIn("Chrome/149.0.0.0", headers["user-agent"])
        self.assertEqual(headers["accept-language"], "en-US,en;q=0.9")
        self.assertIn("sec-ch-ua", headers)
        self.assertEqual(headers["sec-ch-ua-mobile"], "?0")
        self.assertEqual(headers["sec-ch-ua-platform"], '"macOS"')
        self.assertEqual(headers["sec-fetch-site"], "same-origin")
        self.assertEqual(headers["sec-fetch-mode"], "navigate")
        self.assertEqual(headers["sec-fetch-dest"], "document")
        self.assertEqual(headers["sec-fetch-user"], "?1")
        self.assertEqual(headers["referer"], "https://chatgpt.com/")
        self.assertEqual(headers["priority"], "u=0, i")
        self.assertEqual(headers["upgrade-insecure-requests"], "1")
        self.assertTrue(session.closed)

    def test_probe_returns_403_without_exposing_response_or_proxy_credentials(self) -> None:
        secret = "proxy-password-private"
        _FakeSession.response = _FakeResponse(403, text=f"blocked {secret}")
        with patch.dict(sys.modules, {"curl_cffi": _curl_module()}):
            status = self._probe(
                f"socks5://probe-user:{secret}@proxy.example.test:8000"
            )

        self.assertEqual(status, 403)
        self.assertNotIn(secret, str(status))
        self.assertNotIn(secret, str(_FakeSession.instances[-1].get_calls[-1][1]["headers"]))
        self.assertTrue(_FakeSession.instances[-1].closed)

    def test_probe_preserves_upstream_status_and_rejects_invalid_status(self) -> None:
        for status in (200, 399, 403, 500):
            with self.subTest(status=status):
                _FakeSession.response = _FakeResponse(status)
                with patch.dict(sys.modules, {"curl_cffi": _curl_module()}):
                    self.assertEqual(self._probe("http://proxy.example.test:8080"), status)

        for status in (0, 99, 600):
            with self.subTest(status=status):
                _FakeSession.response = _FakeResponse(status)
                with patch.dict(sys.modules, {"curl_cffi": _curl_module()}):
                    with self.assertRaisesRegex(ValueError, "未返回有效 HTTP 状态"):
                        self._probe("http://proxy.example.test:8080")

    def test_probe_rejects_http_200_cloudflare_challenge_without_body_details(self) -> None:
        marker = "Just a moment... /cdn-cgi/challenge-platform/"
        _FakeSession.response = _FakeResponse(200, text=marker)
        with patch.dict(sys.modules, {"curl_cffi": _curl_module()}):
            with self.assertRaises(FreeRegisterError) as raised:
                self._probe("http://proxy.example.test:8080")

        error = raised.exception
        self.assertEqual(error.node_code, "free_proxy_preflight")
        self.assertEqual(error.error_code, "free_proxy_chatgpt_security_challenge")
        self.assertEqual(error.provider_status, 200)
        self.assertEqual(error.page_type, "security_challenge")
        self.assertNotIn(marker, str(error))
        self.assertTrue(_FakeSession.instances[-1].closed)

    def test_probe_ignores_challenge_words_inside_normal_page_scripts(self) -> None:
        _FakeSession.response = _FakeResponse(
            200,
            text=(
                "<html><title>Log in</title>"
                "<script>const marker = 'challenge-platform cloudflare captcha';</script>"
                "</html>"
            ),
        )
        with patch.dict(sys.modules, {"curl_cffi": _curl_module()}):
            self.assertEqual(self._probe("http://proxy.example.test:8080"), 200)


if __name__ == "__main__":
    unittest.main()
