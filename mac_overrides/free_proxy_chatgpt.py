"""Credential-free ChatGPT login-page probe for Free proxy validation."""

from __future__ import annotations

from contextlib import contextmanager
import os
from types import SimpleNamespace
from typing import Any

try:
    from .free_proxy_http import get_via_proxy
    from .free_protocol_bootstrap import _reference_navigation_headers, _security_challenge_html
    from .free_protocol_reference import REFERENCE_TLS_IMPERSONATE, reference_fingerprint
    from .free_register_common import FreeRegisterError, proxy_transport_value
except ImportError:
    from free_proxy_http import get_via_proxy  # type: ignore[no-redef]
    from free_protocol_bootstrap import _reference_navigation_headers, _security_challenge_html  # type: ignore[no-redef]
    from free_protocol_reference import REFERENCE_TLS_IMPERSONATE, reference_fingerprint  # type: ignore[no-redef]
    from free_register_common import FreeRegisterError, proxy_transport_value  # type: ignore[no-redef]


CHATGPT_LOGIN_PROBE_URL = "https://chatgpt.com/login"
CHATGPT_LOGIN_PROBE_REFERER = "https://chatgpt.com/"


@contextmanager
def _without_proxy_environment():
    names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
    saved = {name: os.environ.get(name) for name in names}
    try:
        for name in names:
            os.environ.pop(name, None)
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _reference_probe_headers() -> dict[str, str]:
    """Build the same document-navigation envelope used by Free protocol.

    The standalone pool probe has no task object from which to inherit a
    Sentinel fingerprint.  A fresh default reference profile still keeps the
    probe's TLS image, locale, Client Hints and navigation headers consistent
    with the protocol bootstrap, without carrying any task or credential data.
    """
    fingerprint = reference_fingerprint({}, {"proxy_country": "US"})
    identity = SimpleNamespace(_gptphone_reference_fingerprint=fingerprint)
    return _reference_navigation_headers(
        identity,
        CHATGPT_LOGIN_PROBE_URL,
        CHATGPT_LOGIN_PROBE_REFERER,
        {"cache-control": "no-cache"},
    )


def probe_chatgpt_login(
    proxy: str,
    *,
    verify: bool = True,
    socks5_dns_mode: str = "declared",
) -> int:
    """Return the login status, stopping on a Cloudflare challenge page."""
    transport_proxy = proxy_transport_value(
        proxy,
        driver="probe",
        socks5_dns_mode=socks5_dns_mode,
    )
    if not transport_proxy:
        raise ValueError("代理格式无效")
    with _without_proxy_environment():
        response = get_via_proxy(
            CHATGPT_LOGIN_PROBE_URL,
            proxy=transport_proxy,
            headers=_reference_probe_headers(),
            timeout=12,
            verify=verify,
            impersonate=REFERENCE_TLS_IMPERSONATE,
            allow_redirects=True,
        )
    status = int(getattr(response, "status_code", 0) or 0)
    if not 100 <= status <= 599:
        raise ValueError("ChatGPT 登录页预检未返回有效 HTTP 状态")
    # Cloudflare can serve a challenge document with HTTP 200.  Treat that as
    # a structured preflight stop so the pool never records a false success;
    # keep the provider status for diagnostics and do not expose the body.
    if _security_challenge_html(response):
        raise FreeRegisterError(
            "free_proxy_preflight",
            "Free 代理预检",
            "ChatGPT 登录页预检返回安全挑战页面",
            provider_status=status,
            retryable=False,
            error_code="free_proxy_chatgpt_security_challenge",
            action_hint="当前代理触发 Cloudflare 安全挑战，请更换代理或人工确认后重试；系统不会自动绕过",
            page_type="security_challenge",
            safe_page=CHATGPT_LOGIN_PROBE_URL,
        )
    return status


__all__ = [
    "CHATGPT_LOGIN_PROBE_REFERER",
    "CHATGPT_LOGIN_PROBE_URL",
    "probe_chatgpt_login",
]
