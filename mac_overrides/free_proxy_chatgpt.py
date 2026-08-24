"""Credential-free ChatGPT login-page probe for Free proxy validation."""

from __future__ import annotations

from contextlib import contextmanager
import os

try:
    from .free_register_common import proxy_transport_value
except ImportError:
    from free_register_common import proxy_transport_value  # type: ignore[no-redef]


CHATGPT_LOGIN_PROBE_URL = "https://chatgpt.com/login"


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


def probe_chatgpt_login(proxy: str, *, verify: bool = True) -> int:
    """Return the ChatGPT login response status through one fixed proxy."""
    from curl_cffi import requests as curl_requests

    transport_proxy = proxy_transport_value(proxy, driver="probe")
    if not transport_proxy:
        raise ValueError("代理格式无效")
    session = curl_requests.Session(impersonate="chrome", verify=bool(verify))
    session.proxies = {"http": transport_proxy, "https": transport_proxy}
    if hasattr(session, "trust_env"):
        session.trust_env = False
    with _without_proxy_environment():
        try:
            response = session.get(
                CHATGPT_LOGIN_PROBE_URL,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Cache-Control": "no-cache",
                    "Referer": "https://chatgpt.com/",
                },
                timeout=12,
                allow_redirects=True,
            )
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()
    status = int(getattr(response, "status_code", 0) or 0)
    if not 100 <= status <= 599:
        raise ValueError("ChatGPT 登录页预检未返回有效 HTTP 状态")
    return status


__all__ = ["CHATGPT_LOGIN_PROBE_URL", "probe_chatgpt_login"]
