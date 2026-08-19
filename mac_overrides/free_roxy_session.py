"""Safe ChatGPT Session extraction for the isolated Roxy registration flow."""

from __future__ import annotations

import json
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from .free_register_common import FreeRegisterError
except ImportError:
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]


SESSION_URL = "https://chatgpt.com/api/auth/session"
HOME_URL = "https://chatgpt.com/"
MAX_BODY_CHARS = 65536
MAX_TOKEN_CHARS = 16384


def session_token(payload: Any) -> str:
    """Read the supported Session JSON token fields without logging values."""
    if not isinstance(payload, Mapping):
        return ""
    for key in ("accessToken", "access_token", "token"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip() and len(value.strip()) <= MAX_TOKEN_CHARS:
            return value.strip()
    for key in ("session", "data", "account"):
        nested = payload.get(key)
        value = session_token(nested)
        if value:
            return value
    return ""


def _safe_location(driver: Any) -> str:
    try:
        parsed = urlsplit(str(getattr(driver, "current_url", "") or ""))
        if parsed.scheme and parsed.hostname:
            return f"{parsed.scheme}://{parsed.hostname}{parsed.path or '/'}"
    except Exception:
        pass
    return "页面地址未知"


def _summary(driver: Any, *, keys: Any = (), error: str = "") -> str:
    safe_keys = []
    if isinstance(keys, Mapping):
        keys = keys.keys()
    if not isinstance(keys, (str, bytes)):
        safe_keys = sorted(str(key) for key in keys if str(key))[:20]
    suffix = f"，字段 {','.join(safe_keys)}" if safe_keys else "，未读取到 JSON 字段"
    if error:
        suffix += f"，异常 {str(error)[:40]}"
    return f"Session 未返回 access token（页面 {_safe_location(driver)}{suffix}）"


def _restore_home(driver: Any) -> None:
    try:
        driver.get(HOME_URL)
    except Exception:
        pass


def extract_session(driver: Any, timeout: int) -> dict[str, Any]:
    """Navigate to the Session endpoint, parse JSON, then restore ChatGPT home."""
    deadline = time.time() + max(5, int(timeout or 120))
    last = ""
    while time.time() < deadline:
        payload: Any = None
        try:
            driver.get(SESSION_URL)
            current = urlsplit(str(getattr(driver, "current_url", "") or ""))
            if (current.hostname or "").casefold() != "chatgpt.com" or current.path.rstrip("/") != "/api/auth/session":
                last = _summary(driver, error="Session 导航地址不可信")
            else:
                body = str(driver.find_element("tag name", "body").text or "")
                if len(body) > MAX_BODY_CHARS:
                    last = _summary(driver, error="Session 响应过大")
                else:
                    payload = json.loads(body)
                    token = session_token(payload)
                    if token:
                        result = dict(payload) if isinstance(payload, Mapping) else {}
                        result.setdefault("accessToken", token)
                        _restore_home(driver)
                        return result
                    last = _summary(driver, keys=payload.keys() if isinstance(payload, Mapping) else (), error="字段缺少 access token")
        except Exception as exc:
            last = _summary(driver, keys=payload.keys() if isinstance(payload, Mapping) else (), error=type(exc).__name__)
        _restore_home(driver)
        time.sleep(min(1, max(0, deadline - time.time())))
    raise FreeRegisterError("free_access_token", "获取 Free access token", last or "等待 ChatGPT Session 登录态超时")


__all__ = ["extract_session", "session_token"]
