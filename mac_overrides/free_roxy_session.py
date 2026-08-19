"""Safe ChatGPT Session extraction for the isolated Roxy registration flow."""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

try:
    from .free_register_common import FreeRegisterError, clean
except ImportError:
    from free_register_common import FreeRegisterError, clean  # type: ignore[no-redef]


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


def _summary(driver: Any, *, keys: Any = (), error: str = "", location: str = "") -> str:
    safe_keys = []
    if isinstance(keys, Mapping):
        keys = keys.keys()
    if not isinstance(keys, (str, bytes)):
        safe_keys = sorted(str(key) for key in keys if str(key))[:20]
    suffix = f"，字段 {','.join(safe_keys)}" if safe_keys else "，未读取到 JSON 字段"
    if error:
        suffix += f"，异常 {str(error)[:40]}"
    return f"Session 未返回 access token（页面 {location or _safe_location(driver)}{suffix}）"


def _emit(log_fn: Callable[[str, str], None] | None, message: str, level: str = "info") -> None:
    if not callable(log_fn):
        return
    try:
        log_fn(message, level)
    except Exception:
        pass


def _restore_home(driver: Any) -> None:
    try:
        driver.get(HOME_URL)
    except Exception:
        pass


def _browser_session(driver: Any) -> tuple[dict[str, Any], str]:
    """Read Session with a same-origin browser fetch, like the reference flow.

    Returning only parsed JSON keeps response bodies and cookies out of Python
    logs.  The fallback navigation path below is retained for older Selenium
    bridges that do not expose ``execute_async_script``.
    """
    fetch_script = """
    const done = arguments[arguments.length - 1];
    (async () => {
      try {
        const response = await fetch('/api/auth/session', {
          method: 'GET', credentials: 'include',
          headers: {accept: 'application/json'}, cache: 'no-store',
        });
        const contentType = String(response.headers.get('content-type') || '');
        const text = await response.text();
        let payload = null;
        try { payload = JSON.parse(text); } catch (_) { payload = null; }
        const keys = payload && typeof payload === 'object' && !Array.isArray(payload)
          ? Object.keys(payload).slice(0, 32) : [];
        done({ok: true, status: response.status || 0, content_type: contentType,
          payload, keys, body_length: text.length});
      } catch (error) {
        done({ok: false, error: String(error || 'fetch failed').slice(0, 120)});
      }
    })();
    """
    result = driver.execute_async_script(fetch_script) or {}
    if not isinstance(result, Mapping):
        return {}, "浏览器 Session 请求返回格式无效"
    # Selenium adapters in older Roxy releases used ``data`` instead of
    # ``payload``.  Both are accepted, while the actual response body remains
    # inside the browser process and is never included in a log message.
    payload = result.get("payload", result.get("data"))
    if not isinstance(payload, Mapping):
        payload = {}
    status = int(result.get("status") or 0)
    headers = result.get("headers") if isinstance(result.get("headers"), Mapping) else {}
    content_type = str(result.get("content_type") or headers.get("content-type") or "")[:80]
    if not result.get("ok", True):
        return {}, f"浏览器同源请求异常（{clean(result.get('error') or '未知异常', 120)}）"
    if status != 200:
        return dict(payload), f"HTTP {status or '-'}"
    if "application/json" not in content_type.casefold():
        return dict(payload), f"响应类型 {content_type or '未知'}"
    if int(result.get("body_length") or 0) > MAX_BODY_CHARS:
        return dict(payload), "Session 响应过大"
    return dict(payload), f"HTTP 200，{content_type or 'JSON'}"


def _is_confirmed_home(driver: Any) -> bool:
    """Return true only for a normal ChatGPT document, never an auth/API URL."""
    try:
        current = urlsplit(str(getattr(driver, "current_url", "") or ""))
        return (
            current.scheme.casefold() == "https"
            and (current.hostname or "").casefold() == "chatgpt.com"
            and current.path.rstrip("/") in {"", "/"}
            and not current.query
            and not current.fragment
        )
    except Exception:
        return False


def extract_session(
    driver: Any,
    timeout: int,
    log_fn: Callable[[str, str], None] | None = None,
) -> dict[str, Any]:
    """Confirm the browser session and extract its token without exposing it.

    The preferred path uses a same-origin ``fetch`` while the browser is on
    ChatGPT.  Direct navigation remains a compatibility fallback for old
    Selenium/Roxy versions and for the offline test driver.
    """
    deadline = time.time() + max(5, int(timeout or 120))
    last = ""
    attempt = 0
    _emit(log_fn, "准备读取 ChatGPT Session：保持浏览器 Cookie，不读取或记录响应正文")
    while time.time() < deadline:
        attempt += 1
        payload: Any = None
        started = time.monotonic()
        try:
            current = urlsplit(str(getattr(driver, "current_url", "") or ""))
            if not _is_confirmed_home(driver):
                last = _summary(driver, error="当前页面不是已确认的 ChatGPT 首页")
                _emit(log_fn, f"Session 第 {attempt} 次跳过：{last}", "warn")
                break

            browser_fetch = getattr(driver, "execute_async_script", None)
            if callable(browser_fetch):
                payload, response_summary = _browser_session(driver)
                keys = payload.keys() if isinstance(payload, Mapping) else ()
                token = session_token(payload)
                _emit(log_fn, f"Session 同源请求第 {attempt} 次：{response_summary}，字段={','.join(sorted(str(k) for k in keys)[:20]) or '无'}，Token={'存在' if token else '缺失'}，耗时={int((time.monotonic() - started) * 1000)}ms")
                if token:
                    result = dict(payload)
                    result.setdefault("accessToken", token)
                    _restore_home(driver)
                    _emit(log_fn, "Session Token 提取成功，已恢复 ChatGPT 首页", "success")
                    return result
                last = _summary(driver, keys=keys, error=response_summary, location=_safe_location(driver))
            else:
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
                        _emit(log_fn, f"Session 页面第 {attempt} 次：字段={','.join(sorted(str(k) for k in payload.keys())[:20]) if isinstance(payload, Mapping) else '无'}，Token={'存在' if token else '缺失'}，耗时={int((time.monotonic() - started) * 1000)}ms")
                        if token:
                            result = dict(payload) if isinstance(payload, Mapping) else {}
                            result.setdefault("accessToken", token)
                            _restore_home(driver)
                            _emit(log_fn, "Session Token 提取成功，已恢复 ChatGPT 首页", "success")
                            return result
                        last = _summary(driver, keys=payload.keys() if isinstance(payload, Mapping) else (), error="字段缺少 access token")
        except Exception as exc:
            last = _summary(driver, keys=payload.keys() if isinstance(payload, Mapping) else (), error=type(exc).__name__)
            _emit(log_fn, f"Session 第 {attempt} 次读取失败：{last}", "warn")
        # Do not navigate away from an auth/profile/security page here.  The
        # registration state machine owns those transitions and must surface a
        # missing redirect instead of hiding it behind a forced home visit.
        # The navigation fallback, however, must restore the known home page
        # before its next compatibility attempt; otherwise the next iteration
        # would be rejected before it could read the endpoint body.
        if not callable(getattr(driver, "execute_async_script", None)):
            _restore_home(driver)
        remaining = max(0, deadline - time.time())
        if remaining <= 0:
            break
        time.sleep(min(2, remaining))
    _emit(log_fn, f"Session 在 {max(5, int(timeout or 120))} 秒内未拿到 Token：{last or '登录态未建立'}", "error")
    raise FreeRegisterError("free_access_token", "获取 Free access token", last or "等待 ChatGPT Session 登录态超时", error_code="free_session_token_missing")


__all__ = ["extract_session", "session_token"]
