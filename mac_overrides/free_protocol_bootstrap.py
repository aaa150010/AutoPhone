"""Reference-style protocol preflight and session warmup helpers.

The recovered OAuth transport remains the owner of request headers, Sentinel
flows and PKCE state.  This module only prepares the same network/session
shape observed in AutoRegister before the mailbox is consumed.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

try:
    from .free_register_common import FreeRegisterError, safe_log_message
except ImportError:  # pragma: no cover
    from free_register_common import FreeRegisterError, safe_log_message  # type: ignore[no-redef]


LogFn = Callable[..., Any] | None
_CF_COOKIE_NAMES = frozenset({"cf_clearance", "__cf_bm", "__cfseq", "cf_chl_rc_i", "cf_chl_rc_ni", "cf_chl_rc_m"})
_PREFLIGHT = (
    ("chatgpt-login", "https://chatgpt.com/login", "https://chatgpt.com/"),
    ("auth-login", "https://auth.openai.com/log-in", "https://chatgpt.com/login"),
    ("sentinel-frame", "https://sentinel.openai.com/backend-api/sentinel/frame.html", "https://auth.openai.com/log-in"),
)
_WARMUP_GETS = (
    ("anon-check", "https://chatgpt.com/backend-anon/accounts/check/v4-2023-04-27?timezone_offset_min=0"),
    ("anon-me", "https://chatgpt.com/backend-anon/me"),
    ("anon-models", "https://chatgpt.com/backend-anon/models?iim=false&is_gizmo=false&supports_model_picker_upgrade_presets=true"),
)
_AUTH_WARMUP_GETS = (
    ("auth-me", "https://chatgpt.com/backend-api/me"),
    ("auth-settings", "https://chatgpt.com/backend-api/settings/user"),
)
_SECURITY_HTML_MARKERS = (
    "just a moment",
    "cf-chl-",
    "/cdn-cgi/challenge-platform/",
    "challenge-platform",
    "verify you are human",
    "checking your browser",
    "cloudflare ray id",
    "cf-turnstile",
)


def _emit(log: LogFn, message: str, level: str = "info", **fields: Any) -> None:
    if not callable(log):
        return
    try:
        log(message, level, **fields)
    except TypeError:
        try:
            log(message, level)
        except Exception:
            pass
    except Exception:
        pass


def _headers(transport: Any, url: str, referer: str = "") -> dict[str, str]:
    maker = getattr(transport, "_headers_for_url", None)
    if callable(maker):
        try:
            value = maker(url, referer)
            if isinstance(value, Mapping):
                return {str(k): str(v) for k, v in value.items() if v not in (None, "")}
        except Exception:
            pass
    return {
        "accept": "*/*",
        "user-agent": "Mozilla/5.0",
        "referer": referer or url,
    }


def _session(
    transport: Any,
    *,
    node_code: str = "free_protocol_preflight",
    node_label: str = "协议网络预检",
) -> Any:
    session = getattr(transport, "session", None)
    if session is None:
        raise FreeRegisterError(
            node_code, node_label,
            f"OAuth HTTP 会话不可用，无法执行{node_label}",
            retryable=False, error_code=f"{node_code}_session_missing",
        )
    # curl-cffi and requests both honor trust_env. Free must never inherit a
    # stale HTTP(S)_PROXY/ALL_PROXY value from the desktop process.
    try:
        session.trust_env = False
    except Exception:
        pass
    return session


def _cookie_summary(session: Any) -> dict[str, int]:
    result: dict[str, int] = {}
    try:
        jar = getattr(getattr(session, "cookies", None), "jar", None)
        for cookie in jar or []:
            name = str(getattr(cookie, "name", "") or "")
            if name in _CF_COOKIE_NAMES:
                result[f"{getattr(cookie, 'domain', '')}:{name}"] = len(str(getattr(cookie, "value", "") or ""))
    except Exception:
        return {}
    return result


def _transient(exc: BaseException) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return any(marker in text for marker in ("timeout", "timed out", "connection", "proxy", "tls", "ssl", "reset", "curl:"))


def _http_success(status: int) -> bool:
    return 200 <= int(status) < 400


def _content_type(response: Any) -> str:
    headers = getattr(response, "headers", None)
    if isinstance(headers, Mapping):
        for key, value in headers.items():
            if str(key).strip().lower() == "content-type":
                return str(value or "").split(";", 1)[0].strip().lower()[:120]
    return ""


def _security_challenge_html(response: Any) -> bool:
    content_type = _content_type(response)
    if content_type and "html" not in content_type:
        return False
    body = getattr(response, "text", None)
    if not isinstance(body, str):
        raw = getattr(response, "content", b"")
        if isinstance(raw, (bytes, bytearray, memoryview)):
            body = bytes(raw[:32768]).decode("utf-8", "ignore")
        else:
            body = str(raw or "")[:32768]
    lowered = body[:32768].lower()
    return bool(lowered) and any(marker in lowered for marker in _SECURITY_HTML_MARKERS)


def _request(
    session: Any,
    transport: Any,
    url: str,
    referer: str,
    *,
    timeout: float,
    log: LogFn,
    label: str,
    strict: bool,
    attempt: int = 1,
    node_code: str = "free_protocol_preflight",
    node_label: str = "协议网络预检",
) -> Any:
    started = time.monotonic()
    try:
        response = session.get(url, headers=_headers(transport, url, referer), timeout=timeout, allow_redirects=True)
        status = int(getattr(response, "status_code", 0) or 0)
        content_type = _content_type(response)
        challenge = _http_success(status) and _security_challenge_html(response)
        elapsed = int((time.monotonic() - started) * 1000)
        success = _http_success(status) and not challenge
        result_label = "安全挑战" if challenge else "完成" if success else "HTTP 失败"
        _emit(
            log,
            f"[协议预热/{label}] {result_label}",
            "info" if success else "warn",
            node_code="free_oauth_security_challenge" if challenge else node_code,
            node_label="等待 Free OAuth 安全验证" if challenge else node_label,
            http_status=status,
            content_type=content_type,
            page_type="security_challenge" if challenge else "",
            duration_ms=elapsed,
            attempt=attempt,
            outcome="success" if success else "failed",
        )
        if challenge:
            if strict:
                raise FreeRegisterError(
                    "free_oauth_security_challenge",
                    "等待 Free OAuth 安全验证",
                    f"{label} 预检返回安全挑战页面",
                    provider_status=status,
                    retryable=False,
                    error_code="free_oauth_security_challenge",
                    action_hint="在当前代理和 Profile 中人工确认安全状态后重新运行；系统不会自动绕过挑战",
                    page_type="security_challenge",
                    safe_page=url,
                    content_type=content_type,
                )
            return None
        if strict and not success:
            raise FreeRegisterError(
                node_code, node_label,
                f"{label} 预检返回 HTTP {status}", provider_status=status,
                retryable=status == 0 or status in {408, 425, 429} or status >= 500,
                error_code="free_protocol_preflight_http",
                action_hint="检查当前任务代理的连接、DNS、TLS 和出口可用性后重试",
            )
        return response
    except FreeRegisterError:
        raise
    except Exception as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        _emit(log, f"[协议预热/{label}] 请求失败：{type(exc).__name__}", "warn", node_code=node_code, node_label=node_label, duration_ms=elapsed, attempt=attempt, outcome="failed", diagnostic=safe_log_message(str(exc)))
        if strict:
            raise FreeRegisterError(
                node_code, node_label,
                f"{label} 预检请求失败：{type(exc).__name__}",
                retryable=_transient(exc),
                error_code="free_protocol_preflight_request_failed",
                action_hint="检查当前任务代理的连接、DNS、TLS 和出口可用性后重试",
            ) from exc
        return None


def network_preflight(transport: Any, config: Mapping[str, Any], log: LogFn = None, stop_requested: Callable[[], bool] | None = None) -> dict[str, Any]:
    """Run ChatGPT/Auth/Sentinel checks before authorize/continue."""
    session = _session(transport)
    protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
    timeout = max(5.0, min(60.0, float(protocol.get("network_timeout") or 20)))
    retries = max(1, min(5, int(protocol.get("network_preflight_retries") or 3)))
    _emit(log, "[协议网络预检/free_protocol_preflight] 开始", "info", node_code="free_protocol_preflight", node_label="协议网络预检", outcome="started")
    checks = list(_PREFLIGHT)
    sentinel_version = str(protocol.get("sentinel_version") or "").strip()
    if sentinel_version:
        checks[-1] = (checks[-1][0], f"{checks[-1][1]}?sv={sentinel_version}", checks[-1][2])
    for label, url, referer in checks:
        if stop_requested and stop_requested():
            raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在协议网络预检期间停止", retryable=False)
        last: BaseException | None = None
        for attempt in range(1, retries + 1):
            try:
                response = _request(session, transport, url, referer, timeout=timeout, log=log, label=label, strict=True, attempt=attempt)
                if response is not None:
                    break
            except FreeRegisterError as exc:
                last = exc
                if attempt >= retries or not getattr(exc, "retryable", True):
                    raise
                time.sleep(min(2.0 ** (attempt - 1), 4.0))
        else:
            if last:
                raise last
    cookie_summary = _cookie_summary(session)
    _emit(
        log,
        "[协议网络预检/free_protocol_preflight] 完成",
        "success",
        node_code="free_protocol_preflight",
        node_label="协议网络预检",
        outcome="success",
        diagnostic=f"三段预检通过，Cloudflare Cookie 摘要 {len(cookie_summary)} 项",
    )
    return {"checks": [item[0] for item in checks], "cloudflare_cookies": cookie_summary}


def anonymous_warmup(transport: Any, config: Mapping[str, Any], log: LogFn = None) -> dict[str, Any]:
    """Best-effort anonymous ChatGPT bootstrap matching the reference flow."""
    protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
    if protocol.get("anonymous_warmup") is False:
        return {"enabled": False, "cloudflare_cookies": _cookie_summary(_session(transport, node_code="free_protocol_warmup", node_label="匿名态 ChatGPT 预热"))}
    session = _session(transport, node_code="free_protocol_warmup", node_label="匿名态 ChatGPT 预热")
    _emit(log, "[匿名预热/free_protocol_warmup] 开始", "info", node_code="free_protocol_warmup", node_label="匿名态 ChatGPT 预热", outcome="started")
    checks: list[dict[str, Any]] = []
    for label, url in _WARMUP_GETS:
        response = _request(
            session,
            transport,
            url,
            "https://chatgpt.com/",
            timeout=10.0,
            log=log,
            label=label,
            strict=False,
            node_code="free_protocol_warmup",
            node_label="匿名态 ChatGPT 预热",
        )
        status = int(getattr(response, "status_code", 0) or 0) if response is not None else 0
        checks.append({"name": label, "status": status, "ok": _http_success(status)})
    summary = _cookie_summary(session)
    failed = sum(1 for item in checks if not item["ok"])
    _emit(log, "[匿名预热/free_protocol_warmup] 完成" if not failed else "[匿名预热/free_protocol_warmup] 部分请求未通过", "success" if not failed else "warn", node_code="free_protocol_warmup", node_label="匿名态 ChatGPT 预热", outcome="success" if not failed else "partial", diagnostic=f"成功 {len(checks) - failed}/{len(checks)} 项，Cloudflare Cookie 摘要 {len(summary)} 项")
    return {"enabled": True, "checks": checks, "ok": failed == 0, "cloudflare_cookies": summary}


def authenticated_warmup(transport: Any, config: Mapping[str, Any], token: str, log: LogFn = None) -> dict[str, Any]:
    """Best-effort authenticated bootstrap after token exchange."""
    protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
    if protocol.get("authenticated_warmup") is False:
        return {"enabled": False}
    session = _session(transport, node_code="free_authenticated_warmup", node_label="认证态 ChatGPT 预热")
    _emit(log, "[认证预热/free_authenticated_warmup] 开始", "info", node_code="free_authenticated_warmup", node_label="认证态 ChatGPT 预热", outcome="started")
    checks: list[dict[str, Any]] = []
    for label, url in _AUTH_WARMUP_GETS:
        try:
            headers = _headers(transport, url, "https://chatgpt.com/")
            headers["authorization"] = f"Bearer {token}"
            response = session.get(url, headers=headers, timeout=10.0, allow_redirects=True)
            status = int(getattr(response, "status_code", 0) or 0)
            success = _http_success(status)
            checks.append({"name": label, "status": status, "ok": success})
            if not success:
                _emit(
                    log,
                    f"[认证预热/{label}] HTTP {status}，已跳过",
                    "warn",
                    node_code="free_authenticated_warmup",
                    node_label="认证态 ChatGPT 预热",
                    http_status=status,
                    outcome="skipped",
                )
        except Exception as exc:
            checks.append({"name": label, "status": 0, "ok": False})
            _emit(log, f"[认证预热/{label}] 跳过：{type(exc).__name__}", "warn", node_code="free_authenticated_warmup", node_label="认证态 ChatGPT 预热", outcome="skipped", diagnostic=safe_log_message(str(exc)))
    failed = sum(1 for item in checks if not item["ok"])
    _emit(
        log,
        "[认证预热/free_authenticated_warmup] 完成" if not failed else "[认证预热/free_authenticated_warmup] 部分请求未通过",
        "success" if not failed else "warn",
        node_code="free_authenticated_warmup",
        node_label="认证态 ChatGPT 预热",
        outcome="success" if not failed else "partial",
        diagnostic=f"成功 {len(checks) - failed}/{len(checks)} 项",
    )
    return {"enabled": True, "checks": checks, "ok": failed == 0}


def exit_geo_profile(transport: Any, config: Mapping[str, Any], log: LogFn = None) -> dict[str, Any]:
    """Read a redacted country/timezone profile through the task's proxy."""
    protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
    url = str(protocol.get("geo_probe_url") or "").strip()
    parsed = urlsplit(url)
    if not url or parsed.scheme != "https" or not parsed.netloc:
        return {}
    try:
        session = _session(transport, node_code="free_proxy_geo", node_label="出口地区画像")
        response = session.get(url, headers={"accept": "application/json"}, timeout=8.0, allow_redirects=True)
        status = int(getattr(response, "status_code", 0) or 0)
        if not _http_success(status):
            _emit(
                log,
                f"[指纹画像/free_proxy_geo] HTTP {status}，已跳过",
                "warn",
                node_code="free_proxy_geo",
                node_label="出口地区画像",
                http_status=status,
                outcome="skipped",
            )
            return {}
        data = response.json() if hasattr(response, "json") else {}
        if not isinstance(data, Mapping):
            return {}
        profile = {
            "country": str(data.get("country_code") or data.get("countryCode") or data.get("country") or "").upper()[:2],
            "city": str(data.get("city") or "")[:80],
            "timezone": str((data.get("timezone") or {}).get("id") if isinstance(data.get("timezone"), Mapping) else data.get("timezone") or "")[:100],
        }
        _emit(log, "[指纹画像/free_proxy_geo] 出口地区画像已更新", "info", node_code="free_proxy_geo", node_label="出口地区画像", outcome="success", diagnostic=f"country={profile['country'] or '-'} city={profile['city'] or '-'} timezone={profile['timezone'] or '-'}")
        return profile
    except Exception as exc:
        _emit(log, f"[指纹画像/free_proxy_geo] 跳过：{type(exc).__name__}", "warn", node_code="free_proxy_geo", node_label="出口地区画像", outcome="skipped", diagnostic=safe_log_message(str(exc)))
        return {}


__all__ = ["anonymous_warmup", "authenticated_warmup", "exit_geo_profile", "network_preflight"]
