"""Reference-style protocol preflight and session warmup helpers.

The recovered OAuth transport remains the owner of request headers, Sentinel
flows and PKCE state.  This module only prepares the same network/session
shape observed in AutoRegister before the mailbox is consumed.
"""

from __future__ import annotations

import time
from html import unescape
import re
from types import MethodType
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from .free_register_common import FreeRegisterError, proxy_error_code, safe_log_message
except ImportError:  # pragma: no cover
    from free_register_common import FreeRegisterError, proxy_error_code, safe_log_message  # type: ignore[no-redef]


LogFn = Callable[..., Any] | None
REFERENCE_SENTINEL_VERSION = "20260219f9f6"
_CF_COOKIE_NAMES = frozenset({"cf_clearance", "__cf_bm", "__cfseq", "cf_chl_rc_i", "cf_chl_rc_ni", "cf_chl_rc_m"})
_PREFLIGHT = (
    ("chatgpt-login", "https://chatgpt.com/login", "https://chatgpt.com/"),
    ("auth-login", "https://auth.openai.com/log-in", "https://chatgpt.com/login"),
    ("sentinel-frame", "https://sentinel.openai.com/backend-api/sentinel/frame.html", "https://auth.openai.com/log-in"),
)
_WARMUP_GETS = (
    ("anon-check", "https://chatgpt.com/backend-anon/accounts/check/v4-2023-04-27"),
    ("anon-me", "https://chatgpt.com/backend-anon/me"),
    ("anon-models", "https://chatgpt.com/backend-anon/models?iim=false&is_gizmo=false&supports_model_picker_upgrade_presets=true"),
)
_AUTH_WARMUP_GETS = (
    ("auth-me", "https://chatgpt.com/backend-api/me"),
    ("auth-settings", "https://chatgpt.com/backend-api/settings/user"),
)
_SECURITY_HTML_MARKERS = (
    "captcha",
    "cloudflare",
    "turnstile",
    "just a moment",
    "verify you are human",
    "checking your browser",
    "cloudflare ray id",
)
_SECURITY_HTML_PATH_MARKERS = (
    "/cdn-cgi/challenge-platform/",
    "cf-chl-",
    "cf-turnstile",
)
SECURITY_CHALLENGE_WAIT_SECONDS = 60.0
SECURITY_CHALLENGE_POLL_SECONDS = 2.0

# Keep the navigation shape in lockstep with AutoRegister's BrowserSession.
# The recovered transport's PAGE_HEADERS describe an older Windows Chrome
# profile and omit the document-navigation fields that Auth expects.  Free
# owns its transport, so it is safe to derive these fields from the task's
# stable reference fingerprint here without changing ordinary SMS/OAuth.
_REFERENCE_NAV_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.7"
)
_REFERENCE_DOMAINS = ("chatgpt.com", "auth.openai.com", "sentinel.openai.com")


def _reference_fingerprint(transport: Any) -> Mapping[str, Any]:
    value = getattr(transport, "_gptphone_reference_fingerprint", None)
    if isinstance(value, Mapping):
        return value
    provider = getattr(transport, "sentinel_provider", None)
    value = getattr(provider, "fingerprint", None)
    return value if isinstance(value, Mapping) else {}


def _host(value: Any) -> str:
    try:
        return str(urlsplit(str(value or "")).hostname or "").casefold()
    except Exception:
        return ""


def _normalized_headers(base: Mapping[str, Any] | None) -> dict[str, str]:
    """Return one lowercase entry for each case-insensitive header name."""
    headers: dict[str, str] = {}
    for key, value in (base or {}).items():
        name = str(key or "").strip().casefold()
        if name and value not in (None, ""):
            headers[name] = str(value)
    return headers


def _header_value(base: Mapping[str, Any] | None, name: str) -> str:
    target = str(name or "").casefold()
    for key, value in (base or {}).items():
        if str(key or "").strip().casefold() == target:
            return str(value or "")
    return ""


def _apply_reference_identity_headers(headers: dict[str, str], profile: Mapping[str, Any]) -> None:
    for key, profile_key in (
        ("user-agent", "user_agent"),
        ("accept-language", "accept_language"),
    ):
        value = profile.get(profile_key)
        if value not in (None, ""):
            headers[key] = str(value)
    if bool(profile.get("send_client_hints", True)):
        for key, profile_key in (
            ("sec-ch-ua", "sec_ch_ua"),
            ("sec-ch-ua-mobile", "sec_ch_ua_mobile"),
            ("sec-ch-ua-platform", "sec_ch_ua_platform"),
            ("sec-ch-ua-full-version-list", "sec_ch_ua_full_version_list"),
            ("sec-ch-ua-platform-version", "sec_ch_ua_platform_version"),
            ("sec-ch-ua-arch", "sec_ch_ua_arch"),
            ("sec-ch-ua-bitness", "sec_ch_ua_bitness"),
            ("sec-ch-ua-model", "sec_ch_ua_model"),
        ):
            value = profile.get(profile_key)
            if value not in (None, ""):
                headers[key] = str(value)
    for key, profile_key in (
        ("x-datadog-origin", "datadog_origin"),
        ("x-datadog-sampling-priority", "datadog_sampling_priority"),
        ("x-datadog-trace-id", "datadog_trace_id"),
        ("x-datadog-parent-id", "datadog_parent_id"),
        ("traceparent", "traceparent"),
        ("tracestate", "tracestate"),
    ):
        value = profile.get(profile_key)
        if value not in (None, ""):
            headers[key] = str(value)


def _reference_navigation_headers(
    transport: Any,
    url: str,
    referer: str,
    base: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Build browser-like document headers while preserving caller values."""
    headers = _normalized_headers(base)
    profile = _reference_fingerprint(transport)
    _apply_reference_identity_headers(headers, profile)

    target_host = _host(url)
    ref_host = _host(referer)
    if target_host and ref_host:
        headers["sec-fetch-site"] = "same-origin" if target_host == ref_host else "cross-site"
    elif target_host:
        headers["sec-fetch-site"] = "cross-site"
    headers.update({
        "accept": _REFERENCE_NAV_ACCEPT,
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
        "priority": "u=0, i",
        "upgrade-insecure-requests": "1",
        "sec-fetch-user": "?1",
    })
    if referer:
        headers["referer"] = str(referer)
    return headers


def _reference_json_headers(transport: Any, base: Mapping[str, Any] | None = None) -> dict[str, str]:
    """Apply the same stable browser locale/client hints to JSON requests."""
    headers = _normalized_headers(base)
    profile = _reference_fingerprint(transport)
    _apply_reference_identity_headers(headers, profile)
    return headers


def _reference_get_headers(transport: Any, url: str, referer: str, base: Mapping[str, Any] | None = None) -> dict[str, str]:
    """Choose navigation or API headers for a wrapped session GET."""
    path = ""
    try:
        path = str(urlsplit(str(url or "")).path or "").casefold()
    except Exception:
        pass
    if _host(url) == "chatgpt.com" and path.startswith(("/backend-api/", "/backend-anon/")):
        headers = _reference_json_headers(transport, base)
        if referer:
            headers["referer"] = str(referer)
        return headers
    return _reference_navigation_headers(transport, url, referer, base)


def prepare_reference_session(transport: Any, fingerprint: Mapping[str, Any] | None = None) -> Any:
    """Apply AutoRegister's session identity and header policy to Free.

    This is intentionally idempotent: a rebuilt OAuth session calls it again,
    while a test double can omit cookies or private transport methods.
    """
    if fingerprint is not None and isinstance(fingerprint, Mapping):
        setattr(transport, "_gptphone_reference_fingerprint", dict(fingerprint))
    session = getattr(transport, "session", None)
    if session is None:
        return transport
    try:
        session.trust_env = False
    except Exception:
        pass
    try:
        session.verify = True
    except Exception:
        pass
    device_id = str(getattr(transport, "device_id", "") or "").strip()
    cookies = getattr(session, "cookies", None)
    setter = getattr(cookies, "set", None)
    if device_id and callable(setter):
        for domain in _REFERENCE_DOMAINS:
            try:
                setter("oai-did", device_id, domain=domain, path="/")
            except TypeError:
                try:
                    setter("oai-did", device_id)
                except Exception:
                    pass
            except Exception:
                pass

    # The recovered POST methods call ``self._headers`` directly.  Wrap that
    # bound method once so Sentinel JSON requests use the same UA/locale as the
    # page preflight and Node fingerprint.  Ordinary transports never receive
    # this marker and remain untouched.
    if not getattr(transport, "_gptphone_reference_headers_wrapped", False):
        original_headers = getattr(transport, "_headers", None)
        if callable(original_headers):
            def wrapped_headers(_self: Any, flow: str, referer: str) -> dict[str, str]:
                return _reference_json_headers(_self, original_headers(flow, referer))
            try:
                transport._headers = MethodType(wrapped_headers, transport)
                setattr(transport, "_gptphone_reference_headers_wrapped", True)
            except Exception:
                pass
    if not getattr(session, "_gptphone_reference_get_wrapped", False):
        original_get = getattr(session, "get", None)
        if callable(original_get):
            def wrapped_get(url: str, *args: Any, **kwargs: Any) -> Any:
                target_host = _host(url)
                if target_host in _REFERENCE_DOMAINS:
                    supplied = kwargs.get("headers")
                    referer = _header_value(supplied, "referer") if isinstance(supplied, Mapping) else ""
                    if not referer and target_host == "auth.openai.com":
                        # The recovered initiate_oauth GET omits Referer;
                        # BrowserSession follows the OAuth link from ChatGPT.
                        referer = "https://chatgpt.com/"
                    kwargs["headers"] = _reference_get_headers(
                        transport,
                        url,
                        referer,
                        supplied if isinstance(supplied, Mapping) else None,
                    )
                return original_get(url, *args, **kwargs)
            try:
                session.get = wrapped_get
                setattr(session, "_gptphone_reference_get_wrapped", True)
            except Exception:
                pass
    return transport


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
    base: Mapping[str, Any] = {}
    if callable(maker):
        try:
            value = maker(url, referer)
            if isinstance(value, Mapping):
                base = value
        except Exception:
            pass
    if base:
        return _reference_navigation_headers(transport, url, referer, base)
    return _reference_navigation_headers(
        transport,
        url,
        referer or url,
        {"user-agent": "Mozilla/5.0"},
    )


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


def _transport_context(transport: Any, url: str, exc: BaseException | None = None) -> dict[str, Any]:
    """Return a bounded, credential-free transport diagnostic context."""
    proxy = str(getattr(transport, "proxy", "") or "").strip()
    try:
        proxy_scheme = str(urlsplit(proxy).scheme or "").lower()
    except (TypeError, ValueError):
        proxy_scheme = ""
    try:
        target_domain = str(urlsplit(url).hostname or "").lower()
    except (TypeError, ValueError):
        target_domain = ""
    context: dict[str, Any] = {
        "declared_scheme": proxy_scheme,
        "transport_scheme": proxy_scheme,
        "target_domain": target_domain,
    }
    if exc is not None:
        code = proxy_error_code(exc)
        text = str(exc).lower()
        # A TLS exception from the OpenAI target without proxy evidence is a
        # target/session failure, not proof that the proxy itself failed.
        if code.startswith("proxy_") and not any(
            marker in text for marker in ("proxy", "socks", "connect", "407", "curl:")
        ) and any(marker in text for marker in ("tls", "ssl", "handshake", "certificate")):
            code = "tls_connection_failed"
        context["transport_error_code"] = code
    return context


def _http_success(status: int) -> bool:
    return 200 <= int(status) < 400


def _sentinel_frame_url(version: str) -> str:
    base = _PREFLIGHT[-1][1]
    parsed = urlsplit(base)
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key.casefold() != "sv"]
    query.append(("sv", str(version or REFERENCE_SENTINEL_VERSION).strip() or REFERENCE_SENTINEL_VERSION))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


def _anonymous_warmup_gets(transport: Any) -> tuple[tuple[str, str], ...]:
    profile = _reference_fingerprint(transport)
    raw_offset = profile.get("timezone_offset_minutes")
    if raw_offset is None:
        raw_offset = getattr(transport, "_gptphone_timezone_offset_minutes", 0)
    try:
        js_offset = -int(raw_offset or 0)
    except (TypeError, ValueError):
        js_offset = 0
    urls = list(_WARMUP_GETS)
    urls[0] = (urls[0][0], f"{urls[0][1]}?timezone_offset_min={js_offset}")
    return tuple(urls)


def _content_type(response: Any) -> str:
    headers = getattr(response, "headers", None)
    if isinstance(headers, Mapping):
        for key, value in headers.items():
            if str(key).strip().lower() == "content-type":
                return str(value or "").split(";", 1)[0].strip().lower()[:120]
    return ""


def _provider_code(response: Any) -> str:
    """Extract only a short provider error identifier, never response text."""
    try:
        payload = response.json()
    except Exception:
        return ""
    if not isinstance(payload, Mapping):
        return ""
    candidates: list[Mapping[str, Any]] = [payload]
    error = payload.get("error")
    if isinstance(error, Mapping):
        candidates.insert(0, error)
    for candidate in candidates:
        for key in ("error_code", "code", "type", "reason"):
            value = safe_log_message(candidate.get(key))[:120]
            if value:
                return value
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
    bounded = body[:32768]
    lowered = bounded.lower()
    # Challenge URLs and Turnstile identifiers are explicit transport signals;
    # inspect them in the raw document so a script src still counts.
    if any(marker in lowered for marker in _SECURITY_HTML_PATH_MARKERS):
        return True
    # Normal OpenAI bundles may mention the generic challenge-platform script
    # name. Only classify text a user can see, after removing script/style
    # blocks and markup, to avoid a false Cloudflare stop on a normal login
    # document.
    visible = re.sub(r"(?is)<(script|style|noscript)\b[^>]*>.*?</\1>", " ", bounded)
    visible = re.sub(r"(?is)<[^>]+>", " ", visible)
    visible = re.sub(r"\s+", " ", unescape(visible)).casefold()
    return bool(visible) and any(marker in visible for marker in _SECURITY_HTML_MARKERS)


def _wait_for_security_challenge(
    session: Any,
    transport: Any,
    response: Any,
    url: str,
    referer: str,
    *,
    timeout: float,
    wait_seconds: float,
    log: LogFn,
    label: str,
    attempt: int,
    stop_requested: Callable[[], bool] | None,
) -> Any:
    """Poll the same session/proxy while a challenge may clear naturally.

    This is deliberately a bounded wait only.  It never changes cookies,
    headers, proxy, fingerprint or page content and never submits a challenge
    token.  The final response is classified by the caller so an unresolved
    challenge keeps its stable security node.
    """
    budget = max(0.0, min(float(wait_seconds or 0.0), SECURITY_CHALLENGE_WAIT_SECONDS))
    if budget <= 0:
        return response
    deadline = time.monotonic() + budget
    poll_seconds = max(0.1, min(float(SECURITY_CHALLENGE_POLL_SECONDS), budget))
    _emit(
        log,
        f"[协议预热/{label}] 检测到安全挑战，保持当前会话和代理等待最多 {int(budget)} 秒",
        "warn",
        node_code="free_oauth_security_challenge",
        node_label="等待 Free OAuth 安全验证",
        http_status=int(getattr(response, "status_code", 0) or 0),
        page_type="security_challenge",
        attempt=attempt,
        outcome="waiting",
        diagnostic="同一 Session/Profile/代理轮询；不执行自动绕过",
    )
    current = response
    while True:
        if stop_requested and stop_requested():
            raise FreeRegisterError(
                "free_run_stop", "停止 Free 注册", "任务在安全挑战等待期间停止", retryable=False,
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return current
        time.sleep(min(poll_seconds, remaining))
        try:
            current = session.get(
                url,
                headers=_headers(transport, url, referer),
                timeout=max(1.0, min(float(timeout), remaining)),
                allow_redirects=True,
            )
        except Exception as exc:
            _emit(
                log,
                f"[协议预热/{label}] 安全挑战等待请求异常：{type(exc).__name__}",
                "warn",
                node_code="free_oauth_security_challenge",
                node_label="等待 Free OAuth 安全验证",
                attempt=attempt,
                outcome="waiting",
                diagnostic="同一会话重试；未记录响应正文",
            )
            continue
        if not _security_challenge_html(current):
            _emit(
                log,
                f"[协议预热/{label}] 安全挑战等待后页面已恢复",
                "info",
                node_code="free_oauth_security_challenge",
                node_label="等待 Free OAuth 安全验证",
                http_status=int(getattr(current, "status_code", 0) or 0),
                page_type="challenge_cleared",
                attempt=attempt,
                outcome="success",
                diagnostic="继续使用同一会话和代理",
            )
            return current


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
    challenge_wait_seconds: float = 0.0,
    stop_requested: Callable[[], bool] | None = None,
) -> Any:
    started = time.monotonic()
    try:
        response = session.get(url, headers=_headers(transport, url, referer), timeout=timeout, allow_redirects=True)
        status = int(getattr(response, "status_code", 0) or 0)
        content_type = _content_type(response)
        provider_code = _provider_code(response)
        # A challenge page can be returned with 403 as well as 200.  Detect it
        # before interpreting the status as a replaceable proxy denial so the
        # Free flow never rotates around or attempts to bypass a security page.
        challenge = _security_challenge_html(response)
        if challenge and strict and challenge_wait_seconds > 0:
            response = _wait_for_security_challenge(
                session,
                transport,
                response,
                url,
                referer,
                timeout=timeout,
                wait_seconds=challenge_wait_seconds,
                log=log,
                label=label,
                attempt=attempt,
                stop_requested=stop_requested,
            )
            status = int(getattr(response, "status_code", 0) or 0)
            content_type = _content_type(response)
            provider_code = _provider_code(response)
            challenge = _security_challenge_html(response)
        success = _http_success(status) and not challenge
        if challenge:
            page_type = "security_challenge"
        elif status in {401, 403}:
            page_type = "access_denied"
        elif status == 429:
            page_type = "rate_limited"
        elif status >= 500:
            page_type = "upstream_error"
        elif not success:
            page_type = "http_error"
        else:
            page_type = ""
        elapsed = int((time.monotonic() - started) * 1000)
        result_label = "安全挑战" if challenge else "完成" if success else "HTTP 失败"
        transport_context = _transport_context(transport, url)
        _emit(
            log,
            f"[协议预热/{label}] {result_label}",
            "info" if success else "warn",
            node_code="free_oauth_security_challenge" if challenge else node_code,
            node_label="等待 Free OAuth 安全验证" if challenge else node_label,
            http_status=status,
            provider_code=provider_code,
            content_type=content_type,
            page_type=page_type,
            duration_ms=elapsed,
            attempt=attempt,
            retry_count=max(0, int(attempt) - 1),
            request_stage=node_code,
            **transport_context,
            outcome="success" if success else "failed",
            diagnostic=(
                f"HTTP {status}; content_type={content_type or '-'}; page_type={page_type or '-'}"
                if not success else ""
            ),
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
            if status in {401, 403}:
                action_hint = "当前出口或 Auth 页面被拒绝，请更换代理后重试"
            elif status == 429:
                action_hint = "当前出口触发频率限制，请降低并发或更换代理后重试"
            elif status >= 500:
                action_hint = "等待上游服务恢复后重试，并保留当前代理诊断"
            else:
                action_hint = "检查当前任务代理的连接、DNS、TLS 和出口可用性后重试"
            failure = FreeRegisterError(
                node_code, node_label,
                f"{label} 预检返回 HTTP {status}", provider_status=status,
                # A normal Auth access denial is a route decision.  Let the
                # task-level healthy-pool policy choose another proxy, but do
                # not hammer the same proxy repeatedly within this preflight.
                retryable=(status == 0 or status in {408, 425, 429} or status >= 500),
                error_code="free_protocol_preflight_http",
                provider_code=provider_code,
                diagnostic=f"{label}: HTTP {status}; content_type={content_type or '-'}; page_type={page_type or '-'}",
                action_hint=action_hint,
                page_type=page_type,
                safe_page=url,
                content_type=content_type,
                declared_scheme=transport_context.get("declared_scheme"),
                transport_scheme=transport_context.get("transport_scheme"),
                target_domain=transport_context.get("target_domain"),
                request_stage=node_code,
                retry_count=max(0, int(attempt) - 1),
            )
            # Access denied before authorize/continue is route-specific and
            # safe to retry with another pool member.  Keep it distinct from
            # proxy health evidence: a risk decision must not quarantine a
            # proxy for later tasks, and OTP/page failures never reach here.
            if status in {401, 403}:
                setattr(failure, "proxy_retryable", True)
            raise failure
        return response
    except FreeRegisterError:
        raise
    except Exception as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        transport_context = _transport_context(transport, url, exc)
        _emit(
            log,
            f"[协议预热/{label}] 请求失败：{type(exc).__name__}",
            "warn",
            node_code=node_code,
            node_label=node_label,
            duration_ms=elapsed,
            attempt=attempt,
            retry_count=max(0, int(attempt) - 1),
            request_stage=node_code,
            outcome="failed",
            diagnostic=safe_log_message(str(exc)),
            **transport_context,
        )
        if strict:
            transport_error = str(transport_context.get("transport_error_code") or "")
            raise FreeRegisterError(
                node_code, node_label,
                f"{label} 预检请求失败：{type(exc).__name__}",
                retryable=_transient(exc),
                error_code=transport_error or "free_protocol_preflight_request_failed",
                action_hint="检查当前任务代理的连接、DNS、TLS 和出口可用性后重试",
                declared_scheme=transport_context.get("declared_scheme"),
                transport_scheme=transport_context.get("transport_scheme"),
                target_domain=transport_context.get("target_domain"),
                request_stage=node_code,
                retry_count=max(0, int(attempt) - 1),
                transport_error_code=transport_error,
            ) from exc
        return None


def network_preflight(transport: Any, config: Mapping[str, Any], log: LogFn = None, stop_requested: Callable[[], bool] | None = None) -> dict[str, Any]:
    """Run ChatGPT/Auth/Sentinel checks before authorize/continue."""
    prepare_reference_session(transport)
    session = _session(transport)
    protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
    timeout = max(5.0, min(60.0, float(protocol.get("network_timeout") or 20)))
    retries = max(1, min(5, int(protocol.get("network_preflight_retries") or 3)))
    try:
        challenge_wait_seconds = float(
            protocol.get("security_challenge_wait_seconds", SECURITY_CHALLENGE_WAIT_SECONDS)
        )
    except (TypeError, ValueError):
        challenge_wait_seconds = SECURITY_CHALLENGE_WAIT_SECONDS
    challenge_wait_seconds = max(0.0, min(SECURITY_CHALLENGE_WAIT_SECONDS, challenge_wait_seconds))
    _emit(log, "[协议网络预检/free_protocol_preflight] 开始", "info", node_code="free_protocol_preflight", node_label="协议网络预检", outcome="started")
    checks = list(_PREFLIGHT)
    sentinel_version = str(protocol.get("sentinel_version") or REFERENCE_SENTINEL_VERSION).strip()
    checks[-1] = (checks[-1][0], _sentinel_frame_url(sentinel_version), checks[-1][2])
    for label, url, referer in checks:
        if stop_requested and stop_requested():
            raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在协议网络预检期间停止", retryable=False)
        last: BaseException | None = None
        for attempt in range(1, retries + 1):
            try:
                response = _request(
                    session,
                    transport,
                    url,
                    referer,
                    timeout=timeout,
                    log=log,
                    label=label,
                    strict=True,
                    attempt=attempt,
                    challenge_wait_seconds=challenge_wait_seconds,
                    stop_requested=stop_requested,
                )
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
    prepare_reference_session(transport)
    protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
    if protocol.get("anonymous_warmup") is False:
        return {"enabled": False, "cloudflare_cookies": _cookie_summary(_session(transport, node_code="free_protocol_warmup", node_label="匿名态 ChatGPT 预热"))}
    session = _session(transport, node_code="free_protocol_warmup", node_label="匿名态 ChatGPT 预热")
    _emit(log, "[匿名预热/free_protocol_warmup] 开始", "info", node_code="free_protocol_warmup", node_label="匿名态 ChatGPT 预热", outcome="started")
    checks: list[dict[str, Any]] = []
    for label, url in _anonymous_warmup_gets(transport):
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
    prepare_reference_session(transport)
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
    prepare_reference_session(transport)
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
            return {}
        data = response.json() if hasattr(response, "json") else {}
        if not isinstance(data, Mapping):
            return {}
        profile = {
            "country": str(data.get("country_code") or data.get("countryCode") or data.get("country") or "").upper()[:2],
            "city": str(data.get("city") or "")[:80],
            "timezone": str((data.get("timezone") or {}).get("id") if isinstance(data.get("timezone"), Mapping) else data.get("timezone") or "")[:100],
        }
        return profile
    except Exception as exc:
        return {}


def prepare_reference_bootstrap(
    transport: Any,
    fingerprint: dict[str, Any],
    config: Mapping[str, Any],
    *,
    task_id: str,
    stage: Callable[[str, str], None],
    stop_requested: Callable[[], bool] | None,
    log: LogFn,
    geo_profile: Callable[..., Mapping[str, Any]],
    preflight: Callable[..., Mapping[str, Any]],
    warmup: Callable[..., Mapping[str, Any]],
    apply_geo: Callable[[dict[str, Any], Mapping[str, Any]], Any],
    mark_prepared: Callable[[Any], Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Run the reference bootstrap in the same order as AutoRegister.

    Keeping this lifecycle here prevents the already-large protocol manager
    from accumulating another orchestration branch.  Callbacks keep the
    helper independent from the manager's task/log implementations.
    """
    prepare_reference_session(transport, fingerprint)
    geo_value = geo_profile(transport, config, log=log)
    geo = dict(geo_value) if isinstance(geo_value, Mapping) else {}
    apply_geo(fingerprint, geo)
    setattr(transport, "_gptphone_reference_fingerprint", dict(fingerprint))
    prepare_reference_session(transport, fingerprint)
    provider_fingerprint = getattr(getattr(transport, "sentinel_provider", None), "fingerprint", None)
    if isinstance(provider_fingerprint, dict) and provider_fingerprint is not fingerprint:
        provider_fingerprint.update(fingerprint)
    stage(task_id, "free_protocol_preflight")
    preflight_value = preflight(
        transport,
        config,
        log=log,
        stop_requested=stop_requested,
    )
    warmup_value = warmup(transport, config, log=log)
    mark_prepared(transport)
    return (
        dict(preflight_value) if isinstance(preflight_value, Mapping) else {},
        geo,
        dict(warmup_value) if isinstance(warmup_value, Mapping) else {},
    )
__all__ = [
    "REFERENCE_SENTINEL_VERSION",
    "SECURITY_CHALLENGE_WAIT_SECONDS",
    "anonymous_warmup",
    "authenticated_warmup",
    "exit_geo_profile",
    "network_preflight",
    "prepare_reference_session",
    "prepare_reference_bootstrap",
]
