"""Response parsing and observation helpers for the Free protocol driver.

Split out of ``free_protocol_runtime.py``; the original module re-exports
every name for compatibility.
"""

from __future__ import annotations

import inspect
import re
from typing import Any, Mapping
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

DEFAULT_AUTH_IMPERSONATES = (
    "chrome",
    "chrome136",
    "chrome133a",
    "safari15_3",
    "safari17_0",
)

CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL = (
    "https://chatgpt.com/backend-api/accounts/add_password/eligibility"
)

try:
    from .free_failure_runtime import sanitize_safe_page as _sanitize_safe_page
    from .free_register_common import FreeRegisterError, safe_log_message as _safe_log_message
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_failure_runtime import sanitize_safe_page as _sanitize_safe_page  # type: ignore[no-redef]
    from free_register_common import FreeRegisterError, safe_log_message as _safe_log_message  # type: ignore[no-redef]


def _response_status(response: Any) -> int | None:
    raw = getattr(response, "status_code", None)
    if isinstance(response, Mapping):
        raw = response.get("_status") if "_status" in response else response.get("status_code")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _response_content_type(response: Any) -> str:
    """Return only the media type from a response-like value."""
    raw: Any = ""
    if isinstance(response, Mapping):
        raw = response.get("_content_type") or response.get("content_type") or ""
        if not raw:
            headers = response.get("headers") or response.get("_headers")
            if isinstance(headers, Mapping):
                raw = headers.get("content-type") or headers.get("Content-Type") or ""
    else:
        headers = getattr(response, "headers", None)
        if isinstance(headers, Mapping):
            raw = headers.get("content-type") or headers.get("Content-Type") or ""
        raw = raw or getattr(response, "content_type", "") or ""
    media_type = str(raw or "").split(";", 1)[0].strip().lower()
    if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type):
        return ""
    return media_type[:80]


def _response_location_parts(response: Any) -> tuple[str, str]:
    """Extract a response's final host/path without retaining its query."""
    candidates: list[Any] = []
    if isinstance(response, Mapping):
        for key in ("_location", "_url", "location", "url"):
            value = response.get(key)
            if value:
                candidates.append(value)
    else:
        value = getattr(response, "url", "")
        if value:
            candidates.append(value)
    for candidate in candidates:
        try:
            parsed = urlsplit(str(candidate or ""))
            host = str(parsed.hostname or "").strip().lower()
            path = str(parsed.path or "/")
            if host and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?", host):
                # Route paths are useful when diagnosing an auth redirect, but
                # a hostile upstream can put a one-off token/OTP in the path.
                # Reuse the shared page sanitizer so trusted OpenAI routes stay
                # visible while untrusted hosts and sensitive path segments are
                # reduced to a bounded placeholder.  The query/fragment are
                # already excluded by taking ``parsed.path`` above.
                safe_page = _sanitize_safe_page(f"https://{host}{path}")
                if safe_page.startswith(("http://", "https://")):
                    safe_path = str(urlsplit(safe_page).path or "/")
                    safe_segments: list[str] = []
                    for segment in safe_path.split("/"):
                        if not segment:
                            continue
                        decoded = unquote(segment)
                        # Keep ordinary route names, but hide dynamic path
                        # values that commonly carry a token, code or state.
                        # This is a second defense after query removal because
                        # an upstream can place credentials directly in a URL
                        # path (for example ``/callback/<token>``).
                        sensitive_segment = bool(re.search(
                            r"(?i)(?:^|[^a-z0-9])(?:token|secret|password|passwd|code|state|nonce|otp|verifier|key|credential)(?:$|[^a-z0-9])",
                            decoded,
                        ))
                        high_entropy_segment = (
                            len(decoded) >= 20
                            and bool(re.fullmatch(r"[A-Za-z0-9._~-]+", decoded))
                        )
                        if (
                            sensitive_segment
                            or high_entropy_segment
                            or bool(re.fullmatch(r"\d{6,}", decoded))
                            or "@" in decoded
                        ):
                            safe_segments.append("[值已隐藏]")
                        else:
                            cleaned = re.sub(r"[^A-Za-z0-9._~-]", "_", decoded)[:80]
                            safe_segments.append(cleaned or "[值已隐藏]")
                    safe_path = "/" + "/".join(safe_segments)
                else:
                    safe_path = "/[路径已隐藏]"
                return host, safe_path[:240]
        except (TypeError, ValueError):
            continue
    return "", ""


def _emit_twofa_reauth_observation(
    transport: Any,
    task_id: str,
    message: str,
    *,
    response: Any = None,
    request_stage: str = "",
    include_location: bool = False,
    transport_fields: Mapping[str, Any] | None = None,
    outcome: str = "info",
) -> None:
    """Write a credential-free observation for one 2FA re-auth request."""
    logger = getattr(transport, "log_fn", None)
    if not callable(logger):
        return
    # Project optional caller metadata before invoking any logger. The built-in
    # DiagnosticStore applies the same policy again, but third-party callbacks
    # must never receive an unfiltered URL, proxy or credential-bearing field.
    details: dict[str, Any] = {}
    if isinstance(transport_fields, Mapping):
        authorize_url_present = transport_fields.get("authorize_url_present")
        if isinstance(authorize_url_present, bool):
            details["authorize_url_present"] = authorize_url_present
    safe_request_stage = str(request_stage or "").strip().lower()
    if re.fullmatch(r"reauth_[a-z0-9_]{1,48}", safe_request_stage):
        details["request_stage"] = safe_request_stage
    status = _response_status(response)
    content_type = _response_content_type(response)
    if status is not None:
        details.setdefault("http_status", status)
    if content_type:
        details.setdefault("content_type", content_type)
    if include_location:
        host, path = _response_location_parts(response)
        if host:
            details.setdefault("final_host", host)
        if path:
            details.setdefault("final_path", path)
    rendered_parts = [str(message or "").strip()]
    if status is not None and "HTTP " not in rendered_parts[0]:
        rendered_parts.append(f"HTTP {status}")
    if content_type and "Content-Type" not in rendered_parts[0]:
        rendered_parts.append(f"Content-Type {content_type}")
    if include_location:
        host, path = _response_location_parts(response)
        if host and path:
            rendered_parts.append(f"落点 {host}{path}")
    rendered = "；".join(part for part in rendered_parts if part)
    fields: dict[str, Any] = {
        "task_id": task_id,
        "node_code": "free_twofa_reauth",
        "node_label": "Free 2FA 重认证诊断",
        "outcome": outcome,
    }
    if safe_request_stage:
        fields["request_stage"] = safe_request_stage
    if details:
        fields["transport"] = details
    try:
        logger(
            f"[{task_id}/Free 2FA 重认证诊断/free_twofa_reauth] {rendered}",
            "warn" if outcome in {"warn", "skipped"} else "info",
            **fields,
        )
    except TypeError:
        # Older callbacks accept only the historic two positional arguments.
        try:
            logger(
                f"[{task_id}/Free 2FA 重认证诊断/free_twofa_reauth] {rendered}",
                "warn" if outcome in {"warn", "skipped"} else "info",
            )
        except Exception:
            # Log delivery must never break the request it describes.
            pass
    except Exception:
        # Log delivery must never break the request it describes.
        pass


def _response_provider_code(response: Any, data: Any = None) -> str:
    for source in (data, response):
        if not isinstance(source, Mapping):
            continue
        error = source.get("error")
        candidates = (error, source) if isinstance(error, Mapping) else (source,)
        for candidate in candidates:
            for key in ("error_code", "code", "type", "reason"):
                value = str(candidate.get(key) or "").strip()
                if value:
                    return _safe_log_message(value)[:120]
    return ""


def _response_continue_url(response: Any) -> str:
    """Extract a continuation without letting a nested page URL win.

    Auth envelopes may contain both the current page URL (for example
    ``page.url=/email-verification``) and the actual next step in a
    top-level or nested ``continue_url``.  The Camoufox/shared account
    service treats the explicit continuation fields as authoritative and
    only falls back to a generic ``url`` after walking the whole envelope.
    Keep protocol on that same contract so password and OAuth callback
    responses cannot be misrouted by a page URL.
    """
    if not isinstance(response, Mapping):
        return ""
    queue: list[Mapping[str, Any]] = [response]
    seen: set[int] = set()
    generic_urls: list[str] = []
    strong_keys = (
        "continue_url",
        "external_url",
        "redirect_url",
        "next_url",
        "location",
        "_location",
    )
    while queue and len(seen) < 32:
        source = queue.pop(0)
        identity = id(source)
        if identity in seen:
            continue
        seen.add(identity)
        for key in strong_keys:
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        value = source.get("url")
        if isinstance(value, str) and value.strip():
            generic_urls.append(value.strip())
        for value in source.values():
            if isinstance(value, Mapping):
                queue.append(value)
            elif isinstance(value, (list, tuple)):
                queue.extend(item for item in value if isinstance(item, Mapping))
    return generic_urls[0] if generic_urls else ""


def _explicit_false(value: Any) -> bool:
    return value is False or (
        isinstance(value, str)
        and value.strip().casefold() in {"false", "0", "no", "failed", "failure", "error"}
    )


def _config_bool(value: Any, default: bool = False) -> bool:
    """Parse persisted/direct-call booleans without treating ``"false"`` as true."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _plan_failure(exc: FreeRegisterError) -> dict[str, Any]:
    cause = _safe_log_message(exc) or "服务端未返回错误详情"
    failure = {
        "node_code": "free_plan_check",
        "node_label": "查询 Free 套餐资格",
        "error_code": str(exc.error_code or "free_plan_check_failed"),
        "public_message": f"查询 Free 套餐资格 [查询 Free 套餐资格/free_plan_check]：{cause}",
        "technical_summary": cause,
        "retryable": bool(exc.retryable),
        "action_hint": str(exc.action_hint or "账号已保存；稍后重新测活以补查套餐与试用资格"),
    }
    if exc.provider_status is not None:
        failure["http_status"] = exc.provider_status
    if exc.provider_code:
        failure["provider_code"] = exc.provider_code
    return failure


def _call_otp_wait(provider: Any, email: str, **kwargs: Any) -> str:
    waiter = getattr(provider, "wait_code", None)
    if not callable(waiter):
        raise FreeRegisterError(
            "free_twofa_otp_validate", "等待 Free 账号 2FA 邮箱验证码",
            "邮箱取件 Provider 缺少 wait_code 方法", retryable=False,
            error_code="free_twofa_otp_waiter_missing",
        )
    try:
        inspect.signature(waiter).bind(email, **kwargs)
    except ValueError:
        return waiter(email, **kwargs)
    except TypeError:
        return waiter(email)
    return waiter(email, **kwargs)


def resolve_auth_impersonates(config: Mapping[str, Any]) -> list[str]:
    """Keep explicit candidates; otherwise use the recovered rotation order."""
    for key in ("auth_impersonates", "chatgpt_impersonates"):
        value = config.get(key)
        if isinstance(value, list):
            candidates: list[str] = []
            for item in value:
                name = str(item or "").strip()
                if name and name not in candidates:
                    candidates.append(name)
            if candidates:
                return candidates
    return list(DEFAULT_AUTH_IMPERSONATES)


def _ensure_oauth_context_params(
    oauth_url: str,
    *,
    device_id: str,
    auth_session_logging_id: str,
) -> str:
    """Keep the authorize URL aligned with AutoRegister's browser context."""
    try:
        parsed = urlsplit(str(oauth_url or ""))
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        present = {key for key, _value in pairs}
        additions = (
            ("prompt", "login"),
            ("ext-oai-did", str(device_id or "")),
            ("auth_session_logging_id", str(auth_session_logging_id or "")),
        )
        for key, value in additions:
            if value and key not in present:
                pairs.append((key, value))
                present.add(key)
        return urlunsplit(parsed._replace(query=urlencode(pairs)))
    except (TypeError, ValueError):
        return str(oauth_url or "")


__all__ = [
    "DEFAULT_AUTH_IMPERSONATES",
    "CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL",
    "resolve_auth_impersonates",
]
