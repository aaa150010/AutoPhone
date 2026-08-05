"""Safe per-transport request context for the OpenAI auth flow.

The recovered transport owns the real HTTP session. This module only tracks
non-secret request metadata and provides the small policy helpers needed by
the macOS override layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import time
import uuid
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from .auth_session_runtime import AuthSessionRegistry, _short_fingerprint, _safe_path
except ImportError:  # Loaded as a top-level runtime override.
    from auth_session_runtime import AuthSessionRegistry, _short_fingerprint, _safe_path  # type: ignore[no-redef]


# OpenAI keeps the same authenticated transport while moving from the number
# entry page to the SMS code page. A timed-out SMS order may therefore leave
# the transport on an OTP page when the next number is submitted.
PHONE_PAGE_TYPES = frozenset(
    {
        "add_phone",
        "contact_verification",
        "phone_number_collection",
        "phone_otp",
        "phone-verification",
        "phone_number_verification",
        "sms_otp",
    }
)


class AuthRequestContextError(RuntimeError):
    """Raised when a request would use an incomplete or stale auth context."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class TransportRequestContext:
    task_id: str
    transport_fingerprint: str
    invocation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generation: int = 0
    page_type: str = ""
    continue_path: str = ""
    request_count: int = 0
    last_request_id: str = ""
    last_sentinel: dict[str, bool] = field(default_factory=dict)

    def request_id(self) -> str:
        self.request_count += 1
        self.last_request_id = f"{self.task_id or self.transport_fingerprint}:{self.generation}:{self.request_count}"
        return self.last_request_id

    def observe(self, response: Any = None, *, page_type: Any = "", continue_url: Any = "") -> None:
        if isinstance(response, Mapping):
            page = response.get("page")
            if isinstance(page, Mapping):
                page_type = page.get("type") or page_type
            page_type = response.get("page_type") or page_type
            continue_url = response.get("continue_url") or continue_url
        if page_type:
            self.page_type = str(page_type)[:80]
        path = _safe_path(continue_url)
        if path:
            self.continue_path = path

    def rotate(self) -> int:
        self.generation += 1
        self.invocation_id = str(uuid.uuid4())
        self.page_type = ""
        self.continue_path = ""
        self.last_sentinel = {}
        return self.generation


def _task_id(transport: Any) -> str:
    config = getattr(transport, "config", None)
    config = config if isinstance(config, Mapping) else {}
    return str(config.get("sms_task_id") or config.get("run_id") or "").strip()


def _account_email(transport: Any) -> str:
    config = getattr(transport, "config", None)
    config = config if isinstance(config, Mapping) else {}
    return str(
        getattr(transport, "account_email", "")
        or config.get("_auth_account_email")
        or ""
    ).strip().lower()


def _session_fingerprint(transport: Any) -> str:
    value = getattr(transport, "session", None)
    if value is None:
        value = id(transport)
    return _short_fingerprint(value) or hashlib.sha256(str(id(transport)).encode()).hexdigest()[:12]


def _page_type(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page")
    if isinstance(page, Mapping):
        return str(page.get("type") or "")[:80]
    return str(response.get("page_type") or "")[:80]


def _cookies_present(transport: Any) -> bool:
    session = getattr(transport, "session", None)
    cookies = getattr(session, "cookies", None)
    try:
        return bool(cookies)
    except Exception:
        return False


def _csrf_present(transport: Any) -> bool:
    session = getattr(transport, "session", None)
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return False
    try:
        names = {str(item.name).lower() for item in cookies}
    except Exception:
        return False
    return any("csrf" in name or "xsrf" in name for name in names)


def ensure_transport_context(
    transport: Any,
    registry: AuthSessionRegistry | None = None,
    *,
    force_new: bool = False,
) -> TransportRequestContext:
    context = getattr(transport, "_gptphone_request_context", None)
    if not isinstance(context, TransportRequestContext) or force_new:
        context = TransportRequestContext(
            task_id=_task_id(transport),
            transport_fingerprint=_session_fingerprint(transport),
        )
        setattr(transport, "_gptphone_request_context", context)
        if registry is not None and context.task_id:
            item = registry.start_generation(
                context.task_id,
                email=_account_email(transport),
                node_instance_id=getattr(getattr(transport, "sentinel_provider", None), "device_id", ""),
                transport_instance_id=context.transport_fingerprint,
            )
            context.generation = item.generation
    return context


def begin_request(
    transport: Any,
    registry: AuthSessionRegistry | None,
    *,
    endpoint: str,
    stage: str,
    continue_url: str = "",
) -> dict[str, Any]:
    context = ensure_transport_context(transport, registry)
    context.observe(page_type=getattr(transport, "_gptphone_page_type", ""), continue_url=continue_url)
    if registry is None or not context.task_id:
        request_id = context.request_id()
        return {
            "request_context_id": request_id,
            "endpoint": endpoint,
            "stage": stage,
            "session_generation": context.generation,
            "session_fingerprint": context.transport_fingerprint,
            "continue_path": context.continue_path,
            "cookies_present": _cookies_present(transport),
            "csrf_present": _csrf_present(transport),
        }
    item = registry.get(context.task_id, email=_account_email(transport))
    event = item.begin_request(
        endpoint=endpoint,
        stage=stage,
        cookies_present=_cookies_present(transport),
        csrf_present=_csrf_present(transport),
        proxy=getattr(transport, "proxy", ""),
    )
    context.last_request_id = str(event.get("request_context_id") or "")
    return event


def finish_request(
    transport: Any,
    registry: AuthSessionRegistry | None,
    request: Mapping[str, Any],
    response: Any = None,
    *,
    page_type: str = "",
    continue_url: str = "",
) -> dict[str, Any]:
    context = ensure_transport_context(transport, registry)
    context.observe(response, page_type=page_type, continue_url=continue_url)
    setattr(transport, "_gptphone_page_type", context.page_type)
    if registry is not None and context.task_id:
        item = registry.get(context.task_id, email=_account_email(transport))
        event = item.finish_request(
            request.get("request_context_id"),
            response=response,
            continue_url=continue_url,
        ) or dict(request)
        return event
    result = dict(request)
    if isinstance(response, Mapping):
        result["response_status"] = response.get("_status")
        result["page_type"] = _page_type(response)
        result["continue_path"] = _safe_path(response.get("continue_url")) or result.get("continue_path", "")
    return result


def mark_phone_ready(
    transport: Any,
    registry: AuthSessionRegistry | None,
    response: Any,
    *,
    continue_url: str = "",
) -> None:
    context = ensure_transport_context(transport, registry)
    page_type = _page_type(response) or "add_phone"
    context.observe(response, page_type=page_type, continue_url=continue_url)
    setattr(transport, "_gptphone_page_type", page_type)
    if registry is not None and context.task_id:
        registry.observe(
            context.task_id,
            "phone_submitting",
            email=_account_email(transport),
            continue_url=continue_url,
            success=True,
        )


def validate_phone_context(transport: Any, registry: AuthSessionRegistry | None) -> TransportRequestContext:
    context = ensure_transport_context(transport, registry)
    page_type = str(getattr(transport, "_gptphone_page_type", "") or context.page_type)
    if page_type not in PHONE_PAGE_TYPES:
        raise AuthRequestContextError("auth_context_page_mismatch", "当前登录页面不是手机号验证页面")
    if not _cookies_present(transport):
        raise AuthRequestContextError("auth_context_cookies_missing", "当前登录会话缺少有效 cookies")
    return context


def observe_auth_response(
    transport: Any,
    registry: AuthSessionRegistry | None,
    response: Any,
    *,
    stage: str,
) -> None:
    context = ensure_transport_context(transport, registry)
    context.observe(response)
    setattr(transport, "_gptphone_page_type", context.page_type)
    if registry is not None and context.task_id:
        registry.observe(
            context.task_id,
            stage,
            email=_account_email(transport),
            continue_url=(response.get("continue_url") if isinstance(response, Mapping) else ""),
            success=True,
        )


def invalidate_auth_session(
    transport: Any,
    registry: AuthSessionRegistry | None,
    error: Any,
    *,
    stage: str = "phone_submitting",
) -> None:
    context = ensure_transport_context(transport, registry)
    context.rotate()
    setattr(transport, "_gptphone_page_type", "")
    if registry is not None and context.task_id:
        registry.invalidate(
            context.task_id,
            error,
            stage=stage,
            email=_account_email(transport),
        )


def request_headers(
    transport: Any,
    headers: Mapping[str, Any] | None = None,
    *,
    include_sentinel: bool = True,
) -> dict[str, str]:
    """Add stable browser-flow headers without retaining their values."""

    context = ensure_transport_context(transport)
    result = {str(key): str(value) for key, value in dict(headers or {}).items()}
    result["x-access-flow-invocation-id"] = context.invocation_id
    if not include_sentinel:
        for key in tuple(result):
            if key.lower() in {"openai-sentinel-token", "openai-sentinel-so-token"}:
                result.pop(key, None)
    return result


def refresh_sentinel(
    transport: Any,
    registry: AuthSessionRegistry | None,
    *,
    flow: str,
    referer: str,
) -> dict[str, Any]:
    """Force a fresh Sentinel value after the no-Sentinel phone request."""

    context = ensure_transport_context(transport, registry)
    provider = getattr(transport, "sentinel_provider", None)
    if provider is None or not callable(getattr(provider, "token_for", None)):
        raise AuthRequestContextError("sentinel_provider_missing", "手机号发送后无法刷新 Sentinel")
    reset = getattr(provider, "reset", None)
    if callable(reset):
        reset(flow)
    token = provider.token_for(
        flow,
        {
            "persona": str((getattr(transport, "config", None) or {}).get("codex_persona") or "chatgpt-noauth"),
            "device_id": str(getattr(transport, "device_id", "") or ""),
            "referer": referer,
        },
    )
    result = dict(token or {}) if isinstance(token, Mapping) else {}
    if not result.get("token") and not result.get("so_token"):
        raise AuthRequestContextError("sentinel_refresh_failed", "手机号发送后 Sentinel 刷新失败")
    context.last_sentinel = {
        "token_present": bool(result.get("token")),
        "so_token_present": bool(result.get("so_token")),
    }
    return result


def safe_context_snapshot(transport: Any) -> dict[str, Any]:
    context = ensure_transport_context(transport)
    return {
        "request_context_id": context.last_request_id,
        "session_generation": context.generation,
        "session_fingerprint": context.transport_fingerprint,
        "flow_invocation_id_present": bool(context.invocation_id),
        "page_type": context.page_type,
        "continue_path": context.continue_path,
        "cookies_present": _cookies_present(transport),
        "csrf_present": _csrf_present(transport),
        "proxy_fingerprint": _short_fingerprint(getattr(transport, "proxy", "")),
        "observed_at": int(time.time()),
    }


__all__ = [
    "AuthRequestContextError",
    "PHONE_PAGE_TYPES",
    "TransportRequestContext",
    "begin_request",
    "ensure_transport_context",
    "finish_request",
    "invalidate_auth_session",
    "mark_phone_ready",
    "observe_auth_response",
    "refresh_sentinel",
    "request_headers",
    "safe_context_snapshot",
    "validate_phone_context",
]
