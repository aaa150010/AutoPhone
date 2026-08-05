"""Pure recovery policies for the recovered authorization runtime."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import re
import time
from typing import Any


_SUB2_EXPIRED_MARKERS = (
    "session not found or expired",
    "sub2_session_expired",
    "openai_oauth_session_not_found",
)
_POST_PHONE_STATES = {
    "PHONE_OTP_VERIFIED",
    "CALLBACK_RECEIVED",
}

_NON_RETRYABLE_NETWORK_MARKERS = (
    "certificate verify failed",
    "hostname mismatch",
    "invalid credentials",
    "invalid password",
    "task_stopped",
)
_CLIENT_HTTP_STATUS_RE = re.compile(
    r"\b(?:http(?:\s+status)?|status(?:_code)?)\s*[:=]?\s*(4\d\d)\b",
    re.IGNORECASE,
)
_HTTP_STATUS_FIELDS = frozenset({"_status", "status", "status_code", "http_status"})
_TRANSIENT_PRE_AUTH_RULES = (
    (
        "invalid_json_response",
        (
            "jsondecodeerror",
            "invalidjsonerror",
            "expecting value: line 1 column 1",
            "invalid json response",
            "empty json",
        ),
    ),
    (
        "empty_response",
        (
            "oauth_start_no_response",
            "empty response body",
            "response body is empty",
            "empty reply from server",
            "curl: (52)",
        ),
    ),
    (
        "tls_connection_failed",
        (
            "tls connect error",
            "ssl connect error",
            "ssleoferror",
            "sslerror",
            "unexpected_eof_while_reading",
            "eof occurred in violation of protocol",
            "curl: (35)",
        ),
    ),
    (
        "connection_timeout",
        (
            "connecttimeout",
            "readtimeout",
            "connection timeout",
            "connection timed out",
            "operation timed out",
            "timed out after",
            "curl: (28)",
        ),
    ),
    (
        "remote_disconnected",
        (
            "remotedisconnected",
            "remote disconnected",
            "remote end closed connection",
            "connection aborted",
            "connection reset",
            "connection closed without response",
            "server disconnected",
            "curl: (56)",
        ),
    ),
)

_RELOGIN_NON_RETRYABLE_MARKERS = (
    "relogin_phone_required",
    "password_verify_failed",
    "incorrect password",
    "invalid password",
    "wrong password",
    "mfa_otp_failed",
    "verify_mfa_otp",
    "oauth_callback_state_mismatch",
    "oauth_state_mismatch",
    "state mismatch",
    "invalid_state",
    "account_banned",
    "account_deactivated",
    "account_suspended",
    "account_deleted",
)
_RELOGIN_RATE_LIMIT_MARKERS = (
    "http 429",
    "status=429",
    "status_code=429",
    "too many requests",
    "rate limit",
    "rate_limited",
)

ACCOUNT_BANNED_MESSAGE = "OpenAI 账号已被封禁，无法继续接码"

_ACCOUNT_BANNED_CODES = frozenset(
    {
        "account_banned",
        "account_deactivated",
        "account_deleted",
        "account_suspended",
        "user_banned",
        "user_deactivated",
        "user_deleted",
        "user_suspended",
    }
)
_ACCOUNT_STATUS_FIELDS = frozenset(
    {"code", "error_code", "error_type", "reason", "state", "status", "type"}
)
_ACCOUNT_MESSAGE_FIELDS = frozenset(
    {"detail", "error", "error_description", "error_message", "message", "technical_error"}
)
_ACCOUNT_BANNED_PHRASES = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:this|the|your)?\s*account\s+(?:has\s+been|was|is)\s+"
        r"(?:banned|deactivated|deleted|suspended)\b",
        r"\baccount\s+(?:banned|deactivated|deleted|suspended)\b",
        r"\baccount\s+(?:was\s+)?deleted\s+or\s+deactivated\b",
        r"\byou\s+do\s+not\s+have\s+an\s+account\b.*\b(?:deleted|deactivated)\b",
        r"(?:账号|账户)(?:已被|已|被)(?:封禁|停用|删除|暂停)",
    )
)


class AccountBannedError(RuntimeError):
    """Terminal phone-stage signal whose public string is deliberately stable."""

    def __init__(self, technical_detail: Any = "") -> None:
        super().__init__(ACCOUNT_BANNED_MESSAGE)
        self.technical_detail = str(technical_detail or "")[:1000]


def _searchable_failure_text(value: Any) -> str:
    pending = [value]
    seen: set[int] = set()
    parts: list[str] = []
    while pending and len(seen) < 100:
        current = pending.pop()
        if current is None:
            continue
        if isinstance(current, BaseException):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            parts.extend((type(current).__name__, str(current)))
            pending.extend((current.__cause__, current.__context__))
            continue
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend(current.values())
            continue
        if isinstance(current, (list, tuple, set, frozenset)):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend(current)
            continue
        parts.append(str(current))
    return " ".join(parts).lower()


def _failure_http_statuses(value: Any) -> set[int]:
    pending = [value]
    seen: set[int] = set()
    statuses: set[int] = set()
    while pending and len(seen) < 100:
        current = pending.pop()
        if current is None:
            continue
        if isinstance(current, BaseException):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend((str(current), current.__cause__, current.__context__))
            continue
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            for key, child in current.items():
                if str(key or "").strip().lower() in _HTTP_STATUS_FIELDS:
                    try:
                        status = int(child)
                    except (TypeError, ValueError):
                        pass
                    else:
                        if 100 <= status <= 599:
                            statuses.add(status)
                pending.append(child)
            continue
        if isinstance(current, (list, tuple, set, frozenset)):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend(current)
            continue
        text = str(current)
        statuses.update(int(match.group(1)) for match in _CLIENT_HTTP_STATUS_RE.finditer(text))
    return statuses


def transient_pre_auth_error_code(value: Any) -> str:
    """Return a stable code only for narrow, pre-auth transient network failures."""
    text = _searchable_failure_text(value)
    if not text or any(marker in text for marker in _NON_RETRYABLE_NETWORK_MARKERS):
        return ""
    client_statuses = _failure_http_statuses(value)
    # Only client errors make a pre-auth response permanently non-retryable.
    # 5xx responses are exactly the transient upstream failures this helper
    # is intended to retry; structured payloads may expose them via `_status`.
    if any(400 <= status < 500 and status not in {408, 425} for status in client_statuses):
        return ""
    for code, markers in _TRANSIENT_PRE_AUTH_RULES:
        if any(marker in text for marker in markers):
            return code
    return ""


def is_relogin_transient_failure(value: Any) -> bool:
    """Allow whole-chain relogin retries only for narrow transient failures."""
    text = _searchable_failure_text(value)
    if not text or any(marker in text for marker in _RELOGIN_NON_RETRYABLE_MARKERS):
        return False
    statuses = _failure_http_statuses(value)
    if 429 in statuses or any(marker in text for marker in _RELOGIN_RATE_LIMIT_MARKERS):
        return True
    return bool(transient_pre_auth_error_code(value))


def call_with_transient_pre_auth_retry(
    operation: Callable[[], Any],
    *,
    attempts: int = 2,
    delay_seconds: float = 0.25,
    stop_requested: Callable[[], bool] | None = None,
    on_retry: Callable[[str, int, int, float], Any] | None = None,
    sleep_fn: Callable[[float], Any] = time.sleep,
    retry_result: bool = False,
    retry_codes: set[str] | frozenset[str] | None = None,
) -> Any:
    """Retry a thrown transient failure without expanding the paid-service boundary."""
    try:
        attempt_limit = max(1, min(3, int(attempts)))
    except (TypeError, ValueError):
        attempt_limit = 2
    try:
        delay = max(0.0, min(2.0, float(delay_seconds)))
    except (TypeError, ValueError):
        delay = 0.25
    allowed_codes = (
        frozenset(str(code or "").strip() for code in retry_codes)
        if retry_codes is not None
        else None
    )

    def allowed(error_code: str) -> bool:
        return bool(error_code) and (allowed_codes is None or error_code in allowed_codes)

    def result_error_code(result: Any) -> str:
        if not retry_result:
            return ""
        if isinstance(result, Mapping):
            try:
                status = int(result.get("_status") or result.get("status_code") or 0)
            except (TypeError, ValueError):
                status = 0
            if (200 <= status < 400 or result.get("ok") is True) and not result.get("error"):
                return ""
        return transient_pre_auth_error_code(result)

    def stopped() -> bool:
        if not callable(stop_requested):
            return False
        try:
            return bool(stop_requested())
        except Exception:
            return False

    def notify_retry(error_code: str, next_attempt: int) -> None:
        if callable(on_retry):
            try:
                on_retry(error_code, next_attempt, attempt_limit, delay)
            except Exception:
                pass
        if delay:
            sleep_fn(delay)

    for attempt in range(1, attempt_limit + 1):
        try:
            result = operation()
        except Exception as exc:
            error_code = transient_pre_auth_error_code(exc)
            if not allowed(error_code) or attempt >= attempt_limit or stopped():
                raise
            next_attempt = attempt + 1
            notify_retry(error_code, next_attempt)
            if stopped():
                raise
            continue
        error_code = result_error_code(result)
        if not allowed(error_code) or attempt >= attempt_limit or stopped():
            return result
        notify_retry(error_code, attempt + 1)
        if stopped():
            return result
    raise RuntimeError("pre-auth retry loop ended unexpectedly")


def _normalized_account_code(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _has_explicit_account_banned_phrase(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if text == ACCOUNT_BANNED_MESSAGE:
        return True
    return any(pattern.search(text) for pattern in _ACCOUNT_BANNED_PHRASES)


def is_explicit_account_banned(value: Any) -> bool:
    """Recognize explicit account terminal signals without treating a bare 403 as a ban."""
    if isinstance(value, AccountBannedError):
        return True

    pending: list[tuple[str, Any]] = [("", value)]
    seen: set[int] = set()
    visited = 0
    while pending and visited < 100:
        key, current = pending.pop()
        visited += 1
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            for child_key, child_value in current.items():
                normalized_key = str(child_key or "").strip().lower()
                if (
                    normalized_key in _ACCOUNT_STATUS_FIELDS
                    and _normalized_account_code(child_value) in _ACCOUNT_BANNED_CODES
                ):
                    return True
                if (
                    normalized_key in _ACCOUNT_MESSAGE_FIELDS
                    and _has_explicit_account_banned_phrase(child_value)
                ):
                    return True
                pending.append((normalized_key, child_value))
            continue
        if isinstance(current, (list, tuple, set, frozenset)):
            pending.extend((key, child) for child in current)
            continue
        if key in _ACCOUNT_STATUS_FIELDS and _normalized_account_code(current) in _ACCOUNT_BANNED_CODES:
            return True
        if key in _ACCOUNT_MESSAGE_FIELDS and _has_explicit_account_banned_phrase(current):
            return True
        if not key and _has_explicit_account_banned_phrase(current):
            return True
    return False


def is_account_banned_failure(result: Any, error: Any = "") -> bool:
    return is_explicit_account_banned(error) or is_explicit_account_banned(result)


def should_retry_expired_sub2_session(result: Any) -> bool:
    """Retry only when a completed phone flow outlived its SUB2 OAuth session."""
    if not isinstance(result, dict):
        return False
    error = " ".join(
        str(result.get(name) or "")
        for name in ("error", "phase2_error", "local_oauth_exchange_error", "technical_error")
    ).lower()
    if "sub2_exchange_failed" not in error:
        return False
    if not any(marker in error for marker in _SUB2_EXPIRED_MARKERS):
        return False

    events = result.get("codex_chain_events")
    if not isinstance(events, list):
        return False
    states = {
        str(item.get("state") or "")
        for item in events
        if isinstance(item, dict)
    }
    return bool(states.intersection(_POST_PHONE_STATES))
