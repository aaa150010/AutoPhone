"""Bounded recovery for an expired ChatGPT TOTP authorization step."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import re
import time
from typing import Any


EXPIRED_MFA_CODES = frozenset(
    {
        "invalid_authorization_step",
        "mfa_authorization_step_expired",
    }
)
_SAFE_LOG_CODES = EXPIRED_MFA_CODES | frozenset(
    {
        "incorrect_code",
        "oauth_session_invalid",
        "invalid_session",
    }
)


def response_error_code(value: Any) -> str:
    if not isinstance(value, Mapping):
        return ""
    error = value.get("error")
    if isinstance(error, Mapping):
        candidate = (
            error.get("code")
            or error.get("error_code")
            or error.get("type")
            or error.get("message")
        )
    else:
        candidate = (
            error
            or value.get("error_code")
            or value.get("code")
            or value.get("message")
        )
    return (
        str(candidate or "")
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")[:80]
    )


def is_expired_mfa_response(path: Any, response: Any) -> bool:
    return (
        str(path or "").strip() == "/api/accounts/mfa/verify"
        and response_error_code(response) in EXPIRED_MFA_CODES
    )


def mfa_factor_id_from_response(
    response: Any,
    *,
    continue_url_fn: Callable[[Any], Any] | None = None,
) -> str:
    """Extract a TOTP factor without publishing it to diagnostics."""
    value = response if isinstance(response, Mapping) else {}
    page = value.get("page") if isinstance(value.get("page"), Mapping) else {}
    payload = page.get("payload") if isinstance(page.get("payload"), Mapping) else {}
    factor_id = str(payload.get("factor_id") or "").strip()
    if factor_id:
        return factor_id
    for key in ("mfa_challenge_factors", "mfa_factors"):
        factors = value.get(key)
        if not isinstance(factors, list):
            auth = value.get("oai-client-auth-session")
            factors = auth.get(key) if isinstance(auth, Mapping) else None
        if not isinstance(factors, list):
            continue
        for factor in factors:
            if isinstance(factor, Mapping) and factor.get("factor_type") == "totp":
                factor_id = str(factor.get("id") or "").strip()
                if factor_id:
                    return factor_id
    try:
        continue_url = continue_url_fn(value) if callable(continue_url_fn) else value.get("continue_url")
    except Exception:
        continue_url = ""
    match = re.search(r"/mfa-challenge/([^/?#]+)", str(continue_url or ""))
    return match.group(1) if match else ""


def _stopped(stop_event: Any) -> bool:
    is_set = getattr(stop_event, "is_set", None)
    if callable(is_set):
        return bool(is_set())
    if callable(stop_event):
        try:
            return bool(stop_event())
        except TypeError:
            return False
    return False


def _clear_totp_retry_state(transport: Any) -> None:
    setattr(transport, "_gptphone_totp_flow", False)
    setattr(transport, "_gptphone_totp_incorrect_retries", 0)
    for name in ("_gptphone_totp_secret", "_chatgpt_totp_factor_id"):
        try:
            delattr(transport, name)
        except AttributeError:
            pass


def verify_email_totp_with_one_window_retry(
    transport: Any,
    *,
    factor_id: Any,
    secret: Any,
    verify_fn: Callable[[Any, str], Any],
    manual_fallback_fn: Callable[[Any, Any], Any] | None,
    session_invalid_fn: Callable[[Any], bool],
    stop_event: Any = None,
    clock: Callable[[], float] | None = None,
    sleep_fn: Callable[[float], Any] | None = None,
    log_fn: Callable[[str, str], Any] | None = None,
) -> Any:
    """Verify URL-mailbox TOTP and retry only in the next 30-second window."""
    factor = str(factor_id or "").strip()
    seed = str(secret or "").strip()
    if not factor or not seed:
        raise ValueError("TOTP factor 或密钥为空")
    setattr(transport, "_chatgpt_totp_factor_id", factor)
    setattr(transport, "_gptphone_totp_flow", True)
    setattr(transport, "_gptphone_totp_secret", seed)
    setattr(transport, "_gptphone_totp_incorrect_retries", 0)

    response = verify_fn(transport, "")
    if response_error_code(response) != "incorrect_code" or session_invalid_fn(response):
        _clear_totp_retry_state(transport)
        return response
    if _stopped(stop_event):
        _clear_totp_retry_state(transport)
        return response

    now_fn = clock or time.time
    waiter = getattr(stop_event, "wait", None)
    wait_seconds = 30.0 - (float(now_fn()) % 30.0) + 0.05
    if callable(log_fn):
        log_fn(
            "  [2FA 换窗重试/mfa_otp_verifying] 动态码被拒绝，等待下一个时间窗口后自动重试一次",
            "warn",
        )
    if callable(waiter):
        if waiter(wait_seconds):
            _clear_totp_retry_state(transport)
            return response
    else:
        sleeper = sleep_fn or time.sleep
        remaining = wait_seconds
        while remaining > 0:
            if _stopped(stop_event):
                _clear_totp_retry_state(transport)
                return response
            interval = min(0.25, remaining)
            sleeper(interval)
            remaining -= interval
    if _stopped(stop_event):
        _clear_totp_retry_state(transport)
        return response

    response = verify_fn(transport, "")
    if (
        response_error_code(response) == "incorrect_code"
        and not session_invalid_fn(response)
        and callable(manual_fallback_fn)
    ):
        response = manual_fallback_fn(transport, response)
    _clear_totp_retry_state(transport)
    return response


def _retry_marker(generation: Any, factor_id: str) -> tuple[str, str]:
    """Keep factor identity private while allowing one retry per factor."""
    generation_value = str(generation or "0")[:32]
    factor_fingerprint = hashlib.sha256(
        factor_id.encode("utf-8", "replace")
    ).hexdigest()[:12]
    return generation_value, factor_fingerprint


def retry_expired_mfa_step(
    transport: Any,
    *,
    path: Any,
    payload: Any,
    response: Any,
    generation: Any,
    post_json: Callable[..., Any],
    pending_totp_payload: Callable[..., Any],
    success_fn: Callable[[Any], bool],
    auth_origin: str,
    timeout: int = 30,
    log_fn: Callable[[str, str], Any] | None = None,
) -> tuple[Any, bool]:
    """Retry one expired MFA step without broadening other session retries.

    Returns ``(response, attempted)``. A failed refresh returns the original
    or retry response so the caller's existing session invalidation remains
    authoritative.
    """

    if not is_expired_mfa_response(path, response) or not isinstance(payload, dict):
        return response, False

    factor_id = str(payload.get("id") or "").strip()
    secret = str(getattr(transport, "_gptphone_totp_secret", "") or "").strip()
    marker = _retry_marker(generation, factor_id)
    markers = getattr(transport, "_gptphone_mfa_fresh_retry_markers", None)
    if not isinstance(markers, set):
        markers = set()
        legacy_marker = getattr(transport, "_gptphone_mfa_fresh_retry_generation", None)
        if isinstance(legacy_marker, tuple) and len(legacy_marker) == 2:
            markers.add(legacy_marker)
        setattr(transport, "_gptphone_mfa_fresh_retry_markers", markers)
    if not factor_id or not secret or marker in markers:
        return response, False

    markers.add(marker)
    setattr(transport, "_gptphone_mfa_fresh_retry_generation", marker)
    if callable(log_fn):
        log_fn(
            "  [2FA 挑战刷新/mfa_otp_verifying] 授权步骤已过期，正在刷新一次 TOTP challenge",
            "warn",
        )

    try:
        issued = post_json(
            transport,
            "/api/accounts/mfa/issue_challenge",
            {"id": factor_id, "type": "totp", "force_fresh_challenge": True},
            flow="mfa_otp_issue",
            referer=f"{auth_origin}/log-in/password",
            timeout=timeout,
        )
    except Exception:
        return response, True
    if not success_fn(issued):
        return issued if isinstance(issued, Mapping) else response, True

    fresh_payload = {"id": factor_id, "type": "totp", "code": ""}
    try:
        with pending_totp_payload(transport, fresh_payload, secret):
            retried = post_json(
                transport,
                "/api/accounts/mfa/verify",
                fresh_payload,
                flow="mfa_otp_verify",
                referer=f"{auth_origin}/mfa-challenge/{factor_id}",
                timeout=timeout,
            )
    except Exception:
        return response, True

    # The outer TOTP patch uses this payload to remember an explicitly rejected
    # code. Keep it aligned with the code generated after fresh Sentinel headers.
    payload["code"] = str(fresh_payload.get("code") or "")
    if callable(log_fn):
        code = response_error_code(retried)
        # Provider messages are not a safe diagnostics surface. Retain only
        # stable codes that can be acted on without leaking response content.
        code = code if code in _SAFE_LOG_CODES else "provider_error"
        suffix = f"，provider_code={code}" if code else ""
        log_fn(
            "  [2FA 挑战刷新/mfa_otp_verifying] TOTP challenge 已刷新并完成一次重试"
            f"{suffix}",
            "info" if success_fn(retried) else "warn",
        )
    return retried, True


__all__ = [
    "EXPIRED_MFA_CODES",
    "is_expired_mfa_response",
    "mfa_factor_id_from_response",
    "response_error_code",
    "retry_expired_mfa_step",
    "verify_email_totp_with_one_window_retry",
]
