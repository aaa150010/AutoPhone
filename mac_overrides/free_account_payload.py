"""Payload parsing and plan/session semantics for the Free account services.

Split out of ``free_account_service.py``; the original module re-exports
every name for compatibility.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

try:
    from .chatgpt_plan_gate import plan_from_accounts_check
    from .chatgpt_totp import totp_code
    from .free_failure_runtime import password_status_from_result
    from .free_register_common import FIXED_PASSWORD, FreeRegisterError, clean
except ImportError:  # pragma: no cover - top-level recovery import
    from chatgpt_plan_gate import plan_from_accounts_check  # type: ignore[no-redef]
    from chatgpt_totp import totp_code  # type: ignore[no-redef]
    from free_failure_runtime import password_status_from_result  # type: ignore[no-redef]
    from free_register_common import FIXED_PASSWORD, FreeRegisterError, clean  # type: ignore[no-redef]


MAX_TOKEN_CHARS = 16384


def session_token(payload: Any) -> str:
    """Read supported Session JSON token fields without logging values."""
    if not isinstance(payload, Mapping):
        return ""
    for key in ("accessToken", "access_token", "token"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip() and len(value.strip()) <= MAX_TOKEN_CHARS:
            return value.strip()
    for key in ("session", "data", "account"):
        value = session_token(payload.get(key))
        if value:
            return value
    return ""


def _provider_code(payload: Any, fallback: str = "") -> str:
    candidates: list[Mapping[str, Any]] = []
    pending: list[Mapping[str, Any]] = [payload] if isinstance(payload, Mapping) else []
    seen: set[int] = set()
    while pending and len(candidates) < 12:
        item = pending.pop(0)
        if id(item) in seen:
            continue
        seen.add(id(item))
        candidates.append(item)
        for key in ("value", "payload", "data", "error"):
            value = item.get(key)
            if isinstance(value, Mapping):
                pending.append(value)
    for item in candidates:
        for key in ("provider_code", "error_code", "code", "type"):
            value = item.get(key)
            if value not in (None, "", 0, "0") and not isinstance(value, (Mapping, list, tuple)):
                return clean(value, 120)
    return clean(fallback, 120)


def _status(payload: Any) -> int:
    if not isinstance(payload, Mapping):
        return 0
    try:
        return int(payload.get("status") or payload.get("status_code") or 0)
    except (TypeError, ValueError):
        return 0


def _retry_after(payload: Any) -> int | None:
    if not isinstance(payload, Mapping):
        return None
    values = [payload.get("retry_after_seconds"), payload.get("retry_after")]
    headers = payload.get("headers") or payload.get("_headers")
    if isinstance(headers, Mapping):
        values.extend((headers.get("retry-after"), headers.get("Retry-After")))
    for value in values:
        try:
            parsed = int(float(str(value).strip()))
        except (TypeError, ValueError):
            continue
        if 0 <= parsed <= 86400:
            return parsed
    return None


def _json_payload(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    for key in ("payload", "value", "data"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            return value
    return payload


def _response_continue_url(payload: Any) -> str:
    """Find a continuation URL in the nested Auth response envelope.

    Auth responses have appeared both as a top-level ``continue_url`` and as
    ``page.payload.continue_url``.  Keep the traversal bounded and return only
    a string; callers still validate the expected host/path before navigating.
    """
    queue: list[Mapping[str, Any]] = [payload] if isinstance(payload, Mapping) else []
    seen: set[int] = set()
    # Prefer explicit continuation fields at any depth. A page envelope can
    # contain an unrelated ``url`` alongside ``payload.continue_url``; taking
    # the generic URL first would navigate to the wrong auth page.
    strong_keys = ("continue_url", "external_url", "redirect_url", "next_url", "location")
    generic_urls: list[str] = []
    while queue and len(seen) < 32:
        current = queue.pop(0)
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        for key in strong_keys:
            value = current.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        value = current.get("url")
        if isinstance(value, str) and value.strip():
            generic_urls.append(value.strip())
        for value in current.values():
            if isinstance(value, Mapping):
                queue.append(value)
            elif isinstance(value, (list, tuple)):
                queue.extend(item for item in value if isinstance(item, Mapping))
    if generic_urls:
        return generic_urls[0]
    return ""


def normalize_session(payload: Any) -> dict[str, Any]:
    """Normalize browser/protocol Session payloads without logging secrets."""
    value = dict(payload) if isinstance(payload, Mapping) else {}
    token = session_token(value)
    if not token:
        raise FreeRegisterError(
            "free_access_token", "获取 Free access token",
            "Session 已返回但未发现兼容 Token 字段",
            error_code="free_session_token_missing",
        )
    value["accessToken"] = token
    value["access_token"] = token
    value["has_access_token"] = True
    return value


def plan_details_from_payloads(accounts_payload: Any, eligibility_payload: Any) -> dict[str, Any]:
    """Parse the two plan endpoints into the public Free result shape."""
    accounts = dict(_json_payload(accounts_payload))
    eligibility = dict(_json_payload(eligibility_payload))
    accounts_status = _status(accounts_payload)
    eligibility_status = _status(eligibility_payload)
    if not accounts_status and isinstance(accounts_payload, Mapping):
        accounts_status = 200 if accounts else 0
    if not eligibility_status and isinstance(eligibility_payload, Mapping):
        eligibility_status = 200 if eligibility else 0
    try:
        plan, _ = plan_from_accounts_check(accounts, token="")
    except Exception:
        plan = ""
    plan = clean(plan, 120) or "free"
    eligible = _plus_trial_from_payload(accounts) or _plus_trial_from_payload(eligibility)
    eligibility_ok = 200 <= eligibility_status < 300 and bool(eligibility)
    details: dict[str, Any] = {
        "plan_check_status": "success" if 200 <= accounts_status < 300 and bool(accounts) else "failed",
        "plan_type": plan if 200 <= accounts_status < 300 and bool(accounts) else "",
        "subscription_plan": plan if 200 <= accounts_status < 300 and bool(accounts) else "",
        "has_active_subscription": bool(plan and plan != "free" and 200 <= accounts_status < 300),
        "plus_trial_eligible": bool(eligible),
        "plan_accounts_http_status": accounts_status or None,
        "plan_eligibility_http_status": eligibility_status or None,
        "plan_http_status": accounts_status or eligibility_status or None,
        "plan_eligibility_status": "success" if eligibility_ok else "failed",
        "plan_checked_at": time.time(),
    }
    retry_after = _retry_after(accounts_payload)
    if retry_after is None:
        retry_after = _retry_after(eligibility_payload)
    if retry_after is not None:
        details["retry_after_seconds"] = retry_after
    if details["plan_check_status"] == "failed":
        details["plan_error_code"] = "free_plan_accounts_response_invalid"
        details["plan_error_detail"] = "套餐接口返回无效或非成功响应"
        details["plan_provider_code"] = _provider_code(accounts_payload, "accounts_response_invalid")
        details["plan_failure"] = {
            "node_code": "free_plan_check",
            "node_label": "查询 Free 套餐资格",
            "error_code": details["plan_error_code"],
            "public_message": "查询 Free 套餐资格 [查询 Free 套餐资格/free_plan_check]：套餐接口响应无效",
            "technical_summary": "套餐接口返回无效或非成功响应",
            "retryable": True,
            "http_status": details["plan_http_status"],
            "provider_code": details["plan_provider_code"],
            "action_hint": "保留已注册账号，稍后重新查询套餐状态",
        }
        if retry_after is not None:
            details["plan_failure"]["retry_after_seconds"] = retry_after
    if not eligibility_ok:
        details["plan_eligibility_error_code"] = "free_plan_eligibility_response_invalid"
        details["plan_eligibility_provider_code"] = _provider_code(eligibility_payload, "eligibility_response_invalid")
        details["plan_check_status"] = "failed"
        details["plan_error_code"] = "free_plan_eligibility_response_invalid"
        details["plan_error_detail"] = "Plus 资格接口返回无效或非成功响应"
        details["plan_provider_code"] = details["plan_eligibility_provider_code"]
        details["plan_http_status"] = eligibility_status or accounts_status or None
        details["plan_failure"] = {
            "node_code": "free_plan_check",
            "node_label": "查询 Free 套餐资格",
            "error_code": details["plan_error_code"],
            "public_message": "查询 Free 套餐资格 [查询 Free 套餐资格/free_plan_check]：Plus 资格接口响应无效",
            "technical_summary": "Plus 资格接口返回无效或非成功响应",
            "retryable": True,
            "http_status": details["plan_http_status"],
            "provider_code": details["plan_provider_code"],
            "action_hint": "已保留账号套餐信息，稍后重新查询 Plus 资格",
        }
        if retry_after is not None:
            details["plan_failure"]["retry_after_seconds"] = retry_after
    return details


def _fallback_plan(payload: Any) -> str:
    """Read the small plan shapes returned by ``/me`` and ``wham/usage``."""
    value = _json_payload(payload)
    if not isinstance(value, Mapping):
        return ""
    try:
        from .chatgpt_plan_gate import normalize_plan_type
    except ImportError:  # pragma: no cover - recovery import
        from chatgpt_plan_gate import normalize_plan_type  # type: ignore[no-redef]
    for key in ("plan_type", "planType", "subscription_plan", "subscriptionPlan"):
        plan = normalize_plan_type(value.get(key))
        if plan:
            return plan
    orgs = value.get("orgs")
    if isinstance(orgs, Mapping):
        items = orgs.get("data")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, Mapping):
                    settings = item.get("settings") if isinstance(item.get("settings"), Mapping) else {}
                    plan = normalize_plan_type(settings.get("workspace_plan_type") or settings.get("workspacePlanType"))
                    if plan and plan != "free":
                        return plan
    return ""


def plan_details_with_fallbacks(
    accounts_payload: Any,
    eligibility_payload: Any,
    fallback_payloads: list[tuple[str, Any]] | tuple[tuple[str, Any], ...] = (),
) -> dict[str, Any]:
    """Parse accounts/check and, when necessary, aBai-compatible fallbacks."""
    details = plan_details_from_payloads(accounts_payload, eligibility_payload)
    if details.get("plan_check_status") == "success":
        return details
    for source, payload in fallback_payloads:
        plan = _fallback_plan(payload)
        status = _status(payload)
        if not plan or not 200 <= status < 300:
            continue
        details.update({
            "plan_check_status": "success",
            "plan_type": plan,
            "subscription_plan": plan,
            "has_active_subscription": plan != "free",
            "plan_http_status": status,
            "plan_checked_at": time.time(),
            "plan_source": source,
        })
        for key in ("plan_failure", "plan_error_code", "plan_error_detail", "plan_provider_code"):
            details.pop(key, None)
        return details
    if fallback_payloads:
        details["plan_fallback_attempts"] = [
            {"source": source, "http_status": _status(payload) or None}
            for source, payload in fallback_payloads
        ]
    return details


def _plus_trial_from_payload(payload: Mapping[str, Any]) -> bool:
    markers = ("plus_trial_eligible", "plusTrialEligible", "eligible_for_plus", "eligible")
    if any(bool(payload.get(key)) for key in markers):
        return True
    campaigns = payload.get("eligible_promo_campaigns")
    if isinstance(campaigns, Mapping):
        return bool(campaigns.get("plus"))
    accounts = payload.get("accounts")
    if isinstance(accounts, Mapping):
        for value in accounts.values():
            if isinstance(value, Mapping) and _plus_trial_from_payload(value):
                return True
    return False


def twofa_activation_payload(enrollment: Mapping[str, Any]) -> tuple[str, str, dict[str, str]]:
    secret = clean(enrollment.get("secret"), 256).replace(" ", "").upper()
    session_id = clean(enrollment.get("session_id"), 256)
    if not secret or not session_id:
        raise FreeRegisterError(
            "free_twofa_enroll", "注册 Free 账号 2FA",
            "2FA enrollment 未返回 secret/session_id",
            error_code="free_twofa_enroll_response_invalid",
        )
    return secret, session_id, {
        "code": totp_code(secret),
        "factor_type": "totp",
        "session_id": session_id,
    }


def mfa_enabled_from_payload(payload: Any) -> bool:
    """Recognize the stable MFA status shapes without exposing factor data."""
    value = payload if isinstance(payload, Mapping) else {}
    if bool(value.get("mfa_enabled") or value.get("mfaEnabled")):
        return True
    factors = value.get("factors")
    if isinstance(factors, Mapping):
        totp = factors.get("totp")
        if isinstance(totp, (list, tuple)) and bool(totp):
            return True
        if isinstance(totp, Mapping) and bool(totp):
            return True
    return False


def password_retry_allowed(result: Mapping[str, Any] | None) -> bool:
    """Return whether a saved signup account may run password continuation.

    ``pending`` is the durable marker for an interrupted password operation.
    A passwordless signup is also eligible when its optional password step was
    explicitly disabled, because the account already has a Token and can be
    completed later without replaying registration.  Existing-login results
    are intentionally excluded: they require the account's real password and
    must never be treated as passwordless signups.
    """
    if not isinstance(result, Mapping):
        return False
    flow = str(result.get("account_flow") or "").strip().lower()
    if flow == "existing_login":
        return False
    status = password_status_from_result(result)
    if status == "pending":
        # Keep compatibility with older pending snapshots that predate the
        # explicit account_flow field, while still rejecting existing_login.
        return True
    if status != "disabled" or flow != "signup":
        return False
    registration_used = result.get("registration_password_used")
    if isinstance(registration_used, bool):
        used = registration_used
    elif isinstance(registration_used, (int, float)):
        used = registration_used != 0
    else:
        used = str(registration_used or "").strip().lower() in {
            "1", "true", "yes", "on", "enabled", "complete", "completed", "success",
        }
    return not bool(result.get("password")) and not used


def finalize_registration_result(
    result: Mapping[str, Any],
    *,
    driver: str,
    email: str = "",
    password_used: bool | None = None,
) -> dict[str, Any]:
    """Apply the shared password/result contract to a driver result."""
    normalized = dict(result)
    normalized["driver"] = clean(driver, 32)
    if email:
        normalized.setdefault("email", clean(email, 320))
    account_flow = clean(normalized.get("account_flow"), 32) or "signup"
    # This marker is deliberately independent from ``password_status``:
    # ``enabled`` also describes a password entered on the original signup
    # page.  Inferring the post-registration operation from that status makes
    # a completed password signup look pending again on the next retry.
    password_set_after_registration = bool(normalized.get("password_set_after_registration"))
    if password_used is None:
        # Current drivers always emit the explicit marker.  A few legacy
        # transport adapters predate it and only return ``signup + password``;
        # infer that narrow shape for backwards compatibility while keeping
        # passwordless results password-free.
        if "registration_password_used" in normalized:
            used = bool(normalized.get("registration_password_used"))
        else:
            used = account_flow == "signup" and bool(normalized.get("password"))
    else:
        used = bool(password_used)
    # ``password_used`` historically described only the signup password page.
    # A password added after a passwordless signup is equally valid account
    # evidence and must survive the common result normalizer.
    used = bool(used or (account_flow == "signup" and password_set_after_registration))
    normalized["registration_password_used"] = used
    if account_flow != "signup" or not used:
        normalized.pop("password", None)
        normalized.pop("credential_line", None)
    elif not normalized.get("password"):
        normalized["password"] = FIXED_PASSWORD
    if normalized.get("totp_secret") and account_flow == "signup" and used:
        normalized["credential_line"] = (
            f"{normalized.get('email') or email}----{normalized['password']}----{normalized['totp_secret']}"
        )
    elif account_flow == "signup" and used and normalized.get("password"):
        # Password-only exports are intentionally a two-field credential.  The
        # mailbox URL remains available through the dedicated private mailbox
        # endpoint/transfer format and is never copied into public task state.
        normalized["credential_line"] = (
            f"{normalized.get('email') or email}----{normalized['password']}"
        )
    return normalized


__all__ = [
    "MAX_TOKEN_CHARS",
    "finalize_registration_result",
    "mfa_enabled_from_payload",
    "normalize_session",
    "password_retry_allowed",
    "plan_details_from_payloads",
    "plan_details_with_fallbacks",
    "session_token",
    "twofa_activation_payload",
]
