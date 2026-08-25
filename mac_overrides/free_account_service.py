"""Shared account semantics for the isolated Free registration drivers.

The protocol, RoxyBrowser and Camoufox drivers use different transports, but
they must expose the same Session, MFA, plan and result contract.  This module
contains only transport-neutral helpers; it never owns an HTTP session or a
browser context.
"""

from __future__ import annotations

import json
import asyncio
import time
from typing import Any, Callable, Mapping

try:
    from .chatgpt_plan_gate import plan_from_accounts_check
    from .chatgpt_totp import totp_code
    from .free_register_common import FIXED_PASSWORD, FreeRegisterError, clean
    from .free_roxy_session import session_token
except ImportError:  # pragma: no cover - top-level recovery import
    from chatgpt_plan_gate import plan_from_accounts_check  # type: ignore[no-redef]
    from chatgpt_totp import totp_code  # type: ignore[no-redef]
    from free_register_common import FIXED_PASSWORD, FreeRegisterError, clean  # type: ignore[no-redef]
    from free_roxy_session import session_token  # type: ignore[no-redef]


CHATGPT_ACCOUNTS_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
CHATGPT_ELIGIBILITY_URL = "https://chatgpt.com/backend-api/aip/first-party/eligibility"
CHATGPT_ME_URL = "https://chatgpt.com/backend-api/me"
CHATGPT_WHAM_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
MFA_ENROLL_URL = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
MFA_ACTIVATE_URL = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"


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


async def browser_plan_details(page: Any, token: str) -> dict[str, Any]:
    """Query browser same-origin plan endpoints with aBai's fallback order."""
    accounts_url = CHATGPT_ACCOUNTS_URL
    if "?" not in accounts_url:
        accounts_url += "?timezone_offset_min=-"
    accounts = await browser_json_fetch(page, accounts_url, token=token)
    eligibility = await browser_json_fetch(page, CHATGPT_ELIGIBILITY_URL, token=token)
    fallbacks: list[tuple[str, Any]] = []
    if plan_details_from_payloads(accounts, eligibility).get("plan_check_status") != "success":
        me = await browser_json_fetch(page, CHATGPT_ME_URL, token=token)
        fallbacks.append(("backend-api/me", me))
        if _fallback_plan(me):
            return plan_details_with_fallbacks(accounts, eligibility, fallbacks)
        usage = await browser_json_fetch(page, CHATGPT_WHAM_USAGE_URL, token=token)
        fallbacks.append(("backend-api/wham/usage", usage))
    return plan_details_with_fallbacks(accounts, eligibility, fallbacks)


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
    return normalized


async def browser_json_fetch(
    page: Any,
    url: str,
    *,
    method: str = "GET",
    token: str = "",
    body: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Fetch same-origin/account JSON from an async browser page."""
    script = """
    async ({url, method, token, body}) => {
      try {
        const headers = {accept: 'application/json'};
        if (token) headers.authorization = 'Bearer ' + token;
        if (url.includes('/backend-api/accounts/check/')) {
          headers['x-openai-target-path'] = '/backend-api/accounts/check/v4-2023-04-27';
          headers['x-openai-target-route'] = '/backend-api/accounts/check/v4-2023-04-27';
        }
        if (body !== null) headers['content-type'] = 'application/json';
        const response = await fetch(url, {
          method, credentials: 'include', headers,
          body: body === null ? undefined : JSON.stringify(body),
          cache: 'no-store'
        });
        const text = await response.text();
        let payload = {};
        try { payload = JSON.parse(text); } catch (_) {}
        return {ok: response.ok, status: response.status || 0,
          retry_after: String(response.headers.get('retry-after') || ''),
          content_type: String(response.headers.get('content-type') || ''),
          payload: payload && typeof payload === 'object' ? payload : {}};
      } catch (error) {
        return {ok: false, status: 0, payload: {}, error: String(error || 'fetch failed').slice(0, 160)};
      }
    }
    """
    result = await page.evaluate(script, {"url": url, "method": method, "token": token, "body": dict(body) if body is not None else None})
    return dict(result) if isinstance(result, Mapping) else {"ok": False, "status": 0, "payload": {}}


async def browser_session(page: Any) -> dict[str, Any]:
    deadline = time.monotonic() + 45
    last_status = 0
    last_code = "session_http_failed"
    while time.monotonic() < deadline:
        result = await browser_json_fetch(page, "https://chatgpt.com/api/auth/session")
        last_status = _status(result)
        last_code = _provider_code(result, "session_http_failed")
        if last_status == 200:
            try:
                return normalize_session(result.get("payload"))
            except FreeRegisterError:
                last_code = "session_token_missing"
        await asyncio.sleep(1.5)
    raise FreeRegisterError(
        "free_access_token", "获取 Free access token",
        f"浏览器 Session 返回 HTTP {last_status or '-'} 或未返回 access token",
        provider_status=last_status or None,
        provider_code=last_code,
        error_code="free_session_http_failed" if last_status != 200 else "free_session_token_missing",
    )


async def browser_twofa(page: Any, token: str) -> str:
    enrolled = await browser_json_fetch(page, MFA_ENROLL_URL, method="POST", token=token, body={"factor_type": "totp"})
    if not enrolled.get("ok"):
        raise FreeRegisterError(
            "free_twofa_enroll", "注册 Free 账号 2FA", "浏览器内 2FA enrollment 失败",
            provider_status=_status(enrolled) or None,
            provider_code=_provider_code(enrolled, "mfa_enroll_rejected"),
            error_code="free_twofa_enroll_failed",
        )
    secret, _session_id, activation = twofa_activation_payload(_json_payload(enrolled))
    activated = await browser_json_fetch(page, MFA_ACTIVATE_URL, method="POST", token=token, body=activation)
    value = _json_payload(activated)
    if not activated.get("ok") or not bool(value.get("success")):
        raise FreeRegisterError(
            "free_twofa_activate", "激活 Free 账号 2FA", "浏览器内 2FA activation 未确认",
            provider_status=_status(activated) or None,
            provider_code=_provider_code(activated, "mfa_activate_rejected"),
            error_code="free_twofa_activate_failed",
        )
    return secret


__all__ = [
    "CHATGPT_ACCOUNTS_URL", "CHATGPT_ELIGIBILITY_URL", "CHATGPT_ME_URL", "CHATGPT_WHAM_USAGE_URL",
    "MFA_ENROLL_URL", "MFA_ACTIVATE_URL", "browser_json_fetch", "browser_plan_details",
    "browser_session", "browser_twofa", "finalize_registration_result", "normalize_session",
    "plan_details_from_payloads", "plan_details_with_fallbacks", "twofa_activation_payload",
]
