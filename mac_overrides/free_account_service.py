"""Shared account semantics for the isolated Free registration drivers.

Payload parsing, plan/session semantics and the bounded OTP callback runner
live in ``free_account_payload`` / ``free_account_otp``; this module keeps the
browser flows and re-exports the moved names for compatibility.
"""

from __future__ import annotations

import asyncio
import inspect
import math
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlencode, urlsplit

try:
    from .chatgpt_totp import totp_code
    from .free_account_payload import (
        MAX_TOKEN_CHARS,
        finalize_registration_result,
        mfa_enabled_from_payload,
        normalize_session,
        password_retry_allowed,
        plan_details_from_payloads,
        plan_details_with_fallbacks,
        session_token,
        twofa_activation_payload,
        _fallback_plan,
        _json_payload,
        _plus_trial_from_payload,
        _provider_code,
        _response_continue_url,
        _retry_after,
        _status,
    )
    from .free_account_otp import (
        _await_account_otp_callback,
        _invoke_staged_otp_callback,
        _otp_stop_requested,
    )
    from .free_register_common import FIXED_PASSWORD, FreeRegisterError, clean
    from .free_timing import emit_timing
except ImportError:  # pragma: no cover - top-level recovery import
    from chatgpt_totp import totp_code  # type: ignore[no-redef]
    from free_account_payload import (  # type: ignore[no-redef]
        MAX_TOKEN_CHARS,
        finalize_registration_result,
        mfa_enabled_from_payload,
        normalize_session,
        password_retry_allowed,
        plan_details_from_payloads,
        plan_details_with_fallbacks,
        session_token,
        twofa_activation_payload,
        _fallback_plan,
        _json_payload,
        _plus_trial_from_payload,
        _provider_code,
        _response_continue_url,
        _retry_after,
        _status,
    )
    from free_account_otp import (  # type: ignore[no-redef]
        _await_account_otp_callback,
        _invoke_staged_otp_callback,
        _otp_stop_requested,
    )
    from free_register_common import FIXED_PASSWORD, FreeRegisterError, clean  # type: ignore[no-redef]
    from free_timing import emit_timing  # type: ignore[no-redef]


CHATGPT_ACCOUNTS_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
CHATGPT_ELIGIBILITY_URL = "https://chatgpt.com/backend-api/aip/first-party/eligibility"
CHATGPT_ME_URL = "https://chatgpt.com/backend-api/me"
CHATGPT_WHAM_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
MFA_ENROLL_URL = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
MFA_ACTIVATE_URL = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
MFA_INFO_URL = "https://chatgpt.com/backend-api/accounts/mfa_info"
ADD_PASSWORD_ELIGIBILITY_URL = "https://chatgpt.com/backend-api/accounts/add_password/eligibility"
AUTH_CSRF_URL = "https://chatgpt.com/api/auth/csrf"
AUTH_SIGNIN_URL = "https://chatgpt.com/api/auth/signin/openai"
AUTH_EMAIL_OTP_VALIDATE_URL = "https://auth.openai.com/api/accounts/email-otp/validate"
AUTH_PASSWORD_ADD_URL = "https://auth.openai.com/api/accounts/password/add"


async def browser_plan_details(
    page: Any,
    token: str,
    *,
    timing_fn: Callable[..., Any] | None = None,
    timing_stage: str = "free_access_token",
) -> dict[str, Any]:
    """Query browser same-origin plan endpoints with aBai's fallback order."""
    accounts_url = CHATGPT_ACCOUNTS_URL
    if "?" not in accounts_url:
        accounts_url += "?timezone_offset_min=-"
    accounts = await browser_json_fetch(
        page,
        accounts_url,
        token=token,
        timing_fn=timing_fn,
        timing_stage=timing_stage,
        timing_code="plan_accounts_fetch",
    )
    eligibility = await browser_json_fetch(
        page,
        CHATGPT_ELIGIBILITY_URL,
        token=token,
        timing_fn=timing_fn,
        timing_stage=timing_stage,
        timing_code="plan_eligibility_fetch",
    )
    fallbacks: list[tuple[str, Any]] = []
    if plan_details_from_payloads(accounts, eligibility).get("plan_check_status") != "success":
        me = await browser_json_fetch(
            page,
            CHATGPT_ME_URL,
            token=token,
            timing_fn=timing_fn,
            timing_stage=timing_stage,
            timing_code="plan_fallback_fetch",
        )
        fallbacks.append(("backend-api/me", me))
        if _fallback_plan(me):
            return plan_details_with_fallbacks(accounts, eligibility, fallbacks)
        usage = await browser_json_fetch(
            page,
            CHATGPT_WHAM_USAGE_URL,
            token=token,
            timing_fn=timing_fn,
            timing_stage=timing_stage,
            timing_code="plan_fallback_fetch",
        )
        fallbacks.append(("backend-api/wham/usage", usage))
    return plan_details_with_fallbacks(accounts, eligibility, fallbacks)


async def browser_json_fetch(
    page: Any,
    url: str,
    *,
    method: str = "GET",
    token: str = "",
    body: Mapping[str, Any] | None = None,
    form: bool = False,
    timing_fn: Callable[..., Any] | None = None,
    timing_stage: str = "",
    timing_code: str = "",
) -> dict[str, Any]:
    """Fetch same-origin/account JSON from an async browser page."""
    started = time.monotonic()
    script = """
    async ({url, method, token, body, form}) => {
      try {
        const headers = {accept: 'application/json'};
        if (token) headers.authorization = 'Bearer ' + token;
        if (url.includes('/backend-api/accounts/check/')) {
          headers['x-openai-target-path'] = '/backend-api/accounts/check/v4-2023-04-27';
          headers['x-openai-target-route'] = '/backend-api/accounts/check/v4-2023-04-27';
        }
        if (body !== null) headers['content-type'] = form
          ? 'application/x-www-form-urlencoded'
          : 'application/json';
        const requestBody = body === null ? undefined : (form
          ? new URLSearchParams(Object.entries(body).map(([key, value]) => [key, String(value ?? '')])).toString()
          : JSON.stringify(body));
        const response = await fetch(url, {
          method, credentials: 'include', headers,
          body: requestBody,
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
    try:
        result = await page.evaluate(script, {"url": url, "method": method, "token": token, "body": dict(body) if body is not None else None, "form": bool(form)})
    except Exception:
        emit_timing(timing_fn, timing_stage, timing_code, (time.monotonic() - started) * 1000, "error")
        raise
    normalized = dict(result) if isinstance(result, Mapping) else {"ok": False, "status": 0, "payload": {}}
    if timing_code:
        emit_timing(
            timing_fn,
            timing_stage,
            timing_code,
            (time.monotonic() - started) * 1000,
            "success" if normalized.get("ok") else "error",
        )
    return normalized


async def browser_session(
    page: Any,
    *,
    timing_fn: Callable[..., Any] | None = None,
    timing_stage: str = "free_access_token",
) -> dict[str, Any]:
    deadline = time.monotonic() + 45
    last_status = 0
    last_code = "session_http_failed"
    while time.monotonic() < deadline:
        result = await browser_json_fetch(
            page,
            "https://chatgpt.com/api/auth/session",
            timing_fn=timing_fn,
            timing_stage=timing_stage,
            timing_code="session_fetch",
        )
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


async def browser_add_password(
    page: Any,
    token: str,
    email: str,
    password: str,
    *,
    otp_callback: Callable[..., Any],
    otp_prepare: Callable[..., Any] | None = None,
    otp_mark_sent: Callable[..., Any] | None = None,
    stage_fn: Callable[[str], Any] | None = None,
    task_id: str = "",
    device_id: str = "",
    deadline_monotonic: float | None = None,
    deadline_controller: Any | None = None,
    stop_requested: Callable[[], bool] | None = None,
    timing_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Set a password from an authenticated browser context.

    The browser transport follows the same HAR sequence as the protocol
    adapter.  Auth endpoints are called from the auth.openai.com page with
    browser cookies; the ChatGPT bearer token is used only for the eligibility
    request.  A separate OTP preparation/mark/wait cycle is mandatory, so this
    helper can safely run before or after browser 2FA enrollment.
    """
    email_value = str(email or "")
    password_value = str(password or FIXED_PASSWORD)

    def stage(code: str) -> None:
        if callable(stage_fn):
            try:
                stage_fn(str(code))
            except Exception:
                pass

    def failure(
        node_code: str,
        node_label: str,
        message: str,
        response: Mapping[str, Any] | None = None,
        *,
        retryable: bool = True,
    ) -> FreeRegisterError:
        return FreeRegisterError(
            node_code,
            node_label,
            message,
            retryable=retryable,
            provider_status=_status(response) if isinstance(response, Mapping) else None,
            provider_code=_provider_code(response, "") if isinstance(response, Mapping) else "",
            error_code=f"{node_code}_failed",
            action_hint="保留账号和 Token，稍后重试密码设置",
        )

    async def invoke(callback: Callable[..., Any], stage_code: str) -> Any:
        """Support legacy no-arg callbacks and the current staged callback."""
        if not callable(callback):
            raise failure(
                "free_password_otp_wait",
                "等待密码设置邮箱验证码",
                "未提供密码设置邮箱验证码回调",
                retryable=False,
            )
        try:
            return await _await_account_otp_callback(
                callback,
                stage_code,
                stop_requested=stop_requested,
                deadline_monotonic=deadline_monotonic,
                deadline_controller=deadline_controller,
            )
        except TypeError as exc:
            # Keep the public node stable for an unsupported legacy adapter;
            # TypeErrors raised inside a supported callback are delivered as
            # the callback's own exception and are not replayed.
            if str(exc) == "unsupported OTP callback signature":
                raise failure(
                    "free_password_otp_wait",
                    "等待密码设置邮箱验证码",
                    "邮箱验证码回调签名不受支持",
                    retryable=False,
                ) from exc
            raise

    async def call_prepare() -> None:
        # A registration OTP request may still be active when the home page is
        # reached. End that phase before taking the password-operation
        # baseline so the second security action cannot reuse its snapshot.
        provider = getattr(otp_prepare, "__self__", None)
        state = getattr(provider, "state", None)
        if state is None:
            service = getattr(provider, "service", None)
            state = getattr(service, "state", None)
        finish_request = getattr(state, "finish_request", None)
        if callable(finish_request) and bool(getattr(state, "active", False)):
            finish_request()
        if not callable(otp_prepare):
            return
        try:
            signature = inspect.signature(otp_prepare)
        except (TypeError, ValueError):
            await asyncio.to_thread(otp_prepare, "free_password_otp_wait", force_snapshot=True)
            return
        for kwargs in (
            {"force_snapshot": True, "notify_stage": False},
            {"force_snapshot": True},
            {},
        ):
            try:
                signature.bind("free_password_otp_wait", **kwargs)
            except TypeError:
                continue
            await asyncio.to_thread(otp_prepare, "free_password_otp_wait", **kwargs)
            return
        raise failure(
            "free_password_otp_wait",
            "准备密码设置邮箱验证码",
            "邮箱 provider 准备签名不受支持",
            retryable=False,
        )

    async def call_mark_sent() -> None:
        if not callable(otp_mark_sent):
            return
        try:
            await asyncio.to_thread(otp_mark_sent, "free_password_otp_wait")
        except TypeError:
            await asyncio.to_thread(otp_mark_sent)

    async def navigate(url: str, *, timeout_ms: int = 45_000) -> Any:
        goto = getattr(page, "goto", None)
        if not callable(goto):
            raise failure(
                "free_password_reauth_authorize",
                "打开密码设置授权页面",
                "浏览器页面不支持授权跳转",
                retryable=True,
            )
        try:
            return await goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except TypeError:
            try:
                return await goto(url, timeout=timeout_ms)
            except Exception as exc:
                raise failure(
                    "free_password_reauth_authorize",
                    "打开密码设置授权页面",
                    f"密码设置授权页面跳转失败（{type(exc).__name__}）",
                ) from exc
        except Exception as exc:
            raise failure(
                "free_password_reauth_authorize",
                "打开密码设置授权页面",
                f"密码设置授权页面跳转失败（{type(exc).__name__}）",
            ) from exc

    # Eligibility is the sole ChatGPT-side gate.  An explicit false response
    # is a normal no-op; do not open a new auth session in that case.
    eligibility = await browser_json_fetch(
        page,
        ADD_PASSWORD_ELIGIBILITY_URL,
        token=str(token or ""),
        timing_fn=timing_fn,
        timing_stage="free_plan_check",
        timing_code="password_eligibility_fetch",
    )
    if not eligibility.get("ok") and _status(eligibility) not in {0}:
        raise failure(
            "free_password_eligibility",
            "检查 Free 账号密码资格",
            "密码资格接口返回失败",
            eligibility,
        )
    eligibility_payload = _json_payload(eligibility.get("payload"))
    if isinstance(eligibility_payload, Mapping) and eligibility_payload.get("eligible") is False:
        return {"password_status": "disabled", "password_set_after_registration": False}

    # The first request that can issue the auth OTP is the signin/authorize
    # sequence. Capture a fresh mailbox baseline before it starts.
    await call_prepare()
    stage("free_password_reauth_csrf")
    csrf = await browser_json_fetch(
        page, AUTH_CSRF_URL,
        timing_fn=timing_fn, timing_stage="free_password_reauth_csrf", timing_code="auth_csrf_fetch",
    )
    csrf_payload = _json_payload(csrf.get("payload"))
    csrf_token = str(csrf_payload.get("csrfToken") or "") if isinstance(csrf_payload, Mapping) else ""
    if not csrf.get("ok") or not csrf_token:
        raise failure(
            "free_password_reauth_csrf",
            "密码设置重认证 CSRF",
            "密码设置重认证 CSRF 响应无效",
            csrf,
        )

    stage("free_password_reauth_signin")
    device_id = str(device_id or "") or str(getattr(page, "device_id", "") or "") or str(
        (getattr(page, "_gptphone_device_id", "") or "")
    )
    if not device_id:
        # The browser context normally receives this from the task runner;
        # keeping the field optional preserves compatibility with old page
        # doubles while still allowing the production caller to provide the
        # exact per-context device id.
        device_id = str(getattr(page, "context_device_id", "") or "")
    # A browser page normally carries the device id in the ChatGPT cookies;
    # use a stable per-context value when the adapter exposes one, otherwise
    # let the server infer it from the existing session.
    # The password-reset HAR does not include the legacy ``connection``
    # selector.  Auth derives the connection from ``reauth`` and the
    # post-login continuation flag; sending the extra selector can route the
    # request through the wrong state machine.
    signin_query = (
        "login_hint="
        + quote(email_value, safe="")
        + "&reauth=password&post_login_add_password=true&max_age=0"
    )
    if device_id:
        signin_query += "&ext-oai-did=" + quote(device_id, safe="")
    signin = await browser_json_fetch(
        page,
        f"{AUTH_SIGNIN_URL}?{signin_query}",
        method="POST",
        body={"callbackUrl": "https://chatgpt.com/", "csrfToken": csrf_token, "json": "true"},
        form=True,
        timing_fn=timing_fn,
        timing_stage="free_password_reauth_signin",
        timing_code="auth_signin_fetch",
    )
    signin_payload = _json_payload(signin.get("payload"))
    auth_url = str(signin_payload.get("url") or "") if isinstance(signin_payload, Mapping) else ""
    try:
        auth_parts = urlsplit(auth_url)
    except (TypeError, ValueError):
        auth_parts = None
    if not signin.get("ok") or auth_parts is None or auth_parts.scheme.casefold() != "https" or (auth_parts.hostname or "").casefold() != "auth.openai.com":
        raise failure(
            "free_password_reauth_signin",
            "启动密码设置重认证",
            "密码设置重认证未返回有效 authorize 地址",
            signin,
        )

    stage("free_password_reauth_authorize")
    await navigate(auth_url)
    await call_mark_sent()
    stage("free_password_otp_wait")
    code = str(await invoke(otp_callback, "free_password_otp_wait") or "").strip()
    if not code:
        raise failure(
            "free_password_otp_wait",
            "等待密码设置邮箱验证码",
            "未获取到密码设置邮箱验证码",
        )

    stage("free_password_otp_validate")
    validated = await browser_json_fetch(
        page,
        AUTH_EMAIL_OTP_VALIDATE_URL,
        method="POST",
        body={"code": code},
        timing_fn=timing_fn,
        timing_stage="free_password_otp_validate",
        timing_code="otp_validate_fetch",
    )
    validated_payload = _json_payload(validated.get("payload"))
    if not validated.get("ok"):
        raise failure(
            "free_password_otp_validate",
            "验证密码设置邮箱验证码",
            "密码设置邮箱验证码验证失败",
            validated,
        )
    reset_url = _response_continue_url(validated)
    try:
        reset_parts = urlsplit(reset_url)
    except (TypeError, ValueError):
        reset_parts = None
    if reset_parts is None or reset_parts.scheme.casefold() != "https" or (reset_parts.hostname or "").casefold() != "auth.openai.com" or not reset_parts.path.startswith("/reset-password/"):
        raise failure(
            "free_password_otp_validate",
            "验证密码设置邮箱验证码",
            "验证码响应缺少新密码 continuation",
            validated,
        )

    stage("free_password_enroll")
    await navigate(reset_url)
    stage("free_password_add")
    added = await browser_json_fetch(
        page,
        AUTH_PASSWORD_ADD_URL,
        method="POST",
        body={"password": password_value},
        timing_fn=timing_fn,
        timing_stage="free_password_add",
        timing_code="password_add_fetch",
    )
    added_payload = _json_payload(added.get("payload"))
    if not added.get("ok"):
        raise failure(
            "free_password_add",
            "提交 Free 账号密码",
            "密码添加接口返回失败",
            added,
        )
    callback_url = _response_continue_url(added)
    try:
        callback_parts = urlsplit(callback_url)
    except (TypeError, ValueError):
        callback_parts = None
    if callback_parts is None or callback_parts.scheme.casefold() != "https" or (callback_parts.hostname or "").casefold() != "chatgpt.com" or not callback_parts.path.startswith("/api/auth/callback/"):
        raise failure(
            "free_password_callback",
            "刷新密码设置会话",
            "密码添加响应缺少 ChatGPT callback",
            added,
        )
    stage("free_password_callback")
    callback_started = time.monotonic()
    try:
        await navigate(callback_url)
    except Exception:
        emit_timing(timing_fn, "free_password_callback", "oauth_callback_navigation", (time.monotonic() - callback_started) * 1000, "error")
        raise
    emit_timing(timing_fn, "free_password_callback", "oauth_callback_navigation", (time.monotonic() - callback_started) * 1000, "success")
    if callable(timing_fn):
        refreshed = await browser_session(
            page, timing_fn=timing_fn, timing_stage="free_password_callback",
        )
    else:
        refreshed = await browser_session(page)
    active_token = str(refreshed.get("accessToken") or token or "")
    if not active_token:
        raise failure(
            "free_password_callback",
            "刷新密码设置会话",
            "密码设置 callback 后未取得 Session Token",
            refreshed,
        )
    return {
        "password_status": "enabled",
        "password_set_after_registration": True,
        "password": password_value,
        "access_token": active_token,
        "has_access_token": True,
    }


async def browser_twofa(
    page: Any,
    token: str,
    email: str = "",
    *,
    otp_callback: Callable[..., Any] | None = None,
    otp_prepare: Callable[..., Any] | None = None,
    otp_mark_sent: Callable[..., Any] | None = None,
    stage_fn: Callable[[str], Any] | None = None,
    task_id: str = "",
    device_id: str = "",
    deadline_monotonic: float | None = None,
    deadline_controller: Any | None = None,
    stop_requested: Callable[[], bool] | None = None,
    timing_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Enroll browser 2FA through a fresh password re-authentication.

    The browser must perform the same state transition as the protocol
    driver: CSRF/signin on ``chatgpt.com``, authorize navigation on
    ``auth.openai.com`` (which sends a new email OTP), OTP validation and
    callback navigation, then MFA enrollment with the refreshed Session
    token.  This helper deliberately does not share the password helper's
    state and never asks ``mfa_info`` until after the re-authentication has
    completed.
    """
    email_value = str(email or "").strip()
    active_token = str(token or "").strip()

    def stage(code: str) -> None:
        if callable(stage_fn):
            try:
                stage_fn(str(code))
            except Exception:
                pass

    def failure(
        node_code: str,
        node_label: str,
        message: str,
        response: Mapping[str, Any] | None = None,
        *,
        retryable: bool = True,
    ) -> FreeRegisterError:
        return FreeRegisterError(
            node_code,
            node_label,
            message,
            retryable=retryable,
            provider_status=_status(response) if isinstance(response, Mapping) else None,
            provider_code=_provider_code(response, "") if isinstance(response, Mapping) else "",
            error_code=f"{node_code}_failed",
            action_hint="保留账号和 Token，稍后重试 2FA 设置",
        )

    async def invoke_otp(stage_code: str) -> Any:
        if not callable(otp_callback):
            raise failure(
                "free_twofa_otp_wait",
                "等待 2FA 邮箱验证码",
                "未提供 2FA 邮箱验证码回调",
                retryable=False,
            )
        try:
            return await _await_account_otp_callback(
                otp_callback,
                stage_code,
                stop_requested=stop_requested,
                deadline_monotonic=deadline_monotonic,
                deadline_controller=deadline_controller,
            )
        except TypeError as exc:
            if str(exc) == "unsupported OTP callback signature":
                raise failure(
                    "free_twofa_otp_wait",
                    "等待 2FA 邮箱验证码",
                    "邮箱验证码回调签名不受支持",
                    retryable=False,
                ) from exc
            raise

    async def prepare_otp() -> None:
        # The registration OTP request can still be marked active when the
        # home page is reached. Close that phase before taking the mandatory
        # 2FA baseline, otherwise stale messages can be selected.
        state = getattr(getattr(otp_prepare, "__self__", None), "state", None)
        service = getattr(otp_prepare, "__self__", None)
        if state is None:
            service = getattr(getattr(otp_prepare, "__self__", None), "service", None)
            state = getattr(service, "state", None)
        finish_request = getattr(state, "finish_request", None)
        if callable(finish_request) and bool(getattr(state, "active", False)):
            finish_request()
        if not callable(otp_prepare):
            return
        try:
            signature = inspect.signature(otp_prepare)
        except (TypeError, ValueError):
            await asyncio.to_thread(otp_prepare, "free_twofa_enroll", force_snapshot=True)
            return
        for kwargs in (
            {"force_snapshot": True, "notify_stage": False},
            {"force_snapshot": True},
            {},
        ):
            try:
                signature.bind("free_twofa_enroll", **kwargs)
            except TypeError:
                continue
            await asyncio.to_thread(otp_prepare, "free_twofa_enroll", **kwargs)
            return
        raise failure(
            "free_twofa_otp_wait",
            "准备 2FA 邮箱验证码",
            "邮箱 provider 准备签名不受支持",
            retryable=False,
        )

    async def mark_otp_sent() -> None:
        if not callable(otp_mark_sent):
            return
        try:
            signature = inspect.signature(otp_mark_sent)
        except (TypeError, ValueError):
            await asyncio.to_thread(otp_mark_sent, "free_twofa_enroll")
            return
        for args in (("free_twofa_enroll",), ()):
            try:
                signature.bind(*args)
            except TypeError:
                continue
            await asyncio.to_thread(otp_mark_sent, *args)
            return
        raise failure(
            "free_twofa_otp_wait",
            "发送 2FA 邮箱验证码",
            "邮箱 provider 标记签名不受支持",
            retryable=False,
        )

    async def navigate(url: str, node_code: str, node_label: str) -> Any:
        goto = getattr(page, "goto", None)
        if not callable(goto):
            raise failure(node_code, node_label, "浏览器页面不支持授权跳转")
        timeout_ms = 45_000
        try:
            controller_remaining = getattr(deadline_controller, "remaining", None)
            controller_paused = getattr(deadline_controller, "is_paused", None)
            controller_grace = getattr(deadline_controller, "manual_submission_grace_active", None)
            controller_grace_remaining = getattr(
                deadline_controller, "manual_submission_grace_remaining", None,
            )
        except Exception:
            controller_remaining = controller_paused = None
            controller_grace = controller_grace_remaining = None
        controller_budget = False
        try:
            paused = bool(controller_paused()) if callable(controller_paused) else False
        except Exception:
            paused = False
        try:
            grace_active = bool(controller_grace()) if callable(controller_grace) else False
        except Exception:
            grace_active = False
        if grace_active:
            grace_seconds: float | None = None
            if callable(controller_grace_remaining):
                try:
                    candidate = float(controller_grace_remaining())
                    if math.isfinite(candidate):
                        grace_seconds = max(0.0, candidate)
                except Exception:
                    pass
            if grace_seconds is None:
                # Older controllers expose only the boolean flag. Keep the
                # same finite handoff allowance for those adapters.
                grace_seconds = MANUAL_SUBMISSION_GRACE_SECONDS
            timeout_ms = max(1_000, min(timeout_ms, int(max(0.0, grace_seconds) * 1000)))
            controller_budget = True
        if callable(controller_remaining) and not paused and not controller_budget:
            try:
                timeout_ms = max(1_000, min(timeout_ms, int(float(controller_remaining()) * 1000)))
                controller_budget = True
            except Exception:
                pass
        if deadline_monotonic is not None and not controller_budget and not paused:
            try:
                timeout_ms = max(1_000, min(timeout_ms, int((float(deadline_monotonic) - time.monotonic()) * 1000)))
            except (TypeError, ValueError, OverflowError):
                pass
        try:
            return await goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except TypeError:
            try:
                return await goto(url, timeout=timeout_ms)
            except Exception as exc:
                raise failure(node_code, node_label, f"2FA 页面跳转失败（{type(exc).__name__}）") from exc
        except Exception as exc:
            raise failure(node_code, node_label, f"2FA 页面跳转失败（{type(exc).__name__}）") from exc

    # Capture a new mailbox baseline before the signin/authorize request that
    # causes OpenAI to send the 2FA re-authentication code.
    await prepare_otp()
    stage("free_twofa_reauth_csrf")
    csrf = await browser_json_fetch(
        page, AUTH_CSRF_URL,
        timing_fn=timing_fn, timing_stage="free_twofa_reauth_csrf", timing_code="auth_csrf_fetch",
    )
    csrf_payload = _json_payload(csrf.get("payload"))
    csrf_token = str(csrf_payload.get("csrfToken") or "") if isinstance(csrf_payload, Mapping) else ""
    if not csrf.get("ok") or not csrf_token:
        raise failure(
            "free_twofa_reauth_csrf",
            "2FA 重认证 CSRF",
            "2FA 重认证 CSRF 响应无效",
            csrf,
        )

    stage("free_twofa_reauth_signin")
    resolved_device_id = str(device_id or "").strip() or str(getattr(page, "device_id", "") or "").strip()
    if not resolved_device_id:
        resolved_device_id = str(
            getattr(page, "_gptphone_device_id", "")
            or getattr(page, "context_device_id", "")
            or ""
        ).strip()
    signin_query = urlencode(
        {
            "connection": "password",
            "login_hint": email_value,
            "reauth": "password",
            "max_age": "0",
            "ext-oai-did": resolved_device_id,
        }
    )
    signin = await browser_json_fetch(
        page,
        f"{AUTH_SIGNIN_URL}?{signin_query}",
        method="POST",
        body={
            "callbackUrl": "https://chatgpt.com/?action=enable&factor=totp",
            "csrfToken": csrf_token,
            "json": "true",
        },
        form=True,
        timing_fn=timing_fn,
        timing_stage="free_twofa_reauth_signin",
        timing_code="auth_signin_fetch",
    )
    signin_payload = _json_payload(signin.get("payload"))
    auth_url = _response_continue_url(signin_payload or signin)
    try:
        auth_parts = urlsplit(auth_url)
    except (TypeError, ValueError):
        auth_parts = None
    if (
        not signin.get("ok")
        or auth_parts is None
        or auth_parts.scheme.casefold() != "https"
        or (auth_parts.hostname or "").casefold() != "auth.openai.com"
    ):
        raise failure(
            "free_twofa_reauth_signin",
            "启动 2FA 重认证",
            "2FA 重认证未返回有效 authorize 地址",
            signin,
        )

    stage("free_twofa_reauth_authorize")
    await navigate(auth_url, "free_twofa_reauth_authorize", "打开 2FA 重认证授权页面")
    await mark_otp_sent()
    stage("free_twofa_otp_wait")
    code = str(await invoke_otp("free_twofa_enroll") or "").strip()
    if not code:
        raise failure(
            "free_twofa_otp_wait",
            "等待 2FA 邮箱验证码",
            "未获取到 2FA 邮箱验证码",
        )

    stage("free_twofa_otp_validate")
    validated = await browser_json_fetch(
        page,
        AUTH_EMAIL_OTP_VALIDATE_URL,
        method="POST",
        body={"code": code},
        timing_fn=timing_fn,
        timing_stage="free_twofa_otp_validate",
        timing_code="otp_validate_fetch",
    )
    if not validated.get("ok"):
        raise failure(
            "free_twofa_otp_validate",
            "验证 2FA 邮箱验证码",
            "2FA 重认证邮箱验证码验证失败",
            validated,
        )
    continue_url = _response_continue_url(validated)
    try:
        callback_parts = urlsplit(continue_url)
    except (TypeError, ValueError):
        callback_parts = None
    if (
        callback_parts is None
        or callback_parts.scheme.casefold() != "https"
        or (callback_parts.hostname or "").casefold() != "chatgpt.com"
        or not callback_parts.path.startswith("/api/auth/callback/")
    ):
        raise failure(
            "free_twofa_otp_validate",
            "验证 2FA 邮箱验证码",
            "2FA 验证响应缺少 ChatGPT OAuth callback",
            validated,
        )

    stage("free_twofa_reauth_callback")
    callback_started = time.monotonic()
    try:
        await navigate(continue_url, "free_twofa_reauth_callback", "刷新 2FA 重认证会话")
    except Exception:
        emit_timing(timing_fn, "free_twofa_reauth_callback", "oauth_callback_navigation", (time.monotonic() - callback_started) * 1000, "error")
        raise
    emit_timing(timing_fn, "free_twofa_reauth_callback", "oauth_callback_navigation", (time.monotonic() - callback_started) * 1000, "success")
    if callable(timing_fn):
        refreshed = await browser_session(
            page, timing_fn=timing_fn, timing_stage="free_twofa_reauth_callback",
        )
    else:
        refreshed = await browser_session(page)
    refreshed_token = str(refreshed.get("accessToken") or "").strip()
    if refreshed_token:
        active_token = refreshed_token
    if not active_token:
        raise failure(
            "free_twofa_reauth_callback",
            "刷新 2FA 重认证会话",
            "2FA OAuth callback 后未取得 Session Token",
            refreshed,
        )

    # Idempotency is checked only after the fresh re-authentication.  The
    # password helper above has no call to this endpoint at all.
    current = await browser_json_fetch(
        page, MFA_INFO_URL, token=active_token,
        timing_fn=timing_fn, timing_stage="free_twofa_enroll", timing_code="mfa_info_fetch",
    )
    if current.get("ok") and mfa_enabled_from_payload(current.get("payload")):
        return {
            "twofa_status": "enabled",
            "access_token": active_token,
            "has_access_token": True,
        }

    enrolled = await browser_json_fetch(
        page,
        MFA_ENROLL_URL,
        method="POST",
        token=active_token,
        body={"factor_type": "totp"},
        timing_fn=timing_fn,
        timing_stage="free_twofa_enroll",
        timing_code="mfa_enroll_fetch",
    )
    if not enrolled.get("ok"):
        raise failure(
            "free_twofa_enroll",
            "注册 Free 账号 2FA",
            "浏览器内 2FA enrollment 失败",
            enrolled,
        )
    secret, _session_id, activation = twofa_activation_payload(_json_payload(enrolled))
    activated = await browser_json_fetch(
        page,
        MFA_ACTIVATE_URL,
        method="POST",
        token=active_token,
        body=activation,
        timing_fn=timing_fn,
        timing_stage="free_twofa_activate",
        timing_code="mfa_activate_fetch",
    )
    value = _json_payload(activated)
    if not activated.get("ok") or not bool(value.get("success")):
        # The activation response can be lost after the server commits it.
        # Confirm the authoritative state before reporting a retryable failure.
        confirmed = await browser_json_fetch(
            page, MFA_INFO_URL, token=active_token,
            timing_fn=timing_fn, timing_stage="free_twofa_activate", timing_code="mfa_info_fetch",
        )
        if confirmed.get("ok") and mfa_enabled_from_payload(confirmed.get("payload")):
            return {
                "twofa_status": "enabled",
                "totp_secret": secret,
                "access_token": active_token,
                "has_access_token": True,
            }
        raise failure(
            "free_twofa_activate",
            "激活 Free 账号 2FA",
            "浏览器内 2FA activation 未确认",
            activated,
        )
    return {
        "twofa_status": "enabled",
        "totp_secret": secret,
        "access_token": active_token,
        "has_access_token": True,
    }


__all__ = [
    "CHATGPT_ACCOUNTS_URL", "CHATGPT_ELIGIBILITY_URL", "CHATGPT_ME_URL", "CHATGPT_WHAM_USAGE_URL", "MFA_INFO_URL",
    "ADD_PASSWORD_ELIGIBILITY_URL", "AUTH_CSRF_URL", "AUTH_SIGNIN_URL",
    "AUTH_EMAIL_OTP_VALIDATE_URL", "AUTH_PASSWORD_ADD_URL",
    "MFA_ENROLL_URL", "MFA_ACTIVATE_URL", "browser_json_fetch", "browser_plan_details",
    "browser_session", "browser_add_password", "browser_twofa", "finalize_registration_result", "normalize_session",
    "plan_details_from_payloads", "plan_details_with_fallbacks", "twofa_activation_payload", "mfa_enabled_from_payload",
    "password_retry_allowed", "session_token",
]
