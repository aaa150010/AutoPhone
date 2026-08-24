"""Free protocol registration state machine.

The recovered chain contains a legacy ChatGPT signup prelude which combines a
NextAuth page bootstrap with ``user/register``.  That prelude is too eager to
reuse a stale login session.  This module keeps the Free workflow in a small,
testable state machine and uses the transport's ordinary OAuth endpoints in
the same order as the maintained protocol implementations.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import hmac
import inspect
import re
from typing import Any
from urllib.parse import urlsplit

try:
    from .free_protocol_diagnostics import (
        callback_matches_redirect as _callback_matches_redirect,
        callback_query as _callback_query,
        content_type as _content_type,
        next_url as _next_url,
        page_is_html as _page_is_html,
        page_location as _page_location,
        page_locations as _page_locations,
        page_type_value as _page_type_value,
        response_detail as _response_detail,
        response_metadata as _response_metadata,
        response_search_text as _response_search_text,
        response_status as _status,
        safe_url as _safe_callback_label,
    )
    from .free_register_common import (
        FIXED_PASSWORD,
        FreeRegisterError,
        random_birthdate,
        random_display_name,
        safe_log_message,
    )
except ImportError:  # pragma: no cover - compatibility import for recovered runtime
    from free_protocol_diagnostics import (  # type: ignore[no-redef]
        callback_matches_redirect as _callback_matches_redirect,
        callback_query as _callback_query,
        content_type as _content_type,
        next_url as _next_url,
        page_is_html as _page_is_html,
        page_location as _page_location,
        page_locations as _page_locations,
        page_type_value as _page_type_value,
        response_detail as _response_detail,
        response_metadata as _response_metadata,
        response_search_text as _response_search_text,
        response_status as _status,
        safe_url as _safe_callback_label,
    )
    from free_register_common import (  # type: ignore[no-redef]
        FIXED_PASSWORD,
        FreeRegisterError,
        random_birthdate,
        random_display_name,
        safe_log_message,
    )


_CHALLENGE_MARKERS = (
    "captcha",
    "cloudflare",
    "turnstile",
    "verify you are human",
    "checking your browser",
    "just a moment",
    "人机验证",
    "人間であることを確認",
)
_SESSION_INVALID_MARKERS = (
    "sign-in session is no longer valid",
    "oauth_session_invalid",
    "auth_session_invalid",
    "session expired",
    "invalid authorization step",
)
_RETRYABLE_OTP_MARKERS = (
    "invalid",
    "incorrect",
    "wrong",
    "expired",
    "验证码",
    "認証コード",
    "verification code",
)
_PROFILE_MARKERS = (
    "/about-you",
    "/about_you",
    "/birthdate",
    "/create-account/profile",
    "/signup/profile",
    "/u/signup/profile",
)
_SIGNUP_PASSWORD_MARKERS = (
    "/create-account/password",
    "/signup/password",
    "/u/signup/password",
    "signup_password",
    "create_account_password",
)
_PASSWORD_PAGE_TYPES = frozenset({
    "password", "password_required", "password_verification", "login_password",
    "signup_password", "create_account_password",
})
_OTP_PAGE_TYPES = frozenset({
    "email_otp", "email_otp_verification", "email_verification",
    "mfa_challenge", "mfa_otp", "mfa_otp_verification",
})
_PROFILE_PAGE_TYPES = frozenset({
    "about_you", "about-you", "account_profile", "profile", "create_account", "birthdate",
})
_CALLBACK_READY_PAGE_TYPES = frozenset({
    "sign_in_with_chatgpt_codex_consent", "consent", "consent_required",
    "workspace_select", "external_url", "oauth_callback",
})
_SECURITY_PAGE_MARKERS = (
    "security_challenge",
    "security-challenge",
    "security-check",
    "captcha",
    "cloudflare",
    "turnstile",
    "/cdn-cgi/challenge-platform/",
)
_SECURITY_PAGE_TYPES = frozenset({
    "security_challenge",
    "security_verification",
    "human_verification",
    "captcha",
})
_MFA_PAGE_TYPES = frozenset({"mfa_challenge", "mfa_otp", "mfa_otp_verification"})
_MAX_PAGE_TRANSITIONS = 8


def _chain_helpers() -> tuple[Callable[..., Any], ...]:
    """Load recovered response helpers lazily so unit tests need no runtime artifacts."""
    try:
        import codex_oauth_chain as chain
    except ImportError:  # pragma: no cover
        def ok(value: Any) -> bool:
            return bool(isinstance(value, Mapping) and 200 <= int(value.get("_status") or 0) < 300)
        def page(value: Any) -> str:
            return str(value.get("page", {}).get("type") or "") if isinstance(value, Mapping) and isinstance(value.get("page"), Mapping) else ""
        def cont(value: Any) -> str:
            return str(value.get("continue_url") or "") if isinstance(value, Mapping) else ""
        def error(value: Any) -> str:
            return str(value.get("error") or "") if isinstance(value, Mapping) else str(value or "")
        return ok, page, cont, error, lambda value: _contains(value, _SESSION_INVALID_MARKERS)
    return (
        chain._is_success_response,
        chain._page_type,
        chain._continue_url,
        chain._error_text,
        getattr(chain, "_is_session_invalid_error", lambda value: _contains(value, _SESSION_INVALID_MARKERS)),
    )


def _contains(value: Any, markers: tuple[str, ...]) -> bool:
    text = str(value or "").casefold()
    return any(marker.casefold() in text for marker in markers)


def _raise_response(response: Any, *, node: str, label: str, stage: str) -> None:
    """Map a transport response to a stable Free node error."""
    _ok, _page, _continue, error_text, session_invalid = _chain_helpers()
    error = str(error_text(response) or "").strip()
    if session_invalid(response) or _contains(error, _SESSION_INVALID_MARKERS):
        raise FreeRegisterError(
            node,
            label,
            f"{_response_detail(response, error)}；OAuth 会话已失效",
            error_code="oauth_session_invalid",
            **_response_metadata(response, action_hint="保持当前邮箱、代理和设备上下文，重建一次 OAuth 会话", diagnostic_error=error),
        )
    if _contains(error, _CHALLENGE_MARKERS) or _contains(_response_search_text(response), _CHALLENGE_MARKERS):
        raise FreeRegisterError(
            "free_oauth_security_challenge",
            "等待 Free OAuth 安全验证",
            f"{_response_detail(response, error)}；检测到安全验证页面，已停止自动流程",
            retryable=False,
            error_code="free_oauth_security_challenge",
            **_response_metadata(response, action_hint="保留当前代理与 Profile，人工确认风控状态后再重试", diagnostic_error=error),
        )
    raise FreeRegisterError(
        node,
        label,
        _response_detail(response, error),
        error_code=f"{stage}_failed",
        **_response_metadata(response, action_hint=f"检查 {label} 的服务端状态后再重试", diagnostic_error=error),
    )


def _password_context(response: Any) -> str:
    """Classify a password page without guessing from ``type=password``.

    The authorize API has used the generic ``password`` page type for both
    existing-account login and new-account signup.  A generic type alone is
    therefore unsafe: calling ``verify_password`` on a signup page consumes a
    different authorization step.  Prefer explicit page/path/context fields,
    and return ``unknown`` when the server did not tell us which flow it is.
    """
    if not isinstance(response, Mapping):
        return "unknown"
    locations = " ".join(_page_locations(response)).casefold()
    page_value = response.get("page")
    page = page_value if isinstance(page_value, Mapping) else {}
    page_type = str(page.get("type") or response.get("page_type") or response.get("type") or "").casefold()
    if any(marker.casefold() in locations or marker.casefold() in page_type for marker in _SIGNUP_PASSWORD_MARKERS):
        return "signup"
    login_markers = (
        "/log-in/password",
        "/login/password",
        "login_password",
        "existing_account",
        "existing-account",
    )
    if any(marker in locations or marker in page_type for marker in login_markers):
        return "login"

    # Newer authorize responses expose a context/intent instead of a distinct
    # page type.  Only inspect bounded scalar fields; never copy response
    # bodies into diagnostics.
    context_keys = (
        "context", "flow", "intent", "mode", "reason", "kind", "action",
        "account_type", "account_kind", "auth_type", "password_context",
    )
    context = " ".join(str(response.get(key) or "") for key in context_keys)
    if isinstance(page_value, Mapping):
        context += " " + " ".join(str(page.get(key) or "") for key in context_keys)
    context = context.casefold()
    if any(marker in context for marker in ("signup", "sign_up", "register", "registration", "create_account", "new_account")):
        return "signup"
    if any(marker in context for marker in ("login", "log_in", "sign_in", "existing")):
        return "login"
    return "unknown"


def _is_signup_password(response: Any) -> bool:
    return _password_context(response) == "signup"


def _is_login_password(response: Any) -> bool:
    return _password_context(response) == "login"


def _account_flow(response: Any) -> str:
    password_flow = _password_context(response)
    if password_flow == "signup":
        return "signup"
    if password_flow == "login":
        return "existing_login"
    page_type = _page_type_value(response).casefold().replace("-", "_")
    if page_type in _MFA_PAGE_TYPES:
        return "existing_login"
    if page_type in _PROFILE_PAGE_TYPES or _is_profile(response):
        return "signup"
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page") if isinstance(response.get("page"), Mapping) else {}
    keys = ("context", "flow", "intent", "mode", "reason", "kind", "action", "account_flow")
    text = " ".join(str(source.get(key) or "") for source in (response, page) for key in keys).casefold()
    locations = " ".join(_page_locations(response)).casefold()
    if any(marker in text or marker in locations for marker in ("existing", "login", "log_in", "sign_in", "/log-in/")):
        return "existing_login"
    if any(marker in text or marker in locations for marker in ("signup", "sign_up", "register", "create_account", "/signup/")):
        return "signup"
    return ""


def _is_profile(response: Any) -> bool:
    locations = " ".join(_page_locations(response)).casefold()
    return any(marker in locations for marker in _PROFILE_MARKERS)


def _is_phone(response: Any) -> bool:
    page = ""
    if isinstance(response, Mapping) and isinstance(response.get("page"), Mapping):
        page = str(response["page"].get("type") or "").casefold()
    locations = " ".join(_page_locations(response)).casefold()
    return "phone" in page or "/phone" in locations or "contact-verification" in locations


def _is_retryable_otp_error(response: Any) -> bool:
    _ok, _page, _continue, error_text, _session_invalid = _chain_helpers()
    return _contains(error_text(response), _RETRYABLE_OTP_MARKERS)


def _is_security_page(response: Any) -> bool:
    """Recognize a successful HTTP response that is still a security stop."""
    if not isinstance(response, Mapping):
        return False
    page = response.get("page")
    page_type = str(page.get("type") or "") if isinstance(page, Mapping) else ""
    locations = " ".join(_page_locations(response))
    normalized_page_type = page_type.strip().casefold().replace("-", "_")
    # ``mfa_challenge`` is an authentication step, not a security stop.  Do
    # not use a broad ``challenge`` substring here: the recovered API uses
    # that word for both MFA and Cloudflare/security pages.
    if normalized_page_type in _MFA_PAGE_TYPES or normalized_page_type.replace("_", "-") in {value.replace("_", "-") for value in _MFA_PAGE_TYPES}:
        return False
    return (
        normalized_page_type in _SECURITY_PAGE_TYPES
        or any(
            marker.casefold().replace("-", "_") in normalized_page_type
            for marker in _SECURITY_PAGE_MARKERS
            if marker.casefold() != "security-challenge"
        )
        or any(marker.casefold() in locations.casefold() for marker in _SECURITY_PAGE_MARKERS)
    )


def _callback_code_and_state(callback_url: str) -> tuple[str, str]:
    values = _callback_query(callback_url)
    return values.get("code", ""), values.get("state", "")


def _callback_error(callback_url: str) -> tuple[str, str]:
    values = _callback_query(callback_url)
    return values.get("error", ""), safe_log_message(values.get("error_description", ""))[:180]


def _oauth_context(value: Mapping[str, Any] | None) -> dict[str, Any]:
    source = value if isinstance(value, Mapping) else {}
    params = source.get("params") if isinstance(source.get("params"), Mapping) else source
    return {
        "url": str(source.get("url") or ""),
        "code_verifier": str(source.get("code_verifier") or ""),
        "state": str(source.get("state") or params.get("state") or ""),
        "client_id": str(source.get("client_id") or params.get("client_id") or ""),
        "redirect_uri": str(source.get("redirect_uri") or params.get("redirect_uri") or ""),
        "params": dict(params),
    }


def _is_callback_destination(value: str, redirect_uri: str = "") -> bool:
    try:
        parsed = urlsplit(str(value or ""))
        expected = urlsplit(str(redirect_uri or ""))
    except ValueError:
        return False
    path = str(parsed.path or "").rstrip("/").casefold()
    if path.endswith("/authorize/continue"):
        return True
    if not expected.scheme or not expected.netloc:
        return False
    actual_path = str(parsed.path or "/").rstrip("/") or "/"
    expected_path = str(expected.path or "/").rstrip("/") or "/"
    return (
        parsed.scheme.casefold() == expected.scheme.casefold()
        and parsed.netloc.casefold() == expected.netloc.casefold()
        and actual_path == expected_path
    )


def _check_stopped(stop_requested: Callable[[], bool] | None) -> None:
    if callable(stop_requested) and bool(stop_requested()):
        raise FreeRegisterError(
            "free_run_stop",
            "停止 Free 注册",
            "任务已请求停止，协议链路不再发起后续请求",
            retryable=False,
            error_code="free_run_stop",
        )


def _raise_security_page(response: Any) -> None:
    if _is_security_page(response) or _contains(_response_search_text(response), _CHALLENGE_MARKERS):
        raise FreeRegisterError(
            "free_oauth_security_challenge",
            "等待 Free OAuth 安全验证",
            f"{_response_detail(response)}；检测到安全验证页面，已停止自动流程",
            retryable=False,
            error_code="free_oauth_security_challenge",
            **_response_metadata(response, action_hint="保留当前代理与会话，人工确认风控状态后再重试"),
        )


def _reset_sentinel(transport: Any, flow: str = "authorize_continue") -> None:
    provider = getattr(transport, "sentinel_provider", None)
    reset = getattr(provider, "reset", None)
    if callable(reset):
        reset(flow)


def _reset_otp_request(provider: Any) -> None:
    service = getattr(provider, "service", None)
    state = getattr(service, "state", None)
    finish = getattr(state, "finish_request", None)
    if callable(finish) and bool(getattr(state, "active", False)):
        finish()


def _prepare_otp(
    provider: Any,
    stage_code: str,
    *,
    force_snapshot: bool = False,
    preserve_active_baseline: bool = False,
) -> None:
    """Prepare a mailbox phase, refreshing its baseline after session rebuild."""
    service = getattr(provider, "service", None)
    previous_stage = str(getattr(service, "current_stage", "") or "")
    # A single provider instance is reused across registration, existing-login
    # and 2FA enrollment.  A phase transition needs a new request-time
    # baseline even when the OAuth session itself was not rebuilt.
    if (
        previous_stage
        and previous_stage != str(stage_code or "")
        and not preserve_active_baseline
    ):
        force_snapshot = True
    prepare = getattr(provider, "prepare", None)
    if not callable(prepare):
        return
    try:
        inspect.signature(prepare).bind(stage_code, force_snapshot=force_snapshot)
    except ValueError:
        prepare(stage_code, force_snapshot=force_snapshot)
        return
    except TypeError:
        pass
    else:
        prepare(stage_code, force_snapshot=force_snapshot)
        return
    service_prepare = getattr(service, "prepare", None)
    if callable(service_prepare):
        service_prepare(stage_code, force_snapshot=force_snapshot)
    else:
        prepare(stage_code)


def _log(log: Callable[..., Any] | None, message: str, level: str = "info") -> None:
    if not callable(log):
        return
    try:
        log(message, level)
    except TypeError:
        log(message)


def _stage(stage: Callable[[str, str], None], task_id: str, code: str) -> None:
    stage(task_id, code)


def _transport_node(method: str) -> tuple[str, str]:
    return {
        "initiate_oauth": ("free_oauth_session", "Free OAuth 会话"),
        "submit_email_identifier": ("free_email_identifier", "识别 Free 注册邮箱"),
        "register_user": ("free_email_password", "提交 Free 注册密码"),
        "verify_password": ("free_email_password", "验证 Free 登录密码"),
        "send_email_otp": ("free_email_otp_wait", "派发 Free 邮箱验证码"),
        "send_mfa_otp": ("free_existing_login_otp", "派发已有账号登录验证码"),
        "verify_email_otp": ("free_email_otp_validate", "验证 Free 邮箱验证码"),
        "verify_mfa_otp": ("free_email_otp_validate", "验证已有账号登录验证码"),
        "visit_continue": ("free_account_create", "进入 Free 账号资料页"),
        "create_account_profile": ("free_account_create", "创建 Free 账号"),
        "accept_consent": ("free_oauth_callback", "确认 Free OAuth 授权"),
        "follow_continue_until_code": ("free_oauth_callback", "Free OAuth 回调"),
        "exchange_code": ("free_access_token", "获取 Free access token"),
    }.get(method, ("free_protocol_result", "Free 协议注册"))


def _call_transport(
    transport: Any,
    method: str,
    *args: Any,
    flow: str = "authorize_continue",
    stop_requested: Callable[[], bool] | None = None,
) -> Any:
    _check_stopped(stop_requested)
    _reset_sentinel(transport, flow)
    function = getattr(transport, method, None)
    if not callable(function):
        raise FreeRegisterError(
            "free_oauth_session",
            "Free OAuth 会话",
            f"Transport 缺少 {method} 方法",
            retryable=False,
            error_code="free_transport_method_missing",
        )
    try:
        result = function(*args)
        _check_stopped(stop_requested)
        node, label = _transport_node(method)
        if flow == "password_verify" and method in {"send_email_otp", "verify_email_otp"}:
            action = "派发" if method.startswith("send_") else "验证"
            node, label = "free_existing_login_otp", f"{action}已有账号登录验证码"
        _raise_security_page(result)
        _ok, _page, _continue, error_text, session_invalid = _chain_helpers()
        error = str(error_text(result) or "")
        if session_invalid(result) or _contains(error, _SESSION_INVALID_MARKERS):
            raise FreeRegisterError(
                node, label, f"{_response_detail(result, error)}；OAuth 会话已失效",
                error_code="oauth_session_invalid",
                **_response_metadata(result, action_hint="保持当前邮箱、代理和设备上下文，重建一次 OAuth 会话", diagnostic_error=error),
            )
        return result
    except FreeRegisterError:
        raise
    except Exception as exc:
        node, label = _transport_node(method)
        if flow == "password_verify" and method in {"send_email_otp", "verify_email_otp"}:
            action = "派发" if method.startswith("send_") else "验证"
            node, label = "free_existing_login_otp", f"{action}已有账号登录验证码"
        if _contains(exc, _SESSION_INVALID_MARKERS):
            raise FreeRegisterError(
                node,
                label,
                "OAuth 会话已失效，需要重新建立会话",
                error_code="oauth_session_invalid", action_hint="保持当前任务上下文并重建一次 OAuth 会话",
                diagnostic=f"transport={method}; exception={type(exc).__name__}",
            ) from exc
        detail = safe_log_message(exc) or type(exc).__name__
        raise FreeRegisterError(
            node,
            label,
            f"{method} 请求异常（{type(exc).__name__}）：{detail}",
            error_code=f"{node}_transport_failed",
            action_hint=f"检查 {label} 的网络与服务端状态后重试",
            diagnostic=f"transport={method}; exception={type(exc).__name__}",
        ) from exc


def _wait_code(otp_provider: Any, email: str, **kwargs: Any) -> str:
    waiter = getattr(otp_provider, "wait_code", None)
    if not callable(waiter):
        raise FreeRegisterError(
            str(kwargs.get("stage_code") or "free_email_otp_wait"),
            "等待 Free 邮箱验证码", "邮箱取件 Provider 缺少 wait_code 方法",
            retryable=False, error_code="free_otp_waiter_missing",
        )
    try:
        inspect.signature(waiter).bind(email, **kwargs)
    except ValueError:
        return waiter(email, **kwargs)
    except TypeError:
        return waiter(email)
    return waiter(email, **kwargs)


def _wait_and_validate_email_otp(
    transport: Any,
    otp_provider: Any,
    email: str,
    response: Any,
    *,
    task_id: str,
    stage: Callable[[str, str], None],
    log: Callable[..., Any] | None,
    stage_code: str = "free_email_otp_wait",
    send_method: str = "send_email_otp",
    verify_method: str = "verify_email_otp",
    send_before_wait: bool = False,
    resend_budget: dict[str, int] | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> Any:
    ok, page_type, continue_url, error_text, _session_invalid = _chain_helpers()
    current = response
    retry_count = 0
    max_attempts = 3
    budget = resend_budget if isinstance(resend_budget, dict) else {"used": 0}
    sentinel_flow = (
        "password_verify"
        if stage_code == "free_existing_login_otp"
        or send_method == "send_mfa_otp"
        or verify_method == "verify_mfa_otp"
        else "authorize_continue"
    )

    def mark_request_sent() -> None:
        marker = getattr(otp_provider, "mark_sent", None)
        if callable(marker):
            marker(stage_code)

    def send_otp(*, controlled_resend: bool) -> bool:
        nonlocal current
        used_resends = max(0, int(budget.get("used") or 0))
        if controlled_resend and used_resends >= 2:
            return False
        sender = getattr(transport, send_method, None)
        if not callable(sender):
            if controlled_resend:
                return False
            raise FreeRegisterError(
                stage_code,
                "等待 Free 邮箱验证码",
                f"Transport 缺少 {send_method} 方法",
                retryable=False,
                error_code="free_otp_sender_missing",
            )
        if controlled_resend:
            # Each round owns a request-time baseline. Finish the previous
            # wait and take the next snapshot before dispatch so a message
            # produced by this resend cannot enter its own baseline.
            _reset_otp_request(otp_provider)
            _prepare_otp(otp_provider, stage_code, force_snapshot=True)
        mark_request_sent()
        sent = _call_transport(
            transport,
            send_method,
            continue_url(current) or "",
            flow=sentinel_flow,
            stop_requested=stop_requested,
        )
        if not ok(sent):
            _raise_response(sent, node=stage_code, label="等待 Free 邮箱验证码", stage=f"{stage_code}_send")
        if controlled_resend:
            budget["used"] = used_resends + 1
        current = sent
        _log(
            log,
            f"邮箱验证码{'受控重发' if controlled_resend else '派发'}完成（stage={stage_code}）",
            "warn" if controlled_resend else "info",
        )
        return True

    if send_before_wait:
        send_otp(controlled_resend=False)

    while retry_count < max_attempts:
        _check_stopped(stop_requested)
        retry_count += 1
        _stage(stage, task_id, stage_code)
        mark_request_sent()
        try:
            code = _wait_code(
                otp_provider,
                email,
                stage_code=stage_code,
                resend_fn=(lambda: send_otp(controlled_resend=True))
                if int(budget.get("used") or 0) < 2 else None,
                stop_requested=stop_requested,
            )
        except FreeRegisterError as exc:
            if retry_count >= max_attempts or not bool(exc.retryable):
                raise
            if int(budget.get("used") or 0) < 2:
                send_otp(controlled_resend=True)
            _log(
                log,
                f"邮箱验证码第 {retry_count}/{max_attempts} 轮等待未取得可用新邮件，继续沿用阶段基线",
                "warn",
            )
            continue
        _check_stopped(stop_requested)
        validate_stage = "free_existing_login_otp" if stage_code == "free_existing_login_otp" else "free_email_otp_validate"
        _stage(stage, task_id, validate_stage)
        try:
            current = _call_transport(
                transport,
                verify_method,
                code,
                flow=sentinel_flow,
                stop_requested=stop_requested,
            )
        except Exception:
            # The mailbox code was not confirmed as submitted when the
            # transport failed before returning a response. Let the provider
            # offer the same message again on a controlled retry.
            discard = getattr(otp_provider, "discard_code", None)
            if callable(discard):
                discard(stage_code, code)
            raise
        _raise_security_page(current)
        if ok(current):
            _log(log, f"邮箱验证码验证请求已接受（attempt={retry_count}，HTTP {_status(current) or '-'}）", "success")
            return current
        detail = str(error_text(current) or "验证码验证未通过")
        if _contains(detail, _CHALLENGE_MARKERS):
            raise FreeRegisterError(
                "free_oauth_security_challenge",
                "等待 Free OAuth 安全验证",
                "验证码验证后进入安全验证页面，已停止自动流程",
                retryable=False,
                error_code="free_oauth_security_challenge",
            )
        if _contains(detail, _SESSION_INVALID_MARKERS):
            raise FreeRegisterError(
                "free_email_otp_validate",
                "验证 Free 邮箱验证码",
                "验证码提交时 OAuth 会话已失效",
                error_code="oauth_session_invalid",
            )
        if retry_count >= max_attempts or not _is_retryable_otp_error(current):
            raise FreeRegisterError(
                "free_email_otp_validate",
                "验证 Free 邮箱验证码",
                f"验证码验证失败（attempt={retry_count}，{_response_detail(current, detail)}）",
                error_code="free_email_otp_invalid",
            )
        if int(budget.get("used") or 0) < 2:
            send_otp(controlled_resend=True)
        _log(log, f"验证码被服务端拒绝，继续第 {retry_count + 1}/{max_attempts} 轮等待（全流程最多重发两次）", "warn")
    raise FreeRegisterError(stage_code, "验证 Free 邮箱验证码", "验证码尝试次数已耗尽", error_code="free_email_otp_attempts_exhausted")


def _run_once(
    transport: Any,
    *,
    oauth_context: Mapping[str, Any],
    email: str,
    password: str,
    otp_provider: Any,
    task_id: str,
    stage: Callable[[str, str], None],
    log: Callable[..., Any] | None,
    force_otp_snapshot: bool = False,
    otp_resend_budget: dict[str, int] | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    ok, page_type, continue_url, error_text, _session_invalid = _chain_helpers()
    context = _oauth_context(oauth_context)
    oauth_url = context["url"]
    if not all(context.get(key) for key in ("url", "code_verifier", "state", "client_id", "redirect_uri")):
        raise FreeRegisterError(
            "free_oauth_session",
            "Free OAuth 会话",
            "OAuth PKCE 上下文不完整，缺少授权地址、state、verifier、client_id 或 redirect_uri",
            retryable=False,
            error_code="free_oauth_context_incomplete",
        )

    _stage(stage, task_id, "free_oauth_session")
    _log(log, "创建全新 OAuth HTTP 会话并开始授权", "info")
    start = _call_transport(
        transport,
        "initiate_oauth",
        oauth_url,
        flow="oauth_authorize",
        stop_requested=stop_requested,
    )
    if not ok(start):
        _raise_response(start, node="free_oauth_session", label="Free OAuth 会话", stage="free_oauth_session")
    if _page_is_html(start):
        if _contains(_response_search_text(start), _CHALLENGE_MARKERS):
            raise FreeRegisterError(
                "free_oauth_security_challenge",
                "等待 Free OAuth 安全验证",
                "OAuth 授权返回安全验证页面，已停止自动流程",
                retryable=False,
                error_code="free_oauth_security_challenge",
            )
        locations = _page_locations(start)
        same_origin_login = False
        for value in locations:
            try:
                parsed = urlsplit(value)
            except ValueError:
                continue
            host = str(parsed.hostname or "").casefold()
            path = str(parsed.path or "/").casefold()
            if host in {"auth.openai.com", "auth0.openai.com"} and path.startswith(("/log-in", "/login")):
                same_origin_login = True
                break
        if not same_origin_login:
            raise FreeRegisterError(
                "free_oauth_session",
                "Free OAuth 会话",
                f"OAuth 授权返回无法识别的 HTML（{_response_detail(start)}）",
                error_code="oauth_bootstrap_html",
            )
        _log(log, "OAuth 授权返回同源登录壳，继续使用当前会话提交邮箱", "info")
    _log(log, f"OAuth 会话建立成功（HTTP {_status(start) or '-'}，Content-Type {_content_type(start) or '-'}）", "success")

    _stage(stage, task_id, "free_email_identifier")
    # Capture the mailbox baseline before the authorize/continue request can
    # dispatch an OTP. This is also repeated after a session rebuild.
    _reset_otp_request(otp_provider)
    _prepare_otp(otp_provider, "free_email_otp_wait", force_snapshot=force_otp_snapshot)
    response = _call_transport(
        transport,
        "submit_email_identifier",
        email,
        stop_requested=stop_requested,
    )
    if not ok(response):
        _raise_response(response, node="free_email_identifier", label="识别 Free 注册邮箱", stage="free_email_identifier")
    if _page_is_html(response):
        if _contains(_response_search_text(response), _CHALLENGE_MARKERS):
            raise FreeRegisterError(
                "free_oauth_security_challenge",
                "等待 Free OAuth 安全验证",
                "邮箱识别返回安全验证页面，已停止自动流程",
                retryable=False,
                error_code="free_oauth_security_challenge",
            )
        raise FreeRegisterError(
            "free_email_identifier",
            "识别 Free 注册邮箱",
            f"邮箱识别返回 HTML（{_response_detail(response)}），授权会话未建立",
            error_code="oauth_bootstrap_html",
        )
    current_page = str(page_type(response) or _page_type_value(response) or "").strip().casefold().replace("-", "_")
    _log(log, f"邮箱提交成功（页面={current_page or '-'}，continue={'yes' if _next_url(response) else 'no'}）", "info")

    # Keep advancing through the finite authorization state machine. Providers
    # can return another OTP/password envelope after a successful transition;
    # never jump straight to callback/token in that case.
    password_page_handled = False
    profile_submitted = False
    consent_accepted = False
    account_flow = _account_flow(response)
    for _transition in range(_MAX_PAGE_TRANSITIONS):
        current_page = str(page_type(response) or _page_type_value(response) or "").strip().casefold().replace("-", "_")
        account_flow = _account_flow(response) or account_flow
        if current_page in _OTP_PAGE_TYPES:
            is_mfa = current_page in _MFA_PAGE_TYPES
            existing_login = is_mfa or account_flow == "existing_login"
            otp_stage = "free_existing_login_otp" if existing_login else "free_email_otp_wait"
            if is_mfa:
                _reset_otp_request(otp_provider)
                _prepare_otp(otp_provider, otp_stage, force_snapshot=True)
            elif existing_login:
                # authorize/continue may dispatch the login OTP while returning
                # this page. Keep the baseline captured before that request and
                # only switch the diagnostic/used-code stage identity.
                _prepare_otp(
                    otp_provider,
                    otp_stage,
                    preserve_active_baseline=True,
                )
            response = _wait_and_validate_email_otp(
                transport, otp_provider, email, response,
                task_id=task_id, stage=stage, log=log,
                stage_code=otp_stage,
                send_method="send_mfa_otp" if is_mfa else "send_email_otp",
                verify_method="verify_mfa_otp" if is_mfa else "verify_email_otp",
                send_before_wait=is_mfa,
                resend_budget=otp_resend_budget,
                stop_requested=stop_requested,
            )
            continue
        if current_page in _PASSWORD_PAGE_TYPES:
            password_context = _password_context(response)
            if password_context == "unknown":
                raise FreeRegisterError(
                    "free_email_password",
                    "识别 Free 密码页面",
                    "服务端只返回通用密码页面，无法确认是注册还是已有账号登录，已停止以避免误调用接口",
                    retryable=False,
                    error_code="free_password_context_unknown",
                )
            if password_page_handled:
                existing_login = password_context == "login"
                raise FreeRegisterError(
                    "free_existing_login_otp" if existing_login else "free_email_password",
                    "已有账号邮箱验证" if existing_login else "验证 Free 注册密码",
                    f"{'邮箱验证码登录' if existing_login else '注册密码提交'}后重复返回密码页（页面={current_page or '-'}）",
                    error_code="free_login_otp_transition_loop" if existing_login else "free_password_transition_loop",
                )
            password_page_handled = True
            if password_context == "signup":
                account_flow = "signup"
                _stage(stage, task_id, "free_email_password")
                response = _call_transport(
                    transport,
                    "register_user",
                    email,
                    password,
                    flow="username_password_create",
                    stop_requested=stop_requested,
                )
            else:
                account_flow = "existing_login"
                _reset_otp_request(otp_provider)
                _prepare_otp(otp_provider, "free_existing_login_otp", force_snapshot=False)
                response = _wait_and_validate_email_otp(
                    transport,
                    otp_provider,
                    email,
                    response,
                    task_id=task_id,
                    stage=stage,
                    log=log,
                    stage_code="free_existing_login_otp",
                    send_method="send_email_otp",
                    verify_method="verify_email_otp",
                    send_before_wait=True,
                    resend_budget=otp_resend_budget,
                    stop_requested=stop_requested,
                )
            if not ok(response):
                _raise_response(response, node="free_email_password", label="提交 Free 注册密码", stage="free_email_password")
            continue
        if _is_phone(response):
            raise FreeRegisterError(
                "free_phone_required",
                "Free 注册手机号节点",
                "协议注册进入手机号验证，Free 流程未调用接码平台",
                retryable=False,
                error_code="free_phone_required",
            )
        if (_is_profile(response) or current_page in _PROFILE_PAGE_TYPES) and not profile_submitted:
            profile_submitted = True
            account_flow = "signup"
            _stage(stage, task_id, "free_account_create")
            next_url = _next_url(response)
            if next_url and callable(getattr(transport, "visit_continue", None)):
                response = _call_transport(
                    transport,
                    "visit_continue",
                    next_url,
                    "https://auth.openai.com/email-verification",
                    flow="oauth_create_account",
                    stop_requested=stop_requested,
                )
                if not ok(response):
                    _raise_response(
                        response,
                        node="free_account_create",
                        label="进入 Free 账号资料页",
                        stage="free_account_profile_navigation",
                    )
            response = _call_transport(
                transport,
                "create_account_profile",
                random_display_name(),
                random_birthdate(),
                flow="oauth_create_account",
                stop_requested=stop_requested,
            )
            if not ok(response):
                _raise_response(response, node="free_account_create", label="创建 Free 账号", stage="free_account_create")
            continue
        if current_page in {"sign_in_with_chatgpt_codex_consent", "consent", "consent_required"} and not consent_accepted:
            consent_accepted = True
            consent_url = _next_url(response)
            accept = getattr(transport, "accept_consent", None)
            if callable(accept):
                response = _call_transport(
                    transport,
                    "accept_consent",
                    consent_url,
                    flow="oauth_consent",
                    stop_requested=stop_requested,
                )
                if not ok(response):
                    _raise_response(response, node="free_oauth_callback", label="Free OAuth 回调", stage="free_oauth_consent")
                continue
            _log(log, "Transport 未提供 consent 方法，沿用现有回调地址", "warn")
        # Consent/external callback envelopes are ready for the callback
        # method. An unknown state with no continuation must never be treated
        # as a successful registration.
        destination = _next_url(response)
        if destination and (
            current_page in _CALLBACK_READY_PAGE_TYPES
            or _is_callback_destination(destination, context["redirect_uri"])
        ):
            break
        if destination:
            raise FreeRegisterError(
                "free_oauth_callback",
                "推进 Free OAuth 页面状态",
                f"未识别的授权页面状态（页面={current_page or '-'}），未盲目跟随回调地址",
                retryable=False,
                error_code="free_page_state_unknown",
            )
        raise FreeRegisterError(
            "free_oauth_callback",
            "推进 Free OAuth 页面状态",
            f"未识别的授权页面状态（页面={current_page or '-'}），且没有回调地址",
            retryable=False,
            error_code="free_page_state_unknown",
        )
    else:
        raise FreeRegisterError(
            "free_oauth_session",
            "推进 Free OAuth 页面状态",
            f"授权页面状态超过 {_MAX_PAGE_TRANSITIONS} 次仍未进入资料或回调节点",
            retryable=False,
            error_code="free_page_transition_limit",
        )

    current_page = page_type(response) or _page_type_value(response)
    next_url = _next_url(response)
    if not next_url:
        raise FreeRegisterError(
            "free_oauth_callback",
            "Free OAuth 回调",
            f"页面状态未提供 OAuth 回调地址（页面={page_type(response) or '-'}）",
            error_code="free_oauth_callback_missing",
        )
    _stage(stage, task_id, "free_oauth_callback")
    callback_url = str(_call_transport(
        transport,
        "follow_continue_until_code",
        next_url,
        context["params"],
        flow="oauth_callback",
        stop_requested=stop_requested,
    ) or "").strip()
    callback_error, callback_error_description = _callback_error(callback_url)
    if callback_error:
        raise FreeRegisterError(
            "free_oauth_callback", "Free OAuth 回调",
            f"OAuth 回调返回错误：{callback_error_description or safe_log_message(callback_error)}",
            retryable=False, error_code="oauth_callback_provider_error",
            provider_code=callback_error,
            safe_page=_safe_callback_label(callback_url),
            action_hint="检查授权同意状态和账号风控后重新发起 OAuth",
        )
    if not _callback_matches_redirect(callback_url, context["redirect_uri"]):
        raise FreeRegisterError(
            "free_oauth_callback", "Free OAuth 回调",
            f"OAuth 回调落点与当前 redirect_uri 不匹配（落点={_safe_callback_label(callback_url)}）",
            retryable=False, error_code="oauth_callback_redirect_mismatch",
            safe_page=_safe_callback_label(callback_url),
            action_hint="检查 OAuth 客户端 redirect_uri 配置，不要继续交换 Token",
        )
    code, callback_state = _callback_code_and_state(callback_url)
    if not code:
        raise FreeRegisterError(
            "free_oauth_callback",
            "Free OAuth 回调",
            f"OAuth 回调未返回 authorization code（落点={_safe_callback_label(callback_url)}）",
            error_code="oauth_callback_missing_code",
        )
    if not callback_state or not hmac.compare_digest(callback_state, context["state"]):
        raise FreeRegisterError(
            "free_oauth_callback",
            "Free OAuth 回调",
            "OAuth 回调 state 缺失或与当前任务不匹配，已停止 Token 交换",
            retryable=False,
            error_code="oauth_callback_state_mismatch",
        )
    _log(log, "OAuth 回调 code/state 校验完成（内容不写入日志）", "success")

    _stage(stage, task_id, "free_access_token")
    tokens = _call_transport(
        transport,
        "exchange_code",
        code,
        context["code_verifier"],
        context["client_id"],
        context["redirect_uri"],
        email,
        flow="oauth_token_exchange",
        stop_requested=stop_requested,
    )
    # Some replay/compatibility transports return an HTTP envelope instead of
    # raising for a failed token endpoint. Preserve that provider status and
    # error node rather than collapsing it into a missing-token result.
    if isinstance(tokens, Mapping):
        token_status = _status(tokens)
        token_ok = tokens.get("ok")
        token_failed = token_ok is False or (
            isinstance(token_ok, str) and token_ok.strip().casefold() in {"false", "0", "no", "failed", "failure", "error"}
        )
        if (token_status is not None and not 200 <= token_status < 300) or token_failed:
            _raise_response(
                tokens,
                node="free_access_token",
                label="获取 Free access token",
                stage="token_exchange",
            )
    if not isinstance(tokens, Mapping):
        tokens = {}
    token = str(tokens.get("access_token") or "").strip()
    if not token:
        raise FreeRegisterError(
            "free_access_token",
            "获取 Free access token",
            "OAuth Token 交换完成但未返回 access token",
            error_code="token_exchange_failed",
        )
    if not str(tokens.get("refresh_token") or "").strip() or not str(tokens.get("id_token") or "").strip():
        # Some valid OAuth-compatible exchanges expose only the short-lived
        # access token.  Registration completion is established by the
        # callback/state check above; optional token siblings must not turn a
        # successful account creation into a false Token failure.
        _log(log, "OAuth Token 响应未包含全部可选 Token 字段，已保留 access token 继续后续查询", "warn")
    _log(log, "OAuth Token 交换完成（敏感内容不写入日志）", "success")
    result = {
        "ok": True,
        "registration_completed": True,
        "oauth_callback_completed": True,
        "oauth_code_received": True,
        "local_oauth_exchange_ok": True,
        "access_token": token,
        "has_access_token": True,
        # Public task state only needs the callback destination. Query values
        # contain the short-lived OAuth code/state and must not be persisted.
        "callback_url": _safe_callback_label(callback_url),
        "account_flow": account_flow or ("signup" if profile_submitted else "existing_login"),
    }
    if result["account_flow"] == "signup":
        result["password"] = password or FIXED_PASSWORD
    for key in ("refresh_token", "id_token", "expires_at", "token_type", "email", "scope"):
        if key in tokens:
            result[key] = tokens.get(key)
    return result

def run_free_protocol_flow(
    transport: Any,
    *,
    transport_factory: Callable[[], Any] | None = None,
    oauth_context_factory: Callable[[], Mapping[str, Any]] | None = None,
    oauth_context: Mapping[str, Any],
    email: str,
    password: str = FIXED_PASSWORD,
    otp_provider: Any,
    task_id: str,
    stage: Callable[[str, str], None],
    log: Callable[..., Any] | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> tuple[dict[str, Any], Any]:
    """Run Free protocol registration and rebuild a stale HTTP session once.

    ``oauth_context_factory`` remains in the signature for compatibility with
    older callers. A task's PKCE state/verifier are immutable and are never
    regenerated when only its HTTP session is rebuilt.
    """
    session_rebuilds = 0
    active = transport
    current_oauth_context = _oauth_context(oauth_context)
    otp_resend_budget = {"used": 0}
    while True:
        try:
            result = _run_once(
                active,
                oauth_context=current_oauth_context,
                email=email,
                password=password,
                otp_provider=otp_provider,
                task_id=task_id,
                stage=stage,
                log=log,
                force_otp_snapshot=session_rebuilds > 0,
                otp_resend_budget=otp_resend_budget,
                stop_requested=stop_requested,
            )
            result["oauth_session_rebuilds"] = session_rebuilds
            return result, active
        except FreeRegisterError as exc:
            should_rebuild = (
                session_rebuilds == 0
                and str(exc.error_code or "") in {"oauth_session_invalid", "oauth_bootstrap_html"}
                and bool(transport_factory)
            )
            if not should_rebuild:
                exc.session_rebuilds = session_rebuilds
                raise
            session_rebuilds += 1
            _log(log, "OAuth 会话失效，清理旧 Cookie/CSRF 并重建一次授权会话；邮箱、代理和出口 IP 保持不变", "warn")
            close = getattr(active, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
            session = getattr(active, "session", None)
            session_close = getattr(session, "close", None)
            if callable(session_close):
                try:
                    session_close()
                except Exception:
                    pass
            provider = getattr(active, "sentinel_provider", None)
            reset = getattr(provider, "reset", None)
            if callable(reset):
                reset()
            _reset_otp_request(otp_provider)
            active = transport_factory()
            _log(log, "OAuth 会话重建完成，重新从授权节点开始", "info")


__all__ = ["run_free_protocol_flow"]
