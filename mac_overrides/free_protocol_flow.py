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
        is_known_state_response as _is_known_state_response,
        next_url as _next_url,
        page_is_html as _page_is_html,
        page_location as _page_location,
        page_locations as _page_locations,
        page_type_value as _page_type_value,
        response_detail as _response_detail,
        response_metadata as _response_metadata,
        retry_after_seconds as _retry_after_seconds,
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
    from .free_protocol_security import (
        MFA_PAGE_TYPES as _MFA_PAGE_TYPES,
        SECURITY_CHALLENGE_MARKERS as _CHALLENGE_MARKERS,
        is_security_page as _is_security_page,
        is_security_challenge as _is_security_challenge_response,
        trusted_oauth_bootstrap_location as _trusted_oauth_bootstrap_location,
        wait_for_security_challenge as _wait_for_security_challenge,
    )
except ImportError:  # pragma: no cover - compatibility import for recovered runtime
    from free_protocol_diagnostics import (  # type: ignore[no-redef]
        callback_matches_redirect as _callback_matches_redirect,
        callback_query as _callback_query,
        content_type as _content_type,
        is_known_state_response as _is_known_state_response,
        next_url as _next_url,
        page_is_html as _page_is_html,
        page_location as _page_location,
        page_locations as _page_locations,
        page_type_value as _page_type_value,
        response_detail as _response_detail,
        response_metadata as _response_metadata,
        retry_after_seconds as _retry_after_seconds,
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
    from free_protocol_security import (  # type: ignore[no-redef]
        MFA_PAGE_TYPES as _MFA_PAGE_TYPES,
        SECURITY_CHALLENGE_MARKERS as _CHALLENGE_MARKERS,
        is_security_page as _is_security_page,
        is_security_challenge as _is_security_challenge_response,
        trusted_oauth_bootstrap_location as _trusted_oauth_bootstrap_location,
        wait_for_security_challenge as _wait_for_security_challenge,
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
    # Auth has returned these email-code aliases across authorize/continue
    # versions. They all use the same URL mailbox wait/verify path.
    "email_otp", "email_otp_send", "email_otp_verification", "email_verification",
    "email_code_verification", "passwordless_email_otp",
    "mfa_challenge", "mfa_otp", "mfa_otp_verification",
})
_PROFILE_PAGE_TYPES = frozenset({
    "about_you", "about-you", "account_profile", "profile", "create_account", "birthdate",
})
_CALLBACK_READY_PAGE_TYPES = frozenset({
    "sign_in_with_chatgpt_codex_consent", "consent", "consent_required",
    "workspace_select", "external_url", "oauth_callback",
})
_MAX_PAGE_TRANSITIONS = 8
_PRE_AUTH_PROXY_RETRY_NODES = frozenset({"free_oauth_session", "free_email_identifier"})


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


def _is_rate_limited_response(response: Any, error: str = "") -> bool:
    """Keep provider rate limits out of the OAuth-session rebuild branch."""
    if _status(response) == 429:
        return True
    values: list[str] = [str(error or "")]
    if isinstance(response, Mapping):
        for key in ("error_code", "code", "type", "reason", "message"):
            values.append(str(response.get(key) or ""))
        nested = response.get("error")
        if isinstance(nested, Mapping):
            values.extend(str(nested.get(key) or "") for key in ("error_code", "code", "type", "reason", "message"))
    text = " ".join(values).casefold()
    return any(marker in text for marker in ("rate_limit", "rate limit", "ratelimit", "too many requests"))


def _is_state_response(response: Any, ok: Callable[[Any], bool] | None = None) -> bool:
    page_types = _PASSWORD_PAGE_TYPES | _OTP_PAGE_TYPES | _PROFILE_PAGE_TYPES | _CALLBACK_READY_PAGE_TYPES
    # The recovered chain's success predicate has changed across runtime
    # builds: some builds return a valid 2xx page envelope while reporting
    # ``success=False``.  Keep the explicit AutoRegister state machine as the
    # authority so a legitimate login_password/email_otp/profile transition
    # cannot be misclassified as a failed email identifier request.
    try:
        if _is_known_state_response(response, ok, page_types):
            return True
    except Exception:
        pass
    status = _status(response)
    page_value = response.get("page") if isinstance(response, Mapping) else ""
    explicit_page = page_value.get("type") if isinstance(page_value, Mapping) else page_value
    page = str(
        _page_type_value(response)
        or explicit_page
        or (response.get("page_type") if isinstance(response, Mapping) else "")
        or (response.get("type") if isinstance(response, Mapping) else "")
        or ""
    ).strip().casefold().replace("-", "_")
    return bool(status is not None and 200 <= int(status) < 300 and page in page_types)


def _pre_auth_html_response(response: Any, node: str) -> bool:
    """Return whether an HTML response can be retried on another pool proxy."""
    if node not in {"free_oauth_session", "free_email_identifier"} or not _page_is_html(response):
        return False
    status = _status(response)
    return status is None or 200 <= int(status) < 400


def _pre_auth_access_denied(response: Any, node: str) -> bool:
    """Allow ordinary pre-email 401/403 responses to rotate the proxy."""
    if node not in _PRE_AUTH_PROXY_RETRY_NODES or _is_security_challenge_response(response):
        return False
    try:
        return int(_status(response) or 0) in {401, 403}
    except (TypeError, ValueError):
        return False


def _trusted_html_bootstrap(response: Any, method: str) -> bool:
    return bool(
        method == "initiate_oauth"
        and _page_is_html(response)
        and _trusted_oauth_bootstrap_location(response)
        and not _is_security_challenge_response(response)
    )


def _raise_response(response: Any, *, node: str, label: str, stage: str) -> None:
    """Map a transport response to a stable Free node error."""
    _ok, _page, _continue, error_text, session_invalid = _chain_helpers()
    error = str(error_text(response) or "").strip()
    # A valid authorize state can be a 2xx JSON envelope even when the
    # recovered success helper reports it as false.  Let the finite state
    # machine consume known password/OTP/profile/consent pages instead of
    # converting them into a false transport failure at the current node.
    response_status_value = _status(response)
    response_page_value = response.get("page") if isinstance(response, Mapping) else ""
    response_page = str(
        _page_type_value(response)
        or (response_page_value.get("type") if isinstance(response_page_value, Mapping) else response_page_value)
        or (response.get("page_type") if isinstance(response, Mapping) else "")
        or (response.get("type") if isinstance(response, Mapping) else "")
        or ""
    ).strip().casefold().replace("-", "_")
    if (
        response_status_value is not None
        and 200 <= int(response_status_value) < 300
        and response_page in (_PASSWORD_PAGE_TYPES | _OTP_PAGE_TYPES | _PROFILE_PAGE_TYPES | _CALLBACK_READY_PAGE_TYPES)
    ):
        return
    if _is_rate_limited_response(response, error):
        raise FreeRegisterError(
            node,
            label,
            f"{_response_detail(response, error)}；服务端限流，未重放当前请求",
            retryable=True,
            error_code=f"{stage}_rate_limited",
            **_response_metadata(response, action_hint="等待服务端限流窗口后再重试，避免立即重复提交", diagnostic_error=error),
        )
    if session_invalid(response) or _contains(error, _SESSION_INVALID_MARKERS):
        failure = FreeRegisterError(
            node,
            label,
            f"{_response_detail(response, error)}；OAuth 会话已失效",
            error_code="oauth_session_invalid",
            **_response_metadata(response, action_hint="保持当前邮箱、代理和设备上下文，重建一次 OAuth 会话", diagnostic_error=error),
        )
        if _pre_auth_html_response(response, node) or _pre_auth_access_denied(response, node):
            # A 200 HTML login/error envelope is a route-level response.  The
            # worker may switch to another healthy pool member after the
            # bounded same-session rebuild, without quarantining this proxy.
            setattr(failure, "proxy_retryable", True)
        raise failure
    if _contains(error, _CHALLENGE_MARKERS) or _is_security_challenge_response(response):
        raise FreeRegisterError(
            "free_oauth_security_challenge",
            "等待 Free OAuth 安全验证",
            f"{_response_detail(response, error)}；检测到安全验证页面，已停止自动流程",
            retryable=False,
            error_code="free_oauth_security_challenge",
            **_response_metadata(response, action_hint="保留当前代理与 Profile，人工确认风控状态后再重试", diagnostic_error=error),
        )
    failure = FreeRegisterError(
        node,
        label,
        _response_detail(response, error),
        error_code=f"{stage}_failed",
        **_response_metadata(
            response,
            action_hint=(
                "邮箱尚未确认提交，切换其他健康代理后重试"
                if _pre_auth_access_denied(response, node)
                else f"检查 {label} 的服务端状态后再重试"
            ),
            diagnostic_error=error,
        ),
    )
    if _pre_auth_access_denied(response, node):
        setattr(failure, "proxy_retryable", True)
    raise failure


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
    # An explicit login_password state is authoritative.  Do this before the
    # broader signup URL markers because older responses sometimes carry a
    # stale create-account location alongside the current page type.
    if page_type in {"login_password", "login-password", "log_in_password"}:
        return "login"
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
    # An explicit profile/about-you page is authoritative. Some authorize
    # envelopes retain a stale phone-related continuation URL while the
    # visible state has already advanced to the profile form.
    if page.replace("-", "_") in _PROFILE_PAGE_TYPES:
        return False
    locations = " ".join(_page_locations(response)).casefold()
    return "phone" in page or "/phone" in locations or "contact-verification" in locations


def _is_retryable_otp_error(response: Any) -> bool:
    _ok, _page, _continue, error_text, _session_invalid = _chain_helpers()
    return _contains(error_text(response), _RETRYABLE_OTP_MARKERS)


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
    if (
        _is_security_page(response)
        or _is_security_challenge_response(response)
    ):
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
        # A login-password page exposes a separate one-time-code action in
        # the maintained AutoRegister flow.  Keep its node in the existing
        # login-OTP bucket so diagnostics and retry policy remain stable.
        "send_passwordless_otp": ("free_existing_login_otp", "派发已有账号一次性验证码"),
        "send_mfa_otp": ("free_existing_login_otp", "派发已有账号登录验证码"),
        "verify_email_otp": ("free_email_otp_validate", "验证 Free 邮箱验证码"),
        "verify_mfa_otp": ("free_email_otp_validate", "验证已有账号登录验证码"),
        "visit_continue": ("free_account_create", "进入 Free 账号资料页"),
        "create_account_profile": ("free_account_create", "创建 Free 账号"),
        "accept_consent": ("free_oauth_callback", "确认 Free OAuth 授权"),
        "follow_continue_until_code": ("free_oauth_callback", "Free OAuth 回调"),
        "complete_chatgpt_callback": ("free_oauth_callback", "完成 ChatGPT OAuth 回调"),
        "exchange_code": ("free_access_token", "获取 Free access token"),
    }.get(method, ("free_protocol_result", "Free 协议注册"))


def _call_transport(
    transport: Any,
    method: str,
    *args: Any,
    flow: str = "authorize_continue",
    stop_requested: Callable[[], bool] | None = None,
    log: Callable[..., Any] | None = None,
    on_not_started: Callable[[], Any] | None = None,
) -> Any:
    try:
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
    except BaseException:
        # No transport callable has been entered, so a confirmation made
        # immediately before this helper may be safely undone. Never let an
        # abort-hook failure replace the original transport failure.
        if callable(on_not_started):
            try:
                on_not_started()
            except Exception as abort_exc:
                _log(
                    log,
                    f"邮箱租约确认撤销失败（{type(abort_exc).__name__}），保留为已确认",
                    "warn",
                )
        raise
    try:
        result = function(*args)
        _check_stopped(stop_requested)
        # ``authorize/continue`` returns the next page as a successful JSON
        # envelope.  Some recovered wrappers run their generic success/error
        # classifier before returning that envelope and mislabel
        # ``login_password`` as a failed email identifier.  Preserve the raw
        # 2xx JSON state for the explicit state machine; security HTML still
        # follows the normal challenge path below.
        if (
            method == "submit_email_identifier"
            and _status(result) is not None
            and 200 <= int(_status(result)) < 300
            and not _page_is_html(result)
            and not _is_security_challenge_response(result)
        ):
            return result
        node, label = _transport_node(method)
        if flow == "password_verify" and method in {
            "send_email_otp", "send_passwordless_otp", "verify_email_otp"
        }:
            action = "派发" if method.startswith("send_") else "验证"
            node, label = "free_existing_login_otp", f"{action}已有账号登录验证码"
        # A challenge can be returned by initiate, authorize/continue, OTP,
        # profile, consent, or callback requests.  Wait only through the
        # existing transport session/hook; never replay ``function`` (which
        # would duplicate an email/OTP POST).  The helper returns the original
        # challenge when it remains unresolved, so the stable failure node is
        # retained below.
        result = _wait_for_security_challenge(
            transport,
            result,
            method=method,
            flow=flow,
            stop_requested=stop_requested,
            log=log or getattr(transport, "log_fn", None),
        )
        _raise_security_page(result)
        _ok, _page, _continue, error_text, session_invalid = _chain_helpers()
        error = str(error_text(result) or "")
        if _is_rate_limited_response(result, error):
            raise FreeRegisterError(
                node,
                label,
                f"{_response_detail(result, error)}；服务端限流，未重放当前请求",
                retryable=True,
                error_code=f"{node}_rate_limited",
                **_response_metadata(result, action_hint="等待服务端限流窗口后再重试，避免立即重复提交", diagnostic_error=error),
            )
        trusted_bootstrap = _trusted_html_bootstrap(result, method)
        if (session_invalid(result) or _contains(error, _SESSION_INVALID_MARKERS)) and not trusted_bootstrap:
            failure = FreeRegisterError(
                node, label, f"{_response_detail(result, error)}；OAuth 会话已失效",
                error_code="oauth_session_invalid",
                **_response_metadata(result, action_hint="保持当前邮箱、代理和设备上下文，重建一次 OAuth 会话", diagnostic_error=error),
            )
            if _pre_auth_html_response(result, node) or _pre_auth_access_denied(result, node):
                setattr(failure, "proxy_retryable", True)
            raise failure
        if _pre_auth_access_denied(result, node):
            failure = FreeRegisterError(
                node,
                label,
                f"{_response_detail(result, error)}；邮箱提交前访问被拒绝",
                error_code=f"{node}_access_denied",
                **_response_metadata(
                    result,
                    action_hint="邮箱尚未确认提交，切换其他健康代理后重试",
                    diagnostic_error=error,
                ),
            )
            setattr(failure, "proxy_retryable", True)
            raise failure
        return result
    except FreeRegisterError:
        raise
    except Exception as exc:
        node, label = _transport_node(method)
        if flow == "password_verify" and method in {
            "send_email_otp", "send_passwordless_otp", "verify_email_otp"
        }:
            action = "派发" if method.startswith("send_") else "验证"
            node, label = "free_existing_login_otp", f"{action}已有账号登录验证码"
        if _contains(exc, ("rate_limit", "rate limit", "ratelimit", "too many requests")):
            raise FreeRegisterError(
                node,
                label,
                "OAuth 请求被服务端限流，未重放当前请求",
                retryable=True,
                error_code=f"{node}_rate_limited",
                action_hint="等待服务端限流窗口后再重试，避免立即重复提交",
                diagnostic=f"transport={method}; exception={type(exc).__name__}",
            ) from exc
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


def _invoke_mailbox_hook(
    callback: Callable[..., Any] | None,
    *,
    task_id: str,
    email: str,
    driver: str,
    stage: str,
    submission_definitely_not_started: bool | None = None,
) -> Any:
    """Invoke a mailbox lease callback exactly once after signature binding."""
    if not callable(callback):
        return None
    keyword_context: dict[str, Any] = {
        "task_id": task_id,
        "email": email,
        "driver": driver,
        "stage": stage,
    }
    if submission_definitely_not_started is not None:
        keyword_context["submission_definitely_not_started"] = bool(
            submission_definitely_not_started
        )
    candidates = (
        ((), keyword_context),
        ((task_id,), {}),
        ((), {}),
    )
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        return callback(**keyword_context)
    for args, kwargs in candidates:
        try:
            signature.bind(*args, **kwargs)
        except TypeError:
            continue
        return callback(*args, **kwargs)
    raise TypeError("unsupported mailbox lease callback signature")


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
    send_url_override: str | None = None,
) -> Any:
    ok, page_type, continue_url, error_text, _session_invalid = _chain_helpers()
    current = response
    retry_count = 0
    max_attempts = 3
    budget = resend_budget if isinstance(resend_budget, dict) else {"used": 0}
    # AutoRegister sends the login-page email OTP through the normal email
    # verification action (with an empty continuation URL). Keep the existing
    # stage identity for diagnostics while the transport owns its concrete
    # request flow and endpoint fallback.
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
            (continue_url(current) if send_url_override is None else send_url_override) or "",
            flow=sentinel_flow,
            stop_requested=stop_requested,
            log=log,
        )
        if not _is_state_response(sent, ok):
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
                log=log,
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
        if _is_state_response(current, ok):
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
    confirm_mailbox: Callable[..., Any] | None = None,
    abort_mailbox_confirmation: Callable[..., Any] | None = None,
    prelude: Callable[..., Any] | None = None,
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
    # The authorize/continue request can itself dispatch the first email OTP.
    # Capture the mailbox baseline before any request in this phase.
    _reset_otp_request(otp_provider)
    _prepare_otp(otp_provider, "free_email_otp_wait", force_snapshot=force_otp_snapshot)
    mailbox_confirmed_for_submit = False

    def confirm_mailbox_for_submission() -> None:
        nonlocal mailbox_confirmed_for_submit
        if mailbox_confirmed_for_submit or not callable(confirm_mailbox):
            return
        try:
            confirmed = _invoke_mailbox_hook(
                confirm_mailbox,
                task_id=task_id,
                email=email,
                driver="protocol",
                stage="free_email_identifier",
            )
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError(
                "free_mailbox_lease",
                "确认 Free 邮箱租约",
                "提交邮箱前确认租约失败",
                retryable=True,
                error_code="free_mailbox_lease_confirm_failed",
                diagnostic=f"callback={type(exc).__name__}",
            ) from exc
        if confirmed is False:
            raise FreeRegisterError(
                "free_mailbox_lease",
                "确认 Free 邮箱租约",
                "提交邮箱前邮箱租约已失效或被其他任务占用",
                retryable=True,
                error_code="free_mailbox_lease_conflict",
            )
        mailbox_confirmed_for_submit = True

    def abort_if_transport_not_started() -> None:
        if not mailbox_confirmed_for_submit or not callable(abort_mailbox_confirmation):
            return
        outcome = _invoke_mailbox_hook(
            abort_mailbox_confirmation,
            task_id=task_id,
            email=email,
            driver="protocol",
            stage="free_email_identifier",
            submission_definitely_not_started=True,
        )
        if outcome is False:
            _log(log, "邮箱提交尚未开始，但租约确认未撤销；保守保留已确认状态", "warn")

    # ``prelude`` remains in the keyword signature for older callers, but is
    # intentionally ignored.  The ChatGPT/NextAuth prelude has its own CSRF
    # and cookie session and cannot be mixed with this task's Codex PKCE
    # context.  Keeping the argument as a no-op avoids breaking facades while
    # making the session boundary explicit and testable.
    if callable(prelude):
        _log(log, "忽略不兼容的 AutoRegister OAuth 前置；沿用当前任务 Codex PKCE 会话", "warn")

    # The Free protocol flow always owns one Codex OAuth session.  In
    # particular, do not replace this pair with a ChatGPT/NextAuth prelude:
    # the returned continuation must remain bound to ``oauth_context``.
    start = _call_transport(
        transport,
        "initiate_oauth",
        oauth_url,
        flow="oauth_authorize",
        stop_requested=stop_requested,
        log=log,
    )
    trusted_start = _trusted_html_bootstrap(start, "initiate_oauth")
    if not ok(start) and not trusted_start:
        _raise_response(start, node="free_oauth_session", label="Free OAuth 会话", stage="free_oauth_session")
    if _page_is_html(start):
        if _is_security_challenge_response(start):
            raise FreeRegisterError(
                "free_oauth_security_challenge",
                "等待 Free OAuth 安全验证",
                "OAuth 授权返回安全验证页面，已停止自动流程",
                retryable=False,
                error_code="free_oauth_security_challenge",
            )
        if not _trusted_oauth_bootstrap_location(start):
            failure = FreeRegisterError(
                "free_oauth_session",
                "Free OAuth 会话",
                f"OAuth 授权返回无法识别的 HTML（{_response_detail(start)}）",
                error_code="oauth_bootstrap_html",
            )
            if _pre_auth_html_response(start, "free_oauth_session"):
                setattr(failure, "proxy_retryable", True)
            raise failure
        _log(log, "OAuth 授权返回受信任 Auth HTML 起始页，继续使用当前会话提交邮箱", "info")
    _log(log, f"OAuth 会话建立成功（HTTP {_status(start) or '-'}，Content-Type {_content_type(start) or '-'}）", "success")

    _stage(stage, task_id, "free_email_identifier")
    confirm_mailbox_for_submission()
    response = _call_transport(
        transport,
        "submit_email_identifier",
        email,
        stop_requested=stop_requested,
        log=log,
        on_not_started=abort_if_transport_not_started,
    )
    identifier_status = _status(response)
    if identifier_status is None or not 200 <= int(identifier_status) < 300:
        _raise_response(response, node="free_email_identifier", label="识别 Free 注册邮箱", stage="free_email_identifier")
    current_page = str(page_type(response) or _page_type_value(response) or "").strip().casefold().replace("-", "_")
    known_html_page = current_page in (_PASSWORD_PAGE_TYPES | _OTP_PAGE_TYPES | _PROFILE_PAGE_TYPES | _CALLBACK_READY_PAGE_TYPES)
    if _page_is_html(response) and not known_html_page:
        if _is_security_challenge_response(response):
            raise FreeRegisterError(
                "free_oauth_security_challenge",
                "等待 Free OAuth 安全验证",
                "邮箱识别返回安全验证页面，已停止自动流程",
                retryable=False,
                error_code="free_oauth_security_challenge",
            )
        failure = FreeRegisterError(
            "free_email_identifier",
            "识别 Free 注册邮箱",
            f"邮箱识别返回 HTML（{_response_detail(response)}），授权会话未建立",
            error_code="oauth_bootstrap_html",
        )
        if _pre_auth_html_response(response, "free_email_identifier"):
            setattr(failure, "proxy_retryable", True)
        raise failure
    _log(log, f"邮箱提交成功（页面={current_page or '-'}，continue={'yes' if _next_url(response) else 'no'}）", "info")

    # Keep advancing through the finite authorization state machine. Providers
    # can return another OTP/password envelope after a successful transition;
    # never jump straight to callback/token in that case.
    password_page_handled = False
    registration_password_used = False
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
                    log=log,
                )
                registration_password_used = True
            else:
                # AutoRegister's browser path treats ``login_password`` as a
                # passwordless-capable entry page: it clicks the explicit
                # one-time-code action before waiting for mail.  The
                # recovered HTTP response may advertise an email-OTP send
                # URL as ``continue_url`` even when that action was not
                # selected, so do not let that URL choose the endpoint here.
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
                    # The reference transport owns endpoint fallback here;
                    # do not force the dedicated passwordless endpoint.
                    send_method="send_email_otp",
                    verify_method="verify_email_otp",
                    send_before_wait=True,
                    resend_budget=otp_resend_budget,
                    stop_requested=stop_requested,
                    send_url_override="",
                )
            if not _is_state_response(response, ok):
                _raise_response(response, node="free_email_password", label="提交 Free 注册密码", stage="free_email_password")
            continue
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
                    log=log,
                )
                if not _is_state_response(response, ok):
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
                log=log,
            )
            if not _is_state_response(response, ok):
                _raise_response(response, node="free_account_create", label="创建 Free 账号", stage="free_account_create")
            continue
        if _is_phone(response):
            raise FreeRegisterError(
                "free_phone_required",
                "Free 注册手机号节点",
                "协议注册进入手机号验证，Free 流程未调用接码平台",
                retryable=False,
                error_code="free_phone_required",
                **_response_metadata(
                    response,
                    action_hint="根据节点日志检查上游响应和当前代理",
                    diagnostic_error="协议注册进入手机号验证，Free 流程未调用接码平台",
                ),
            )
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
                    log=log,
                )
                if not _is_state_response(response, ok):
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
        log=log,
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
    session_token = ""
    complete_callback = getattr(transport, "complete_chatgpt_callback", None)
    capture_session_token = getattr(transport, "chatgpt_access_token", None)
    if callable(complete_callback) and callable(capture_session_token):
        callback_result = _call_transport(
            transport,
            "complete_chatgpt_callback",
            next_url,
            flow="oauth_callback",
            stop_requested=stop_requested,
            log=log,
        )
        if isinstance(callback_result, Mapping):
            callback_status = _status(callback_result)
            callback_ok = callback_result.get("ok")
            callback_failed = callback_ok is False or (
                isinstance(callback_ok, str)
                and callback_ok.strip().casefold() in {"false", "0", "no", "failed", "failure", "error"}
            )
            if (callback_status is not None and not 200 <= callback_status < 300) or callback_failed:
                _raise_response(
                    callback_result,
                    node="free_oauth_callback",
                    label="完成 ChatGPT OAuth 回调",
                    stage="free_oauth_callback",
                )
        session_token = str(capture_session_token() or "").strip()

    if session_token:
        tokens: Mapping[str, Any] = {
            "access_token": session_token,
            "token_source": "chatgpt_session",
        }
    else:
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
            log=log,
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
    token = str(
        tokens.get("access_token")
        or tokens.get("accessToken")
        or tokens.get("token")
        or ""
    ).strip()
    if not token:
        raise FreeRegisterError(
            "free_access_token",
            "获取 Free access token",
            "OAuth Token 交换完成但未返回 access token",
            error_code="token_exchange_failed",
        )
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
        "registration_password_used": registration_password_used,
    }
    if result["account_flow"] == "signup" and registration_password_used:
        result["password"] = password or FIXED_PASSWORD
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
    confirm_mailbox: Callable[..., Any] | None = None,
    abort_mailbox_confirmation: Callable[..., Any] | None = None,
    prelude: Callable[..., Any] | None = None,
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
    # A lease confirmation is the durable hand-off boundary for the mailbox.
    # Once the transport callable has been entered, its response may be
    # ambiguous (for example, a connection can close after the server writes
    # the identifier).  In that case a session rebuild would replay the email
    # POST.  Track the boundary at this outer scope so the one-shot recovery
    # decision can fail closed without changing legacy callers that do not
    # provide lease callbacks.
    mailbox_boundary_crossed = {"value": False}

    def tracked_confirm(*args: Any, **kwargs: Any) -> Any:
        outcome = _invoke_mailbox_hook(
            confirm_mailbox,
            task_id=str(kwargs.get("task_id") or (args[0] if args else "")),
            email=str(kwargs.get("email") or email),
            driver=str(kwargs.get("driver") or "protocol"),
            stage=str(kwargs.get("stage") or "free_email_identifier"),
        )
        # ``_run_once`` treats every result except an explicit ``False`` as a
        # successful confirmation. Mirror that compatibility rule, but keep
        # the outer recovery guard conservative when an adapter returns None.
        if outcome is not False:
            mailbox_boundary_crossed["value"] = True
        return outcome

    def tracked_abort(*args: Any, **kwargs: Any) -> Any:
        outcome = _invoke_mailbox_hook(
            abort_mailbox_confirmation,
            task_id=str(kwargs.get("task_id") or (args[0] if args else "")),
            email=str(kwargs.get("email") or email),
            driver=str(kwargs.get("driver") or "protocol"),
            stage=str(kwargs.get("stage") or "free_email_identifier"),
            submission_definitely_not_started=kwargs.get(
                "submission_definitely_not_started"
            ),
        )
        if outcome:
            mailbox_boundary_crossed["value"] = False
        return outcome

    tracked_confirm_callback = tracked_confirm if callable(confirm_mailbox) else None
    tracked_abort_callback = (
        tracked_abort if callable(abort_mailbox_confirmation) else None
    )
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
                confirm_mailbox=tracked_confirm_callback,
                abort_mailbox_confirmation=tracked_abort_callback,
                prelude=prelude,
            )
            result["oauth_session_rebuilds"] = session_rebuilds
            return result, active
        except FreeRegisterError as exc:
            should_rebuild = (
                session_rebuilds == 0
                and str(exc.error_code or "") in {"oauth_session_invalid", "oauth_bootstrap_html"}
                and bool(transport_factory)
                # Legacy callers without a mailbox callback retain the
                # historical rebuild behavior.  Lease-aware callers must
                # preserve an ambiguous confirmed submission as pending
                # instead of replaying the identifier POST.
                and not mailbox_boundary_crossed["value"]
            )
            if not should_rebuild:
                exc.session_rebuilds = session_rebuilds
                raise
            session_rebuilds += 1
            _log(log, "OAuth 会话失效，清理旧 Cookie/CSRF 并重建一次授权会话；邮箱、代理和设备上下文保持不变", "warn")
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
