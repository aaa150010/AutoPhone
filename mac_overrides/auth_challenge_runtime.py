"""Challenge-driven orchestration for the pre-phone OpenAI auth flow.

The recovered chain remains responsible for its established happy path. This
module only continues challenge combinations that the recovered fixed ordering
cannot consume. Phone entry and every later step are explicit terminal values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable, Mapping
from urllib.parse import urljoin, urlsplit


DYNAMIC_AUTH_CHALLENGES = "dynamic_auth_challenges"
MAX_CHALLENGE_STEPS = 8

PASSWORD_PAGE_TYPES = frozenset(
    {"password", "password_required", "password_verification", "login_password"}
)
EMAIL_OTP_PAGE_TYPES = frozenset(
    {"email_otp", "email_otp_verification", "email_verification"}
)
TOTP_PAGE_TYPES = frozenset(
    {"mfa_otp", "mfa_challenge", "mfa_otp_verification", "totp", "totp_verification"}
)
PHONE_PAGE_TYPES = frozenset(
    {
        "add_phone",
        "contact_verification",
        "phone_number_collection",
        "phone_otp",
        "phone_otp_verification",
        "phone_verification",
        "phone_number_verification",
        "sms_otp",
        "sms_otp_verification",
    }
)
COMPLETE_PAGE_TYPES = frozenset(
    {
        "account_setup",
        "complete",
        "completed",
        "consent",
        "oauth_callback",
        "profile",
        "profile_complete",
        "profile_completion",
        "register",
        "sign_in_with_chatgpt_codex_consent",
        "success",
        "terms",
        "workspace_select",
    }
)

_PASSWORD_CONTINUE_PREFIXES = ("/log-in/password", "/password")
_EMAIL_OTP_CONTINUE_PREFIXES = ("/email-verification", "/email-otp")
_TOTP_CONTINUE_PREFIXES = ("/mfa-challenge", "/mfa", "/totp")
_PHONE_CONTINUE_PREFIXES = (
    "/add-phone",
    "/contact-verification",
    "/phone-number-collection",
    "/phone-verification",
)
_COMPLETE_CONTINUE_PREFIXES = (
    "/account-setup",
    "/authorize",
    "/callback",
    "/consent",
    "/oauth/",
    "/profile",
    "/workspace",
)
_SESSION_INVALID_CODES = frozenset(
    {
        "auth_session_invalid",
        "invalid_authorization_step",
        "mfa_authorization_step_expired",
        "oauth_session_invalid",
        "session_expired",
    }
)
_SESSION_INVALID_MARKERS = (
    "invalid authorization step",
    "mfa_authorization_step_expired",
    "oauth_session_invalid",
    "sign-in session is no longer valid",
    "session is no longer valid",
)

_RECOVERED_ALLOWED_AFTER = {
    "submit_email": PASSWORD_PAGE_TYPES | EMAIL_OTP_PAGE_TYPES | TOTP_PAGE_TYPES,
    "password": EMAIL_OTP_PAGE_TYPES | TOTP_PAGE_TYPES,
    "mfa": EMAIL_OTP_PAGE_TYPES,
    "email_otp": frozenset(),
}
_SAFE_CODE_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,80}$")


class AuthChallengeError(RuntimeError):
    """Stable, credential-free failure raised by the challenge orchestrator."""

    def __init__(self, code: str, message: str) -> None:
        self.code = str(code or "auth_challenge_failed")
        super().__init__(f"{self.code}: {message}")


@dataclass(frozen=True)
class ChallengeSnapshot:
    kind: str
    page_type: str
    continue_path: str

    @property
    def signature(self) -> tuple[str, str, str]:
        return self.kind, self.page_type, self.continue_path


@dataclass
class AuthChallengeContext:
    transport: Any = field(repr=False)
    account_email: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    email_otp_provider: Any = field(default=None, repr=False)
    config: Mapping[str, Any] = field(default_factory=dict, repr=False)
    log_fn: Callable[..., Any] | None = field(default=None, repr=False)
    page_type_fn: Callable[[Any], Any] | None = field(default=None, repr=False)
    continue_url_fn: Callable[[Any], Any] | None = field(default=None, repr=False)
    success_fn: Callable[[Any], bool] | None = field(default=None, repr=False)

    @property
    def enabled(self) -> bool:
        return dynamic_auth_enabled(self.config)


Handler = Callable[[AuthChallengeContext, Any], Any]


def _as_bool(value: Any, default: bool = True) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", "disabled"}


def dynamic_auth_enabled(config: Any) -> bool:
    value = config if isinstance(config, Mapping) else {}
    return _as_bool(value.get(DYNAMIC_AUTH_CHALLENGES), True)


def normalize_page_type(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    return re.sub(r"[^a-z0-9_]+", "_", text)[:80].strip("_")


def _page_type(response: Any, callback: Callable[[Any], Any] | None = None) -> str:
    if callable(callback):
        try:
            value = callback(response)
        except Exception:
            value = ""
        if value:
            return normalize_page_type(value)
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page")
    if isinstance(page, Mapping):
        return normalize_page_type(page.get("type"))
    return normalize_page_type(response.get("page_type"))


def _continue_url(response: Any, callback: Callable[[Any], Any] | None = None) -> str:
    if callable(callback):
        try:
            value = str(callback(response) or "").strip()
        except Exception:
            value = ""
        if value:
            return value
    if isinstance(response, Mapping):
        return str(response.get("continue_url") or response.get("url") or "").strip()
    return ""


def _safe_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(urljoin("https://auth.openai.com/", text))
    except (TypeError, ValueError):
        return ""
    if parsed.hostname not in {"auth.openai.com", "chatgpt.com", "www.chatgpt.com"}:
        return ""
    return parsed.path[:160]


def _path_matches(path: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        base = prefix.rstrip("/")
        if path == base or path.startswith(f"{base}/"):
            return True
    return False


def classify_challenge(
    response: Any,
    *,
    page_type_fn: Callable[[Any], Any] | None = None,
    continue_url_fn: Callable[[Any], Any] | None = None,
) -> ChallengeSnapshot:
    page_type = _page_type(response, page_type_fn)
    continue_path = _safe_path(_continue_url(response, continue_url_fn))
    if page_type in PASSWORD_PAGE_TYPES or _path_matches(
        continue_path, _PASSWORD_CONTINUE_PREFIXES
    ):
        kind = "password"
    elif page_type in EMAIL_OTP_PAGE_TYPES or _path_matches(
        continue_path, _EMAIL_OTP_CONTINUE_PREFIXES
    ):
        kind = "email_otp"
    elif page_type in TOTP_PAGE_TYPES or _path_matches(
        continue_path, _TOTP_CONTINUE_PREFIXES
    ):
        kind = "totp"
    elif page_type in PHONE_PAGE_TYPES or _path_matches(
        continue_path, _PHONE_CONTINUE_PREFIXES
    ):
        kind = "phone"
    elif page_type in COMPLETE_PAGE_TYPES or (
        not page_type and _path_matches(continue_path, _COMPLETE_CONTINUE_PREFIXES)
    ):
        kind = "complete"
    else:
        kind = "unsupported"
    return ChallengeSnapshot(kind, page_type, continue_path)


def bind_transport_context(
    transport: Any,
    *,
    account_email: Any = "",
    password: Any = "",
    email_otp_provider: Any = None,
    config: Any = None,
    log_fn: Callable[..., Any] | None = None,
    page_type_fn: Callable[[Any], Any] | None = None,
    continue_url_fn: Callable[[Any], Any] | None = None,
    success_fn: Callable[[Any], bool] | None = None,
) -> AuthChallengeContext | None:
    if transport is None:
        return None
    runtime_config = config if isinstance(config, Mapping) else {}
    register = runtime_config.get("register")
    register = register if isinstance(register, Mapping) else {}
    context = AuthChallengeContext(
        transport=transport,
        account_email=str(account_email or "").strip().lower(),
        password=str(password or register.get("password") or "").strip(),
        email_otp_provider=email_otp_provider,
        config=runtime_config,
        log_fn=log_fn,
        page_type_fn=page_type_fn,
        continue_url_fn=continue_url_fn,
        success_fn=success_fn,
    )
    setattr(transport, "_gptphone_auth_challenge_context", context)
    return context


def clear_transport_context(transport: Any) -> None:
    if transport is None:
        return
    try:
        delattr(transport, "_gptphone_auth_challenge_context")
    except AttributeError:
        pass
    try:
        delattr(transport, "_gptphone_dynamic_auth_active")
    except AttributeError:
        pass


def _context(transport: Any) -> AuthChallengeContext | None:
    value = getattr(transport, "_gptphone_auth_challenge_context", None)
    return value if isinstance(value, AuthChallengeContext) else None


def _stopped(context: AuthChallengeContext) -> bool:
    value = context.config.get("_stop_requested")
    if callable(value):
        try:
            return bool(value())
        except TypeError:
            return bool(value)
    is_set = getattr(value, "is_set", None)
    return bool(is_set()) if callable(is_set) else bool(value)


def _is_success(context: AuthChallengeContext, response: Any) -> bool:
    if callable(context.success_fn):
        return bool(context.success_fn(response))
    if not isinstance(response, Mapping):
        return False
    try:
        status = int(response.get("_status") or 200)
    except (TypeError, ValueError):
        return False
    return 200 <= status < 400 and not response.get("error")


def _failure_code(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    error = response.get("error")
    code = error.get("code") if isinstance(error, Mapping) else error
    if not code:
        code = response.get("error_code") or response.get("code")
    value = str(code or "").strip()
    return value if _SAFE_CODE_RE.fullmatch(value) else ""


def _session_invalidation_code(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    code = _failure_code(response).lower()
    if code in _SESSION_INVALID_CODES:
        return (
            "mfa_authorization_step_expired"
            if code in {"invalid_authorization_step", "mfa_authorization_step_expired"}
            else "oauth_session_invalid"
        )
    candidates: list[Any] = [response.get("error"), response.get("message")]
    error = response.get("error")
    if isinstance(error, Mapping):
        candidates.extend((error.get("code"), error.get("message")))
    text = " ".join(str(value or "") for value in candidates).lower()
    if "invalid authorization step" in text or "mfa_authorization_step_expired" in text:
        return "mfa_authorization_step_expired"
    if any(marker in text for marker in _SESSION_INVALID_MARKERS):
        return "oauth_session_invalid"
    return ""


def _stop_for_session_invalidation(
    context: AuthChallengeContext,
    response: Any,
) -> Any:
    reason_code = _session_invalidation_code(response)
    if not reason_code:
        return None
    clear_transport_context(context.transport)
    raw_code = _failure_code(response).lower()
    if raw_code in {"session_expired", "auth_session_invalid"}:
        raise AuthChallengeError(
            "oauth_session_invalid",
            f"OpenAI 登录会话已失效：{_failure_detail(response)}",
        )
    return response


def _failure_detail(response: Any) -> str:
    if not isinstance(response, Mapping):
        return "服务端未返回可识别响应"
    details = []
    try:
        status = int(response.get("_status") or 0)
    except (TypeError, ValueError):
        status = 0
    if status:
        details.append(f"HTTP {status}")
    code = _failure_code(response)
    if code:
        details.append(code)
    return " / ".join(details) or "服务端未返回错误详情"


def _log(context: AuthChallengeContext, message: str, level: str = "info") -> None:
    if not callable(context.log_fn):
        return
    try:
        context.log_fn(message, level)
    except TypeError:
        context.log_fn(message)


def _provider_call(provider: Any, name: str, *args: Any) -> Any:
    callback = getattr(provider, name, None)
    return callback(*args) if callable(callback) else None


def _handle_password(context: AuthChallengeContext, _response: Any) -> Any:
    if not context.password:
        raise AuthChallengeError("password_required", "当前邮箱行没有可用密码")
    return context.transport.verify_password(context.password)


def _handle_email_otp(context: AuthChallengeContext, response: Any) -> Any:
    provider = context.email_otp_provider
    if provider is None:
        raise AuthChallengeError("email_otp_provider_missing", "邮箱验证码处理器不可用")
    _provider_call(provider, "acquire_login_slot")
    continue_url = _continue_url(response, context.continue_url_fn)
    sender = getattr(context.transport, "send_email_otp", None)
    if callable(sender):
        sent = sender(continue_url)
        if not _is_success(context, sent):
            raise AuthChallengeError(
                "email_otp_send_failed", f"邮箱验证码发送失败：{_failure_detail(sent)}"
            )
    _provider_call(provider, "mark_sent")
    code = str(_provider_call(provider, "wait_code", context.account_email) or "").strip()
    if not code:
        raise AuthChallengeError("email_otp_empty", "邮箱验证码处理器未返回验证码")
    verified = context.transport.verify_email_otp(code)
    if _is_success(context, verified):
        _provider_call(provider, "mark_verified")
    return verified


def _handle_totp(context: AuthChallengeContext, response: Any) -> Any:
    provider = context.email_otp_provider
    if provider is None:
        raise AuthChallengeError("mfa_otp_provider_missing", "2FA 验证码处理器不可用")
    continue_url = _continue_url(response, context.continue_url_fn)
    sender = getattr(context.transport, "send_mfa_otp", None)
    if callable(sender):
        sent = sender(continue_url)
        if not _is_success(context, sent):
            raise AuthChallengeError(
                "mfa_otp_send_failed", f"2FA challenge 创建失败：{_failure_detail(sent)}"
            )
    _provider_call(provider, "mark_sent")
    code = str(_provider_call(provider, "wait_code", context.account_email) or "").strip()
    if not code:
        raise AuthChallengeError("mfa_otp_empty", "2FA 验证码处理器未返回验证码")
    verified = context.transport.verify_mfa_otp(code)
    if _is_success(context, verified):
        _provider_call(provider, "mark_verified")
        return verified
    if _failure_code(verified).lower() != "incorrect_code":
        return verified
    if _stopped(context):
        raise AuthChallengeError("task_stopped", "任务已停止")
    _log(context, "  [动态认证/auth_challenge] 2FA 动态码被拒绝，等待下一时间窗口重试", "warn")
    retry_code = str(
        _provider_call(provider, "wait_code", context.account_email) or ""
    ).strip()
    if not retry_code:
        if _stopped(context):
            raise AuthChallengeError("task_stopped", "任务已停止")
        raise AuthChallengeError("mfa_otp_empty", "2FA 重试未返回新的动态码")
    if retry_code == code:
        raise AuthChallengeError(
            "mfa_otp_retry_code_unchanged",
            "2FA 重试仍处于同一动态码时间窗口",
        )
    verified = context.transport.verify_mfa_otp(retry_code)
    if _is_success(context, verified):
        _provider_call(provider, "mark_verified")
    return verified


DEFAULT_HANDLERS: Mapping[str, Handler] = {
    "password": _handle_password,
    "email_otp": _handle_email_otp,
    "totp": _handle_totp,
}


def resolve_auth_challenges(
    transport: Any,
    response: Any,
    *,
    handlers: Mapping[str, Handler] | None = None,
    max_steps: int = MAX_CHALLENGE_STEPS,
) -> Any:
    context = _context(transport)
    if context is None or not context.enabled:
        return response
    if getattr(transport, "_gptphone_dynamic_auth_active", False):
        return response
    selected_handlers = dict(DEFAULT_HANDLERS if handlers is None else handlers)
    seen: set[tuple[str, str, str]] = set()
    steps = 0
    setattr(transport, "_gptphone_dynamic_auth_active", True)
    try:
        while True:
            invalid = _stop_for_session_invalidation(context, response)
            if invalid is not None:
                return invalid
            snapshot = classify_challenge(
                response,
                page_type_fn=context.page_type_fn,
                continue_url_fn=context.continue_url_fn,
            )
            if snapshot.kind == "phone":
                clear_transport_context(transport)
                return response
            if snapshot.kind == "complete":
                if not _is_success(context, response):
                    raise AuthChallengeError(
                        "auth_challenge_complete_failed",
                        f"认证完成响应失败：{_failure_detail(response)}",
                    )
                clear_transport_context(transport)
                return response
            if snapshot.kind == "unsupported":
                raise AuthChallengeError(
                    "auth_challenge_unsupported",
                    "无法识别认证页面"
                    f" (page_type={snapshot.page_type or 'unknown'}, "
                    f"continue_path={snapshot.continue_path or '-'})",
                )
            if snapshot.signature in seen:
                raise AuthChallengeError(
                    "auth_challenge_loop_detected",
                    "认证页面重复出现"
                    f" (challenge={snapshot.kind}, continue_path={snapshot.continue_path or '-'})",
                )
            if steps >= max(1, min(int(max_steps), MAX_CHALLENGE_STEPS)):
                raise AuthChallengeError(
                    "auth_challenge_step_limit",
                    f"认证挑战超过 {MAX_CHALLENGE_STEPS} 步",
                )
            seen.add(snapshot.signature)
            handler = selected_handlers.get(snapshot.kind)
            if not callable(handler):
                raise AuthChallengeError(
                    "auth_challenge_handler_missing",
                    f"认证挑战缺少处理器 (challenge={snapshot.kind})",
                )
            if _stopped(context):
                raise AuthChallengeError("task_stopped", "任务已停止")
            steps += 1
            _log(
                context,
                "  [动态认证/auth_challenge] "
                f"步骤 {steps}/{MAX_CHALLENGE_STEPS}：{snapshot.kind} "
                f"(continue_path={snapshot.continue_path or '-'})",
            )
            response = handler(context, response)
            invalid = _stop_for_session_invalidation(context, response)
            if invalid is not None:
                return invalid
            if not _is_success(context, response):
                raise AuthChallengeError(
                    f"auth_challenge_{snapshot.kind}_failed",
                    f"认证挑战提交失败：{_failure_detail(response)}",
                )
    except Exception:
        clear_transport_context(transport)
        raise


def continue_if_needed(transport: Any, response: Any, *, origin: str) -> Any:
    """Continue only when the recovered ordering cannot consume the response."""

    context = _context(transport)
    if (
        context is None
        or not context.enabled
        or getattr(transport, "_gptphone_dynamic_auth_active", False)
    ):
        return response
    invalid = _stop_for_session_invalidation(context, response)
    if invalid is not None:
        return invalid
    snapshot = classify_challenge(
        response,
        page_type_fn=context.page_type_fn,
        continue_url_fn=context.continue_url_fn,
    )
    if snapshot.kind == "phone":
        clear_transport_context(transport)
        return response
    if snapshot.kind == "complete" and _is_success(context, response):
        clear_transport_context(transport)
        return response
    allowed = _RECOVERED_ALLOWED_AFTER.get(str(origin or ""), frozenset())
    if snapshot.page_type in allowed:
        return response
    return resolve_auth_challenges(transport, response)


__all__ = [
    "AuthChallengeContext",
    "AuthChallengeError",
    "ChallengeSnapshot",
    "DEFAULT_HANDLERS",
    "DYNAMIC_AUTH_CHALLENGES",
    "MAX_CHALLENGE_STEPS",
    "bind_transport_context",
    "classify_challenge",
    "clear_transport_context",
    "continue_if_needed",
    "dynamic_auth_enabled",
    "normalize_page_type",
    "resolve_auth_challenges",
]
