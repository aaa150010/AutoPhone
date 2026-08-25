"""AutoRegister-compatible protocol prelude.

The recovered transport already implements AutoRegister's anonymous ChatGPT
bootstrap and NextAuth sign-in sequence.  Free protocol tasks must execute
that sequence before the Codex OAuth state machine so the auth session has the
same cookies and server-side context as the reference implementation.

Mailbox parsing and OTP retrieval deliberately remain outside this module.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

try:
    from .free_protocol_diagnostics import response_detail, response_status
    from .free_register_common import FreeRegisterError, safe_log_message
except ImportError:  # pragma: no cover
    from free_protocol_diagnostics import response_detail, response_status  # type: ignore[no-redef]
    from free_register_common import FreeRegisterError, safe_log_message  # type: ignore[no-redef]


def _log(log: Callable[..., Any] | None, message: str, level: str = "info") -> None:
    if not callable(log):
        return
    try:
        log(message, level)
    except TypeError:
        log(message)


def _stopped(stop_requested: Callable[[], bool] | None) -> None:
    if callable(stop_requested) and stop_requested():
        raise FreeRegisterError(
            "free_run_stop",
            "停止 Free 注册",
            "任务已请求停止，协议前置链路不再发起后续请求",
            retryable=False,
            error_code="free_run_stop",
        )


def _failed(response: Any) -> FreeRegisterError:
    status = response_status(response)
    detail = response_detail(response)
    provider_code = ""
    if isinstance(response, Mapping):
        error = response.get("error")
        sources = (error, response) if isinstance(error, Mapping) else (response,)
        for source in sources:
            for key in ("error_code", "code", "type", "reason"):
                value = str(source.get(key) or "").strip()
                if value:
                    provider_code = safe_log_message(value)[:120]
                    break
            if provider_code:
                break
    failure = FreeRegisterError(
        "free_oauth_session",
        "Free OAuth 会话",
        f"AutoRegister OAuth 前置失败：{detail}",
        provider_status=status,
        provider_code=provider_code,
        error_code="free_autoregister_prelude_failed",
        action_hint="保持当前邮箱、代理和设备上下文，按 AutoRegister 顺序重建 OAuth 会话",
    )
    return failure


def run_autoregister_prelude(
    transport: Any,
    email: str,
    *,
    task_id: str = "",
    stage: Callable[[str, str], None] | None = None,
    log: Callable[..., Any] | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> Mapping[str, Any] | None:
    """Run AutoRegister's login/csrf/providers/signin/authorize prelude.

    ``RealCodexTransport.start_chatgpt_signup_authorize`` performs the exact
    reference order internally.  Test doubles and older recovered transports
    without that method are left untouched for compatibility.
    """
    function = getattr(transport, "start_chatgpt_signup_authorize", None)
    if not callable(function):
        return None
    _stopped(stop_requested)
    if callable(stage):
        stage(str(task_id or ""), "free_oauth_session")
    _log(log, "按 AutoRegister 顺序建立 ChatGPT/NextAuth OAuth 前置会话", "info")
    try:
        # AutoRegister reads the provider catalog before requesting CSRF and
        # signing in.  The recovered transport exposes this request as its
        # private JSON helper; use it only when available and keep the
        # response body out of diagnostics.
        providers_get = getattr(transport, "_chatgpt_json_get", None)
        if callable(providers_get):
            providers = providers_get("/api/auth/providers", referer="https://chatgpt.com/auth/login", timeout=30)
            provider_status = response_status(providers)
            if provider_status is not None and not 200 <= provider_status < 400:
                raise _failed(providers)
            _log(log, "AutoRegister providers 节点完成", "info")
        response = function(str(email or ""))
    except FreeRegisterError:
        raise
    except Exception as exc:
        raise FreeRegisterError(
            "free_oauth_session",
            "Free OAuth 会话",
            f"AutoRegister OAuth 前置请求异常（{type(exc).__name__}）",
            error_code="free_autoregister_prelude_transport_failed",
            action_hint="检查当前代理和 Auth/Sentinel 连通性后重试",
        ) from exc
    _stopped(stop_requested)
    status = response_status(response)
    if status is not None and not 200 <= status < 400:
        raise _failed(response)
    if isinstance(response, Mapping):
        marker = response.get("ok")
        if marker is False or (isinstance(marker, str) and marker.casefold() in {"false", "failed", "error"}):
            raise _failed(response)
    setattr(transport, "_gptphone_autoregister_prelude", True)
    _log(log, "AutoRegister OAuth 前置会话建立完成，继续 Free OAuth 状态机", "success")
    return response if isinstance(response, Mapping) else {"ok": True}


__all__ = ["run_autoregister_prelude"]
