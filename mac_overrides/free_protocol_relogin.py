"""Shared pure-protocol re-login core for Free deep checks and plan re-checks.

The module owns the OAuth -> email OTP / password / TOTP -> consent -> callback
login state machine on the codex protocol transport, plus the transient-failure
session resilience used by the authenticated Free account queries. Live deep
checks and the plan re-check queue delegate here so the re-login sequence
keeps a single source of truth. The module never persists results: callers
own storage, liveness classification and row lifecycle.
"""

from __future__ import annotations

import secrets
from typing import Any, Callable, Mapping

try:
    from .free_register_common import FreeRegisterError, proxy_transport_value
except ImportError:  # pragma: no cover - top-level recovery import
    from free_register_common import FreeRegisterError, proxy_transport_value  # type: ignore[no-redef]


__all__ = [
    "ProtocolReloginDeactivated",
    "is_deactivated_response",
    "live_failure_is_transient",
    "live_response_received",
    "protocol_relogin_proxy",
    "run_protocol_relogin",
    "wrap_session_transient_retry",
]


class ProtocolReloginDeactivated(RuntimeError):
    """Re-login explicitly confirmed the account is deactivated."""

    def __init__(self, http_status: Any = None) -> None:
        super().__init__("protocol re-login confirmed the account is deactivated")
        self.http_status = http_status


def is_deactivated_response(value: Any) -> bool:
    """Reuse the SMS-chain ``account_banned`` classifier via a lazy import."""
    try:
        from .runtime_policy import is_account_banned_failure
    except ImportError:
        from runtime_policy import is_account_banned_failure  # type: ignore[no-redef]
    try:
        return bool(is_account_banned_failure(value))
    except Exception:
        return False


def live_response_received(exc: BaseException) -> bool:
    if getattr(exc, "response", None) is not None:
        return True
    status = getattr(exc, "status_code", None)
    return isinstance(status, int) and status > 0


def live_failure_is_transient(exc: BaseException) -> bool:
    """Pre-response transport failure (TLS handshake, connection reset, proxy connect)."""
    text = f"{type(exc).__name__} {exc}".lower()
    if any(marker in text for marker in ("timeout", "timed out", "connection", "proxy", "tls", "ssl", "reset", "curl:", "handshake")):
        return not live_response_received(exc)
    return False


def wrap_session_transient_retry(session: Any) -> None:
    """Retry one-off pre-response transport failures on the same session.

    A session rebuild would drop the oai-did cookie that authenticates the
    account queries, so the single retry must reuse this session object.
    Failures carrying an HTTP response (server answered) are never retried.
    """
    for name in ("get", "post"):
        original = getattr(session, name, None)
        if not callable(original) or getattr(original, "_gptphone_retry_wrapped", False):
            continue

        def wrapped(*args: Any, __original: Callable[..., Any] = original, **kwargs: Any) -> Any:
            try:
                return __original(*args, **kwargs)
            except Exception as first:
                if not live_failure_is_transient(first):
                    raise
                try:
                    return __original(*args, **kwargs)
                except Exception as second:
                    raise second from first

        wrapped._gptphone_retry_wrapped = True
        try:
            setattr(session, name, wrapped)
        except Exception:
            continue


def protocol_relogin_proxy(raw_proxy: Any, config: Mapping[str, Any], *, stage_label: str = "深度测活") -> str:
    """Convert one allocated raw proxy into the protocol transport value."""
    proxy = proxy_transport_value(
        str(raw_proxy or ""),
        driver="protocol",
        socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
    )
    if not proxy:
        raise FreeRegisterError(
            "proxy_connect_failed", "代理连接失败", f"{stage_label}代理格式无效",
            retryable=False, error_code="proxy_connect_failed",
        )
    return proxy


def _response_status(value: Any) -> int:
    try:
        return int(getattr(value, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _page_type(module: Any, response: Any) -> str:
    try:
        return str(module._page_type(response) or "").strip().lower()
    except Exception:
        return ""


def _continue_url(module: Any, response: Any) -> str:
    try:
        return str(module._continue_url(response) or "").strip()
    except Exception:
        return ""


def run_protocol_relogin(
    context: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    proxy: str,
    otp: Any,
    log_fn: Callable[..., Any],
    stage_fn: Callable[[str], None],
    device_id: str = "",
    node_code: str = "free_live_deep",
    node_label: str = "深度测活",
    error_context_fn: Callable[[BaseException], Mapping[str, Any]] | None = None,
    post_login: Callable[[Any, str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the shared protocol re-login state machine and return the new token.

    The caller owns the OTP provider construction and passes it in; the core
    closes it, the transport and its session in every path. ``post_login``
    runs inside the guarded section right after the fresh token is obtained,
    so its failures keep the historical re-login error mapping.
    """
    import codex_chain_runner
    import codex_oauth_chain

    email = str(context["email"])
    if not proxy:
        raise FreeRegisterError(
            "proxy_connect_failed", "代理连接失败", f"{node_label}代理格式无效",
            retryable=False, error_code="proxy_connect_failed",
        )
    if not device_id:
        device_id = f"{node_code}-{secrets.token_hex(16)}"
    auth_session_logging_id = f"{node_code}-auth-{secrets.token_hex(12)}"
    oauth_url, _code_verifier, _state = codex_chain_runner.build_oauth_url(
        login_hint=email,
        screen_hint="login_or_signup",
        prompt="login",
    )
    try:
        from .free_protocol_runtime import _ensure_oauth_context_params
    except ImportError:
        from free_protocol_runtime import _ensure_oauth_context_params  # type: ignore[no-redef]
    oauth_url = _ensure_oauth_context_params(
        oauth_url,
        device_id=device_id,
        auth_session_logging_id=auth_session_logging_id,
    )
    oauth_params = codex_oauth_chain.parse_oauth_url(oauth_url)
    # The re-login shares the live-check transport profile verbatim: the codex
    # chain keys off this run mode and no caller needs a different one.
    protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
    chain_config = dict(config)
    chain_config.update({
        "run_mode": "free_live_check",
        "codex_chain_mode": "real",
        "free_protocol_state_machine": True,
        "free_register_no_phone": True,
        "codex_node_runner": str(protocol.get("node_runner") or ""),
        "_auth_account_email": email,
    })
    sentinel = codex_oauth_chain.RealNodeSentinelProvider(
        config=chain_config,
        device_id=device_id,
        proxy_label=str(context.get("proxy_fingerprint") or ""),
        proxy=proxy,
        log_fn=log_fn,
    )
    transport = codex_oauth_chain.RealCodexTransport(
        chain_config,
        oauth_params=oauth_params,
        proxy=proxy,
        sentinel_provider=sentinel,
        device_id=device_id,
        log_fn=log_fn,
    )
    # Re-logins use the same bounded protocol bootstrap as registration:
    # fixed proxy, device cookie, anonymous warmup and Sentinel preflight.
    # Test doubles without an HTTP ``get`` remain transport-only tests and
    # do not attempt network calls.
    transport_session = getattr(transport, "session", None)
    if callable(getattr(transport_session, "get", None)):
        try:
            try:
                from .free_protocol_bootstrap import (
                    anonymous_warmup,
                    network_preflight,
                    prepare_reference_session,
                )
            except ImportError:
                from free_protocol_bootstrap import (  # type: ignore[no-redef]
                    anonymous_warmup,
                    network_preflight,
                    prepare_reference_session,
                )
            prepare_reference_session(transport)
            network_preflight(transport, chain_config, log=log_fn)
            anonymous_warmup(transport, chain_config, log=log_fn)
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError(
                node_code,
                node_label,
                f"{node_label}协议预检异常（{type(exc).__name__}）",
                retryable=True,
                error_code="free_live_deep_preflight_failed",
            ) from exc
    try:
        response = transport.start_chatgpt_signup_authorize(email)
        if is_deactivated_response(response):
            raise ProtocolReloginDeactivated(_response_status(response))
        otp.mark_sent()
        response = transport.submit_email_identifier(email)
        for _attempt in range(10):
            if is_deactivated_response(response):
                raise ProtocolReloginDeactivated(_response_status(response))
            page_type = _page_type(codex_oauth_chain, response)
            continue_url = _continue_url(codex_oauth_chain, response)
            if page_type in {"email_otp", "email_otp_verification", "email_verification"}:
                if not bool(getattr(transport, "_gptphone_initial_email_otp_send_confirmed", False)):
                    otp.mark_sent()
                    sent = transport.send_email_otp(continue_url)
                    if not bool(codex_oauth_chain._is_success_response(sent)):
                        raise FreeRegisterError("free_live_email", "深度测活邮箱验证", "登录 OTP 发送失败")
                stage_fn("email_otp")
                code = otp.wait_code(email)
                response = transport.verify_email_otp(code)
                continue
            if page_type in {"password", "password_verification", "email_password"}:
                password = str(context.get("password") or "")
                try:
                    try:
                        from .free_protocol_flow import _password_context
                    except ImportError:
                        from free_protocol_flow import _password_context  # type: ignore[no-redef]
                    password_context = str(_password_context(response) or "unknown")
                except Exception:
                    password_context = "unknown"
                if password_context == "login" and password:
                    response = transport.verify_password(password)
                    continue
                if password_context == "unknown" and password:
                    raise FreeRegisterError(
                        "free_live_password_context_unknown",
                        "识别深度测活密码页面",
                        "服务端返回通用密码页面，无法确认是否为已有账号登录，已停止避免误提交",
                        retryable=False,
                        error_code="free_live_password_context_unknown",
                    )
                # A passwordless account must first use the email OTP
                # branch above. A real password is accepted only when the
                # server explicitly identifies the page as existing-login.
                if password_context in {"login", "signup", "unknown"}:
                    raise FreeRegisterError(
                        "free_live_password_required",
                        "深度测活需要真实账号密码",
                        "服务端进入密码页面，但本地没有可用的真实 OpenAI 账号密码",
                        retryable=False,
                        error_code="free_live_password_required",
                        action_hint="该账号注册时走 passwordless 邮箱 OTP；不要填入固定注册密码",
                    )
            if page_type in {"mfa_otp", "mfa_challenge", "mfa_otp_verification"}:
                secret = str(context.get("totp_secret") or "")
                if not secret:
                    raise FreeRegisterError("free_live_mfa", "深度测活动态口令验证", "账号已启用 2FA，但没有保存动态口令密钥", retryable=False)
                try:
                    from .free_protocol_runtime import FreeProtocolMixin
                except ImportError:
                    from free_protocol_runtime import FreeProtocolMixin  # type: ignore[no-redef]
                stage_fn("mfa")
                response = transport.verify_mfa_otp(FreeProtocolMixin._totp_code(secret))
                continue
            if page_type in {"phone", "phone_otp", "phone_verification"}:
                raise FreeRegisterError("free_live_phone_required", "深度测活手机号验证", "重新登录进入手机号验证页面，未调用接码平台", retryable=False)
            if page_type in {"about_you", "about-you", "create_account"}:
                raise FreeRegisterError("free_live_incomplete_account", "确认 Free 账号状态", "重新登录进入资料创建页面，账号注册状态不完整", retryable=False)
            if page_type in {"consent", "consent_required"}:
                response = transport.accept_consent(continue_url)
                continue
            if continue_url:
                response = transport.complete_chatgpt_callback(continue_url)
            token = str(transport.chatgpt_access_token() or "")
            if token:
                session = getattr(transport, "session", None)
                if session is not None:
                    wrap_session_transient_retry(session)
                if post_login is not None:
                    return dict(post_login(transport, token))
                return {"access_token": token, "transport": transport}
            if not continue_url:
                break
            response = transport.visit_continue(continue_url, "https://auth.openai.com")
        raise FreeRegisterError(node_code, node_label, "重新登录完成后未取得新的 access token")
    except FreeRegisterError:
        raise
    except ProtocolReloginDeactivated:
        raise
    except Exception as exc:
        if is_deactivated_response(exc):
            raise ProtocolReloginDeactivated(getattr(exc, "provider_status", None)) from exc
        error_context = dict(error_context_fn(exc)) if error_context_fn is not None else {}
        raise FreeRegisterError(
            node_code,
            node_label,
            f"重新登录异常（{type(exc).__name__}）",
            error_code=str(error_context.get("transport_error_code") or "") or f"{node_code}_failed",
            **error_context,
        ) from exc
    finally:
        otp_close = getattr(otp, "close", None)
        if callable(otp_close):
            otp_close()
        for candidate in (getattr(transport, "session", None), transport):
            close = getattr(candidate, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    # Best-effort resource cleanup must not mask the caller result.
                    _note_stderr("resource_close", exc)


try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]


def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr("free_protocol_relogin", where, exc)
