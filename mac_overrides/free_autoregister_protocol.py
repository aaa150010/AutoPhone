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
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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


def _json_response(transport: Any, response: Any) -> dict[str, Any]:
    """Use the recovered parser while keeping response bodies out of logs."""
    parser = getattr(transport, "_gptphone_json_response", None)
    if callable(parser):
        try:
            value = parser(response)
            if isinstance(value, Mapping):
                return dict(value)
        except Exception:
            pass
    try:
        payload = response.json()
    except Exception:
        payload = {}
    if not isinstance(payload, Mapping):
        payload = {}
    result = dict(payload)
    result["_status"] = int(getattr(response, "status_code", 0) or 0)
    result["_content_type"] = str(getattr(response, "headers", {}).get("content-type", "") or "")
    result["_location"] = str(getattr(response, "headers", {}).get("location", "") or "")
    result["_url"] = str(getattr(response, "url", "") or "")
    return result


def _reference_authorize_url(
    value: str,
    *,
    email: str,
    device_id: str,
    auth_session_logging_id: str,
) -> str:
    """Keep NextAuth's returned authorize URL in the AutoRegister shape."""
    try:
        parsed = urlsplit(str(value or ""))
        if (parsed.hostname or "").casefold() != "auth.openai.com":
            return str(value or "")
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        present = {key for key, _value in pairs}
        additions = (
            ("ext-oai-did", device_id),
            ("auth_session_logging_id", auth_session_logging_id),
            ("ext-passkey-client-capabilities", "11111"),
            ("screen_hint", "login_or_signup"),
            ("login_hint", email),
            ("ccaps", "login_methods"),
        )
        for key, item in additions:
            if item and key not in present:
                pairs.append((key, item))
                present.add(key)
        return urlunsplit(parsed._replace(query=urlencode(pairs)))
    except (TypeError, ValueError):
        return str(value or "")


def _annotate_page_response(transport: Any, response: Any) -> dict[str, Any]:
    """Normalize the HTML landing page into the same page envelope as JSON.

    AutoRegister follows the authorize redirect as HTML, while the Free state
    machine consumes JSON-like page envelopes.  Mapping only stable route
    names keeps the transport difference isolated and avoids body scraping.
    """
    result = dict(response) if isinstance(response, Mapping) else {}
    page = result.get("page")
    page_type = str(page.get("type") or "") if isinstance(page, Mapping) else ""
    locations = []
    for key in ("url", "_url", "_location", "location"):
        value = str(result.get(key) or "").strip()
        if value and value not in locations:
            locations.append(value)
    path = " ".join(locations).casefold()
    if not page_type:
        if "/email-verification" in path or "/email-otp" in path:
            page_type = "email_otp_verification"
        elif "/log-in/password" in path or "/login/password" in path:
            page_type = "login_password"
        elif "/create-account/password" in path or "/signup/password" in path:
            page_type = "signup_password"
        elif "/about-you" in path or "/about_you" in path:
            page_type = "profile"
        if page_type:
            result["page"] = {"type": page_type}
    if page_type and not result.get("continue_url"):
        for value in locations:
            if value:
                result["continue_url"] = value
                break
    result["_gptphone_autoregister_prelude"] = True
    return result


def _run_reference_chatgpt_prelude(transport: Any, email: str) -> Mapping[str, Any]:
    """Run AutoRegister's exact NextAuth prelude for the recovered transport."""
    session = getattr(transport, "session", None)
    json_get = getattr(transport, "_chatgpt_json_get", None)
    if session is None or not callable(getattr(session, "get", None)) or not callable(getattr(session, "post", None)) or not callable(json_get):
        raise RuntimeError("reference transport helpers unavailable")

    try:
        import codex_oauth_chain as chain
    except ImportError:  # pragma: no cover - only real runtime transports expose this module
        chain = None
    chatgpt = str(getattr(chain, "CHATGPT", "https://chatgpt.com"))
    page_headers = dict(getattr(chain, "PAGE_HEADERS", {}) or {})
    page_headers.setdefault("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    login_response = session.get(
        f"{chatgpt}/auth/login",
        headers=page_headers,
        allow_redirects=True,
        timeout=30,
    )
    login_data = _json_response(transport, login_response)
    login_status = response_status(login_data)
    if login_status is not None and not 200 <= login_status < 400:
        raise _failed(login_data)
    csrf_data = json_get("/api/auth/csrf", referer=f"{chatgpt}/auth/login", timeout=30)
    csrf_status = response_status(csrf_data)
    if csrf_status is not None and not 200 <= csrf_status < 400:
        raise _failed(csrf_data)
    csrf = str(csrf_data.get("csrfToken") or "") if isinstance(csrf_data, Mapping) else ""
    if not csrf:
        raise _failed(csrf_data)

    device_id = str(getattr(transport, "device_id", "") or "")
    auth_session_logging_id = str(
        getattr(transport, "_gptphone_auth_session_logging_id", "") or ""
    )
    params = {
        "prompt": "login",
        "ext-oai-did": device_id,
        "auth_session_logging_id": auth_session_logging_id,
        "ext-passkey-client-capabilities": "11111",
        "screen_hint": "login_or_signup",
        "login_hint": str(email or ""),
    }
    signin_url = f"{chatgpt}/api/auth/signin/openai?{urlencode(params)}"
    signin_headers = {
        **page_headers,
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "origin": chatgpt,
        "referer": f"{chatgpt}/",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
    }
    response = session.post(
        signin_url,
        headers=signin_headers,
        data=urlencode({"callbackUrl": f"{chatgpt}/", "csrfToken": csrf, "json": "true"}),
        timeout=30,
    )
    data = _json_response(transport, response)
    authorize_url = str(data.get("url") or "")
    if not authorize_url:
        raise _failed(data)
    authorize_url = _reference_authorize_url(
        authorize_url,
        email=str(email or ""),
        device_id=device_id,
        auth_session_logging_id=auth_session_logging_id,
    )
    navigate_headers = {
        **page_headers,
        "referer": f"{chatgpt}/",
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
    }
    final_response = session.get(
        authorize_url,
        headers=navigate_headers,
        allow_redirects=True,
        timeout=45,
    )
    result = _annotate_page_response(transport, _json_response(transport, final_response))
    result["url"] = str(getattr(final_response, "url", "") or authorize_url)
    result.setdefault("_url", result["url"])
    setattr(transport, "last_response", result)
    setattr(transport, "last_oauth_url", result["url"])
    return result


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

    Real transports use the maintained AutoRegister-compatible override below;
    test doubles and older recovered transports without the private HTTP
    helpers keep their original compatibility method.
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
        if callable(getattr(transport, "_chatgpt_json_get", None)) and getattr(transport, "session", None) is not None:
            response = _run_reference_chatgpt_prelude(transport, str(email or ""))
        else:
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
    if isinstance(response, Mapping):
        response = _annotate_page_response(transport, response)
    return response if isinstance(response, Mapping) else {"ok": True}


__all__ = ["run_autoregister_prelude"]
