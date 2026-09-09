"""2FA (TOTP) enrollment mixin for the Free protocol chain.

Split out of ``free_protocol_runtime.py``; ``FreeProtocolMixin`` composes this
mixin so the responsibility band keeps its own module.  Methods rely on
attributes and helpers defined by the composing protocol mixin (``self._log``,
``self._totp_code``, ``self._confirm_mfa_enabled`` ...).
"""

from __future__ import annotations

import inspect
from typing import Any, Callable, Mapping
from urllib.parse import urlencode, urlsplit

try:
    from .free_failure_runtime import sanitize_safe_page as _sanitize_safe_page
    from .free_mailbox_otp import MailboxUrlOtpProvider
    from .free_protocol_bootstrap import _reference_navigation_headers
    from .free_account_service import mfa_enabled_from_payload
    from .mfa_retry_runtime import mfa_factor_id_from_response
    from .free_register_common import (
        FreeRegisterError,
        FreeTwoFaPending,
        configured_free_password,
    )
    from .free_protocol_helpers import (
        _response_status,
        _response_provider_code,
        _response_continue_url,
        _explicit_false,
        _call_otp_wait,
        _emit_twofa_reauth_observation,
        CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL,
    )
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_failure_runtime import sanitize_safe_page as _sanitize_safe_page  # type: ignore[no-redef]
    from free_mailbox_otp import MailboxUrlOtpProvider  # type: ignore[no-redef]
    from free_protocol_bootstrap import _reference_navigation_headers  # type: ignore[no-redef]
    from free_account_service import mfa_enabled_from_payload  # type: ignore[no-redef]
    from mfa_retry_runtime import mfa_factor_id_from_response  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FreeRegisterError,
        FreeTwoFaPending,
        configured_free_password,
    )
    from free_protocol_helpers import (  # type: ignore[no-redef]
        _response_status,
        _response_provider_code,
        _response_continue_url,
        _explicit_false,
        _call_otp_wait,
        _emit_twofa_reauth_observation,
        CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL,
    )


def _note_stderr(where: str, exc: BaseException) -> None:
    """Last-resort stderr note for swallowed best-effort side paths."""
    try:
        print(f"[free_protocol_twofa/{where}] {type(exc).__name__}", file=sys.stderr)
    except Exception:
        return


class FreeProtocolTwoFaMixin:
    """Methods moved verbatim from the FreeProtocolMixin band."""

    def _enroll_twofa(self, transport: Any, token: str, task: Mapping[str, Any], password: str, config: Mapping[str, Any], otp_provider: MailboxUrlOtpProvider, stage: Callable[[str, str], None]) -> dict[str, Any]:
        if transport is None or getattr(transport, "session", None) is None:
            raise FreeTwoFaPending(
                "2FA 会话不可用", token=token, plan_type="free", plus_trial_eligible=False,
                node_code="free_twofa_enroll", node_label="注册 Free 账号 2FA",
                error_code="free_twofa_session_missing",
                action_hint="保留账号和 Token，重建认证会话后重试 2FA",
            )
        session = transport.session
        task_id = str(task["task_id"])
        stage(task_id, "free_twofa_enroll")
        active_token = str(token or "")
        headers = {
            "accept": "application/json", "content-type": "application/json",
            "authorization": f"Bearer {active_token}",
            "oai-device-id": str(getattr(transport, "device_id", "") or ""), "oai-language": "en-GB",
        }
        phase = (
            "free_twofa_enroll", "注册 Free 账号 2FA", "free_twofa_enroll_failed",
            "保留账号和 Token，稍后重试 2FA",
        )
    
        def fail(message: str, response: Any = None, data: Any = None) -> None:
            raise FreeRegisterError(
                phase[0], phase[1], message,
                provider_status=_response_status(response),
                provider_code=_response_provider_code(response, data),
                error_code=phase[2], action_hint=phase[3],
            )
    
        def mfa_already_enabled() -> bool:
            """Read the authoritative MFA state for idempotent retries."""
            getter = getattr(session, "get", None)
            if not callable(getter):
                return False
            try:
                response = getter(
                    "https://chatgpt.com/backend-api/accounts/mfa_info",
                    headers=headers,
                    timeout=15,
                )
                status = _response_status(response)
                if status is not None and not 200 <= status < 300:
                    return False
                data = response.json() if hasattr(response, "json") else response
                return bool(mfa_enabled_from_payload(data))
            except Exception:
                # A status-check outage must preserve the original enrollment
                # or activation failure; it is never evidence of success.
                return False
    
        try:
            # Fast path (any-auto-register bind_totp_inline): a prior attempt
            # already persisted this account's single-issue TOTP secret.  The
            # registration session authenticated moments ago, so activating
            # the stored enrollment directly satisfies the recent-auth check
            # without another PoW or mailbox OTP.
            stored_secret = str((task.get("result") or {}).get("totp_secret") or "") if isinstance(task.get("result"), Mapping) else ""
            stored_session_id = str((task.get("result") or {}).get("twofa_session_id") or "") if isinstance(task.get("result"), Mapping) else ""
            if stored_secret and not mfa_already_enabled():
                stage(task_id, "free_twofa_activate")
                phase = (
                    "free_twofa_activate", "激活 Free 账号 2FA", "free_twofa_activate_failed",
                    "保留账号和 Token，稍后重试 2FA 激活",
                )
                activated = session.post(
                    "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment",
                    headers=headers, json={"code": self._totp_code(stored_secret), "factor_type": "totp", "session_id": stored_session_id}, timeout=20,
                )
                activated_data = activated.json() if hasattr(activated, "json") else {}
                activated_status = _response_status(activated)
                success = activated_data.get("success") if isinstance(activated_data, Mapping) else None
                if (activated_status is not None and not 200 <= activated_status < 300) or success is not True:
                    if mfa_already_enabled():
                        return {"twofa_status": "enabled", "totp_secret": stored_secret}
                    hint = ""
                    if activated_status == 429:
                        hint = "（429 多为同码重复提交，等一个 30 秒 TOTP 窗口换新码再试）"
                    raise FreeTwoFaPending(
                        f"2FA 快路径激活失败（HTTP {activated_status if activated_status is not None else '-'}）{hint}",
                        token=active_token, plan_type="free", plus_trial_eligible=False,
                        node_code="free_twofa_activate", node_label="激活 Free 账号 2FA",
                        error_code="free_twofa_activate_failed",
                        retryable=True,
                        action_hint="secret 已保存在账号结果中，重试 2FA 会直接走快路径激活",
                    )
                self._confirm_mfa_enabled(transport, session, headers, task_id)
                return {"twofa_status": "enabled", "totp_secret": stored_secret}
            post_auth_json = getattr(transport, "_post_auth_json", None)
            if callable(post_auth_json):
                # AutoRegister's setup_2fa starts a fresh NextAuth password
                # re-authentication. The existing-login MFA endpoint is not
                # equivalent and does not produce an MFA-eligible session.
                stage(task_id, "free_twofa_enroll")
                mailbox_service = getattr(otp_provider, "service", None)
                mailbox_state = getattr(mailbox_service, "state", None)
                finish_mailbox_request = getattr(mailbox_state, "finish_request", None)
                if callable(finish_mailbox_request) and bool(getattr(mailbox_state, "active", False)):
                    finish_mailbox_request()
                prepare_mailbox_request = getattr(otp_provider, "prepare", None)
                if callable(prepare_mailbox_request):
                    try:
                        inspect.signature(prepare_mailbox_request).bind("free_twofa_enroll", force_snapshot=True)
                    except ValueError:
                        prepare_mailbox_request("free_twofa_enroll", force_snapshot=True)
                    except TypeError:
                        prepare_mailbox_request("free_twofa_enroll")
                    else:
                        prepare_mailbox_request("free_twofa_enroll", force_snapshot=True)
    
                session = transport.session
                chatgpt_origin = "https://chatgpt.com"
                auth_origin = "https://auth.openai.com"
    
                def _reauth_headers(
                    referer: str,
                    *,
                    form: bool = False,
                    navigate: bool = False,
                    url: str = "",
                ) -> dict[str, str]:
                    headers: dict[str, str] = {}
                    maker = getattr(transport, "_headers", None)
                    if callable(maker):
                        try:
                            candidate = maker("twofa_reauth", referer)
                            if isinstance(candidate, Mapping):
                                headers.update({str(k): str(v) for k, v in candidate.items()})
                        except Exception:
                            # Optional header hints must not break the 2FA flow.
                            pass
                    if navigate:
                        # Auth authorize/callback GETs are top-level document
                        # navigations.  Sending the JSON/CORS envelope here
                        # can leave NextAuth in an incomplete re-auth state,
                        # so mirror AutoRegister's browser navigation headers.
                        headers = _reference_navigation_headers(
                            transport,
                            url or referer,
                            referer,
                            headers,
                        )
                        # A document navigation does not carry the API
                        # origin/body headers (and must never forward a Bearer
                        # token to auth.openai.com).
                        for key in ("origin", "content-type", "authorization"):
                            headers.pop(key, None)
                        return headers
                    headers.update({
                        "accept": "application/json",
                        "origin": chatgpt_origin,
                        "referer": referer,
                    })
                    if form:
                        headers["content-type"] = "application/x-www-form-urlencoded"
                    return headers
    
                csrf_response = None
                csrf_data: Any = {}
                try:
                    csrf_response = session.get(
                        f"{chatgpt_origin}/api/auth/csrf",
                        headers=_reauth_headers(f"{chatgpt_origin}/"),
                        timeout=30,
                        allow_redirects=True,
                    )
                    csrf_data = csrf_response.json() if hasattr(csrf_response, "json") else {}
                except Exception as exc:
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        f"CSRF 请求异常（{type(exc).__name__}）",
                        request_stage="reauth_csrf",
                        outcome="warn",
                    )
                    fail(f"2FA 重认证 CSRF 请求失败（{type(exc).__name__}）")
                csrf_token = str(csrf_data.get("csrfToken") or "") if isinstance(csrf_data, Mapping) else ""
                csrf_status = _response_status(csrf_response)
                _emit_twofa_reauth_observation(
                    transport,
                    task_id,
                    f"CSRF 响应{'已取得令牌' if csrf_token else '未取得令牌'}",
                    response=csrf_response,
                    request_stage="reauth_csrf",
                )
                if not csrf_token:
                    fail(
                        f"2FA 重认证 CSRF 响应无效（HTTP {csrf_status if csrf_status is not None else '-'}）",
                        csrf_response,
                        csrf_data,
                    )
    
                signin_query = urlencode({
                    "connection": "password",
                    "login_hint": str(task.get("email") or ""),
                    "reauth": "password",
                    "max_age": "0",
                    "ext-oai-did": str(getattr(transport, "device_id", "") or ""),
                })
                signin_body = urlencode({
                    "callbackUrl": f"{chatgpt_origin}/?action=enable&factor=totp",
                    "csrfToken": csrf_token,
                    "json": "true",
                })
                signin_response = None
                signin_data: Any = {}
                try:
                    signin_response = session.post(
                        f"{chatgpt_origin}/api/auth/signin/openai?{signin_query}",
                        headers=_reauth_headers(f"{chatgpt_origin}/", form=True),
                        data=signin_body,
                        allow_redirects=False,
                        timeout=30,
                    )
                    signin_data = signin_response.json() if hasattr(signin_response, "json") else {}
                except Exception as exc:
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        f"signin/openai 请求异常（{type(exc).__name__}）",
                        request_stage="reauth_signin",
                        outcome="warn",
                    )
                    fail(f"2FA 重认证启动失败（{type(exc).__name__}）")
                auth_url = str(signin_data.get("url") or "") if isinstance(signin_data, Mapping) else ""
                signin_status = _response_status(signin_response)
                _emit_twofa_reauth_observation(
                    transport,
                    task_id,
                    f"signin/openai 响应，authorize 地址{'已返回' if auth_url else '未返回'}",
                    response=signin_response,
                    request_stage="reauth_signin",
                    transport_fields={"authorize_url_present": bool(auth_url)},
                )
                if not auth_url:
                    fail(
                        f"2FA 重认证启动响应无效（HTTP {signin_status if signin_status is not None else '-'}）",
                        signin_response,
                        signin_data,
                    )
                try:
                    authorize_response = session.get(
                        auth_url,
                        headers=_reauth_headers(
                            f"{chatgpt_origin}/",
                            navigate=True,
                            url=auth_url,
                        ),
                        allow_redirects=True,
                        timeout=45,
                    )
                except Exception as exc:
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        f"authorize 页面请求异常（{type(exc).__name__}）",
                        request_stage="reauth_authorize",
                        transport_fields={"authorize_url_present": True},
                        outcome="warn",
                    )
                    fail(f"2FA 重认证页面请求失败（{type(exc).__name__}）")
                _emit_twofa_reauth_observation(
                    transport,
                    task_id,
                    "authorize 页面最终响应",
                    response=authorize_response,
                    request_stage="reauth_authorize",
                    include_location=True,
                    transport_fields={"authorize_url_present": True},
                )
    
                phase = (
                    "free_twofa_otp_send", "发送 Free 账号 2FA 邮箱验证码",
                    "free_twofa_otp_send_failed", "保留账号和 Token，检查邮箱重认证状态后重试 2FA",
                )
                otp_provider.mark_sent("free_twofa_enroll")
                phase = (
                    "free_twofa_otp_validate", "验证 Free 账号 2FA 邮箱验证码",
                    "free_twofa_otp_validate_failed", "保留账号和 Token，确认验证码属于本次 2FA 请求后重试",
                )
                code = _call_otp_wait(
                    otp_provider, str(task.get("email") or ""), stage_code="free_twofa_enroll",
                )
                stage(task_id, "free_email_otp_validate")
                verified = post_auth_json(
                    "/api/accounts/email-otp/validate",
                    {"code": code},
                    flow="twofa_reauth_email_otp",
                    referer=f"{auth_origin}/email-verification",
                    timeout=30,
                )
                verified_status = _response_status(verified)
                _emit_twofa_reauth_observation(
                    transport,
                    task_id,
                    "邮箱 OTP validate 响应",
                    response=verified,
                    request_stage="reauth_otp_validate",
                )
                verified_ok = verified.get("ok") if isinstance(verified, Mapping) else None
                if (verified_status is not None and not 200 <= verified_status < 300) or _explicit_false(verified_ok):
                    fail(f"重新认证 OTP 验证失败（HTTP {verified_status if verified_status is not None else '-'}）", verified)
                continue_url = _response_continue_url(verified)
                if continue_url:
                    try:
                        callback_response = session.get(
                            continue_url,
                            headers=_reauth_headers(
                                f"{auth_origin}/email-verification",
                                navigate=True,
                                url=continue_url,
                            ),
                            allow_redirects=True,
                            timeout=45,
                        )
                    except Exception as exc:
                        _emit_twofa_reauth_observation(
                            transport,
                            task_id,
                            f"OAuth callback 请求异常（{type(exc).__name__}）",
                            request_stage="reauth_callback",
                            outcome="warn",
                        )
                        fail(f"重新认证 OAuth 回调失败（{type(exc).__name__}）")
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        "OAuth callback 最终响应",
                        response=callback_response,
                        request_stage="reauth_callback",
                        include_location=True,
                    )
                else:
                    fail("重新认证 OTP 响应缺少 OAuth 回调地址", verified)
                capture_token = getattr(transport, "chatgpt_access_token", None)
                if callable(capture_token):
                    refreshed = str(capture_token() or "").strip()
                    if refreshed:
                        active_token = refreshed
                if continue_url and callable(capture_token) and active_token == str(token or "").strip():
                    fail("重新认证 OAuth 回调完成后未提供新的 ChatGPT Session Token")
                headers["authorization"] = f"Bearer {active_token}"
            else:
                # Compatibility for older recovered callers and test doubles.
                send_mfa_otp = getattr(transport, "send_mfa_otp", None)
                verify_mfa_otp = getattr(transport, "verify_mfa_otp", None)
                if callable(send_mfa_otp) and callable(verify_mfa_otp):
                    stage(task_id, "free_twofa_enroll")
                    mailbox_service = getattr(otp_provider, "service", None)
                    mailbox_state = getattr(mailbox_service, "state", None)
                    finish_mailbox_request = getattr(mailbox_state, "finish_request", None)
                    if callable(finish_mailbox_request) and bool(getattr(mailbox_state, "active", False)):
                        finish_mailbox_request()
                    prepare_mailbox_request = getattr(otp_provider, "prepare", None)
                    if callable(prepare_mailbox_request):
                        prepare_mailbox_request("free_twofa_enroll")
                    phase = (
                        "free_twofa_otp_send", "发送 Free 账号 2FA 邮箱验证码",
                        "free_twofa_otp_send_failed", "保留账号和 Token，检查邮箱重认证状态后重试 2FA",
                    )
                    sent = send_mfa_otp("")
                    sent_status = _response_status(sent)
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        "兼容 2FA OTP 发送响应",
                        response=sent,
                        request_stage="reauth_otp_send",
                    )
                    sent_ok = sent.get("ok") if isinstance(sent, Mapping) else None
                    if (sent_status is not None and not 200 <= sent_status < 300) or _explicit_false(sent_ok):
                        fail(f"重新认证 OTP 发送失败（HTTP {sent_status if sent_status is not None else '-'}）", sent)
                    otp_provider.mark_sent("free_twofa_enroll")
                    phase = (
                        "free_twofa_otp_validate", "验证 Free 账号 2FA 邮箱验证码",
                        "free_twofa_otp_validate_failed", "保留账号和 Token，确认验证码属于本次 2FA 请求后重试",
                    )
                    code = _call_otp_wait(
                        otp_provider, str(task.get("email") or ""), stage_code="free_twofa_enroll",
                    )
                    stage(task_id, "free_email_otp_validate")
                    verified = verify_mfa_otp(code)
                    verified_status = _response_status(verified)
                    _emit_twofa_reauth_observation(
                        transport,
                        task_id,
                        "兼容 2FA OTP validate 响应",
                        response=verified,
                        request_stage="reauth_otp_validate",
                    )
                    verified_ok = verified.get("ok") if isinstance(verified, Mapping) else None
                    if (verified_status is not None and not 200 <= verified_status < 300) or _explicit_false(verified_ok):
                        fail(f"重新认证 OTP 验证失败（HTTP {verified_status if verified_status is not None else '-'}）", verified)
                    continue_url = _response_continue_url(verified)
                    if continue_url:
                        complete_callback = getattr(transport, "complete_chatgpt_callback", None)
                        if not callable(complete_callback):
                            fail("重新认证 OTP 响应包含 OAuth 回调，但传输会话不支持回调", verified)
                        callback = complete_callback(continue_url)
                        callback_status = _response_status(callback)
                        _emit_twofa_reauth_observation(
                            transport,
                            task_id,
                            "兼容 OAuth callback 响应",
                            response=callback,
                            request_stage="reauth_callback",
                            include_location=True,
                        )
                        callback_ok = callback.get("ok") if isinstance(callback, Mapping) else None
                        if (callback_status is not None and not 200 <= callback_status < 300) or _explicit_false(callback_ok):
                            fail(f"重新认证 OAuth 回调失败（HTTP {callback_status if callback_status is not None else '-'}）", callback)
                    capture_token = getattr(transport, "chatgpt_access_token", None)
                    if callable(capture_token):
                        refreshed = str(capture_token() or "").strip()
                        if refreshed:
                            active_token = refreshed
                    headers["authorization"] = f"Bearer {active_token}"
            if mfa_already_enabled():
                return {"twofa_status": "enabled"}
            phase = (
                "free_twofa_enroll", "注册 Free 账号 2FA", "free_twofa_enroll_failed",
                "保留账号和 Token，稍后重试 2FA 注册",
            )
            enrolled = session.post("https://chatgpt.com/backend-api/accounts/mfa/enroll", headers=headers, json={"factor_type": "totp"}, timeout=20)
            enrolled_status = _response_status(enrolled)
            data = enrolled.json() if hasattr(enrolled, "json") else {}
            if enrolled_status is not None and not 200 <= enrolled_status < 300:
                fail(f"2FA enroll 接口返回 HTTP {enrolled_status}", enrolled, data)
            secret = str(data.get("secret") or "")
            session_id = str(data.get("session_id") or "")
            if not secret or not session_id:
                fail("2FA enroll 响应缺少 TOTP 材料", enrolled, data)
            # The server issues the secret exactly once and never stores it in
            # plaintext.  Persist it (with the enrollment session id the
            # activation call requires) before activation (any-auto-register
            # two_factor.py: bind the result before activate runs) so a failed
            # or interrupted activation leaves the retry on the fast path.
            self._persist_partial(
                config,
                task,
                {"twofa_status": "pending", "totp_secret": secret, "twofa_session_id": session_id},
                stage_code="free_twofa_enroll",
            )
            stage(task_id, "free_twofa_activate")
            phase = (
                "free_twofa_activate", "激活 Free 账号 2FA", "free_twofa_activate_failed",
                "保留账号和 Token，稍后重试 2FA 激活",
            )
            activated = session.post(
                "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment",
                headers=headers, json={"code": self._totp_code(secret), "factor_type": "totp", "session_id": session_id}, timeout=20,
            )
            activated_data = activated.json() if hasattr(activated, "json") else {}
            activated_status = _response_status(activated)
            success = activated_data.get("success") if isinstance(activated_data, Mapping) else None
            if (activated_status is not None and not 200 <= activated_status < 300) or success is not True:
                if mfa_already_enabled():
                    # The server may have committed activation while the
                    # response was dropped or reported an idempotent conflict.
                    return {"twofa_status": "enabled", "totp_secret": secret}
                hint = ""
                if activated_status == 429:
                    hint = "（429 多为同码重复提交，等一个 30 秒 TOTP 窗口换新码再试）"
                fail(
                    f"2FA 激活失败（HTTP {activated_status if activated_status is not None else '-'}）{hint}",
                    activated, activated_data,
                )
            self._confirm_mfa_enabled(transport, session, headers, task_id)
            return {"twofa_status": "enabled", "totp_secret": secret}
        except Exception as exc:
            if isinstance(exc, FreeRegisterError):
                node_code = str(exc.node_code or phase[0])
                node_label = str(exc.node_label or phase[1])
                error_code = str(exc.error_code or phase[2])
                if phase[0] in {"free_twofa_otp_send", "free_twofa_otp_validate"} and node_code in {
                    "free_twofa_enroll", "free_email_otp_wait", "free_email_otp_validate",
                    "free_existing_login_otp",
                }:
                    node_code, node_label, error_code = phase[:3]
                raise FreeTwoFaPending(
                    str(exc), token=active_token, plan_type="free", plus_trial_eligible=False,
                    node_code=node_code, node_label=node_label, error_code=error_code,
                    provider_status=exc.provider_status,
                    retryable=bool(exc.retryable),
                    provider_code=str(exc.provider_code or ""),
                    action_hint=str(exc.action_hint or phase[3]),
                ) from exc
            raise FreeTwoFaPending(
                f"2FA 设置失败：{type(exc).__name__}", token=active_token, plan_type="free", plus_trial_eligible=False,
                node_code=phase[0], node_label=phase[1], error_code=phase[2], retryable=True,
                action_hint=phase[3],
            ) from exc


__all__ = [
    "FreeProtocolTwoFaMixin",
]
