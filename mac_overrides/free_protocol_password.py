"""Password enrollment mixin for the Free protocol chain.

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


class FreeProtocolPasswordMixin:
    """Methods moved verbatim from the FreeProtocolMixin band."""

    def _set_password(
        self,
        transport: Any,
        token: str,
        task: Mapping[str, Any],
        password: str,
        config: Mapping[str, Any],
        otp_provider: MailboxUrlOtpProvider,
        stage: Callable[[str, str], None],
    ) -> dict[str, Any]:
        """Add a password to a passwordless signup account.
    
        The Auth API deliberately uses a fresh NextAuth session for this
        operation.  Keep this sequence separate from ``_enroll_twofa`` so a
        password request never probes or otherwise touches ``mfa_info``:
    
        ``eligibility -> csrf -> signin(openai) -> authorize -> OTP ->
        validate -> password/add -> ChatGPT callback``.
    
        The method returns a result envelope rather than mutating the task;
        callers can preserve a successfully-created account when a later
        password step is temporarily unavailable.
        """
        task_id = str(task.get("task_id") or "")
        email = str(task.get("email") or "")
        active_token = str(token or "").strip()
        password_value = str(password or configured_free_password(config))
        session = getattr(transport, "session", None)
        if session is None or not callable(getattr(session, "get", None)) or not callable(getattr(session, "post", None)):
            raise FreeRegisterError(
                "free_password_enroll",
                "注册 Free 账号密码",
                "密码设置会话不可用",
                retryable=True,
                error_code="free_password_session_missing",
                action_hint="保留账号和 Token，重建认证会话后重试密码设置",
            )
    
        phase: list[str] = [
            "free_password_eligibility",
            "检查 Free 账号密码资格",
            "free_password_eligibility_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
    
        def response_data(response: Any) -> dict[str, Any]:
            if isinstance(response, Mapping):
                return dict(response)
            try:
                value = response.json() if hasattr(response, "json") else {}
            except Exception:
                value = {}
            return dict(value) if isinstance(value, Mapping) else {}
    
        def fail(
            message: str,
            response: Any = None,
            data: Any = None,
            *,
            safe_page: str = "",
            page_type: str = "",
        ) -> None:
            raise FreeRegisterError(
                phase[0],
                phase[1],
                message,
                provider_status=_response_status(response),
                provider_code=_response_provider_code(response, data),
                error_code=phase[2],
                action_hint=phase[3],
                safe_page=safe_page,
                page_type=page_type,
            )
    
        def status_ok(response: Any) -> bool:
            status = _response_status(response)
            return status is None or 200 <= status < 300
    
        def prepare_mailbox_request() -> None:
            finish = getattr(getattr(otp_provider, "service", None), "state", None)
            finish_request = getattr(finish, "finish_request", None)
            if callable(finish_request) and bool(getattr(finish, "active", False)):
                finish_request()
            prepare = getattr(otp_provider, "prepare", None)
            if not callable(prepare):
                return
            try:
                signature = inspect.signature(prepare)
            except (TypeError, ValueError):
                prepare("free_password_otp_wait", force_snapshot=True)
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
                prepare("free_password_otp_wait", **kwargs)
                return
            raise FreeRegisterError(
                "free_password_otp_wait",
                "准备 Free 账号密码邮箱验证码",
                "邮箱 provider 不支持密码验证码准备签名",
                retryable=False,
                error_code="free_password_otp_prepare_failed",
            )
    
        def auth_headers(referer: str, *, form: bool = False, navigate: bool = False, url: str = "") -> dict[str, str]:
            headers: dict[str, str] = {}
            maker = getattr(transport, "_headers", None)
            if callable(maker):
                try:
                    candidate = maker("password_reauth", referer)
                    if isinstance(candidate, Mapping):
                        headers.update({str(key): str(value) for key, value in candidate.items()})
                except Exception:
                    pass
            if navigate:
                try:
                    headers = _reference_navigation_headers(
                        transport,
                        url or referer,
                        referer,
                        headers,
                    )
                except Exception:
                    headers.setdefault("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    headers.setdefault("referer", referer)
                    headers.setdefault("sec-fetch-site", "same-origin")
                    headers.setdefault("sec-fetch-mode", "navigate")
                    headers.setdefault("sec-fetch-dest", "document")
                for key in ("origin", "content-type", "authorization"):
                    headers.pop(key, None)
                return headers
            headers.update({
                "accept": "application/json",
                "origin": "https://chatgpt.com",
                "referer": referer,
            })
            if form:
                headers["content-type"] = "application/x-www-form-urlencoded"
            return headers
    
        def no_sentinel_headers(referer: str) -> dict[str, str]:
            """Build the compatibility fallback envelope without Sentinel."""
            headers = auth_headers(referer)
            for key in tuple(headers):
                if str(key).lower() in {"openai-sentinel-token", "openai-sentinel-so-token"}:
                    headers.pop(key, None)
            return headers
    
        def auth_post(
            path: str,
            payload: Mapping[str, Any],
            *,
            flow: str,
            referer: str,
            timeout: int = 30,
            include_sentinel: bool = True,
        ) -> dict[str, Any]:
            """Call the recovered transport helper, with an old-runtime fallback."""
            # The browser/HAR password re-authentication validates the OTP as
            # a plain same-origin JSON request.  The recovered generic helper
            # always creates and sends a Sentinel token, which is valid for
            # authorize/MFA flows but causes this password continuation to be
            # rejected as ``wrong_email_otp_code``.  A dedicated transport
            # boundary keeps that exception explicit and cannot affect the
            # ordinary registration or 2FA calls.
            helper = getattr(
                transport,
                "_post_auth_json" if include_sentinel else "_post_auth_json_without_sentinel",
                None,
            )
            if callable(helper):
                value = helper(path, dict(payload), flow=flow, referer=referer, timeout=timeout)
                return dict(value) if isinstance(value, Mapping) else {}
            try:
                response = session.post(
                    f"https://auth.openai.com{path}",
                    json=dict(payload),
                    headers=auth_headers(referer) if include_sentinel else no_sentinel_headers(referer),
                    allow_redirects=False,
                    timeout=timeout,
                )
            except Exception as exc:
                return {"_status": 0, "error": type(exc).__name__}
            value = response_data(response)
            status = _response_status(response)
            if status is not None:
                value.setdefault("_status", status)
            return value
    
        def task_totp_secret() -> str:
            """Read a previously enrolled TOTP seed from the task-local result.
    
            Retry tasks carry the merged durable result (including private
            fields) in memory.  Do not query ``mfa_info`` here: password-only
            registrations must never probe 2FA, and the seed is needed only
            when the password continuation explicitly returns an MFA page.
            """
            candidates: list[Any] = [task.get("totp_secret")]
            saved_result = task.get("result")
            if isinstance(saved_result, Mapping):
                candidates.append(saved_result.get("totp_secret"))
            for candidate in candidates:
                value = str(candidate or "").strip()
                if value:
                    return value
            return ""
    
        # This endpoint is the only admission check for the post-registration
        # password operation.  An explicit ``eligible: false`` means the
        # account already has a password (or the operation is unavailable), so
        # report it as disabled without attempting a second auth session.
        try:
            eligibility_response = session.get(
                CHATGPT_ADD_PASSWORD_ELIGIBILITY_URL,
                headers={
                    "accept": "application/json",
                    "authorization": f"Bearer {active_token}",
                    "oai-device-id": str(getattr(transport, "device_id", "") or ""),
                },
                timeout=20,
            )
        except Exception as exc:
            fail(f"密码资格请求失败（{type(exc).__name__}）")
        eligibility_data = response_data(eligibility_response)
        eligibility_status = _response_status(eligibility_response)
        if eligibility_status is not None and not 200 <= eligibility_status < 300:
            fail(
                f"密码资格接口返回 HTTP {eligibility_status}",
                eligibility_response,
                eligibility_data,
            )
        if eligibility_data.get("eligible") is False:
            return {
                "password_status": "disabled",
                "password_set_after_registration": False,
            }
    
        prepare_mailbox_request()
        chatgpt_origin = "https://chatgpt.com"
        auth_origin = "https://auth.openai.com"
    
        # CSRF and signin are form requests on chatgpt.com.  The
        # ``post_login_add_password`` query flag is what selects the reset
        # password continuation after the OTP, and is intentionally kept out
        # of the ordinary MFA flow.
        phase[:] = [
            "free_password_reauth_csrf",
            "密码设置重认证 CSRF",
            "free_password_reauth_csrf_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        try:
            csrf_response = session.get(
                f"{chatgpt_origin}/api/auth/csrf",
                headers=auth_headers(f"{chatgpt_origin}/"),
                timeout=30,
                allow_redirects=True,
            )
            csrf_data = response_data(csrf_response)
        except Exception as exc:
            fail(f"密码设置重认证 CSRF 请求失败（{type(exc).__name__}）")
        csrf_token = str(csrf_data.get("csrfToken") or "")
        if not csrf_token:
            fail(
                f"密码设置重认证 CSRF 响应无效（HTTP {_response_status(csrf_response) or '-'}）",
                csrf_response,
                csrf_data,
            )
    
        phase[:] = [
            "free_password_reauth_signin",
            "启动密码设置重认证",
            "free_password_reauth_signin_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        # Keep this request byte-for-byte compatible with the password-setting
        # HAR: ``connection=password`` belongs to the 2FA re-auth flow, not
        # the add-password continuation.
        signin_query = urlencode({
            "login_hint": email,
            "reauth": "password",
            "post_login_add_password": "true",
            "max_age": "0",
            "ext-oai-did": str(getattr(transport, "device_id", "") or ""),
        })
        signin_body = urlencode({
            "callbackUrl": f"{chatgpt_origin}/",
            "csrfToken": csrf_token,
            "json": "true",
        })
        try:
            signin_response = session.post(
                f"{chatgpt_origin}/api/auth/signin/openai?{signin_query}",
                headers=auth_headers(f"{chatgpt_origin}/", form=True),
                data=signin_body,
                allow_redirects=False,
                timeout=30,
            )
            signin_data = response_data(signin_response)
        except Exception as exc:
            fail(f"密码设置 signin/openai 请求失败（{type(exc).__name__}）")
        auth_url = str(signin_data.get("url") or "").strip()
        if not auth_url:
            fail(
                f"密码设置重认证未返回 authorize 地址（HTTP {_response_status(signin_response) or '-'}）",
                signin_response,
                signin_data,
            )
        try:
            parsed_auth = urlsplit(auth_url)
        except (TypeError, ValueError):
            parsed_auth = None
        if parsed_auth is None or parsed_auth.scheme.casefold() != "https" or (parsed_auth.hostname or "").casefold() != "auth.openai.com":
            fail("密码设置 authorize 地址不是 auth.openai.com", signin_response, signin_data)
    
        phase[:] = [
            "free_password_reauth_authorize",
            "打开密码设置授权页面",
            "free_password_reauth_authorize_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        try:
            authorize_response = session.get(
                auth_url,
                headers=auth_headers(
                    f"{chatgpt_origin}/",
                    navigate=True,
                    url=auth_url,
                ),
                allow_redirects=True,
                timeout=45,
            )
        except Exception as exc:
            fail(f"密码设置 authorize 页面请求失败（{type(exc).__name__}）")
        authorize_status = _response_status(authorize_response)
        if authorize_status is not None and not 200 <= authorize_status < 400:
            fail(
                f"密码设置 authorize 页面返回 HTTP {authorize_status}",
                authorize_response,
                response_data(authorize_response),
            )
    
        phase[:] = [
            "free_password_otp_wait",
            "等待密码设置邮箱验证码",
            "free_password_otp_wait_failed",
            "保留账号和 Token，确认本次密码设置验证码后重试",
        ]
        mark_sent = getattr(otp_provider, "mark_sent", None)
        if callable(mark_sent):
            mark_sent("free_password_otp_wait")
        code = _call_otp_wait(
            otp_provider,
            email,
            stage_code="free_password_otp_wait",
        )
        if not str(code or "").strip():
            fail("密码设置邮箱验证码为空")
    
        phase[:] = [
            "free_password_otp_validate",
            "验证密码设置邮箱验证码",
            "free_password_otp_validate_failed",
            "保留账号和 Token，确认验证码属于本次密码设置请求后重试",
        ]
        stage(task_id, "free_password_otp_validate")
        verified = auth_post(
            "/api/accounts/email-otp/validate",
            {"code": str(code).strip()},
            flow="password_add_reauth_email_otp",
            referer=f"{auth_origin}/email-verification",
            timeout=30,
            include_sentinel=False,
        )
        verified_status = _response_status(verified)
        if (verified_status is not None and not 200 <= verified_status < 300) or _explicit_false(verified.get("ok")):
            fail(
                f"密码设置邮箱验证码验证失败（HTTP {verified_status or '-'}）",
                verified,
                verified,
            )
        reset_url = _response_continue_url(verified)
        verified_page = verified.get("page") if isinstance(verified, Mapping) else None
        verified_page_type = ""
        if isinstance(verified_page, Mapping):
            verified_page_type = str(verified_page.get("type") or "").strip().lower()
        try:
            verified_path = str(urlsplit(reset_url).path or "").rstrip("/").lower()
        except (TypeError, ValueError):
            verified_path = ""
        mfa_page = verified_page_type in {"mfa_challenge", "mfa-challenge", "mfa"} or verified_path.startswith("/mfa-challenge")
        if mfa_page:
            # An account with 2FA enabled can require a TOTP challenge during
            # password re-authentication.  This branch is activated solely by
            # the server page; ``auto_set_2fa`` remains an independent signup
            # option and is never consulted as a prerequisite.
            phase[:] = [
                "free_password_mfa_challenge",
                "密码设置 2FA 验证",
                "free_password_mfa_required",
                "保留账号和 Token，确认已保存 2FA 后重试密码设置",
            ]
            stage(task_id, "free_password_mfa_challenge")
            factor_id = mfa_factor_id_from_response(
                verified,
                continue_url_fn=_response_continue_url,
            )
            secret = task_totp_secret()
            if not factor_id:
                fail(
                    "密码设置 2FA 页面缺少验证因子",
                    verified,
                    verified,
                    safe_page=_sanitize_safe_page(reset_url),
                    page_type=verified_page_type or "mfa_challenge",
                )
            if not secret:
                raise FreeRegisterError(
                    "free_password_mfa_required",
                    "密码设置 2FA 验证",
                    "密码设置要求 2FA，但当前账号没有已保存的 TOTP",
                    retryable=False,
                    error_code="free_password_totp_missing",
                    action_hint="先完成 2FA 激活，或关闭密码设置的 2FA 要求后重试",
                    safe_page=_sanitize_safe_page(reset_url),
                    page_type=verified_page_type or "mfa_challenge",
                )
            phase[:] = [
                "free_password_mfa_validate",
                "验证密码设置 2FA 动态码",
                "free_password_mfa_validate_failed",
                "保留账号和 Token，确认 2FA 时间同步后重试密码设置",
            ]
            stage(task_id, "free_password_mfa_validate")
            issued = auth_post(
                "/api/accounts/mfa/issue_challenge",
                {"id": factor_id, "type": "totp", "force_fresh_challenge": False},
                flow="mfa_otp_issue",
                referer=f"{auth_origin}/mfa-challenge/{factor_id}",
                timeout=30,
                include_sentinel=False,
            )
            issued_status = _response_status(issued)
            if (issued_status is not None and not 200 <= issued_status < 300) or _explicit_false(issued.get("ok")):
                fail(
                    f"密码设置 2FA 挑战初始化失败（HTTP {issued_status or '-'}）",
                    issued,
                    issued,
                    safe_page=_sanitize_safe_page(reset_url),
                    page_type="mfa_challenge",
                )
            mfa_verified = auth_post(
                "/api/accounts/mfa/verify",
                {"id": factor_id, "type": "totp", "code": self._totp_code(secret)},
                flow="mfa_otp_verify",
                referer=f"{auth_origin}/mfa-challenge/{factor_id}",
                timeout=30,
                # AutoRegister's protocol reference sends the MFA verify
                # envelope without Sentinel; keep this limited to the
                # password re-auth branch and leave normal MFA unchanged.
                include_sentinel=False,
            )
            mfa_status = _response_status(mfa_verified)
            if (mfa_status is not None and not 200 <= mfa_status < 300) or _explicit_false(mfa_verified.get("ok")):
                fail(
                    f"密码设置 2FA 验证失败（HTTP {mfa_status or '-'}）",
                    mfa_verified,
                    mfa_verified,
                    safe_page=_sanitize_safe_page(reset_url),
                    page_type="mfa_challenge",
                )
            reset_url = _response_continue_url(mfa_verified)
            if not reset_url:
                fail(
                    "密码设置 2FA 响应缺少新密码页面地址",
                    mfa_verified,
                    mfa_verified,
                    page_type="mfa_challenge",
                )
        if not reset_url:
            fail("密码设置 OTP 响应缺少新密码页面地址", verified, verified)
        try:
            parsed_reset = urlsplit(reset_url)
        except (TypeError, ValueError):
            parsed_reset = None
        reset_path = str(parsed_reset.path or "").rstrip("/") if parsed_reset is not None else ""
        if (
            parsed_reset is None
            or parsed_reset.scheme.casefold() != "https"
            or (parsed_reset.hostname or "").casefold() != "auth.openai.com"
            or not (reset_path == "/reset-password" or reset_path.startswith("/reset-password/"))
        ):
            fail(
                "密码设置 OTP 响应地址不是 auth.openai.com/reset-password 页面",
                verified,
                verified,
                safe_page=_sanitize_safe_page(reset_url),
                page_type=verified_page_type,
            )
    
        # The browser loads the continuation page before submitting the JSON
        # password/add request.  Keep the GET for cookies and server-side
        # continuation state, while never persisting its URL/query.
        phase[:] = [
            "free_password_enroll",
            "打开新密码页面",
            "free_password_enroll_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        try:
            reset_response = session.get(
                reset_url,
                headers=auth_headers(
                    f"{auth_origin}/email-verification",
                    navigate=True,
                    url=reset_url,
                ),
                allow_redirects=True,
                timeout=45,
            )
        except Exception as exc:
            fail(f"新密码页面请求失败（{type(exc).__name__}）")
        reset_status = _response_status(reset_response)
        if reset_status is not None and not 200 <= reset_status < 400:
            fail(f"新密码页面返回 HTTP {reset_status}", reset_response, response_data(reset_response))
    
        phase[:] = [
            "free_password_add",
            "提交 Free 账号密码",
            "free_password_add_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        added = auth_post(
            "/api/accounts/password/add",
            {"password": password_value},
            flow="password_add",
            referer=reset_url,
            timeout=30,
        )
        added_status = _response_status(added)
        if (added_status is not None and not 200 <= added_status < 300) or _explicit_false(added.get("ok")):
            fail(
                f"密码添加接口返回 HTTP {added_status or '-'}",
                added,
                added,
            )
        # The password is now server-side authoritative.  Persist it before
        # the callback/2FA tail: any later failure must not lose the only
        # password this account will accept (any-auto-register registers the
        # same lesson at its register_password callback).
        self._persist_partial(
            config,
            task,
            {
                "password_status": "enabled",
                "password_set_after_registration": True,
                "password": password_value,
                "access_token": active_token,
                "has_access_token": bool(active_token),
            },
            stage_code="free_password_add",
        )
        callback_url = _response_continue_url(added)
        if not callback_url:
            fail("密码添加响应缺少 ChatGPT OAuth callback 地址", added, added)
        try:
            parsed_callback = urlsplit(callback_url)
        except (TypeError, ValueError):
            parsed_callback = None
        if parsed_callback is None or parsed_callback.scheme.casefold() != "https" or (parsed_callback.hostname or "").casefold() != "chatgpt.com" or not parsed_callback.path.startswith("/api/auth/callback/"):
            fail("密码添加 callback 地址不是 ChatGPT OAuth callback", added, added)
    
        phase[:] = [
            "free_password_callback",
            "刷新密码设置会话",
            "free_password_callback_failed",
            "保留账号和 Token，稍后重试密码设置",
        ]
        complete_callback = getattr(transport, "complete_chatgpt_callback", None)
        if callable(complete_callback):
            callback_response = complete_callback(callback_url)
        else:
            try:
                callback_raw = session.get(
                    callback_url,
                    headers=auth_headers(
                        f"{auth_origin}/reset-password/new-password",
                        navigate=True,
                        url=callback_url,
                    ),
                    allow_redirects=True,
                    timeout=45,
                )
            except Exception as exc:
                fail(f"密码设置 OAuth callback 请求失败（{type(exc).__name__}）")
            callback_response = response_data(callback_raw)
            callback_status = _response_status(callback_raw)
            if callback_status is not None and not 200 <= callback_status < 400:
                fail(f"密码设置 OAuth callback 返回 HTTP {callback_status}", callback_raw, callback_response)
    
        refreshed = ""
        capture_token = getattr(transport, "chatgpt_access_token", None)
        if callable(capture_token):
            try:
                refreshed = str(capture_token() or "").strip()
            except Exception:
                refreshed = ""
        if refreshed:
            active_token = refreshed
        if not active_token:
            fail("密码设置 callback 完成后未取得 ChatGPT Session Token", callback_response, callback_response)
        return {
            "password_status": "enabled",
            "password_set_after_registration": True,
            "password": password_value,
            "access_token": active_token,
            "has_access_token": True,
        }


__all__ = [
    "FreeProtocolPasswordMixin",
]
