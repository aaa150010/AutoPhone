"""Full-protocol Free registration driver.

This mixin keeps the recovered OAuth chain and the optional second OTP/2FA
flow separate from task scheduling.  The manager supplies storage, logging,
and stage callbacks through its existing methods.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping

try:
    from .free_mailbox_otp import MailboxUrlOtpProvider
    from .free_register_common import (
        FIXED_PASSWORD,
        FreeRegisterError,
        FreeTwoFaPending,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        random_birthdate,
        random_display_name,
        safe_log_message as _safe_log_message,
        timezone_offset_minutes as _timezone_offset_minutes,
    )
except ImportError:
    from free_mailbox_otp import MailboxUrlOtpProvider  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FIXED_PASSWORD, FreeRegisterError, FreeTwoFaPending,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        random_birthdate, random_display_name,
        safe_log_message as _safe_log_message,
        timezone_offset_minutes as _timezone_offset_minutes,
    )


class FreeProtocolMixin:
    """Protocol driver methods mixed into ``FreeRegisterManager``."""

    @staticmethod
    def _totp_code(secret: str, now: float | None = None) -> str:
        normalized = re.sub(r"\s+", "", secret or "").upper()
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        key = base64.b32decode(normalized + padding, casefold=True)
        counter = int((now or time.time()) // 30).to_bytes(8, "big")
        digest = hmac.new(key, counter, hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
        return f"{value % 1_000_000:06d}"

    def _run_protocol(self, task: Mapping[str, Any], config: Mapping[str, Any], stop_event: threading.Event, stage: Callable[[str, str], None], log: Callable[[str, str], None], *, twofa_retry: bool = False) -> Mapping[str, Any]:
        # Import the recovered chain inside the worker so fake-runner tests do
        # not need to load the bundled runtime.
        import codex_chain_runner
        import codex_oauth_chain

        task_id = str(task["task_id"])
        email = str(task["email"])
        proxy = str(task["proxy"])
        password = FIXED_PASSWORD
        stage(task_id, "free_twofa_enroll" if twofa_retry else "free_oauth_session")
        oauth_url, code_verifier, _state = codex_chain_runner.build_oauth_url(login_hint=email, screen_hint="signup")
        parsed = codex_oauth_chain.parse_oauth_url(oauth_url)
        device_id = str(task.get("device_id") or f"free-{secrets.token_hex(16)}")
        sentinel = codex_oauth_chain.RealNodeSentinelProvider(config=dict(config), device_id=device_id, proxy_label=str(task.get("proxy_fingerprint") or ""), proxy=proxy, log_fn=log)
        otp_provider = MailboxUrlOtpProvider(
            str(task["mailbox_url"]), proxy,
            timeout=int(config.get("email_code_timeout") or 90),
            log_fn=log, task_id=task_id, stage_fn=stage,
        )
        chain_config = dict(config)
        protocol_config = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
        chain_config["codex_node_runner"] = str(
            protocol_config.get("node_runner")
            or config.get("codex_node_runner")
            or config.get("node_runner")
            or (config.get("node") or {}).get("runner")
            or ""
        ).strip()
        chain_config.update({
            "run_mode": "free_register",
            "codex_chain_mode": "real",
            "run_chatgpt_signup_phase": True,
            "free_register_no_phone": True,
            "phone_max_attempts": 1,
            "code_timeout": int(config.get("email_code_timeout") or 90),
            "_stop_requested": stop_event.is_set,
            "_auth_account_email": email,
            "register": {"password": password, "name": random_display_name(), "birthdate": random_birthdate()},
        })

        def reject_phone(*_args: Any, **_kwargs: Any) -> Any:
            raise FreeRegisterError("free_phone_required", "Free 注册手机号节点", "Free 注册流程要求手机号，未调用接码平台")

        class NoPhoneProvider:
            get_number = staticmethod(reject_phone)

        transport = codex_oauth_chain.RealCodexTransport(
            chain_config, oauth_params=parsed, proxy=proxy,
            sentinel_provider=sentinel, device_id=device_id, log_fn=log,
        )
        self._instrument_transport(transport, task_id, stage)
        try:
            if twofa_retry:
                saved = self.pool.result(str(task["row_id"]))
                token = str(saved.get("access_token") or "")
                if not token:
                    raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "原账号没有可用 access token", retryable=False)
                twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
                result = dict(saved)
                result.update(twofa)
                result["password"] = str(saved.get("password") or password)
                if result.get("totp_secret"):
                    result["credential_line"] = f"{email}----{result['password']}----{result['totp_secret']}"
                return result

            stage(task_id, "free_email_identifier")
            result = codex_oauth_chain.run_codex_after_registration(
                oauth_url=oauth_url, code_verifier=code_verifier,
                account_email=email, password=password, config=chain_config,
                proxy=proxy, email_proxy=proxy, log_fn=log, mode="real",
                transport=transport, sentinel_provider=sentinel,
                email_otp_provider=otp_provider, phone_otp_provider=NoPhoneProvider(),
            )
            token = str((result or {}).get("access_token") or (result or {}).get("token") or "")
            if not token:
                stage(task_id, "free_access_token")
                token = str(transport.chatgpt_access_token() or "")
            if not token:
                raise FreeRegisterError("free_access_token", "获取 Free access token", "注册完成但未返回 access token")
            stage(task_id, "free_plan_check")
            try:
                plan_type, eligible = self._plan_check(transport, token)
                plan_details = {
                    "plan_check_status": "success", "plan_type": plan_type,
                    "subscription_plan": plan_type,
                    "has_active_subscription": plan_type not in {"", "free"},
                    "plus_trial_eligible": eligible, "plan_checked_at": time.time(),
                }
            except FreeRegisterError as exc:
                plan_details = {
                    "plan_check_status": "failed",
                    "plan_error_code": str(getattr(exc, "error_code", "free_plan_check_failed")),
                    "plan_http_status": getattr(exc, "provider_status", None),
                    "plan_type": "", "plus_trial_eligible": False,
                }
            if bool(config.get("auto_set_2fa", True)):
                try:
                    twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
                except FreeTwoFaPending as pending:
                    twofa = {"twofa_status": "pending", "twofa_error": _safe_log_message(pending)}
            else:
                twofa = {"twofa_status": "disabled"}
            twofa.update({"access_token": token, "password": password, "has_access_token": True, **plan_details})
            if twofa.get("totp_secret"):
                twofa["twofa_status"] = "enabled"
                twofa["credential_line"] = f"{email}----{password}----{twofa['totp_secret']}"
            return twofa
        finally:
            self._close_transport(transport)

    @staticmethod
    def _instrument_transport(transport: Any, task_id: str, stage: Callable[[str, str], None]) -> None:
        mapping = {
            "start_chatgpt_signup_authorize": "free_oauth_session",
            "register_user": "free_email_identifier",
            "verify_password": "free_email_password",
            "send_email_otp": "free_email_otp_wait",
            "verify_signup_email_otp": "free_email_otp_validate",
            "verify_email_otp": "free_email_otp_validate",
            "create_account_profile": "free_account_create",
            "complete_chatgpt_callback": "free_oauth_callback",
            "follow_continue_until_code": "free_oauth_callback",
            "exchange_code": "free_access_token",
            "chatgpt_access_token": "free_access_token",
        }
        for name, code in mapping.items():
            original = getattr(transport, name, None)
            if not callable(original):
                continue

            def wrapped(*args: Any, __original: Callable[..., Any] = original, __code: str = code, **kwargs: Any) -> Any:
                stage(task_id, __code)
                return __original(*args, **kwargs)

            setattr(transport, name, wrapped)

    @staticmethod
    def _close_transport(transport: Any) -> None:
        for candidate in (getattr(transport, "session", None), transport):
            close = getattr(candidate, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

    def _plan_check(self, transport: Any, token: str) -> tuple[str, bool]:
        if transport is None:
            raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "认证传输会话不可用")
        session = getattr(transport, "session", None)
        if session is None:
            raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "认证 HTTP 会话不可用")
        try:
            response = session.get(
                "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
                f"?timezone_offset_min={_timezone_offset_minutes()}",
                headers={"authorization": f"Bearer {token}", "accept": "*/*"}, timeout=20,
            )
            status = getattr(response, "status_code", None)
            if status is not None and not 200 <= int(status) < 300:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", f"套餐接口返回 HTTP {int(status)}")
            data = response.json() if hasattr(response, "json") else {}
            try:
                from .chatgpt_plan_gate import plan_from_accounts_check
            except ImportError:
                from chatgpt_plan_gate import plan_from_accounts_check
            plan, _ = plan_from_accounts_check(data, token=token)
            if not plan:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "套餐接口未返回可识别的套餐")
            eligible = _plus_trial_from_accounts(data)
            eligibility = session.get(
                "https://chatgpt.com/backend-api/aip/first-party/eligibility",
                headers={"authorization": f"Bearer {token}", "accept": "application/json"}, timeout=20,
            )
            eligibility_status = getattr(eligibility, "status_code", None)
            if eligibility_status is not None and not 200 <= int(eligibility_status) < 300:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", f"试用资格接口返回 HTTP {int(eligibility_status)}")
            eligible_data = eligibility.json() if hasattr(eligibility, "json") else {}
            if not isinstance(eligible_data, Mapping):
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "试用资格接口响应不是 JSON 对象")
            eligible = eligible or _plus_trial_from_accounts(eligible_data)
            campaigns = eligible_data.get("eligible_promo_campaigns")
            return plan, bool(eligible or (isinstance(campaigns, Mapping) and campaigns.get("plus")))
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", f"套餐或试用资格查询异常（{type(exc).__name__}）") from exc

    def _enroll_twofa(self, transport: Any, token: str, task: Mapping[str, Any], password: str, config: Mapping[str, Any], otp_provider: MailboxUrlOtpProvider, stage: Callable[[str, str], None]) -> dict[str, Any]:
        if transport is None or getattr(transport, "session", None) is None:
            raise FreeTwoFaPending("2FA 会话不可用", token=token, plan_type="free", plus_trial_eligible=False)
        session = transport.session
        task_id = str(task["task_id"])
        stage(task_id, "free_twofa_enroll")
        headers = {
            "accept": "application/json", "content-type": "application/json",
            "authorization": f"Bearer {token}",
            "oai-device-id": str(getattr(transport, "device_id", "") or ""), "oai-language": "en-GB",
        }
        try:
            send_mfa_otp = getattr(transport, "send_mfa_otp", None)
            verify_mfa_otp = getattr(transport, "verify_mfa_otp", None)
            if callable(send_mfa_otp) and callable(verify_mfa_otp):
                stage(task_id, "free_email_otp_wait")
                sent = send_mfa_otp("")
                status = int((sent or {}).get("_status") or (sent or {}).get("status_code") or 0) if isinstance(sent, Mapping) else 0
                if status >= 400:
                    raise ValueError(f"重新认证 OTP 发送返回 HTTP {status}")
                otp_provider.mark_sent()
                code = otp_provider.wait_code(str(task.get("email") or ""))
                stage(task_id, "free_email_otp_validate")
                verified = verify_mfa_otp(code)
                verified_status = int((verified or {}).get("_status") or (verified or {}).get("status_code") or 0) if isinstance(verified, Mapping) else 0
                if verified_status >= 400 or (isinstance(verified, Mapping) and verified.get("ok") is False):
                    raise ValueError(f"重新认证 OTP 验证失败（HTTP {verified_status or '-'})")
            enrolled = session.post("https://chatgpt.com/backend-api/accounts/mfa/enroll", headers=headers, json={"factor_type": "totp"}, timeout=20)
            data = enrolled.json() if hasattr(enrolled, "json") else {}
            secret = str(data.get("secret") or "")
            session_id = str(data.get("session_id") or "")
            if not secret or not session_id:
                raise ValueError("enroll 响应缺少 TOTP 材料")
            stage(task_id, "free_twofa_activate")
            activated = session.post(
                "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment",
                headers=headers, json={"code": self._totp_code(secret), "factor_type": "totp", "session_id": session_id}, timeout=20,
            )
            activated_data = activated.json() if hasattr(activated, "json") else {}
            if not bool(activated_data.get("success")):
                raise ValueError("2FA 激活返回 success=false")
            return {"twofa_status": "enabled", "totp_secret": secret}
        except Exception as exc:
            raise FreeTwoFaPending(f"2FA 设置失败：{type(exc).__name__}", token=token, plan_type="free", plus_trial_eligible=False) from exc


__all__ = ["FreeProtocolMixin"]
