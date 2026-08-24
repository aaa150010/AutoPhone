"""Shared MFA completion for ordinary OAuth email verification flows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class EmailOtpMfaRuntime:
    secret_get: Callable[..., str]
    secret_clear: Callable[[], None]
    checkpoint_save: Callable[[Any, Any], Any]
    response_error_code: Callable[[Any], str]
    page_type: Callable[[Any], str]
    observe_auth_step: Callable[[Any, Any, str], Any]
    continue_if_needed: Callable[..., Any]
    factor_id: Callable[[Any], str]
    verify_totp: Callable[..., Any]
    verify_mfa: Callable[..., Any]
    manual_fallback: Callable[[Any, Any], Any]
    session_invalid: Callable[[Any], bool]
    stop_event: Callable[[Any], Any]

    def _secret(self, transport: Any) -> str:
        """Read the task-bound secret, including passwordless signup flows."""
        try:
            value = self.secret_get(transport)
        except TypeError:
            # Preserve compatibility with the original zero-argument hook.
            value = self.secret_get()
        return str(value or "").strip()

    def verify(self, transport: Any, code: str, original_verify: Callable[..., Any]) -> Any:
        response = original_verify(transport, code)
        self.checkpoint_save(transport, response)
        secret = self._secret(transport)
        self.secret_clear()
        if self.response_error_code(response) == "incorrect_code":
            self.observe_auth_step(transport, response, "email_code_verifying")
            return response

        try:
            page_type = self.page_type(response)
        except Exception:
            page_type = ""
        if page_type not in {"mfa_otp", "mfa_challenge", "mfa_otp_verification"} or not secret:
            self.observe_auth_step(transport, response, "email_code_verifying")
            if getattr(transport, "_gptphone_free_protocol_state_machine", False):
                return response
            return self.continue_if_needed(transport, response, origin="email_otp")

        factor_id = self.factor_id(response)
        if not factor_id:
            self.observe_auth_step(transport, response, "email_code_verifying")
            if getattr(transport, "_gptphone_free_protocol_state_machine", False):
                return response
            return self.continue_if_needed(transport, response, origin="email_otp")

        log_fn = getattr(transport, "log_fn", None)
        if callable(log_fn):
            try:
                log_fn("  [Codex] 邮箱验证码后遇到 MFA，正在验证 2FA 动态码", "info")
            except TypeError:
                log_fn("  [Codex] 邮箱验证码后遇到 MFA，正在验证 2FA 动态码")

        response = self.verify_totp(
            transport,
            factor_id=factor_id,
            secret=secret,
            verify_fn=self.verify_mfa,
            manual_fallback_fn=self.manual_fallback,
            session_invalid_fn=self.session_invalid,
            stop_event=self.stop_event(transport),
            log_fn=log_fn,
        )
        self.checkpoint_save(transport, response)
        self.observe_auth_step(transport, response, "mfa_otp_verifying")
        if self.response_error_code(response) == "incorrect_code":
            return response
        if getattr(transport, "_gptphone_free_protocol_state_machine", False):
            return response
        return self.continue_if_needed(transport, response, origin="email_otp")


__all__ = ["EmailOtpMfaRuntime"]
