"""Compatibility wrapper around the shared mailbox OTP service for Free runs."""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping

try:
    from .free_register_common import FreeRegisterError
    from .mailbox_otp_service import (
        DEFAULT_FREE_MAILBOX_PROXY,
        MailboxOtpError,
        MailboxOtpService,
        normalize_network_policy,
    )
    from .mailbox_url_runtime import MailboxResponse
except ImportError:
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]
    from mailbox_otp_service import (  # type: ignore[no-redef]
        DEFAULT_FREE_MAILBOX_PROXY,
        MailboxOtpError,
        MailboxOtpService,
        normalize_network_policy,
    )
    from mailbox_url_runtime import MailboxResponse  # type: ignore[no-redef]


class MailboxUrlOtpProvider:
    """Keep the historic provider signature while isolating mailbox networking."""

    def __init__(
        self,
        mailbox_url: str,
        proxy: str = "",
        *,
        timeout: int,
        log_fn: Callable[..., Any] | None = None,
        task_id: str = "",
        stage_fn: Callable[[str, str], None] | None = None,
        network_mode: str = "local_proxy",
        mailbox_proxy_url: str = DEFAULT_FREE_MAILBOX_PROXY,
        request_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
        poll_interval_seconds: float = 1.0,
        fetcher: Callable[[str], MailboxResponse] | None = None,
        session: Any | None = None,
        session_factory: Callable[..., Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        now_fn: Callable[[], float] = time.time,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        # ``proxy`` is the former registration-proxy argument. It is retained
        # for callable compatibility and deliberately never used for mailbox IO.
        self.registration_proxy = str(proxy or "")
        self.network_policy = normalize_network_policy(
            mode=network_mode,
            proxy_url=mailbox_proxy_url,
            retries=request_retries,
            backoff_seconds=retry_backoff_seconds,
            request_timeout_seconds=min(15, max(3, int(timeout))),
        )
        self.service = MailboxOtpService(
            mailbox_url,
            timeout_seconds=timeout,
            poll_interval_seconds=poll_interval_seconds,
            network_policy=self.network_policy,
            log_fn=log_fn,
            task_id=task_id,
            stage_fn=stage_fn,
            fetcher=fetcher,
            session=session,
            session_factory=session_factory,
            sleep_fn=sleep_fn,
            now_fn=now_fn,
            monotonic_fn=monotonic_fn,
        )
        # Compatibility attributes used by focused tests and older helpers.
        self.client = self.service.client
        self.state = self.service.state
        self.timeout = self.service.timeout_seconds
        self.log_fn = log_fn
        self.task_id = str(task_id or "")
        self.stage_fn = stage_fn

    @staticmethod
    def _label(stage_code: str) -> str:
        if "twofa" in stage_code:
            return "等待 Free 账号 2FA 邮箱验证码"
        if "existing_login" in stage_code:
            return "等待已有 Free 账号登录验证码"
        if "live" in stage_code:
            return "等待 Free 深度测活邮箱验证码"
        return "等待 Free 邮箱验证码"

    def mark_sent(self, stage_code: str = "free_email_otp_wait") -> None:
        self.service.mark_sent(stage_code)

    def prepare(self, stage_code: str = "free_email_otp_wait") -> None:
        """Capture the baseline before browser/protocol actions can send a code."""
        self.service.prepare(stage_code)

    def wait_code(
        self,
        _email: str,
        stage_code: str = "free_email_otp_wait",
        *,
        resend_fn: Callable[[], None] | None = None,
        resend_after_seconds: float = 12.0,
    ) -> str:
        try:
            return self.service.wait_code(
                stage_code,
                resend_fn=resend_fn,
                resend_after_seconds=resend_after_seconds,
            )
        except MailboxOtpError as exc:
            raise FreeRegisterError(
                stage_code,
                self._label(stage_code),
                str(exc),
                error_code=f"{stage_code}_{exc.code}",
                retryable=exc.retryable,
                provider_status=exc.status,
            ) from exc

    def diagnostic(self) -> dict[str, Any]:
        return self.service.diagnostic()

    def close(self) -> None:
        self.service.close()


def build_free_mailbox_otp_provider(
    mailbox_url: str,
    registration_proxy: str,
    config: Mapping[str, Any],
    *,
    log_fn: Callable[..., Any] | None = None,
    task_id: str = "",
    stage_fn: Callable[[str, str], None] | None = None,
) -> MailboxUrlOtpProvider:
    """Create a Free provider without ever borrowing the registration proxy."""
    return MailboxUrlOtpProvider(
        mailbox_url,
        registration_proxy,
        timeout=int(config.get("email_code_timeout") or 90),
        log_fn=log_fn,
        task_id=task_id,
        stage_fn=stage_fn,
        network_mode=str(config.get("mailbox_network_mode") or "local_proxy"),
        mailbox_proxy_url=str(config.get("mailbox_proxy_url") or DEFAULT_FREE_MAILBOX_PROXY),
        request_retries=int(config.get("mailbox_request_retries", 3)),
        retry_backoff_seconds=float(config.get("mailbox_retry_backoff_seconds", 1.0)),
    )


__all__ = ["MailboxUrlOtpProvider", "build_free_mailbox_otp_provider"]
