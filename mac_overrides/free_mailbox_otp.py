"""Proxy-bound OTP reader used only by Free registration."""

from __future__ import annotations

import time
from typing import Any, Callable

try:
    from .free_register_common import FreeRegisterError, OTP_RE
except ImportError:
    from free_register_common import FreeRegisterError, OTP_RE  # type: ignore[no-redef]


class MailboxUrlOtpProvider:
    def __init__(
        self,
        mailbox_url: str,
        proxy: str,
        *,
        timeout: int,
        log_fn: Callable[..., Any] | None = None,
        task_id: str = "",
        stage_fn: Callable[[str, str], None] | None = None,
    ) -> None:
        try:
            from mailbox_url_runtime import MailboxRequestState, MailboxResponse, MailboxUrlClient
        except ImportError:
            from .mailbox_url_runtime import MailboxRequestState, MailboxResponse, MailboxUrlClient

        timeout_seconds = max(3, min(int(timeout), 60))

        def fetcher(url: str) -> Any:
            from curl_cffi import requests as curl_requests

            response = curl_requests.get(
                url,
                headers={
                    "Accept": "application/json,text/plain,text/html,*/*",
                    "User-Agent": "gptphone-free-mailbox/1.0",
                    "Cache-Control": "no-cache, no-store, max-age=0",
                    "Pragma": "no-cache",
                },
                proxies={"http": proxy, "https": proxy},
                timeout=timeout_seconds,
                allow_redirects=True,
                impersonate="chrome",
                verify=False,
            )
            return MailboxResponse(
                str(getattr(response, "url", "") or url),
                bytes(getattr(response, "content", b"") or b""),
                str(getattr(response, "headers", {}).get("content-type", "") or ""),
                int(getattr(response, "status_code", 0) or 0),
            )

        self.client = MailboxUrlClient(mailbox_url, timeout_seconds=timeout_seconds, proxy=proxy, fetcher=fetcher)
        self.state = MailboxRequestState(self.client)
        self.timeout = max(5, int(timeout))
        self.log_fn = log_fn
        self.task_id = str(task_id or "")
        self.stage_fn = stage_fn

    def _stage(self, code: str) -> None:
        if self.task_id and callable(self.stage_fn):
            self.stage_fn(self.task_id, code)

    def mark_sent(self) -> None:
        self._stage("free_email_otp_wait")
        self.state.begin_request()

    def prepare(self) -> None:
        """Start the OTP baseline before an auth redirect can send the code."""
        self.state.begin_request()

    def wait_code(self, _email: str) -> str:
        self._stage("free_email_otp_wait")
        if not self.state.active:
            self.state.begin_request()
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            selection = self.state.snapshot()
            code = str(getattr(selection, "code", "") or "").strip()
            if OTP_RE.fullmatch(code):
                self.state.finish_request()
                return code
            time.sleep(1)
        raise FreeRegisterError("free_email_otp_wait", "等待 Free 邮箱验证码", "邮箱验证码等待超时")


__all__ = ["MailboxUrlOtpProvider"]
