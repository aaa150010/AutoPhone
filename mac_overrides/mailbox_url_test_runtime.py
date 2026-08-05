"""Read-only mailbox URL test workflow shared by the dashboard route."""

from __future__ import annotations

import time
from typing import Any, Callable
from urllib.parse import urlsplit

try:
    from .mailbox_url_runtime import MailboxRequestState, MailboxUrlClient, MailboxUrlError, parse_mailbox_url_row
except ImportError:  # Loaded as a top-level runtime override.
    from mailbox_url_runtime import (  # type: ignore[no-redef]
        MailboxRequestState,
        MailboxUrlClient,
        MailboxUrlError,
        parse_mailbox_url_row,
    )


def parse_test_input(value: Any) -> tuple[str, str]:
    raw = str(value or "").strip()
    parsed_row = parse_mailbox_url_row(raw)
    if parsed_row is not None:
        return parsed_row.email, parsed_row.mailbox_url
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise MailboxUrlError("mailbox_url_invalid", "请输入完整的 HTTP(S) 取件 URL") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise MailboxUrlError("mailbox_url_invalid", "请输入完整的 HTTP(S) 取件 URL")
    return "", raw


def _diagnostics(selection: Any) -> dict[str, int]:
    scan = getattr(selection, "scan", None)
    value = getattr(scan, "diagnostics", None)
    if value is None:
        return {
            "listing_messages": 0,
            "detail_links": 0,
            "detail_refreshed": 0,
            "detail_cache_hits": 0,
            "detail_refresh_pending": 0,
            "detail_errors": 0,
            "openai_messages": 0,
            "code_messages": 0,
        }
    detail_links = max(0, int(getattr(value, "detail_links", 0) or 0))
    detail_refreshed = max(0, int(getattr(value, "detail_refreshed", 0) or 0))
    return {
        "listing_messages": max(0, int(getattr(value, "listing_messages", 0) or 0)),
        "detail_links": detail_links,
        "detail_refreshed": detail_refreshed,
        "detail_cache_hits": max(0, int(getattr(value, "detail_cache_hits", 0) or 0)),
        "detail_refresh_pending": max(0, detail_links - detail_refreshed),
        "detail_errors": max(0, int(getattr(value, "detail_errors", 0) or 0)),
        "openai_messages": max(0, int(getattr(value, "openai_messages", 0) or 0)),
        "code_messages": max(0, int(getattr(value, "code_messages", 0) or 0)),
    }


class MailboxUrlTester:
    def __init__(
        self,
        *,
        client_factory: Callable[..., MailboxUrlClient] = MailboxUrlClient,
        now_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
        resend_fn: Callable[[], Any] | None = None,
    ) -> None:
        self.client_factory = client_factory
        self.now_fn = now_fn
        self.sleep_fn = sleep_fn
        self.resend_fn = resend_fn

    def test(
        self,
        value: Any,
        *,
        timeout_seconds: int = 60,
        interval_seconds: int = 5,
        resend_after_seconds: int = 15,
        proxy: str = "",
    ) -> dict[str, Any]:
        _email, mailbox_url = parse_test_input(value)
        timeout = max(1, min(int(timeout_seconds), 60))
        interval = max(1, min(int(interval_seconds), 5))
        resend_after = max(1, min(int(resend_after_seconds), timeout))
        client = self.client_factory(
            mailbox_url,
            timeout_seconds=min(15, timeout),
            proxy=str(proxy or "").strip(),
        )
        state = MailboxRequestState(client, now_fn=self.now_fn)
        state.begin_request()
        started = self.now_fn()
        attempts = 0
        resend_attempted = False
        resend_succeeded = False
        selection = None
        try:
            while True:
                attempts += 1
                selection = state.snapshot()
                elapsed = max(0.0, self.now_fn() - started)
                if selection.code:
                    return {
                        "ok": True,
                        "code_found": True,
                        "reason": "code_found",
                        "attempts": attempts,
                        "elapsed_seconds": round(elapsed, 3),
                        "resend_attempted": resend_attempted,
                        "resend_succeeded": resend_succeeded,
                        "diagnostics": _diagnostics(selection),
                    }
                if not resend_attempted and elapsed >= resend_after:
                    resend_attempted = True
                    if callable(self.resend_fn):
                        try:
                            self.resend_fn()
                            resend_succeeded = True
                        except Exception:
                            resend_succeeded = False
                if elapsed >= timeout:
                    return {
                        "ok": False,
                        "code": "mailbox_code_timeout",
                        "code_found": False,
                        "reason": str(selection.reason or "mailbox_code_timeout"),
                        "error": f"等待 {timeout} 秒后仍未识别到新的 OpenAI 验证码",
                        "attempts": attempts,
                        "elapsed_seconds": round(elapsed, 3),
                        "resend_attempted": resend_attempted,
                        "resend_succeeded": resend_succeeded,
                        "diagnostics": _diagnostics(selection),
                    }
                self.sleep_fn(min(float(interval), max(0.0, timeout - elapsed)))
        except MailboxUrlError as exc:
            return {
                "ok": False,
                "code": exc.code,
                "code_found": False,
                "reason": exc.code,
                "error": str(exc),
                "attempts": attempts,
                "elapsed_seconds": round(max(0.0, self.now_fn() - started), 3),
                "resend_attempted": resend_attempted,
                "resend_succeeded": resend_succeeded,
                "diagnostics": _diagnostics(selection),
            }
        finally:
            state.finish_request()


__all__ = ["MailboxUrlTester", "parse_test_input"]
