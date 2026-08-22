"""Read-only mailbox URL test workflow shared by the dashboard route."""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

try:
    from .chatgpt_totp import parse_mailbox_url_totp_row
except ImportError:  # Loaded as a top-level runtime override.
    from chatgpt_totp import parse_mailbox_url_totp_row

try:
    from .mailbox_url_runtime import MailboxRequestState, MailboxUrlClient, MailboxUrlError, parse_mailbox_url_row
except ImportError:  # Loaded as a top-level runtime override.
    from mailbox_url_runtime import (  # type: ignore[no-redef]
        MailboxRequestState,
        MailboxUrlClient,
        MailboxUrlError,
        parse_mailbox_url_row,
    )

try:
    from .mailbox_otp_service import MailboxOtpError, MailboxOtpService, normalize_network_policy
except ImportError:  # Loaded as a top-level runtime override.
    from mailbox_otp_service import (  # type: ignore[no-redef]
        MailboxOtpError,
        MailboxOtpService,
        normalize_network_policy,
    )


def parse_test_input(value: Any) -> tuple[str, str]:
    raw = str(value or "").strip()
    parsed_url_totp = parse_mailbox_url_totp_row(raw)
    if parsed_url_totp is not None:
        email, mailbox_url, _totp_secret = parsed_url_totp
        return email, mailbox_url
    parsed_row = parse_mailbox_url_row(raw)
    if parsed_row is not None:
        return parsed_row.email, parsed_row.mailbox_url
    if "----" in raw:
        raise MailboxUrlError("mailbox_url_invalid", "请输入完整的 HTTP(S) 取件 URL")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise MailboxUrlError("mailbox_url_invalid", "请输入完整的 HTTP(S) 取件 URL") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise MailboxUrlError("mailbox_url_invalid", "请输入完整的 HTTP(S) 取件 URL")
    return "", raw


def _diagnostics(
    selection: Any,
    service_diagnostic: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    scan = getattr(selection, "scan", None)
    value = getattr(scan, "diagnostics", None)
    supplied = dict(service_diagnostic or {})
    if value is None:
        return {
            "listing_messages": max(0, int(supplied.get("listing_messages") or 0)),
            "detail_links": max(0, int(supplied.get("detail_links") or 0)),
            "detail_refreshed": max(0, int(supplied.get("detail_refreshed") or 0)),
            "detail_cache_hits": max(0, int(supplied.get("detail_cache_hits") or 0)),
            "detail_refresh_pending": max(0, int(supplied.get("detail_refresh_pending") or 0)),
            "detail_errors": max(0, int(supplied.get("detail_errors") or 0)),
            "refresh_error_code": str(supplied.get("refresh_error_code") or ""),
            "refresh_http_status": _safe_http_status(supplied.get("refresh_http_status")),
            "openai_messages": max(0, int(supplied.get("openai_messages") or 0)),
            "code_messages": max(0, int(supplied.get("code_messages") or 0)),
            "otp_context_messages": max(0, int(supplied.get("otp_context_messages") or 0)),
            "explicit_code_messages": max(0, int(supplied.get("explicit_code_messages") or 0)),
            "bare_code_messages": max(0, int(supplied.get("bare_code_messages") or 0)),
            "request_attempts": max(0, int(supplied.get("request_attempts") or 0)),
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
        "refresh_error_code": str(getattr(value, "refresh_error_code", "") or ""),
        "refresh_http_status": (
            int(getattr(value, "refresh_http_status"))
            if isinstance(getattr(value, "refresh_http_status", None), int)
            and not isinstance(getattr(value, "refresh_http_status", None), bool)
            else None
        ),
        "openai_messages": max(0, int(getattr(value, "openai_messages", 0) or 0)),
        "code_messages": max(0, int(getattr(value, "code_messages", 0) or 0)),
        "otp_context_messages": max(0, int(getattr(value, "otp_context_messages", 0) or 0)),
        "explicit_code_messages": max(0, int(getattr(value, "explicit_code_messages", 0) or 0)),
        "bare_code_messages": max(0, int(getattr(value, "bare_code_messages", 0) or 0)),
        "request_attempts": max(0, int(supplied.get("request_attempts") or 0)),
    }


def _safe_http_status(value: Any) -> int | None:
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else None


class MailboxUrlTester:
    def __init__(
        self,
        *,
        client_factory: Callable[..., MailboxUrlClient] | None = None,
        service_factory: Callable[..., MailboxOtpService] = MailboxOtpService,
        now_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
        resend_fn: Callable[[], Any] | None = None,
    ) -> None:
        self.client_factory = client_factory
        self.service_factory = service_factory
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
        if self.client_factory is None:
            return self._test_with_shared_service(
                mailbox_url,
                timeout=timeout,
                interval=interval,
                resend_after=resend_after,
                proxy=str(proxy or "").strip(),
            )
        return self._test_with_legacy_client(
            mailbox_url,
            timeout=timeout,
            interval=interval,
            resend_after=resend_after,
            proxy=str(proxy or "").strip(),
        )

    def _test_with_shared_service(
        self,
        mailbox_url: str,
        *,
        timeout: int,
        interval: int,
        resend_after: int,
        proxy: str,
    ) -> dict[str, Any]:
        started = self.now_fn()
        attempts = 0
        resend_attempted = False
        resend_succeeded = False
        selection = None
        service: Any | None = None
        try:
            policy = normalize_network_policy(
                mode="local_proxy" if proxy else "direct",
                proxy_url=proxy,
                retries=3,
                request_timeout_seconds=min(15, timeout),
            )
            service = self.service_factory(
                mailbox_url,
                timeout_seconds=timeout,
                poll_interval_seconds=float(interval),
                network_policy=policy,
                sleep_fn=self.sleep_fn,
                now_fn=self.now_fn,
                monotonic_fn=self.now_fn,
            )
            # URL testing is intentionally not a registration request. It can
            # show the mailbox's current newest code without creating a baseline.
            request_refresh = getattr(getattr(service, "client", None), "_request_client_mailbox_refresh", None)
            if callable(request_refresh):
                request_refresh(force=True)
            while True:
                attempts += 1
                selection = service.snapshot()
                elapsed = max(0.0, self.now_fn() - started)
                diagnostics = _diagnostics(selection, _service_diagnostic(service))
                if getattr(selection, "code", ""):
                    return _success_result(
                        str(selection.code),
                        attempts=attempts,
                        elapsed=elapsed,
                        resend_attempted=resend_attempted,
                        resend_succeeded=resend_succeeded,
                        diagnostics=diagnostics,
                    )
                if not resend_attempted and elapsed >= resend_after:
                    resend_attempted = True
                    resend_succeeded = _attempt_resend(self.resend_fn)
                if elapsed >= timeout:
                    return _timeout_result(
                        selection,
                        timeout=timeout,
                        attempts=attempts,
                        elapsed=elapsed,
                        resend_attempted=resend_attempted,
                        resend_succeeded=resend_succeeded,
                        diagnostics=diagnostics,
                    )
                self.sleep_fn(min(float(interval), max(0.0, timeout - elapsed)))
        except (MailboxOtpError, MailboxUrlError) as exc:
            diagnostic = getattr(exc, "diagnostic", None)
            return _failure_result(
                exc,
                attempts=attempts,
                elapsed=max(0.0, self.now_fn() - started),
                resend_attempted=resend_attempted,
                resend_succeeded=resend_succeeded,
                diagnostics=_diagnostics(selection, diagnostic or _service_diagnostic(service)),
            )
        except Exception:
            # Keep URL test failures structured even when a custom service
            # factory has an integration error; do not expose request details.
            return _failure_result(
                MailboxUrlError("mailbox_request_failed", "邮箱取件测试失败"),
                attempts=attempts,
                elapsed=max(0.0, self.now_fn() - started),
                resend_attempted=resend_attempted,
                resend_succeeded=resend_succeeded,
                diagnostics=_diagnostics(selection, _service_diagnostic(service)),
            )
        finally:
            close = getattr(service, "close", None)
            if callable(close):
                close()

    def _test_with_legacy_client(
        self,
        mailbox_url: str,
        *,
        timeout: int,
        interval: int,
        resend_after: int,
        proxy: str,
    ) -> dict[str, Any]:
        assert self.client_factory is not None
        client = self.client_factory(
            mailbox_url,
            timeout_seconds=min(15, timeout),
            proxy=proxy,
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
                    return _success_result(
                        str(selection.code),
                        attempts=attempts,
                        elapsed=elapsed,
                        resend_attempted=resend_attempted,
                        resend_succeeded=resend_succeeded,
                        diagnostics=_diagnostics(selection),
                    )
                if not resend_attempted and elapsed >= resend_after:
                    resend_attempted = True
                    resend_succeeded = _attempt_resend(self.resend_fn)
                if elapsed >= timeout:
                    return _timeout_result(
                        selection,
                        timeout=timeout,
                        attempts=attempts,
                        elapsed=elapsed,
                        resend_attempted=resend_attempted,
                        resend_succeeded=resend_succeeded,
                        diagnostics=_diagnostics(selection),
                    )
                self.sleep_fn(min(float(interval), max(0.0, timeout - elapsed)))
        except MailboxUrlError as exc:
            return _failure_result(
                exc,
                attempts=attempts,
                elapsed=max(0.0, self.now_fn() - started),
                resend_attempted=resend_attempted,
                resend_succeeded=resend_succeeded,
                diagnostics=_diagnostics(selection),
            )
        finally:
            state.finish_request()


def _service_diagnostic(service: Any) -> Mapping[str, Any]:
    diagnostic = getattr(service, "diagnostic", None)
    if not callable(diagnostic):
        return {}
    value = diagnostic()
    return value if isinstance(value, Mapping) else {}


def _attempt_resend(resend_fn: Callable[[], Any] | None) -> bool:
    if not callable(resend_fn):
        return False
    try:
        resend_fn()
    except Exception:
        return False
    return True


def _success_result(
    verification_code: str,
    *,
    attempts: int,
    elapsed: float,
    resend_attempted: bool,
    resend_succeeded: bool,
    diagnostics: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "ok": True,
        "code_found": True,
        "verification_code": verification_code,
        "reason": "code_found",
        "attempts": attempts,
        "elapsed_seconds": round(elapsed, 3),
        "resend_attempted": resend_attempted,
        "resend_succeeded": resend_succeeded,
        "diagnostics": dict(diagnostics),
    }


def _timeout_result(
    selection: Any,
    *,
    timeout: int,
    attempts: int,
    elapsed: float,
    resend_attempted: bool,
    resend_succeeded: bool,
    diagnostics: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "ok": False,
        "code": "mailbox_code_timeout",
        "code_found": False,
        "reason": str(getattr(selection, "reason", "") or "mailbox_code_timeout"),
        "error": f"等待 {timeout} 秒后仍未识别到新的 OpenAI 验证码",
        "attempts": attempts,
        "elapsed_seconds": round(elapsed, 3),
        "resend_attempted": resend_attempted,
        "resend_succeeded": resend_succeeded,
        "diagnostics": dict(diagnostics),
    }


def _failure_result(
    exc: MailboxOtpError | MailboxUrlError,
    *,
    attempts: int,
    elapsed: float,
    resend_attempted: bool,
    resend_succeeded: bool,
    diagnostics: Mapping[str, Any],
) -> dict[str, Any]:
    code = str(getattr(exc, "code", "") or "mailbox_request_failed")
    return {
        "ok": False,
        "code": code,
        "code_found": False,
        "reason": code,
        "error": str(exc),
        "attempts": attempts,
        "elapsed_seconds": round(elapsed, 3),
        "resend_attempted": resend_attempted,
        "resend_succeeded": resend_succeeded,
        "diagnostics": dict(diagnostics),
    }


__all__ = ["MailboxUrlTester", "parse_test_input"]
