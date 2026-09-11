"""Mailbox HTTP transport, network policy and transport-error classification.

Split out of ``mailbox_otp_service.py`` so the OTP service keeps only the
pickup strategy while the transport layer stays importable on its own. The
original module re-exports every public name here, so callers keep importing
from ``mailbox_otp_service`` unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable, Mapping
from urllib.parse import urljoin, urlsplit

try:
    from .mailbox_url_runtime import (
        BASELINE_FALLBACK_POLL_MILESTONES,
        MAX_RESPONSE_BYTES,
        MailboxResponse,
        MailboxUrlError,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_url_runtime import (  # type: ignore[no-redef]
        BASELINE_FALLBACK_POLL_MILESTONES,
        MAX_RESPONSE_BYTES,
        MailboxResponse,
        MailboxUrlError,
    )


DEFAULT_FREE_MAILBOX_PROXY = "http://127.0.0.1:7897"
RETRYABLE_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})
RETRYABLE_ERROR_CODES = frozenset({
    "mailbox_connection_error",
    "mailbox_request_failed",
    "mailbox_ssl_error",
    "mailbox_timeout",
    "mailbox_unavailable",
})
DIAGNOSTIC_LABELS = {
    "mailbox_empty": "邮箱入口当前没有邮件",
    "mailbox_messages_without_openai_otp": "邮箱已有邮件，但没有识别到 OpenAI 验证邮件",
    "mailbox_openai_message_without_otp": "已识别 OpenAI 邮件，但没有匹配到有效六位验证码",
    "mailbox_only_baseline_code": "邮箱当前只有本次请求前的旧验证码",
    "mailbox_baseline_code_fallback": "轮询达到兜底节点后，已尝试最近的 OpenAI 基线验证码",
    "mailbox_final_baseline_code_fallback": "邮箱等待超时后，已最后尝试一次最新的 OpenAI 基线验证码",
    "mailbox_last_resort_code": "最终超时兜底：使用邮箱中可获取到的最新验证码",
    "mailbox_candidate_too_old": "识别到的验证码邮件早于本次请求",
    "mailbox_detail_request_failed": "部分邮件详情读取失败，未识别到新验证码",
    "mailbox_detail_refresh_pending": "仍有缓存邮件详情等待下一轮刷新",
    "mailbox_refresh_request_failed": "邮箱异步刷新失败，仍在按受控间隔重试",
}

@dataclass(frozen=True, slots=True)
class MailboxNetworkPolicy:
    mode: str = "direct"
    proxy_url: str = ""
    retries: int = 3
    backoff_seconds: float = 1.0
    request_timeout_seconds: int = 15

    @property
    def effective_proxy(self) -> str:
        return self.proxy_url if self.mode == "local_proxy" else ""

class MailboxOtpError(RuntimeError):
    """Credential-safe failure raised by the shared mailbox OTP service."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int | None = None,
        retryable: bool = True,
        diagnostic: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = str(code or "mailbox_request_failed")
        self.status = status
        self.retryable = bool(retryable)
        self.diagnostic = dict(diagnostic or {})


def normalize_network_policy(
    *,
    mode: Any = "direct",
    proxy_url: Any = "",
    retries: Any = 3,
    backoff_seconds: Any = 1.0,
    request_timeout_seconds: Any = 15,
) -> MailboxNetworkPolicy:
    normalized_mode = str(mode or "direct").strip().lower()
    if normalized_mode not in {"direct", "local_proxy"}:
        raise MailboxOtpError(
            "mailbox_network_mode_invalid",
            "邮箱取件网络模式只能选择本机代理或直连",
            retryable=False,
        )
    normalized_proxy = str(proxy_url or "").strip()
    if normalized_mode == "local_proxy":
        normalized_proxy = normalized_proxy or DEFAULT_FREE_MAILBOX_PROXY
        try:
            parsed = urlsplit(normalized_proxy)
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise MailboxOtpError(
                "mailbox_proxy_invalid",
                "邮箱取件代理地址格式无效",
                retryable=False,
            ) from exc
        if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
            raise MailboxOtpError(
                "mailbox_proxy_invalid",
                "邮箱取件代理必须是完整的 HTTP、HTTPS、SOCKS5 或 SOCKS5H 地址",
                retryable=False,
            )
        if port is not None and not 1 <= port <= 65535:
            raise MailboxOtpError("mailbox_proxy_invalid", "邮箱取件代理端口无效", retryable=False)
    try:
        normalized_retries = max(0, min(5, int(retries)))
    except (TypeError, ValueError):
        normalized_retries = 3
    try:
        normalized_backoff = max(0.0, min(15.0, float(backoff_seconds)))
    except (TypeError, ValueError):
        normalized_backoff = 1.0
    try:
        normalized_timeout = max(3, min(60, int(request_timeout_seconds)))
    except (TypeError, ValueError):
        normalized_timeout = 15
    return MailboxNetworkPolicy(
        mode=normalized_mode,
        proxy_url=normalized_proxy,
        retries=normalized_retries,
        backoff_seconds=normalized_backoff,
        request_timeout_seconds=normalized_timeout,
    )


def _classify_transport_error(exc: BaseException) -> tuple[str, str]:
    name = type(exc).__name__.casefold()
    text = str(exc or "").casefold()
    if "ssl" in name or "ssl" in text or "certificate" in text or "tls" in text:
        return "mailbox_ssl_error", "邮箱取件服务 TLS/SSL 连接失败"
    if "timeout" in name or "timed out" in text or "timeout" in text:
        return "mailbox_timeout", "邮箱取件服务连接或读取超时"
    if any(marker in name or marker in text for marker in ("connection", "connect", "proxy")):
        return "mailbox_connection_error", "邮箱取件服务连接失败"
    return "mailbox_request_failed", "邮箱取件请求失败"


class MailboxHttpTransport:
    """Explicit-network HTTP transport which never inherits host proxy variables."""

    def __init__(
        self,
        policy: MailboxNetworkPolicy,
        *,
        session: Any | None = None,
        session_factory: Callable[..., Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        monotonic_fn: Callable[[], float] = time.monotonic,
        event_fn: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        if session is None:
            if session_factory is None:
                from curl_cffi import requests as curl_requests

                session_factory = curl_requests.Session
            session = session_factory(trust_env=False)
        if hasattr(session, "trust_env"):
            session.trust_env = False
        # Constant request envelope frozen once; the per-attempt loop below
        # only varies the timeout (and proxies for configured policies).
        self._base_headers = {
            "Accept": "application/json,text/plain,text/html,*/*",
            "User-Agent": "gptphone-mailbox/2.0",
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
        }
        self._base_kwargs: dict[str, Any] = {
            "headers": self._base_headers,
            "allow_redirects": False,
            "impersonate": "chrome",
            "verify": True,
            "stream": True,
        }
        self.session = session
        self.policy = policy
        self.sleep_fn = sleep_fn
        self.monotonic_fn = monotonic_fn
        self.event_fn = event_fn
        self.request_attempts = 0
        self.last_error_code = ""
        self.last_http_status: int | None = None
        # A single OTP request may cause a listing request plus several
        # same-origin detail requests.  Keep one optional monotonic deadline
        # for the whole scan so a slow detail page cannot multiply the
        # configured email timeout by the number of links in the mailbox.
        self._deadline_monotonic: float | None = None

    def set_deadline(self, deadline: float | None) -> None:
        """Bound all subsequent requests until the current scan completes."""
        self._deadline_monotonic = None if deadline is None else float(deadline)

    def clear_deadline(self) -> None:
        self._deadline_monotonic = None

    def _event(self, **fields: Any) -> None:
        if callable(self.event_fn):
            self.event_fn(fields)

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int | None]:
        parsed = urlsplit(url)
        return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), parsed.port

    @staticmethod
    def _response_bytes(response: Any) -> bytes:
        length = str(getattr(response, "headers", {}).get("content-length", "") or "").strip()
        if length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
            raise MailboxOtpError(
                "mailbox_response_too_large",
                "邮箱取件响应超过 2 MB 安全上限",
                retryable=False,
            )
        iterator = getattr(response, "iter_content", None)
        if callable(iterator):
            chunks: list[bytes] = []
            size = 0
            for chunk in iterator(chunk_size=64 * 1024):
                value = bytes(chunk or b"")
                size += len(value)
                if size > MAX_RESPONSE_BYTES:
                    raise MailboxOtpError(
                        "mailbox_response_too_large",
                        "邮箱取件响应超过 2 MB 安全上限",
                        retryable=False,
                    )
                chunks.append(value)
            return b"".join(chunks)
        value = bytes(getattr(response, "content", b"") or b"")
        if len(value) > MAX_RESPONSE_BYTES:
            raise MailboxOtpError(
                "mailbox_response_too_large",
                "邮箱取件响应超过 2 MB 安全上限",
                retryable=False,
            )
        return value

    def _request(self, url: str, kwargs: Mapping[str, Any]) -> tuple[Any, str]:
        current = str(url)
        origin = self._origin(current)
        for _redirect in range(6):
            if self._deadline_monotonic is not None and self._deadline_monotonic <= self.monotonic_fn():
                raise MailboxOtpError(
                    "mailbox_timeout",
                    "邮箱取件请求已达到本轮时间预算",
                    retryable=True,
                )
            response = self.session.get(current, **dict(kwargs))
            status = int(getattr(response, "status_code", 0) or 0)
            if status not in {301, 302, 303, 307, 308}:
                return response, current
            location = str(getattr(response, "headers", {}).get("location", "") or "").strip()
            target = urljoin(current, location)
            if not location or self._origin(target) != origin:
                raise MailboxOtpError(
                    "mailbox_cross_origin_redirect",
                    "邮箱取件服务返回了不受信任的跨域跳转",
                    status=status,
                    retryable=False,
                )
            current = target
        raise MailboxOtpError(
            "mailbox_redirect_limit",
            "邮箱取件服务同源跳转次数过多",
            retryable=False,
        )

    def fetch(self, url: str) -> MailboxResponse:
        total_attempts = 1 + self.policy.retries
        last_error: MailboxOtpError | None = None
        for attempt in range(1, total_attempts + 1):
            self.request_attempts += 1
            started = self.monotonic_fn()
            try:
                request_timeout = self.policy.request_timeout_seconds
                if self._deadline_monotonic is not None:
                    remaining = self._deadline_monotonic - self.monotonic_fn()
                    if remaining <= 0:
                        raise MailboxOtpError(
                            "mailbox_timeout",
                            "邮箱取件请求已达到本轮时间预算",
                            retryable=True,
                        )
                    # urllib/curl transports accept fractional timeouts, but
                    # retain a small floor so a request is not handed a zero
                    # timeout due to clock rounding.
                    request_timeout = min(request_timeout, max(0.2, remaining))
                kwargs = dict(self._base_kwargs)
                kwargs["timeout"] = request_timeout
                proxy = self.policy.effective_proxy
                if proxy:
                    kwargs["proxies"] = {"http": proxy, "https": proxy}
                response, final_url = self._request(url, kwargs)
                status = int(getattr(response, "status_code", 0) or 0)
                self.last_http_status = status or None
                duration_ms = max(0, int((self.monotonic_fn() - started) * 1000))
                if status in RETRYABLE_HTTP_STATUSES and attempt < total_attempts:
                    self.last_error_code = "mailbox_http_error"
                    self._event(
                        outcome="retry",
                        error_code="mailbox_http_error",
                        http_status=status,
                        attempt=attempt,
                        max_attempts=total_attempts,
                        duration_ms=duration_ms,
                    )
                    delay = self.policy.backoff_seconds * attempt
                    if self._deadline_monotonic is not None:
                        remaining = self._deadline_monotonic - self.monotonic_fn()
                        if remaining <= 0:
                            raise MailboxOtpError(
                                "mailbox_timeout",
                                "邮箱取件请求已达到本轮时间预算",
                                retryable=True,
                            )
                        delay = min(delay, remaining)
                    self.sleep_fn(max(0.0, delay))
                    continue
                self.last_error_code = "" if 200 <= status < 300 else "mailbox_http_error"
                self._event(
                    outcome="success" if 200 <= status < 300 else "failed",
                    error_code=self.last_error_code,
                    http_status=status or None,
                    attempt=attempt,
                    max_attempts=total_attempts,
                    duration_ms=duration_ms,
                )
                return MailboxResponse(
                    str(getattr(response, "url", "") or final_url),
                    self._response_bytes(response),
                    str(getattr(response, "headers", {}).get("content-type", "") or ""),
                    status,
                )
            except MailboxOtpError:
                raise
            except Exception as exc:
                code, message = _classify_transport_error(exc)
                duration_ms = max(0, int((self.monotonic_fn() - started) * 1000))
                self.last_error_code = code
                last_error = MailboxOtpError(code, message, retryable=True)
                self._event(
                    outcome="retry" if attempt < total_attempts else "failed",
                    error_code=code,
                    attempt=attempt,
                    max_attempts=total_attempts,
                    duration_ms=duration_ms,
                )
                if attempt >= total_attempts:
                    break
                delay = self.policy.backoff_seconds * attempt
                if self._deadline_monotonic is not None:
                    remaining = self._deadline_monotonic - self.monotonic_fn()
                    if remaining <= 0:
                        break
                    delay = min(delay, remaining)
                self.sleep_fn(max(0.0, delay))
        assert last_error is not None
        raise MailboxUrlError(last_error.code, str(last_error)) from last_error

    def close(self) -> None:
        close = getattr(self.session, "close", None)
        if callable(close):
            close()


__all__ = [
    "DEFAULT_FREE_MAILBOX_PROXY",
    "RETRYABLE_HTTP_STATUSES",
    "RETRYABLE_ERROR_CODES",
    "DIAGNOSTIC_LABELS",
    "MailboxNetworkPolicy",
    "MailboxOtpError",
    "normalize_network_policy",
    "MailboxHttpTransport",
]
