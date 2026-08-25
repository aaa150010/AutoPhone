"""Shared mailbox OTP orchestration for regular and isolated Free runs."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable, Mapping
from urllib.parse import urljoin, urlsplit

try:
    from .mailbox_url_runtime import (
        BASELINE_FALLBACK_POLL_MILESTONES,
        MAX_RESPONSE_BYTES,
        MailboxRequestState,
        MailboxResponse,
        MailboxSelection,
        MailboxUrlClient,
        MailboxUrlError,
    )
except ImportError:
    from mailbox_url_runtime import (  # type: ignore[no-redef]
        BASELINE_FALLBACK_POLL_MILESTONES,
        MAX_RESPONSE_BYTES,
        MailboxRequestState,
        MailboxResponse,
        MailboxSelection,
        MailboxUrlClient,
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
    "mailbox_candidate_too_old": "识别到的验证码邮件早于本次请求",
    "mailbox_detail_request_failed": "部分邮件详情读取失败，未识别到新验证码",
    "mailbox_detail_refresh_pending": "仍有缓存邮件详情等待下一轮刷新",
    "mailbox_refresh_request_failed": "邮箱异步刷新失败，仍在按受控间隔重试",
}


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
        self.session = session
        self.policy = policy
        self.sleep_fn = sleep_fn
        self.monotonic_fn = monotonic_fn
        self.event_fn = event_fn
        self.request_attempts = 0
        self.last_error_code = ""
        self.last_http_status: int | None = None

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
                kwargs: dict[str, Any] = {
                    "headers": {
                        "Accept": "application/json,text/plain,text/html,*/*",
                        "User-Agent": "gptphone-mailbox/2.0",
                        "Cache-Control": "no-cache, no-store, max-age=0",
                        "Pragma": "no-cache",
                    },
                    "timeout": self.policy.request_timeout_seconds,
                    "allow_redirects": False,
                    "impersonate": "chrome",
                    "verify": True,
                    "stream": True,
                }
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
                    self.sleep_fn(self.policy.backoff_seconds * attempt)
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
                self.sleep_fn(self.policy.backoff_seconds * attempt)
        assert last_error is not None
        raise MailboxUrlError(last_error.code, str(last_error)) from last_error

    def close(self) -> None:
        close = getattr(self.session, "close", None)
        if callable(close):
            close()


SourceFactory = Callable[..., tuple[MailboxUrlClient, MailboxHttpTransport | None]]
_SOURCE_FACTORIES: dict[str, SourceFactory] = {}


def register_mailbox_source(name: str, factory: SourceFactory) -> None:
    normalized = str(name or "").strip().lower()
    if not normalized:
        raise ValueError("mailbox source name is required")
    _SOURCE_FACTORIES[normalized] = factory


def _url_source_factory(
    mailbox_source: str,
    *,
    policy: MailboxNetworkPolicy,
    fetcher: Callable[[str], MailboxResponse] | None = None,
    session: Any | None = None,
    session_factory: Callable[..., Any] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
    event_fn: Callable[[Mapping[str, Any]], None] | None = None,
    now_fn: Callable[[], float] = time.time,
) -> tuple[MailboxUrlClient, MailboxHttpTransport | None]:
    transport: MailboxHttpTransport | None = None
    effective_fetcher = fetcher
    if effective_fetcher is None:
        transport = MailboxHttpTransport(
            policy,
            session=session,
            session_factory=session_factory,
            sleep_fn=sleep_fn,
            monotonic_fn=monotonic_fn,
            event_fn=event_fn,
        )
        effective_fetcher = transport.fetch
    client = MailboxUrlClient(
        mailbox_source,
        timeout_seconds=policy.request_timeout_seconds,
        proxy=policy.effective_proxy,
        fetcher=effective_fetcher,
        now_fn=now_fn,
    )
    return client, transport


register_mailbox_source("url", _url_source_factory)


def _selection_diagnostic(state: MailboxRequestState, transport: MailboxHttpTransport | None) -> dict[str, Any]:
    selection = state.last_selection
    if selection is None:
        return {
            "request_attempts": int(getattr(transport, "request_attempts", 0) or 0),
            "refresh_error_code": str(getattr(transport, "last_error_code", "") or ""),
            "refresh_http_status": getattr(transport, "last_http_status", None),
        }
    diagnostics = selection.scan.diagnostics
    return {
        "reason": selection.reason,
        "baseline_fallback_attempts": int(state.baseline_fallback_attempts),
        "baseline_fallback_age_seconds": state.baseline_fallback_age_seconds,
        "baseline_fallback_poll": state.baseline_fallback_poll,
        "max_poll_attempts": int(state.max_poll_attempts),
        "listing_messages": diagnostics.listing_messages,
        "detail_links": diagnostics.detail_links,
        "detail_refreshed": diagnostics.detail_refreshed,
        "detail_refresh_pending": max(diagnostics.detail_links - diagnostics.detail_refreshed, 0),
        "detail_errors": diagnostics.detail_errors,
        "refresh_error_code": diagnostics.refresh_error_code or str(getattr(transport, "last_error_code", "") or ""),
        "refresh_http_status": diagnostics.refresh_http_status or getattr(transport, "last_http_status", None),
        "openai_messages": diagnostics.openai_messages,
        "code_messages": diagnostics.code_messages,
        "otp_context_messages": diagnostics.otp_context_messages,
        "explicit_code_messages": diagnostics.explicit_code_messages,
        "bare_code_messages": diagnostics.bare_code_messages,
        "sender_mapped_messages": diagnostics.sender_mapped_messages,
        "subject_mapped_messages": diagnostics.subject_mapped_messages,
        "body_mapped_messages": diagnostics.body_mapped_messages,
        "received_mapped_messages": diagnostics.received_mapped_messages,
        "request_attempts": int(getattr(transport, "request_attempts", 0) or 0),
    }


def diagnostic_message(diagnostic: Mapping[str, Any]) -> str:
    reason = str(diagnostic.get("reason") or "")
    label = DIAGNOSTIC_LABELS.get(reason, "未识别到新的邮箱验证码")
    detail = (
        f"{label}（{reason or 'mailbox_no_selection'}；"
        f"列表消息 {int(diagnostic.get('listing_messages') or 0)}，"
        f"详情链接 {int(diagnostic.get('detail_links') or 0)}，"
        f"本轮刷新 {int(diagnostic.get('detail_refreshed') or 0)}，"
        f"详情错误 {int(diagnostic.get('detail_errors') or 0)}，"
        f"OpenAI 邮件 {int(diagnostic.get('openai_messages') or 0)}，"
        f"含验证码邮件 {int(diagnostic.get('code_messages') or 0)}，"
        f"上下文/显式/可信裸码 {int(diagnostic.get('otp_context_messages') or 0)}/"
        f"{int(diagnostic.get('explicit_code_messages') or 0)}/"
        f"{int(diagnostic.get('bare_code_messages') or 0)}，"
        f"字段 sender/subject/body/time "
        f"{int(diagnostic.get('sender_mapped_messages') or 0)}/"
        f"{int(diagnostic.get('subject_mapped_messages') or 0)}/"
        f"{int(diagnostic.get('body_mapped_messages') or 0)}/"
        f"{int(diagnostic.get('received_mapped_messages') or 0)}"
    )
    refresh_error = str(diagnostic.get("refresh_error_code") or "")
    if refresh_error:
        detail += f"，刷新错误 {refresh_error}"
        status = diagnostic.get("refresh_http_status")
        if isinstance(status, int) and not isinstance(status, bool):
            detail += f"/HTTP {status}"
    return detail + "）"


class MailboxOtpService:
    """One mailbox request lifecycle shared by every URL-based registration flow."""

    def __init__(
        self,
        mailbox_source: str,
        *,
        source: str = "url",
        timeout_seconds: int = 90,
        poll_interval_seconds: float = 1.0,
        network_policy: MailboxNetworkPolicy | None = None,
        log_fn: Callable[..., Any] | None = None,
        task_id: str = "",
        stage_fn: Callable[[str, str], None] | None = None,
        fetcher: Callable[[str], MailboxResponse] | None = None,
        session: Any | None = None,
        session_factory: Callable[..., Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        now_fn: Callable[[], float] = time.time,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        normalized_source = str(source or "url").strip().lower()
        factory = _SOURCE_FACTORIES.get(normalized_source)
        if factory is None:
            raise MailboxOtpError(
                "mailbox_source_unsupported",
                f"不支持的邮箱取件来源：{normalized_source or '-'}",
                retryable=False,
            )
        self.timeout_seconds = max(5, min(600, int(timeout_seconds)))
        self.poll_interval_seconds = max(0.05, min(60.0, float(poll_interval_seconds)))
        self.policy = network_policy or normalize_network_policy(mode="direct")
        self.log_fn = log_fn
        self.task_id = str(task_id or "")
        self.stage_fn = stage_fn
        self.sleep_fn = sleep_fn
        self.monotonic_fn = monotonic_fn
        self.current_stage = "email_code_waiting"
        # OTP usage is scoped to an authentication phase.  A provider may
        # legitimately reuse the same code for a later re-authentication mail;
        # a process-wide code set would incorrectly reject that new message.
        self.used_codes_by_stage: dict[str, set[str]] = {}
        self.used_identities_by_stage: dict[str, set[str]] = {}
        self.used_code_identities_by_stage: dict[str, dict[str, set[str]]] = {}
        self._last_returned_by_stage: dict[str, tuple[str, str]] = {}
        self._last_diagnostic_signature = ""
        self.client, self.transport = factory(
            mailbox_source,
            policy=self.policy,
            fetcher=fetcher,
            session=session,
            session_factory=session_factory,
            sleep_fn=sleep_fn,
            monotonic_fn=monotonic_fn,
            event_fn=self._transport_event,
            now_fn=now_fn,
        )
        self.state = MailboxRequestState(self.client, now_fn=now_fn)

    def _log(self, message: str, level: str = "info") -> None:
        if not callable(self.log_fn):
            return
        try:
            self.log_fn(message, level)
        except TypeError as exc:
            if "argument" not in str(exc):
                raise
            self.log_fn(message)

    @property
    def used_codes(self) -> set[str]:
        """Compatibility view for callers that inspect the active phase."""
        key = str(self.current_stage or "email_code_waiting")
        return self.used_codes_by_stage.setdefault(key, set())

    def _stage(self, code: str) -> None:
        self.current_stage = str(code or self.current_stage)
        if self.task_id and callable(self.stage_fn):
            self.stage_fn(self.task_id, self.current_stage)

    def _transport_event(self, event: Mapping[str, Any]) -> None:
        outcome = str(event.get("outcome") or "")
        if outcome == "success" and int(event.get("attempt") or 1) <= 1:
            return
        attempt = int(event.get("attempt") or 0)
        maximum = int(event.get("max_attempts") or 0)
        error_code = str(event.get("error_code") or "")
        status = event.get("http_status")
        status_text = f"，HTTP {status}" if isinstance(status, int) and not isinstance(status, bool) else ""
        duration_ms = int(event.get("duration_ms") or 0)
        if outcome == "retry":
            self._log(
                f"[邮箱取件请求/{self.current_stage}] 请求失败，正在受控重试"
                f"（{error_code or 'mailbox_request_failed'}{status_text}，第 {attempt}/{maximum} 次，"
                f"duration_ms={duration_ms}）",
                "warn",
            )
        elif outcome == "success":
            self._log(
                f"[邮箱取件请求/{self.current_stage}] 第 {attempt}/{maximum} 次请求恢复成功，"
                f"duration_ms={duration_ms} outcome=success",
                "success",
            )
        else:
            self._log(
                f"[邮箱取件请求/{self.current_stage}] 请求失败"
                f"（{error_code or 'mailbox_request_failed'}{status_text}，第 {attempt}/{maximum} 次，"
                f"duration_ms={duration_ms}）",
                "error",
            )

    def diagnostic(self) -> dict[str, Any]:
        return _selection_diagnostic(self.state, self.transport)

    def _log_diagnostic(self, *, force: bool = False) -> None:
        diagnostic = self.diagnostic()
        reason = str(diagnostic.get("reason") or "")
        signature = "|".join(str(diagnostic.get(key) or "") for key in (
            "reason", "listing_messages", "detail_links", "detail_refreshed",
            "detail_errors", "openai_messages", "code_messages", "refresh_error_code",
        ))
        if not force and (not reason or reason == "code_found" or signature == self._last_diagnostic_signature):
            return
        self._last_diagnostic_signature = signature
        self._log(f"[邮箱取码诊断/{self.current_stage}] {diagnostic_message(diagnostic)}", "warn")

    def prepare(
        self,
        stage_code: str = "email_code_waiting",
        *,
        force_snapshot: bool = False,
    ) -> None:
        """Start an OTP request, optionally taking a fresh mailbox baseline.

        A rebuilt OAuth session is a new authorization attempt even though the
        mailbox provider instance is intentionally retained.  In that case a
        cached ``last_scan`` belongs to the previous attempt and must not be
        used to classify the next message as new or old.
        """
        self._stage(stage_code)
        if self.state.active:
            return
        if force_snapshot:
            self.state.last_scan = None
            self.state.last_selection = None
            self.state.baseline_identities = frozenset()
            self.state.baseline_fallback_attempts = 0
            self.state.baseline_fallback_identities.clear()
            self.state.baseline_fallback_codes.clear()
        if self.state.last_scan is None:
            try:
                self.state.snapshot()
                diagnostic = self.diagnostic()
                self._log(
                    f"[邮箱验证码基线/{self.current_stage}] 已记录请求前基线"
                    f"（列表消息 {int(diagnostic.get('listing_messages') or 0)}，"
                    f"OpenAI 邮件 {int(diagnostic.get('openai_messages') or 0)}，验证码内容未记录）",
                    "info",
                )
            except MailboxUrlError as exc:
                error = mailbox_error_from_url_error(exc, self.diagnostic())
                if not error.retryable:
                    raise error from exc
                self._log(
                    f"[邮箱验证码基线/{self.current_stage}] 请求前基线读取失败，等待阶段将继续重试"
                    f"（{error.code}）",
                    "warn",
                )
        self.state.begin_request()

    def mark_sent(self, stage_code: str = "email_code_waiting") -> None:
        self._stage(stage_code)
        if not self.state.active:
            self.prepare(stage_code)

    def discard_code(self, stage_code: str, code: Any) -> None:
        """Release a code reserved by ``wait_code`` when no request was sent.

        A local transport exception can happen before an OTP validation request
        leaves the process. In that case the same newly fetched message may be
        retried; a response returned by the server remains committed.
        """
        key = str(stage_code or self.current_stage or "email_code_waiting")
        value = str(code or "").strip()
        returned = self._last_returned_by_stage.get(key)
        if not value or not returned or returned[0] != value:
            return
        identity = returned[1]
        mapping = self.used_code_identities_by_stage.setdefault(key, {})
        identities = mapping.get(value, set())
        identities.discard(identity or "__value__")
        if identities:
            mapping[value] = identities
            return
        mapping.pop(value, None)
        self.used_codes_by_stage.setdefault(key, set()).discard(value)
        if identity:
            self.used_identities_by_stage.setdefault(key, set()).discard(identity)
        self._last_returned_by_stage.pop(key, None)

    def snapshot(self) -> MailboxSelection:
        return self.state.snapshot()

    def wait_code(
        self,
        stage_code: str = "email_code_waiting",
        *,
        resend_fn: Callable[[], None] | None = None,
        resend_after_seconds: float = 12.0,
        stop_requested: Callable[[], bool] | None = None,
    ) -> str:
        self._stage(stage_code)
        stage_key = str(stage_code or self.current_stage or "email_code_waiting")
        used_codes = self.used_codes_by_stage.setdefault(stage_key, set())
        used_identities = self.used_identities_by_stage.setdefault(stage_key, set())
        code_identities = self.used_code_identities_by_stage.setdefault(stage_key, {})
        if not self.state.active:
            self.prepare(stage_code)
        maximum = max(1, int(self.timeout_seconds / self.poll_interval_seconds))
        # A 2FA re-authentication must never submit a code that existed before
        # its own request. Registration and existing-login phases retain the
        # shared bounded baseline fallback; 2FA waits for a new message or
        # reports a retryable timeout so the caller can resend safely.
        self.state.configure_request(
            max_poll_attempts=maximum,
            allow_baseline_fallback=stage_key != "free_twofa_enroll",
        )
        started = self.monotonic_fn()
        deadline = started + self.timeout_seconds
        resend_at = started + max(3.0, min(float(resend_after_seconds), self.timeout_seconds / 2))
        resend_attempted = False
        last_error: MailboxOtpError | None = None
        successful_scan = False
        while self.monotonic_fn() < deadline:
            if callable(stop_requested) and bool(stop_requested()):
                self.state.finish_request()
                raise MailboxOtpError(
                    "mailbox_wait_stopped",
                    "邮箱验证码轮询已按任务停止请求中断",
                    retryable=False,
                )
            try:
                selection = self.state.snapshot()
                successful_scan = True
                last_error = None
            except MailboxUrlError as exc:
                last_error = mailbox_error_from_url_error(exc, self.diagnostic())
                self.state.finish_request()
                raise last_error from exc
            if selection is not None:
                code = str(selection.code or "").strip()
                identity = str(selection.identity or "").strip()
                is_new_message = bool(identity and identity not in used_identities)
                if code and (code not in used_codes or is_new_message):
                    used_codes.add(code)
                    used_identities.add(identity) if identity else None
                    code_identities.setdefault(code, set()).add(identity or "__value__")
                    self._last_returned_by_stage[stage_key] = (code, identity)
                    self.state.finish_request()
                    return code
                if code:
                    self.state.baseline_identities = frozenset({*self.state.baseline_identities, selection.identity})
                if self.state.poll_attempt in {1, *BASELINE_FALLBACK_POLL_MILESTONES}:
                    self._log_diagnostic(force=True)
                else:
                    self._log_diagnostic()
            if (
                callable(resend_fn)
                and not resend_attempted
                and self.monotonic_fn() >= resend_at
            ):
                resend_attempted = True
                try:
                    resend_fn()
                    self._log(
                        f"[邮箱验证码重发/{self.current_stage}] 已触发一次受控重发，"
                        "继续沿用原始邮箱基线并排除已使用验证码",
                        "warn",
                    )
                except Exception as exc:
                    # A resend callback can be the point where the OAuth
                    # session is discovered to be invalid.  Do not turn that
                    # structured failure into a misleading OTP timeout: the
                    # caller must rebuild the session or preserve its node.
                    if (
                        getattr(exc, "error_code", "") == "oauth_session_invalid"
                        or bool(getattr(exc, "node_code", ""))
                    ):
                        raise
                    self._log(
                        f"[邮箱验证码重发/{self.current_stage}] 重发未完成"
                        f"（{type(exc).__name__}），继续等待原请求",
                        "warn",
                    )
            remaining = deadline - self.monotonic_fn()
            if remaining > 0:
                delay = min(self.poll_interval_seconds, remaining)
                if callable(stop_requested):
                    # Bound stop latency even when the configured poll interval
                    # is large. Fake clocks still advance through sleep_fn.
                    slept = 0.0
                    while slept < delay:
                        if bool(stop_requested()):
                            self.state.finish_request()
                            raise MailboxOtpError(
                                "mailbox_wait_stopped",
                                "邮箱验证码轮询已按任务停止请求中断",
                                retryable=False,
                            )
                        chunk = min(0.25, delay - slept)
                        self.sleep_fn(chunk)
                        slept += chunk
                else:
                    self.sleep_fn(delay)

        try:
            fallback = self.state.final_baseline_fallback()
        except MailboxUrlError as exc:
            fallback = None
            last_error = mailbox_error_from_url_error(exc, self.diagnostic())
        if fallback is not None:
            code = str(fallback.code or "").strip()
            identity = str(fallback.identity or "").strip()
            is_new_message = bool(identity and identity not in used_identities)
            if code and (code not in used_codes or is_new_message):
                used_codes.add(code)
                used_identities.add(identity) if identity else None
                code_identities.setdefault(code, set()).add(identity or "__value__")
                self._last_returned_by_stage[stage_key] = (code, identity)
                self._log_diagnostic(force=True)
                self.state.finish_request()
                return code
        diagnostic = self.diagnostic()
        self._log_diagnostic(force=True)
        self.state.finish_request()
        if last_error is not None and not successful_scan:
            raise MailboxOtpError(
                last_error.code,
                str(last_error),
                status=last_error.status,
                retryable=True,
                diagnostic=diagnostic,
            )
        reason = str(diagnostic.get("reason") or "mailbox_code_timeout")
        raise MailboxOtpError(
            "mailbox_code_timeout",
            f"邮箱验证码等待超时：{DIAGNOSTIC_LABELS.get(reason, '未识别到新的六位验证码')}",
            status=diagnostic.get("refresh_http_status") if isinstance(diagnostic.get("refresh_http_status"), int) else None,
            retryable=True,
            diagnostic=diagnostic,
        )

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()


def mailbox_error_from_url_error(
    exc: MailboxUrlError,
    diagnostic: Mapping[str, Any] | None = None,
) -> MailboxOtpError:
    code = str(getattr(exc, "code", "") or "mailbox_request_failed")
    status = getattr(exc, "status", None)
    retryable = code in RETRYABLE_ERROR_CODES or (
        code == "mailbox_http_error" and status in RETRYABLE_HTTP_STATUSES
    )
    return MailboxOtpError(
        code,
        str(exc),
        status=status if isinstance(status, int) and not isinstance(status, bool) else None,
        retryable=retryable,
        diagnostic=diagnostic,
    )


def _runtime_service(provider: Any) -> MailboxOtpService:
    service = getattr(provider, "_gptphone_mailbox_otp_service", None)
    if isinstance(service, MailboxOtpService):
        return service
    proxy = str(getattr(provider, "proxy", "") or "").strip()
    policy = normalize_network_policy(
        mode="local_proxy" if proxy else "direct",
        proxy_url=proxy,
        retries=getattr(provider, "mailbox_request_retries", 3),
        backoff_seconds=getattr(provider, "mailbox_retry_backoff_seconds", 1.0),
        request_timeout_seconds=getattr(provider, "timeout_seconds", 15),
    )
    service = MailboxOtpService(
        str(getattr(provider, "mailbox_url", "") or ""),
        timeout_seconds=getattr(provider, "timeout", 90),
        network_policy=policy,
        log_fn=getattr(provider, "log_fn", None),
    )
    setattr(provider, "_gptphone_mailbox_otp_service", service)
    # Preserve compatibility for callers which inspect the low-level state.
    setattr(provider, "_generic_mailbox_state", service.state)
    return service


def runtime_snapshot(provider: Any) -> MailboxSelection:
    return _runtime_service(provider).snapshot()


def begin_runtime_request(provider: Any) -> None:
    service = _runtime_service(provider)
    if not service.state.active:
        service.state.begin_request()


def configure_runtime_request(provider: Any, *, max_poll_attempts: int) -> None:
    _runtime_service(provider).state.configure_request(max_poll_attempts=max_poll_attempts)


def final_runtime_baseline_fallback(provider: Any) -> MailboxSelection:
    return _runtime_service(provider).state.final_baseline_fallback()


def finish_runtime_request(provider: Any) -> None:
    service = getattr(provider, "_gptphone_mailbox_otp_service", None)
    if isinstance(service, MailboxOtpService):
        service.state.finish_request()


def runtime_diagnostic(provider: Any) -> dict[str, Any]:
    return _runtime_service(provider).diagnostic()


def log_runtime_diagnostic(provider: Any, log_fn: Callable[..., Any] | None) -> None:
    diagnostic = runtime_diagnostic(provider)
    if not diagnostic or str(diagnostic.get("reason") or "") == "code_found":
        return
    if callable(log_fn):
        message = f"  [邮箱取码诊断/email_code_waiting] {diagnostic_message(diagnostic)}"
        try:
            log_fn(message, "warn")
        except TypeError:
            log_fn(message)


def legacy_wait_code(
    otp_provider: Any,
    email: str,
    *,
    wait_fn: Callable[[Any, str], str],
    max_poll_attempts: int,
    timeout_seconds: int,
    interval_seconds: int,
    deadline_monotonic: float | None = None,
) -> str:
    """Run the recovered URL provider through the shared state and diagnostics."""
    provider = getattr(otp_provider, "provider", None)
    service = _runtime_service(provider)
    stage_key = str(getattr(service, "current_stage", "email_code_waiting") or "email_code_waiting")
    stage_used_codes = getattr(service, "used_codes_by_stage", {}).setdefault(stage_key, set())
    used_codes = set(getattr(otp_provider, "_gptphone_used_email_otp_codes", ()) or ())
    used_codes.update(stage_used_codes)
    configure_runtime_request(provider, max_poll_attempts=max_poll_attempts)
    original_timeout = getattr(otp_provider, "timeout", None)
    original_interval = getattr(otp_provider, "interval", None)
    effective_timeout = max(1, int(timeout_seconds))
    if deadline_monotonic is not None:
        effective_timeout = min(effective_timeout, max(1, int(deadline_monotonic - time.monotonic())))
    if original_timeout is not None:
        otp_provider.timeout = effective_timeout
    if original_interval is not None:
        interval_for_budget = max(1, (effective_timeout + max_poll_attempts - 1) // max_poll_attempts)
        otp_provider.interval = min(max(1, int(interval_seconds)), interval_for_budget)
    try:
        try:
            code = wait_fn(otp_provider, email)
        except Exception as exc:
            if "mailbox_code_timeout" not in str(exc).casefold():
                log_runtime_diagnostic(provider, getattr(otp_provider, "log_fn", None))
                raise
            try:
                fallback = final_runtime_baseline_fallback(provider)
            except MailboxUrlError:
                fallback = None
            if fallback is None:
                # The recovered runtime's public fallback helper remains a
                # compatibility seam for callers that replace it in tests or
                # older integrations. It resolves to this same state for a
                # provider created by the shared service.
                try:
                    from . import mailbox_url_runtime as legacy_runtime
                except ImportError:
                    import mailbox_url_runtime as legacy_runtime  # type: ignore[no-redef]
                try:
                    fallback = legacy_runtime.final_runtime_baseline_fallback(provider)
                except Exception:
                    fallback = None
            if fallback is None or not fallback.code:
                log_runtime_diagnostic(provider, getattr(otp_provider, "log_fn", None))
                raise
            code = fallback.code
        normalized = str(code or "").strip()
        if normalized and normalized in used_codes:
            raise MailboxOtpError(
                "mailbox_code_reused",
                "邮箱取件只返回了已经使用过的验证码",
                retryable=True,
                diagnostic=runtime_diagnostic(provider),
            )
        if normalized:
            used_codes.add(normalized)
            stage_used_codes.add(normalized)
            setattr(otp_provider, "_gptphone_used_email_otp_codes", used_codes)
            code = normalized
    finally:
        if original_timeout is not None:
            otp_provider.timeout = original_timeout
        if original_interval is not None:
            otp_provider.interval = original_interval
        finish_runtime_request(provider)
    diagnostic = runtime_diagnostic(provider)
    fallback_reason = str(diagnostic.get("reason") or "")
    if code and fallback_reason in {"mailbox_baseline_code_fallback", "mailbox_final_baseline_code_fallback"}:
        poll = int(diagnostic.get("baseline_fallback_poll") or 0)
        maximum = int(diagnostic.get("max_poll_attempts") or 0)
        phase = "最终超时回退" if fallback_reason == "mailbox_final_baseline_code_fallback" else f"轮询 {poll}/{maximum}"
        log_fn = getattr(otp_provider, "log_fn", None)
        if callable(log_fn):
            message = f"  [邮箱取码诊断/email_code_waiting] {phase}：尝试最近的 OpenAI 基线验证码（本任务最多三次）"
            try:
                log_fn(message, "info")
            except TypeError:
                log_fn(message)
    return code


__all__ = [
    "DEFAULT_FREE_MAILBOX_PROXY",
    "DIAGNOSTIC_LABELS",
    "MailboxHttpTransport",
    "MailboxNetworkPolicy",
    "MailboxOtpError",
    "MailboxOtpService",
    "begin_runtime_request",
    "configure_runtime_request",
    "diagnostic_message",
    "finish_runtime_request",
    "final_runtime_baseline_fallback",
    "legacy_wait_code",
    "log_runtime_diagnostic",
    "normalize_network_policy",
    "register_mailbox_source",
    "runtime_diagnostic",
    "runtime_snapshot",
]
