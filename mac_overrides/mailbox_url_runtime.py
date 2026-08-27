"""Generic, credential-safe mailbox URL parsing and OTP selection."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request

try:
    from .mailbox_code_parser import (
        OPENAI_PATTERN as _OPENAI_PATTERN,
        decode_bytes as _decode_bytes,
    )
    from .mailbox_pickup_runtime import (
        ClientMailboxApi as _ClientMailboxApi,
        client_mailbox_api_from_shell as _client_mailbox_api_from_shell,
        client_mailbox_detail_url as _client_mailbox_detail_url,
        safe_detail_url as _safe_detail_url,
        same_origin as _same_origin,
        MailboxMessage,
        MailboxUrlError,
        decode_mail_body,
        extract_openai_code,
        parse_mailbox_payload,
        parse_received_timestamp,
        _first,
        _merge_messages,
        _messages_from_json,
        _message_from_mapping,
        _response_too_complex,
        _safe_http_status,
        _safe_identity,
        _explicit_code_from_mapping,
        _trusted_otp_source,
        _values_for_keys,
    )
except ImportError:  # Loaded as a top-level runtime override.
    from mailbox_code_parser import (  # type: ignore[no-redef]
        OPENAI_PATTERN as _OPENAI_PATTERN,
        decode_bytes as _decode_bytes,
    )
    from mailbox_pickup_runtime import (
        ClientMailboxApi as _ClientMailboxApi,
        client_mailbox_api_from_shell as _client_mailbox_api_from_shell,
        client_mailbox_detail_url as _client_mailbox_detail_url,
        safe_detail_url as _safe_detail_url,
        same_origin as _same_origin,
        MailboxMessage,
        MailboxUrlError,
        decode_mail_body,
        extract_openai_code,
        parse_mailbox_payload,
        parse_received_timestamp,
        _first,
        _merge_messages,
        _messages_from_json,
        _message_from_mapping,
        _response_too_complex,
        _safe_http_status,
        _safe_identity,
        _explicit_code_from_mapping,
        _trusted_otp_source,
        _values_for_keys,
    )


def _parse_client_mailbox_payload(
    raw: str,
    source_url: str,
    *,
    include_messages: bool = True,
) -> tuple[tuple[MailboxMessage, ...], tuple[str, ...], bool, bool, str, int | None]:
    """Keep provider refresh metadata beside the URL client state machine."""
    try:
        parsed = json.loads(raw)
    except RecursionError as exc:
        raise _response_too_complex() from exc
    except (TypeError, ValueError):
        if include_messages:
            messages, detail_urls = parse_mailbox_payload(raw, source_url)
            return messages, detail_urls, False, False, "", None
        raise MailboxUrlError("mailbox_provider_response_invalid", "邮箱取码数据接口返回了无法识别的响应")
    if isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes, bytearray)):
        if not include_messages:
            return (), (), False, False, "", None
        messages, detail_urls = _messages_from_json(parsed, source_url, message_limit=_MAX_PARSED_MESSAGES)
        return _merge_messages(messages), tuple(dict.fromkeys(detail_urls[:MAX_MESSAGES])), False, False, "", None
    if not isinstance(parsed, Mapping):
        raise MailboxUrlError("mailbox_provider_response_invalid", "邮箱取码数据接口返回了无法识别的响应")
    status = _safe_http_status(_first(parsed, ("status", "status_code", "http_status")))
    if parsed.get("ok") is False or parsed.get("success") is False:
        raise MailboxUrlError("mailbox_provider_error", "邮箱取码数据接口返回失败", status=status)
    if include_messages:
        messages: list[MailboxMessage] = []
        detail_urls: list[str] = []
        raw_messages: Any = _first(parsed, ("messages", "items", "mail", "message"))
        if raw_messages in (None, ""):
            for nested in _values_for_keys(parsed, ("data", "result", "payload")):
                candidate = _first(nested, ("messages", "items", "mail", "message")) if isinstance(nested, Mapping) else nested
                if candidate not in (None, ""):
                    raw_messages = candidate
                    break
        # Some provider revisions return only a scoped six-digit field while
        # the page is still warming its message list.  Accept that field only
        # for an already trusted mailbox API/source; never inspect URL query
        # parameters (notably ``auth_code``) as a code.
        top_level_code = ""
        if raw_messages in (None, "") and _trusted_otp_source(source_url):
            top_level_code = _explicit_code_from_mapping(parsed)
            if not top_level_code:
                for nested in _values_for_keys(parsed, ("data", "result", "payload")):
                    if isinstance(nested, Mapping):
                        top_level_code = _explicit_code_from_mapping(nested)
                        if top_level_code:
                            break
        if raw_messages in (None, ""):
            if not top_level_code:
                raise MailboxUrlError("mailbox_provider_response_invalid", "邮箱取码数据接口返回了无法识别的响应")
        if isinstance(raw_messages, Mapping):
            raw_messages = [raw_messages]
        elif raw_messages not in (None, "") and not isinstance(raw_messages, list):
            raise MailboxUrlError("mailbox_provider_response_invalid", "邮箱取码数据接口返回了无法识别的响应")
        for raw_message in (raw_messages or [])[:_MAX_PARSED_MESSAGES]:
            if not isinstance(raw_message, Mapping):
                continue
            message = _message_from_mapping(raw_message, source_url, len(messages), trust_explicit_code=True)
            if message is not None:
                messages.append(message)
                if message.detail_url:
                    detail_urls.append(message.detail_url)
        if not messages:
            nested = _first(parsed, ("data", "result", "payload"))
            if isinstance(nested, (Mapping, list)):
                messages, nested_links = _messages_from_json(nested, source_url, message_limit=_MAX_PARSED_MESSAGES)
                detail_urls.extend(nested_links)
        if top_level_code and not any(message.code for message in messages):
            messages.append(MailboxMessage(
                identity=_safe_identity("client-mailbox-top-level-code", source_url, top_level_code),
                code=top_level_code,
                code_source="explicit_code",
                order=min((message.order for message in messages), default=0) - 1,
                explicit_code=True,
            ))
        merged = _merge_messages(messages)
        detail_links = tuple(dict.fromkeys(detail_urls[:MAX_MESSAGES]))
    else:
        merged, detail_links = (), ()
    if include_messages and not any(message.code for message in merged):
        top_level_code = _explicit_code_from_mapping(parsed) if _trusted_otp_source(source_url) else ""
        if top_level_code:
            merged = _merge_messages((*merged, MailboxMessage(
                identity=_safe_identity("client-mailbox-top-level-code", source_url, top_level_code),
                code=top_level_code,
                code_source="explicit_code",
                order=min((message.order for message in merged), default=0) - 1,
                explicit_code=True,
            )))
    refresh_error = parsed.get("refresh_error")
    refresh_status = _first(refresh_error if isinstance(refresh_error, Mapping) else parsed, ("status", "status_code", "http_status", "refresh_status"))
    return (
        merged,
        detail_links,
        parsed.get("smtp_inbound") is True,
        parsed.get("refreshing") is True,
        "mailbox_provider_refresh_error" if refresh_error not in (None, "", False) else "",
        _safe_http_status(refresh_status),
    )


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_MESSAGES = 40
REFRESH_DETAIL_LIMIT = 8
REQUEST_CLOCK_SKEW_SECONDS = 120
RECENT_BASELINE_CODE_WINDOW_SECONDS = 600
BASELINE_FALLBACK_MAX_ATTEMPTS = 3
BASELINE_FALLBACK_POLL_MILESTONES = (10, 20, 30)
_CLIENT_MAILBOX_REFRESH_INTERVAL_SECONDS = 10
_CLIENT_MAILBOX_DEEP_REFRESH_AFTER_SECONDS = 25
_MAX_PARSED_MESSAGES = MAX_MESSAGES * 4
_EMAIL_PATTERN = re.compile(
    r"(?i)[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
)
_URL_ROW_PATTERN = re.compile(
    r"^\s*(?P<email>[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})"
    r"\s*(?P<separator>-{3,}|\||｜)\s*(?P<url>https?://\S+)\s*$",
    re.IGNORECASE,
)
@dataclass(frozen=True)
class MailboxUrlRow:
    email: str
    mailbox_url: str
    separator: str


@dataclass(frozen=True)
class MailboxResponse:
    url: str
    body: bytes
    content_type: str = ""
    status: int = 200


@dataclass(frozen=True)
class MailboxScan:
    messages: tuple[MailboxMessage, ...]
    page_fingerprint: str
    fetched_at: float
    diagnostics: "MailboxScanDiagnostics" = field(default_factory=lambda: MailboxScanDiagnostics())

    @property
    def identities(self) -> frozenset[str]:
        return frozenset(message.identity for message in self.messages)


@dataclass(frozen=True)
class MailboxSelection:
    code: str
    identity: str
    received_at: str
    fingerprint: str
    scan: MailboxScan
    reason: str = ""


@dataclass(frozen=True)
class MailboxScanDiagnostics:
    listing_messages: int = 0
    detail_links: int = 0
    detail_refreshed: int = 0
    detail_cache_hits: int = 0
    detail_errors: int = 0
    refresh_error_code: str = ""
    refresh_http_status: int | None = None
    openai_messages: int = 0
    code_messages: int = 0
    otp_context_messages: int = 0
    explicit_code_messages: int = 0
    bare_code_messages: int = 0
    sender_mapped_messages: int = 0
    subject_mapped_messages: int = 0
    body_mapped_messages: int = 0
    received_mapped_messages: int = 0


def parse_mailbox_url_row(value: Any) -> MailboxUrlRow | None:
    raw = str(value or "").strip()
    match = _URL_ROW_PATTERN.fullmatch(raw)
    if not match:
        return None
    mailbox_url = match.group("url").strip()
    separator = match.group("separator")
    if "----" in mailbox_url:
        return None
    try:
        parsed = urllib.parse.urlsplit(mailbox_url)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return MailboxUrlRow(
        email=match.group("email").lower(),
        mailbox_url=mailbox_url,
        separator=separator,
    )


def masked_mailbox_url_row(value: Any, mask: str = "********") -> str:
    parsed = parse_mailbox_url_row(value)
    if parsed is None:
        return ""
    return parsed.separator.join((parsed.email, mask))


def select_latest_code(
    scan: MailboxScan,
    *,
    baseline_identities: Iterable[str] = (),
    requested_at: float | None = None,
    include_existing: bool = False,
    allow_recent_baseline: bool = False,
    recent_baseline_seconds: int = RECENT_BASELINE_CODE_WINDOW_SECONDS,
    allow_baseline_fallback: bool = False,
    baseline_fallback_reason: str = "mailbox_baseline_code_fallback",
) -> MailboxSelection:
    baseline = frozenset(baseline_identities)
    cutoff = None if requested_at is None else requested_at - REQUEST_CLOCK_SKEW_SECONDS
    candidates = []
    baseline_rejected = 0
    stale_rejected = 0
    for message in scan.messages:
        if not message.code:
            continue
        if not include_existing and message.identity in baseline:
            baseline_rejected += 1
            continue
        if cutoff is not None and message.received_timestamp is not None and message.received_timestamp < cutoff:
            stale_rejected += 1
            continue
        candidates.append(message)
    if candidates:
        selected = max(
            candidates,
            key=lambda message: (
                message.received_timestamp if message.received_timestamp is not None else float("-inf"),
                -message.order,
                message.identity,
            ),
        )
        fingerprint = _safe_identity(selected.identity, selected.received_at, selected.code)
        return MailboxSelection(
            selected.code,
            selected.identity,
            selected.received_at,
            fingerprint,
            scan,
            "code_found",
        )
    if allow_recent_baseline or allow_baseline_fallback:
        recent_window = max(1, int(recent_baseline_seconds))
        baseline_candidates = []
        for message in scan.messages:
            if not message.code or message.identity not in baseline:
                continue
            if not message.explicit_code and not _OPENAI_PATTERN.search(
                " ".join((message.sender, message.subject, message.body))
            ):
                continue
            if allow_recent_baseline or allow_baseline_fallback:
                if requested_at is not None and message.received_timestamp is not None:
                    age = float(requested_at) - float(message.received_timestamp)
                    if age < -REQUEST_CLOCK_SKEW_SECONDS or age > recent_window:
                        continue
                elif not allow_baseline_fallback:
                    continue
            baseline_candidates.append(message)
        if baseline_candidates:
            selected = max(
                baseline_candidates,
                key=lambda message: (
                    message.received_timestamp if message.received_timestamp is not None else float("-inf"),
                    -message.order,
                    message.identity,
                ),
            )
            fingerprint = _safe_identity(selected.identity, selected.received_at, selected.code)
            return MailboxSelection(
                selected.code,
                selected.identity,
                selected.received_at,
                fingerprint,
                scan,
                baseline_fallback_reason if allow_baseline_fallback else "mailbox_recent_baseline_code",
            )
    fingerprint = _safe_identity("empty", *sorted(scan.identities), scan.page_fingerprint)
    if scan.diagnostics.refresh_error_code:
        reason = "mailbox_refresh_request_failed"
    elif baseline_rejected and (
        scan.diagnostics.openai_messages
        or scan.diagnostics.explicit_code_messages
    ):
        reason = "mailbox_only_baseline_code"
    elif stale_rejected:
        reason = "mailbox_candidate_too_old"
    elif scan.diagnostics.detail_errors:
        reason = "mailbox_detail_request_failed"
    elif scan.diagnostics.detail_refreshed < scan.diagnostics.detail_links:
        reason = "mailbox_detail_refresh_pending"
    elif not scan.messages:
        reason = "mailbox_empty"
    elif scan.diagnostics.openai_messages:
        reason = "mailbox_openai_message_without_otp"
    else:
        reason = "mailbox_messages_without_openai_otp"
    return MailboxSelection("", "", "", fingerprint, scan, reason)


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        candidate = urllib.parse.urljoin(req.full_url, newurl)
        if not _same_origin(self.base_url, candidate):
            raise MailboxUrlError("mailbox_cross_origin_redirect", "邮箱取码地址跳转到了其他来源")
        return super().redirect_request(req, fp, code, msg, headers, candidate)


FetchFn = Callable[[str], MailboxResponse]
TimingFn = Callable[[str, int, str], Any]


class MailboxUrlClient:
    def __init__(
        self,
        mailbox_url: str,
        *,
        timeout_seconds: int = 15,
        proxy: str = "",
        fetcher: FetchFn | None = None,
        now_fn: Callable[[], float] = time.time,
        monotonic_fn: Callable[[], float] = time.monotonic,
        timing_fn: TimingFn | None = None,
    ) -> None:
        try:
            parsed = urllib.parse.urlsplit(str(mailbox_url or "").strip())
        except ValueError as exc:
            raise MailboxUrlError("mailbox_url_invalid", "邮箱取码地址不是完整的 HTTP(S) URL") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise MailboxUrlError("mailbox_url_invalid", "邮箱取码地址不是完整的 HTTP(S) URL")
        self.mailbox_url = urllib.parse.urlunsplit(parsed)
        self.timeout_seconds = max(3, min(int(timeout_seconds), 60))
        self.proxy = str(proxy or "").strip()
        self.fetcher = fetcher
        self.now_fn = now_fn
        self.monotonic_fn = monotonic_fn
        self.timing_fn = timing_fn
        self._detail_cache: dict[str, tuple[MailboxMessage, ...]] = {}
        self._detail_refresh_cursor = 0
        self._client_mailbox_api: _ClientMailboxApi | None = None
        self._client_mailbox_refresh_pending = False
        self._client_mailbox_refresh_forced = False
        self._client_mailbox_next_refresh_at = 0.0
        self._client_mailbox_request_started_at: float | None = None
        self._client_mailbox_deep_refresh_done = False
        self._client_mailbox_refresh_error_code = ""
        self._client_mailbox_refresh_http_status: int | None = None

    def _timing(self, code: str, started: float, outcome: str = "success") -> None:
        callback = self.timing_fn
        if not callable(callback):
            return
        try:
            callback(
                str(code or ""),
                max(0, int((self.monotonic_fn() - started) * 1000.0)),
                str(outcome or "success"),
            )
        except Exception:
            return

    def _request_client_mailbox_refresh(self, *, force: bool = False) -> None:
        self._client_mailbox_refresh_pending = True
        if force:
            self._client_mailbox_refresh_forced = True
            self._client_mailbox_request_started_at = float(self.now_fn())
            self._client_mailbox_deep_refresh_done = False
            self._clear_client_mailbox_refresh_error()

    def _clear_client_mailbox_refresh_error(self) -> None:
        self._client_mailbox_refresh_error_code = ""
        self._client_mailbox_refresh_http_status = None

    def _remember_client_mailbox_refresh_error(self, exc: MailboxUrlError) -> None:
        self._set_client_mailbox_refresh_error(
            str(getattr(exc, "code", "") or "mailbox_request_failed"),
            getattr(exc, "status", None),
        )

    def _set_client_mailbox_refresh_error(
        self,
        code: str,
        status: int | None = None,
    ) -> None:
        self._client_mailbox_refresh_error_code = str(code or "mailbox_request_failed")
        self._client_mailbox_refresh_http_status = (
            int(status)
            if isinstance(status, int) and not isinstance(status, bool)
            else None
        )

    def _finish_client_mailbox_request(self) -> None:
        self._client_mailbox_refresh_pending = False
        self._client_mailbox_refresh_forced = False
        self._client_mailbox_request_started_at = None
        self._client_mailbox_deep_refresh_done = False
        self._clear_client_mailbox_refresh_error()

    def _opener(self):
        handlers: list[Any] = [_SameOriginRedirectHandler(self.mailbox_url)]
        handlers.append(
            urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy} if self.proxy else {})
        )
        return urllib.request.build_opener(*handlers)

    def _fetch(self, url: str) -> MailboxResponse:
        if not _same_origin(self.mailbox_url, url):
            raise MailboxUrlError("mailbox_cross_origin_detail", "邮箱详情地址与取码入口来源不一致")
        if self.fetcher is not None:
            response = self.fetcher(url)
            if len(response.body) > MAX_RESPONSE_BYTES:
                raise MailboxUrlError("mailbox_response_too_large", "邮箱页面响应超过大小限制")
            if response.status < 200 or response.status >= 300:
                raise MailboxUrlError(
                    "mailbox_http_error",
                    f"邮箱取码请求返回 HTTP {response.status}",
                    status=response.status,
                )
            if not _same_origin(self.mailbox_url, response.url):
                raise MailboxUrlError("mailbox_cross_origin_redirect", "邮箱取码地址跳转到了其他来源")
            return response
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json,text/plain,text/html,*/*",
                "User-Agent": "gptphone-mailbox/1.0",
                "Cache-Control": "no-cache, no-store, max-age=0",
                "Pragma": "no-cache",
            },
            method="GET",
        )
        try:
            with self._opener().open(request, timeout=self.timeout_seconds) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                status = int(getattr(response, "status", response.getcode()))
                content_type = str(response.headers.get("Content-Type") or "")
                final_url = str(response.geturl() or url)
        except urllib.error.HTTPError as exc:
            raise MailboxUrlError(
                "mailbox_http_error",
                f"邮箱取码请求返回 HTTP {int(exc.code)}",
                status=int(exc.code),
            ) from exc
        except MailboxUrlError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise MailboxUrlError("mailbox_request_failed", "邮箱取码请求失败或超时") from exc
        if len(body) > MAX_RESPONSE_BYTES:
            raise MailboxUrlError("mailbox_response_too_large", "邮箱页面响应超过大小限制")
        if status < 200 or status >= 300:
            raise MailboxUrlError("mailbox_http_error", f"邮箱取码请求返回 HTTP {status}", status=status)
        if not _same_origin(self.mailbox_url, final_url):
            raise MailboxUrlError("mailbox_cross_origin_redirect", "邮箱取码地址跳转到了其他来源")
        return MailboxResponse(final_url, body, content_type, status)

    def scan(self) -> MailboxScan:
        client_api = self._client_mailbox_api
        response = self._fetch(client_api.cache_url if client_api is not None else self.mailbox_url)
        raw = _decode_bytes(response.body, response.content_type)
        if client_api is None:
            client_api = _client_mailbox_api_from_shell(response.url, raw)
            if client_api is not None:
                self._client_mailbox_api = client_api
                response = self._fetch(client_api.cache_url)
                raw = _decode_bytes(response.body, response.content_type)

        detail_request_errors = 0
        if client_api is not None:
            (
                messages,
                detail_urls,
                smtp_inbound,
                refreshing,
                cache_refresh_error_code,
                cache_refresh_http_status,
            ) = _parse_client_mailbox_payload(raw, client_api.payload_url)
            if cache_refresh_error_code:
                self._set_client_mailbox_refresh_error(
                    cache_refresh_error_code,
                    cache_refresh_http_status,
                )
        else:
            messages, detail_urls = parse_mailbox_payload(raw, response.url)
            smtp_inbound = False
            refreshing = False
        combined = list(messages)

        if client_api is not None:
            if smtp_inbound is True:
                self._client_mailbox_refresh_pending = False
                self._client_mailbox_refresh_forced = False
                self._clear_client_mailbox_refresh_error()
            elif self._client_mailbox_refresh_pending:
                now = float(self.now_fn())
                deep_due = (
                    self._client_mailbox_request_started_at is not None
                    and not self._client_mailbox_deep_refresh_done
                    and now - self._client_mailbox_request_started_at
                    >= _CLIENT_MAILBOX_DEEP_REFRESH_AFTER_SECONDS
                )
                regular_due = not refreshing and (
                    self._client_mailbox_refresh_forced
                    or now >= self._client_mailbox_next_refresh_at
                )
                if deep_due or regular_due:
                    self._client_mailbox_refresh_pending = False
                    self._client_mailbox_refresh_forced = False
                    self._client_mailbox_next_refresh_at = (
                        now + _CLIENT_MAILBOX_REFRESH_INTERVAL_SECONDS
                    )
                    refresh_url = (
                        client_api.deep_refresh_url
                        if deep_due
                        else client_api.refresh_url
                    )
                    if deep_due:
                        self._client_mailbox_deep_refresh_done = True
                    refresh_started = self.monotonic_fn()
                    try:
                        refresh_response = self._fetch(refresh_url)
                        refresh_raw = _decode_bytes(
                            refresh_response.body,
                            refresh_response.content_type,
                        )
                        (
                            _refresh_messages,
                            _refresh_detail_urls,
                            refresh_smtp_inbound,
                            _refreshing,
                            refresh_error_code,
                            refresh_http_status,
                        ) = _parse_client_mailbox_payload(
                            refresh_raw,
                            client_api.payload_url,
                            include_messages=False,
                        )
                    except MailboxUrlError as exc:
                        self._remember_client_mailbox_refresh_error(exc)
                        self._timing("mailbox_provider_refresh", refresh_started, "error")
                    else:
                        self._timing("mailbox_provider_refresh", refresh_started, "success")
                        if refresh_error_code:
                            self._set_client_mailbox_refresh_error(
                                refresh_error_code,
                                refresh_http_status,
                            )
                        elif not cache_refresh_error_code:
                            self._clear_client_mailbox_refresh_error()
                        if refresh_smtp_inbound is True:
                            self._client_mailbox_refresh_pending = False
                            self._client_mailbox_refresh_forced = False

        listing_messages = len(_merge_messages(combined))
        active_detail_urls = list(dict.fromkeys(detail_urls[:MAX_MESSAGES]))
        active_set = set(active_detail_urls)
        for stale_url in tuple(self._detail_cache):
            if stale_url not in active_set:
                self._detail_cache.pop(stale_url, None)

        uncached_urls = [url for url in active_detail_urls if url not in self._detail_cache]
        cached_urls = [url for url in active_detail_urls if url in self._detail_cache]
        refresh_urls: list[str] = []
        if cached_urls:
            start = self._detail_refresh_cursor % len(cached_urls)
            refresh_count = min(REFRESH_DETAIL_LIMIT, len(cached_urls))
            refresh_urls = [cached_urls[(start + offset) % len(cached_urls)] for offset in range(refresh_count)]
            self._detail_refresh_cursor = (start + refresh_count) % len(cached_urls)
        else:
            self._detail_refresh_cursor = (
                min(REFRESH_DETAIL_LIMIT, len(active_detail_urls)) % len(active_detail_urls)
                if active_detail_urls
                else 0
            )

        refreshed = 0
        detail_started = self.monotonic_fn()
        detail_outcome = "success"
        for detail_url in [*uncached_urls, *refresh_urls]:
            try:
                detail_response = self._fetch(detail_url)
                detail_raw = _decode_bytes(detail_response.body, detail_response.content_type)
                detail_messages, _unused_links = parse_mailbox_payload(detail_raw, detail_response.url)
            except MailboxUrlError:
                detail_request_errors += 1
                detail_outcome = "partial"
                continue
            self._detail_cache[detail_url] = detail_messages
            refreshed += 1
        if [*uncached_urls, *refresh_urls]:
            self._timing("mailbox_detail_refresh", detail_started, detail_outcome)
        for detail_url in active_detail_urls:
            combined.extend(self._detail_cache.get(detail_url, ()))
        merged = _merge_messages(combined)
        page_fingerprint = hashlib.sha256(response.body).hexdigest()
        openai_messages = sum(
            1
            for message in merged
            if _OPENAI_PATTERN.search(" ".join((message.sender, message.subject, message.body)))
        )
        code_messages = sum(1 for message in merged if message.code)
        diagnostics = MailboxScanDiagnostics(
            listing_messages=listing_messages,
            detail_links=len(active_detail_urls),
            detail_refreshed=refreshed,
            detail_cache_hits=sum(1 for url in active_detail_urls if url in self._detail_cache),
            detail_errors=detail_request_errors,
            refresh_error_code=self._client_mailbox_refresh_error_code,
            refresh_http_status=self._client_mailbox_refresh_http_status,
            openai_messages=openai_messages,
            code_messages=code_messages,
            otp_context_messages=sum(
                1 for message in merged if message.code_source == "otp_context"
            ),
            explicit_code_messages=sum(
                1 for message in merged if message.code_source == "explicit_code"
            ),
            bare_code_messages=sum(
                1 for message in merged if message.code_source == "bare_code"
            ),
            sender_mapped_messages=sum(
                1 for message in merged if "sender" in message.field_sources
            ),
            subject_mapped_messages=sum(
                1 for message in merged if "subject" in message.field_sources
            ),
            body_mapped_messages=sum(
                1 for message in merged if "body" in message.field_sources or "html" in message.field_sources or "scalar" in message.field_sources
            ),
            received_mapped_messages=sum(
                1 for message in merged if "received_at" in message.field_sources
            ),
        )
        return MailboxScan(merged, page_fingerprint, self.now_fn(), diagnostics)

    def latest_code(self, *, include_existing: bool = True) -> MailboxSelection:
        return select_latest_code(self.scan(), include_existing=include_existing)


try:
    from .mailbox_request_runtime import (
        MailboxRequestState,
        begin_runtime_request,
        configure_runtime_request,
        finish_runtime_request,
        final_runtime_baseline_fallback,
        runtime_diagnostic,
        runtime_snapshot,
    )
except ImportError:  # Loaded as a top-level runtime override.
    from mailbox_request_runtime import (  # type: ignore[no-redef]
        MailboxRequestState,
        begin_runtime_request,
        configure_runtime_request,
        finish_runtime_request,
        final_runtime_baseline_fallback,
        runtime_diagnostic,
        runtime_snapshot,
    )


__all__ = [
    "MAX_MESSAGES",
    "MAX_RESPONSE_BYTES",
    "REFRESH_DETAIL_LIMIT",
    "BASELINE_FALLBACK_MAX_ATTEMPTS",
    "RECENT_BASELINE_CODE_WINDOW_SECONDS",
    "MailboxMessage",
    "MailboxRequestState",
    "MailboxResponse",
    "MailboxScan",
    "MailboxScanDiagnostics",
    "MailboxSelection",
    "MailboxUrlClient",
    "MailboxUrlError",
    "TimingFn",
    "MailboxUrlRow",
    "begin_runtime_request",
    "configure_runtime_request",
    "decode_mail_body",
    "extract_openai_code",
    "finish_runtime_request",
    "final_runtime_baseline_fallback",
    "masked_mailbox_url_row",
    "parse_mailbox_payload",
    "parse_mailbox_url_row",
    "parse_received_timestamp",
    "runtime_snapshot",
    "runtime_diagnostic",
    "select_latest_code",
]
