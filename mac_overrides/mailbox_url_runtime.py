"""Generic, credential-safe mailbox URL parsing and OTP selection."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
import hashlib
from html import unescape
from html.parser import HTMLParser
import json
import re
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_MESSAGES = 40
REFRESH_DETAIL_LIMIT = 8
REQUEST_CLOCK_SKEW_SECONDS = 120
RECENT_BASELINE_CODE_WINDOW_SECONDS = 180
BASELINE_FALLBACK_MAX_ATTEMPTS = 2
_EMAIL_PATTERN = re.compile(
    r"(?i)[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
)
_URL_ROW_PATTERN = re.compile(
    r"^\s*(?P<email>[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})"
    r"\s*(?P<separator>-{3,}|\||｜)\s*(?P<url>https?://\S+)\s*$",
    re.IGNORECASE,
)
_OTP_CONTEXT = (
    r"verification|verify|security\s+code|login\s+code|sign[\s-]?in\s+code|"
    r"one[\s-]?time|otp|验证码|校验码|登录代码|临时代码|認証コード|ログインコード"
)
_OTP_COMPACT_PATTERNS = (
    re.compile(rf"(?is)(?:{_OTP_CONTEXT}).{{0,260}}?(?<!\d)(\d{{6}})(?!\d)"),
    re.compile(rf"(?is)(?<!\d)(\d{{6}})(?!\d).{{0,180}}?(?:{_OTP_CONTEXT})"),
)
_OTP_PATTERNS = (
    re.compile(
        rf"(?is)(?:{_OTP_CONTEXT}).{{0,260}}?(\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d)"
    ),
    re.compile(
        rf"(?is)(\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d).{{0,180}}?(?:{_OTP_CONTEXT})"
    ),
)
_DATE_TIME_FRAGMENT_RE = re.compile(
    r"^(?:\d{4}[-/]\d{2}|\d{2}[-/:]\d{2}[-/:]\d{2})$"
)
_EMBEDDED_DATETIME_RE = re.compile(
    r"(?<!\d)(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)(?!\d)"
)
_OPENAI_PATTERN = re.compile(r"(?i)open\s*ai|chat\s*gpt")
_ACTION_PATTERN = re.compile(
    r"(?i)(?:^|[/_.?&=-])(delete|remove|destroy|clear|trash|logout|unsubscribe)(?:$|[/_.?&=-])"
)
_MESSAGE_PATH_PATTERN = re.compile(r"(?i)(?:message|mail|inbox)")
_MESSAGE_ID_ATTRS = (
    "data-message-id",
    "data-messageid",
    "data-mail-id",
    "data-id",
    "message-id",
)
_DETAIL_URL_ATTRS = ("href", "data-url", "data-href", "data-detail-url")
_ID_KEYS = ("messageId", "message_id", "mailId", "mail_id", "id", "uid", "key")
_SENDER_KEYS = ("fromAddress", "from_address", "senderAddress", "sender", "from")
_SUBJECT_KEYS = ("subject", "title")
_RECEIVED_KEYS = (
    "receivedAt",
    "received_at",
    "received",
    "createdAt",
    "created_at",
    "timestamp",
    "date",
    "time",
)
_BODY_KEYS = (
    "textBody",
    "text_body",
    "htmlBody",
    "html_body",
    "body",
    "html",
    "text",
    "content",
)
_DETAIL_KEYS = ("detailUrl", "detail_url", "messageUrl", "message_url", "href", "url", "link")


class MailboxUrlError(RuntimeError):
    """An error whose message is safe to surface without the mailbox URL."""

    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


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
class MailboxMessage:
    identity: str
    sender: str = ""
    subject: str = ""
    received_at: str = ""
    received_timestamp: float | None = None
    body: str = ""
    detail_url: str = ""
    code: str = ""
    order: int = 0


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
    openai_messages: int = 0
    code_messages: int = 0


def parse_mailbox_url_row(value: Any) -> MailboxUrlRow | None:
    raw = str(value or "").strip()
    match = _URL_ROW_PATTERN.fullmatch(raw)
    if not match:
        return None
    mailbox_url = match.group("url").strip()
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
        separator=match.group("separator"),
    )


def masked_mailbox_url_row(value: Any, mask: str = "********") -> str:
    parsed = parse_mailbox_url_row(value)
    if parsed is None:
        return ""
    return parsed.separator.join((parsed.email, mask))


def _first(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value not in (None, ""):
            return value
    return ""


def _scalar_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, Mapping):
        parts = [_scalar_text(item) for item in value.values()]
        return "\n".join(part for part in parts if part)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        parts = [_scalar_text(item) for item in value]
        return "\n".join(part for part in parts if part)
    return ""


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth and data.strip():
            self.parts.append(data)


def _html_text(value: str) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(value)
    except Exception:
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unescape(value))).strip()
    return re.sub(r"\s+", " ", unescape(" ".join(parser.parts))).strip()


def _decode_bytes(value: bytes, content_type: str = "") -> str:
    charset_match = re.search(r"(?i)charset\s*=\s*[\"']?([^;\s\"']+)", content_type)
    charsets = [charset_match.group(1)] if charset_match else []
    charsets.extend(("utf-8-sig", "gb18030", "latin-1"))
    for charset in dict.fromkeys(charsets):
        try:
            return value.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
    return value.decode("utf-8", errors="replace")


def _decode_data_url(value: str) -> str:
    if not value.lower().startswith("data:") or "," not in value:
        return value
    header, payload = value.split(",", 1)
    try:
        raw = base64.b64decode(payload, validate=False) if ";base64" in header.lower() else urllib.parse.unquote_to_bytes(payload)
    except (ValueError, TypeError):
        return value
    return _decode_bytes(raw, header)


def _decode_possible_base64(value: str) -> str:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 24 or len(compact) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return value
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, TypeError):
        return value
    text = _decode_bytes(decoded)
    if "<" in text or _OPENAI_PATTERN.search(text) or any(pattern.search(text) for pattern in _OTP_PATTERNS):
        return text
    return value


def decode_mail_body(value: Any) -> str:
    text = _scalar_text(value).strip()
    if not text:
        return ""
    text = _decode_data_url(text)
    text = _decode_possible_base64(text)
    if "<" in text and ">" in text:
        text = _html_text(text)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def extract_openai_code(*values: Any) -> str:
    text = "\n".join(decode_mail_body(value) for value in values if value not in (None, ""))
    if not text or not _OPENAI_PATTERN.search(text):
        return ""
    for pattern in (*_OTP_COMPACT_PATTERNS, *_OTP_PATTERNS):
        for match in pattern.finditer(text):
            candidate = match.group(1).strip()
            if _DATE_TIME_FRAGMENT_RE.fullmatch(candidate):
                continue
            digits = re.sub(r"\D", "", candidate)
            if len(digits) == 6:
                return digits
    return ""


def parse_received_timestamp(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 10_000_000_000:
            timestamp /= 1000
        return timestamp if timestamp > 0 else None
    text = str(value or "").strip()
    if not text:
        return None
    if re.fullmatch(r"\d{10,13}(?:\.\d+)?", text):
        return parse_received_timestamp(float(text))
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError, OverflowError):
            for pattern in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M"):
                try:
                    parsed = datetime.strptime(text, pattern)
                    break
                except ValueError:
                    continue
    if parsed is None:
        embedded = _EMBEDDED_DATETIME_RE.search(text)
        if embedded is not None and embedded.group(1) != text:
            return parse_received_timestamp(embedded.group(1))
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
    try:
        return parsed.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


def _safe_identity(*values: Any) -> str:
    material = "\x1f".join(str(value or "") for value in values)
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def _same_origin(base_url: str, candidate_url: str) -> bool:
    try:
        return _origin(base_url) == _origin(candidate_url)
    except ValueError:
        return False


def _safe_detail_url(base_url: str, value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or raw.startswith(("#", "javascript:", "mailto:", "data:")):
        return ""
    candidate = urllib.parse.urljoin(base_url, raw)
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    if not _same_origin(base_url, candidate) or _ACTION_PATTERN.search(candidate):
        return ""
    return candidate


def _message_from_mapping(value: Mapping[str, Any], source_url: str, order: int) -> MailboxMessage | None:
    message_id = _scalar_text(_first(value, _ID_KEYS)).strip()
    sender = decode_mail_body(_first(value, _SENDER_KEYS))
    subject = decode_mail_body(_first(value, _SUBJECT_KEYS))
    received_value = _first(value, _RECEIVED_KEYS)
    received_at = _scalar_text(received_value).strip()
    body_values = [value[key] for key in _BODY_KEYS if key in value and value[key] not in (None, "")]
    body = " ".join(part for part in (decode_mail_body(item) for item in body_values) if part)
    detail_url = _safe_detail_url(source_url, _first(value, _DETAIL_KEYS))
    code = extract_openai_code(sender, subject, body)
    if not any((message_id, sender, subject, received_at, body, detail_url)):
        return None
    if message_id or detail_url:
        identity = _safe_identity(
            message_id or detail_url,
            received_at,
            sender,
            subject,
            body,
            code,
        )
    elif received_at:
        identity = _safe_identity(source_url, received_at, sender, subject)
    else:
        identity = _safe_identity(source_url, sender, subject, body)
    return MailboxMessage(
        identity=identity,
        sender=sender,
        subject=subject,
        received_at=received_at,
        received_timestamp=(
            parse_received_timestamp(received_value)
            or parse_received_timestamp(" ".join((subject, body)))
        ),
        body=body,
        detail_url=detail_url,
        code=code,
        order=order,
    )


def _walk_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            yield from _walk_mappings(child)


@dataclass
class _HtmlFrame:
    tag: str
    attrs: dict[str, str]
    parts: list[str] = field(default_factory=list)


class _MailboxHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.frames: list[_HtmlFrame] = []
        self.candidates: list[tuple[dict[str, str], str]] = []
        self.json_scripts: list[str] = []
        self._script_parts: list[str] | None = None
        self._script_is_json = False
        self.all_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {str(key).lower(): str(value or "") for key, value in attrs}
        lowered = " ".join((values.get("class", ""), values.get("id", ""))).lower()
        has_message_attr = any(values.get(key) for key in _MESSAGE_ID_ATTRS + _DETAIL_URL_ATTRS)
        if tag.lower() in {"a", "article", "li", "tr", "button"} or has_message_attr or _MESSAGE_PATH_PATTERN.search(lowered):
            self.frames.append(_HtmlFrame(tag.lower(), values))
        if tag.lower() == "script":
            self._script_parts = []
            script_type = values.get("type", "").lower()
            self._script_is_json = "json" in script_type

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered == "script" and self._script_parts is not None:
            script = "".join(self._script_parts).strip()
            if script and (self._script_is_json or script[:1] in "{["):
                self.json_scripts.append(script)
            self._script_parts = None
            self._script_is_json = False
        for index in range(len(self.frames) - 1, -1, -1):
            frame = self.frames[index]
            if frame.tag == lowered:
                self.frames.pop(index)
                self.candidates.append((frame.attrs, " ".join(frame.parts)))
                break

    def handle_data(self, data: str) -> None:
        if self._script_parts is not None:
            self._script_parts.append(data)
            return
        if data.strip():
            self.all_text.append(data)
            for frame in self.frames:
                frame.parts.append(data)


def _inferred_detail_urls(page_url: str, source: str, message_ids: Iterable[str]) -> list[str]:
    parsed = urllib.parse.urlsplit(page_url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    inbox_index = next((index for index, segment in enumerate(segments) if segment.lower() == "messages"), None)
    if inbox_index is None:
        return []
    source_lower = source.lower()
    if "/message/" not in source_lower and "message" not in source_lower:
        return []
    result = []
    for message_id in message_ids:
        if not re.fullmatch(r"[A-Za-z0-9._~-]{1,160}", message_id):
            continue
        detail_segments = list(segments)
        detail_segments[inbox_index] = "message"
        detail_segments.insert(inbox_index + 1, urllib.parse.quote(message_id, safe="._~-"))
        path = "/" + "/".join(detail_segments)
        candidate = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        if _safe_detail_url(page_url, candidate):
            result.append(candidate)
    return result


def _parse_html_messages(raw: str, source_url: str, start_order: int = 0) -> tuple[list[MailboxMessage], list[str]]:
    parser = _MailboxHtmlParser()
    try:
        parser.feed(raw)
    except Exception:
        pass
    messages: list[MailboxMessage] = []
    detail_urls: list[str] = []
    message_ids: list[str] = []
    order = start_order
    for attrs, candidate_text in parser.candidates:
        message_id = next((attrs.get(key, "").strip() for key in _MESSAGE_ID_ATTRS if attrs.get(key)), "")
        detail_url = next((_safe_detail_url(source_url, attrs.get(key)) for key in _DETAIL_URL_ATTRS if attrs.get(key)), "")
        received_at = next((attrs.get(key, "") for key in ("datetime", "data-received-at", "data-date", "data-time") if attrs.get(key)), "")
        text = decode_mail_body(candidate_text)
        if message_id:
            message_ids.append(message_id)
        if detail_url and (_MESSAGE_PATH_PATTERN.search(urllib.parse.urlsplit(detail_url).path) or message_id):
            detail_urls.append(detail_url)
        if not any((message_id, detail_url, text, received_at)):
            continue
        sender_match = _EMAIL_PATTERN.search(text)
        identity_source = message_id or detail_url or text
        messages.append(
            MailboxMessage(
                identity=_safe_identity(identity_source, received_at),
                sender=sender_match.group(0) if sender_match else "",
                subject=text[:500],
                received_at=received_at,
                received_timestamp=parse_received_timestamp(received_at or text),
                body=text,
                detail_url=detail_url,
                code=extract_openai_code(text),
                order=order,
            )
        )
        order += 1
    for script in parser.json_scripts:
        try:
            parsed = json.loads(script)
        except (TypeError, ValueError):
            continue
        for mapping in _walk_mappings(parsed):
            message = _message_from_mapping(mapping, source_url, order)
            if message:
                messages.append(message)
                order += 1
                if message.detail_url:
                    detail_urls.append(message.detail_url)
    detail_urls.extend(_inferred_detail_urls(source_url, raw, message_ids))
    visible = decode_mail_body(" ".join(parser.all_text))
    if visible:
        visible_code = extract_openai_code(visible)
        messages.append(
            MailboxMessage(
                identity=_safe_identity(source_url, visible),
                subject=visible[:500],
                body=visible,
                code=visible_code,
                order=order,
            )
        )
    return messages, list(dict.fromkeys(url for url in detail_urls if url))


def _merge_messages(messages: Iterable[MailboxMessage]) -> tuple[MailboxMessage, ...]:
    merged: dict[str, MailboxMessage] = {}
    for message in messages:
        previous = merged.get(message.identity)
        if previous is None or (message.code and not previous.code) or len(message.body) > len(previous.body):
            merged[message.identity] = message
    ordered = sorted(merged.values(), key=lambda message: message.order)
    with_code = [message for message in ordered if message.code]
    without_code = [message for message in ordered if not message.code]
    return tuple((with_code + without_code)[:MAX_MESSAGES])


def parse_mailbox_payload(raw: str, source_url: str) -> tuple[tuple[MailboxMessage, ...], tuple[str, ...]]:
    messages: list[MailboxMessage] = []
    detail_urls: list[str] = []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        parsed = None
    if parsed is not None:
        order = 0
        for mapping in _walk_mappings(parsed):
            message = _message_from_mapping(mapping, source_url, order)
            if message:
                messages.append(message)
                order += 1
                if message.detail_url:
                    detail_urls.append(message.detail_url)
    else:
        messages, detail_urls = _parse_html_messages(raw, source_url)
    return _merge_messages(messages), tuple(dict.fromkeys(detail_urls[:MAX_MESSAGES]))


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
            if not _OPENAI_PATTERN.search(" ".join((message.sender, message.subject, message.body))):
                continue
            if allow_recent_baseline and not allow_baseline_fallback:
                if requested_at is None or message.received_timestamp is None:
                    continue
                age = float(requested_at) - float(message.received_timestamp)
                if age < 0 or age > recent_window:
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
    if baseline_rejected:
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


class MailboxUrlClient:
    def __init__(
        self,
        mailbox_url: str,
        *,
        timeout_seconds: int = 15,
        proxy: str = "",
        fetcher: FetchFn | None = None,
        now_fn: Callable[[], float] = time.time,
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
        self._detail_cache: dict[str, tuple[MailboxMessage, ...]] = {}
        self._detail_refresh_cursor = 0

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
        response = self._fetch(self.mailbox_url)
        raw = _decode_bytes(response.body, response.content_type)
        messages, detail_urls = parse_mailbox_payload(raw, response.url)
        combined = list(messages)
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

        detail_errors = 0
        refreshed = 0
        for detail_url in [*uncached_urls, *refresh_urls]:
            try:
                detail_response = self._fetch(detail_url)
                detail_raw = _decode_bytes(detail_response.body, detail_response.content_type)
                detail_messages, _unused_links = parse_mailbox_payload(detail_raw, detail_response.url)
            except MailboxUrlError:
                detail_errors += 1
                continue
            self._detail_cache[detail_url] = detail_messages
            refreshed += 1
        for detail_url in active_detail_urls:
            combined.extend(self._detail_cache.get(detail_url, ()))
        merged = _merge_messages(combined)
        page_fingerprint = hashlib.sha256(response.body).hexdigest()
        openai_messages = sum(
            1
            for message in merged
            if _OPENAI_PATTERN.search(" ".join((message.sender, message.subject, message.body)))
        )
        diagnostics = MailboxScanDiagnostics(
            listing_messages=len(messages),
            detail_links=len(active_detail_urls),
            detail_refreshed=refreshed,
            detail_cache_hits=sum(1 for url in active_detail_urls if url in self._detail_cache),
            detail_errors=detail_errors,
            openai_messages=openai_messages,
            code_messages=sum(1 for message in merged if message.code),
        )
        return MailboxScan(merged, page_fingerprint, self.now_fn(), diagnostics)

    def latest_code(self, *, include_existing: bool = True) -> MailboxSelection:
        return select_latest_code(self.scan(), include_existing=include_existing)


class MailboxRequestState:
    def __init__(self, client: MailboxUrlClient, *, now_fn: Callable[[], float] = time.time) -> None:
        self.client = client
        self.now_fn = now_fn
        self.last_scan: MailboxScan | None = None
        self.last_selection: MailboxSelection | None = None
        self.baseline_identities: frozenset[str] = frozenset()
        self.requested_at: float | None = None
        self.active = False
        self.max_poll_attempts = 30
        self.poll_attempt = 0
        self.baseline_fallback_attempts = 0
        self.baseline_fallback_age_seconds: int | None = None
        self.baseline_fallback_poll: int | None = None

    def configure_request(self, *, max_poll_attempts: int) -> None:
        self.max_poll_attempts = max(1, int(max_poll_attempts))

    def begin_request(self) -> None:
        if self.active:
            return
        self.baseline_identities = self.last_scan.identities if self.last_scan is not None else frozenset()
        self.requested_at = self.now_fn()
        self.active = True
        self.poll_attempt = 0
        self.baseline_fallback_age_seconds = None
        self.baseline_fallback_poll = None

    def _baseline_fallback(
        self,
        scan: MailboxScan,
        *,
        reason: str,
    ) -> MailboxSelection | None:
        if self.baseline_fallback_attempts >= BASELINE_FALLBACK_MAX_ATTEMPTS:
            return None
        fallback = select_latest_code(
            scan,
            baseline_identities=self.baseline_identities,
            requested_at=self.requested_at,
            allow_baseline_fallback=True,
            baseline_fallback_reason=reason,
        )
        if not fallback.code:
            return None
        self.baseline_fallback_attempts += 1
        self.baseline_fallback_poll = self.poll_attempt
        matched = next(
            (message for message in scan.messages if message.identity == fallback.identity),
            None,
        )
        if (
            matched is not None
            and matched.received_timestamp is not None
            and self.requested_at is not None
        ):
            self.baseline_fallback_age_seconds = max(
                0,
                int(self.requested_at - matched.received_timestamp),
            )
        self.last_selection = fallback
        return fallback

    def snapshot(self) -> MailboxSelection:
        scan = self.client.scan()
        if self.active:
            self.poll_attempt += 1
        self.last_scan = scan
        self.last_selection = select_latest_code(
            scan,
            baseline_identities=self.baseline_identities,
            requested_at=self.requested_at,
            include_existing=not self.active,
        )
        if (
            self.active
            and self.baseline_fallback_attempts == 0
            and not self.last_selection.code
            and self.poll_attempt >= max(1, (self.max_poll_attempts * 2 + 2) // 3)
        ):
            self._baseline_fallback(scan, reason="mailbox_baseline_code_fallback")
        return self.last_selection

    def final_baseline_fallback(self) -> MailboxSelection:
        scan = self.client.scan()
        self.last_scan = scan
        self.last_selection = select_latest_code(
            scan,
            baseline_identities=self.baseline_identities,
            requested_at=self.requested_at,
            include_existing=not self.active,
        )
        if self.last_selection.code:
            return self.last_selection
        fallback = self._baseline_fallback(
            scan,
            reason="mailbox_final_baseline_code_fallback",
        )
        return fallback or self.last_selection

    def finish_request(self) -> None:
        if self.last_scan is not None:
            self.baseline_identities = self.last_scan.identities
        self.active = False
        self.requested_at = None


def _runtime_state(provider: Any) -> MailboxRequestState:
    state = getattr(provider, "_generic_mailbox_state", None)
    if isinstance(state, MailboxRequestState):
        return state
    client = MailboxUrlClient(
        getattr(provider, "mailbox_url", ""),
        timeout_seconds=getattr(provider, "timeout_seconds", 15),
        proxy=getattr(provider, "proxy", ""),
    )
    state = MailboxRequestState(client)
    setattr(provider, "_generic_mailbox_state", state)
    return state


def runtime_snapshot(provider: Any) -> MailboxSelection:
    return _runtime_state(provider).snapshot()


def begin_runtime_request(provider: Any) -> None:
    _runtime_state(provider).begin_request()


def configure_runtime_request(provider: Any, *, max_poll_attempts: int) -> None:
    _runtime_state(provider).configure_request(max_poll_attempts=max_poll_attempts)


def final_runtime_baseline_fallback(provider: Any) -> MailboxSelection:
    return _runtime_state(provider).final_baseline_fallback()


def finish_runtime_request(provider: Any) -> None:
    state = getattr(provider, "_generic_mailbox_state", None)
    if isinstance(state, MailboxRequestState):
        state.finish_request()


def runtime_diagnostic(provider: Any) -> dict[str, Any]:
    state = getattr(provider, "_generic_mailbox_state", None)
    if not isinstance(state, MailboxRequestState) or state.last_selection is None:
        return {}
    diagnostics = state.last_selection.scan.diagnostics
    return {
        "reason": state.last_selection.reason,
        "baseline_fallback_attempts": int(state.baseline_fallback_attempts),
        "baseline_fallback_age_seconds": state.baseline_fallback_age_seconds,
        "baseline_fallback_poll": state.baseline_fallback_poll,
        "max_poll_attempts": int(state.max_poll_attempts),
        "listing_messages": diagnostics.listing_messages,
        "detail_links": diagnostics.detail_links,
        "detail_refreshed": diagnostics.detail_refreshed,
        "detail_refresh_pending": max(
            diagnostics.detail_links - diagnostics.detail_refreshed,
            0,
        ),
        "detail_errors": diagnostics.detail_errors,
        "openai_messages": diagnostics.openai_messages,
        "code_messages": diagnostics.code_messages,
    }


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
