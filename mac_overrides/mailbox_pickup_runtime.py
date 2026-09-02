"""Safe discovery of dynamic mailbox pickup pages and same-origin APIs.

The URL mailbox parser owns message normalization and OTP extraction.  This
module owns only the transport-facing details for providers whose public page
is a JavaScript shell (``/latest`` or ``/pickup``).  Keeping endpoint
discovery here makes it harder for parsing changes to accidentally broaden
the set of URLs the mailbox client may request.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
import hashlib
from html import unescape
from html.parser import HTMLParser
import json
import re
from typing import Any, Callable, Iterable, Mapping, Pattern, Sequence
import urllib.parse

try:
    from .mailbox_code_parser import (
        OPENAI_PATTERN as _OPENAI_PATTERN,
        decode_bytes as _decode_bytes,
        decode_mail_body as _decode_mail_body,
        extract_mailbox_code,
    )
    from .mailbox_api798 import (
        allows_bare_code as _allows_bare_code,
        api798_embedded_html as _api798_embedded_html,
        api798_get_code_response as _api798_get_code_response,
        api798_received_at as _api798_received_at,
        mailbox_provider_strategy as _mailbox_provider_strategy,
    )
    from .mail_code_envelope import parse_mail_code_envelope
except ImportError:
    from mailbox_code_parser import (  # type: ignore[no-redef]
        OPENAI_PATTERN as _OPENAI_PATTERN,
        decode_bytes as _decode_bytes,
        decode_mail_body as _decode_mail_body,
        extract_mailbox_code,
    )
    from mailbox_api798 import (  # type: ignore[no-redef]
        allows_bare_code as _allows_bare_code,
        api798_embedded_html as _api798_embedded_html,
        api798_get_code_response as _api798_get_code_response,
        api798_received_at as _api798_received_at,
        mailbox_provider_strategy as _mailbox_provider_strategy,
    )
    from mail_code_envelope import parse_mail_code_envelope


_EMAIL_PATTERN = re.compile(
    r"(?i)[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
)
_ACTION_PATTERN = re.compile(
    r"(?i)(?:^|[/_.?&=-])(delete|remove|destroy|clear|trash|logout|unsubscribe)(?:$|[/_.?&=-])"
)
_SHELL_PATHS = frozenset({"/latest", "/pickup"})
_SHELL_MARKERS = (
    "weimail_customer.js",
    'id="mail-address"',
    'id="message-list"',
    'id="code-box"',
)
_PICKUP_MARKERS = ("/api/messages", "/api/message/")
# The pickup page may append the query with URLSearchParams instead of
# embedding a literal ``?``.  Match only a relative path boundary so an
# absolute third-party URL is never treated as a provider endpoint.
_PICKUP_SCRIPT_MARKER = re.compile(r"(?i)(?<![a-z0-9_.-])/api/messages(?![a-z0-9_.-])")
_EMAIL_QUERY_KEYS = ("email", "mail")
_AUTH_QUERY_KEYS = ("auth_code", "code", "key")
_AUTH_MAX_LENGTH = 512
MAX_MESSAGES = 40
MAX_PARSED_MESSAGES = MAX_MESSAGES * 4
MAX_JSON_DEPTH = 64
MAX_JSON_CONTAINER_NODES = 4096
_MESSAGE_PATH_PATTERN = re.compile(r"(?i)(?:message|mail|inbox)")
_MESSAGE_ID_ATTRS = ("data-message-id", "data-messageid", "data-mail-id", "data-id", "message-id")
_DETAIL_URL_ATTRS = ("href", "data-url", "data-href", "data-detail-url")
_ID_KEYS = ("messageId", "message_id", "mailId", "mail_id", "id", "uid", "key")
_SENDER_KEYS = (
    "fromAddress", "from_address", "senderAddress", "sender_address", "fromEmail", "from_email",
    "emailFrom", "email_from", "mailFrom", "senderEmail", "sender_email", "sendEmail", "send_email",
    "from_mail", "fromMail", "fromName", "from_name", "sendName", "send_name", "senderName", "sender_name",
    "sender", "from",
)
_SUBJECT_KEYS = (
    "subject", "mailSubject", "mail_subject", "mailTitle", "mail_title", "subjectLine", "subject_line",
    "title", "topic",
)
_RECEIVED_KEYS = (
    "receivedAt", "received_at", "received", "createdAt", "created_at", "timestamp", "received_time",
    "sentAt", "sent_at", "sentTime", "sent_time", "sendAt", "send_at", "sendTime", "send_time",
    "deliveredAt", "delivered_at", "mailTime", "mail_time", "date", "time",
)
_BODY_KEYS = (
    "textBody", "text_body", "htmlBody", "html_body", "body", "bodyHtml", "body_html", "bodyText",
    "body_text", "bodyPreview", "body_preview", "previewText", "preview_text", "html", "text", "content",
    "contentHtml", "content_html", "contentText", "content_text", "message", "msg", "snippet", "preview",
    "contentPreview", "content_preview", "bodyContent", "body_content", "description", "payload",
)
_DETAIL_KEYS = ("detailUrl", "detail_url", "messageUrl", "message_url", "href", "url", "link")
_EXPLICIT_CODE_KEYS = (
    "verification_code", "verificationCode", "otp_code", "otpCode", "one_time_code", "oneTimeCode",
    "security_code", "securityCode", "login_code", "loginCode", "passcode", "otp", "code", "codes",
)
_EMBEDDED_DATETIME_RE = re.compile(
    r"(?<!\d)(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)(?!\d)"
)
_CHINESE_DATETIME_RE = re.compile(
    r"(?<!\d)(\d{4}年\d{1,2}月\d{1,2}日\s+\d{1,2}:\d{2}(?::\d{2})?)(?!\d)"
)


class MailboxUrlError(RuntimeError):
    """An error whose message is safe to surface without the mailbox URL."""

    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


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
    code_source: str = ""
    order: int = 0
    explicit_code: bool = False
    field_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClientMailboxApi:
    """Same-origin endpoints derived from a dynamic mailbox shell."""

    payload_url: str
    cache_url: str
    refresh_url: str
    deep_refresh_url: str
    detail_url_template: str = ""


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def same_origin(base_url: str, candidate_url: str) -> bool:
    """Return whether two HTTP URLs share scheme, hostname and port."""
    try:
        return _origin(base_url) == _origin(candidate_url)
    except (TypeError, ValueError):
        return False


def safe_detail_url(base_url: str, value: Any) -> str:
    """Resolve a message link without allowing actions or cross-origin hops."""
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
    if not same_origin(base_url, candidate) or _ACTION_PATTERN.search(candidate):
        return ""
    return candidate


def _scalar_text(value: Any) -> str:
    """Flatten an endpoint id/query value without accepting control bytes."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, Mapping):
        return "\n".join(_scalar_text(item) for item in value.values() if item not in (None, ""))
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return "\n".join(_scalar_text(item) for item in value if item not in (None, ""))
    return ""


def client_mailbox_detail_url(source_url: str, message_id: Any) -> str:
    """Build the provider's same-origin detail endpoint from a listing id."""
    candidate_id = _scalar_text(message_id).strip()
    if not candidate_id or len(candidate_id) > 256:
        return ""
    if any(ord(character) < 32 or ord(character) == 127 for character in candidate_id):
        return ""
    try:
        parsed = urllib.parse.urlsplit(source_url)
    except ValueError:
        return ""
    if parsed.path.rstrip("/").casefold() != "/api/messages":
        return ""
    try:
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=16)
    except ValueError:
        return ""
    safe_query = [
        (key, value)
        for key, value in query
        if key.casefold() in {"email", "key", "auth_code", "code"}
    ]
    candidate = urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        "/api/message/" + urllib.parse.quote(candidate_id, safe="._~-%"),
        urllib.parse.urlencode(safe_query),
        "",
    ))
    return candidate if same_origin(source_url, candidate) else ""


def _first_query_value(params: Mapping[str, Sequence[str]], keys: Sequence[str]) -> str:
    for key in keys:
        values = params.get(key) or ()
        candidate = str(values[0] if values else "").strip()
        if candidate:
            return candidate
    return ""


def client_mailbox_api_from_shell(
    page_url: str,
    raw: str,
    *,
    email_pattern: Pattern[str] | None = None,
) -> ClientMailboxApi | None:
    """Discover only fixed, same-origin APIs advertised by a mailbox shell."""
    try:
        parsed = urllib.parse.urlsplit(page_url)
    except ValueError:
        return None
    shell_path = parsed.path.rstrip("/") or "/"
    if shell_path not in _SHELL_PATHS:
        return None
    lowered = raw.lower()
    if shell_path == "/pickup":
        if not _PICKUP_SCRIPT_MARKER.search(lowered):
            return None
    elif not all(marker in lowered for marker in _SHELL_MARKERS):
        return None
    try:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, max_num_fields=32)
    except ValueError:
        return None
    email = _first_query_value(params, _EMAIL_QUERY_KEYS)
    auth_code = _first_query_value(params, _AUTH_QUERY_KEYS)
    matcher = email_pattern or _EMAIL_PATTERN
    if not matcher.fullmatch(email):
        return None
    if (
        not auth_code
        or len(auth_code) > _AUTH_MAX_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in auth_code)
    ):
        return None
    if shell_path == "/pickup":
        common_query = (("email", email), ("key", auth_code))
        cache_url = urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            "/api/messages",
            urllib.parse.urlencode((*common_query, ("force", "0"))),
            "",
        ))
        refresh_url = urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            "/api/messages",
            urllib.parse.urlencode((*common_query, ("force", "1"))),
            "",
        ))
        detail_url_template = urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            "/api/message/{message_id}",
            urllib.parse.urlencode(common_query),
            "",
        ))
        candidates = (cache_url, refresh_url, detail_url_template)
        if not all(same_origin(page_url, candidate) for candidate in candidates):
            return None
        return ClientMailboxApi(
            payload_url=cache_url,
            cache_url=cache_url,
            refresh_url=refresh_url,
            deep_refresh_url=refresh_url,
            detail_url_template=detail_url_template,
        )
    api_path = "/mail-api/{}/{}".format(
        urllib.parse.quote(auth_code, safe=""),
        urllib.parse.quote(email, safe=""),
    )
    payload_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, api_path, "", ""))
    cache_url = urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        api_path,
        urllib.parse.urlencode((("folder", "inbox"), ("cache_first", "1"))),
        "",
    ))
    refresh_url = urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        api_path,
        urllib.parse.urlencode((("folder", "inbox"), ("refresh", "1"), ("async", "1"))),
        "",
    ))
    deep_refresh_url = urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        api_path,
        urllib.parse.urlencode((("folder", "inbox"), ("refresh", "1"), ("async", "1"), ("deep", "1"))),
        "",
    ))
    if not all(same_origin(page_url, candidate) for candidate in (cache_url, refresh_url, deep_refresh_url)):
        return None
    return ClientMailboxApi(
        payload_url=payload_url,
        cache_url=cache_url,
        refresh_url=refresh_url,
        deep_refresh_url=deep_refresh_url,
    )


def _response_too_complex() -> MailboxUrlError:
    return MailboxUrlError("mailbox_provider_response_too_complex", "邮箱取码响应结构超过复杂度限制")


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


def _values_for_keys(mapping: Mapping[str, Any], keys: Sequence[str]) -> list[Any]:
    wanted = {str(key).casefold() for key in keys}
    return [value for key, value in mapping.items() if str(key).casefold() in wanted and value not in (None, "")]


def _strict_explicit_code(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    candidate = str(value).strip()
    return candidate if re.fullmatch(r"\d{6}", candidate) else ""


def _explicit_code_from_mapping(mapping: Mapping[str, Any]) -> str:
    for value in _values_for_keys(mapping, _EXPLICIT_CODE_KEYS):
        direct = _strict_explicit_code(value)
        if direct:
            return direct
        if isinstance(value, Mapping):
            nested = _explicit_code_from_mapping(value)
            if nested:
                return nested
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                direct = _strict_explicit_code(item)
                if direct:
                    return direct
                if isinstance(item, Mapping):
                    nested = _explicit_code_from_mapping(item)
                    if nested:
                        return nested
    return ""


def _trusted_otp_source(source_url: str) -> bool: return bool(_mailbox_provider_strategy(source_url))
def _safe_http_status(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 599 else None


def _scalar_text(value: Any) -> str:
    parts: list[str] = []
    stack: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_CONTAINER_NODES or depth > MAX_JSON_DEPTH:
            raise _response_too_complex()
        if isinstance(current, str):
            parts.append(current)
            continue
        if isinstance(current, (int, float)):
            parts.append(str(current))
            continue
        if isinstance(current, Mapping):
            values = current.values()
        elif isinstance(current, Sequence) and not isinstance(current, (bytes, bytearray, str)):
            values = current
        else:
            continue
        children: list[tuple[Any, int]] = []
        for child in values:
            if visited + len(stack) + len(children) >= MAX_JSON_CONTAINER_NODES:
                raise _response_too_complex()
            children.append((child, depth + 1))
        stack.extend(reversed(children))
    return "\n".join(part for part in parts if part)


def decode_mail_body(value: Any) -> str:
    return _decode_mail_body(value, scalar_text=_scalar_text)


def extract_openai_code(*values: Any, source_url: str = "", allow_bare_code: bool = False) -> str:
    return extract_mailbox_code(
        *values,
        decoder=decode_mail_body,
        allow_bare_code=allow_bare_code or _allows_bare_code(source_url),
    ).code


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
            for pattern in (
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y年%m月%d日 %H:%M:%S",
                "%Y年%m月%d日 %H:%M",
            ):
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
        chinese = _CHINESE_DATETIME_RE.search(text)
        if chinese is not None and chinese.group(1) != text:
            return parse_received_timestamp(chinese.group(1))
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


def _message_from_mapping(
    value: Mapping[str, Any], source_url: str, order: int, *,
    trust_explicit_code: bool = False,
    allow_bare_code: bool | None = None,
) -> MailboxMessage | None:
    message_id = _scalar_text(_first(value, _ID_KEYS)).strip()
    sender = decode_mail_body(_first(value, _SENDER_KEYS))
    subject = decode_mail_body(_first(value, _SUBJECT_KEYS))
    received_value = _first(value, _RECEIVED_KEYS)
    received_at = _scalar_text(received_value).strip()
    body = " ".join(part for part in (decode_mail_body(item) for item in _values_for_keys(value, _BODY_KEYS)) if part)
    detail_url = safe_detail_url(source_url, _first(value, _DETAIL_KEYS))
    if not detail_url:
        detail_url = client_mailbox_detail_url(source_url, _first(value, _ID_KEYS))
    trusted_source = trust_explicit_code or _trusted_otp_source(source_url)
    explicit_code = _explicit_code_from_mapping(value) if trusted_source else ""
    bare_code_allowed = (
        _trusted_otp_source(source_url)
        if allow_bare_code is None
        else bool(allow_bare_code)
    )
    code_match = extract_mailbox_code(
        sender,
        subject,
        body,
        decoder=decode_mail_body,
        allow_bare_code=bare_code_allowed,
    )
    code = explicit_code or code_match.code
    if not any((message_id, sender, subject, received_at, body, detail_url, code)):
        return None
    if message_id or detail_url:
        identity = _safe_identity(message_id or detail_url, received_at, sender, subject, body, code)
    elif received_at:
        identity = _safe_identity(source_url, received_at, sender, subject)
    else:
        identity = _safe_identity(source_url, sender, subject, body)
    if explicit_code:
        identity = _safe_identity(identity, received_at, explicit_code)
    return MailboxMessage(
        identity=identity,
        sender=sender,
        subject=subject,
        received_at=received_at,
        received_timestamp=parse_received_timestamp(received_value) or parse_received_timestamp(" ".join((subject, body))),
        body=body,
        detail_url=detail_url,
        code=code,
        code_source="explicit_code" if explicit_code else code_match.source,
        order=order,
        explicit_code=bool(explicit_code),
        field_sources=tuple(source for source, present in (
            ("sender", bool(sender)), ("subject", bool(subject)), ("received_at", bool(received_at)),
            ("body", bool(body)), ("detail_url", bool(detail_url)),
        ) if present),
    )


def _message_from_scalar(value: Any, source_url: str, order: int) -> MailboxMessage | None:
    text = decode_mail_body(value)
    if not text:
        return None
    match = extract_mailbox_code(text, decoder=decode_mail_body, allow_bare_code=_trusted_otp_source(source_url))
    if not match.code:
        return None
    sender_match = _EMAIL_PATTERN.search(text)
    return MailboxMessage(
        identity=_safe_identity(source_url, order, text),
        sender=sender_match.group(0) if sender_match else "",
        subject=text[:500],
        body=text,
        code=match.code,
        code_source=match.source,
        order=order,
        field_sources=("scalar", "sender") if sender_match else ("scalar",),
    )


def _walk_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    stack: list[tuple[Any, int]] = [(value, 0)]
    container_nodes = 0
    while stack:
        current, depth = stack.pop()
        container_nodes += 1
        if depth > MAX_JSON_DEPTH or container_nodes > MAX_JSON_CONTAINER_NODES:
            raise _response_too_complex()
        if isinstance(current, Mapping):
            yield current
            values = current.values()
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            values = current
        else:
            continue
        children: list[tuple[Any, int]] = []
        for child in values:
            if isinstance(child, Mapping) or (isinstance(child, Sequence) and not isinstance(child, (str, bytes, bytearray))):
                if container_nodes + len(stack) + len(children) >= MAX_JSON_CONTAINER_NODES:
                    raise _response_too_complex()
                children.append((child, depth + 1))
        stack.extend(reversed(children))


def _messages_from_json(
    parsed: Any, source_url: str, *, start_order: int = 0, message_limit: int = MAX_PARSED_MESSAGES,
    trust_explicit_code: bool = False,
    allow_bare_code: bool | None = None,
) -> tuple[list[MailboxMessage], list[str]]:
    messages: list[MailboxMessage] = []
    detail_urls: list[str] = []
    order = start_order
    limit = max(0, min(int(message_limit), MAX_PARSED_MESSAGES))
    for mapping in _walk_mappings(parsed):
        if len(messages) >= limit:
            break
        message = _message_from_mapping(
            mapping,
            source_url,
            order,
            trust_explicit_code=trust_explicit_code,
            allow_bare_code=allow_bare_code,
        )
        if message is None:
            continue
        messages.append(message)
        order += 1
        if message.detail_url:
            detail_urls.append(message.detail_url)
    return messages, detail_urls


@dataclass
class _HtmlFrame:
    tag: str
    attrs: dict[str, str]
    parts: list[str]


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
            self.frames.append(_HtmlFrame(tag.lower(), values, []))
        srcdoc = values.get("srcdoc", "").strip()
        if srcdoc:
            embedded = unescape(srcdoc)
            (self.frames[-1].parts if self.frames else self.all_text).append(embedded)
        if tag.lower() == "script":
            self._script_parts = []
            self._script_is_json = "json" in values.get("type", "").lower()

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
    if inbox_index is None or ("/message/" not in source.lower() and "message" not in source.lower()):
        return []
    result: list[str] = []
    for message_id in message_ids:
        if not re.fullmatch(r"[A-Za-z0-9._~-]{1,160}", message_id):
            continue
        detail_segments = list(segments)
        detail_segments[inbox_index] = "message"
        detail_segments.insert(inbox_index + 1, urllib.parse.quote(message_id, safe="._~-"))
        candidate = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/" + "/".join(detail_segments), "", ""))
        if safe_detail_url(page_url, candidate):
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
        detail_url = next((safe_detail_url(source_url, attrs.get(key)) for key in _DETAIL_URL_ATTRS if attrs.get(key)), "")
        received_at = next((attrs.get(key, "") for key in ("datetime", "data-received-at", "data-date", "data-time") if attrs.get(key)), "")
        text = decode_mail_body(candidate_text)
        if message_id:
            message_ids.append(message_id)
        if detail_url and (_MESSAGE_PATH_PATTERN.search(urllib.parse.urlsplit(detail_url).path) or message_id):
            detail_urls.append(detail_url)
        if not any((message_id, detail_url, text, received_at)):
            continue
        sender_match = _EMAIL_PATTERN.search(text)
        code_match = extract_mailbox_code(text, decoder=decode_mail_body, allow_bare_code=_allows_bare_code(source_url))
        messages.append(MailboxMessage(
            identity=_safe_identity(message_id or detail_url or text, received_at),
            sender=sender_match.group(0) if sender_match else "",
            subject=text[:500],
            received_at=received_at,
            received_timestamp=parse_received_timestamp(received_at or text),
            body=text,
            detail_url=detail_url,
            code=code_match.code,
            code_source=code_match.source,
            order=order,
            field_sources=("html", "sender") if sender_match else ("html",),
        ))
        order += 1
    for script in parser.json_scripts:
        try:
            parsed = json.loads(script)
        except RecursionError as exc:
            raise _response_too_complex() from exc
        except (TypeError, ValueError):
            continue
        script_messages, script_detail_urls = _messages_from_json(parsed, source_url, start_order=order, message_limit=MAX_PARSED_MESSAGES - len(messages))
        messages.extend(script_messages)
        detail_urls.extend(script_detail_urls)
        order += len(script_messages)
        if len(messages) >= MAX_PARSED_MESSAGES:
            break
    # Decode api798's inert htmlContent body and run the normal matcher.
    api798_received_at = _api798_received_at(raw, source_url)
    for embedded_html in _api798_embedded_html(raw, source_url):
        embedded_visible = decode_mail_body(embedded_html)
        if not embedded_visible:
            continue
        embedded_match = extract_openai_code(embedded_visible, source_url=source_url)
        if not embedded_match:
            continue
        sender_match = _EMAIL_PATTERN.search(embedded_visible)
        messages.append(MailboxMessage(
            identity=_safe_identity(
                source_url, "api798_latest", api798_received_at, embedded_visible,
            ),
            sender=sender_match.group(0) if sender_match else "",
            subject=embedded_visible[:500],
            received_at=api798_received_at,
            received_timestamp=parse_received_timestamp(api798_received_at),
            body=embedded_visible,
            code=embedded_match,
            code_source="openai_context" if _OPENAI_PATTERN.search(embedded_visible) else "otp_context",
            order=order,
            field_sources=(
                ("html", "sender", "received_at")
                if sender_match and api798_received_at
                else ("html", "received_at")
                if api798_received_at
                else ("html", "sender")
                if sender_match
                else ("html",)
            ),
        ))
        order += 1
    detail_urls.extend(_inferred_detail_urls(source_url, raw, message_ids))
    visible = decode_mail_body(" ".join(parser.all_text))
    if visible:
        visible_code = extract_openai_code(visible, source_url=source_url)
        messages.append(MailboxMessage(identity=_safe_identity(source_url, visible), subject=visible[:500], body=visible, code=visible_code, order=order))
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


def _parse_api798_get_code_payload(
    raw: str,
    source_url: str,
) -> tuple[tuple[MailboxMessage, ...], tuple[str, ...]] | None:
    response = _api798_get_code_response(raw, source_url)
    if response is None:
        return None
    if not response.success:
        return (), ()
    messages: list[MailboxMessage] = []
    order = 0
    if isinstance(response.data, Mapping):
        message = _message_from_mapping(
            response.data,
            source_url,
            order,
            trust_explicit_code=True,
            allow_bare_code=False,
        )
        if message is not None:
            messages.append(message)
            order += 1
        else:
            nested, _detail_urls = _messages_from_json(
                response.data,
                source_url,
                start_order=order,
                message_limit=MAX_PARSED_MESSAGES,
                trust_explicit_code=True,
                allow_bare_code=False,
            )
            messages.extend(nested)
            order += len(nested)
    message_text = decode_mail_body(response.message)
    if message_text:
        code_match = extract_mailbox_code(
            message_text,
            decoder=decode_mail_body,
            allow_bare_code=True,
        )
        messages.append(MailboxMessage(
            identity=_safe_identity(source_url, "api798_get_code", message_text),
            subject=message_text[:500],
            body=message_text,
            code=code_match.code,
            code_source=code_match.source,
            explicit_code=False,
            field_sources=("api798_get_code",),
            order=order,
        ))
    return _merge_messages(messages), ()


def parse_mailbox_payload(raw: str, source_url: str) -> tuple[tuple[MailboxMessage, ...], tuple[str, ...]]:
    api798_payload = _parse_api798_get_code_payload(raw, source_url)
    if api798_payload is not None:
        return api798_payload
    try:
        parsed = json.loads(raw)
    except RecursionError as exc:
        raise _response_too_complex() from exc
    except (TypeError, ValueError):
        parsed = None
    if parsed is not None:
        envelope = (
            parse_mail_code_envelope(
                parsed,
                source_url,
                email_pattern=_EMAIL_PATTERN,
                scalar_text=_scalar_text,
                first=_first,
                strict_explicit_code=_strict_explicit_code,
                message_from_mapping=_message_from_mapping,
                safe_identity=_safe_identity,
                message_type=MailboxMessage,
            )
            if isinstance(parsed, Mapping) else None
        )
        if envelope is not None:
            messages, detail_urls = [envelope], []
        else:
            messages, detail_urls = _messages_from_json(parsed, source_url)
            if _trusted_otp_source(source_url) and isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes, bytearray)):
                order = len(messages)
                for item in parsed[:MAX_MESSAGES]:
                    if isinstance(item, Mapping):
                        continue
                    message = _message_from_scalar(item, source_url, order)
                    if message is not None:
                        messages.append(message)
                        order += 1
    else:
        messages, detail_urls = _parse_html_messages(raw, source_url)
    return _merge_messages(messages), tuple(dict.fromkeys(detail_urls[:MAX_MESSAGES]))


__all__ = [
    "ClientMailboxApi",
    "client_mailbox_api_from_shell",
    "client_mailbox_detail_url",
    "safe_detail_url",
    "same_origin",
]
