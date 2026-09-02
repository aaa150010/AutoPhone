"""Provider strategy for api798 mailbox responses.

The ``/latest`` page is a JavaScript shell that embeds a message body in an
``htmlContent`` assignment.  The ``/get_code`` endpoint returns a small JSON
envelope.  Keeping both URL trust policies and decoders here prevents the
general mailbox parser from broadening its bare-code rules for unrelated
providers.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import re
from typing import Any
import urllib.parse


_API798_HOST = "api798.com"
_API798_LATEST_PATH = "/latest"
_API798_GET_CODE_PATH = "/get_code"
_REMAIL_HOST = "remail.aishop6.com"
_REMAIL_PICKUP_PATH = "/v1/pickup"
_TRUSTED_OTP_PATH_PATTERN = re.compile(
    r"(?i)(?:^|/)(?:pickup|mail-api|mail-code|api/messages?)(?:/|$)"
)


@dataclass(frozen=True, slots=True)
class Api798GetCodeResponse:
    """Credential-safe projection of an api798 ``/get_code`` response.

    The endpoint has shipped both a scalar top-level ``message`` and a nested
    ``data`` mail object.  Keep only fields that describe the mail itself;
    URL query parameters (including ``auth_code``) never enter this object.
    """

    success: bool
    message: str = ""
    data: Mapping[str, Any] | None = None


_API798_DATA_KEYS = frozenset({
    # ``key`` is intentionally excluded: on some revisions it is the same
    # mailbox credential carried as ``auth_code`` in the request URL.  Message
    # ids are still covered by the non-secret id/uid aliases below.
    "id", "uid", "messageid", "message_id", "mailid", "mail_id",
    "from", "fromaddress", "from_address", "sender", "senderemail",
    "sender_email", "sendemail", "send_email", "emailfrom", "email_from",
    "subject", "title", "mailsubject", "mail_subject", "mailtitle", "mail_title",
    "body", "content", "html", "text", "message", "msg", "snippet", "preview",
    "bodyhtml", "body_html", "bodytext", "body_text", "contenthtml", "content_html",
    "contenttext", "content_text", "date", "time", "received", "receivedat",
    "received_at", "sentat", "sent_at", "timestamp", "code", "otp", "otpcode",
    "otp_code", "verificationcode", "verification_code", "securitycode", "security_code",
})


def _project_data(value: Any, *, depth: int = 0) -> Mapping[str, Any] | None:
    """Project nested mail metadata without retaining unrelated response data."""
    if depth > 8 or not isinstance(value, Mapping):
        return None
    projected: dict[str, Any] = {}
    for key, item in value.items():
        normalized_key = str(key).replace("-", "_").casefold()
        if normalized_key not in _API798_DATA_KEYS:
            continue
        if isinstance(item, Mapping):
            nested = _project_data(item, depth=depth + 1)
            if nested:
                projected[normalized_key] = nested
        elif isinstance(item, (list, tuple)):
            nested_items: list[Any] = []
            for child in item[:40]:
                if isinstance(child, Mapping):
                    nested = _project_data(child, depth=depth + 1)
                    if nested:
                        nested_items.append(nested)
                elif isinstance(child, (str, int, float)) and not isinstance(child, bool):
                    nested_items.append(child)
            if nested_items:
                projected[normalized_key] = nested_items
        elif isinstance(item, (str, int, float)) and not isinstance(item, bool):
            projected[normalized_key] = item
    return projected or None
_API798_HTML_CONTENT_PATTERNS = (
    re.compile(r'(?is)\bhtmlContent\s*=\s*"((?:\\.|[^"\\])*)"'),
    re.compile(r"(?is)\bhtmlContent\s*=\s*'((?:\\.|[^'\\])*)'"),
)
_API798_RECEIVED_AT_PATTERN = re.compile(
    r"(?is)(?:接收时间|时间|time|date|received|sent)\s*[:：]"
    r"(?:\s|&nbsp;|<[^>]*>)*"
    r"((?:\d{4}年\d{1,2}月\d{1,2}日\s+\d{1,2}:\d{2}(?::\d{2})?)|"
    r"(?:\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}(?::\d{2})?))"
)


def mailbox_provider_strategy(source_url: str) -> str:
    """Return the narrow parser policy for a mailbox source URL."""
    try:
        parsed = urllib.parse.urlsplit(source_url)
    except (TypeError, ValueError):
        return ""
    if parsed.scheme.lower() in {"http", "https"} and (
        parsed.hostname or ""
    ).casefold() == _API798_HOST:
        path = parsed.path.rstrip("/").casefold()
        if path == _API798_LATEST_PATH:
            return "api798_latest"
        if path == _API798_GET_CODE_PATH:
            return "api798_get_code"
    # Remail's pickup response is a scoped API projection.  Treat it as a
    # trusted mailbox source so explicit ``verificationCode`` fields are
    # accepted by the shared parser without trusting arbitrary URL sources.
    if parsed.scheme.lower() in {"http", "https"} and (
        parsed.hostname or ""
    ).casefold() == _REMAIL_HOST and parsed.path.rstrip("/").casefold() == _REMAIL_PICKUP_PATH:
        return "remail_pickup"
    if _TRUSTED_OTP_PATH_PATTERN.search(parsed.path):
        return "trusted_path"
    return ""


def _top_level_scalar(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value).strip()
    return ""


def api798_get_code_response(
    raw: str,
    source_url: str,
) -> Api798GetCodeResponse | None:
    """Parse the successful envelope and its nested mail projection.

    ``None`` means the URL is not the exact api798 endpoint.  Once the URL is
    recognized, malformed data is kept as an unsuccessful empty response so
    it cannot fall through to broader JSON traversal.  Query parameters are
    intentionally never inspected here.
    """
    if mailbox_provider_strategy(source_url) != "api798_get_code":
        return None
    try:
        parsed = json.loads(str(raw or ""))
    except (RecursionError, TypeError, ValueError):
        return Api798GetCodeResponse(False)
    if not isinstance(parsed, Mapping):
        return Api798GetCodeResponse(False)
    if parsed.get("success") is not True:
        return Api798GetCodeResponse(False)
    data = _project_data(parsed.get("data"))
    return Api798GetCodeResponse(
        True,
        _top_level_scalar(parsed.get("message")),
        data,
    )


def _decode_javascript_string(value: str) -> str:
    """Decode JSON-compatible JS string escapes without executing script."""
    try:
        return json.loads('"' + value + '"')
    except (TypeError, ValueError):
        replacements = {
            "\\\\": "\\",
            "\\r": "\r",
            "\\n": "\n",
            "\\t": "\t",
            "\\b": "\b",
            "\\f": "\f",
            "\\v": "\v",
            '\\"': '"',
            "\\'": "'",
            "\\/": "/",
        }
        decoded = value
        for escaped, replacement in replacements.items():
            decoded = decoded.replace(escaped, replacement)

        def _unicode(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except (TypeError, ValueError):
                return match.group(0)

        decoded = re.sub(r"\\u([0-9a-fA-F]{4})", _unicode, decoded)
        return re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda match: chr(int(match.group(1), 16)),
            decoded,
        )


def api798_embedded_html(raw: str, source_url: str) -> tuple[str, ...]:
    """Extract bounded, inert HTML strings from an api798 latest page."""
    if mailbox_provider_strategy(source_url) != "api798_latest":
        return ()
    embedded: list[str] = []
    for pattern in _API798_HTML_CONTENT_PATTERNS:
        for match in pattern.finditer(raw):
            value = _decode_javascript_string(match.group(1)).strip()
            if not value or "<" not in value or ">" not in value:
                continue
            if len(value) > 2 * 1024 * 1024:
                continue
            if value not in embedded:
                embedded.append(value)
            if len(embedded) >= 4:
                return tuple(embedded)
    return tuple(embedded)


def api798_received_at(raw: str, source_url: str) -> str:
    """Extract the page's displayed latest-mail time without reading secrets."""
    if mailbox_provider_strategy(source_url) != "api798_latest":
        return ""
    match = _API798_RECEIVED_AT_PATTERN.search(str(raw or ""))
    return str(match.group(1) or "").strip() if match else ""


def allows_bare_code(source_url: str) -> bool:
    """Allow a standalone six-digit value only on legacy OTP API paths."""
    return mailbox_provider_strategy(source_url) == "trusted_path"


__all__ = [
    "Api798GetCodeResponse",
    "allows_bare_code",
    "api798_embedded_html",
    "api798_get_code_response",
    "api798_received_at",
    "mailbox_provider_strategy",
]
