"""Provider strategy for the api798 ``/latest`` mailbox page.

The api798 page is a JavaScript shell that embeds a message body in an
``htmlContent`` assignment.  Keeping its URL trust policy and inert string
decoder separate prevents the general mailbox parser from broadening its
bare-code rules for unrelated providers.
"""

from __future__ import annotations

import json
import re
from typing import Any
import urllib.parse


_API798_HOST = "api798.com"
_API798_LATEST_PATH = "/latest"
_TRUSTED_OTP_PATH_PATTERN = re.compile(
    r"(?i)(?:^|/)(?:pickup|mail-api|mail-code|api/messages?)(?:/|$)"
)
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
    if (
        parsed.scheme.lower() in {"http", "https"}
        and (parsed.hostname or "").casefold() == _API798_HOST
        and parsed.path.rstrip("/").casefold() == _API798_LATEST_PATH
    ):
        return "api798_latest"
    if _TRUSTED_OTP_PATH_PATTERN.search(parsed.path):
        return "trusted_path"
    return ""


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
    "allows_bare_code",
    "api798_embedded_html",
    "api798_received_at",
    "mailbox_provider_strategy",
]
