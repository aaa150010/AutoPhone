"""Credential redaction helpers for mailbox administration."""

from __future__ import annotations

from typing import Any, Sequence
import re
import urllib.parse


SECRET_MASK = "********"
REDACTION_INPUT_LIMIT = 4096


def url_credential_secrets(value: Any) -> tuple[str, ...]:
    """Return full and component forms that must be redacted from public text."""
    raw = str(value or "").strip()
    if not raw:
        return ()
    candidates = [raw]
    try:
        parsed = urllib.parse.urlsplit(raw)
        for component in (parsed.username, parsed.password):
            if component:
                candidates.extend((component, urllib.parse.unquote(component)))
        for _key, component in urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=False,
        ):
            if component:
                candidates.extend((component, urllib.parse.unquote_plus(component)))
        if parsed.fragment:
            candidates.extend((parsed.fragment, urllib.parse.unquote(parsed.fragment)))
    except (TypeError, ValueError):
        pass
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate))


def redact_mailbox_credentials(error: Any, secrets: Sequence[Any]) -> str:
    text = str(error or "")[:REDACTION_INPUT_LIMIT]
    candidates = {
        str(secret)
        for secret in secrets
        if str(secret or "") and not set(str(secret)).issubset({"*"})
    }
    encoded: set[str] = set()
    for secret in candidates:
        # Query-string providers commonly use ``+`` for spaces while path
        # providers use percent escapes.  Redact both spellings because an
        # error may echo only one credential fragment rather than the URL.
        for escaped in (
            urllib.parse.quote(secret, safe=""),
            urllib.parse.quote_plus(secret, safe=""),
        ):
            if escaped != secret:
                encoded.add(escaped)
    for secret in sorted(candidates | encoded, key=len, reverse=True):
        if secret.isascii() and text.isascii():
            needle = secret.lower()
            source = text
            lowered = source.lower()
            pieces: list[str] = []
            cursor = 0
            while True:
                start = lowered.find(needle, cursor)
                if start < 0:
                    break
                pieces.extend((source[cursor:start], SECRET_MASK))
                cursor = start + len(secret)
            if pieces:
                pieces.append(source[cursor:])
                text = "".join(pieces)
        else:
            text = text.replace(secret, SECRET_MASK)
    return text
