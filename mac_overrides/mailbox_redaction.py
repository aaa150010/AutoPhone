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
    encoded = {
        urllib.parse.quote(secret, safe="")
        for secret in candidates
        if urllib.parse.quote(secret, safe="") != secret
    }
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
