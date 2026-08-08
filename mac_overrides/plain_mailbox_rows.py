"""Plain account/password mailbox row parsing."""

from __future__ import annotations

from typing import Any
import re


_EMAIL_PATTERN = re.compile(
    r"(?i)[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
)
_DOUBLE_DASH_SEPARATOR = re.compile(r"(?<!-)--(?!-)")


def parse_plain_password_mailbox_row(raw: Any) -> tuple[str, str, str] | None:
    value = str(raw or "").strip()
    if not value or value.startswith("#"):
        return None
    for delimiter in ("--", "|"):
        if delimiter == "--":
            matches = list(_DOUBLE_DASH_SEPARATOR.finditer(value))
            if len(matches) != 1:
                continue
            match = matches[0]
            email = value[: match.start()].strip()
            password = value[match.end() :].strip()
        else:
            if value.count(delimiter) != 1:
                continue
            email, password = [part.strip() for part in value.split(delimiter, 1)]
        if not _EMAIL_PATTERN.fullmatch(email) or not password:
            continue
        if password.lower().startswith(("http://", "https://")):
            continue
        return email.lower(), password, delimiter
    return None


def masked_plain_password_row(raw: Any, mask: str = "********") -> str:
    parsed = parse_plain_password_mailbox_row(raw)
    if parsed is None:
        return ""
    email, _password, delimiter = parsed
    return delimiter.join((email, mask))
