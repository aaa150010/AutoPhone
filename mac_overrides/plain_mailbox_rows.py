"""Plain account/password mailbox row parsing and stable identities."""

from __future__ import annotations

from typing import Any
import re


_EMAIL_PATTERN = re.compile(
    r"(?i)[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
)
_DASH_SEPARATOR = re.compile(r"(?<!-)(?P<separator>-{2,})(?!-)")


def parse_plain_password_mailbox_row(raw: Any) -> tuple[str, str, str] | None:
    value = str(raw or "").strip()
    if not value or value.startswith("#"):
        return None
    separators = list(_DASH_SEPARATOR.finditer(value))
    candidates: list[tuple[str, str, str]] = []
    if len(separators) == 1:
        match = separators[0]
        candidates.append(
            (
                value[: match.start()].strip(),
                value[match.end() :].strip(),
                match.group("separator"),
            )
        )
    if value.count("|") == 1:
        email, password = [part.strip() for part in value.split("|", 1)]
        candidates.append((email, password, "|"))

    for email, password, delimiter in candidates:
        if not _EMAIL_PATTERN.fullmatch(email) or not password:
            continue
        if password.lower().startswith(("http://", "https://")):
            continue
        return email.lower(), password, delimiter
    return None


def plain_password_identity(email: Any, password: Any) -> str:
    """Return the recovered mailbox-pool identity for a password row."""

    account = str(email or "").strip().lower()
    secret = str(password or "").strip()
    if not _EMAIL_PATTERN.fullmatch(account) or not secret:
        return ""
    return f"outlook::{secret}"


def masked_plain_password_row(raw: Any, mask: str = "********") -> str:
    parsed = parse_plain_password_mailbox_row(raw)
    if parsed is None:
        return ""
    email, _password, delimiter = parsed
    return delimiter.join((email, mask))


__all__ = [
    "masked_plain_password_row",
    "parse_plain_password_mailbox_row",
    "plain_password_identity",
]
