"""Parsing for mailbox rows that carry both a login password and pickup URL."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

try:
    from .mailbox_url_runtime import parse_mailbox_url_row
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_url_runtime import parse_mailbox_url_row


_EMAIL = (
    r"[a-z0-9][a-z0-9._%+-]*@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
)
_SEPARATOR = r"(?P<separator>-{3,}|\|+|｜+)"
_PASSWORD_FIRST = re.compile(
    rf"^\s*(?P<email>{_EMAIL})\s*{_SEPARATOR}\s*"
    rf"(?P<password>.+?)\s*(?P=separator)\s*(?P<url>https?://\S+)\s*$",
    re.IGNORECASE,
)
_URL_FIRST_LABELED = re.compile(
    rf"^\s*(?P<email>{_EMAIL})\s*{_SEPARATOR}\s*"
    rf"(?P<url>https?://\S+?)\s*(?P=separator)\s*"
    r"(?:密码|password)\s*[:：]\s*(?P<password>.+?)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class MailboxPasswordUrlRow:
    email: str
    password: str
    mailbox_url: str
    separator: str

    def canonical(self) -> str:
        return "----".join((self.email, self.password, self.mailbox_url))


def parse_mailbox_password_url_row(value: Any) -> MailboxPasswordUrlRow | None:
    """Parse an unambiguous password+URL row without stealing URL+TOTP rows."""
    raw = str(value or "").strip()
    if not raw or raw.startswith("#"):
        return None
    match = _PASSWORD_FIRST.fullmatch(raw) or _URL_FIRST_LABELED.fullmatch(raw)
    if match is None:
        return None
    email = match.group("email").lower()
    password = match.group("password").strip()
    mailbox_url = match.group("url").strip()
    if not password or password.lower().startswith(("http://", "https://")):
        return None
    parsed_url = parse_mailbox_url_row(f"{email}|{mailbox_url}")
    if parsed_url is None or parsed_url.email != email:
        return None
    return MailboxPasswordUrlRow(
        email=email,
        password=password,
        mailbox_url=parsed_url.mailbox_url,
        separator=match.group("separator"),
    )


def masked_mailbox_password_url_row(value: Any, mask: str = "********") -> str:
    parsed = parse_mailbox_password_url_row(value)
    if parsed is None:
        return ""
    return parsed.separator.join((parsed.email, mask, mask))


__all__ = [
    "MailboxPasswordUrlRow",
    "masked_mailbox_password_url_row",
    "parse_mailbox_password_url_row",
]
