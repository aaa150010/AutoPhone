"""Credential-aware parsing and masking for supported mailbox source rows."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

try:
    from .chatgpt_totp import (
        masked_chatgpt_totp_row,
        parse_chatgpt_totp_row,
        parse_mailbox_url_totp_row,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from chatgpt_totp import (
        masked_chatgpt_totp_row,
        parse_chatgpt_totp_row,
        parse_mailbox_url_totp_row,
    )

try:
    from .mailbox_url_runtime import masked_mailbox_url_row, parse_mailbox_url_row
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_url_runtime import masked_mailbox_url_row, parse_mailbox_url_row

try:
    from .mailbox_password_url_rows import (
        masked_mailbox_password_url_row,
        parse_mailbox_password_url_row,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_password_url_rows import (
        masked_mailbox_password_url_row,
        parse_mailbox_password_url_row,
    )

try:
    from .mailbox_redaction import url_credential_secrets
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from mailbox_redaction import url_credential_secrets

try:
    from .plain_mailbox_rows import (
        masked_plain_password_row,
        parse_plain_password_mailbox_row,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from plain_mailbox_rows import (
        masked_plain_password_row,
        parse_plain_password_mailbox_row,
    )


_EMAIL_RE = re.compile(
    r"(?i)\b[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"
)
_SECRET_MASK = "********"


def email_from_row(row: Any) -> str:
    match = _EMAIL_RE.search(str(row or ""))
    return match.group(0).lower() if match else ""


def parse_oauth_mailbox_row(row: Any) -> tuple[str, str, str, str] | None:
    raw = str(row or "").strip()
    if "----" not in raw:
        return None
    parts = [part.strip() for part in raw.split("----")]
    if len(parts) != 4:
        return None
    email = parts[0].lower() if _EMAIL_RE.fullmatch(parts[0]) else ""
    password, oauth_client_id, oauth_refresh_token = parts[1], parts[2], parts[3]
    if not email or not password or not oauth_client_id or not oauth_refresh_token:
        return None
    return email, password, oauth_client_id, oauth_refresh_token


def is_importable_mailbox_row(row: Any) -> bool:
    raw = str(row or "").strip()
    if not raw or raw.startswith("#") or not email_from_row(raw):
        return False
    return (
        parse_mailbox_password_url_row(raw) is not None
        or parse_mailbox_url_totp_row(raw) is not None
        or parse_oauth_mailbox_row(raw) is not None
        or parse_chatgpt_totp_row(raw) is not None
        or parse_mailbox_url_row(raw) is not None
        or parse_plain_password_mailbox_row(raw) is not None
    )


def password_from_row(row: Any) -> str:
    raw = str(row or "").strip()
    if not raw:
        return ""
    parsed_password_url = parse_mailbox_password_url_row(raw)
    if parsed_password_url is not None:
        return parsed_password_url.password
    if parse_mailbox_url_totp_row(raw) is not None or parse_mailbox_url_row(raw) is not None:
        return ""
    parsed_oauth = parse_oauth_mailbox_row(raw)
    if parsed_oauth is not None:
        return parsed_oauth[1]
    parsed_totp = parse_chatgpt_totp_row(raw)
    if parsed_totp is not None:
        return parsed_totp[1]
    parsed_plain = parse_plain_password_mailbox_row(raw)
    if parsed_plain is not None:
        return parsed_plain[1]
    delimiter = "----" if "----" in raw else "|" if "|" in raw else ""
    if not delimiter:
        return ""
    parts = [part.strip() for part in raw.split(delimiter)]
    if len(parts) < 2:
        return ""
    # An unlabeled URL-first composite is intentionally rejected as
    # ambiguous with URL+TOTP.  Do not expose its URL as a mailbox password
    # through the legacy fallback path.
    candidate = parts[1]
    if candidate.lower().startswith(("http://", "https://")):
        return ""
    return candidate


def totp_secret_from_row(row: Any) -> str:
    """Return the private TOTP seed only for supported TOTP mailbox formats."""
    if parse_mailbox_password_url_row(row) is not None:
        return ""
    parsed_url_totp = parse_mailbox_url_totp_row(row)
    if parsed_url_totp is not None:
        return str(parsed_url_totp[2] or "").strip()
    parsed_totp = parse_chatgpt_totp_row(row)
    if parsed_totp is not None:
        return str(parsed_totp[2] or "").strip()
    return ""


def mailbox_url_from_row(row: Any) -> str:
    """Return the transient mailbox page URL for a supported source row."""
    parsed_password_url = parse_mailbox_password_url_row(row)
    if parsed_password_url is not None:
        return parsed_password_url.mailbox_url
    parsed_url_totp = parse_mailbox_url_totp_row(row)
    if parsed_url_totp is not None:
        return str(parsed_url_totp[1] or "").strip()
    parsed_url = parse_mailbox_url_row(row)
    return str(parsed_url.mailbox_url or "").strip() if parsed_url is not None else ""


def row_id_from_source(row: Any) -> str:
    return hashlib.sha256(str(row or "").encode("utf-8")).hexdigest()


def public_task_account(task: Any, source_row: Any = "") -> str:
    """Reduce any recovered account label to its public email address."""
    value = task if isinstance(task, Mapping) else {}
    for candidate in (value.get("email"), value.get("account"), source_row):
        email = email_from_row(candidate)
        if email:
            return email
    return ""


def masked_source_row(row: Any) -> str:
    raw = str(row or "").strip()
    email = email_from_row(raw)
    if not email:
        return ""
    if parse_mailbox_password_url_row(raw) is not None:
        return masked_mailbox_password_url_row(raw, _SECRET_MASK)
    if parse_mailbox_url_totp_row(raw) is not None:
        return "----".join((email, _SECRET_MASK, _SECRET_MASK))
    if parse_oauth_mailbox_row(raw) is not None:
        return "----".join((email, _SECRET_MASK, _SECRET_MASK, _SECRET_MASK))
    if parse_chatgpt_totp_row(raw) is not None:
        return masked_chatgpt_totp_row(raw, _SECRET_MASK)
    if parse_mailbox_url_row(raw) is not None:
        return masked_mailbox_url_row(raw, _SECRET_MASK)
    masked_plain = masked_plain_password_row(raw, _SECRET_MASK)
    if masked_plain:
        return masked_plain
    return email


def row_secrets(row: Any) -> tuple[str, ...]:
    """Return all credential fragments that diagnostics must redact for one row."""
    raw = str(row or "").strip()
    values = [raw, email_from_row(raw), password_from_row(raw)]
    # Keep malformed rows safe too.  They are not importable, but mailbox
    # diagnostics still inspect every source line before reporting it.
    for delimiter in ("----", "---", "--", "|", "｜"):
        if delimiter in raw:
            values.extend(part.strip() for part in raw.split(delimiter)[1:])
            break
    for parsed in (
        parse_oauth_mailbox_row(raw),
        parse_chatgpt_totp_row(raw),
        parse_mailbox_url_totp_row(raw),
    ):
        if parsed is not None:
            values.extend(parsed)
    mailbox_url = mailbox_url_from_row(raw)
    if mailbox_url:
        values.append(mailbox_url)
        values.extend(url_credential_secrets(mailbox_url))
    for match in re.finditer(r"https?://\S+", raw, re.IGNORECASE):
        url = match.group(0).rstrip("。，；,;)]}>")
        if url:
            values.append(url)
            values.extend(url_credential_secrets(url))
    return tuple(dict.fromkeys(value for value in values if value))


__all__ = [
    "email_from_row",
    "is_importable_mailbox_row",
    "mailbox_url_from_row",
    "masked_source_row",
    "parse_mailbox_password_url_row",
    "parse_chatgpt_totp_row",
    "parse_mailbox_url_row",
    "parse_mailbox_url_totp_row",
    "parse_oauth_mailbox_row",
    "parse_plain_password_mailbox_row",
    "password_from_row",
    "public_task_account",
    "row_id_from_source",
    "row_secrets",
    "totp_secret_from_row",
]
