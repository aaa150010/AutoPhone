"""Provider adapter for online mailbox ``email``/``code``/``mail`` payloads."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import re
from typing import Any


def parse_mail_code_envelope(
    parsed: Mapping[str, Any],
    source_url: str,
    *,
    email_pattern: re.Pattern[str],
    scalar_text: Callable[[Any], str],
    first: Callable[[Mapping[str, Any], Sequence[str]], Any],
    strict_explicit_code: Callable[[Any], str],
    message_from_mapping: Callable[..., Any | None],
    safe_identity: Callable[..., str],
    message_type: Callable[..., Any],
) -> Any | None:
    """Return one trusted message for a successful online mailbox response."""
    email = scalar_text(first(parsed, ("email", "address"))).strip()
    mail = parsed.get("mail")
    code = strict_explicit_code(parsed.get("code"))
    error = parsed.get("error")
    if (
        not email_pattern.fullmatch(email)
        or not isinstance(mail, Mapping)
        or not code
        or error not in (None, "", False)
    ):
        return None

    # Keep the normal sender/subject/date handling while trusting only the
    # provider's explicitly scoped code field.
    message_payload = dict(mail)
    message_payload["verification_code"] = code
    message = message_from_mapping(
        message_payload,
        source_url,
        0,
        trust_explicit_code=True,
    )
    if message is not None:
        return message
    return message_type(
        identity=safe_identity("mail-code-envelope", source_url, email, code),
        code=code,
        order=0,
        explicit_code=True,
    )


__all__ = ["parse_mail_code_envelope"]
