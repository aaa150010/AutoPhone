"""Credential-safe decoding and OTP extraction for mailbox payloads."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
import re
from typing import Any, Callable
import unicodedata
import urllib.parse


OPENAI_PATTERN = re.compile(r"(?i)open\s*ai|chat\s*gpt")
OTP_CONTEXT = (
    r"verification(?:\s+code)?|verify|security\s+code|authentication\s+code|"
    r"login\s+code|sign[\s-]?in\s+code|temporary\s+code|one[\s-]?time|"
    r"otp|passcode|your\s+code|code\s+is|验证码|校验码|验证代码|安全代码|"
    r"登录代码|登录码|临时代码|一次性代码|認証コード|認証用コード|"
    r"検証コード|一時検証コード|確認コード|ログインコード"
)
OTP_CONTEXT_PATTERN = re.compile(rf"(?is)(?:{OTP_CONTEXT})")
_OTP_COMPACT_PATTERNS = (
    re.compile(rf"(?is)(?:{OTP_CONTEXT}).{{0,260}}?(?<!\d)(\d{{6}})(?!\d)"),
    re.compile(rf"(?is)(?<!\d)(\d{{6}})(?!\d).{{0,180}}?(?:{OTP_CONTEXT})"),
)
_OTP_SPACED_PATTERNS = (
    re.compile(
        rf"(?is)(?:{OTP_CONTEXT}).{{0,260}}?"
        r"(\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d)"
    ),
    re.compile(
        r"(?is)(\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d)"
        rf".{{0,180}}?(?:{OTP_CONTEXT})"
    ),
)
_DATE_TIME_FRAGMENT_RE = re.compile(
    r"^(?:\d{4}[-/]\d{2}|\d{2}[-/:]\d{2}[-/:]\d{2})$"
)
_SIX_DIGIT_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")


@dataclass(frozen=True, slots=True)
class MailboxCodeMatch:
    code: str = ""
    source: str = ""


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth and data.strip():
            self.parts.append(data)


def decode_bytes(value: bytes, content_type: str = "") -> str:
    charset_match = re.search(r"(?i)charset\s*=\s*[\"']?([^;\s\"']+)", content_type)
    charsets = [charset_match.group(1)] if charset_match else []
    charsets.extend(("utf-8-sig", "gb18030", "latin-1"))
    for charset in dict.fromkeys(charsets):
        try:
            return value.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
    return value.decode("utf-8", errors="replace")


def _html_text(value: str) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(value)
    except Exception:
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unescape(value))).strip()
    return re.sub(r"\s+", " ", unescape(" ".join(parser.parts))).strip()


def _decode_data_url(value: str) -> str:
    if not value.lower().startswith("data:") or "," not in value:
        return value
    header, payload = value.split(",", 1)
    try:
        raw = (
            base64.b64decode(payload, validate=False)
            if ";base64" in header.lower()
            else urllib.parse.unquote_to_bytes(payload)
        )
    except (ValueError, TypeError):
        return value
    return decode_bytes(raw, header)


def _decode_possible_base64(value: str) -> str:
    compact = re.sub(r"\s+", "", value)
    if (
        len(compact) < 24
        or len(compact) % 4
        or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact)
    ):
        return value
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, TypeError):
        return value
    text = decode_bytes(decoded)
    if "<" in text or OPENAI_PATTERN.search(text) or OTP_CONTEXT_PATTERN.search(text):
        return text
    return value


def decode_mail_body(value: Any, *, scalar_text: Callable[[Any], str] = str) -> str:
    text = scalar_text(value).strip()
    if not text:
        return ""
    text = _decode_possible_base64(_decode_data_url(text))
    if "<" in text and ">" in text:
        text = _html_text(text)
    # Mail providers mix full-width punctuation/digits with ASCII content.
    # NFKC keeps Japanese text intact while making OTP matching deterministic.
    text = unicodedata.normalize("NFKC", unescape(text))
    return re.sub(r"\s+", " ", text).strip()


def extract_mailbox_code(
    *values: Any,
    decoder: Callable[[Any], str] = decode_mail_body,
    allow_bare_code: bool = False,
) -> MailboxCodeMatch:
    decoded = [decoder(value) for value in values if value not in (None, "")]
    decoded = [value for value in decoded if value]
    text = "\n".join(decoded)
    if not text:
        return MailboxCodeMatch()
    branded = bool(OPENAI_PATTERN.search(text))
    contextual = bool(OTP_CONTEXT_PATTERN.search(text))
    if not branded and not contextual:
        if allow_bare_code:
            for value in decoded:
                candidate = value.strip()
                if _SIX_DIGIT_RE.fullmatch(candidate):
                    return MailboxCodeMatch(candidate, "bare_code")
        return MailboxCodeMatch()
    for pattern in (*_OTP_COMPACT_PATTERNS, *_OTP_SPACED_PATTERNS):
        for match in pattern.finditer(text):
            candidate = match.group(1).strip()
            if _DATE_TIME_FRAGMENT_RE.fullmatch(candidate):
                continue
            digits = re.sub(r"\D", "", candidate)
            if len(digits) == 6:
                return MailboxCodeMatch(
                    digits,
                    "openai_context" if branded else "otp_context",
                )
    return MailboxCodeMatch()


__all__ = [
    "MailboxCodeMatch",
    "OPENAI_PATTERN",
    "OTP_CONTEXT_PATTERN",
    "decode_bytes",
    "decode_mail_body",
    "extract_mailbox_code",
]
