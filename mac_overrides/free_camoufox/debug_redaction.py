"""Credential-safe debug text redaction for Camoufox artifacts.

Debug artifacts have a stricter redaction boundary than ordinary business
diagnostics.  The latter intentionally keeps short numeric identifiers and
route labels useful; a retained browser page, however, can contain an OTP in
visible text or a console error.  This policy is local to the Camoufox scene
dump so changing it cannot alter normal task/log semantics.

This is now the single implementation source: the runtime module re-exports
the private aliases, and ``debug_artifacts.sanitize_debug_text`` calls into
this module instead of keeping its own fallback copy.
"""

from __future__ import annotations

import re
from typing import Any

try:
    from ..free_failure_runtime import sanitize_failure_text
except ImportError:  # pragma: no cover - top-level recovery import
    from free_failure_runtime import sanitize_failure_text  # type: ignore[no-redef]


_DEBUG_OTP_CONTEXT_RE = re.compile(
    r"(?ix)"
    r"(?:\b(?:one[\s_-]?time(?:[\s_-]?password)?|otp|"
    r"verification(?:[\s_-]?code)?|verify(?:[\s_-]?code)?|"
    r"authentication(?:[\s_-]?code)?|auth(?:[\s_-]?code)?|"
    r"security[\s_-]?(?:code|pin|passcode|token)|pass[\s_-]?code|"
    r"pin|code|(?:access|login|email|sms)[\s_-]?code"
    r")\b|验证码|校验码|动态码|一次性密码|認証(?:コード)?|確認コード|検証コード)"
 )
_DEBUG_NUMERIC_OTP_RE = re.compile(r"(?<![A-Za-z0-9])\d{4,7}(?![A-Za-z0-9])")
# Require both letters and digits so ordinary words ("security", "Cloudflare")
# are never treated as an OTP.  A context label is still required before this
# candidate is masked; this avoids destroying browser/version identifiers such
# as ``HTTP403`` in otherwise useful diagnostics.
_DEBUG_ALNUM_OTP_RE = re.compile(
    r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]{4,12}(?![A-Za-z0-9]))"
    r"(?=[A-Za-z0-9]*[A-Za-z])(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{4,12}(?![A-Za-z0-9])"
)
# Verification codes are also commonly rendered as short groups, for example
# ``A1-B2-C3`` or ``12 34 56``.  A contiguous-token pass cannot see those
# values, so inspect bounded groups separately and apply the same conservative
# status/version allow-list below.
_DEBUG_GROUPED_ALNUM_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9]{1,8}(?:[\s-][A-Za-z0-9]{1,8}){1,7}(?![A-Za-z0-9])"
)
# Grouped-code matching can include the label immediately before the value
# (for example, ``code A1-B2-C3``).  Keep those labels in the scene dump while
# masking only the value itself.
_DEBUG_GROUP_LABELS = {
    "one", "time", "password", "otp", "verification", "verify",
    "authentication", "auth", "security", "code", "pin", "passcode",
    "token", "access", "login", "email", "sms",
}
# A few unambiguous protocol/status spellings are useful diagnostics rather
# than OTPs.  Version-like values need an explicit version/build/release
# label; a bare ``v2024`` is still treated as a possible code.
_DEBUG_ALNUM_STATUS_RE = re.compile(r"(?i)^(?:https?|http|err|ns|tls|ssl)\d{3}$")
_DEBUG_VERSION_CONTEXT_RE = re.compile(r"(?i)\b(?:version|build|release)\b")
_DEBUG_EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])")
_DEBUG_PHONE_RE = re.compile(r"(?<![\w])\+?\d{8,15}(?![\w])")
_SENSITIVE_BODY_RE = re.compile(
    r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|"
    r"(?<![A-Za-z0-9])\+?\d{8,15}(?![A-Za-z0-9])|"
    r"(?<![A-Za-z0-9])\d{4,7}(?![A-Za-z0-9])"
)
_SCREENSHOT_SCAN_LIMIT = 100_000


def debug_otp_context(text: str, start: int, end: int, *, radius: int = 72) -> bool:
    """Return whether a candidate is near an OTP/verification label."""
    window = text[max(0, start - radius):min(len(text), end + radius)]
    return bool(_DEBUG_OTP_CONTEXT_RE.search(window))


def debug_alnum_is_safe_identifier(text: str, start: int, end: int, candidate: str) -> bool:
    """Keep protocol/version labels while rejecting code-shaped tokens."""
    if _DEBUG_ALNUM_STATUS_RE.fullmatch(candidate):
        # HTTP/NS/TLS status tokens are diagnostics, never credentials. Keep
        # them readable even when the surrounding message also mentions a
        # verification code.
        return True
    if re.fullmatch(r"(?i)v\d{1,4}", candidate):
        window = text[max(0, start - 32):min(len(text), end + 32)]
        return bool(_DEBUG_VERSION_CONTEXT_RE.search(window))
    return False


def debug_grouped_is_candidate(text: str, start: int, end: int, candidate: str) -> bool:
    """Recognize grouped code-shaped values without masking normal prose."""
    chunks = [item for item in re.split(r"[\s-]+", candidate) if item]
    compact = "".join(chunks)
    if len(compact) < 4 or not any(char.isdigit() for char in compact):
        return False
    # ``Version v2024`` (and the equivalent build/release labels) is a
    # diagnostic identifier, not an OTP.  The broad context window may also
    # contain a real ``code`` label elsewhere in the same message, so check
    # the version token before applying that context.
    if len(chunks) == 2 and re.fullmatch(r"(?i)v\d{1,4}", chunks[1]):
        window = text[max(0, start - 32):min(len(text), end + 32)]
        if _DEBUG_VERSION_CONTEXT_RE.search(window):
            return False
    if debug_alnum_is_safe_identifier(text, start, end, compact):
        return False
    # An OTP label makes even uneven groups (``AB-1234``) unambiguous.  In an
    # unlabeled string require several short code-like groups so phrases such
    # as ``Version v2024`` are not swallowed as a single secret.
    if debug_otp_context(text, start, end):
        return True
    return (
        len(chunks) >= 2
        and all(len(chunk) <= 4 for chunk in chunks)
        and sum(any(char.isdigit() for char in chunk) for chunk in chunks) >= 2
    )


def debug_grouped_secret_start(text: str, start: int, end: int) -> int:
    """Return the first character of a grouped secret, after its label."""
    candidate = text[start:end]
    tokens = list(re.finditer(r"[A-Za-z0-9]+", candidate))
    secret_start = start
    for token in tokens:
        word = token.group(0).casefold()
        if word not in _DEBUG_GROUP_LABELS:
            break
        secret_start = start + token.end()
    while secret_start < end and text[secret_start] in " \t-":
        secret_start += 1
    return secret_start


def sanitize_debug_text(value: Any, limit: int = 800, *, mask_bare_numeric: bool = True) -> str:
    """Redact credentials and likely OTPs before writing a debug artifact.

    Numeric 4--7 digit values are masked even without a nearby label.  This
    is deliberately fail-closed for retained browser scenes because a page
    may render a code by itself (for example, a single ``<p>1234</p>``).  Mixed
    alphanumeric candidates are masked when they have an OTP context or match
    a code-like standalone token.  A small protocol/status allowlist keeps
    values such as ``HTTP403`` readable; version values are retained only
    beside an explicit ``version``/``build``/``release`` label.
    """
    text = sanitize_failure_text(value, max(0, int(limit)))
    if not text:
        return ""
    replacements: list[tuple[int, int, str]] = []
    occupied_until = -1
    for match in _DEBUG_GROUPED_ALNUM_RE.finditer(text):
        if match.start() < occupied_until:
            continue
        if debug_grouped_is_candidate(text, match.start(), match.end(), match.group(0)):
            secret_start = debug_grouped_secret_start(text, match.start(), match.end())
            if secret_start < match.end():
                replacements.append((secret_start, match.end(), "<验证码>"))
            occupied_until = match.end()
    for matcher, is_numeric in ((_DEBUG_NUMERIC_OTP_RE, True), (_DEBUG_ALNUM_OTP_RE, False)):
        for match in matcher.finditer(text):
            if match.start() < occupied_until:
                continue
            if is_numeric:
                should_mask = mask_bare_numeric or debug_otp_context(text, match.start(), match.end())
            else:
                candidate = match.group(0)
                should_mask = debug_otp_context(text, match.start(), match.end())
                if debug_alnum_is_safe_identifier(text, match.start(), match.end(), candidate):
                    # Keep unambiguous protocol/version forms readable when
                    # they are not part of an OTP-labelled message.
                    should_mask = False
                elif not should_mask:
                    # Mixed alpha/numeric values are a common OTP format even
                    # when a page renders the value without its label. Keep
                    # ordinary protocol/status identifiers above readable.
                    should_mask = True
            if should_mask:
                replacements.append((match.start(), match.end(), "<验证码>"))
                occupied_until = match.end()
    for start, end, replacement in reversed(replacements):
        text = text[:start] + replacement + text[end:]
    return text[: max(0, int(limit))]


def debug_body_has_sensitive_token(value: Any) -> bool:
    """Check raw page text before screenshot capture, without returning it."""
    text = str(value or "")
    if _SENSITIVE_BODY_RE.search(text) or _DEBUG_EMAIL_RE.search(text) or _DEBUG_PHONE_RE.search(text):
        return True
    for match in _DEBUG_NUMERIC_OTP_RE.finditer(text):
        # A bare code is unsafe to capture; labels are not required here.
        if debug_otp_context(text, match.start(), match.end()) or len(match.group(0)) in {4, 5, 6, 7}:
            return True
    for match in _DEBUG_ALNUM_OTP_RE.finditer(text):
        if not debug_alnum_is_safe_identifier(text, match.start(), match.end(), match.group(0)):
            return True
    for match in _DEBUG_GROUPED_ALNUM_RE.finditer(text):
        if debug_grouped_is_candidate(text, match.start(), match.end(), match.group(0)):
            return True
    return False


def safe_body_markers(value: Any) -> list[str]:
    """Report only sensitivity classes, never page/response text."""
    text = str(value or "")
    markers: list[str] = []
    if re.search(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text):
        markers.append("<邮箱>")
    if re.search(r"(?<!\d)\+?\d{8,15}(?!\d)", text):
        markers.append("<手机号>")
    if _DEBUG_NUMERIC_OTP_RE.search(text) or any(
        debug_otp_context(text, match.start(), match.end())
        or not _DEBUG_ALNUM_STATUS_RE.fullmatch(match.group(0))
        for match in _DEBUG_ALNUM_OTP_RE.finditer(text)
    ) or any(
        debug_grouped_is_candidate(text, match.start(), match.end(), match.group(0))
        for match in _DEBUG_GROUPED_ALNUM_RE.finditer(text)
    ):
        markers.append("<验证码>")
    return markers


__all__ = [
    "debug_alnum_is_safe_identifier",
    "debug_body_has_sensitive_token",
    "debug_grouped_is_candidate",
    "debug_grouped_secret_start",
    "debug_otp_context",
    "safe_body_markers",
    "sanitize_debug_text",
]
