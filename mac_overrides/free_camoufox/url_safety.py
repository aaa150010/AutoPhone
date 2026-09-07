"""Credential-safe URL/identifier projections for Camoufox diagnostics.

Every helper here reduces a raw value to a bounded, origin/path-only or
fingerprint-only projection so OAuth query parameters, mailbox routes, phone
numbers and tokens can never reach a debug event, artifact or incident id.

Single implementation source; ``free_camoufox_runtime`` re-exports the private
aliases and ``debug_artifacts``/``transport`` use these functions directly.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlsplit

try:
    from ..free_register_common import fingerprint
except ImportError:  # pragma: no cover - top-level recovery import
    from free_register_common import fingerprint  # type: ignore[no-redef]

from .debug_redaction import sanitize_debug_text


def safe_url(page: Any) -> str:
    try:
        parsed = urlsplit(str(getattr(page, "url", "") or ""))
        if parsed.scheme and parsed.hostname:
            return safe_event_url(parsed.geturl()) or "页面地址未知"
    except Exception:
        pass
    return "页面地址未知"


def safe_event_url(value: Any) -> str:
    """Keep only a request host/path for the bounded debug event trace."""
    try:
        parsed = urlsplit(str(value or ""))
        if not parsed.hostname:
            return ""
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        path = parsed.path or "/"
        # Decode nested percent-encoding before applying the redaction rules.
        # A bounded loop handles values encoded by browser/router layers while
        # avoiding unbounded work on malformed input.
        for _ in range(8):
            decoded = unquote(path)
            if decoded == path:
                break
            path = decoded
        trusted_host = (
            host.casefold() == "chatgpt.com"
            or host.casefold().endswith(".chatgpt.com")
            or host.casefold() == "openai.com"
            or host.casefold().endswith(".openai.com")
        )
        if not trusted_host:
            path = "/[路径已隐藏]"
        # Opaque authorization/callback routes and encoded values are not
        # useful for diagnosis. Keep known ChatGPT routes readable, but hide
        # tokens, mailbox addresses, phone numbers and long opaque segments.
        path = re.sub(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "<邮箱>", path)
        path = re.sub(r"(?<!\d)\+?\d{8,15}(?!\d)", "<手机号>", path)
        # URL query strings are discarded below, but short OTPs can also be
        # embedded in a verification route path.  Apply the debug-only text
        # policy here after decoding nested percent escapes.
        path = sanitize_debug_text(path, 500)
        path = re.sub(r"(?i)((?:token|code|state|nonce|session|key|secret|credential|assertion))(?:/|=)[^/?#&]+", r"\1/<已隐藏>", path)
        path = re.sub(
            r"(?i)(/(?:authorize|callback|oauth|continue|session))(?:/[^/?#]*)?",
            r"\1/<已隐藏>",
            path,
        )
        # Encoded query strings can become a literal ``?`` only after the
        # repeated decode above.  Drop that suffix even when it does not use a
        # recognized key, because it may contain an opaque authorization value.
        if "?" in path or "#" in path:
            path = re.split(r"[?#]", path, maxsplit=1)[0].rstrip("/") or "/"
            path = f"{path}/<已隐藏>" if path != "/" else "/<已隐藏>"
        elif re.search(r"[&=]", path):
            path = path.split("&", 1)[0].split("=", 1)[0].rstrip("/") or "/"
            path = f"{path}/<已隐藏>" if path != "/" else "/<已隐藏>"
        # Leave no partially encoded token-looking value in the public trace.
        if "%" in path:
            path = "/[路径已隐藏]"
        path = "/".join(
            "<已隐藏>" if len(segment) > 96 and re.fullmatch(r"[A-Za-z0-9._~-]+", segment) else segment
            for segment in path.split("/")
        )
        return f"{parsed.scheme.lower()}://{host}{path}"[:500]
    except Exception:
        return ""


def safe_incident_id(value: Any) -> str:
    candidate = str(value or "").strip().upper()
    if re.fullmatch(r"LOG-\d{8}-[A-Z0-9]{8}", candidate):
        return candidate
    return ""


def safe_debug_task_id(value: Any) -> str:
    """Project a task identifier without retaining email/phone-like input."""
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    candidate = candidate[:160]
    internal = re.fullmatch(
        r"(?i)(?:free|task|batch|camoufox)(?:[-_.:][A-Za-z0-9][A-Za-z0-9_.:-]{0,150})?",
        candidate,
    )
    if internal and not re.search(
        r"(?i)(?:@|https?://|socks5?h?://|\+?\d{8,15})", candidate,
    ):
        return candidate
    return f"task-{fingerprint(candidate)}"


def safe_proxy_fingerprint(provided: Any, proxy: Any = "") -> str:
    """Accept only the runtime's fixed-size hexadecimal proxy fingerprint."""
    candidate = str(provided or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{16}", candidate):
        return candidate
    raw_proxy = str(proxy or "").strip()
    return fingerprint(raw_proxy) if raw_proxy else ""


__all__ = [
    "safe_debug_task_id",
    "safe_event_url",
    "safe_incident_id",
    "safe_proxy_fingerprint",
    "safe_url",
]
