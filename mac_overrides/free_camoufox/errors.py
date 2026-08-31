"""Error classification shared by Camoufox adapters.

This module deliberately does not import the optional Camoufox package.  The
legacy runtime classes are exposed lazily so existing callers can use the
canonical exception identity while the new package remains importable during
preflight and tests.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit


_BROWSER_PROCESS_LOST_MARKERS = (
    "target page, context or browser has been closed",
    "browser has been closed",
    "browser closed",
    "browser disconnected",
    "target closed",
    "connection closed while reading from the driver",
    "playwright connection closed",
)

_TRANSIENT_NAVIGATION_MARKERS = (
    "err_connection_closed",
    "err_connection_reset",
    "err_connection_refused",
    "err_connection_aborted",
    "err_connection_failed",
    "err_timed_out",
    "err_network_changed",
    "err_empty_response",
    "err_socks_connection_failed",
    "err_proxy_connection_failed",
    "ns_error_connection_closed",
    "ns_error_connection_reset",
    "ns_error_connection_refused",
    "ns_error_net_timeout",
    "ns_error_unknown_host",
    "ns_error_proxy_connection_refused",
    "connection refused",
    "connection reset",
    "navigation timeout",
    "page.goto: timeout",
    "timed out",
)


def browser_process_lost(exc: BaseException | Any) -> bool:
    """Return whether an exception indicates the browser process disappeared."""

    message = str(exc or "").casefold()
    return any(marker in message for marker in _BROWSER_PROCESS_LOST_MARKERS)


def is_transient_navigation_error(exc: BaseException | Any) -> bool:
    """Match transport-only failures that may be retried before submission."""

    message = str(exc or "").casefold()
    return any(marker in message for marker in _TRANSIENT_NAVIGATION_MARKERS)


def navigation_failure_category(exc: BaseException | Any) -> str:
    if browser_process_lost(exc):
        return "browser_process_lost"
    message = str(exc or "").casefold()
    if "timeout" in message or "timed out" in message:
        return "navigation_timeout"
    if is_transient_navigation_error(exc):
        return "navigation_transient"
    return "navigation_error"


def navigation_failure_reason(exc: BaseException | Any) -> str:
    message = str(exc or "").casefold()
    if any(item in message for item in (
        "ns_error_connection_refused", "err_connection_refused", "connection refused",
    )):
        return "connection_refused"
    if any(item in message for item in (
        "ns_error_connection_reset", "err_connection_reset", "connection reset",
    )):
        return "connection_reset"
    if any(item in message for item in (
        "ns_error_net_timeout", "err_timed_out", "timed out", "navigation timeout",
    )):
        return "timeout"
    if any(item in message for item in (
        "ns_error_unknown_host", "err_name_not_resolved",
    )):
        return "name_resolution"
    if any(item in message for item in (
        "err_proxy_connection_failed", "ns_error_proxy_connection_refused",
    )):
        return "proxy_connection_failed"
    return ""


def navigation_diagnostic(exc: BaseException | Any, safe_page: str = "") -> str:
    """Create a bounded diagnostic from exception type and safe page URL only."""

    category = navigation_failure_category(exc)
    reason = navigation_failure_reason(exc)
    exception_type = type(exc).__name__[:80] or "UnknownError"
    reason_field = f"; reason={reason}" if reason else ""
    page = _safe_page_value(safe_page)
    return f"category={category}; exception_type={exception_type}{reason_field}; safe_page={page}"


def _safe_page_value(value: Any) -> str:
    """Keep only an origin/path; never expose OAuth query parameters."""

    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            path = parsed.path or "/"
            # Unknown hosts are represented without a path because provider
            # routes may contain mailbox/token material.
            trusted = (
                host.casefold() == "chatgpt.com"
                or host.casefold().endswith(".chatgpt.com")
                or host.casefold() == "openai.com"
                or host.casefold().endswith(".openai.com")
            )
            if not trusted:
                path = "/[路径已隐藏]"
            path = re.sub(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "<邮箱>", path)
            path = re.sub(r"(?<!\d)\+?\d{8,15}(?!\d)", "<手机号>", path)
            if "?" in path or "#" in path:
                path = re.split(r"[?#]", path, maxsplit=1)[0] or "/"
            return f"{parsed.scheme.lower()}://{host}{path}"[:500]
    except Exception:
        pass
    return "页面地址未知"


def mark_recycle_required(error: BaseException, reason: str = "") -> BaseException:
    """Attach pool recovery intent without changing the public error schema."""

    try:
        setattr(error, "recycle_required", True)
        if reason:
            setattr(error, "recycle_reason", str(reason)[:240])
    except Exception:
        pass
    return error


def __getattr__(name: str) -> Any:
    """Resolve legacy exception classes only when a caller asks for them."""

    if name in {"CamoufoxBrowserError", "CamoufoxDependencyError"}:
        try:
            from .. import free_camoufox_runtime
        except ImportError:  # pragma: no cover - top-level recovery import
            import free_camoufox_runtime  # type: ignore
        return getattr(free_camoufox_runtime, name)
    raise AttributeError(name)


__all__ = [
    "CamoufoxBrowserError",
    "CamoufoxDependencyError",
    "browser_process_lost",
    "is_transient_navigation_error",
    "navigation_diagnostic",
    "navigation_failure_category",
    "navigation_failure_reason",
    "mark_recycle_required",
]
