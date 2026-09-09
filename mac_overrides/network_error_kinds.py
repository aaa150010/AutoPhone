"""Shared network-error marker tables for OpenAI-facing connectivity classifiers.

Three classifiers consume these tables with different output contracts: the
auth runtime maps markers to OpenAI reason codes, the diagnostics probe maps
them to probe reason codes, and the quota runtime maps them to user labels.
Keeping one marker source prevents the rule sets from drifting apart again.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "classify_network_error_kind",
    "stop_event_is_set",
]


# Marker tables ordered from most specific to most generic. Each entry is
# (category, markers). Categories are consumed by the three classifier
# domains and mapped to their own reason codes / labels.
_NETWORK_ERROR_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "proxy_connect",
        (
            "proxyerror",
            "proxy error",
            "proxy connect",
            "proxy_connect_failed",
            "unable to connect to proxy",
            "proxy connect aborted",
            "proxy connection",
        ),
    ),
    (
        "dns",
        (
            "name resolution",
            "could not resolve",
            "nodename nor servname",
            "getaddrinfo",
            "could not resolve host",
        ),
    ),
    (
        "tls",
        (
            "certificate verify",
            "sslerror",
            "ssleoferror",
            "ssl handshake",
            "tls handshake",
            "tls connect",
            "handshake failure",
            "curl: (35)",
            "curl (35)",
        ),
    ),
    (
        "read_timeout",
        ("read timed out", "readtimeout", "timed out reading"),
    ),
    (
        "connect_timeout",
        (
            "connecttimeout",
            "connect timeout",
            "connection timeout",
            "connection timed out",
            "timed out while connecting",
            "operation timed out",
            "curl: (28)",
            "curl (28)",
        ),
    ),
    (
        "remote_disconnect",
        (
            "connection reset",
            "remote disconnected",
            "remotedisconnected",
            "connection aborted",
            "unexpected eof",
            "connection closed",
            "remote end closed connection",
            "server disconnected",
            "curl: (56)",
            "curl (56)",
        ),
    ),
    (
        "connect_failure",
        (
            "connectionerror",
            "failed to connect",
            "connection refused",
            "network is unreachable",
            "no route to host",
            "curl: (6)",
            "curl (6)",
            "curl: (7)",
            "curl (7)",
        ),
    ),
)


def _error_text(value: Any) -> str:
    if value is None:
        return ""
    text = f"{type(value).__name__}: {value}".lower()
    return text


def classify_network_error_kind(value: Any) -> str | None:
    """Return the shared category for a network error, or ``None``.

    ``connect_timeout`` also covers the generic word ``timeout`` only when a
    more specific read/connect marker did not match first, mirroring the
    historical per-domain fallbacks.
    """
    text = _error_text(value)
    if not text:
        return None
    for category, markers in _NETWORK_ERROR_CATEGORIES:
        if any(marker in text for marker in markers):
            return category
    if "timeout" in text or "timed out" in text:
        return "connect_timeout"
    return None


def stop_event_is_set(stop_event: Any) -> bool:
    """Shared stop-event predicate for gate loops and wait helpers."""
    if stop_event is None:
        return False
    checker = getattr(stop_event, "is_set", None)
    if callable(checker):
        return bool(checker())
    return bool(stop_event()) if callable(stop_event) else bool(stop_event)
