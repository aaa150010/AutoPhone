"""Pure parsing and normalization helpers for the Free proxy pool.

Split out of ``free_proxy_store.py``; the original module re-exports every
name (including the private ones its tests import) for compatibility.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import quote, unquote, urlsplit, urlunsplit

try:
    from .free_register_common import (
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeRegisterError,
        fingerprint,
        normalize_proxy_value,
    )
    from .free_proxy_numeric import safe_int as _safe_int
except ImportError:  # pragma: no cover - top-level recovery import
    from free_register_common import (  # type: ignore[no-redef]
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeRegisterError,
        fingerprint,
        normalize_proxy_value,
    )
    from free_proxy_numeric import safe_int as _safe_int  # type: ignore[no-redef]


SUPPORTED_FREE_DRIVERS = frozenset({"protocol", "camoufox"})
DEFAULT_PROXY_COUNTRY = "ZZ"
DEFAULT_PROXY_GROUP = "默认组"
SINGLE_POOL_COUNTRY = ""
SINGLE_POOL_GROUP = ""
DEFAULT_PROXY_PROBE_URL = "https://chatgpt.com/"
_LEGACY_PROBE_HOST = "ipinfo.io"
_LEGACY_EXIT_IP_HOST = "api.ipify.org"
_PROBE_BODY_LIMIT = 4096

PROXY_COUNTRY_PATTERN = re.compile(
    r"(?:^|[-_.])(?:region|country|res|area|dc|res_sc)-([A-Za-z]{2})(?:[-_.:]|$)",
    re.IGNORECASE,
)


def _normalize_driver(value: Any) -> str:
    """Validate a Free driver before touching proxy-pool state.

    The driver is part of the public allocation contract even though the
    supported drivers currently share one pool.  Keeping validation in this
    module prevents removed or unknown transports from accidentally reading,
    probing, or leasing proxy rows through a compatibility query.
    """
    candidate = str(value or "protocol").strip().lower()
    if candidate not in SUPPORTED_FREE_DRIVERS:
        raise FreeRegisterError(
            "free_config",
            "校验 Free 注册链路",
            "Free 注册链路只能选择全协议或 Camoufox",
            retryable=False,
            error_code="free_driver_unsupported",
        )
    return candidate


def normalize_country(value: Any) -> str:
    candidate = str(value or "").strip().upper()
    return candidate if re.fullmatch(r"[A-Z]{2}", candidate) else DEFAULT_PROXY_COUNTRY


def infer_country(username: Any, host: Any = "") -> str:
    for candidate in (username, host):
        match = PROXY_COUNTRY_PATTERN.search(str(candidate or ""))
        if match:
            return match.group(1).upper()
    return DEFAULT_PROXY_COUNTRY


def normalize_group(value: Any) -> str:
    return " ".join(str(value or "").split())[:64] or DEFAULT_PROXY_GROUP


def _percentile(values: Iterable[int], percentile: float) -> int | None:
    samples = sorted(max(0, int(value)) for value in values)
    if not samples:
        return None
    index = min(len(samples) - 1, max(0, int(round((len(samples) - 1) * percentile))))
    return samples[index]


def _parse(value: Any, default_scheme: str) -> tuple[str, Any] | None:
    normalized = normalize_proxy_value(value, default_scheme=default_scheme)
    if not normalized:
        return None
    try:
        parsed = urlsplit(normalized)
        scheme = parsed.scheme.lower()
        if scheme not in FREE_PROXY_SCHEMES or not parsed.hostname or not parsed.port:
            return None
        return normalized, parsed
    except ValueError:
        return None


def _identity(parsed: Any) -> str:
    username = unquote(str(parsed.username or ""))
    password = unquote(str(parsed.password or ""))
    host = str(parsed.hostname or "").lower()
    return f"{host}\x00{int(parsed.port or 0)}\x00{username}\x00{password}"


def _proxy_url(record: Mapping[str, Any]) -> str:
    scheme = str(record.get("scheme") or DEFAULT_FREE_PROXY_SCHEME).lower()
    if scheme not in FREE_PROXY_SCHEMES:
        scheme = DEFAULT_FREE_PROXY_SCHEME
    host = str(record.get("host") or "").strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = _safe_int(record.get("port"), default=0, minimum=1, maximum=65535) or 0
    username = quote(str(record.get("username") or ""), safe="")
    password = quote(str(record.get("password") or ""), safe="")
    auth = f"{username}:{password}@" if username or password else ""
    return urlunsplit((scheme, f"{auth}{host}:{port}", "", "", ""))


def _exception_text(error: BaseException) -> str:
    """Collect a short, credential-free description from an exception chain."""
    values: list[str] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(values) < 4:
        seen.add(id(current))
        text = str(current or "").strip()
        if text:
            values.append(text[:240])
        current = current.__cause__ or current.__context__
    return " | ".join(values)


def _is_tls_compatibility_error(error: BaseException) -> bool:
    """Only certificate validation errors qualify for compatibility retry."""
    name = type(error).__name__.lower()
    text = _exception_text(error).lower()
    # Authentication/authorization failures are also often wrapped as a
    # curl-cffi ProxyError.  They cannot be fixed by disabling certificate
    # verification, so do not spend a second request on them.
    auth_markers = (
        "407", "proxy authentication", "authentication required",
        "auth failed", "invalid username", "invalid password",
        "unauthorized", "forbidden",
    )
    if any(marker in text for marker in auth_markers):
        return False
    if any(marker in text for marker in ("wrong_version_number", "wrong version number", "proxy protocol", "socks handshake", "proxy connect", "connect tunnel")):
        return False
    markers = (
        "certificate verify failed", "certificate_verify_failed", "cert verify",
        "self signed certificate", "unable to get local issuer", "curl: (60)", "curl: (77)",
    )
    if name in {"sslerror", "certificateverifyerror"}:
        return any(marker in text for marker in markers)
    return any(marker in text for marker in markers)


def normalize_probe_url(value: Any) -> str:
    """Normalize legacy probe settings without treating them as IP checks."""
    candidate = str(value or "").strip()
    if not candidate:
        return DEFAULT_PROXY_PROBE_URL
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return candidate
    # Older Free builds used ipinfo.io/ip as their implicit default. Keep
    # explicit JSON and other user-supplied URLs unchanged; migrate only this
    # exact legacy default to the normal connectivity target.
    if (
        parsed.scheme in {"http", "https"}
        and str(parsed.hostname or "").lower() == _LEGACY_PROBE_HOST
        and parsed.path.rstrip("/") == "/ip"
        and not parsed.query
        and not parsed.fragment
    ):
        return DEFAULT_PROXY_PROBE_URL
    if (
        parsed.scheme in {"http", "https"}
        and str(parsed.hostname or "").lower() == _LEGACY_EXIT_IP_HOST
        and parsed.path.rstrip("/") in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    ):
        return DEFAULT_PROXY_PROBE_URL
    return candidate


_CHATGPT_PROBE_HOSTS = frozenset({"chatgpt.com", "chat.openai.com"})


def _is_chatgpt_probe_target(value: Any) -> bool:
    """Return whether a probe URL is an OpenAI/ChatGPT edge target.

    Keep this allow-list narrow: a 401/403 from an arbitrary user-supplied
    endpoint is still a failed health probe, while the default ChatGPT edge
    commonly rejects unauthenticated requests even when the proxy works.
    """
    try:
        host = str(urlsplit(normalize_probe_url(value)).hostname or "").lower().rstrip(".")
    except (TypeError, ValueError):
        return False
    return host in _CHATGPT_PROBE_HOSTS or host.endswith(".chatgpt.com")


def _candidate_probe_ip(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    return str(parsed)


def _extract_probe_ip(payload: Any) -> str:
    """Read an exit IP from plain text or a small JSON object.

    ipify's text endpoint and the historical ipinfo JSON endpoint are both
    used by existing configurations.  Keep the accepted shape deliberately
    narrow so an arbitrary successful proxy response is not treated as an IP.
    """
    if isinstance(payload, (bytes, bytearray, memoryview)):
        text = bytes(payload)[:_PROBE_BODY_LIMIT].decode("utf-8", "ignore").strip()
    else:
        text = str(payload or "")[:_PROBE_BODY_LIMIT].strip()
    direct = _candidate_probe_ip(text)
    if direct:
        return direct
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    pending: list[Any] = [parsed]
    seen: set[int] = set()
    while pending and len(seen) < 32:
        current = pending.pop(0)
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            for key in ("ip", "query", "address", "client_ip"):
                candidate = _candidate_probe_ip(current.get(key))
                if candidate:
                    return candidate
            pending.extend(value for value in current.values() if isinstance(value, (Mapping, list, tuple)))
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
    raise ValueError("代理探测响应格式无效")


def _record_from_url(value: str, *, country: Any, group: Any, source_label: Any = "") -> dict[str, Any] | None:
    parsed_result = _parse(value, DEFAULT_FREE_PROXY_SCHEME)
    if parsed_result is None:
        return None
    normalized, parsed = parsed_result
    username = unquote(str(parsed.username or ""))
    password = unquote(str(parsed.password or ""))
    proxy_id = fingerprint(_identity(parsed))
    return {
        "proxy_id": proxy_id,
        "host": str(parsed.hostname or ""),
        "port": int(parsed.port or 0),
        "username": username,
        "password": password,
        "scheme": str(parsed.scheme or DEFAULT_FREE_PROXY_SCHEME).lower(),
        "effective_scheme": str(parsed.scheme or DEFAULT_FREE_PROXY_SCHEME).lower(),
        # Keep legacy arguments for callers, but persist one shared pool.
        "country": SINGLE_POOL_COUNTRY,
        "group": SINGLE_POOL_GROUP,
        "enabled": True,
        "status": "unknown",
        "lease_owner": "",
        "lease_until": None,
        "lease_batch_id": "",
        "lease_task_id": "",
        "leases": [],
        "last_checked_at": None,
        # Last upstream status is diagnostic metadata only; it never contains
        # response bodies or proxy credentials.
        "last_probe_http_status": None,
        "last_exit_ip": "",
        "latency_ms": None,
        "last_chatgpt_login_checked_at": None,
        "last_chatgpt_login_status": 0,
        "last_chatgpt_login_probe_mode": "",
        "consecutive_failures": 0,
        "quarantined_until": None,
        "last_failure": None,
        "last_probe_ok": None,
        "source_label": str(source_label or "").strip()[:40],
        "probe_attempts": 0,
        "probe_successes": 0,
        "probe_latencies_ms": [],
        "_identity": _identity(parsed),
        "_normalized": normalized,
    }


__all__ = [
    "DEFAULT_PROXY_COUNTRY",
    "DEFAULT_PROXY_GROUP",
    "DEFAULT_PROXY_PROBE_URL",
    "PROXY_COUNTRY_PATTERN",
    "SINGLE_POOL_COUNTRY",
    "SINGLE_POOL_GROUP",
    "SUPPORTED_FREE_DRIVERS",
    "infer_country",
    "normalize_country",
    "normalize_group",
    "normalize_probe_url",
    "_candidate_probe_ip",
    "_exception_text",
    "_extract_probe_ip",
    "_identity",
    "_is_chatgpt_probe_target",
    "_is_tls_compatibility_error",
    "_normalize_driver",
    "_parse",
    "_percentile",
    "_proxy_url",
    "_record_from_url",
]
