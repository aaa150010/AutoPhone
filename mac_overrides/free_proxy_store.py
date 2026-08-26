"""Structured proxy resources for the isolated Free registration center.

The public surface deliberately keeps credentials out of every response.  The
private JSON file is mode 0600 and is only read by the Free workers.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import copy
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import socket
import threading
import time
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote, unquote, urlsplit, urlunsplit

try:
    from .free_register_common import (
        DEFAULT_SOCKS5_DNS_MODE,
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        normalize_proxy_value,
        proxy_transport_value,
        proxy_error_code,
        proxy_error_label,
        proxy_error_detail,
        safe_log_message,
    )
except ImportError:
    from free_register_common import (  # type: ignore[no-redef]
        DEFAULT_SOCKS5_DNS_MODE,
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        normalize_proxy_value,
        proxy_transport_value,
        proxy_error_code,
        proxy_error_label,
        proxy_error_detail,
        safe_log_message,
    )

try:
    from .free_proxy_http import get_via_proxy
    from .free_proxy_chatgpt import probe_chatgpt_login
except ImportError:
    from free_proxy_http import get_via_proxy  # type: ignore[no-redef]
    from free_proxy_chatgpt import probe_chatgpt_login  # type: ignore[no-redef]

try:
    from .free_proxy_numeric import safe_float as _safe_float, safe_int as _safe_int
except ImportError:
    from free_proxy_numeric import safe_float as _safe_float, safe_int as _safe_int  # type: ignore[no-redef]

try:
    from .free_proxy_health import is_proxy_health_failure
except ImportError:
    from free_proxy_health import is_proxy_health_failure  # type: ignore[no-redef]


SUPPORTED_ROXY_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})
PROXY_STATUSES = frozenset({"unknown", "available", "quarantined"})
PROXY_ALLOCATION_MODES = frozenset({"healthy_random"})
DEFAULT_PROXY_COUNTRY = "ZZ"
DEFAULT_PROXY_GROUP = "默认组"
SINGLE_POOL_COUNTRY = ""
SINGLE_POOL_GROUP = ""
# Manual connectivity diagnostics use a normal HTTP target.  The target is
# never consulted by automatic registration binding and its response is not
# interpreted as an account or exit-IP assertion.
DEFAULT_PROXY_PROBE_URL = "https://chatgpt.com/"
CHATGPT_LOGIN_PROBE_URL = "https://chatgpt.com/login"
PROXY_COUNTRY_PATTERN = re.compile(
    r"(?:^|[-_.])(?:region|country|res|area|dc|res_sc)-([A-Za-z]{2})(?:[-_.:]|$)",
    re.IGNORECASE,
)


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


_PROBE_BODY_LIMIT = 4096
_LEGACY_PROBE_HOST = "ipinfo.io"
_LEGACY_EXIT_IP_HOST = "api.ipify.org"


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


@dataclass(frozen=True, slots=True)
class FreeProxyLease:
    proxy_id: str
    proxy: str
    masked: str
    fingerprint: str
    scheme: str
    country: str
    group: str
    exit_ip: str = ""

    def binding(self) -> ProxyBinding:
        return ProxyBinding(
            self.proxy,
            self.fingerprint,
            self.masked,
            self.exit_ip,
            proxy_id=self.proxy_id,
            scheme=self.scheme,
            country=self.country,
            group=self.group,
        )


class FreeProxyPool:
    """Structured Free proxy pool with compatibility methods for old callers."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        default_scheme: str = DEFAULT_FREE_PROXY_SCHEME,
        failure_threshold: int = 2,
        quarantine_seconds: int = 600,
        # Keep direct/legacy manager callers on the historic no-extra-probe
        # path.  The production Free config supplies its explicit 300-second
        # TTL when it is normalized by FreeConfigStore.
        health_probe_ttl_seconds: int = 0,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = self.data_dir / "free_proxy_pool.json"
        self.legacy_path = self.data_dir / "free_proxy_pool.txt"
        scheme = str(default_scheme or DEFAULT_FREE_PROXY_SCHEME).strip().lower()
        self.default_scheme = scheme if scheme in FREE_PROXY_SCHEMES else DEFAULT_FREE_PROXY_SCHEME
        self.failure_threshold = max(1, int(failure_threshold))
        self.quarantine_seconds = max(1, int(quarantine_seconds))
        self.health_probe_ttl_seconds = max(0, int(health_probe_ttl_seconds))
        self.proxy_tls_verify = True
        self.proxy_tls_compat_fallback = True
        # Keep the low-level compatibility default strict. Production Free
        # config passes ``auto`` explicitly; direct legacy callers and test
        # probes must receive the declared URL unchanged.
        self.socks5_dns_mode = "declared"
        self.allocation_mode = "healthy_random"
        # Ephemeral metadata for the most recent explicit/manual bind.  It is
        # intentionally not persisted and never contains an observed exit IP.
        self._last_bind_diagnostics: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    def _load(self) -> list[dict[str, Any]]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            payload = None
        raw_rows = payload.get("proxies") if isinstance(payload, Mapping) else None
        if not isinstance(raw_rows, list):
            raw_rows = []
        rows = [self._normalize_record(row) for row in raw_rows if isinstance(row, Mapping)]
        rows = [row for row in rows if row is not None]
        if rows or self.path.exists():
            version = _safe_int(payload.get("version"), default=0, minimum=0) if isinstance(payload, Mapping) else 0
            if rows and version < 4:
                self._save(rows)
            return rows
        if self.legacy_path.exists():
            try:
                content = self.legacy_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                content = ""
            migrated = self._parse_lines(content, country=SINGLE_POOL_COUNTRY, group=SINGLE_POOL_GROUP, scheme=self.default_scheme)
            if migrated:
                self._save(migrated)
            return migrated
        return []

    def _normalize_record(self, value: Mapping[str, Any]) -> dict[str, Any] | None:
        try:
            parsed = _parse(
                str(value.get("proxy") or _proxy_url(value) or ""),
                str(value.get("scheme") or self.default_scheme),
            )
        except (TypeError, ValueError):
            parsed = None
        if parsed is None:
            return None
        normalized, url_parts = parsed
        username = unquote(str(url_parts.username or value.get("username") or ""))
        password = unquote(str(url_parts.password or value.get("password") or ""))
        leases = self._normalize_leases(value)
        port = _safe_int(url_parts.port or value.get("port"), default=0, minimum=1, maximum=65535) or 0
        record = {
            "proxy_id": str(value.get("proxy_id") or fingerprint(_identity(url_parts))),
            "host": str(url_parts.hostname or value.get("host") or ""),
            "port": port,
            "username": username,
            "password": password,
            "scheme": str(url_parts.scheme or value.get("scheme") or self.default_scheme).lower(),
            # Preserve the transport scheme observed by the last probe. Older
            # records did not have this field, so the declared scheme is the
            # correct migration fallback.
            "effective_scheme": str(value.get("effective_scheme") or url_parts.scheme or self.default_scheme).lower(),
            "country": SINGLE_POOL_COUNTRY,
            "group": SINGLE_POOL_GROUP,
            "enabled": bool(value.get("enabled", True)),
            "status": str(value.get("status") or "unknown") if str(value.get("status") or "unknown") in PROXY_STATUSES else "unknown",
            "lease_owner": str(value.get("lease_owner") or ""),
            "lease_until": value.get("lease_until"),
            "lease_batch_id": str(value.get("lease_batch_id") or ""),
            "lease_task_id": str(value.get("lease_task_id") or ""),
            "leases": leases,
            "last_checked_at": _safe_float(value.get("last_checked_at"), minimum=0),
            "last_exit_ip": str(value.get("last_exit_ip") or ""),
            "latency_ms": _safe_int(value.get("latency_ms"), default=None, minimum=0),
            "last_chatgpt_login_checked_at": _safe_float(value.get("last_chatgpt_login_checked_at"), minimum=0),
            "last_chatgpt_login_status": _safe_int(value.get("last_chatgpt_login_status"), default=0, minimum=0, maximum=999) or 0,
            "last_chatgpt_login_probe_mode": str(value.get("last_chatgpt_login_probe_mode") or ""),
            "consecutive_failures": _safe_int(value.get("consecutive_failures"), default=0, minimum=0) or 0,
            "quarantined_until": (
                None if value.get("quarantined_until") is None
                else _safe_float(value.get("quarantined_until"), default=0, minimum=0)
            ),
            "last_failure": copy.deepcopy(value.get("last_failure")) if isinstance(value.get("last_failure"), Mapping) else None,
            "last_probe_ok": value.get("last_probe_ok") if isinstance(value.get("last_probe_ok"), bool) else None,
            "last_probe_mode": str(value.get("last_probe_mode") or ""),
            "source_label": str(value.get("source_label") or value.get("provider") or "").strip()[:40],
            "probe_attempts": _safe_int(value.get("probe_attempts"), default=0, minimum=0) or 0,
            "probe_successes": _safe_int(value.get("probe_successes"), default=0, minimum=0) or 0,
            "probe_latencies_ms": [
                max(0, int(item)) for item in (value.get("probe_latencies_ms") or [])
                if isinstance(item, (int, float)) and not isinstance(item, bool)
            ][-50:],
            "_identity": _identity(url_parts),
            "_normalized": normalized,
        }
        self._sync_lease_compat(record)
        return record if record["host"] and record["port"] > 0 else None

    @staticmethod
    def _normalize_leases(value: Mapping[str, Any]) -> list[dict[str, Any]]:
        leases: list[dict[str, Any]] = []
        raw_leases = value.get("leases")
        if isinstance(raw_leases, list):
            for raw in raw_leases:
                if not isinstance(raw, Mapping):
                    continue
                owner = str(raw.get("owner") or "").strip()
                task_id = str(raw.get("task_id") or "").strip()
                until = _safe_float(raw.get("until"), default=0, minimum=0) or 0
                if not owner or until <= 0:
                    continue
                leases.append({
                    "owner": owner,
                    "batch_id": str(raw.get("batch_id") or ""),
                    "task_id": task_id,
                    "until": until,
                })
        legacy_owner = str(value.get("lease_owner") or "").strip()
        legacy_until = _safe_float(value.get("lease_until"), default=0, minimum=0) or 0
        if legacy_owner and legacy_until > 0 and not any(lease["owner"] == legacy_owner for lease in leases):
            leases.append({
                "owner": legacy_owner,
                "batch_id": str(value.get("lease_batch_id") or ""),
                "task_id": str(value.get("lease_task_id") or ""),
                "until": legacy_until,
            })
        return leases

    @staticmethod
    def _active_leases(row: Mapping[str, Any], now: float | None = None) -> list[dict[str, Any]]:
        current_time = time.time() if now is None else now
        values = row.get("leases")
        if not isinstance(values, list):
            return []
        active = []
        for lease in values:
            if not isinstance(lease, Mapping):
                continue
            until = _safe_float(lease.get("until"), default=0, minimum=0) or 0
            valid = bool(lease.get("owner")) and until > current_time
            if valid:
                active.append({**lease, "until": until})
        return active

    @classmethod
    def _sync_lease_compat(cls, row: dict[str, Any], now: float | None = None) -> None:
        active = cls._active_leases(row, now)
        row["leases"] = active
        if active:
            latest = max(active, key=lambda lease: float(lease.get("until") or 0))
            row.update({
                "lease_owner": str(latest.get("owner") or ""),
                "lease_until": float(latest.get("until") or 0),
                "lease_batch_id": str(latest.get("batch_id") or ""),
                "lease_task_id": str(latest.get("task_id") or ""),
            })
        else:
            row.update({"lease_owner": "", "lease_until": None, "lease_batch_id": "", "lease_task_id": ""})

    def _save(self, rows: Iterable[Mapping[str, Any]]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = []
        for row in rows:
            value = dict(row)
            self._sync_lease_compat(value)
            value.pop("_identity", None)
            value.pop("_normalized", None)
            payload.append(value)
        atomic_write(self.path, {"version": 4, "proxies": payload})

    def _parse_lines(self, content: str, *, country: Any, group: Any, scheme: str, source_label: Any = "") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        selected_scheme = str(scheme or self.default_scheme).strip().lower()
        if selected_scheme not in FREE_PROXY_SCHEMES:
            selected_scheme = self.default_scheme
        for raw in str(content or "").splitlines():
            text = str(raw or "").strip()
            if not text:
                continue
            parsed_value = _parse(text, selected_scheme)
            if parsed_value is None:
                continue
            normalized, parsed = parsed_value
            record = _record_from_url(normalized, country=country, group=group, source_label=source_label)
            if record is None:
                continue
            identity = str(record["_identity"])
            if identity in seen:
                continue
            seen.add(identity)
            rows.append(record)
        return rows

    def import_text(
        self,
        content: str,
        *,
        country: str | None = None,
        group: str | None = None,
        scheme: str | None = None,
        source_label: str | None = None,
        provider: str | None = None,
    ) -> int:
        incoming = self._parse_lines(
            content,
            country=SINGLE_POOL_COUNTRY,
            group=SINGLE_POOL_GROUP,
            scheme=scheme or self.default_scheme,
            source_label=source_label or provider or "",
        )
        if not incoming:
            raise FreeRegisterError("free_proxy_pool", "Free 代理池", "Free 代理池没有有效代理")
        with self._lock:
            existing = self._load()
            by_identity = {str(row.get("_identity")): row for row in existing}
            added = 0
            for row in incoming:
                current = by_identity.get(str(row["_identity"]))
                if current is None:
                    by_identity[str(row["_identity"])] = row
                    added += 1
                    continue
                current["scheme"] = row["scheme"]
                current["country"] = SINGLE_POOL_COUNTRY
                current["group"] = SINGLE_POOL_GROUP
                current["enabled"] = True
                if source_label or provider:
                    current["source_label"] = str(source_label or provider or "").strip()[:40]
                if current.get("status") == "quarantined" and self._quarantine_expired(current):
                    current["status"] = "unknown"
            self._save(by_identity.values())
            return added

    def configure_policy(
        self,
        *,
        failure_threshold: int | None = None,
        quarantine_seconds: int | None = None,
        health_probe_ttl_seconds: int | None = None,
        tls_verify: bool | None = None,
        tls_compat_fallback: bool | None = None,
        socks5_dns_mode: str | None = None,
        allocation_mode: str | None = None,
    ) -> None:
        self.failure_threshold = max(1, int(failure_threshold or self.failure_threshold))
        self.quarantine_seconds = max(1, int(quarantine_seconds or self.quarantine_seconds))
        if health_probe_ttl_seconds is not None:
            self.health_probe_ttl_seconds = max(0, int(health_probe_ttl_seconds))
        if tls_verify is not None:
            self.proxy_tls_verify = bool(tls_verify)
        if tls_compat_fallback is not None:
            self.proxy_tls_compat_fallback = bool(tls_compat_fallback)
        if socks5_dns_mode is not None:
            mode = str(socks5_dns_mode or DEFAULT_SOCKS5_DNS_MODE).strip().lower()
            self.socks5_dns_mode = mode if mode in {"declared", "local", "remote", "auto"} else DEFAULT_SOCKS5_DNS_MODE
        # ``exclusive`` was the old policy. Accept it for compatibility but
        # always run the shared AutoRegister-style allocator.
        self.allocation_mode = "healthy_random"

    def _quarantine_expired(self, row: Mapping[str, Any], now: float | None = None) -> bool:
        until = row.get("quarantined_until")
        if until is None:
            return False
        normalized = _safe_float(until, default=0, minimum=0) or 0
        return normalized <= (time.time() if now is None else now)

    def _probe_is_stale(self, row: Mapping[str, Any], now: float | None = None) -> bool:
        """Return whether a persisted health result needs one bounded refresh."""
        ttl = max(0, int(self.health_probe_ttl_seconds or 0))
        if ttl <= 0:
            return False
        checked = _safe_float(row.get("last_checked_at"), default=0, minimum=0) or 0
        return row.get("last_probe_ok") is False or not checked or checked + ttl <= (time.time() if now is None else now)

    def _eligible(self, *, country: str | None = None, group: str | None = None, driver: str = "protocol", now: float | None = None) -> list[dict[str, Any]]:
        current_time = time.time() if now is None else now
        rows: list[dict[str, Any]] = []
        for row in self._load():
            if not row.get("enabled"):
                continue
            if row.get("status") == "quarantined" and not self._quarantine_expired(row, current_time):
                continue
            if driver == "roxybrowser" and str(row.get("scheme") or "").lower() not in SUPPORTED_ROXY_SCHEMES:
                continue
            rows.append(row)
        return rows

    def values(self, content: str = "") -> list[str]:
        with self._lock:
            rows = self._parse_lines(content, country=SINGLE_POOL_COUNTRY, group=SINGLE_POOL_GROUP, scheme=self.default_scheme) if str(content or "").strip() else self._load()
            return [_proxy_url(row) for row in rows]

    def entries(self) -> list[dict[str, Any]]:
        """Compatibility view used by the existing Free manager."""
        with self._lock:
            return copy.deepcopy(self._load())

    def available(self, count: int, *, country: str | None = None, group: str | None = None, driver: str = "protocol") -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._eligible(country=country, group=group, driver=driver)[:max(0, int(count))])

    def records(self, *, country: str | None = None, group: str | None = None, driver: str = "protocol") -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._eligible(country=country, group=group, driver=driver))

    def public(self) -> dict[str, Any]:
        with self._lock:
            rows = self._load()
            return {
                "count": len(rows),
                "allocation_mode": self.allocation_mode,
                "rows": [self._public_row(row, index) for index, row in enumerate(rows, 1)],
                "groups": self.group_summaries(),
                "countries": self.country_summaries(),
            }

    def _public_row(self, row: Mapping[str, Any], index: int | None = None) -> dict[str, Any]:
        leases = self._active_leases(row)
        configured_scheme = str(row.get("scheme") or self.default_scheme)
        latency_samples = [
            max(0, int(item)) for item in (row.get("probe_latencies_ms") or [])
            if isinstance(item, (int, float)) and not isinstance(item, bool)
        ]
        attempts = max(0, int(row.get("probe_attempts") or 0))
        successes = max(0, min(attempts, int(row.get("probe_successes") or 0)))
        value = {
            "proxy_id": row.get("proxy_id", ""),
            "index": index,
            "masked": mask_proxy(_proxy_url(row)),
            "fingerprint": str(row.get("proxy_id") or ""),
            "scheme": configured_scheme,
            # Public metadata reflects the declared scheme. Protocol
            # requests must not silently switch SOCKS5 to SOCKS5H.
            "protocol_scheme": configured_scheme,
            "roxy_scheme": "SOCKS5" if configured_scheme in {"socks5", "socks5h"} else configured_scheme.upper() if configured_scheme in {"http", "https"} else "",
            "country": SINGLE_POOL_COUNTRY,
            "group": SINGLE_POOL_GROUP,
            "enabled": bool(row.get("enabled", True)),
            "status": row.get("status", "unknown"),
            "lease_until": max((float(lease.get("until") or 0) for lease in leases), default=None),
            "active_lease_count": len(leases),
            "last_checked_at": row.get("last_checked_at"),
            "latency_ms": row.get("latency_ms"),
            "last_chatgpt_login_checked_at": row.get("last_chatgpt_login_checked_at"),
            "last_chatgpt_login_status": int(row.get("last_chatgpt_login_status") or 0),
            "last_chatgpt_login_probe_mode": row.get("last_chatgpt_login_probe_mode", ""),
            "consecutive_failures": int(row.get("consecutive_failures") or 0),
            "last_probe_mode": row.get("last_probe_mode", ""),
            "last_probe_ok": row.get("last_probe_ok"),
            "source_label": str(row.get("source_label") or "")[:40],
            "probe_attempts": attempts,
            "probe_successes": successes,
            "probe_success_rate": round(successes / attempts, 4) if attempts else None,
            "p50_latency_ms": _percentile(latency_samples, 0.50),
            "p95_latency_ms": _percentile(latency_samples, 0.95),
            "effective_scheme": str(row.get("effective_scheme") or configured_scheme),
        }
        return value

    def group_summaries(self) -> list[dict[str, Any]]:
        rows = self._load()
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        now = time.time()
        for row in rows:
            key = (SINGLE_POOL_COUNTRY, SINGLE_POOL_GROUP)
            current = grouped.setdefault(key, {"country": key[0], "group": key[1], "total": 0, "enabled": 0, "available": 0, "leased": 0, "leased_proxies": 0, "quarantined": 0, "schemes": set()})
            current["total"] += 1
            current["enabled"] += int(bool(row.get("enabled")))
            active_leases = self._active_leases(row, now)
            current["leased"] += len(active_leases)
            current["leased_proxies"] += int(bool(active_leases))
            if row.get("status") == "quarantined" and not self._quarantine_expired(row, now):
                current["quarantined"] += 1
            elif row.get("enabled"):
                # Shared allocation keeps a healthy proxy dispatchable while
                # another task owns a separate lease for the same resource.
                current["available"] += 1
            current["schemes"].add(str(row.get("scheme") or self.default_scheme))
        return [
            {**value, "schemes": sorted(value["schemes"])}
            for _key, value in sorted(grouped.items())
        ]

    def country_summaries(self) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, int]] = {}
        for value in self.group_summaries():
            current = grouped.setdefault(value["country"], {"total": 0, "enabled": 0, "available": 0, "quarantined": 0, "leased": 0, "leased_proxies": 0})
            for key in ("total", "enabled", "available", "quarantined", "leased", "leased_proxies"):
                current[key] += int(value[key])
        return [{"country": country, **values} for country, values in sorted(grouped.items())]

    @staticmethod
    def _probe(
        proxy: str,
        target: str,
        *,
        verify: bool = True,
        socks5_dns_mode: str = "declared",
    ) -> str:
        target = normalize_probe_url(target)
        # Manual diagnostics honor the pool's configured DNS policy while
        # retaining the declared scheme in storage and public metadata.
        transport_proxy = proxy_transport_value(proxy, driver="probe", socks5_dns_mode=socks5_dns_mode)
        if not transport_proxy:
            raise ValueError("代理格式无效")
        with _without_proxy_environment():
            response = get_via_proxy(
                target,
                proxy=transport_proxy,
                headers={"Accept": "text/plain, application/json", "Cache-Control": "no-cache"},
                timeout=12,
                verify=verify,
                impersonate="chrome",
                allow_redirects=True,
            )
        status = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= status < 300:
            raise ValueError(f"代理探测请求返回 HTTP {status}")
        # A connectivity probe is about the proxy request and HTTP response;
        # it must not require an IP-shaped response body.  Keep returning an
        # observed IP when a legacy ipify/ipinfo endpoint provides one so old
        # callers remain compatible, otherwise return an empty observation.
        try:
            return _extract_probe_ip(getattr(response, "content", b"") or b"")
        except (TypeError, ValueError):
            return ""

    def _probe_with_policy(self, proxy: str, target: str) -> tuple[str, str]:
        """Probe securely first and retry only TLS/CONNECT compatibility failures."""
        if not self.proxy_tls_verify:
            return self._probe(proxy, target, verify=False, socks5_dns_mode=self.socks5_dns_mode), "compat"
        try:
            return self._probe(proxy, target, verify=True, socks5_dns_mode=self.socks5_dns_mode), "strict"
        except Exception as first_error:
            if not self.proxy_tls_compat_fallback or not _is_tls_compatibility_error(first_error):
                raise
            # Keep the exact proxy, protocol and target. This is not a node or
            # protocol fallback; it only supports providers with broken certs.
            try:
                return self._probe(proxy, target, verify=False, socks5_dns_mode=self.socks5_dns_mode), "compat"
            except Exception as second_error:
                # Preserve both attempts for the structured diagnostic while
                # keeping the original exception type and redaction rules.
                raise second_error from first_error

    @staticmethod
    def _chatgpt_login_probe(
        proxy: str,
        *,
        verify: bool = True,
        socks5_dns_mode: str = "declared",
    ) -> int:
        return probe_chatgpt_login(
            proxy,
            verify=verify,
            socks5_dns_mode=socks5_dns_mode,
        )

    def _chatgpt_login_with_policy(self, proxy: str) -> tuple[int, str]:
        """Apply the same strict/compat TLS policy to the ChatGPT eligibility check."""
        if not self.proxy_tls_verify:
            return self._chatgpt_login_probe(
                proxy,
                verify=False,
                socks5_dns_mode=self.socks5_dns_mode,
            ), "compat"
        try:
            return self._chatgpt_login_probe(
                proxy,
                verify=True,
                socks5_dns_mode=self.socks5_dns_mode,
            ), "strict"
        except Exception as first_error:
            if not self.proxy_tls_compat_fallback or not _is_tls_compatibility_error(first_error):
                raise
            try:
                return self._chatgpt_login_probe(
                    proxy,
                    verify=False,
                    socks5_dns_mode=self.socks5_dns_mode,
                ), "compat"
            except Exception as second_error:
                raise second_error from first_error

    def layered_probe(self, proxy: str, target: str = DEFAULT_PROXY_PROBE_URL) -> dict[str, Any]:
        """Collect bounded transport timings for a diagnostic-only probe.

        This method never returns response bodies or credentials.  It is kept
        separate from normal binding so registration retains its existing
        AutoRegister probe order and cost.
        """
        configured = str(proxy or "").strip()
        parsed = urlsplit(configured)
        if not parsed.hostname or not parsed.port:
            raise ValueError("代理格式无效")
        result: dict[str, Any] = {
            "declared_scheme": parsed.scheme.lower(),
            "effective_scheme": proxy_transport_value(configured, driver="probe", socks5_dns_mode=self.socks5_dns_mode).split(":", 1)[0].lower(),
            "tcp_connect_ms": None,
            "https_request_ms": None,
            "chatgpt_request_ms": None,
            "chatgpt_status": None,
            "ok": False,
        }
        started = time.monotonic()
        try:
            with socket.create_connection((str(parsed.hostname), int(parsed.port)), timeout=5):
                pass
            result["tcp_connect_ms"] = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            result["failure_node"] = "proxy_tcp_connect"
            result["failure_reason"] = type(exc).__name__
            return result
        started = time.monotonic()
        try:
            self._probe_with_policy(configured, target)
            result["https_request_ms"] = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            result["https_request_ms"] = int((time.monotonic() - started) * 1000)
            result["failure_node"] = proxy_error_code(exc)
            result["failure_reason"] = proxy_error_detail(exc)
            return result
        started = time.monotonic()
        try:
            status, _mode = self._chatgpt_login_with_policy(configured)
            result["chatgpt_status"] = int(status)
            result["chatgpt_request_ms"] = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            result["chatgpt_request_ms"] = int((time.monotonic() - started) * 1000)
            result["failure_node"] = getattr(exc, "error_code", "free_proxy_chatgpt_probe")
            result["failure_reason"] = proxy_error_detail(exc)
            return result
        result["ok"] = True
        return result

    def bind(
        self,
        count: int,
        *,
        content: str = "",
        probe: Callable[[str, str], str] | None = None,
        chatgpt_probe: Callable[[str], int] | None = None,
        check_chatgpt: bool = False,
        probe_url: str = DEFAULT_PROXY_PROBE_URL,
        country: str | None = None,
        group: str | None = None,
        driver: str = "protocol",
        exclude_proxy_ids: Iterable[str] = (),
        exclude_exit_ips: Iterable[str] = (),
        perform_probe: bool = True,
        health_probe_ttl_seconds: int | None = None,
    ) -> list[ProxyBinding]:
        requested = max(0, int(count))
        if requested == 0:
            return []
        self._last_bind_diagnostics = []
        with self._lock:
            if health_probe_ttl_seconds is not None:
                self.health_probe_ttl_seconds = max(0, int(health_probe_ttl_seconds))
            inline_content = bool(str(content or "").strip())
            if inline_content:
                values = self._parse_lines(content, country=SINGLE_POOL_COUNTRY, group=SINGLE_POOL_GROUP, scheme=self.default_scheme)
            else:
                # Read the shared healthy pool before applying the Roxy
                # protocol capability filter.  This preserves the explicit
                # SOCKS4 diagnostic below instead of collapsing an otherwise
                # healthy-but-unsupported row into the generic pool-empty
                # error.  Other drivers accept the same shared candidates.
                values = self._eligible(driver="protocol")
            excluded = {str(value) for value in exclude_proxy_ids if str(value)}
            if excluded:
                values = [row for row in values if str(row.get("proxy_id") or "") not in excluded]
            if driver == "roxybrowser":
                roxy_values = [
                    row for row in values
                    if str(row.get("scheme") or "").lower() in SUPPORTED_ROXY_SCHEMES
                ]
                if not roxy_values and values and all(
                    str(row.get("scheme") or "").lower() == "socks4" for row in values
                ):
                    raise FreeRegisterError(
                        "free_roxy_proxy", "配置 RoxyBrowser 代理",
                        "RoxyBrowser 不支持 SOCKS4；请为 RoxyBrowser 分组提供 HTTP、HTTPS 或 SOCKS5 代理",
                        retryable=False,
                        error_code="free_roxy_socks4_unsupported",
                        provider_code="unsupported_proxy_scheme",
                        action_hint="将该分组切换为 HTTP、HTTPS、SOCKS5 或 SOCKS5H；SOCKS4 仍可用于纯协议注册",
                    )
                values = roxy_values
            if not values:
                raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "当前没有符合条件的健康代理", retryable=False, error_code="free_proxy_pool_empty")
            source = random.SystemRandom()
            # Production startup passes ``perform_probe=False`` to preserve
            # the AutoRegister call order.  Refresh only stale candidates in
            # that mode, once each, before leasing them. Recent successful
            # health results remain fast-path and are preferred.
            stale_refresh = (
                not inline_content
                and not perform_probe
                and self.health_probe_ttl_seconds > 0
            )
            if stale_refresh:
                now = time.time()
                recent = [row for row in values if not self._probe_is_stale(row, now)]
                stale = [row for row in values if self._probe_is_stale(row, now)]
                source.shuffle(recent)
                source.shuffle(stale)
                selected_values = list(recent[:requested])
                # Only probe enough stale rows to fill the requested count.
                # A failed stale proxy is quarantined and skipped so another
                # healthy candidate can be leased in the same transaction.
                for record in stale:
                    if len(selected_values) >= requested:
                        break
                    configured_proxy = _proxy_url(record)
                    transport_proxy = proxy_transport_value(
                        configured_proxy,
                        driver=driver,
                        socks5_dns_mode=self.socks5_dns_mode,
                    )
                    try:
                        started = time.monotonic()
                        if probe is None:
                            exit_ip, probe_mode = self._probe_with_policy(transport_proxy, probe_url)
                        else:
                            exit_ip, probe_mode = str(probe(transport_proxy, probe_url)).strip(), "custom"
                        exit_ip = str(exit_ip or "").strip() if _candidate_probe_ip(exit_ip) else ""
                        self.record_success(
                            str(record.get("proxy_id") or ""),
                            exit_ip=exit_ip,
                            latency_ms=int((time.monotonic() - started) * 1000),
                            probe_mode=probe_mode,
                            effective_scheme=urlsplit(transport_proxy).scheme.lower(),
                        )
                        # ``record_success`` reloads and persists the row;
                        # carry the fresh observation into this bind's local
                        # snapshot so the returned binding reflects it.
                        record["last_exit_ip"] = exit_ip
                        record["latency_ms"] = int((time.monotonic() - started) * 1000)
                        record["last_probe_mode"] = probe_mode
                        selected_values.append(record)
                    except Exception as exc:
                        self.record_failure(
                            str(record.get("proxy_id") or ""),
                            node_code=proxy_error_code(exc),
                            message=proxy_error_detail(exc),
                        )
                # Shared healthy_random allocation intentionally permits a
                # single healthy proxy to serve multiple concurrent tasks.
                # Once one stale candidate has passed its bounded refresh,
                # reuse it for any remaining requested slots.
                if selected_values and len(selected_values) < requested:
                    selected_values.extend(
                        source.choice(selected_values)
                        for _ in range(requested - len(selected_values))
                    )
                if len(selected_values) < requested:
                    raise FreeRegisterError(
                        "free_proxy_preflight", "Free 代理预检",
                        f"代理绑定数量不足：需要 {requested} 个，当前只有 {len(selected_values)} 个",
                        retryable=True,
                        error_code="free_proxy_pool_empty",
                    )
                # Recent rows were already health-checked; stale rows have
                # just been refreshed and should not be probed a second time.
                perform_probe_for_selected = False
            else:
                selected_values = [source.choice(values) for _ in range(requested)]
                perform_probe_for_selected = perform_probe
        check = probe
        bindings: list[ProxyBinding] = []
        checked: dict[str, tuple[str, str, int, int, str]] = {}
        for index, record in enumerate(selected_values, 1):
            configured_proxy = _proxy_url(record)
            transport_proxy = proxy_transport_value(
                configured_proxy,
                driver=driver,
                socks5_dns_mode=self.socks5_dns_mode,
            )
            if not transport_proxy:
                raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", f"代理池第 {index} 条格式无效", retryable=False)
            cache_key = str(record.get("proxy_id") or record.get("_identity") or transport_proxy)
            cached = checked.get(cache_key)
            if cached is None:
                started = time.monotonic()
                try:
                    if perform_probe_for_selected:
                        if check is None:
                            exit_ip, probe_mode = self._probe_with_policy(transport_proxy, probe_url)
                        else:
                            exit_ip, probe_mode = str(check(transport_proxy, probe_url)).strip(), "custom"
                        # Manual diagnostics accept any successful HTTP body;
                        # an IP is optional legacy metadata, never a gate.
                        exit_ip = str(exit_ip or "").strip() if _candidate_probe_ip(exit_ip) else ""
                    else:
                        exit_ip = str(record.get("last_exit_ip") or "")
                        probe_mode = str(record.get("last_probe_mode") or "")
                    chatgpt_status = 0
                    chatgpt_probe_mode = ""
                    if not perform_probe_for_selected:
                        latency_ms = int(record.get("latency_ms") or 0)
                        chatgpt_status = int(record.get("last_chatgpt_login_status") or 0)
                        chatgpt_probe_mode = str(record.get("last_chatgpt_login_probe_mode") or "")
                    if check_chatgpt:
                        # ChatGPT login-page status is diagnostic metadata,
                        # not an account or proxy-health gate.  In particular,
                        # a normal 403/401 login response must not quarantine
                        # an otherwise reachable proxy.
                        if chatgpt_probe is None:
                            chatgpt_status, chatgpt_probe_mode = self._chatgpt_login_with_policy(transport_proxy)
                        else:
                            chatgpt_status = int(chatgpt_probe(transport_proxy) or 0)
                            chatgpt_probe_mode = "custom"
                except FreeRegisterError as exc:
                    if not inline_content and is_proxy_health_failure(exc):
                        self.record_failure(
                            str(record.get("proxy_id") or ""),
                            node_code="free_proxy_preflight",
                            message=str(exc),
                        )
                    raise
                except Exception as exc:
                    failure_code = proxy_error_code(exc)
                    failure = FreeRegisterError(
                        failure_code,
                        proxy_error_label(failure_code),
                        f"代理池第 {index} 条代理请求失败：{proxy_error_detail(exc)}",
                        error_code=failure_code,
                    )
                    # Preserve the transport type for health classification
                    # before the exception is raised to the caller.
                    failure.__cause__ = exc
                    if not inline_content and is_proxy_health_failure(failure):
                        self.record_failure(
                            str(record.get("proxy_id") or ""),
                            node_code=failure_code,
                            message=str(failure),
                        )
                    raise failure from exc
                latency_ms = int((time.monotonic() - started) * 1000)
                checked[cache_key] = (exit_ip, probe_mode, latency_ms, chatgpt_status, chatgpt_probe_mode)
            else:
                if not perform_probe_for_selected:
                    exit_ip = str(record.get("last_exit_ip") or "")
                    probe_mode = str(record.get("last_probe_mode") or "")
                    latency_ms = int(record.get("latency_ms") or 0)
                    chatgpt_status = int(record.get("last_chatgpt_login_status") or 0)
                    chatgpt_probe_mode = str(record.get("last_chatgpt_login_probe_mode") or "")
                else:
                    exit_ip, probe_mode, latency_ms, chatgpt_status, chatgpt_probe_mode = cached
            if (perform_probe_for_selected or check_chatgpt) and not inline_content and cached is None:
                self.record_success(
                    str(record.get("proxy_id") or ""),
                    exit_ip=exit_ip,
                    latency_ms=latency_ms if perform_probe_for_selected else None,
                    probe_mode=probe_mode,
                    chatgpt_login_status=chatgpt_status,
                    chatgpt_login_probe_mode=chatgpt_probe_mode,
                    effective_scheme=urlsplit(transport_proxy).scheme.lower(),
                )
            declared_scheme = urlsplit(configured_proxy).scheme.lower()
            effective_scheme = urlsplit(transport_proxy).scheme.lower()
            bindings.append(ProxyBinding(
                configured_proxy,
                str(record.get("proxy_id") or fingerprint(configured_proxy)),
                mask_proxy(configured_proxy),
                exit_ip,
                proxy_id=str(record.get("proxy_id") or ""),
                scheme=declared_scheme,
                effective_scheme=effective_scheme,
                country=SINGLE_POOL_COUNTRY,
                group=SINGLE_POOL_GROUP,
                chatgpt_login_status=chatgpt_status,
                chatgpt_login_checked=bool(check_chatgpt),
                chatgpt_login_probe_mode=chatgpt_probe_mode,
            ))
            self._last_bind_diagnostics.append({
                "index": len(bindings),
                "masked": mask_proxy(configured_proxy),
                "fingerprint": str(record.get("proxy_id") or fingerprint(configured_proxy)),
                "scheme": declared_scheme,
                "declared_scheme": declared_scheme,
                "effective_scheme": effective_scheme,
                "available": True,
                "http_status": 200 if perform_probe else None,
                "local_to_proxy_ms": None,
                "proxy_to_target_ms": latency_ms if perform_probe else None,
                "failure_node": "",
                "failure_reason": "",
            })
            if len(bindings) >= requested:
                break
        if len(bindings) < requested:
            raise FreeRegisterError(
                "free_proxy_preflight",
                "Free 代理预检",
                f"代理绑定数量不足：需要 {requested} 个，当前只有 {len(bindings)} 个",
                retryable=False,
                error_code="free_proxy_pool_empty",
            )
        return bindings

    def verify(self, binding: ProxyBinding, *, probe: Callable[[str, str], str] | None = None, probe_url: str = DEFAULT_PROXY_PROBE_URL) -> str:
        transport_proxy = proxy_transport_value(
            binding.proxy,
            driver="probe",
            socks5_dns_mode=self.socks5_dns_mode,
        )
        if not transport_proxy:
            raise FreeRegisterError(
                "proxy_connect_failed",
                "代理连接失败",
                "代理地址格式无效",
                retryable=False,
                error_code="proxy_connect_failed",
            )
        try:
            if probe is None:
                current, probe_mode = self._probe_with_policy(transport_proxy, probe_url)
            else:
                current, probe_mode = str(probe(transport_proxy, probe_url)).strip(), "custom"
            current = str(current or "").strip()
            # A successful connectivity response does not need to contain an
            # IP address. Preserve an IP only when a legacy probe endpoint
            # provides one; otherwise return an empty observation.
            if not _candidate_probe_ip(current):
                current = ""
        except Exception as exc:
            failure_code = proxy_error_code(exc)
            raise FreeRegisterError(
                failure_code,
                proxy_error_label(failure_code),
                f"代理请求失败：{proxy_error_detail(exc)}",
                error_code=failure_code,
            ) from exc
        if binding.proxy_id:
            self.record_success(
                binding.proxy_id,
                exit_ip=current,
                probe_mode=probe_mode,
                effective_scheme=urlsplit(transport_proxy).scheme.lower(),
            )
        return current

    def lease(self, binding: ProxyBinding, *, owner: str, batch_id: str, task_id: str, lease_seconds: int = 180) -> None:
        with self._lock:
            rows = self._load()
            target = next((
                row for row in rows
                if str(row.get("proxy_id")) == str(binding.proxy_id)
                or row.get("_normalized") == binding.proxy
                or proxy_transport_value(str(row.get("_normalized") or ""), driver="protocol") == str(binding.proxy)
            ), None)
            if target is None:
                raise FreeRegisterError("free_proxy_lease", "租用 Free 代理", "固定代理已不存在", retryable=False)
            now = time.time()
            active = [lease for lease in self._active_leases(target, now) if str(lease.get("owner") or "") != str(owner)]
            active.append({
                "owner": str(owner),
                "batch_id": str(batch_id),
                "task_id": str(task_id),
                "until": now + max(30, int(lease_seconds)),
            })
            if str(binding.exit_ip or "").strip():
                target["last_exit_ip"] = str(binding.exit_ip).strip()
            target["leases"] = active
            self._sync_lease_compat(target, now)
            self._save(rows)

    def heartbeat(self, owner: str, *, lease_seconds: int = 180) -> None:
        with self._lock:
            rows = self._load()
            changed = False
            until = time.time() + max(30, int(lease_seconds))
            for row in rows:
                active = self._active_leases(row)
                matched = False
                for lease in active:
                    if str(lease.get("owner") or "") == str(owner):
                        lease["until"] = until
                        matched = True
                if matched:
                    row["leases"] = active
                    self._sync_lease_compat(row)
                    changed = True
            if changed:
                self._save(rows)

    def heartbeat_batch(self, batch_id: str, *, lease_seconds: int = 180) -> None:
        """Renew only leases belonging to one Free batch."""
        with self._lock:
            rows = self._load()
            changed = False
            until = time.time() + max(30, int(lease_seconds))
            for row in rows:
                active = self._active_leases(row)
                matched = False
                for lease in active:
                    if str(lease.get("batch_id") or "") == str(batch_id):
                        lease["until"] = until
                        matched = True
                if matched:
                    row["leases"] = active
                    self._sync_lease_compat(row)
                    changed = True
            if changed:
                self._save(rows)

    def release(self, binding: ProxyBinding, *, owner: str = "") -> None:
        with self._lock:
            rows = self._load()
            changed = False
            for row in rows:
                if str(row.get("proxy_id")) != str(binding.proxy_id):
                    continue
                active = self._active_leases(row)
                remaining = [lease for lease in active if owner and str(lease.get("owner") or "") != str(owner)] if owner else []
                if len(remaining) != len(active):
                    row["leases"] = remaining
                    self._sync_lease_compat(row)
                    changed = True
            if changed:
                self._save(rows)

    def record_success(
        self,
        proxy_id: str,
        *,
        exit_ip: str = "",
        latency_ms: int | None = None,
        probe_mode: str = "",
        chatgpt_login_status: int = 0,
        chatgpt_login_probe_mode: str = "",
        effective_scheme: str = "",
    ) -> None:
        with self._lock:
            rows = self._load()
            for row in rows:
                if str(row.get("proxy_id")) != str(proxy_id):
                    continue
                now = time.time()
                latency_samples = list(row.get("probe_latencies_ms") or [])
                if latency_ms is not None:
                    latency_samples.append(max(0, int(latency_ms)))
                row.update({
                    "status": "available", "consecutive_failures": 0, "last_checked_at": now,
                    "last_exit_ip": exit_ip or row.get("last_exit_ip", ""),
                    "latency_ms": latency_ms if latency_ms is not None else row.get("latency_ms"),
                    "last_failure": None,
                    "last_probe_ok": True,
                    "probe_attempts": int(row.get("probe_attempts") or 0) + 1,
                    "probe_successes": int(row.get("probe_successes") or 0) + 1,
                    "probe_latencies_ms": latency_samples[-50:],
                })
                if chatgpt_login_status:
                    row["last_chatgpt_login_checked_at"] = now
                    row["last_chatgpt_login_status"] = int(chatgpt_login_status)
                if chatgpt_login_probe_mode:
                    row["last_chatgpt_login_probe_mode"] = str(chatgpt_login_probe_mode)
                if probe_mode:
                    row["last_probe_mode"] = str(probe_mode)
                if effective_scheme:
                    row["effective_scheme"] = str(effective_scheme).lower()
                row["quarantined_until"] = None
                self._save(rows)
                return

    def record_failure(self, proxy_id: str, *, node_code: str, message: str, threshold: int | None = None, quarantine_seconds: int | None = None) -> None:
        with self._lock:
            rows = self._load()
            for row in rows:
                if str(row.get("proxy_id")) != str(proxy_id):
                    continue
                failures = int(row.get("consecutive_failures") or 0) + 1
                limit = max(1, int(threshold or self.failure_threshold))
                row.update({"consecutive_failures": failures, "last_checked_at": time.time(), "probe_attempts": int(row.get("probe_attempts") or 0) + 1, "last_probe_ok": False, "last_failure": {"node_code": node_code, "message": safe_log_message(message)[:300]}})
                if failures >= limit:
                    row["status"] = "quarantined"
                    row["quarantined_until"] = time.time() + max(1, int(quarantine_seconds or self.quarantine_seconds))
                self._save(rows)
                return

    def update_group(self, country: str, group: str, *, new_country: str | None = None, new_group: str | None = None, enabled: bool | None = None) -> dict[str, int]:
        with self._lock:
            rows = self._load()
            matched = len(rows)
            modified = 0
            for row in rows:
                before = (bool(row.get("enabled")), row.get("country"), row.get("group"))
                row["country"] = SINGLE_POOL_COUNTRY
                row["group"] = SINGLE_POOL_GROUP
                if enabled is not None:
                    row["enabled"] = bool(enabled)
                modified += int(before != (bool(row.get("enabled")), row.get("country"), row.get("group")))
            if modified:
                self._save(rows)
            return {"matched": matched, "modified": modified}

    def delete_group(self, country: str, group: str) -> int:
        with self._lock:
            rows = self._load()
            # A legacy group-delete request must never delete the shared pool.
            if any(row.get("country") or row.get("group") for row in rows):
                self._save([{**row, "country": SINGLE_POOL_COUNTRY, "group": SINGLE_POOL_GROUP} for row in rows])
            return 0


@contextmanager
def _without_proxy_environment():
    names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
    saved = {name: os.environ.get(name) for name in names}
    try:
        for name in names:
            os.environ.pop(name, None)
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


__all__ = [
    "CHATGPT_LOGIN_PROBE_URL",
    "DEFAULT_PROXY_PROBE_URL",
    "DEFAULT_PROXY_COUNTRY",
    "DEFAULT_PROXY_GROUP",
    "SUPPORTED_ROXY_SCHEMES",
    "FreeProxyLease",
    "FreeProxyPool",
    "infer_country",
    "normalize_country",
    "normalize_group",
    "normalize_probe_url",
    "_extract_probe_ip",
    "_is_tls_compatibility_error",
]
