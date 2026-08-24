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
import threading
import time
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote, unquote, urlsplit, urlunsplit

try:
    from .free_register_common import (
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        normalize_proxy_value,
        proxy_transport_value,
        proxy_error_detail,
        safe_log_message,
    )
except ImportError:
    from free_register_common import (  # type: ignore[no-redef]
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        normalize_proxy_value,
        proxy_transport_value,
        proxy_error_detail,
        safe_log_message,
    )

try:
    from .free_proxy_chatgpt import probe_chatgpt_login
except ImportError:
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
PROXY_ALLOCATION_MODES = frozenset({"healthy_random", "exclusive"})
DEFAULT_PROXY_COUNTRY = "ZZ"
DEFAULT_PROXY_GROUP = "默认组"
DEFAULT_PROXY_PROBE_URL = "https://api.ipify.org"
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
    """Only certificate/TLS/CONNECT errors qualify for the compatibility retry."""
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
    markers = (
        "ssl", "tls", "certificate", "cert verify", "handshake",
        "secure transport", "curl: (35)", "curl: (51)", "curl: (60)", "curl: (77)", "curl: (97)",
        "proxy connect", "connect tunnel",
    )
    # curl-cffi frequently wraps a TLS/CONNECT failure as ProxyError and only
    # exposes the useful libcurl code on a nested cause. Retry only when that
    # evidence is present; a bare ProxyError is not enough.
    if name in {"sslerror", "certificateverifyerror"}:
        return True
    return any(marker in text for marker in markers)


_PROBE_BODY_LIMIT = 4096
_LEGACY_PROBE_HOST = "ipinfo.io"


def normalize_probe_url(value: Any) -> str:
    """Normalize the old built-in ipinfo text endpoint without touching custom URLs."""
    candidate = str(value or "").strip()
    if not candidate:
        return DEFAULT_PROXY_PROBE_URL
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return candidate
    # Older Free builds used ipinfo.io/ip as their implicit default.  That
    # endpoint is still valid when explicitly chosen, but several residential
    # SOCKS gateways reject its CONNECT path.  Keep ipinfo JSON and all other
    # user-supplied URLs unchanged; only migrate this exact legacy default.
    if (
        parsed.scheme in {"http", "https"}
        and str(parsed.hostname or "").lower() == _LEGACY_PROBE_HOST
        and parsed.path.rstrip("/") == "/ip"
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
    raise ValueError("代理出口 IP 响应格式无效")


def _record_from_url(value: str, *, country: Any, group: Any) -> dict[str, Any] | None:
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
        "country": normalize_country(country) if str(country or "").strip() else infer_country(username, parsed.hostname),
        "group": normalize_group(group),
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
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = self.data_dir / "free_proxy_pool.json"
        self.legacy_path = self.data_dir / "free_proxy_pool.txt"
        scheme = str(default_scheme or DEFAULT_FREE_PROXY_SCHEME).strip().lower()
        self.default_scheme = scheme if scheme in FREE_PROXY_SCHEMES else DEFAULT_FREE_PROXY_SCHEME
        self.failure_threshold = max(1, int(failure_threshold))
        self.quarantine_seconds = max(1, int(quarantine_seconds))
        self.proxy_tls_verify = True
        self.proxy_tls_compat_fallback = True
        self.allocation_mode = "healthy_random"
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
            if rows and version < 3:
                self._save(rows)
            return rows
        if self.legacy_path.exists():
            try:
                content = self.legacy_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                content = ""
            migrated = self._parse_lines(content, country="", group=DEFAULT_PROXY_GROUP, scheme=self.default_scheme)
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
            "country": normalize_country(value.get("country") or infer_country(username, url_parts.hostname)),
            "group": normalize_group(value.get("group")),
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
            "last_probe_mode": str(value.get("last_probe_mode") or ""),
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
        atomic_write(self.path, {"version": 3, "proxies": payload})

    def _parse_lines(self, content: str, *, country: Any, group: Any, scheme: str) -> list[dict[str, Any]]:
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
            record = _record_from_url(normalized, country=country, group=group)
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
    ) -> int:
        incoming = self._parse_lines(content, country=country or "", group=group or DEFAULT_PROXY_GROUP, scheme=scheme or self.default_scheme)
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
                for key in ("scheme", "country", "group"):
                    current[key] = row[key]
                current["enabled"] = True
                if current.get("status") == "quarantined" and self._quarantine_expired(current):
                    current["status"] = "unknown"
            self._save(by_identity.values())
            return added

    def configure_policy(
        self,
        *,
        failure_threshold: int | None = None,
        quarantine_seconds: int | None = None,
        tls_verify: bool | None = None,
        tls_compat_fallback: bool | None = None,
        allocation_mode: str | None = None,
    ) -> None:
        self.failure_threshold = max(1, int(failure_threshold or self.failure_threshold))
        self.quarantine_seconds = max(1, int(quarantine_seconds or self.quarantine_seconds))
        if tls_verify is not None:
            self.proxy_tls_verify = bool(tls_verify)
        if tls_compat_fallback is not None:
            self.proxy_tls_compat_fallback = bool(tls_compat_fallback)
        if allocation_mode is not None:
            selected_mode = str(allocation_mode or "").strip().lower()
            self.allocation_mode = selected_mode if selected_mode in PROXY_ALLOCATION_MODES else "healthy_random"

    def _quarantine_expired(self, row: Mapping[str, Any], now: float | None = None) -> bool:
        until = row.get("quarantined_until")
        if until is None:
            return False
        normalized = _safe_float(until, default=0, minimum=0) or 0
        return normalized <= (time.time() if now is None else now)

    def _eligible(self, *, country: str | None = None, group: str | None = None, driver: str = "protocol", now: float | None = None) -> list[dict[str, Any]]:
        current_time = time.time() if now is None else now
        selected_country = normalize_country(country) if str(country or "").strip() else None
        selected_group = normalize_group(group) if str(group or "").strip() else None
        rows: list[dict[str, Any]] = []
        for row in self._load():
            if selected_country and row["country"] != selected_country:
                continue
            if selected_group and row["group"] != selected_group:
                continue
            if not row.get("enabled"):
                continue
            if row.get("status") == "quarantined" and not self._quarantine_expired(row, current_time):
                continue
            if self.allocation_mode == "exclusive" and self._active_leases(row, current_time):
                continue
            if driver == "roxybrowser" and str(row.get("scheme") or "").lower() not in SUPPORTED_ROXY_SCHEMES:
                continue
            rows.append(row)
        return rows

    def values(self, content: str = "") -> list[str]:
        with self._lock:
            rows = self._parse_lines(content, country="", group=DEFAULT_PROXY_GROUP, scheme=self.default_scheme) if str(content or "").strip() else self._load()
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
        value = {
            "proxy_id": row.get("proxy_id", ""),
            "index": index,
            "masked": mask_proxy(_proxy_url(row)),
            "fingerprint": str(row.get("proxy_id") or ""),
            "scheme": configured_scheme,
            "protocol_scheme": "socks5h" if configured_scheme == "socks5" else configured_scheme,
            "roxy_scheme": "SOCKS5" if configured_scheme in {"socks5", "socks5h"} else configured_scheme.upper() if configured_scheme in {"http", "https"} else "",
            "country": row.get("country", DEFAULT_PROXY_COUNTRY),
            "group": row.get("group", DEFAULT_PROXY_GROUP),
            "enabled": bool(row.get("enabled", True)),
            "status": row.get("status", "unknown"),
            "lease_until": max((float(lease.get("until") or 0) for lease in leases), default=None),
            "active_lease_count": len(leases),
            "last_checked_at": row.get("last_checked_at"),
            "last_exit_ip": row.get("last_exit_ip", ""),
            "latency_ms": row.get("latency_ms"),
            "last_chatgpt_login_checked_at": row.get("last_chatgpt_login_checked_at"),
            "last_chatgpt_login_status": int(row.get("last_chatgpt_login_status") or 0),
            "last_chatgpt_login_probe_mode": row.get("last_chatgpt_login_probe_mode", ""),
            "consecutive_failures": int(row.get("consecutive_failures") or 0),
            "last_probe_mode": row.get("last_probe_mode", ""),
        }
        return value

    def group_summaries(self) -> list[dict[str, Any]]:
        rows = self._load()
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        now = time.time()
        for row in rows:
            key = (str(row.get("country") or DEFAULT_PROXY_COUNTRY), normalize_group(row.get("group")))
            current = grouped.setdefault(key, {"country": key[0], "group": key[1], "total": 0, "enabled": 0, "available": 0, "leased": 0, "leased_proxies": 0, "quarantined": 0, "schemes": set()})
            current["total"] += 1
            current["enabled"] += int(bool(row.get("enabled")))
            active_leases = self._active_leases(row, now)
            current["leased"] += len(active_leases)
            current["leased_proxies"] += int(bool(active_leases))
            if row.get("status") == "quarantined" and not self._quarantine_expired(row, now):
                current["quarantined"] += 1
            elif row.get("enabled") and (self.allocation_mode != "exclusive" or not active_leases):
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
    def _probe(proxy: str, target: str, *, verify: bool = True) -> str:
        from curl_cffi import requests as curl_requests

        target = normalize_probe_url(target)
        transport_proxy = proxy_transport_value(proxy, driver="probe")
        if not transport_proxy:
            raise ValueError("代理格式无效")
        session = curl_requests.Session(impersonate="chrome", verify=bool(verify))
        session.proxies = {"http": transport_proxy, "https": transport_proxy}
        if hasattr(session, "trust_env"):
            session.trust_env = False
        with _without_proxy_environment():
            try:
                response = session.get(
                    target,
                    headers={"Accept": "text/plain, application/json", "Cache-Control": "no-cache"},
                    timeout=12,
                )
            finally:
                close = getattr(session, "close", None)
                if callable(close):
                    close()
        status = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= status < 300:
            raise ValueError(f"代理出口检测返回 HTTP {status}")
        return _extract_probe_ip(getattr(response, "content", b"") or b"")

    def _probe_with_policy(self, proxy: str, target: str) -> tuple[str, str]:
        """Probe securely first and retry only TLS/CONNECT compatibility failures."""
        if not self.proxy_tls_verify:
            return self._probe(proxy, target, verify=False), "compat"
        try:
            return self._probe(proxy, target, verify=True), "strict"
        except Exception as first_error:
            if not self.proxy_tls_compat_fallback or not _is_tls_compatibility_error(first_error):
                raise
            # Keep the exact proxy, protocol and target. This is not a node or
            # protocol fallback; it only supports providers with broken certs.
            try:
                return self._probe(proxy, target, verify=False), "compat"
            except Exception as second_error:
                # Preserve both attempts for the structured diagnostic while
                # keeping the original exception type and redaction rules.
                raise second_error from first_error

    @staticmethod
    def _chatgpt_login_probe(proxy: str, *, verify: bool = True) -> int:
        return probe_chatgpt_login(proxy, verify=verify)

    def _chatgpt_login_with_policy(self, proxy: str) -> tuple[int, str]:
        """Apply the same strict/compat TLS policy to the ChatGPT eligibility check."""
        if not self.proxy_tls_verify:
            return self._chatgpt_login_probe(proxy, verify=False), "compat"
        try:
            return self._chatgpt_login_probe(proxy, verify=True), "strict"
        except Exception as first_error:
            if not self.proxy_tls_compat_fallback or not _is_tls_compatibility_error(first_error):
                raise
            try:
                return self._chatgpt_login_probe(proxy, verify=False), "compat"
            except Exception as second_error:
                raise second_error from first_error

    def bind(
        self,
        count: int,
        *,
        content: str = "",
        probe: Callable[[str, str], str] | None = None,
        chatgpt_probe: Callable[[str], int] | None = None,
        check_chatgpt: bool = False,
        probe_url: str = "https://api.ipify.org",
        country: str | None = None,
        group: str | None = None,
        driver: str = "protocol",
        exclude_proxy_ids: Iterable[str] = (),
        exclude_exit_ips: Iterable[str] = (),
    ) -> list[ProxyBinding]:
        requested = max(0, int(count))
        if requested == 0:
            return []
        with self._lock:
            inline_content = bool(str(content or "").strip())
            now = time.time()
            persisted_rows = self._load()
            active_rows = [row for row in persisted_rows if self._active_leases(row, now)]
            active_proxy_ids = {str(row.get("proxy_id") or "") for row in active_rows}
            active_identities = {str(row.get("_identity") or "") for row in active_rows}
            active_exit_ips = {
                str(row.get("last_exit_ip") or "").strip()
                for row in active_rows
                if str(row.get("last_exit_ip") or "").strip()
            }
            if inline_content:
                values = self._parse_lines(content, country=country or "", group=group or DEFAULT_PROXY_GROUP, scheme=self.default_scheme)
                selected_country = normalize_country(country) if str(country or "").strip() else None
                selected_group = normalize_group(group) if str(group or "").strip() else None
                values = [
                    row for row in values
                    if (not selected_country or row.get("country") == selected_country)
                    and (not selected_group or row.get("group") == selected_group)
                ]
            else:
                # Keep unsupported-but-otherwise-healthy candidates long
                # enough to report an exact Roxy protocol error.
                values = self._eligible(country=country, group=group, driver="protocol")
            excluded = {str(value) for value in exclude_proxy_ids if str(value)}
            if self.allocation_mode == "exclusive":
                excluded.update(active_proxy_ids)
                values = [row for row in values if str(row.get("_identity") or "") not in active_identities]
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
            if inline_content:
                if len(values) >= requested:
                    selected_values = list(values) if self.allocation_mode == "exclusive" else values[:requested]
                elif self.allocation_mode == "exclusive":
                    raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", f"独占代理数量不足：需要 {requested} 个，当前只有 {len(values)} 个", retryable=False, error_code="free_proxy_pool_exhausted")
                else:
                    source = random.SystemRandom()
                    selected_values = list(values)
                    selected_values.extend(source.choice(values) for _ in range(requested - len(values)))
            else:
                source = random.SystemRandom()
                if self.allocation_mode == "exclusive":
                    if len(values) < requested:
                        raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", f"独占代理数量不足：需要 {requested} 个，当前只有 {len(values)} 个", retryable=False, error_code="free_proxy_pool_exhausted")
                    selected_values = list(values)
                    source.shuffle(selected_values)
                else:
                    selected_values = [source.choice(values) for _ in range(requested)]
        reserved_exit_ips = set()
        if self.allocation_mode == "exclusive":
            reserved_exit_ips = {
                str(value).strip()
                for value in (*exclude_exit_ips, *active_exit_ips)
                if str(value).strip()
            }
        check = probe
        bindings: list[ProxyBinding] = []
        checked: dict[str, tuple[str, str, int, int, str]] = {}
        for index, record in enumerate(selected_values, 1):
            configured_proxy = _proxy_url(record)
            transport_proxy = proxy_transport_value(configured_proxy, driver=driver)
            if not transport_proxy:
                raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", f"代理池第 {index} 条格式无效", retryable=False)
            cache_key = str(record.get("proxy_id") or record.get("_identity") or transport_proxy)
            cached = checked.get(cache_key)
            if cached is None:
                started = time.monotonic()
                try:
                    if check is None:
                        exit_ip, probe_mode = self._probe_with_policy(transport_proxy, probe_url)
                    else:
                        exit_ip, probe_mode = str(check(transport_proxy, probe_url)).strip(), "custom"
                    exit_ip = str(exit_ip).strip()
                    if not exit_ip:
                        raise ValueError("出口 IP 为空")
                    chatgpt_status = 0
                    chatgpt_probe_mode = ""
                    if check_chatgpt:
                        if chatgpt_probe is None:
                            chatgpt_status, chatgpt_probe_mode = self._chatgpt_login_with_policy(transport_proxy)
                        else:
                            chatgpt_status, chatgpt_probe_mode = int(chatgpt_probe(transport_proxy) or 0), "custom"
                        if not 200 <= chatgpt_status < 400:
                            raise FreeRegisterError(
                                "free_proxy_preflight", "Free 代理预检",
                                f"代理池第 {index} 条 ChatGPT 登录页预检返回 HTTP {chatgpt_status}",
                                provider_status=chatgpt_status,
                                retryable=chatgpt_status in {0, 408, 425, 429} or chatgpt_status >= 500,
                                error_code="free_proxy_chatgpt_login_http",
                                action_hint="更换当前代理出口后重新检测；出口 IP 可联网但被 ChatGPT 拒绝时不能用于协议注册",
                            )
                except FreeRegisterError as exc:
                    if not inline_content and is_proxy_health_failure(exc):
                        self.record_failure(
                            str(record.get("proxy_id") or ""),
                            node_code="free_proxy_preflight",
                            message=str(exc),
                        )
                    raise
                except Exception as exc:
                    failure = FreeRegisterError(
                        "free_proxy_preflight",
                        "Free 代理预检",
                        f"代理池第 {index} 条出口 IP 检测失败：{proxy_error_detail(exc)}",
                    )
                    # Preserve the transport type for health classification
                    # before the exception is raised to the caller.
                    failure.__cause__ = exc
                    if not inline_content and is_proxy_health_failure(failure):
                        self.record_failure(
                            str(record.get("proxy_id") or ""),
                            node_code="free_proxy_preflight",
                            message=str(failure),
                        )
                    raise failure from exc
                latency_ms = int((time.monotonic() - started) * 1000)
                checked[cache_key] = (exit_ip, probe_mode, latency_ms, chatgpt_status, chatgpt_probe_mode)
            else:
                exit_ip, probe_mode, latency_ms, chatgpt_status, chatgpt_probe_mode = cached
            if not inline_content and cached is None:
                self.record_success(
                    str(record.get("proxy_id") or ""),
                    exit_ip=exit_ip,
                    latency_ms=latency_ms,
                    probe_mode=probe_mode,
                    chatgpt_login_status=chatgpt_status,
                    chatgpt_login_probe_mode=chatgpt_probe_mode,
                )
            if self.allocation_mode == "exclusive" and exit_ip in reserved_exit_ips:
                continue
            transport_scheme = urlsplit(transport_proxy).scheme.lower()
            bindings.append(ProxyBinding(
                transport_proxy,
                str(record.get("proxy_id") or fingerprint(configured_proxy)),
                mask_proxy(transport_proxy),
                exit_ip,
                proxy_id=str(record.get("proxy_id") or ""),
                scheme=transport_scheme,
                country=str(record.get("country") or DEFAULT_PROXY_COUNTRY),
                group=str(record.get("group") or DEFAULT_PROXY_GROUP),
                chatgpt_login_status=chatgpt_status,
                chatgpt_login_checked=bool(check_chatgpt),
                chatgpt_login_probe_mode=chatgpt_probe_mode,
            ))
            reserved_exit_ips.add(exit_ip)
            if len(bindings) >= requested:
                break
        if len(bindings) < requested:
            raise FreeRegisterError(
                "free_proxy_preflight",
                "Free 代理预检",
                f"独占代理或出口 IP 数量不足：需要 {requested} 个，当前只有 {len(bindings)} 个",
                retryable=False,
                error_code="free_proxy_exit_ip_conflict",
            )
        return bindings

    def verify(self, binding: ProxyBinding, *, probe: Callable[[str, str], str] | None = None, probe_url: str = "https://api.ipify.org") -> str:
        try:
            if probe is None:
                current, probe_mode = self._probe_with_policy(binding.proxy, probe_url)
            else:
                current, probe_mode = str(probe(binding.proxy, probe_url)).strip(), "custom"
            current = str(current).strip()
        except Exception as exc:
            raise FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", f"固定代理出口复核失败：{proxy_error_detail(exc)}") from exc
        if current != binding.exit_ip:
            raise FreeRegisterError("free_proxy_drift", "校验 Free 代理出口", "固定代理的出口 IP 在任务期间发生变化，任务已停止且未切换代理", retryable=False)
        if binding.proxy_id:
            self.record_success(binding.proxy_id, exit_ip=current, probe_mode=probe_mode)
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
            if self.allocation_mode == "exclusive":
                conflicting_proxy = bool(active)
                conflicting_exit = any(
                    row is not target
                    and self._active_leases(row, now)
                    and str(row.get("last_exit_ip") or "").strip()
                    and str(row.get("last_exit_ip") or "").strip() == str(binding.exit_ip or "").strip()
                    for row in rows
                )
                if conflicting_proxy or conflicting_exit:
                    raise FreeRegisterError(
                        "free_proxy_lease", "租用 Free 代理", "独占代理或出口 IP 已被其他 Free 任务租用",
                        retryable=False, error_code="free_proxy_lease_conflict",
                    )
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
    ) -> None:
        with self._lock:
            rows = self._load()
            for row in rows:
                if str(row.get("proxy_id")) != str(proxy_id):
                    continue
                now = time.time()
                row.update({
                    "status": "available", "consecutive_failures": 0, "last_checked_at": now,
                    "last_exit_ip": exit_ip or row.get("last_exit_ip", ""),
                    "latency_ms": latency_ms if latency_ms is not None else row.get("latency_ms"),
                    "last_failure": None,
                })
                if chatgpt_login_status:
                    row["last_chatgpt_login_checked_at"] = now
                    row["last_chatgpt_login_status"] = int(chatgpt_login_status)
                if chatgpt_login_probe_mode:
                    row["last_chatgpt_login_probe_mode"] = str(chatgpt_login_probe_mode)
                if probe_mode:
                    row["last_probe_mode"] = str(probe_mode)
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
                row.update({"consecutive_failures": failures, "last_checked_at": time.time(), "last_failure": {"node_code": node_code, "message": safe_log_message(message)[:300]}})
                if failures >= limit:
                    row["status"] = "quarantined"
                    row["quarantined_until"] = time.time() + max(1, int(quarantine_seconds or self.quarantine_seconds))
                self._save(rows)
                return

    def update_group(self, country: str, group: str, *, new_country: str | None = None, new_group: str | None = None, enabled: bool | None = None) -> dict[str, int]:
        with self._lock:
            rows = self._load()
            matched = modified = 0
            source_country = normalize_country(country)
            source_group = normalize_group(group)
            for row in rows:
                if row.get("country") != source_country or row.get("group") != source_group:
                    continue
                matched += 1
                before = (row.get("country"), row.get("group"), row.get("enabled"))
                if new_country is not None:
                    row["country"] = normalize_country(new_country)
                if new_group is not None:
                    row["group"] = normalize_group(new_group)
                if enabled is not None:
                    row["enabled"] = bool(enabled)
                modified += int(before != (row.get("country"), row.get("group"), row.get("enabled")))
            if modified:
                self._save(rows)
            return {"matched": matched, "modified": modified}

    def delete_group(self, country: str, group: str) -> int:
        with self._lock:
            rows = self._load()
            source_country = normalize_country(country)
            source_group = normalize_group(group)
            targets = [row for row in rows if row.get("country") == source_country and row.get("group") == source_group]
            if any(self._active_leases(row) for row in targets):
                raise FreeRegisterError("free_proxy_group_delete", "删除 Free 代理分组", "分组内存在运行中的代理租约", retryable=False)
            if targets:
                self._save([row for row in rows if row not in targets])
            return len(targets)


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
