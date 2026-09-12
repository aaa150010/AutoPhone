"""Structured proxy resources for the isolated Free registration center.

The public surface deliberately keeps credentials out of every response.  The
private JSON file is mode 0600 and is only read by the Free workers.
"""

from __future__ import annotations

from dataclasses import dataclass
import copy
import ipaddress
import json
from pathlib import Path
import random
import re
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
    )

try:
    from .free_proxy_store_health import (
        CHATGPT_LOGIN_PROBE_URL,
        FreeProxyStoreHealthMixin,
        _PROBE_TLS_VERIFY,
        _ProxyProbeHTTPError,
        _probe_status,
        _set_probe_status,
    )
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_proxy_store_health import (  # type: ignore[no-redef]
        CHATGPT_LOGIN_PROBE_URL,
        FreeProxyStoreHealthMixin,
        _PROBE_TLS_VERIFY,
        _ProxyProbeHTTPError,
        _probe_status,
        _set_probe_status,
    )

try:
    from .free_proxy_numeric import safe_float as _safe_float, safe_int as _safe_int
except ImportError:
    from free_proxy_numeric import safe_float as _safe_float, safe_int as _safe_int  # type: ignore[no-redef]

try:
    from .free_proxy_health import is_proxy_health_failure, is_security_challenge_failure
except ImportError:
    from free_proxy_health import is_proxy_health_failure, is_security_challenge_failure  # type: ignore[no-redef]


PROXY_STATUSES = frozenset({"unknown", "available", "quarantined", "burned"})
PROXY_ALLOCATION_MODES = frozenset({"healthy_random"})
# A row whose sticky-session window has less than this remaining is not
# allocated: a task starting near the window end would observe a mid-task
# exit rotation (which invalidates cf_clearance and re-triggers challenges).
# Expired-window rows are replaced by the tunnel target-size maintainer.
MIN_USABLE_WINDOW_SECONDS = 600


try:
    from .free_proxy_parse import (
        DEFAULT_PROXY_COUNTRY,
        DEFAULT_PROXY_GROUP,
        DEFAULT_PROXY_PROBE_URL,
        PROXY_COUNTRY_PATTERN,
        SINGLE_POOL_COUNTRY,
        SINGLE_POOL_GROUP,
        SUPPORTED_FREE_DRIVERS,
        infer_country,
        normalize_country,
        normalize_group,
        normalize_probe_url,
        _candidate_probe_ip,
        _exception_text,
        _extract_probe_ip,
        _identity,
        _is_chatgpt_probe_target,
        _is_tls_compatibility_error,
        _normalize_driver,
        _parse,
        _percentile,
        _proxy_url,
        _record_from_url,
    )
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_proxy_parse import (  # type: ignore[no-redef]
        DEFAULT_PROXY_COUNTRY,
        DEFAULT_PROXY_GROUP,
        DEFAULT_PROXY_PROBE_URL,
        PROXY_COUNTRY_PATTERN,
        SINGLE_POOL_COUNTRY,
        SINGLE_POOL_GROUP,
        SUPPORTED_FREE_DRIVERS,
        infer_country,
        normalize_country,
        normalize_group,
        normalize_probe_url,
        _candidate_probe_ip,
        _exception_text,
        _extract_probe_ip,
        _identity,
        _is_chatgpt_probe_target,
        _is_tls_compatibility_error,
        _normalize_driver,
        _parse,
        _percentile,
        _proxy_url,
        _record_from_url,
    )


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


class FreeProxyPool(FreeProxyStoreHealthMixin):
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
        # config passes ``remote`` explicitly; direct legacy callers and test
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
            "last_probe_http_status": _safe_int(
                value.get("last_probe_http_status"),
                default=None,
                minimum=100,
                maximum=599,
            ),
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
            "burned_reason": str(value.get("burned_reason") or "").strip()[:80],
            "burned_at": _safe_float(value.get("burned_at"), minimum=0),
            "window_started_at": _safe_float(value.get("window_started_at"), minimum=0),
            "window_expires_at": _safe_float(value.get("window_expires_at"), minimum=0),
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
                # Re-importing an identity is an explicit operator statement
                # that the burned exit is usable again (e.g. after the
                # provider rotated it); minted tunnel rows never collide
                # because every mint generates a fresh sid.
                if current.get("status") == "burned":
                    current["status"] = "unknown"
                    current["burned_reason"] = ""
            self._save(by_identity.values())
            return added

    def replace_text(
        self,
        content: str,
        *,
        country: str | None = None,
        group: str | None = None,
        scheme: str | None = None,
        source_label: str | None = None,
        provider: str | None = None,
    ) -> int:
        """Replace the complete saved proxy snapshot atomically.

        Empty content intentionally clears the pool.  Non-empty content must
        contain at least one valid row; parsing happens before touching the
        persisted file so a bad replacement cannot destroy the current pool.
        """
        incoming = self._parse_lines(
            content,
            country=SINGLE_POOL_COUNTRY,
            group=SINGLE_POOL_GROUP,
            scheme=scheme or self.default_scheme,
            source_label=source_label or provider or "",
        )
        if str(content or "").strip() and not incoming:
            raise FreeRegisterError("free_proxy_pool", "Free 代理池", "Free 代理池没有有效代理")
        with self._lock:
            self._save(incoming)
            return len(incoming)

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
        _normalize_driver(driver)
        current_time = time.time() if now is None else now
        rows: list[dict[str, Any]] = []
        for row in self._load():
            if not row.get("enabled"):
                continue
            if row.get("status") == "burned":
                continue
            if row.get("status") == "quarantined" and not self._quarantine_expired(row, current_time):
                continue
            # Window-aware allocation: skip rows whose sticky-session window
            # cannot cover a full task anymore.  Rows without window metadata
            # (manual imports) are never filtered.
            expires = _safe_float(row.get("window_expires_at"), minimum=0) or 0
            if expires and expires - current_time < MIN_USABLE_WINDOW_SECONDS:
                continue
            rows.append(row)
        return rows

    def healthy_count(self, *, driver: str = "protocol") -> int:
        """Number of dispatchable proxies in the shared healthy pool.

        Batch services size their in-flight ceiling from this so account
        operations never outpace the proxy pool they depend on.
        """
        return len(self._eligible(driver=driver))

    def _pool_health_summary(self, *, driver: str = "protocol", candidates: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
        """Summarize why a saved pool cannot currently satisfy a bind.

        This is diagnostic metadata only.  It deliberately exposes counts and
        stable failure node codes, never proxy addresses, usernames, or
        passwords.  Keeping this distinction in the error makes a quarantined
        pool distinguishable from a missing pool without weakening allocation.
        """
        _normalize_driver(driver)
        rows = self._load()
        candidate_ids = {
            str(row.get("proxy_id") or row.get("_identity") or "")
            for row in candidates
            if isinstance(row, Mapping)
        }
        now = time.time()
        enabled = [row for row in rows if bool(row.get("enabled", True))]
        quarantined = [
            row for row in enabled
            if row.get("status") == "quarantined" and not self._quarantine_expired(row, now)
        ]
        burned = [row for row in enabled if row.get("status") == "burned"]
        unsupported: list[Mapping[str, Any]] = []
        failure_nodes: list[str] = []
        for row in quarantined:
            failure = row.get("last_failure")
            if isinstance(failure, Mapping):
                code = str(failure.get("node_code") or "").strip()
                if code and code not in failure_nodes:
                    failure_nodes.append(code)
        return {
            "total": len(rows),
            "enabled": len(enabled),
            "candidates": len(candidate_ids),
            "quarantined": len(quarantined),
            "burned": len(burned),
            "disabled": len(rows) - len(enabled),
            "unsupported": len(unsupported),
            "failure_nodes": failure_nodes[:3],
        }

    def _pool_health_error(self, *, requested: int, driver: str, candidates: Iterable[Mapping[str, Any]] = ()) -> FreeRegisterError:
        driver = _normalize_driver(driver)
        summary = self._pool_health_summary(driver=driver, candidates=candidates)
        if summary["total"] <= 0:
            message = "Free 代理池没有保存记录，请先导入代理"
            retryable = False
        elif summary["candidates"] <= 0:
            reasons: list[str] = []
            if summary["quarantined"]:
                reasons.append(f"已隔离 {summary['quarantined']} 条")
            if summary.get("burned"):
                reasons.append(f"已废弃 {summary['burned']} 条（安全挑战）")
            if summary["disabled"]:
                reasons.append(f"已禁用 {summary['disabled']} 条")
            if summary["unsupported"]:
                reasons.append(f"当前链路不支持 {summary['unsupported']} 条")
            reason_text = "，".join(reasons) or "没有通过健康筛选"
            nodes = "、".join(summary["failure_nodes"])
            suffix = f"；最近失败节点：{nodes}" if nodes else ""
            message = (
                f"Free 代理池有 {summary['total']} 条记录，但当前可分配健康代理为 0 条"
                f"（启用 {summary['enabled']} 条，{reason_text}{suffix}）。"
                "请在非运行状态执行代理连通性检测；隔离期未到前不会自动分配坏代理。"
            )
            retryable = bool(summary["quarantined"])
        else:
            message = f"代理绑定数量不足：需要 {requested} 个，当前只有 {summary['candidates']} 个"
            retryable = True
        return FreeRegisterError(
            "free_proxy_preflight",
            "Free 代理预检",
            message,
            retryable=retryable,
            error_code="free_proxy_pool_empty",
        )

    def values(self, content: str = "") -> list[str]:
        with self._lock:
            rows = self._parse_lines(content, country=SINGLE_POOL_COUNTRY, group=SINGLE_POOL_GROUP, scheme=self.default_scheme) if str(content or "").strip() else self._load()
            return [_proxy_url(row) for row in rows]

    def entries(self) -> list[dict[str, Any]]:
        """Compatibility view used by the existing Free manager."""
        with self._lock:
            # ``_load`` builds a fresh object graph on every call, so the
            # historical deepcopy only duplicated already-private data.
            return self._load()

    def available(self, count: int, *, country: str | None = None, group: str | None = None, driver: str = "protocol") -> list[dict[str, Any]]:
        driver = _normalize_driver(driver)
        with self._lock:
            return self._eligible(country=country, group=group, driver=driver)[:max(0, int(count))]

    def records(self, *, country: str | None = None, group: str | None = None, driver: str = "protocol") -> list[dict[str, Any]]:
        driver = _normalize_driver(driver)
        with self._lock:
            return self._eligible(country=country, group=group, driver=driver)

    def public(self) -> dict[str, Any]:
        with self._lock:
            rows = self._load()
            return {
                "count": len(rows),
                "allocation_mode": self.allocation_mode,
                # This is the editable snapshot used by the local settings
                # page.  It is intentionally canonicalized from persisted
                # rows so loading and saving use the same parser semantics.
                "content": "\n".join(_proxy_url(row) for row in rows),
                "rows": [self._public_row(row, index) for index, row in enumerate(rows, 1)],
                # Keep one unclassified aggregate for response compatibility.
                # Its empty labels are intentional: historical country/group
                # values are never restored and cannot become selectors.
                "groups": self.group_summaries(rows),
                "countries": self.country_summaries(rows),
            }

    def _public_health_state(self, row: Mapping[str, Any], now: float | None = None) -> dict[str, Any]:
        """Project persisted health fields into the state visible to clients.

        ``status`` is persisted history, so an expired quarantine must not be
        rendered as an active quarantine.  Keep the historical value in
        ``stored_status`` for diagnostics and expose explicit booleans for
        schedulers/UI callers.  A row whose quarantine expired is eligible for
        one bounded re-probe, but is shown as ``unknown`` until that probe
        succeeds rather than being advertised as healthy.
        """
        current_time = time.time() if now is None else now
        stored_status = str(row.get("status") or "unknown")
        if stored_status not in PROXY_STATUSES:
            stored_status = "unknown"
        enabled = bool(row.get("enabled", True))
        quarantine_expired = (
            stored_status == "quarantined"
            and self._quarantine_expired(row, current_time)
        )
        quarantine_active = (
            enabled
            and stored_status == "quarantined"
            and not quarantine_expired
        )
        # ``burned`` never expires on its own: a challenged exit stays out of
        # allocation until an operator re-imports the identity or the
        # regenerable tunnel row is replaced.
        burned_active = enabled and stored_status == "burned"
        if not enabled:
            effective_status = "disabled"
        elif burned_active:
            effective_status = "burned"
        elif quarantine_active:
            effective_status = "quarantined"
        elif quarantine_expired:
            effective_status = "unknown"
        else:
            effective_status = stored_status
        dispatchable = enabled and not quarantine_active and not burned_active
        return {
            "enabled": enabled,
            "stored_status": stored_status,
            "effective_status": effective_status,
            "quarantine_active": quarantine_active,
            "quarantine_expired": quarantine_expired,
            "burned_active": burned_active,
            "eligible": dispatchable,
            "dispatchable": dispatchable,
        }

    def _public_row(self, row: Mapping[str, Any], index: int | None = None) -> dict[str, Any]:
        leases = self._active_leases(row)
        configured_scheme = str(row.get("scheme") or self.default_scheme)
        health = self._public_health_state(row)
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
            "country": SINGLE_POOL_COUNTRY,
            "group": SINGLE_POOL_GROUP,
            "enabled": health["enabled"],
            # ``status`` is now the effective UI state.  Preserve the raw
            # persisted status separately so diagnostics can still explain a
            # recently expired quarantine.
            "status": health["effective_status"],
            "stored_status": health["stored_status"],
            "effective_status": health["effective_status"],
            "quarantine_active": health["quarantine_active"],
            "quarantine_expired": health["quarantine_expired"],
            "eligible": health["eligible"],
            "dispatchable": health["dispatchable"],
            "quarantined_until": row.get("quarantined_until"),
            "burned_reason": str(row.get("burned_reason") or ""),
            "burned_at": row.get("burned_at") or None,
            "window_started_at": row.get("window_started_at") or None,
            "window_expires_at": row.get("window_expires_at") or None,
            "lease_until": max((float(lease.get("until") or 0) for lease in leases), default=None),
            "active_lease_count": len(leases),
            "last_checked_at": row.get("last_checked_at"),
            "last_probe_http_status": row.get("last_probe_http_status"),
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

    def group_summaries(self, rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        # Callers that already hold a ``_load`` snapshot (e.g. ``public``)
        # pass it in to avoid re-reading the whole pool per aggregate.
        if rows is None:
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

    def country_summaries(self, rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, int]] = {}
        for value in self.group_summaries(rows):
            current = grouped.setdefault(value["country"], {"total": 0, "enabled": 0, "available": 0, "quarantined": 0, "leased": 0, "leased_proxies": 0})
            for key in ("total", "enabled", "available", "quarantined", "leased", "leased_proxies"):
                current[key] += int(value[key])
        return [{"country": country, **values} for country, values in sorted(grouped.items())]

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
        driver = _normalize_driver(driver)
        requested = max(0, int(count))
        if requested == 0:
            return []
        self._last_bind_diagnostics = []
        # Per-bind, per-proxy status observations stay in memory and are
        # keyed by the stable proxy id.  This avoids leaking status across
        # concurrent binds while retaining the existing public return shape.
        probe_http_statuses: dict[str, int | None] = {}
        with self._lock:
            if health_probe_ttl_seconds is not None:
                self.health_probe_ttl_seconds = max(0, int(health_probe_ttl_seconds))
            inline_content = bool(str(content or "").strip())
            if inline_content:
                values = self._parse_lines(content, country=SINGLE_POOL_COUNTRY, group=SINGLE_POOL_GROUP, scheme=self.default_scheme)
            else:
                # All supported drivers share the same healthy random pool.
                values = self._eligible(driver="protocol")
            excluded = {str(value) for value in exclude_proxy_ids if str(value)}
            if excluded:
                values = [row for row in values if str(row.get("proxy_id") or "") not in excluded]
            if not values:
                if inline_content:
                    raise FreeRegisterError(
                        "free_proxy_preflight", "Free 代理预检",
                        "当前没有符合条件的健康代理",
                        retryable=False,
                        error_code="free_proxy_pool_empty",
                    )
                raise self._pool_health_error(requested=requested, driver=driver)
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
                # The bounded refresh probes run below, after the lock: a
                # multi-second network probe inside the critical section
                # serializes every concurrent bind behind one TLS handshake.
                stale_candidates = stale
                # Recent rows were already health-checked; stale rows have
                # just been refreshed and should not be probed a second time.
                perform_probe_for_selected = False
            else:
                selected_values = [source.choice(values) for _ in range(requested)]
                perform_probe_for_selected = perform_probe
        check = probe
        if stale_refresh:
            for record in stale_candidates:
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
                    _set_probe_status(None)
                    if probe is None:
                        exit_ip, probe_mode = self._probe_with_policy(transport_proxy, probe_url)
                    else:
                        exit_ip, probe_mode = str(probe(transport_proxy, probe_url)).strip(), "custom"
                    observed_status = _probe_status()
                    probe_http_statuses[str(record.get("proxy_id") or "")] = observed_status or 200
                    exit_ip = str(exit_ip or "").strip() if _candidate_probe_ip(exit_ip) else ""
                    self.record_success(
                        str(record.get("proxy_id") or ""),
                        exit_ip=exit_ip,
                        latency_ms=int((time.monotonic() - started) * 1000),
                        probe_mode=probe_mode,
                        effective_scheme=urlsplit(transport_proxy).scheme.lower(),
                        http_status=probe_http_statuses.get(str(record.get("proxy_id") or "")),
                    )
                    # ``record_success`` reloads and persists the row;
                    # carry the fresh observation into this bind's local
                    # snapshot so the returned binding reflects it.
                    record["last_exit_ip"] = exit_ip
                    record["latency_ms"] = int((time.monotonic() - started) * 1000)
                    record["last_probe_mode"] = probe_mode
                    selected_values.append(record)
                except Exception as exc:
                    probe_http_statuses[str(record.get("proxy_id") or "")] = _probe_status()
                    # A stale refresh has the same health policy as an
                    # explicit bind: only transport/5xx evidence may
                    # quarantine a saved row.  Challenges and business
                    # 4xx/429 responses are surfaced to the caller but do
                    # not silently poison the shared pool.
                    health_error: BaseException = exc
                    if not getattr(health_error, "node_code", ""):
                        # Raw probe exceptions do not carry a Free node;
                        # attach one locally so HTTP 5xx can be classified
                        # without broadening the global classifier to all
                        # arbitrary exceptions with a status attribute.
                        health_error = FreeRegisterError(
                            "free_proxy_preflight",
                            "Free 代理预检",
                            proxy_error_detail(exc),
                            provider_status=getattr(exc, "provider_status", None),
                            error_code=proxy_error_code(exc),
                        )
                        health_error.__cause__ = exc
                    if is_proxy_health_failure(health_error):
                        self.record_failure(
                            str(record.get("proxy_id") or ""),
                            node_code=proxy_error_code(exc),
                            message=proxy_error_detail(exc),
                            http_status=probe_http_statuses.get(str(record.get("proxy_id") or "")),
                        )
                    elif is_security_challenge_failure(health_error):
                        # A challenged candidate retires permanently and is
                        # skipped exactly like a failed transport candidate;
                        # binding continues with the next healthy row.
                        self.record_challenge_burn(str(record.get("proxy_id") or ""))
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
                raise self._pool_health_error(
                    requested=requested,
                    driver=driver,
                    candidates=selected_values,
                )
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
                    _set_probe_status(None)
                    if perform_probe_for_selected:
                        if check is None:
                            exit_ip, probe_mode = self._probe_with_policy(transport_proxy, probe_url)
                        else:
                            exit_ip, probe_mode = str(check(transport_proxy, probe_url)).strip(), "custom"
                        probe_http_statuses[cache_key] = _probe_status() or 200
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
                    probe_http_statuses.setdefault(cache_key, _probe_status())
                    if not inline_content and is_proxy_health_failure(exc):
                        self.record_failure(
                            str(record.get("proxy_id") or ""),
                            node_code="free_proxy_preflight",
                            message=str(exc),
                            http_status=probe_http_statuses.get(cache_key),
                        )
                    raise
                except Exception as exc:
                    probe_http_statuses.setdefault(cache_key, _probe_status())
                    failure_code = proxy_error_code(exc)
                    failure = FreeRegisterError(
                        failure_code,
                        proxy_error_label(failure_code),
                        f"代理池第 {index} 条代理请求失败：{proxy_error_detail(exc)}",
                        error_code=failure_code,
                        provider_status=getattr(exc, "provider_status", None),
                    )
                    # Preserve the transport type for health classification
                    # before the exception is raised to the caller.
                    failure.__cause__ = exc
                    if not inline_content and is_proxy_health_failure(failure):
                        self.record_failure(
                            str(record.get("proxy_id") or ""),
                            node_code=failure_code,
                            message=str(failure),
                            http_status=probe_http_statuses.get(cache_key),
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
            if cache_key not in probe_http_statuses:
                probe_http_statuses[cache_key] = _safe_int(
                    record.get("last_probe_http_status"),
                    default=None,
                    minimum=100,
                    maximum=599,
                )
            if (perform_probe_for_selected or check_chatgpt) and not inline_content and cached is None:
                self.record_success(
                    str(record.get("proxy_id") or ""),
                    exit_ip=exit_ip,
                    latency_ms=latency_ms if perform_probe_for_selected else None,
                    probe_mode=probe_mode,
                    chatgpt_login_status=chatgpt_status,
                    chatgpt_login_probe_mode=chatgpt_probe_mode,
                    effective_scheme=urlsplit(transport_proxy).scheme.lower(),
                    http_status=probe_http_statuses.get(cache_key),
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
                "http_status": probe_http_statuses.get(cache_key),
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
            # The transport projection of the binding is row-independent;
            # computing it once keeps the match loop free of repeated
            # normalization/quote work.
            binding_transport = proxy_transport_value(str(binding.proxy), driver="protocol")
            target = next((
                row for row in rows
                if str(row.get("proxy_id")) == str(binding.proxy_id)
                or row.get("_normalized") == binding.proxy
                or proxy_transport_value(str(row.get("_normalized") or ""), driver="protocol") == binding_transport
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

    def record_challenge_burn(self, proxy_id: str, *, reason: str = "security_challenge") -> bool:
        """Mark one proxy burned after a target-site security challenge.

        Burned rows never participate in allocation again and never expire on
        their own; regenerable tunnel rows are removed by the tunnel
        maintainer after a replacement is minted.  Returns True when a row
        matched.
        """
        with self._lock:
            rows = self._load()
            changed = False
            for row in rows:
                if str(row.get("proxy_id")) != str(proxy_id):
                    continue
                row.update({
                    "status": "burned",
                    "burned_reason": str(reason or "security_challenge").strip()[:80] or "security_challenge",
                    "burned_at": time.time(),
                    "quarantined_until": None,
                    "consecutive_failures": 0,
                })
                self._sync_lease_compat(row)
                changed = True
                break
            if changed:
                self._save(rows)
            return changed

    def remove(self, proxy_id: str) -> bool:
        """Delete one row by id.

        Only regenerable tunnel-auto rows are removed programmatically;
        manually imported rows are burned/disabled instead so operator data
        is never deleted automatically.
        """
        with self._lock:
            rows = self._load()
            remaining = [row for row in rows if str(row.get("proxy_id")) != str(proxy_id)]
            if len(remaining) == len(rows):
                return False
            self._save(remaining)
            return True

    def annotate_window(self, proxy_id: str, *, started_at: float, expires_at: float) -> bool:
        """Record the sticky-session window observed for a minted tunnel row.

        The window starts at the row's first transport use, so it is written
        by the minting path right after the row enters the pool.  Rows without
        window metadata are never filtered by the allocation window check.
        """
        with self._lock:
            rows = self._load()
            changed = False
            for row in rows:
                if str(row.get("proxy_id")) != str(proxy_id):
                    continue
                row["window_started_at"] = max(0.0, float(started_at))
                row["window_expires_at"] = max(0.0, float(expires_at))
                changed = True
                break
            if changed:
                self._save(rows)
            return changed

    def update_group(self, country: str, group: str, *, new_country: str | None = None, new_group: str | None = None, enabled: bool | None = None) -> dict[str, int]:
        with self._lock:
            rows = self._load()
            # Country/group are no longer allocation dimensions.  Preserve
            # the legacy endpoint only for an explicit shared-pool toggle
            # (the canonical empty labels), which keeps existing operators'
            # disable/enable control without reintroducing classification.
            # Requests carrying historical labels remain a no-op and cannot
            # mutate or delete the shared pool by accident.
            labels = (str(country or "").strip(), str(group or "").strip())
            replacement_labels = (
                str(new_country or "").strip(), str(new_group or "").strip()
            )
            if any(labels) or any(replacement_labels) or enabled is None:
                return {"matched": 0, "modified": 0, "deprecated": 1}
            matched = len(rows)
            modified = 0
            for row in rows:
                before = bool(row.get("enabled", True))
                row["enabled"] = bool(enabled)
                modified += int(before != bool(enabled))
            if modified:
                self._save(rows)
            return {"matched": matched, "modified": modified, "deprecated": 1}

    def delete_group(self, country: str, group: str) -> int:
        with self._lock:
            # A legacy group-delete request must never delete or rewrite the
            # shared pool.  The integer return preserves the old signature.
            return 0


__all__ = [
    "CHATGPT_LOGIN_PROBE_URL",
    "DEFAULT_PROXY_PROBE_URL",
    "DEFAULT_PROXY_COUNTRY",
    "DEFAULT_PROXY_GROUP",
    "FreeProxyLease",
    "FreeProxyPool",
    "MIN_USABLE_WINDOW_SECONDS",
    "infer_country",
    "normalize_country",
    "normalize_group",
    "normalize_probe_url",
]
