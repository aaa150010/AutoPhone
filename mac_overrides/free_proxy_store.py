"""Structured proxy resources for the isolated Free registration center.

The public surface deliberately keeps credentials out of every response.  The
private JSON file is mode 0600 and is only read by the Free workers.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import copy
import json
import os
from pathlib import Path
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
        proxy_error_detail,
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
        proxy_error_detail,
    )


SUPPORTED_ROXY_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})
PROXY_STATUSES = frozenset({"unknown", "available", "quarantined"})
DEFAULT_PROXY_COUNTRY = "ZZ"
DEFAULT_PROXY_GROUP = "默认组"
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
    port = int(record.get("port") or 0)
    username = quote(str(record.get("username") or ""), safe="")
    password = quote(str(record.get("password") or ""), safe="")
    auth = f"{username}:{password}@" if username or password else ""
    return urlunsplit((scheme, f"{auth}{host}:{port}", "", "", ""))


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
        "last_checked_at": None,
        "last_exit_ip": "",
        "latency_ms": None,
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
        record = {
            "proxy_id": str(value.get("proxy_id") or fingerprint(_identity(url_parts))),
            "host": str(url_parts.hostname or value.get("host") or ""),
            "port": int(url_parts.port or value.get("port") or 0),
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
            "last_checked_at": value.get("last_checked_at"),
            "last_exit_ip": str(value.get("last_exit_ip") or ""),
            "latency_ms": value.get("latency_ms"),
            "consecutive_failures": max(0, int(value.get("consecutive_failures") or 0)),
            "quarantined_until": value.get("quarantined_until"),
            "last_failure": copy.deepcopy(value.get("last_failure")) if isinstance(value.get("last_failure"), Mapping) else None,
            "_identity": _identity(url_parts),
            "_normalized": normalized,
        }
        return record if record["host"] and record["port"] > 0 else None

    def _save(self, rows: Iterable[Mapping[str, Any]]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = []
        for row in rows:
            value = dict(row)
            value.pop("_identity", None)
            value.pop("_normalized", None)
            payload.append(value)
        atomic_write(self.path, {"version": 2, "proxies": payload})

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

    def configure_policy(self, *, failure_threshold: int | None = None, quarantine_seconds: int | None = None) -> None:
        self.failure_threshold = max(1, int(failure_threshold or self.failure_threshold))
        self.quarantine_seconds = max(1, int(quarantine_seconds or self.quarantine_seconds))

    def _quarantine_expired(self, row: Mapping[str, Any], now: float | None = None) -> bool:
        until = row.get("quarantined_until")
        try:
            return until is not None and float(until) <= (time.time() if now is None else now)
        except (TypeError, ValueError):
            return True

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
            lease_until = row.get("lease_until")
            if row.get("lease_owner") and lease_until is not None:
                try:
                    if float(lease_until) > current_time:
                        continue
                except (TypeError, ValueError):
                    pass
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
                "rows": [self._public_row(row, index) for index, row in enumerate(rows, 1)],
                "groups": self.group_summaries(),
                "countries": self.country_summaries(),
            }

    def _public_row(self, row: Mapping[str, Any], index: int | None = None) -> dict[str, Any]:
        value = {
            "proxy_id": row.get("proxy_id", ""),
            "index": index,
            "masked": mask_proxy(_proxy_url(row)),
            "fingerprint": str(row.get("proxy_id") or ""),
            "scheme": row.get("scheme", ""),
            "country": row.get("country", DEFAULT_PROXY_COUNTRY),
            "group": row.get("group", DEFAULT_PROXY_GROUP),
            "enabled": bool(row.get("enabled", True)),
            "status": row.get("status", "unknown"),
            "lease_until": row.get("lease_until"),
            "last_checked_at": row.get("last_checked_at"),
            "last_exit_ip": row.get("last_exit_ip", ""),
            "latency_ms": row.get("latency_ms"),
            "consecutive_failures": int(row.get("consecutive_failures") or 0),
        }
        return value

    def group_summaries(self) -> list[dict[str, Any]]:
        rows = self._load()
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        now = time.time()
        for row in rows:
            key = (str(row.get("country") or DEFAULT_PROXY_COUNTRY), normalize_group(row.get("group")))
            current = grouped.setdefault(key, {"country": key[0], "group": key[1], "total": 0, "enabled": 0, "available": 0, "leased": 0, "quarantined": 0, "schemes": set()})
            current["total"] += 1
            current["enabled"] += int(bool(row.get("enabled")))
            leased = False
            if row.get("lease_owner") and row.get("lease_until") is not None:
                try:
                    leased = float(row["lease_until"]) > now
                except (TypeError, ValueError):
                    pass
            if leased:
                current["leased"] += 1
            elif row.get("status") == "quarantined" and not self._quarantine_expired(row, now):
                current["quarantined"] += 1
            elif row.get("enabled"):
                # "available" is a dispatch count, so an active lease is not
                # reported as available even though the row remains enabled.
                current["available"] += 1
            current["schemes"].add(str(row.get("scheme") or self.default_scheme))
        return [
            {**value, "schemes": sorted(value["schemes"])}
            for _key, value in sorted(grouped.items())
        ]

    def country_summaries(self) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, int]] = {}
        for value in self.group_summaries():
            current = grouped.setdefault(value["country"], {"total": 0, "enabled": 0, "available": 0, "quarantined": 0, "leased": 0})
            for key in ("total", "enabled", "available", "quarantined", "leased"):
                current[key] += int(value[key])
        return [{"country": country, **values} for country, values in sorted(grouped.items())]

    @staticmethod
    def _probe(proxy: str, target: str) -> str:
        from curl_cffi import requests as curl_requests

        session = curl_requests.Session(impersonate="chrome", verify=False)
        session.proxies = {"http": proxy, "https": proxy}
        if hasattr(session, "trust_env"):
            session.trust_env = False
        with _without_proxy_environment():
            try:
                response = session.get(target, headers={"Accept": "text/plain", "Cache-Control": "no-cache"}, timeout=12)
            finally:
                close = getattr(session, "close", None)
                if callable(close):
                    close()
        status = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= status < 300:
            raise ValueError(f"代理出口检测返回 HTTP {status}")
        value = bytes(getattr(response, "content", b"") or b"")[:128].decode("utf-8", "ignore").strip()
        if not re.fullmatch(r"[0-9a-fA-F:.]{3,64}", value):
            raise ValueError("代理出口 IP 响应格式无效")
        return value

    def bind(
        self,
        count: int,
        *,
        content: str = "",
        probe: Callable[[str, str], str] | None = None,
        probe_url: str = "https://api.ipify.org",
        country: str | None = None,
        group: str | None = None,
        driver: str = "protocol",
    ) -> list[ProxyBinding]:
        with self._lock:
            if str(content or "").strip():
                values = self._parse_lines(content, country=country or "", group=group or DEFAULT_PROXY_GROUP, scheme=self.default_scheme)
                selected_country = normalize_country(country) if str(country or "").strip() else None
                selected_group = normalize_group(group) if str(group or "").strip() else None
                values = [
                    row for row in values
                    if (not selected_country or row.get("country") == selected_country)
                    and (not selected_group or row.get("group") == selected_group)
                    and (driver != "roxybrowser" or str(row.get("scheme") or "").lower() in SUPPORTED_ROXY_SCHEMES)
                ]
            else:
                values = self._eligible(country=country, group=group, driver=driver)
            if len(values) < count:
                raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", f"Free 代理数量不足：需要 {count} 个，当前只有 {len(values)} 个", retryable=False)
            selected = values[:max(0, int(count))]
            identities = [str(value.get("_identity") or value.get("proxy_id")) for value in selected]
            if len(set(identities)) != len(identities):
                raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "代理池包含重复代理，无法建立一号一代理绑定", retryable=False)
        check = probe or self._probe
        bindings: list[ProxyBinding] = []
        exit_ips: list[str] = []
        for index, record in enumerate(selected, 1):
            proxy = _proxy_url(record)
            started = time.monotonic()
            try:
                exit_ip = str(check(proxy, probe_url)).strip()
                if not exit_ip:
                    raise ValueError("出口 IP 为空")
            except FreeRegisterError:
                raise
            except Exception as exc:
                if not str(content or "").strip():
                    self.record_failure(str(record.get("proxy_id") or ""), node_code="free_proxy_preflight", message=proxy_error_detail(exc))
                raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", f"代理池第 {index} 条出口 IP 检测失败：{proxy_error_detail(exc)}") from exc
            exit_ips.append(exit_ip)
            if not str(content or "").strip():
                self.record_success(str(record.get("proxy_id") or ""), exit_ip=exit_ip, latency_ms=int((time.monotonic() - started) * 1000))
            bindings.append(ProxyBinding(proxy, str(record.get("proxy_id") or fingerprint(proxy)), mask_proxy(proxy), exit_ip, proxy_id=str(record.get("proxy_id") or ""), scheme=str(record.get("scheme") or self.default_scheme), country=str(record.get("country") or DEFAULT_PROXY_COUNTRY), group=str(record.get("group") or DEFAULT_PROXY_GROUP)))
        if len(set(exit_ips)) != len(exit_ips):
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "代理出口 IP 重复，无法建立一号一 IP 绑定", retryable=False)
        return bindings

    def verify(self, binding: ProxyBinding, *, probe: Callable[[str, str], str] | None = None, probe_url: str = "https://api.ipify.org") -> str:
        try:
            current = str((probe or self._probe)(binding.proxy, probe_url)).strip()
        except Exception as exc:
            raise FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", f"固定代理出口复核失败：{proxy_error_detail(exc)}") from exc
        if current != binding.exit_ip:
            raise FreeRegisterError("free_proxy_drift", "校验 Free 代理出口", "固定代理的出口 IP 在任务期间发生变化，任务已停止且未切换代理", retryable=False)
        if binding.proxy_id:
            self.record_success(binding.proxy_id, exit_ip=current)
        return current

    def lease(self, binding: ProxyBinding, *, owner: str, batch_id: str, task_id: str, lease_seconds: int = 180) -> None:
        with self._lock:
            rows = self._load()
            target = next((row for row in rows if str(row.get("proxy_id")) == str(binding.proxy_id) or row.get("_normalized") == binding.proxy), None)
            if target is None:
                raise FreeRegisterError("free_proxy_lease", "租用 Free 代理", "固定代理已不存在", retryable=False)
            now = time.time()
            if target.get("lease_owner") and float(target.get("lease_until") or 0) > now and target.get("lease_owner") != owner:
                raise FreeRegisterError("free_proxy_lease", "租用 Free 代理", "代理已被其他 Free 任务租用", retryable=False)
            target.update({"lease_owner": owner, "lease_until": now + max(30, int(lease_seconds)), "lease_batch_id": batch_id, "lease_task_id": task_id})
            self._save(rows)

    def heartbeat(self, owner: str, *, lease_seconds: int = 180) -> None:
        with self._lock:
            rows = self._load()
            changed = False
            until = time.time() + max(30, int(lease_seconds))
            for row in rows:
                if row.get("lease_owner") == owner:
                    row["lease_until"] = until
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
                if owner and row.get("lease_owner") not in {"", owner}:
                    continue
                row.update({"lease_owner": "", "lease_until": None, "lease_batch_id": "", "lease_task_id": ""})
                changed = True
            if changed:
                self._save(rows)

    def record_success(self, proxy_id: str, *, exit_ip: str = "", latency_ms: int | None = None) -> None:
        with self._lock:
            rows = self._load()
            for row in rows:
                if str(row.get("proxy_id")) != str(proxy_id):
                    continue
                row.update({"status": "available", "consecutive_failures": 0, "last_checked_at": time.time(), "last_exit_ip": exit_ip or row.get("last_exit_ip", ""), "latency_ms": latency_ms if latency_ms is not None else row.get("latency_ms"), "last_failure": None})
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
                row.update({"consecutive_failures": failures, "last_checked_at": time.time(), "last_failure": {"node_code": node_code, "message": str(message or "")[:300]}})
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
            if any(row.get("lease_owner") and float(row.get("lease_until") or 0) > time.time() for row in targets):
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
    "DEFAULT_PROXY_COUNTRY",
    "DEFAULT_PROXY_GROUP",
    "SUPPORTED_ROXY_SCHEMES",
    "FreeProxyLease",
    "FreeProxyPool",
    "infer_country",
    "normalize_country",
    "normalize_group",
]
