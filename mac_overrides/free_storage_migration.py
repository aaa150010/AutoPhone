"""Legacy JSON/TXT import and one-time migration for the Free SQLite store.

Split out of ``free_storage.py``; ``FreeSQLiteStore`` composes these domain
mixins so the class body stays navigable while the on-disk schema, method set
and behavior remain unchanged.  Mixins rely on attributes defined by the
schema band (``self._dir``, ``self._db_path``, ``self._lock``, ``self._connection``,
``self._transaction`` ...).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import urlsplit

try:
    from .free_storage_common import (
    MANAGER_OWNER_KEY,
    MANAGER_OWNER_TTL_SECONDS,
    MIGRATION_KEY,
    PROXY_REPAIR_KEY,
    SCHEMA_VERSION,
    SECRET_MASK,
    TERMINAL_TASK_STATUSES,
    FreeStorageError,
    LeaseConflict,
    ManagerOwnerConflict,
    RevisionConflict,
    _EMAIL_RE,
    _LEGACY_PLAIN_DIMENSION_KEYS,
    _LEGACY_PROXY_DIMENSION_KEYS,
    _MAILBOX_SPLIT_RE,
    _MISSING,
    _NON_SECRET_METADATA_KEYS,
    _NON_SECRET_METADATA_KEY_TOKENS,
    _PRIVATE_KEYS,
    _SENSITIVE_KEY_RE,
    _clear_legacy_pool_dimensions,
    _fingerprint,
    _is_private_key,
    _json_object,
    _legacy_proxy_url,
    _mask_email,
    _mask_proxy,
    _merge_private_payload,
    _migration_marker_version,
    _normalize_proxy,
    _now,
    _parse_mailbox_line,
    _partition_json,
    _payload_with_fields,
    _redact,
    _safe_float,
    _safe_json,
    _split_private_payload,
    _stored_bool,
    _valid_migration_marker,
    )
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_storage_common import (  # type: ignore[no-redef]
    MANAGER_OWNER_KEY,
    MANAGER_OWNER_TTL_SECONDS,
    MIGRATION_KEY,
    PROXY_REPAIR_KEY,
    SCHEMA_VERSION,
    SECRET_MASK,
    TERMINAL_TASK_STATUSES,
    FreeStorageError,
    LeaseConflict,
    ManagerOwnerConflict,
    RevisionConflict,
    _EMAIL_RE,
    _LEGACY_PLAIN_DIMENSION_KEYS,
    _LEGACY_PROXY_DIMENSION_KEYS,
    _MAILBOX_SPLIT_RE,
    _MISSING,
    _NON_SECRET_METADATA_KEYS,
    _NON_SECRET_METADATA_KEY_TOKENS,
    _PRIVATE_KEYS,
    _SENSITIVE_KEY_RE,
    _clear_legacy_pool_dimensions,
    _fingerprint,
    _is_private_key,
    _json_object,
    _legacy_proxy_url,
    _mask_email,
    _mask_proxy,
    _merge_private_payload,
    _migration_marker_version,
    _normalize_proxy,
    _now,
    _parse_mailbox_line,
    _partition_json,
    _payload_with_fields,
    _redact,
    _safe_float,
    _safe_json,
    _split_private_payload,
    _stored_bool,
    _valid_migration_marker,
    )


class FreeStorageMigrationMixin:
    """Methods moved verbatim from FreeSQLiteStore."""


    def _record_legacy_read_error(self, path: Path, kind: str) -> None:
        """Record a credential-free, stable source-read diagnostic."""
        source_names = {
            "free_mailbox_pool.txt": "mailbox_pool",
            "free_mailbox_state.json": "mailbox_state",
            "free_proxy_pool.json": "proxy_state",
            "free_proxy_pool.txt": "proxy_pool",
            "tasks.json": "task_state",
        }
        # Result filenames came from legacy integrations and are not a safe
        # diagnostic identifier: some installations used an email address or
        # credential-derived value as the stem. Collapse them to a fixed
        # source code. Unknown sources use only a short hash, never the name.
        if path.parent.name == "free_register_results":
            source = "result"
        else:
            source = source_names.get(path.name)
        if not source:
            source = f"source_{hashlib.sha256(path.name.encode('utf-8')).hexdigest()[:8]}"
        marker = f"legacy_{str(kind or 'read').strip().lower()}_{source}"
        if marker not in self._legacy_read_errors:
            self._legacy_read_errors.append(marker)

    def _read_json_file(self, path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default
        except json.JSONDecodeError:
            self._record_legacy_read_error(path, "invalid")
            return default
        except (OSError, UnicodeError):
            self._record_legacy_read_error(path, "read")
            return default

    def _legacy_mailboxes(self) -> tuple[list[dict[str, Any]], list[str]]:
        errors: list[str] = []
        pool_path = self.root / "free_mailbox_pool.txt"
        state_path = self.root / "free_mailbox_state.json"
        try:
            lines = pool_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            lines = []
        except (OSError, UnicodeError):
            self._record_legacy_read_error(pool_path, "read")
            lines = []
        state_payload = self._read_json_file(state_path, {})
        state_rows = state_payload.get("rows") if isinstance(state_payload, Mapping) else {}
        if not isinstance(state_rows, Mapping):
            state_rows = {}
        rows: list[dict[str, Any]] = []
        for line_no, raw in enumerate(lines, 1):
            parsed = _parse_mailbox_line(raw)
            if parsed is None:
                if str(raw or "").strip() and not str(raw).lstrip().startswith("#"):
                    errors.append(f"mailbox_line_{line_no}")
                continue
            email, mailbox_url = parsed
            row_id = _fingerprint(f"{email}|{mailbox_url}")
            state = state_rows.get(row_id) if isinstance(state_rows, Mapping) else None
            state = dict(state) if isinstance(state, Mapping) else {}
            payload = _payload_with_fields(
                _clear_legacy_pool_dimensions(state),
                email=email,
                mailbox_url=mailbox_url,
                row_id=row_id,
            )
            rows.append({
                "row_id": row_id,
                "email": email,
                "mailbox_url": mailbox_url,
                "status": str(state.get("status") or "available"),
                "batch_id": str(state.get("batch_id") or ""),
                "lease_owner": str(state.get("lease_owner") or ""),
                "lease_until": _safe_float(state.get("lease_until")),
                "revision": max(0, int(state.get("revision") or 0)) if str(state.get("revision") or "0").lstrip("-").isdigit() else 0,
                "created_at": str(state.get("created_at") or _now()),
                "updated_at": str(state.get("updated_at") or _now()),
                "payload": payload,
            })
        return rows, errors

    def _legacy_proxies(self) -> tuple[list[dict[str, Any]], list[str]]:
        errors: list[str] = []
        path = self.root / "free_proxy_pool.json"
        payload = self._read_json_file(path, None)
        raw_rows = payload.get("proxies") if isinstance(payload, Mapping) else None
        if not isinstance(raw_rows, list):
            raw_rows = []
        if not raw_rows:
            legacy_path = self.root / "free_proxy_pool.txt"
            try:
                raw_lines = legacy_path.read_text(encoding="utf-8").splitlines()
            except FileNotFoundError:
                raw_lines = []
            except (OSError, UnicodeError):
                self._record_legacy_read_error(legacy_path, "read")
                raw_lines = []
            raw_rows = [{"proxy": line} for line in raw_lines]
        rows: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_rows, 1):
            if not isinstance(raw, Mapping):
                errors.append(f"proxy_row_{index}")
                continue
            # v1-v3 snapshots used host/port/auth scalar fields and did not
            # include a ``proxy`` URL.  Accept that shape as well as the
            # complete URL used by v4+ snapshots.
            proxy = _legacy_proxy_url(raw)
            if not proxy:
                errors.append(f"proxy_row_{index}")
                continue
            parsed = urlsplit(proxy)
            proxy_id = str(raw.get("proxy_id") or _fingerprint(proxy))
            now = _now()
            row_payload = _clear_legacy_pool_dimensions(raw, include_plain=True)
            row_payload.setdefault("proxy", proxy)
            rows.append({
                "proxy_id": proxy_id,
                "proxy": proxy,
                "scheme": str(raw.get("scheme") or parsed.scheme).lower(),
                "status": str(raw.get("status") or "unknown"),
                "enabled": 0 if raw.get("enabled") is False else 1,
                "lease_owner": str(raw.get("lease_owner") or ""),
                "lease_until": _safe_float(raw.get("lease_until")),
                "revision": max(0, int(raw.get("revision") or 0)) if str(raw.get("revision") or "0").lstrip("-").isdigit() else 0,
                "created_at": str(raw.get("created_at") or raw.get("imported_at") or now),
                "updated_at": str(raw.get("updated_at") or now),
                "payload": row_payload,
            })
        # Some installations contain a partially written/old JSON snapshot
        # alongside the authoritative text pool.  If no JSON row could be
        # normalized, use the text rows as a read-only fallback instead of
        # silently creating an empty SQLite proxy pool.
        if not rows:
            legacy_path = self.root / "free_proxy_pool.txt"
            try:
                raw_lines = legacy_path.read_text(encoding="utf-8").splitlines()
            except FileNotFoundError:
                raw_lines = []
            except (OSError, UnicodeError):
                self._record_legacy_read_error(legacy_path, "read")
                raw_lines = []
            for line_no, raw_line in enumerate(raw_lines, 1):
                proxy = _normalize_proxy(raw_line)
                if not proxy:
                    if str(raw_line or "").strip():
                        errors.append(f"proxy_line_{line_no}")
                    continue
                parsed = urlsplit(proxy)
                proxy_id = _fingerprint(proxy)
                now = _now()
                rows.append({
                    "proxy_id": proxy_id,
                    "proxy": proxy,
                    "scheme": str(parsed.scheme or "socks5").lower(),
                    "status": "unknown",
                    "enabled": 1,
                    "lease_owner": "",
                    "lease_until": None,
                    "revision": 0,
                    "created_at": now,
                    "updated_at": now,
                    "payload": {
                        "proxy": proxy,
                        "proxy_id": proxy_id,
                        "line_no": line_no,
                    },
                })
        return rows, errors

    def _legacy_tasks(self) -> tuple[list[dict[str, Any]], list[str]]:
        errors: list[str] = []
        payload = self._read_json_file(self.root / "tasks.json", {})
        raw_tasks = payload.get("tasks") if isinstance(payload, Mapping) else {}
        if not isinstance(raw_tasks, Mapping):
            return [], errors
        rows: list[dict[str, Any]] = []
        for task_id, raw in raw_tasks.items():
            if not isinstance(raw, Mapping):
                # Legacy task keys are operator-controlled and some old
                # integrations used an email address (or another secret) as
                # the dictionary key.  Migration diagnostics must remain
                # credential-free, so expose only a stable shape code.
                errors.append("task_row_invalid")
                continue
            item = _clear_legacy_pool_dimensions(raw)
            normalized_id = str(item.get("task_id") or task_id).strip()
            if not normalized_id:
                errors.append("task_empty_id")
                continue
            value = item.get("revision")
            try:
                revision = max(0, int(value or 0))
            except (TypeError, ValueError):
                revision = 0
            now = _now()
            rows.append({
                "task_id": normalized_id,
                "status": str(item.get("status") or "queued"),
                "revision": revision,
                "lease_owner": str(item.get("lease_owner") or ""),
                "lease_until": _safe_float(item.get("lease_until")),
                "created_at": str(item.get("created_at") or item.get("queued_at") or now),
                "updated_at": str(item.get("updated_at") or now),
                "payload": item,
            })
        return rows, errors

    def _legacy_results(self) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
        directory = self.root / "free_register_results"
        if not directory.is_dir():
            return [], []
        rows: list[tuple[str, dict[str, Any]]] = []
        errors: list[str] = []
        for path in sorted(directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                continue
            except json.JSONDecodeError:
                self._record_legacy_read_error(path, "invalid")
                errors.append("result_invalid")
                continue
            except (OSError, UnicodeError):
                self._record_legacy_read_error(path, "read")
                errors.append("result_unreadable")
                continue
            if not isinstance(payload, Mapping):
                errors.append("result_invalid_shape")
                continue
            row_id = str(payload.get("row_id") or path.stem).strip()
            if row_id:
                rows.append((row_id, _clear_legacy_pool_dimensions(payload)))
        return rows, errors

    def _repair_legacy_proxies(self) -> dict[str, Any]:
        """Serialize a complete legacy proxy repair within this process."""
        with self._lock:
            return self._repair_legacy_proxies_locked()

    def _repair_legacy_proxies_locked(self) -> dict[str, Any]:
        """Backfill proxy rows for databases created by an older runtime.

        The first SQLite migration shipped before the legacy host/port record
        shape was understood.  Its completion marker is still valid for
        mailboxes/tasks/results, so changing that marker would cause an
        unnecessary full import.  This narrow, separately marked repair only
        inserts missing proxy rows and is safe to run more than once.
        """
        self._legacy_read_errors = []
        repair_marker = self._meta(PROXY_REPAIR_KEY)
        repair_version = _migration_marker_version(repair_marker)
        if repair_version is not None and repair_version > SCHEMA_VERSION:
            raise FreeStorageError(
                f"SQLite 代理迁移标记版本 {repair_version} 高于当前运行时 {SCHEMA_VERSION}"
            )
        if _valid_migration_marker(repair_marker):
            return {"migrated": False, "reason": "already_repaired"}
        proxies, errors = self._legacy_proxies()
        blocking_errors = list(self._legacy_read_errors)
        counts = 0
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    for row in proxies:
                        public_payload, private_payload = _partition_json(row["payload"])
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO proxies(proxy_id,proxy,scheme,status,enabled,lease_owner,lease_until,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                row["proxy_id"], row["proxy"], row["scheme"], row["status"],
                                row["enabled"], row["lease_owner"], row["lease_until"],
                                row["revision"], row["created_at"], row["updated_at"],
                                _safe_json(public_payload), _safe_json(private_payload),
                            ),
                        )
                        counts += int(cursor.rowcount > 0)
                    # A source read failure means the repair did not inspect
                    # the complete legacy pool. Store an explicit incomplete
                    # marker so a later startup retries it; malformed rows
                    # alone remain informational and do not block completion.
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (PROXY_REPAIR_KEY, _safe_json({
                            "version": SCHEMA_VERSION,
                            "complete": not bool(blocking_errors),
                            "completed_at": now if not blocking_errors else None,
                            "proxies": counts,
                            "errors": (blocking_errors + errors)[:100],
                        })),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return {
            "migrated": True,
            "proxies": counts,
            "errors": (blocking_errors + errors)[:100],
            "recovery_required": bool(blocking_errors),
        }

    def migrate_legacy(self, *, force: bool = False) -> dict[str, Any]:
        """Serialize legacy source reads, marker writes and imports."""
        with self._lock:
            return self._migrate_legacy_locked(force=force)

    def _migrate_legacy_locked(self, *, force: bool = False) -> dict[str, Any]:
        """Import legacy files once, without deleting or rewriting them.

        ``force`` is intended for an operator explicitly requesting a second
        read.  Inserts remain ``OR IGNORE`` so repeated calls are idempotent.
        """
        self._legacy_read_errors = []
        marker = self._meta(MIGRATION_KEY)
        marker_version = _migration_marker_version(marker)
        if marker_version is not None and marker_version > SCHEMA_VERSION:
            raise FreeStorageError(
                f"SQLite 迁移标记版本 {marker_version} 高于当前运行时 {SCHEMA_VERSION}"
            )
        if not force and _valid_migration_marker(marker):
            # Complete the narrow compatibility repair before returning the
            # usual idempotent result.  Existing callers still receive the
            # historical ``already_migrated`` reason.
            self._repair_legacy_proxies()
            return {"migrated": False, "reason": "already_migrated", "version": SCHEMA_VERSION}
        mailboxes, mailbox_errors = self._legacy_mailboxes()
        proxies, proxy_errors = self._legacy_proxies()
        tasks, task_errors = self._legacy_tasks()
        results, result_errors = self._legacy_results()
        blocking_errors = list(self._legacy_read_errors)
        errors = blocking_errors + mailbox_errors + proxy_errors + task_errors + result_errors
        counts = {"mailboxes": 0, "proxies": 0, "tasks": 0, "results": 0}
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    for row in mailboxes:
                        public_payload, private_payload = _partition_json(row["payload"])
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO mailboxes(row_id,email,mailbox_url,status,batch_id,lease_owner,lease_until,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (row["row_id"], row["email"], row["mailbox_url"], row["status"], row["batch_id"], row["lease_owner"], row["lease_until"], row["revision"], row["created_at"], row["updated_at"], _safe_json(public_payload), _safe_json(private_payload)),
                        )
                        counts["mailboxes"] += int(cursor.rowcount > 0)
                        # Preserve an active legacy owner in the normalized
                        # lease table.  The scalar lease columns remain for
                        # compatibility, but recovery/renewal operates on
                        # ``resource_leases`` exclusively.
                        try:
                            mailbox_until = float(row.get("lease_until") or 0)
                        except (TypeError, ValueError):
                            mailbox_until = 0.0
                        mailbox_owner = str(row.get("lease_owner") or "").strip()
                        if mailbox_owner and mailbox_until > time.time():
                            db.execute(
                                "INSERT OR IGNORE INTO resource_leases "
                                "(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                                "VALUES('mailbox',?,?,?,?,?)",
                                (row["row_id"], mailbox_owner, mailbox_until, now, now),
                            )
                    for row in proxies:
                        public_payload, private_payload = _partition_json(row["payload"])
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO proxies(proxy_id,proxy,scheme,status,enabled,lease_owner,lease_until,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (row["proxy_id"], row["proxy"], row["scheme"], row["status"], row["enabled"], row["lease_owner"], row["lease_until"], row["revision"], row["created_at"], row["updated_at"], _safe_json(public_payload), _safe_json(private_payload)),
                        )
                        counts["proxies"] += int(cursor.rowcount > 0)
                        try:
                            proxy_until = float(row.get("lease_until") or 0)
                        except (TypeError, ValueError):
                            proxy_until = 0.0
                        proxy_owner = str(row.get("lease_owner") or "").strip()
                        if proxy_owner and proxy_until > time.time():
                            db.execute(
                                "INSERT OR IGNORE INTO resource_leases "
                                "(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                                "VALUES('proxy',?,?,?,?,?)",
                                (row["proxy_id"], proxy_owner, proxy_until, now, now),
                            )
                    for row in tasks:
                        public_payload, private_payload = _partition_json(row["payload"])
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO tasks(task_id,status,revision,lease_owner,lease_until,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?)",
                            (row["task_id"], row["status"], row["revision"], row["lease_owner"], row["lease_until"], row["created_at"], row["updated_at"], _safe_json(public_payload), _safe_json(private_payload)),
                        )
                        counts["tasks"] += int(cursor.rowcount > 0)
                        try:
                            task_until = float(row.get("lease_until") or 0)
                        except (TypeError, ValueError):
                            task_until = 0.0
                        task_owner = str(row.get("lease_owner") or "").strip()
                        if task_owner and task_until > time.time():
                            db.execute(
                                "INSERT OR IGNORE INTO resource_leases "
                                "(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                                "VALUES('task',?,?,?,?,?)",
                                (row["task_id"], task_owner, task_until, now, now),
                            )
                    for row_id, payload in results:
                        public_payload, private_payload = _partition_json(payload)
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO results(row_id,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?)",
                            (row_id, now, now, _safe_json(public_payload), _safe_json(private_payload)),
                        )
                        counts["results"] += int(cursor.rowcount > 0)
                    summary = {
                        "version": SCHEMA_VERSION,
                        "complete": not bool(blocking_errors),
                        "completed_at": now if not blocking_errors else None,
                        "counts": counts,
                        "errors": errors[:100],
                    }
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (MIGRATION_KEY, _safe_json(summary)),
                    )
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (PROXY_REPAIR_KEY, _safe_json({
                            "version": SCHEMA_VERSION,
                            "complete": not bool(blocking_errors),
                            "completed_at": now if not blocking_errors else None,
                            "proxies": counts["proxies"],
                            "errors": (blocking_errors + proxy_errors)[:100],
                        })),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return {
            "migrated": True,
            **counts,
            "errors": errors[:100],
            "version": SCHEMA_VERSION,
            "recovery_required": bool(blocking_errors),
        }

    def migration_status(self) -> dict[str, Any]:
        """Return a safe, version-aware view of the legacy import marker."""
        raw = self._meta(MIGRATION_KEY)
        detail: dict[str, Any] = {}
        try:
            parsed = json.loads(str(raw or ""))
            if isinstance(parsed, Mapping):
                detail = dict(parsed)
        except (TypeError, ValueError, json.JSONDecodeError):
            detail = {}
        return {
            "key": MIGRATION_KEY,
            "completed": _valid_migration_marker(raw),
            "version": SCHEMA_VERSION,
            **detail,
        }


__all__ = [
    "FreeStorageMigrationMixin",
]
