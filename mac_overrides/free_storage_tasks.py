"""Registration tasks, durable results and Remail order sync for the Free SQLite store.

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


class FreeStorageTaskMixin:
    """Methods moved verbatim from FreeSQLiteStore."""


    def create_task(self, task_id: str, payload: Mapping[str, Any] | None = None, *, status: str = "queued") -> dict[str, Any]:
        task = str(task_id or "").strip()
        if not task:
            raise ValueError("task_id 不能为空")
        now = _now()
        values = _payload_with_fields(payload, task_id=task, status=str(status or "queued"), revision=0)
        public_values, private_values = _partition_json(values)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("INSERT OR IGNORE INTO tasks(task_id,status,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?)", (task, str(status or "queued"), 0, now, now, _safe_json(public_values), _safe_json(private_values)))
                    row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._task_dict(row)

    def get_task(self, task_id: str, *, public: bool = False) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (str(task_id),)).fetchone()
        return self._task_dict(row, public=public) if row is not None else None

    def list_tasks(self, *, status: str | None = None, limit: int = 500, offset: int = 0, public: bool = False) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        params.extend([max(1, int(limit)), max(0, int(offset))])
        with self._connection() as db:
            rows = db.execute(f"SELECT * FROM tasks WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC,task_id ASC LIMIT ? OFFSET ?", params).fetchall()
        return [self._task_dict(row, public=public) for row in rows]

    def list_tasks_page(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        public: bool = False,
    ) -> dict[str, Any]:
        return self._page(
            "tasks", status=status, limit=limit, offset=offset, public=public
        )

    def save_task(
        self,
        task_id: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: int | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        task = str(task_id or "").strip()
        if not task:
            raise ValueError("task_id 不能为空")
        incoming = _json_object(payload)
        public_incoming, private_incoming = _partition_json(incoming)
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    if current is None:
                        if expected_revision not in (None, 0):
                            raise RevisionConflict(task, expected_revision, None)
                        next_revision = 0
                        task_status = str(status or incoming.get("status") or "queued")
                        incoming.setdefault("task_id", task)
                        incoming["revision"] = next_revision
                        db.execute("INSERT INTO tasks(task_id,status,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?)", (task, task_status, next_revision, now, now, _safe_json(public_incoming), _safe_json(private_incoming)))
                    else:
                        actual = int(current["revision"] or 0)
                        if expected_revision is not None and actual != int(expected_revision):
                            raise RevisionConflict(task, expected_revision, actual)
                        requested_status = str(
                            status
                            or incoming.get("status")
                            or current["status"]
                            or "queued"
                        )
                        if (
                            str(current["status"] or "") in TERMINAL_TASK_STATUSES
                            and requested_status != str(current["status"] or "")
                        ):
                            # Treat a late callback that attempts to revive a
                            # completed task as a compare-and-set conflict.
                            # Callers already handle RevisionConflict as a
                            # benign stale-writer outcome.
                            raise RevisionConflict(task, expected_revision, actual)
                        next_revision = actual + 1
                        task_status = requested_status
                        incoming.setdefault("task_id", task)
                        incoming["revision"] = next_revision
                        public_incoming, private_incoming = _partition_json(incoming)
                        updated = db.execute("UPDATE tasks SET status=?,revision=?,updated_at=?,payload=?,private_payload=? WHERE task_id=? AND revision=?", (task_status, next_revision, now, _safe_json(public_incoming), _safe_json(private_incoming), task, actual))
                        if updated.rowcount != 1:
                            raise RevisionConflict(task, expected_revision, actual)
                    row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._task_dict(row)

    def transition_task(
        self,
        task_id: str,
        from_status: str | Sequence[str],
        to_status: str,
        *,
        payload_patch: Mapping[str, Any] | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Apply one explicit task state transition with compare-and-set.

        ``None`` means the current state is not in ``from_status``.  A stale
        revision raises :class:`RevisionConflict`, allowing callers to
        distinguish a concurrent writer from an invalid state transition.
        """
        task = str(task_id or "").strip()
        if not task:
            raise ValueError("task_id 不能为空")
        allowed = (
            {str(item) for item in from_status}
            if not isinstance(from_status, str)
            else {from_status}
        )
        target_status = str(to_status or "").strip()
        if not target_status or not allowed:
            raise ValueError("任务状态不能为空")
        patch = _json_object(payload_patch)
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    if current is None:
                        db.execute("COMMIT")
                        return None
                    actual = int(current["revision"] or 0)
                    if expected_revision is not None and actual != int(expected_revision):
                        raise RevisionConflict(task, expected_revision, actual)
                    current_status = str(current["status"] or "")
                    if current_status not in allowed:
                        db.execute("COMMIT")
                        return None
                    # A terminal task is immutable unless the caller repeats
                    # the same status as an idempotent write.
                    if current_status in TERMINAL_TASK_STATUSES and target_status != current_status:
                        db.execute("COMMIT")
                        return None
                    payload = self._row_payload(current)
                    payload.update(patch)
                    payload.update({"task_id": task, "status": target_status, "revision": actual + 1})
                    public_payload, private_payload = _partition_json(payload)
                    updated = db.execute(
                        "UPDATE tasks SET status=?,revision=?,updated_at=?,payload=?,private_payload=? "
                        "WHERE task_id=? AND status IN (" + ",".join("?" for _ in allowed) + ") AND revision=?",
                        [target_status, actual + 1, now, _safe_json(public_payload), _safe_json(private_payload), task, *sorted(allowed), actual],
                    )
                    if updated.rowcount != 1:
                        raise RevisionConflict(task, expected_revision, actual)
                    row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return self._task_dict(row) if row is not None else None

    def claim_task(self, task_id: str, *, owner: str, lease_seconds: int = 180, statuses: Sequence[str] = ("queued", "pending")) -> dict[str, Any] | None:
        task = str(task_id or "").strip()
        owner = str(owner or "").strip()
        if not task or not owner:
            return None
        until = time.time() + max(1, int(lease_seconds))
        now = _now()
        placeholders = ",".join("?" for _ in statuses) or "?"
        status_values = tuple(str(value) for value in statuses) or ("queued",)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(f"SELECT * FROM tasks WHERE task_id=? AND status IN ({placeholders}) AND (lease_until IS NULL OR lease_until<=?)", (*((task, *status_values)), time.time())).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    updated = db.execute("UPDATE tasks SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE task_id=? AND revision=? AND (lease_until IS NULL OR lease_until<=?)", (owner, until, now, task, int(row["revision"]), time.time()))
                    if updated.rowcount != 1:
                        db.execute("COMMIT")
                        return None
                    db.execute("INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) VALUES('task',?,?,?,?,?) ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET lease_until=excluded.lease_until,updated_at=excluded.updated_at", (task, owner, until, now, now))
                    current = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return self._task_dict(current) if current is not None else None

    def _lease_single(self, resource_type: str, resource_id: str, owner: str, lease_seconds: int, expected_revision: int | None, *, shared: bool = False) -> bool:
        if not resource_id or not owner:
            return False
        table, key = {"mailbox": ("mailboxes", "row_id"), "proxy": ("proxies", "proxy_id"), "task": ("tasks", "task_id")}[resource_type]
        until = time.time() + max(1, int(lease_seconds))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(f"SELECT * FROM {table} WHERE {key}=?", (resource_id,)).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return False
                    if expected_revision is not None and int(row["revision"] or 0) != int(expected_revision):
                        db.execute("COMMIT")
                        return False
                    if not shared:
                        active = db.execute("SELECT 1 FROM resource_leases WHERE resource_type=? AND resource_id=? AND owner<>? AND lease_until>? LIMIT 1", (resource_type, resource_id, owner, time.time())).fetchone()
                        if active is not None:
                            db.execute("COMMIT")
                            return False
                    revision = int(row["revision"] or 0)
                    updated = db.execute(f"UPDATE {table} SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE {key}=? AND revision=?", (owner, until, now, resource_id, revision))
                    if updated.rowcount != 1:
                        db.execute("COMMIT")
                        return False
                    db.execute("INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET lease_until=excluded.lease_until,updated_at=excluded.updated_at", (resource_type, resource_id, owner, until, now, now))
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

    def save_result(self, row_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        rid = str(row_id or "").strip()
        if not rid:
            raise ValueError("row_id 不能为空")
        now = _now()
        value = _json_object(payload)
        public_value, private_value = _partition_json(value)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("INSERT INTO results(row_id,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?) ON CONFLICT(row_id) DO UPDATE SET updated_at=excluded.updated_at,payload=excluded.payload,private_payload=excluded.private_payload", (rid, now, now, _safe_json(public_value), _safe_json(private_value)))
                    row = db.execute("SELECT * FROM results WHERE row_id=?", (rid,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._result_dict(row)

    def upsert_remail_order(self, order: Mapping[str, Any]) -> dict[str, Any]:
        """Persist an order, keeping service_token in the private sidecar."""
        order_no = str(order.get("orderNo") or order.get("order_no") or "").strip()
        if not order_no:
            raise ValueError("Remail orderNo 不能为空")
        email = str(order.get("deliveryEmail") or order.get("delivery_email") or "").strip().lower()
        status = str(order.get("status") or "").strip().lower()
        public, private = _partition_json(dict(order))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current = db.execute("SELECT imported,pool_row_id,created_at FROM remail_orders WHERE order_no=?", (order_no,)).fetchone()
                    imported = int(current[0]) if current is not None else int(bool(order.get("imported")))
                    pool_row_id = str(current[1]) if current is not None else str(order.get("pool_row_id") or "")
                    created_at = str(current[2]) if current is not None else now
                    db.execute(
                        "INSERT INTO remail_orders(order_no,status,delivery_email,imported,pool_row_id,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(order_no) DO UPDATE SET status=excluded.status,delivery_email=excluded.delivery_email,updated_at=excluded.updated_at,payload=excluded.payload,private_payload=excluded.private_payload",
                        (order_no, status, email, imported, pool_row_id, created_at, now, _safe_json(public), _safe_json(private)),
                    )
                    row = db.execute("SELECT * FROM remail_orders WHERE order_no=?", (order_no,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._remail_order_dict(row)

    def list_remail_orders(self, *, status: str | None = None, imported: bool | None = None, search: str | None = None, public: bool = False, limit: int = 500, offset: int = 0) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        if imported is not None:
            clauses.append("imported=?")
            params.append(int(bool(imported)))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append("(lower(order_no) LIKE ? OR lower(delivery_email) LIKE ? OR lower(status) LIKE ?)")
            params.extend([needle, needle, needle])
        params.extend([max(1, min(5000, int(limit))), max(0, int(offset))])
        with self._connection() as db:
            rows = db.execute(f"SELECT * FROM remail_orders WHERE {' AND '.join(clauses)} ORDER BY created_at DESC, order_no DESC LIMIT ? OFFSET ?", params).fetchall()
        return [self._remail_order_dict(row, public=public) for row in rows]

    def count_remail_orders(self, *, status: str | None = None, imported: bool | None = None, search: str | None = None) -> int:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?"); params.append(str(status))
        if imported is not None:
            clauses.append("imported=?"); params.append(int(bool(imported)))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append("(lower(order_no) LIKE ? OR lower(delivery_email) LIKE ? OR lower(status) LIKE ?)")
            params.extend([needle, needle, needle])
        with self._connection() as db:
            row = db.execute(f"SELECT COUNT(*) FROM remail_orders WHERE {' AND '.join(clauses)}", params).fetchone()
        return int(row[0] if row else 0)

    def mark_remail_order_imported(self, order_no: str, pool_row_id: str) -> dict[str, Any] | None:
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("UPDATE remail_orders SET imported=1,pool_row_id=?,updated_at=? WHERE order_no=?", (str(pool_row_id), _now(), str(order_no).strip()))
                    row = db.execute("SELECT * FROM remail_orders WHERE order_no=?", (str(order_no).strip(),)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return self._remail_order_dict(row) if row is not None else None

    def delete_tasks(
        self,
        task_ids: Sequence[str],
        *,
        terminal_only: bool = True,
        expected_revisions: Mapping[str, int] | None = None,
    ) -> int:
        """Delete task history with optional revision compare-and-set.

        ``expected_revisions`` is used by compatibility snapshot writers.  A
        task may be absent from one process' in-memory map because another
        process created it after the map was read; requiring a known revision
        prevents that stale writer from deleting the newer history.  The
        check and delete run in one ``BEGIN IMMEDIATE`` transaction, so a
        matching row cannot change between the predicate and the delete.
        """
        values = [str(value or "").strip() for value in task_ids if str(value or "").strip()]
        if not values:
            return 0
        revisions: dict[str, int] = {}
        if expected_revisions is not None:
            for task_id in values:
                if task_id not in expected_revisions:
                    continue
                try:
                    revisions[task_id] = int(expected_revisions[task_id])
                except (TypeError, ValueError):
                    continue
            # A CAS deletion is intentionally conservative: unknown rows are
            # never eligible for removal from a stale full snapshot.
            values = [task_id for task_id in values if task_id in revisions]
            if not values:
                return 0
        placeholders = ",".join("?" for _ in values)
        terminal = tuple(TERMINAL_TASK_STATUSES)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    clauses: list[str] = []
                    params: list[Any] = []
                    if revisions:
                        revision_clauses = []
                        for task_id in values:
                            revision_clauses.append("(task_id=? AND revision=?)")
                            params.extend((task_id, revisions[task_id]))
                        clauses.append("(" + " OR ".join(revision_clauses) + ")")
                    else:
                        clauses.append(f"task_id IN ({placeholders})")
                        params.extend(values)
                    if terminal_only:
                        terminal_placeholders = ",".join("?" for _ in terminal)
                        clauses.append(f"status IN ({terminal_placeholders})")
                        params.extend(terminal)
                    # Never delete a row while a live worker lease exists.
                    # The worker may still persist a terminal result after a
                    # UI cleanup request; deleting here would allow that late
                    # callback to recreate inconsistent history.
                    clauses.append(
                        "NOT EXISTS (SELECT 1 FROM resource_leases rl "
                        "WHERE rl.resource_type='task' AND rl.resource_id=tasks.task_id "
                        "AND rl.lease_until>?)"
                    )
                    params.append(time.time())
                    rows = db.execute(
                        f"SELECT task_id FROM tasks WHERE {' AND '.join(clauses)}", params
                    ).fetchall()
                    ids = [str(row[0]) for row in rows]
                    if ids:
                        id_placeholders = ",".join("?" for _ in ids)
                        db.execute(
                            f"DELETE FROM resource_leases WHERE resource_type='task' AND resource_id IN ({id_placeholders})",
                            ids,
                        )
                        deleted = db.execute(
                            f"DELETE FROM tasks WHERE task_id IN ({id_placeholders})", ids
                        ).rowcount
                    else:
                        deleted = 0
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return int(deleted or 0)

    def get_result(self, row_id: str, *, public: bool = False) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM results WHERE row_id=?", (str(row_id),)).fetchone()
        return self._result_dict(row, public=public) if row is not None else None

    def public_mailboxes(self, **kwargs: Any) -> list[dict[str, Any]]:
        kwargs["public"] = True
        return self.list_mailboxes(**kwargs)

    def public_proxies(self, **kwargs: Any) -> list[dict[str, Any]]:
        kwargs["public"] = True
        return self.list_proxies(**kwargs)

    def public_tasks(self, **kwargs: Any) -> list[dict[str, Any]]:
        kwargs["public"] = True
        return self.list_tasks(**kwargs)

    def health(self) -> dict[str, Any]:
        with self._connection() as db:
            tables = {}
            for table in ("mailboxes", "proxies", "tasks", "results"):
                tables[table] = int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            journal = str(db.execute("PRAGMA journal_mode").fetchone()[0] or "").lower()
            busy = int(db.execute("PRAGMA busy_timeout").fetchone()[0] or 0)
        owner_status = self.manager_owner_status()
        return {
            "ok": journal == "wal" and busy >= self.busy_timeout_ms,
            "path": str(self.path),
            "journal_mode": journal,
            "busy_timeout_ms": busy,
            "schema_version": int(self._meta("schema_version") or 0),
            "migration": self._meta(MIGRATION_KEY),
            "counts": tables,
            "manager_owner": owner_status,
        }


__all__ = [
    "FreeStorageTaskMixin",
]
