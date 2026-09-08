"""Proxy CRUD and shareable lease lifecycle for the Free SQLite store.

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


class FreeStorageProxyMixin:
    """Methods moved verbatim from FreeSQLiteStore."""


    def upsert_proxy(
        self,
        *,
        proxy: str,
        proxy_id: str | None = None,
        scheme: str | None = None,
        status: str = "healthy",
        enabled: bool = True,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized = _normalize_proxy(proxy, default_scheme=str(scheme or "socks5"))
        if not normalized:
            raise ValueError("proxy 无效")
        parsed = urlsplit(normalized)
        pid = str(proxy_id or _fingerprint(normalized)).strip()
        now = _now()
        values = _payload_with_fields(
            _clear_legacy_pool_dimensions(payload, include_plain=True),
            proxy=normalized,
            proxy_id=pid,
            scheme=str(scheme or parsed.scheme).lower(),
        )
        public_values, private_values = _partition_json(values)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    existing = db.execute(
                        "SELECT * FROM proxies WHERE proxy_id=?", (pid,)
                    ).fetchone()
                    active_lease = None
                    if existing is not None:
                        active_lease = db.execute(
                            "SELECT 1 FROM resource_leases WHERE resource_type='proxy' "
                            "AND resource_id=? AND lease_until>? LIMIT 1",
                            (pid, time.time()),
                        ).fetchone()
                        if active_lease is not None or (
                            _safe_float(existing["lease_until"]) or 0
                        ) > time.time():
                            # A pool refresh must not erase a worker's shared
                            # lease or reset a quarantined/healthy state
                            # underneath it. Merge non-lifecycle metadata and
                            # leave the CAS revision stable while a lease is
                            # active; lease/heartbeat methods own those
                            # fields and update them conditionally.
                            current_payload = self._row_payload(existing)
                            protected = {
                                "proxy_id", "proxy", "scheme", "status", "enabled",
                                "lease_owner", "lease_until", "leases",
                            }
                            merged_payload = current_payload
                            merged_payload.update({
                                key: value
                                for key, value in values.items()
                                if key not in protected
                            })
                            merged_public, merged_private = _partition_json(merged_payload)
                            db.execute(
                                "UPDATE proxies SET proxy=?,scheme=?,updated_at=?,payload=?,private_payload=? "
                                "WHERE proxy_id=? AND revision=?",
                                (
                                    normalized,
                                    str(scheme or parsed.scheme).lower(),
                                    now,
                                    _safe_json(merged_public),
                                    _safe_json(merged_private),
                                    pid,
                                    int(existing["revision"] or 0),
                                ),
                            )
                        else:
                            db.execute(
                                "UPDATE proxies SET proxy=?,scheme=?,status=?,enabled=?,updated_at=?,revision=revision+1,payload=?,private_payload=? "
                                "WHERE proxy_id=? AND revision=?",
                                (
                                    normalized,
                                    str(scheme or parsed.scheme).lower(),
                                    str(status or "healthy"),
                                    int(bool(enabled)),
                                    now,
                                    _safe_json(public_values),
                                    _safe_json(private_values),
                                    pid,
                                    int(existing["revision"] or 0),
                                ),
                            )
                    else:
                        db.execute(
                            "INSERT INTO proxies(proxy_id,proxy,scheme,status,enabled,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,0,?,?,?,?)",
                            (
                                pid,
                                normalized,
                                str(scheme or parsed.scheme).lower(),
                                str(status or "healthy"),
                                int(bool(enabled)),
                                now,
                                now,
                                _safe_json(public_values),
                                _safe_json(private_values),
                            ),
                        )
                    row = db.execute("SELECT * FROM proxies WHERE proxy_id=?", (pid,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._proxy_dict(row)

    def get_proxy(self, proxy_id: str, *, public: bool = False) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM proxies WHERE proxy_id=?", (str(proxy_id),)).fetchone()
        return self._proxy_dict(row, public=public) if row is not None else None

    def list_proxies(self, *, status: str | None = None, limit: int = 500, offset: int = 0, public: bool = False) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        params.extend([max(1, int(limit)), max(0, int(offset))])
        with self._connection() as db:
            rows = db.execute(
                f"SELECT * FROM proxies WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC,proxy_id ASC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._proxy_dict(row, public=public) for row in rows]

    def list_proxies_page(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        public: bool = False,
    ) -> dict[str, Any]:
        return self._page(
            "proxies", status=status, limit=limit, offset=offset, public=public
        )

    def claim_proxy(
        self,
        *,
        owner: str,
        lease_seconds: int = 180,
        proxy_id: str | None = None,
        shared: bool = True,
    ) -> dict[str, Any] | None:
        owner_value = str(owner or "").strip()
        if not owner_value:
            raise ValueError("owner 不能为空")
        until = time.time() + max(1, int(lease_seconds))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    where = (
                        "proxy_id=? AND enabled=1 AND status IN ('healthy','unknown','available')"
                        if proxy_id
                        else "enabled=1 AND status IN ('healthy','unknown','available')"
                    )
                    params: list[Any] = [str(proxy_id)] if proxy_id else []
                    row = db.execute(
                        f"SELECT * FROM proxies WHERE {where} ORDER BY updated_at DESC,proxy_id ASC LIMIT 1",
                        params,
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    if not shared:
                        active = db.execute(
                            "SELECT 1 FROM resource_leases WHERE resource_type='proxy' AND resource_id=? AND owner<>? AND lease_until>? LIMIT 1",
                            (row["proxy_id"], owner_value, time.time()),
                        ).fetchone()
                        if active is not None:
                            db.execute("COMMIT")
                            return None
                    db.execute(
                        "INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) VALUES('proxy',?,?,?,?,?) ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET lease_until=excluded.lease_until,updated_at=excluded.updated_at",
                        (row["proxy_id"], owner_value, until, now, now),
                    )
                    db.execute("UPDATE proxies SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE proxy_id=?", (owner_value, until, now, row["proxy_id"]));
                    current = db.execute("SELECT * FROM proxies WHERE proxy_id=?", (row["proxy_id"],)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return self._proxy_dict(current) if current is not None else None

    def lease_proxy(self, proxy_id: str, *, owner: str, lease_seconds: int = 180, shared: bool = True) -> bool:
        return self._lease_single("proxy", str(proxy_id), str(owner), lease_seconds, None, shared=shared)

    def release_lease(self, resource_type: str, resource_id: str, *, owner: str, status: str | None = None) -> bool:
        resource_type = str(resource_type or "").strip().lower()
        resource_id = str(resource_id or "").strip()
        owner = str(owner or "").strip()
        if resource_type not in {"mailbox", "proxy", "task"} or not resource_id or not owner:
            return False
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    table, key = {"mailbox": ("mailboxes", "row_id"), "proxy": ("proxies", "proxy_id"), "task": ("tasks", "task_id")}[
                        resource_type
                    ]
                    # Check the parent row in the same transaction.  Without
                    # this guard an orphan lease could report success and
                    # make cleanup callers believe a resource was released.
                    parent = db.execute(
                        f"SELECT 1 FROM {table} WHERE {key}=?", (resource_id,)
                    ).fetchone()
                    if parent is None:
                        db.execute("COMMIT")
                        return False
                    parent_payload: dict[str, Any] = {}
                    parent_status = ""
                    if resource_type == "mailbox":
                        parent_row = db.execute(
                            "SELECT payload,private_payload,status FROM mailboxes WHERE row_id=?",
                            (resource_id,),
                        ).fetchone()
                        if parent_row is not None:
                            parent_status = str(parent_row["status"] or "")
                            parent_payload = self._row_payload(parent_row)
                    deleted = db.execute(
                        "DELETE FROM resource_leases WHERE resource_type=? AND resource_id=? AND owner=?",
                        (resource_type, resource_id, owner),
                    )
                    if deleted.rowcount != 1:
                        db.execute("COMMIT")
                        return False
                    # Clear denormalized owner only when it still points at this owner;
                    # another shared proxy lease must remain represented by its owner.
                    # Recompute the denormalized owner from any remaining
                    # shared leases instead of blanking a proxy while another
                    # worker still owns it.
                    remaining = db.execute(
                        "SELECT owner,lease_until FROM resource_leases "
                        "WHERE resource_type=? AND resource_id=? AND lease_until>? "
                        "ORDER BY lease_until DESC LIMIT 1",
                        (resource_type, resource_id, time.time()),
                    ).fetchone()
                    next_owner = str(remaining["owner"]) if remaining is not None else ""
                    next_until = float(remaining["lease_until"]) if remaining is not None else None
                    # If another owner has already acquired the resource,
                    # preserve its status.  This matters when a stale worker
                    # releases after its lease expired and was replaced.
                    update_status = status if remaining is None else None
                    if (
                        remaining is None
                        and resource_type == "mailbox"
                        and parent_payload.get("lease_confirmed")
                        and parent_status in {"reserved", "queued", "running"}
                        and (update_status is None or str(update_status) in {"available", "reserved", "queued", "running"})
                    ):
                        # The repository facade releases through this generic
                        # method. Preserve the two-phase mailbox invariant
                        # even when it does not pass an explicit status.
                        update_status = "pending_rerun"
                    if (
                        remaining is None
                        and resource_type == "mailbox"
                        and not parent_payload.get("lease_confirmed")
                    ):
                        # Generic repository callers use this method for both
                        # task/proxy leases and mailbox cleanup.  A mailbox
                        # claim is only a reservation until confirmation, so
                        # release must discard all owner/task metadata from a
                        # previous attempt before the row can be claimed
                        # again.  Keep confirmed metadata intact: once the
                        # address was submitted, the row is deliberately
                        # retained as ``pending_rerun`` for audit/retry.
                        for key_name in (
                            "lease_confirmed",
                            "lease_confirmed_at",
                            "task_id",
                            "batch_id",
                            "driver",
                        ):
                            parent_payload.pop(key_name, None)
                        public_payload, private_payload = _partition_json(parent_payload)
                        db.execute(
                            "UPDATE mailboxes SET payload=?,private_payload=? WHERE row_id=?",
                            (
                                _safe_json(public_payload),
                                _safe_json(private_payload),
                                resource_id,
                            ),
                        )
                    if update_status is not None:
                        db.execute(
                            f"UPDATE {table} SET status=? WHERE {key}=?",
                            (str(update_status), resource_id),
                        )
                    db.execute(
                        f"UPDATE {table} SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE {key}=?",
                        (next_owner, next_until, now, resource_id),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return True

    def release_proxy_leases(self, owner: str) -> int:
        """Release every shared proxy lease owned by one interrupted worker.

        A worker normally releases a proxy in its ``finally`` block.  If the
        process exits first, the lease can remain live until its TTL expires
        and unnecessarily reduces the shared pool's capacity.  Recovery uses
        this owner-scoped operation so it cannot touch leases belonging to
        another task.  The denormalized proxy owner is recomputed in the same
        transaction, preserving any remaining shared leases.
        """
        owner_value = str(owner or "").strip()
        if not owner_value:
            return 0
        now_epoch = time.time()
        now = _now()
        released = 0
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    lease_rows = db.execute(
                        "SELECT resource_id FROM resource_leases "
                        "WHERE resource_type='proxy' AND owner=?",
                        (owner_value,),
                    ).fetchall()
                    for lease_row in lease_rows:
                        proxy_id = str(lease_row["resource_id"] or "").strip()
                        deleted = db.execute(
                            "DELETE FROM resource_leases "
                            "WHERE resource_type='proxy' AND resource_id=? AND owner=?",
                            (proxy_id, owner_value),
                        )
                        if deleted.rowcount != 1:
                            continue
                        remaining = db.execute(
                            "SELECT owner,lease_until FROM resource_leases "
                            "WHERE resource_type='proxy' AND resource_id=? "
                            "AND lease_until>? ORDER BY lease_until DESC LIMIT 1",
                            (proxy_id, now_epoch),
                        ).fetchone()
                        next_owner = str(remaining["owner"]) if remaining is not None else ""
                        next_until = (
                            float(remaining["lease_until"])
                            if remaining is not None
                            else None
                        )
                        db.execute(
                            "UPDATE proxies SET lease_owner=?,lease_until=?,"
                            "updated_at=?,revision=revision+1 WHERE proxy_id=?",
                            (next_owner, next_until, now, proxy_id),
                        )
                        released += 1
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return released

    def renew_lease(
        self,
        resource_type: str,
        resource_id: str,
        *,
        owner: str,
        lease_seconds: int = 180,
        expected_revision: int | None = None,
    ) -> bool:
        """Extend an unexpired lease owned by ``owner`` using revision CAS."""
        resource_type = str(resource_type or "").strip().lower()
        resource_id = str(resource_id or "").strip()
        owner = str(owner or "").strip()
        mapping = {
            "mailbox": ("mailboxes", "row_id"),
            "proxy": ("proxies", "proxy_id"),
            "task": ("tasks", "task_id"),
        }
        if resource_type not in mapping or not resource_id or not owner:
            return False
        table, key = mapping[resource_type]
        current_time = time.time()
        until = current_time + max(1, int(lease_seconds))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        f"SELECT revision FROM {table} WHERE {key}=?", (resource_id,)
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return False
                    actual = int(row["revision"] or 0)
                    if expected_revision is not None and actual != int(expected_revision):
                        db.execute("COMMIT")
                        return False
                    renewed = db.execute(
                        "UPDATE resource_leases SET lease_until=?,updated_at=? "
                        "WHERE resource_type=? AND resource_id=? AND owner=? AND lease_until>?",
                        (until, now, resource_type, resource_id, owner, current_time),
                    )
                    if renewed.rowcount != 1:
                        db.execute("COMMIT")
                        return False
                    updated = db.execute(
                        f"UPDATE {table} SET "
                        "lease_owner=CASE WHEN lease_owner='' OR lease_owner=? THEN ? ELSE lease_owner END,"
                        "lease_until=CASE WHEN lease_owner='' OR lease_owner=? THEN ? ELSE lease_until END,"
                        "updated_at=?,revision=revision+1 "
                        f"WHERE {key}=? AND revision=?",
                        (owner, owner, owner, until, now, resource_id, actual),
                    )
                    if updated.rowcount != 1:
                        db.execute("ROLLBACK")
                        return False
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

    def recover_expired_leases(
        self,
        *,
        now: float | None = None,
        resource_type: str | None = None,
    ) -> dict[str, int]:
        """Recover stale mailbox/task ownership and preserve active proxy shares.

        Mailboxes left ``reserved`` become ``available`` when their last lease
        expires.  Interrupted ``running``/``stopping`` tasks return to
        ``queued``.  Proxy health is never changed by lease recovery.
        """
        current_time = time.time() if now is None else float(now)
        selected_type = str(resource_type or "").strip().lower()
        if selected_type and selected_type not in {"mailbox", "proxy", "task"}:
            raise ValueError("resource_type 无效")
        params: tuple[Any, ...]
        where = "lease_until<=?"
        params = (current_time,)
        if selected_type:
            where += " AND resource_type=?"
            params = (current_time, selected_type)
        recovered = {"mailbox": 0, "proxy": 0, "task": 0, "total": 0}
        mapping = {
            "mailbox": ("mailboxes", "row_id"),
            "proxy": ("proxies", "proxy_id"),
            "task": ("tasks", "task_id"),
        }
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    expired = db.execute(
                        f"SELECT resource_type,resource_id,owner FROM resource_leases WHERE {where}",
                        params,
                    ).fetchall()
                    db.execute(f"DELETE FROM resource_leases WHERE {where}", params)
                    resources = {
                        (str(row["resource_type"]), str(row["resource_id"]))
                        for row in expired
                    }
                    stamp = _now()
                    for kind, resource_id in resources:
                        table, key = mapping[kind]
                        active = db.execute(
                            "SELECT owner,lease_until FROM resource_leases "
                            "WHERE resource_type=? AND resource_id=? AND lease_until>? "
                            "ORDER BY lease_until DESC LIMIT 1",
                            (kind, resource_id, current_time),
                        ).fetchone()
                        if active is not None:
                            db.execute(
                                f"UPDATE {table} SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE {key}=?",
                                (str(active["owner"]), float(active["lease_until"]), stamp, resource_id),
                            )
                        elif kind == "mailbox":
                            mailbox_row = db.execute(
                                "SELECT payload,private_payload,status FROM mailboxes WHERE row_id=?",
                                (resource_id,),
                            ).fetchone()
                            if mailbox_row is not None:
                                mailbox_payload = self._row_payload(mailbox_row)
                            else:
                                mailbox_payload = {}
                            confirmed = _stored_bool(mailbox_payload.get("lease_confirmed"))
                            if not confirmed:
                                # An unconfirmed lease never submitted the
                                # address.  Clear all task/driver markers and
                                # return every transient mailbox state to the
                                # dispatchable pool after expiry.
                                for key_name in (
                                    "lease_confirmed",
                                    "lease_confirmed_at",
                                    "task_id",
                                    "batch_id",
                                    "driver",
                                    "lease_owner",
                                    "lease_until",
                                    "stage",
                                ):
                                    mailbox_payload.pop(key_name, None)
                                public_payload, private_payload = _partition_json(mailbox_payload)
                                db.execute(
                                    "UPDATE mailboxes SET lease_owner='',lease_until=NULL,"
                                    "batch_id='',status=CASE WHEN status IN ('reserved','queued','running') "
                                    "THEN 'available' ELSE status END,updated_at=?,revision=revision+1,"
                                    "payload=?,private_payload=? WHERE row_id=?",
                                    (
                                        stamp,
                                        _safe_json(public_payload),
                                        _safe_json(private_payload),
                                        resource_id,
                                    ),
                                )
                            else:
                                db.execute(
                                    "UPDATE mailboxes SET lease_owner='',lease_until=NULL,"
                                    "status=CASE WHEN status IN ('reserved','queued','running') THEN 'pending_rerun' "
                                    "ELSE status END,updated_at=?,revision=revision+1 WHERE row_id=?",
                                    (stamp, resource_id),
                                )
                        elif kind == "task":
                            db.execute(
                                "UPDATE tasks SET lease_owner='',lease_until=NULL,"
                                "status=CASE WHEN status IN ('running','stopping') THEN 'queued' ELSE status END,"
                                "updated_at=?,revision=revision+1 WHERE task_id=?",
                                (stamp, resource_id),
                            )
                        else:
                            db.execute(
                                "UPDATE proxies SET lease_owner='',lease_until=NULL,updated_at=?,revision=revision+1 WHERE proxy_id=?",
                                (stamp, resource_id),
                            )
                        recovered[kind] += 1
                    recovered["total"] = len(resources)
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return recovered

    def recover_orphaned_mailboxes(self, *, now: float | None = None) -> int:
        """Release ``reserved`` mailboxes that have no live normalized lease.

        A process can terminate after the legacy pool row is marked
        ``reserved`` but before the corresponding task/lease transaction is
        committed.  Such a row is not covered by
        :meth:`recover_expired_leases` because there is no row in
        ``resource_leases`` to expire.  Recover only the unconfirmed form of
        this state; a confirmed mailbox remains non-reusable even when a
        malformed/old database lost its lease row.

        The complete scan and conditional updates run under one immediate
        transaction.  This prevents a concurrent claimant from acquiring a
        row between the orphan check and the reset.
        """
        current_time = time.time() if now is None else float(now)
        stamp = _now()
        transient_keys = (
            "lease_confirmed",
            "lease_confirmed_at",
            "task_id",
            "batch_id",
            "driver",
            "lease_owner",
            "lease_until",
            "stage",
        )
        changed = 0
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    rows = db.execute(
                        "SELECT row_id,payload,private_payload FROM mailboxes "
                        "WHERE status='reserved' AND NOT EXISTS ("
                        "SELECT 1 FROM resource_leases rl "
                        "WHERE rl.resource_type='mailbox' "
                        "AND rl.resource_id=mailboxes.row_id "
                        "AND rl.lease_until>?"
                        ")",
                        (current_time,),
                    ).fetchall()
                    for row in rows:
                        payload = _merge_private_payload(
                            self._decode_json_value(row["payload"]),
                            self._decode_json_value(row["private_payload"]),
                        )
                        if not isinstance(payload, Mapping):
                            payload = {}
                        # Confirmed means the address was submitted to the
                        # upstream service. Never make that mailbox available
                        # merely because its lease sidecar is missing.
                        if _stored_bool(payload.get("lease_confirmed")):
                            continue
                        normalized = copy.deepcopy(dict(payload))
                        for key in transient_keys:
                            normalized.pop(key, None)
                        public_payload, private_payload = _partition_json(normalized)
                        updated = db.execute(
                            "UPDATE mailboxes SET status='available',batch_id='',"
                            "lease_owner='',lease_until=NULL,updated_at=?,"
                            "revision=revision+1,payload=?,private_payload=? "
                            "WHERE row_id=? AND status='reserved' AND NOT EXISTS ("
                            "SELECT 1 FROM resource_leases rl "
                            "WHERE rl.resource_type='mailbox' "
                            "AND rl.resource_id=mailboxes.row_id "
                            "AND rl.lease_until>?"
                            ")",
                            (
                                stamp,
                                _safe_json(public_payload),
                                _safe_json(private_payload),
                                str(row["row_id"]),
                                current_time,
                            ),
                        )
                        changed += int(updated.rowcount or 0)
                        if updated.rowcount:
                            # Expired sidecar rows are not authoritative and
                            # can otherwise make a later claim look stale.
                            db.execute(
                                "DELETE FROM resource_leases WHERE "
                                "resource_type='mailbox' AND resource_id=? "
                                "AND lease_until<=?",
                                (str(row["row_id"]), current_time),
                            )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return changed


__all__ = [
    "FreeStorageProxyMixin",
]
