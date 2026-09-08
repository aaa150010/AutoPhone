"""Mailbox CRUD, reservation and lease lifecycle for the Free SQLite store.

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


class FreeStorageMailboxMixin:
    """Methods moved verbatim from FreeSQLiteStore."""


    def upsert_mailbox(
        self,
        *,
        row_id: str | None = None,
        email: str,
        mailbox_url: str,
        status: str = "available",
        batch_id: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        email_value = str(email or "").strip().lower()
        url_value = str(mailbox_url or "").strip()
        parsed = urlsplit(url_value)
        if not _EMAIL_RE.fullmatch(email_value) or parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("邮箱或 mailbox_url 无效")
        rid = str(row_id or _fingerprint(f"{email_value}|{url_value}")).strip()
        now = _now()
        values = _payload_with_fields(payload, row_id=rid, email=email_value, mailbox_url=url_value)
        public_values, private_values = _partition_json(values)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    existing = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (rid,)
                    ).fetchone()
                    if existing is None:
                        db.execute(
                            "INSERT INTO mailboxes(row_id,email,mailbox_url,status,batch_id,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,0,?,?,?,?)",
                            (
                                rid,
                                email_value,
                                url_value,
                                str(status or "available"),
                                str(batch_id or ""),
                                now,
                                now,
                                _safe_json(public_values),
                                _safe_json(private_values),
                            ),
                        )
                    else:
                        # A pool refresh must not turn a row with an active
                        # lease back into ``available`` or erase the worker's
                        # confirmation metadata.  The check is performed in
                        # the same immediate transaction as the update.
                        active_lease = db.execute(
                            "SELECT 1 FROM resource_leases "
                            "WHERE resource_type='mailbox' AND resource_id=? "
                            "AND lease_until>? LIMIT 1",
                            (rid, time.time()),
                        ).fetchone()
                        row_lease_until = _safe_float(existing["lease_until"])
                        row_is_active = row_lease_until is not None and row_lease_until > time.time()
                        current_payload = self._row_payload(existing)
                        if active_lease is not None or row_is_active:
                            merged_payload = current_payload
                            # Pool refreshes may carry stale lifecycle fields
                            # from an old JSON snapshot.  Never let those
                            # fields clear a worker's confirmed hand-off or
                            # change its task ownership while a lease is live.
                            protected_fields = {
                                "row_id",
                                "email",
                                "mailbox_url",
                                "lease_confirmed",
                                "lease_confirmed_at",
                                "task_id",
                                "batch_id",
                                "driver",
                            }
                            merged_payload.update(
                                {
                                    key: value
                                    for key, value in values.items()
                                    if key not in protected_fields
                                }
                            )
                            merged_public, merged_private = _partition_json(merged_payload)
                            db.execute(
                                # Metadata refreshes must not invalidate the
                                # revision captured by a worker between claim
                                # and email submission.  Lifecycle mutations
                                # (claim/confirm/release) remain the only
                                # operations that advance this CAS revision.
                                "UPDATE mailboxes SET updated_at=?,payload=?,private_payload=? "
                                "WHERE row_id=? AND revision=?",
                                (
                                    now,
                                    _safe_json(merged_public),
                                    _safe_json(merged_private),
                                    rid,
                                    int(existing["revision"] or 0),
                                ),
                            )
                        else:
                            db.execute(
                                "UPDATE mailboxes SET email=?,mailbox_url=?,status=?,batch_id=?,"
                                "updated_at=?,revision=revision+1,payload=?,private_payload=? "
                                "WHERE row_id=? AND revision=?",
                                (
                                    email_value,
                                    url_value,
                                    str(status or "available"),
                                    str(batch_id or ""),
                                    now,
                                    _safe_json(public_values),
                                    _safe_json(private_values),
                                    rid,
                                    int(existing["revision"] or 0),
                                ),
                            )
                    row = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (rid,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._mailbox_dict(row)

    def get_mailbox(self, row_id: str, *, public: bool = False) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (str(row_id),)).fetchone()
        return self._mailbox_dict(row, public=public) if row is not None else None

    def is_mailbox_confirmed_for_task(self, row_id: str, task_id: str) -> bool:
        """Return the durable confirmation marker for one task/mailbox pair.

        This deliberately does not inspect ``resource_leases`` or the scalar
        lease expiry.  The lease sidecar is only a temporary ownership guard;
        once the email-submit boundary has been crossed, the payload marker is
        the durable evidence needed by cleanup and retry classification.  The
        task identity check prevents a stale marker from being attributed to a
        different worker.
        """
        normalized_row = str(row_id or "").strip()
        normalized_task = str(task_id or "").strip()
        if not normalized_row or not normalized_task:
            return False
        with self._connection() as db:
            row = db.execute(
                "SELECT payload,private_payload FROM mailboxes WHERE row_id=?",
                (normalized_row,),
            ).fetchone()
        if row is None:
            return False
        payload = self._row_payload(row)
        return bool(
            _stored_bool(payload.get("lease_confirmed"))
            and str(payload.get("task_id") or "").strip() == normalized_task
        )

    def list_mailboxes(
        self,
        *,
        status: str | None = None,
        limit: int = 500,
        offset: int = 0,
        public: bool = False,
    ) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        params.extend([max(1, int(limit)), max(0, int(offset))])
        with self._connection() as db:
            rows = db.execute(
                f"SELECT * FROM mailboxes WHERE {' AND '.join(clauses)} ORDER BY created_at DESC, row_id DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._mailbox_dict(row, public=public) for row in rows]

    def list_mailboxes_page(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        public: bool = False,
    ) -> dict[str, Any]:
        return self._page(
            "mailboxes", status=status, limit=limit, offset=offset, public=public
        )

    def claim_mailbox(
        self,
        *,
        owner: str,
        lease_seconds: int = 180,
        row_id: str | None = None,
        claimed_status: str = "reserved",
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
                    # Explicit row IDs still have to be available.  A caller
                    # must use ``lease_mailbox`` to renew its own reservation;
                    # this prevents accidentally stealing a failed/running
                    # row during a retry race.
                    where = "row_id=? AND status='available'" if row_id else "status='available'"
                    params: list[Any] = [str(row_id)] if row_id else []
                    claim_now = time.time()
                    candidates = db.execute(
                        f"SELECT * FROM mailboxes WHERE {where} "
                        "AND (lease_until IS NULL OR lease_until<=?) "
                        "AND NOT EXISTS ("
                        "SELECT 1 FROM resource_leases rl "
                        "WHERE rl.resource_type='mailbox' AND rl.resource_id=mailboxes.row_id "
                        "AND rl.lease_until>?"
                        ") ORDER BY created_at ASC,row_id ASC",
                        [*params, claim_now, claim_now],
                    ).fetchall()
                    # JSON payloads are intentionally kept portable (some
                    # supported SQLite builds do not expose JSON1).  Filter
                    # the durable confirmation marker in Python while the
                    # surrounding IMMEDIATE transaction still holds the claim
                    # admission lock.
                    row = next(
                        (
                            candidate
                            for candidate in candidates
                            if not _stored_bool(
                                self._row_payload(candidate).get("lease_confirmed")
                            )
                        ),
                        None,
                    )
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    updated = db.execute(
                        "UPDATE mailboxes SET status=?,lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE row_id=? AND (lease_until IS NULL OR lease_until<=?)",
                        (str(claimed_status), owner_value, until, now, row["row_id"], claim_now),
                    )
                    if updated.rowcount != 1:
                        db.execute("COMMIT")
                        return None
                    current = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (row["row_id"],)).fetchone()
                    db.execute(
                        "INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) VALUES('mailbox',?,?,?,?,?) ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET lease_until=excluded.lease_until,updated_at=excluded.updated_at",
                        (row["row_id"], owner_value, until, now, now),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return self._mailbox_dict(current) if current is not None else None

    def reserve_mailboxes(
        self,
        rows: Sequence[Mapping[str, Any]],
        *,
        batch_id: str = "",
    ) -> bool:
        """Reserve a mailbox batch atomically.

        The compatibility pool historically updated one row at a time.  That
        leaves a partially reserved batch when a later row is claimed by
        another process.  Validate every row and apply every update inside a
        single ``BEGIN IMMEDIATE`` transaction so callers see an all-or-none
        result and can safely retry the complete selection.
        """
        normalized: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for item in rows or ():
            if not isinstance(item, Mapping):
                return False
            row_id = str(item.get("row_id") or "").strip()
            if not row_id or row_id in seen:
                return False
            seen.add(row_id)
            normalized.append(
                (
                    row_id,
                    str(item.get("email") or "").strip(),
                    str(item.get("mailbox_url") or "").strip(),
                )
            )
        if not normalized:
            return True
        now_epoch = time.time()
        stamp = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current_rows: list[tuple[tuple[str, str, str], sqlite3.Row]] = []
                    for item in normalized:
                        row = db.execute(
                            "SELECT * FROM mailboxes WHERE row_id=? "
                            "AND status='available' "
                            "AND (lease_until IS NULL OR lease_until<=?) "
                            "AND NOT EXISTS ("
                            "SELECT 1 FROM resource_leases rl "
                            "WHERE rl.resource_type='mailbox' "
                            "AND rl.resource_id=mailboxes.row_id "
                            "AND rl.lease_until>?"
                            ")",
                            (item[0], now_epoch, now_epoch),
                        ).fetchone()
                        if row is None:
                            db.execute("ROLLBACK")
                            return False
                        current_rows.append((item, row))
                    for (row_id, email, mailbox_url), row in current_rows:
                        payload = self._row_payload(row)
                        # A row may have been manually restored from an older
                        # snapshot. Clear stale two-phase markers before a new
                        # reservation is handed to a worker.
                        for key in (
                            "lease_confirmed",
                            "lease_confirmed_at",
                            "task_id",
                            "batch_id",
                            "driver",
                        ):
                            payload.pop(key, None)
                        payload.update({
                            "email": email or str(row["email"] or ""),
                            "mailbox_url": mailbox_url or str(row["mailbox_url"] or ""),
                            "error": "",
                            "next_batch_priority": None,
                            "failure": None,
                        })
                        public_payload, private_payload = _partition_json(payload)
                        updated = db.execute(
                            "UPDATE mailboxes SET status='reserved',batch_id=?,"
                            "lease_owner='',lease_until=NULL,updated_at=?,"
                            "revision=revision+1,payload=?,private_payload=? "
                            "WHERE row_id=? AND status='available'",
                            (
                                str(batch_id or ""),
                                stamp,
                                _safe_json(public_payload),
                                _safe_json(private_payload),
                                row_id,
                            ),
                        )
                        if updated.rowcount != 1:
                            db.execute("ROLLBACK")
                            return False
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def lease_mailbox(
        self,
        row_id: str,
        *,
        owner: str,
        lease_seconds: int = 180,
        expected_revision: int | None = None,
    ) -> bool:
        return self._lease_single("mailbox", str(row_id), str(owner), lease_seconds, expected_revision)

    def confirm_mailbox_lease(
        self,
        row_id: str,
        *,
        owner: str,
        task_id: str,
        batch_id: str = "",
        driver: str = "protocol",
        expected_revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Confirm a mailbox lease at the point the page submits the email.

        Claiming a row only protects it during transport setup.  This second
        conditional update records the irreversible hand-off and is the sole
        place where a worker may mark a mailbox as consumed by a task.
        """
        normalized_row = str(row_id or "").strip()
        normalized_owner = str(owner or "").strip()
        normalized_task = str(task_id or "").strip()
        if not normalized_row or not normalized_owner or not normalized_task:
            return None
        now_epoch = time.time()
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    lease = db.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND owner=? AND lease_until>?",
                        (normalized_row, normalized_owner, now_epoch),
                    ).fetchone()
                    if lease is None or str(row["status"] or "") not in {"reserved", "running"}:
                        db.execute("COMMIT")
                        return None
                    payload = self._row_payload(row)
                    # Confirmation is deliberately idempotent for the same
                    # task, while a second task can never consume the same
                    # mailbox lease. Check this before the revision guard so
                    # a retried callback with an older snapshot can succeed
                    # without incrementing the revision again.
                    if payload.get("lease_confirmed"):
                        if str(payload.get("task_id") or "") == normalized_task:
                            db.execute("COMMIT")
                            return self._mailbox_dict(row)
                        db.execute("COMMIT")
                        return None
                    actual_revision = int(row["revision"] or 0)
                    if expected_revision is not None and actual_revision != int(expected_revision):
                        db.execute("COMMIT")
                        return None
                    payload.update({
                        "task_id": normalized_task,
                        "batch_id": str(batch_id or ""),
                        "driver": str(driver or "protocol"),
                        "lease_confirmed": True,
                        "lease_confirmed_at": now_epoch,
                    })
                    public_payload, private_payload = _partition_json(payload)
                    updated = db.execute(
                        "UPDATE mailboxes SET status='running',batch_id=?,updated_at=?,"
                        "revision=revision+1,payload=?,private_payload=? WHERE row_id=? AND revision=?",
                        (
                            str(batch_id or ""), now, _safe_json(public_payload),
                            _safe_json(private_payload),
                            normalized_row, actual_revision,
                        ),
                    )
                    if updated.rowcount != 1:
                        db.execute("ROLLBACK")
                        return None
                    current = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return self._mailbox_dict(current) if current is not None else None

    def abort_mailbox_confirmation(
        self,
        row_id: str,
        *,
        owner: str,
        task_id: str,
        submission_definitely_not_started: bool = False,
        expected_revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Roll back a pre-submit confirmation while retaining the lease.

        Confirmation is conservative: callers set it immediately before a
        side-effecting submit.  A transport may roll it back only when it can
        prove that the submit primitive was never entered.  Once the request,
        click, or Enter action may have started, normal release semantics keep
        the row in ``pending_rerun``.
        """
        normalized_row = str(row_id or "").strip()
        normalized_owner = str(owner or "").strip()
        normalized_task = str(task_id or "").strip()
        if (
            not normalized_row
            or not normalized_owner
            or not normalized_task
            or submission_definitely_not_started is not True
        ):
            return None
        now_epoch = time.time()
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    lease = db.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND owner=? AND lease_until>?",
                        (normalized_row, normalized_owner, now_epoch),
                    ).fetchone()
                    payload = self._row_payload(row)
                    if (
                        lease is None
                        or str(row["lease_owner"] or "") != normalized_owner
                        or str(row["status"] or "") != "running"
                        or not _stored_bool(payload.get("lease_confirmed"))
                        or str(payload.get("task_id") or "") != normalized_task
                    ):
                        db.execute("COMMIT")
                        return None
                    actual_revision = int(row["revision"] or 0)
                    if (
                        expected_revision is not None
                        and actual_revision != int(expected_revision)
                    ):
                        db.execute("COMMIT")
                        return None
                    for key in (
                        "lease_confirmed",
                        "lease_confirmed_at",
                        "task_id",
                        "batch_id",
                        "driver",
                    ):
                        payload.pop(key, None)
                    public_payload, private_payload = _partition_json(payload)
                    updated = db.execute(
                        "UPDATE mailboxes SET status='reserved',updated_at=?,"
                        "revision=revision+1,payload=?,private_payload=? "
                        "WHERE row_id=? AND revision=? AND lease_owner=?",
                        (
                            now,
                            _safe_json(public_payload),
                            _safe_json(private_payload),
                            normalized_row,
                            actual_revision,
                            normalized_owner,
                        ),
                    )
                    if updated.rowcount != 1:
                        db.execute("ROLLBACK")
                        return None
                    current = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return self._mailbox_dict(current) if current is not None else None

    def release_mailbox_lease(
        self,
        row_id: str,
        *,
        owner: str,
        reusable: bool = True,
    ) -> bool:
        """Release an unconfirmed lease, or consume a confirmed one."""
        normalized_row = str(row_id or "").strip()
        normalized_owner = str(owner or "").strip()
        if not normalized_row or not normalized_owner:
            return False
        now_epoch = time.time()
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return False
                    lease = db.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND owner=?",
                        (normalized_row, normalized_owner),
                    ).fetchone()
                    if lease is None:
                        db.execute("COMMIT")
                        return False
                    payload = self._row_payload(row)
                    confirmed = _stored_bool(payload.get("lease_confirmed"))
                    # Once the email was submitted, the mailbox is never made
                    # immediately available again.  It is explicitly marked
                    # for a later rerun/cleanup instead.
                    # Once a worker has explicitly written a terminal mailbox
                    # result (success/partial/twofa/failure), cleanup must not
                    # overwrite that durable status with ``pending_rerun``.
                    # Only an active confirmed claim needs the pending marker.
                    current_status = str(row["status"] or "")
                    if confirmed:
                        target_status = (
                            "pending_rerun"
                            if current_status in {"reserved", "queued", "running"}
                            else current_status or "pending_rerun"
                        )
                    else:
                        target_status = "available" if reusable else "failed"

                    db.execute(
                        "DELETE FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND owner=?",
                        (normalized_row, normalized_owner),
                    )
                    remaining = db.execute(
                        "SELECT owner,lease_until FROM resource_leases "
                        "WHERE resource_type='mailbox' AND resource_id=? "
                        "AND lease_until>? ORDER BY lease_until DESC LIMIT 1",
                        (normalized_row, now_epoch),
                    ).fetchone()
                    if remaining is not None:
                        # A stale owner may release after its lease was
                        # replaced. Preserve the new owner's state and payload
                        # instead of changing it underneath that worker.
                        db.execute(
                            "UPDATE mailboxes SET lease_owner=?,lease_until=?,"
                            "updated_at=?,revision=revision+1 WHERE row_id=?",
                            (
                                str(remaining["owner"]),
                                float(remaining["lease_until"]),
                                now,
                                normalized_row,
                            ),
                        )
                    else:
                        if not confirmed and reusable:
                            for key in (
                                "lease_confirmed",
                                "lease_confirmed_at",
                                "task_id",
                                "batch_id",
                                "driver",
                            ):
                                payload.pop(key, None)
                        public_payload, private_payload = _partition_json(payload)
                        db.execute(
                            "UPDATE mailboxes SET status=?,lease_owner='',lease_until=NULL,"
                            "updated_at=?,revision=revision+1,payload=?,private_payload=? WHERE row_id=?",
                            (
                                target_status,
                                now,
                                _safe_json(public_payload),
                                _safe_json(private_payload),
                                normalized_row,
                            ),
                        )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return True

    def update_mailbox(
        self,
        row_id: str,
        *,
        status: str | None = None,
        batch_id: str | None = None,
        payload_patch: Mapping[str, Any] | None = None,
        allow_active_status: bool = False,
    ) -> dict[str, Any] | None:
        """Apply a narrow mailbox update without replacing private fields."""
        rid = str(row_id or "").strip()
        if not rid:
            return None
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (rid,)).fetchone()
                    if current is None:
                        db.execute("COMMIT")
                        return None
                    payload = self._row_payload(current)
                    now_epoch = time.time()
                    active_lease = db.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND lease_until>? LIMIT 1",
                        (rid, now_epoch),
                    ).fetchone()
                    if isinstance(payload_patch, Mapping):
                        patch_values = copy.deepcopy(dict(payload_patch))
                        if active_lease is not None:
                            # Lifecycle fields have dedicated atomic methods;
                            # accepting them from a generic progress callback
                            # would let a stale snapshot clear confirmation.
                            for key in (
                                "row_id",
                                "email",
                                "mailbox_url",
                                "status",
                                "lease_owner",
                                "lease_until",
                                "lease_confirmed",
                                "lease_confirmed_at",
                                "task_id",
                                "batch_id",
                                "driver",
                            ):
                                patch_values.pop(key, None)
                        payload.update(patch_values)
                    revision_clause = "revision=revision+1"
                    if active_lease is not None:
                        # Non-lifecycle metadata must not invalidate the
                        # worker's claim-to-confirm CAS revision.
                        revision_clause = "revision=revision"
                    public_payload, private_payload = _partition_json(payload)
                    updates: list[str] = []
                    params: list[Any] = []
                    if status is not None and (active_lease is None or allow_active_status):
                        updates.append("status=?")
                        params.append(str(status))
                    if batch_id is not None and (active_lease is None or allow_active_status):
                        updates.append("batch_id=?")
                        params.append(str(batch_id))
                    updates.extend([
                        "updated_at=?",
                        revision_clause,
                        "payload=?",
                        "private_payload=?",
                    ])
                    params.extend([
                        _now(),
                        _safe_json(public_payload),
                        _safe_json(private_payload),
                        rid,
                    ])
                    db.execute(
                        f"UPDATE mailboxes SET {','.join(updates)} WHERE row_id=?",
                        params,
                    )
                    row = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (rid,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return self._mailbox_dict(row) if row is not None else None


__all__ = [
    "FreeStorageMailboxMixin",
]
