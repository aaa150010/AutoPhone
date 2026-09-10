"""Connection, transaction, schema initialization and manager-owner lease for the Free SQLite store.

Split out of ``free_storage.py``; ``FreeSQLiteStore`` composes these domain
mixins so the class body stays navigable while the on-disk schema, method set
and behavior remain unchanged.  Mixins rely on attributes defined by the
schema band (``self._dir``, ``self._db_path``, ``self._lock``, ``self._connection``,
``self._transaction`` ...).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

try:
    from .free_storage_common import (
        MANAGER_OWNER_KEY,
        MANAGER_OWNER_TTL_SECONDS,
        SCHEMA_VERSION,
        FreeStorageError,
        ManagerOwnerConflict,
        _clear_legacy_pool_dimensions,
        _merge_private_payload,
        _partition_json,
        _safe_json,
        MANAGER_OWNER_KEY,
        MANAGER_OWNER_TTL_SECONDS,
        SCHEMA_VERSION,
        FreeStorageError,
        ManagerOwnerConflict,
        _clear_legacy_pool_dimensions,
        _merge_private_payload,
        _partition_json,
        _safe_json,
    )
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_storage_common import (  # type: ignore[no-redef]
        MANAGER_OWNER_KEY,
        MANAGER_OWNER_TTL_SECONDS,
        SCHEMA_VERSION,
        FreeStorageError,
        ManagerOwnerConflict,
        _clear_legacy_pool_dimensions,
        _merge_private_payload,
        _partition_json,
        _safe_json,
        MANAGER_OWNER_KEY,
        MANAGER_OWNER_TTL_SECONDS,
        SCHEMA_VERSION,
        FreeStorageError,
        ManagerOwnerConflict,
        _clear_legacy_pool_dimensions,
        _merge_private_payload,
        _partition_json,
        _safe_json,
    )


class FreeStorageSchemaMixin:
    """Methods moved verbatim from FreeSQLiteStore."""


    def __init__(
        self,
        data_dir: str | Path,
        *,
        busy_timeout_ms: int = 30_000,
        auto_migrate: bool = True,
    ) -> None:
        self.root = Path(data_dir).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "free_register.sqlite3"
        self.busy_timeout_ms = max(100, int(busy_timeout_ms))
        self._lock = threading.RLock()
        # One lock-serialized handle instead of a connect/PRAGMA/close cycle
        # per call. ``_connection`` always runs under ``self._lock`` (RLock,
        # so nested ``_transaction`` + ``_connection`` stays safe), and every
        # caller finishes its reads inside the context, so no cursor escapes.
        self._conn: sqlite3.Connection | None = None
        # Read failures are kept separate from malformed individual rows.
        # The latter are stable data-quality diagnostics; the former mean a
        # legacy source may not have been seen at all and must keep migration
        # retryable on the next process start.
        self._legacy_read_errors: list[str] = []
        self._initialize()
        if auto_migrate:
            self.migrate_legacy()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._ensure_connection()
            try:
                yield connection
            except sqlite3.Error:
                # A broken handle (disk error, damaged page) must not poison
                # every later operation; drop it so the next caller reconnects.
                self._drop_connection()
                raise

    def _ensure_connection(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000.0,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        # WAL is a persistent database property; the rest are per-connection
        # settings re-asserted on every cold connect.
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA foreign_keys=ON")
        self._conn = connection
        return connection

    def _drop_connection(self) -> None:
        connection, self._conn = self._conn, None
        if connection is None:
            return
        try:
            connection.close()
        except sqlite3.Error:
            pass

    @contextmanager
    def _transaction(self, *, immediate: bool = True) -> Iterator[None]:
        """Serialize a multi-step operation within this process.

        Callers open their own connection inside this context so each SQL
        mutation can use an explicit ``BEGIN IMMEDIATE``.  ``immediate`` is
        retained for compatibility with early callers of this private helper.
        """
        del immediate
        with self._lock:
            yield None

    @staticmethod
    def _decode_json_value(value: Any) -> Any:
        try:
            return json.loads(str(value or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}

    def _migrate_payload_sidecars(self, db: sqlite3.Connection) -> None:
        """Move sensitive leaves out of pre-sidecar payload columns once.

        This is intentionally an in-place schema hygiene migration.  It does
        not alter timestamps, revisions, or lifecycle state, and is safe to
        rerun after an interrupted process because the partition operation is
        deterministic.
        """
        identity_columns = {
            "mailboxes": "row_id",
            "proxies": "proxy_id",
            "tasks": "task_id",
            "results": "row_id",
        }
        for table, identity in identity_columns.items():
            rows = db.execute(
                f"SELECT {identity},payload,private_payload FROM {table}"
            ).fetchall()
            for row in rows:
                combined = _merge_private_payload(
                    self._decode_json_value(row[1]),
                    self._decode_json_value(row[2]),
                )
                combined = _clear_legacy_pool_dimensions(
                    combined, include_plain=table == "proxies"
                )
                public_value, private_value = _partition_json(
                    combined if isinstance(combined, Mapping) else {}
                )
                public_json = _safe_json(public_value)
                private_json = _safe_json(private_value)
                if str(row[1] or "") == public_json and str(row[2] or "") == private_json:
                    continue
                db.execute(
                    f"UPDATE {table} SET payload=?,private_payload=? WHERE {identity}=?",
                    (public_json, private_json, str(row[0])),
                )

    def _initialize(self) -> None:
        with self._transaction():
            # Payload columns preserve forward compatibility while the scalar
            # fields make claims, status counts and pagination indexable.
            with self._connection() as db:
                try:
                    db.executescript(
                        """
                        CREATE TABLE IF NOT EXISTS storage_meta (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS mailboxes (
                            row_id TEXT PRIMARY KEY,
                            email TEXT NOT NULL,
                            mailbox_url TEXT NOT NULL,
                            status TEXT NOT NULL DEFAULT 'available',
                            batch_id TEXT NOT NULL DEFAULT '',
                            lease_owner TEXT NOT NULL DEFAULT '',
                            lease_until REAL,
                            revision INTEGER NOT NULL DEFAULT 0,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS proxies (
                            proxy_id TEXT PRIMARY KEY,
                            proxy TEXT NOT NULL,
                            scheme TEXT NOT NULL DEFAULT '',
                            status TEXT NOT NULL DEFAULT 'unknown',
                            enabled INTEGER NOT NULL DEFAULT 1,
                            lease_owner TEXT NOT NULL DEFAULT '',
                            lease_until REAL,
                            revision INTEGER NOT NULL DEFAULT 0,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS tasks (
                            task_id TEXT PRIMARY KEY,
                            status TEXT NOT NULL DEFAULT 'queued',
                            revision INTEGER NOT NULL DEFAULT 0,
                            lease_owner TEXT NOT NULL DEFAULT '',
                            lease_until REAL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS results (
                            row_id TEXT PRIMARY KEY,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS remail_orders (
                            order_no TEXT PRIMARY KEY,
                            status TEXT NOT NULL DEFAULT '',
                            delivery_email TEXT NOT NULL DEFAULT '',
                            imported INTEGER NOT NULL DEFAULT 0,
                            pool_row_id TEXT NOT NULL DEFAULT '',
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS resource_leases (
                            resource_type TEXT NOT NULL,
                            resource_id TEXT NOT NULL,
                            owner TEXT NOT NULL,
                            lease_until REAL NOT NULL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY(resource_type, resource_id, owner)
                        );
                        CREATE INDEX IF NOT EXISTS idx_mailboxes_status ON mailboxes(status, row_id);
                        CREATE INDEX IF NOT EXISTS idx_mailboxes_lease ON mailboxes(lease_until);
                        CREATE INDEX IF NOT EXISTS idx_mailboxes_updated ON mailboxes(updated_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status, enabled, proxy_id);
                        CREATE INDEX IF NOT EXISTS idx_proxies_lease ON proxies(lease_until);
                        CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, updated_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_tasks_updated ON tasks(updated_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_leases_expiry ON resource_leases(resource_type, lease_until);
                        -- Compatibility names for callers that prefer an
                        -- explicit Free prefix.  Views avoid duplicating data
                        -- or creating a second source of truth.
                        CREATE VIEW IF NOT EXISTS free_storage_meta AS SELECT * FROM storage_meta;
                        CREATE VIEW IF NOT EXISTS free_mailboxes AS SELECT * FROM mailboxes;
                        CREATE VIEW IF NOT EXISTS free_proxies AS SELECT * FROM proxies;
                        CREATE VIEW IF NOT EXISTS free_tasks AS SELECT * FROM tasks;
                        CREATE VIEW IF NOT EXISTS free_results AS SELECT * FROM results;
                        CREATE VIEW IF NOT EXISTS free_remail_orders AS SELECT * FROM remail_orders;
                        CREATE VIEW IF NOT EXISTS free_resource_leases AS SELECT * FROM resource_leases;
                        """
                    )
                    # Existing installations may already have the v1 tables.
                    # Add the sidecar columns in place and normalize any
                    # malformed/null values without touching business rows.
                    existing_schema_row = db.execute(
                        "SELECT value FROM storage_meta WHERE key='schema_version'"
                    ).fetchone()
                    try:
                        existing_schema = int(existing_schema_row[0]) if existing_schema_row else 0
                    except (TypeError, ValueError):
                        existing_schema = 0
                    if existing_schema > SCHEMA_VERSION:
                        raise FreeStorageError(
                            f"SQLite schema 版本 {existing_schema} 高于当前运行时 {SCHEMA_VERSION}"
                        )
                    for table in ("mailboxes", "proxies", "tasks", "results", "remail_orders"):
                        columns = {
                            str(item[1])
                            for item in db.execute(f"PRAGMA table_info({table})").fetchall()
                        }
                        if "private_payload" not in columns:
                            db.execute(
                                f"ALTER TABLE {table} ADD COLUMN private_payload TEXT NOT NULL DEFAULT '{{}}'"
                            )
                        db.execute(
                            f"UPDATE {table} SET private_payload='{{}}' WHERE private_payload IS NULL"
                        )
                    # Remail order rows can be dismissed (hidden) locally so a
                    # wrong-parameter failed order stops reappearing after the
                    # remote order list is re-synced.
                    remail_columns = {
                        str(item[1])
                        for item in db.execute("PRAGMA table_info(remail_orders)").fetchall()
                    }
                    if "hidden" not in remail_columns:
                        db.execute(
                            "ALTER TABLE remail_orders ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0"
                        )
                        db.execute(
                            "UPDATE remail_orders SET hidden=0 WHERE hidden IS NULL"
                        )
                    self._migrate_payload_sidecars(db)
                    # ``executescript`` manages DDL in autocommit mode when
                    # isolation_level=None; use a short explicit transaction
                    # for the metadata write instead of committing a vanished
                    # DDL transaction.
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES('schema_version',?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (str(SCHEMA_VERSION),),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def _meta(self, key: str) -> str | None:
        with self._connection() as db:
            row = db.execute("SELECT value FROM storage_meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row is not None else None

    @staticmethod
    def _decode_manager_owner(value: Any) -> dict[str, Any]:
        try:
            parsed = json.loads(str(value or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return dict(parsed) if isinstance(parsed, Mapping) else {}

    staticmethod
    @staticmethod
    def _pid_is_alive(pid: Any) -> bool:
        """Return whether a recorded process still exists on this host.

        ``os.kill(pid, 0)`` does not terminate anything.  A permission error
        still means that the process exists, so it is treated as live.  A
        malformed/absent PID is intentionally not considered a proof of life;
        the heartbeat timestamp remains the fallback for old metadata.
        """
        try:
            value = int(pid)
        except (TypeError, ValueError, OverflowError):
            return False
        if value <= 0:
            return False
        try:
            os.kill(value, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    classmethod
    @classmethod
    def _manager_owner_live(
        cls,
        owner: Mapping[str, Any],
        *,
        now: float,
        ttl_seconds: float,
    ) -> bool:
        try:
            heartbeat = float(owner.get("heartbeat_at"))
        except (TypeError, ValueError):
            return False
        # A clock adjustment must not make a recently written owner appear
        # stale.  The upper bound is the only expiry condition.
        if now - heartbeat > max(1.0, float(ttl_seconds)):
            return False
        pid = owner.get("pid")
        if pid not in (None, "", 0):
            return cls._pid_is_alive(pid)
        # Metadata written by an older build may not contain a PID.  Keep it
        # fenced while its heartbeat is fresh rather than allowing a second
        # manager to race the unknown process.
        return True

    def acquire_manager_owner(
        self,
        owner_id: str,
        *,
        pid: int | None = None,
        now: float | None = None,
        ttl_seconds: int = MANAGER_OWNER_TTL_SECONDS,
    ) -> dict[str, Any]:
        """Atomically claim the Free manager runtime.

        The claim lives in ``storage_meta`` so it is shared by every process
        using the isolated Free database.  A live owner causes
        :class:`ManagerOwnerConflict`; an expired/dead owner is replaced with
        a monotonically increasing epoch.  Callers must renew the returned
        ``owner_id``/``epoch`` pair and use that pair as a write fence.
        """
        normalized = str(owner_id or "").strip()
        if not normalized:
            raise ValueError("owner_id 不能为空")
        current_time = float(time.time() if now is None else now)
        process_id = int(os.getpid() if pid is None else pid)
        ttl = max(1, int(ttl_seconds))
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT value FROM storage_meta WHERE key=?",
                        (MANAGER_OWNER_KEY,),
                    ).fetchone()
                    existing = self._decode_manager_owner(row[0] if row else None)
                    existing_id = str(existing.get("owner_id") or "").strip()
                    if (
                        existing_id
                        and existing_id != normalized
                        and self._manager_owner_live(
                            existing, now=current_time, ttl_seconds=ttl
                        )
                    ):
                        db.execute("ROLLBACK")
                        raise ManagerOwnerConflict(existing)
                    try:
                        previous_epoch = max(0, int(existing.get("epoch") or 0))
                    except (TypeError, ValueError, OverflowError):
                        previous_epoch = 0
                    # Re-acquiring the same token is idempotent (useful for a
                    # controlled application reload); a new token advances the
                    # fence so stale workers cannot write afterwards.
                    epoch = previous_epoch if existing_id == normalized else previous_epoch + 1
                    record = {
                        "owner_id": normalized,
                        "pid": process_id,
                        "epoch": epoch,
                        "started_at": current_time,
                        "heartbeat_at": current_time,
                        "ttl_seconds": ttl,
                    }
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (MANAGER_OWNER_KEY, _safe_json(record)),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return record

    def renew_manager_owner(
        self,
        owner_id: str,
        epoch: int,
        *,
        pid: int | None = None,
        now: float | None = None,
        ttl_seconds: int = MANAGER_OWNER_TTL_SECONDS,
    ) -> bool:
        """Refresh a manager claim only when its owner/epoch still match."""
        normalized = str(owner_id or "").strip()
        if not normalized:
            return False
        current_time = float(time.time() if now is None else now)
        process_id = int(os.getpid() if pid is None else pid)
        ttl = max(1, int(ttl_seconds))
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT value FROM storage_meta WHERE key=?",
                        (MANAGER_OWNER_KEY,),
                    ).fetchone()
                    existing = self._decode_manager_owner(row[0] if row else None)
                    if (
                        str(existing.get("owner_id") or "").strip() != normalized
                        or int(existing.get("epoch") or -1) != int(epoch)
                    ):
                        db.execute("COMMIT")
                        return False
                    existing.update({
                        "pid": process_id,
                        "heartbeat_at": current_time,
                        "ttl_seconds": ttl,
                    })
                    db.execute(
                        "UPDATE storage_meta SET value=? WHERE key=?",
                        (_safe_json(existing), MANAGER_OWNER_KEY),
                    )
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def manager_owner_is_current(self, owner_id: str, epoch: int) -> bool:
        """Check the exact owner/epoch pair without extending its lease."""
        normalized = str(owner_id or "").strip()
        if not normalized:
            return False
        with self._connection() as db:
            row = db.execute(
                "SELECT value FROM storage_meta WHERE key=?",
                (MANAGER_OWNER_KEY,),
            ).fetchone()
        owner = self._decode_manager_owner(row[0] if row else None)
        try:
            owner_epoch = int(owner.get("epoch"))
        except (TypeError, ValueError, OverflowError):
            return False
        return (
            str(owner.get("owner_id") or "").strip() == normalized
            and owner_epoch == int(epoch)
        )

    def release_manager_owner(self, owner_id: str, epoch: int) -> bool:
        """Delete a claim only if the caller still owns its fence."""
        normalized = str(owner_id or "").strip()
        if not normalized:
            return False
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT value FROM storage_meta WHERE key=?",
                        (MANAGER_OWNER_KEY,),
                    ).fetchone()
                    owner = self._decode_manager_owner(row[0] if row else None)
                    try:
                        matches = (
                            str(owner.get("owner_id") or "").strip() == normalized
                            and int(owner.get("epoch")) == int(epoch)
                        )
                    except (TypeError, ValueError, OverflowError):
                        matches = False
                    if not matches:
                        db.execute("COMMIT")
                        return False
                    deleted = db.execute(
                        "DELETE FROM storage_meta WHERE key=?",
                        (MANAGER_OWNER_KEY,),
                    ).rowcount == 1
                    db.execute("COMMIT")
                    return deleted
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def manager_owner_status(self) -> dict[str, Any]:
        """Return a credential-free owner health snapshot for diagnostics."""
        raw = self._meta(MANAGER_OWNER_KEY)
        owner = self._decode_manager_owner(raw)
        try:
            heartbeat = float(owner.get("heartbeat_at"))
        except (TypeError, ValueError):
            heartbeat = 0.0
        try:
            ttl = max(1, int(owner.get("ttl_seconds") or MANAGER_OWNER_TTL_SECONDS))
        except (TypeError, ValueError, OverflowError):
            ttl = MANAGER_OWNER_TTL_SECONDS
        age = max(0.0, time.time() - heartbeat) if heartbeat else None
        return {
            "present": bool(owner.get("owner_id")),
            "active": bool(owner.get("owner_id")) and self._manager_owner_live(
                owner, now=time.time(), ttl_seconds=ttl
            ),
            "epoch": int(owner.get("epoch") or 0),
            "pid": int(owner.get("pid") or 0),
            "heartbeat_age_seconds": round(age, 3) if age is not None else None,
            "ttl_seconds": ttl,
        }


__all__ = [
    "FreeStorageSchemaMixin",
]
