"""SQLite persistence for the isolated Free email-rebind workspace.

The registration database is intentionally not reused here.  Rebind has a
separate mailbox lifecycle and task queue, so a target mailbox or a rebind
task can never be claimed by a new-account worker.  Legacy text/JSON files
are imported once, but all subsequent mutations use this store.
"""

from __future__ import annotations

from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

try:
    from .free_failure_runtime import canonical_failure, sanitize_failure_text
    from .free_register_common import mask_email, parse_mailbox_line
except ImportError:  # pragma: no cover - direct recovery imports
    from free_failure_runtime import canonical_failure, sanitize_failure_text  # type: ignore[no-redef]
    from free_register_common import mask_email, parse_mailbox_line  # type: ignore[no-redef]


SCHEMA_VERSION = 1
REBIND_MIGRATION_KEY = "legacy_migration_v1"
TERMINAL_REBIND_STATUSES = frozenset({
    "success", "partial_success", "failed", "stopped",
})
ACTIVE_REBIND_STATUSES = frozenset({"queued", "running", "reserved"})
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}$")


def _now() -> int:
    return int(time.time())


def _coerce_timestamp(value: Any, default: int | None = None) -> int:
    """Normalize legacy epoch or ISO-8601 values to epoch seconds.

    Early JSON snapshots used integers while newer snapshots sometimes carry
    the ISO strings emitted by the shared runtime.  Migration and task writes
    must accept both forms without allowing a malformed value to abort
    startup.
    """
    fallback = _now() if default is None else int(default)
    if value is None or value == "":
        return fallback
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return fallback
    text = str(value).strip()
    if not text:
        return fallback
    try:
        return int(float(text))
    except (TypeError, ValueError, OverflowError):
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp())
    except (TypeError, ValueError, OverflowError):
        return fallback


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(str(value or "").strip().encode("utf-8")).hexdigest()


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return "{}"


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return {}


def _safe_text(value: Any, limit: int = 500) -> str:
    return " ".join(str(value or "").replace("\x00", " ").split())[:limit]


def _valid_migration_marker(value: Any) -> bool:
    """Return true only for a current, structured migration marker."""
    try:
        parsed = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(parsed, Mapping):
        return False
    # A version alone does not prove that the source files were read and the
    # import transaction committed.  In particular, a process can terminate
    # after inserting some rows but before writing the completion marker.
    if parsed.get("complete") is not True:
        return False
    try:
        return int(parsed.get("version")) == SCHEMA_VERSION
    except (TypeError, ValueError):
        return False


def _migration_marker_version(value: Any) -> int | None:
    try:
        parsed = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, Mapping):
        return None
    try:
        return int(parsed.get("version"))
    except (TypeError, ValueError):
        return None


def _mask_email(value: Any) -> str:
    text = str(value or "").strip()
    if "@" not in text:
        return ""
    local, domain = text.split("@", 1)
    if len(local) <= 1:
        masked = "*"
    elif len(local) == 2:
        masked = local[0] + "*"
    else:
        masked = local[0] + "***" + local[-1]
    return f"{masked}@{domain[:160]}"


def _mask_url(value: Any) -> str:
    """Expose only an origin/path-less marker in public rows."""
    try:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        return urlunsplit((parsed.scheme.lower(), parsed.hostname, "", "", ""))
    except (TypeError, ValueError):
        return ""


class RebindStorageError(RuntimeError):
    """Base error for the rebind-owned SQLite store."""


class RebindRevisionConflict(RebindStorageError):
    """A compare-and-set task update lost a concurrent revision race."""

    def __init__(self, task_id: str, expected: int | None, actual: int | None) -> None:
        self.task_id = str(task_id)
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"换绑任务 revision 冲突: task_id={self.task_id}, "
            f"expected={expected}, actual={actual}"
        )


class RebindSQLiteStore:
    """Short-connection, transactional store for rebind mailboxes/tasks."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        busy_timeout_ms: int = 30_000,
        auto_migrate: bool = True,
    ) -> None:
        base = Path(data_dir).expanduser().resolve()
        self.root = base if base.name == "rebind" else base / "rebind"
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "free_rebind.sqlite3"
        self.busy_timeout_ms = max(100, int(busy_timeout_ms))
        self._lock = threading.RLock()
        self._initialize()
        if auto_migrate:
            self.migrate_legacy()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000.0,
            isolation_level=None,
            check_same_thread=False,
        )
        db.row_factory = sqlite3.Row
        try:
            db.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute("PRAGMA foreign_keys=ON")
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        # The in-process lock keeps the read/modify/write sequence coherent;
        # BEGIN IMMEDIATE also protects against another process instance.
        with self._lock:
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    yield db
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise

    def _initialize(self) -> None:
        # ``executescript`` intentionally commits any open transaction on
        # sqlite3, so run schema DDL outside ``_transaction`` and then perform
        # the metadata write in its own short transaction.
        with self._lock:
            with self._connection() as db:
                # Check the existing metadata before running any DDL.  An
                # older runtime must fail closed when it opens a database
                # created by a newer runtime instead of replacing the schema
                # marker with its own version.
                try:
                    existing_schema_row = db.execute(
                        "SELECT value FROM storage_meta WHERE key='schema_version'"
                    ).fetchone()
                except sqlite3.OperationalError:
                    # A brand-new database has no metadata table yet.
                    existing_schema_row = None
                try:
                    existing_schema = (
                        int(existing_schema_row[0]) if existing_schema_row else 0
                    )
                except (TypeError, ValueError, OverflowError):
                    existing_schema = 0
                if existing_schema > SCHEMA_VERSION:
                    raise RebindStorageError(
                        f"换绑 SQLite schema 版本 {existing_schema} "
                        f"高于当前运行时 {SCHEMA_VERSION}"
                    )
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
                        task_id TEXT NOT NULL DEFAULT '',
                        revision INTEGER NOT NULL DEFAULT 0,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        payload TEXT NOT NULL DEFAULT '{}'
                    );
                    CREATE TABLE IF NOT EXISTS tasks (
                        task_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL DEFAULT 'queued',
                        revision INTEGER NOT NULL DEFAULT 0,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        payload TEXT NOT NULL DEFAULT '{}'
                    );
                    CREATE INDEX IF NOT EXISTS idx_rebind_mailboxes_status
                        ON mailboxes(status, updated_at DESC, row_id);
                    CREATE INDEX IF NOT EXISTS idx_rebind_mailboxes_task
                        ON mailboxes(task_id);
                    CREATE INDEX IF NOT EXISTS idx_rebind_tasks_status
                        ON tasks(status, updated_at DESC, task_id);
                    CREATE INDEX IF NOT EXISTS idx_rebind_tasks_updated
                        ON tasks(updated_at DESC);
                    """
                )
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO storage_meta(key,value) VALUES('schema_version',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(SCHEMA_VERSION),),
                )
                db.execute("COMMIT")

    def _meta(self, key: str) -> str | None:
        with self._connection() as db:
            row = db.execute("SELECT value FROM storage_meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row is not None else None

    def migration_status(self) -> dict[str, Any]:
        value = self._meta(REBIND_MIGRATION_KEY)
        detail: dict[str, Any] = {}
        if value:
            try:
                parsed = json.loads(value)
                if isinstance(parsed, Mapping):
                    detail = dict(parsed)
            except (TypeError, ValueError, json.JSONDecodeError):
                detail = {}
        # Treat a malformed/old marker as incomplete so an interrupted or
        # manually repaired installation can safely retry the idempotent
        # import.  Only a structured marker carrying the current schema
        # version is considered complete; malformed and old scalar markers
        # are retried idempotently on the next startup.
        completed = _valid_migration_marker(value)
        return {
            "key": REBIND_MIGRATION_KEY,
            "completed": completed,
            "version": SCHEMA_VERSION,
            **detail,
        }

    def _read_json(self, path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return default

    def _legacy_mailboxes(self) -> list[dict[str, Any]]:
        pool_path = self.root / "mailbox_pool.txt"
        state_path = self.root / "mailbox_state.json"
        try:
            lines = pool_path.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, OSError, UnicodeError):
            lines = []
        state_payload = self._read_json(state_path, {})
        state_rows = state_payload.get("rows") if isinstance(state_payload, Mapping) else {}
        if not isinstance(state_rows, Mapping):
            state_rows = {}
        result: list[dict[str, Any]] = []
        for line_no, raw in enumerate(lines, 1):
            parsed = parse_mailbox_line(raw)
            if parsed is None:
                continue
            email, mailbox_url = parsed
            row_id = _fingerprint(f"{email}|{mailbox_url}")
            state = state_rows.get(row_id)
            state = dict(state) if isinstance(state, Mapping) else {}
            payload = _json_object(state)
            payload.update({"line_no": line_no, "email": email, "mailbox_url": mailbox_url})
            result.append({
                "row_id": row_id,
                "email": email,
                "mailbox_url": mailbox_url,
                "status": str(state.get("status") or "available"),
                "task_id": str(state.get("task_id") or ""),
                "revision": max(0, int(state.get("revision") or 0)) if str(state.get("revision") or "0").lstrip("-").isdigit() else 0,
                "created_at": _coerce_timestamp(state.get("created_at"), _now()),
                "updated_at": _coerce_timestamp(state.get("updated_at"), _now()),
                "payload": payload,
            })
        return result

    def _legacy_tasks(self) -> list[dict[str, Any]]:
        payload = self._read_json(self.root / "tasks.json", {})
        raw_tasks = payload.get("tasks") if isinstance(payload, Mapping) else {}
        if not isinstance(raw_tasks, Mapping):
            return []
        result: list[dict[str, Any]] = []
        for key, value in raw_tasks.items():
            if not isinstance(value, Mapping):
                continue
            task = copy.deepcopy(dict(value))
            task_id = str(task.get("task_id") or key).strip()
            if not task_id:
                continue
            try:
                revision = max(0, int(task.get("revision") or 0))
            except (TypeError, ValueError):
                revision = 0
            result.append({
                "task_id": task_id,
                "status": str(task.get("status") or "queued"),
                "revision": revision,
                "created_at": _coerce_timestamp(task.get("created_at"), _now()),
                "updated_at": _coerce_timestamp(task.get("updated_at"), _now()),
                "payload": task,
            })
        return result

    def migrate_legacy(self, *, force: bool = False) -> dict[str, Any]:
        marker = self._meta(REBIND_MIGRATION_KEY)
        marker_version = _migration_marker_version(marker)
        if marker_version is not None and marker_version > SCHEMA_VERSION:
            raise RebindStorageError(
                f"换绑 SQLite 迁移标记版本 {marker_version} 高于当前运行时 {SCHEMA_VERSION}"
            )
        if not force and self.migration_status().get("completed"):
            return {"migrated": False, "reason": "already_migrated", "version": SCHEMA_VERSION}
        mailboxes = self._legacy_mailboxes()
        tasks = self._legacy_tasks()
        now = _now()
        with self._transaction() as db:
            mailbox_count = 0
            task_count = 0
            for row in mailboxes:
                cursor = db.execute(
                    "INSERT OR IGNORE INTO mailboxes "
                    "(row_id,email,mailbox_url,status,task_id,revision,created_at,updated_at,payload) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        row["row_id"], row["email"], row["mailbox_url"], row["status"],
                        row["task_id"], row["revision"], row["created_at"], row["updated_at"],
                        _safe_json(row["payload"]),
                    ),
                )
                mailbox_count += int(cursor.rowcount > 0)
            for row in tasks:
                cursor = db.execute(
                    "INSERT OR IGNORE INTO tasks "
                    "(task_id,status,revision,created_at,updated_at,payload) VALUES(?,?,?,?,?,?)",
                    (
                        row["task_id"], row["status"], row["revision"], row["created_at"],
                        row["updated_at"], _safe_json(row["payload"]),
                    ),
                )
                task_count += int(cursor.rowcount > 0)
            summary = {
                "version": SCHEMA_VERSION,
                "complete": True,
                "completed_at": now,
                "mailboxes": mailbox_count,
                "tasks": task_count,
            }
            db.execute(
                "INSERT INTO storage_meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (REBIND_MIGRATION_KEY, _safe_json(summary)),
            )
        return {
            "migrated": True,
            "mailboxes": mailbox_count,
            "tasks": task_count,
            "version": SCHEMA_VERSION,
        }

    @staticmethod
    def _decode_payload(row: Mapping[str, Any] | None) -> dict[str, Any]:
        if not row:
            return {}
        # ``sqlite3.Row`` implements indexed access but not ``Mapping.get``.
        # Convert it once at this boundary so all callers receive an ordinary
        # mutable dictionary.
        if not isinstance(row, Mapping):
            try:
                row = dict(row)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return {}
        raw = row.get("payload")
        try:
            payload = json.loads(str(raw or "{}")) if not isinstance(raw, Mapping) else dict(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        result = _json_object(payload)
        for key in (
            "row_id", "email", "mailbox_url", "status", "task_id", "revision",
            "created_at", "updated_at", "task_id",
        ):
            if key in row:
                result[key] = row.get(key)
        if "created_at" in result:
            result["created_at"] = _coerce_timestamp(result.get("created_at"))
        if "updated_at" in result:
            result["updated_at"] = _coerce_timestamp(result.get("updated_at"))
        return result

    def _fetch_mailbox(self, db: sqlite3.Connection, row_id: str) -> dict[str, Any] | None:
        row = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (row_id,)).fetchone()
        return self._decode_payload(row) if row is not None else None

    def _fetch_task(self, db: sqlite3.Connection, task_id: str) -> dict[str, Any] | None:
        row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return self._decode_payload(row) if row is not None else None

    @staticmethod
    def _normalize_mailbox(email: Any, mailbox_url: Any) -> tuple[str, str]:
        email_text = str(email or "").strip().lower()
        url_text = str(mailbox_url or "").strip()
        parsed = parse_mailbox_line(f"{email_text}----{url_text}")
        if parsed is None or not _EMAIL_RE.fullmatch(email_text):
            raise ValueError("invalid rebind mailbox")
        return parsed

    def upsert_mailbox(
        self,
        *,
        email: str,
        mailbox_url: str,
        row_id: str | None = None,
        status: str = "available",
        task_id: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        email_text, url_text = self._normalize_mailbox(email, mailbox_url)
        normalized_id = str(row_id or _fingerprint(f"{email_text}|{url_text}")).strip().lower()
        if not normalized_id:
            raise ValueError("row_id is required")
        incoming_payload = _json_object(payload)
        incoming_payload.update({"email": email_text, "mailbox_url": url_text})
        now = _now()
        with self._transaction() as db:
            existing = self._fetch_mailbox(db, normalized_id)
            if existing is None:
                db.execute(
                    "INSERT INTO mailboxes "
                    "(row_id,email,mailbox_url,status,task_id,revision,created_at,updated_at,payload) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (normalized_id, email_text, url_text, str(status or "available"), str(task_id or ""), 0, now, now, _safe_json(incoming_payload)),
                )
            else:
                old_status = str(existing.get("status") or "available")
                old_task = str(existing.get("task_id") or "")
                # Importing a duplicate must never steal an active reservation.
                next_status = old_status if old_status in ACTIVE_REBIND_STATUSES else str(status or old_status)
                next_task = old_task if old_status in ACTIVE_REBIND_STATUSES else str(task_id or old_task)
                merged = _json_object(existing)
                merged.update(incoming_payload)
                db.execute(
                    "UPDATE mailboxes SET email=?,mailbox_url=?,status=?,task_id=?,revision=revision+1,updated_at=?,payload=? WHERE row_id=?",
                    (email_text, url_text, next_status, next_task, now, _safe_json(merged), normalized_id),
                )
            result = self._fetch_mailbox(db, normalized_id)
        assert result is not None
        return result

    def get_mailbox(self, row_id: str) -> dict[str, Any] | None:
        normalized = str(row_id or "").strip().lower()
        if not normalized:
            return None
        with self._connection() as db:
            return self._fetch_mailbox(db, normalized)

    def list_mailboxes(
        self,
        *,
        status: str | None = None,
        limit: int = 10_000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(100_000, int(limit)))
        offset = max(0, int(offset))
        with self._connection() as db:
            if status:
                rows = db.execute(
                    "SELECT * FROM mailboxes WHERE status=? ORDER BY rowid LIMIT ? OFFSET ?",
                    (str(status), limit, offset),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM mailboxes ORDER BY rowid LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [self._decode_payload(row) for row in rows]

    def reserve_mailbox(self, row_id: str, task_id: str) -> dict[str, Any] | None:
        normalized = str(row_id or "").strip().lower()
        owner = str(task_id or "").strip()
        if not normalized or not owner:
            return None
        now = _now()
        with self._transaction() as db:
            current = self._fetch_mailbox(db, normalized)
            if current is None:
                return None
            status = str(current.get("status") or "available")
            current_owner = str(current.get("task_id") or "")
            if status in ACTIVE_REBIND_STATUSES and current_owner != owner:
                return None
            if status not in {"available", "failed", "pending_rerun", "reserved"}:
                return None
            if status == "reserved" and current_owner == owner:
                return current
            payload = _json_object(current)
            payload.pop("failure", None)
            payload["error"] = ""
            db.execute(
                "UPDATE mailboxes SET status='reserved',task_id=?,revision=revision+1,updated_at=?,payload=? WHERE row_id=?",
                (owner, now, _safe_json(payload), normalized),
            )
            return self._fetch_mailbox(db, normalized)

    def release_mailbox(self, row_id: str, task_id: str, *, reusable: bool = True) -> bool:
        normalized = str(row_id or "").strip().lower()
        owner = str(task_id or "").strip()
        if not normalized or not owner:
            return False
        with self._transaction() as db:
            current = self._fetch_mailbox(db, normalized)
            if current is None or str(current.get("task_id") or "") != owner:
                return False
            payload = _json_object(current)
            payload.pop("failure", None)
            payload["error"] = ""
            db.execute(
                "UPDATE mailboxes SET status=?,task_id='',revision=revision+1,updated_at=?,payload=? WHERE row_id=? AND task_id=?",
                ("available" if reusable else "failed", _now(), _safe_json(payload), normalized, owner),
            )
            return True

    def update_mailbox(self, row_id: str, values: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any] | None:
        normalized = str(row_id or "").strip().lower()
        updates = _json_object(values)
        updates.update(kwargs)
        if not normalized:
            return None
        with self._transaction() as db:
            current = self._fetch_mailbox(db, normalized)
            if current is None:
                return None
            payload = _json_object(current)
            status = str(current.get("status") or "available")
            task_id = str(current.get("task_id") or "")
            if updates.get("status") is not None:
                status = str(updates["status"])
            if updates.get("task_id") is not None:
                task_id = str(updates["task_id"] or "")
            if "failure" in updates:
                normalized_failure = canonical_failure(updates.get("failure"))
                if normalized_failure is None:
                    payload.pop("failure", None)
                else:
                    payload["failure"] = normalized_failure
            for key, value in updates.items():
                if key in {"status", "task_id", "failure"}:
                    continue
                if value is not None:
                    payload[str(key)] = copy.deepcopy(value)
            payload["error"] = str(updates.get("error") or payload.get("error") or "")[:500]
            db.execute(
                "UPDATE mailboxes SET status=?,task_id=?,revision=revision+1,updated_at=?,payload=? WHERE row_id=?",
                (status, task_id, _now(), _safe_json(payload), normalized),
            )
            return self._fetch_mailbox(db, normalized)

    def set_mailbox_status(self, row_ids: Sequence[str], status: str) -> int:
        normalized_status = str(status or "").strip().lower()
        if normalized_status not in {"available", "unavailable"}:
            raise ValueError("invalid rebind mailbox status")
        ids = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        if not ids:
            return 0
        with self._transaction() as db:
            placeholders = ",".join("?" for _ in ids)
            active = db.execute(
                f"SELECT row_id FROM mailboxes WHERE row_id IN ({placeholders}) AND status IN ('reserved','running')",
                tuple(ids),
            ).fetchall()
            if active:
                raise RebindStorageError("运行中的换绑邮箱不能修改状态")
            cursor = db.execute(
                f"UPDATE mailboxes SET status=?,revision=revision+1,updated_at=? WHERE row_id IN ({placeholders})",
                (normalized_status, _now(), *ids),
            )
            return max(0, int(cursor.rowcount))

    def delete_mailboxes(self, row_ids: Sequence[str]) -> int:
        ids = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        if not ids:
            return 0
        with self._transaction() as db:
            placeholders = ",".join("?" for _ in ids)
            active = db.execute(
                f"SELECT row_id FROM mailboxes WHERE row_id IN ({placeholders}) AND status IN ('reserved','running')",
                tuple(ids),
            ).fetchall()
            if active:
                raise RebindStorageError("运行中的换绑邮箱不能删除")
            cursor = db.execute(
                f"DELETE FROM mailboxes WHERE row_id IN ({placeholders})",
                tuple(ids),
            )
            return max(0, int(cursor.rowcount))

    def public_mailboxes(self) -> list[dict[str, Any]]:
        rows = self.list_mailboxes()
        result: list[dict[str, Any]] = []
        for row in rows:
            failure = canonical_failure(row.get("failure") if isinstance(row.get("failure"), Mapping) else None)
            email_masked = mask_email(row.get("email"))
            result.append({
                "row_id": str(row.get("row_id") or ""),
                "line_no": int(row.get("line_no") or 0),
                # Keep the existing UI contract (email is displayable); the
                # private pickup URL itself is never included in this shape.
                "email": email_masked,
                "email_masked": email_masked,
                "subject_ref_fingerprint": _fingerprint(row.get("email")),
                "status": str(row.get("status") or "available"),
                "task_id": str(row.get("task_id") or ""),
                "error": sanitize_failure_text(
                    row.get("error") or (failure or {}).get("public_message") or "", 300
                ),
                "failure": failure,
            })
        return result

    def create_task(self, task_id: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        normalized = str(task_id or "").strip()
        if not normalized:
            raise ValueError("task_id is required")
        task = _json_object(payload)
        status = str(task.get("status") or "queued")
        now = _now()
        task.setdefault("task_id", normalized)
        task["created_at"] = _coerce_timestamp(task.get("created_at"), now)
        task["updated_at"] = _coerce_timestamp(task.get("updated_at"), task["created_at"])
        with self._transaction() as db:
            try:
                db.execute(
                    "INSERT INTO tasks(task_id,status,revision,created_at,updated_at,payload) VALUES(?,?,?,?,?,?)",
                    (normalized, status, 0, task["created_at"], task["updated_at"], _safe_json(task)),
                )
            except sqlite3.IntegrityError as exc:
                raise RebindStorageError("换绑任务已存在") from exc
            result = self._fetch_task(db, normalized)
        assert result is not None
        return result

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        normalized = str(task_id or "").strip()
        if not normalized:
            return None
        with self._connection() as db:
            return self._fetch_task(db, normalized)

    def list_tasks(
        self,
        *,
        status: str | None = None,
        limit: int = 10_000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(100_000, int(limit)))
        offset = max(0, int(offset))
        with self._connection() as db:
            if status:
                rows = db.execute(
                    "SELECT * FROM tasks WHERE status=? ORDER BY created_at DESC,task_id LIMIT ? OFFSET ?",
                    (str(status), limit, offset),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM tasks ORDER BY created_at DESC,task_id LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [self._decode_payload(row) for row in rows]

    def save_task(
        self,
        task_id: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        normalized = str(task_id or "").strip()
        if not normalized:
            raise ValueError("task_id is required")
        incoming = _json_object(payload)
        now = _now()
        with self._transaction() as db:
            current = self._fetch_task(db, normalized)
            if current is None:
                if expected_revision not in (None, -1):
                    raise RebindRevisionConflict(normalized, expected_revision, None)
                incoming.setdefault("task_id", normalized)
                incoming["created_at"] = _coerce_timestamp(incoming.get("created_at"), now)
                incoming["updated_at"] = now
                status = str(incoming.get("status") or "queued")
                db.execute(
                    "INSERT INTO tasks(task_id,status,revision,created_at,updated_at,payload) VALUES(?,?,?,?,?,?)",
                    (normalized, status, 0, incoming["created_at"], now, _safe_json(incoming)),
                )
                result = self._fetch_task(db, normalized)
                assert result is not None
                return result
            actual = int(current.get("revision") or 0)
            if expected_revision is not None and int(expected_revision) != actual:
                raise RebindRevisionConflict(normalized, expected_revision, actual)
            current_status = str(current.get("status") or "queued")
            next_status = str(incoming.get("status") or current_status)
            if current_status in TERMINAL_REBIND_STATUSES and next_status != current_status:
                raise RebindRevisionConflict(normalized, expected_revision, actual)
            merged = _json_object(current)
            merged.update(incoming)
            merged["task_id"] = normalized
            merged["created_at"] = _coerce_timestamp(merged.get("created_at"), _coerce_timestamp(current.get("created_at"), now))
            merged["updated_at"] = now
            cursor = db.execute(
                "UPDATE tasks SET status=?,revision=revision+1,updated_at=?,payload=? WHERE task_id=? AND revision=?",
                (next_status, now, _safe_json(merged), normalized, actual),
            )
            if cursor.rowcount <= 0:
                raise RebindRevisionConflict(normalized, expected_revision, actual)
            result = self._fetch_task(db, normalized)
        assert result is not None
        return result

    def delete_tasks(self, task_ids: Sequence[str], *, allow_active: bool = False) -> int:
        """Delete terminal tasks, or explicitly purge an internal rollback.

        Public maintenance calls keep the historical active-task guard.  The
        service uses ``allow_active=True`` only after an in-memory task was
        rolled back before it could run; this prevents a persisted queued row
        from becoming a phantom task after restart without weakening the API
        safety check.
        """
        ids = {str(value or "").strip() for value in task_ids if str(value or "").strip()}
        if not ids:
            return 0
        with self._transaction() as db:
            placeholders = ",".join("?" for _ in ids)
            if not allow_active:
                active = db.execute(
                    f"SELECT task_id FROM tasks WHERE task_id IN ({placeholders}) AND status IN ('queued','running')",
                    tuple(ids),
                ).fetchall()
                if active:
                    raise RebindStorageError("运行中的换绑任务不能删除")
            cursor = db.execute(f"DELETE FROM tasks WHERE task_id IN ({placeholders})", tuple(ids))
            return max(0, int(cursor.rowcount))

    def health(self) -> dict[str, Any]:
        try:
            with self._connection() as db:
                journal = str(db.execute("PRAGMA journal_mode").fetchone()[0]).lower()
                busy = int(db.execute("PRAGMA busy_timeout").fetchone()[0])
                integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0]).lower()
                mailbox_count = int(db.execute("SELECT COUNT(*) FROM mailboxes").fetchone()[0])
                task_count = int(db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0])
            return {
                "ok": integrity == "ok",
                "path": str(self.path),
                "journal_mode": journal,
                "busy_timeout_ms": busy,
                "integrity": integrity,
                "schema_version": int(self._meta("schema_version") or 0),
                "migration": self.migration_status(),
                "mailboxes": mailbox_count,
                "tasks": task_count,
            }
        except Exception as exc:
            return {"ok": False, "error_type": type(exc).__name__}


__all__ = [
    "ACTIVE_REBIND_STATUSES",
    "REBIND_MIGRATION_KEY",
    "RebindRevisionConflict",
    "RebindSQLiteStore",
    "RebindStorageError",
    "TERMINAL_REBIND_STATUSES",
]
