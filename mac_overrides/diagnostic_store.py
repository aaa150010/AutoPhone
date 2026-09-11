"""Local append-only diagnostic index used by the Log Center.

The store deliberately accepts only a small, redacted field set. It is a
diagnostic index, not a second task/result database, so deleting it never
touches account, mailbox, proxy, or registration state. Search/export and
root-cause selection helpers live in ``diagnostic_export`` and
``diagnostic_summary`` and are mixed into ``DiagnosticStore`` below.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

try:
    from .diagnostic_contract import DiagnosticEvent, SCHEMA_VERSION, utc_now
    from .diagnostic_summary import (
        DiagnosticSummaryMixin,
        _FAILURE_OUTCOMES,
        _PARTIAL_OUTCOMES,
        _SUCCESS_OUTCOMES,
        _masked_subject,
        _is_business_failure_event,
        _is_cleanup_event,
        _is_cleanup_node,
        _is_cleanup_root,
        _merge_missing_failure_fields,
        _parse_failure,
        _retryable_value,
        _safe_failure_mapping,
        _safe_id,
        _safe_message,
        _safe_occurred_at,
        _safe_text,
        _safe_transport_mapping,
        _status_for_outcome,
    )
    from .diagnostic_export import DiagnosticExportMixin
except ImportError:  # pragma: no cover
    from diagnostic_contract import DiagnosticEvent, SCHEMA_VERSION, utc_now  # type: ignore[no-redef]
    from diagnostic_summary import (  # type: ignore[no-redef]
        DiagnosticSummaryMixin,
        _FAILURE_OUTCOMES,
        _PARTIAL_OUTCOMES,
        _SUCCESS_OUTCOMES,
        _masked_subject,
        _is_business_failure_event,
        _is_cleanup_event,
        _is_cleanup_node,
        _is_cleanup_root,
        _merge_missing_failure_fields,
        _parse_failure,
        _retryable_value,
        _safe_failure_mapping,
        _safe_id,
        _safe_message,
        _safe_occurred_at,
        _safe_text,
        _safe_transport_mapping,
        _status_for_outcome,
    )
    from diagnostic_export import DiagnosticExportMixin  # type: ignore[no-redef]


_INCIDENT_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
# Marker carried by the first retained event when every predecessor was
# removed by retention. It preserves an explicit incomplete-history signal
# without adding a schema column or fabricating a real event hash.
_MISSING_HISTORY_HASH = "history_pruned"



try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('diagnostic_store', where, exc)


class DiagnosticStore(DiagnosticExportMixin, DiagnosticSummaryMixin):
    """Thread-safe SQLite store for incidents and append-only events."""

    def __init__(self, data_dir: str | Path, *, event_retention_days: int = 30, incident_retention_days: int = 180) -> None:
        self.root = Path(data_dir).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "diagnostics.sqlite3"
        self.key_path = self.root / "diagnostic.key"
        self.event_retention_days = max(1, int(event_retention_days))
        self.incident_retention_days = max(self.event_retention_days, int(incident_retention_days))
        self._lock = threading.RLock()
        # Keep a process-local record even when SQLite itself is unavailable;
        # the health endpoint can then report dropped diagnostic writes instead
        # of presenting a misleading all-clear status.
        self._write_failures = 0
        self._audit_write_failures = 0
        self._last_write_failure = ""
        self._last_write_failure_at = ""
        self._key_load_failure = ""
        self._key_load_attempts = 0
        # One lock-serialized handle for the process. Every ``_connection``
        # user holds ``self._lock`` first, so concurrent use is impossible and
        # the per-record connect/close cycle (the dominant record cost) is
        # paid once instead of per append.
        self._conn: sqlite3.Connection | None = None
        # Short-lived cache for the three health() COUNT(*) aggregates; the
        # dashboard polls health every few seconds and the counts tolerate a
        # one-second lag. Write-failure counters stay read live.
        self._health_counts_cache: tuple[float, int, int, int] | None = None
        self._key = self._load_key()
        self._initialize()

    def _load_key(self) -> bytes:
        """Load the HMAC key, never overwriting an unreadable existing file.

        Regenerating a key over an existing one would invalidate every stored
        fingerprint and break all historical hash chains. A fresh key is only
        written when no file exists at all; read/load failures keep the file
        untouched and fall back to a process-local key surfaced via ``health()``.
        """
        try:
            value = self.key_path.read_bytes()
        except FileNotFoundError:
            value = secrets.token_bytes(32)
            try:
                self.key_path.write_bytes(value)
                os.chmod(self.key_path, 0o600)
            except OSError as exc:
                # A missing key file that cannot be created must still tolerate
                # startup; fingerprints remain valid for this process only.
                self._key_load_failure = _safe_id(type(exc).__name__, 64) or "key_create_failed"
                self._key_load_attempts += 1
            return value
        except OSError as exc:
            # Never overwrite the existing key file when reading failed; use a
            # process-local key so the on-disk chain stays intact.
            self._key_load_failure = _safe_id(type(exc).__name__, 64) or "key_read_failed"
            self._key_load_attempts += 1
            self.note_write_failure("key_load", exc)
            return secrets.token_bytes(32)
        if len(value) < 32:
            # Keep the short key file as-is; replacing it would orphan both
            # prior fingerprints and event hashes. Expose the condition via
            # ``health()`` and run with a process-local key this session.
            self._key_load_failure = "key_too_short"
            self._key_load_attempts += 1
            return secrets.token_bytes(32)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return value

    @contextmanager
    def _connection(self):
        connection = self._ensure_connection()
        try:
            yield connection
        except sqlite3.Error:
            # A broken handle (disk error, corrupted page) must not poison
            # every later operation; drop it so the next caller reconnects.
            self._drop_connection()
            raise

    def _ensure_connection(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        # The cached handle is shared across Flask request threads and writer
        # threads; every access is serialized by ``self._lock``, so the
        # connection must opt out of sqlite3's same-thread affinity check.
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        # WAL is a persistent database property and synchronous a connection
        # property; both are cheap to (re)assert on every cold connect.
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
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

    def _initialize(self) -> None:
        with self._lock, self._connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS diagnostic_incidents (
                    incident_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    workflow TEXT NOT NULL,
                    driver TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT '',
                    batch_id TEXT NOT NULL DEFAULT '',
                    task_id TEXT NOT NULL DEFAULT '',
                    subject_kind TEXT NOT NULL DEFAULT '',
                    subject_ref TEXT NOT NULL DEFAULT '',
                    subject_display TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    outcome TEXT NOT NULL DEFAULT 'error',
                    first_node_code TEXT NOT NULL DEFAULT '',
                    first_node_label TEXT NOT NULL DEFAULT '',
                    first_error_code TEXT NOT NULL DEFAULT '',
                    retryable INTEGER NOT NULL DEFAULT 0,
                    failure_json TEXT NOT NULL DEFAULT '{}',
                    event_count INTEGER NOT NULL DEFAULT 0,
                    integrity_status TEXT NOT NULL DEFAULT 'unverified'
                );
                CREATE TABLE IF NOT EXISTS diagnostic_events (
                    event_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    incident_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    workflow TEXT NOT NULL,
                    driver TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT '',
                    batch_id TEXT NOT NULL DEFAULT '',
                    task_id TEXT NOT NULL DEFAULT '',
                    subject_kind TEXT NOT NULL DEFAULT '',
                    subject_ref TEXT NOT NULL DEFAULT '',
                    subject_display TEXT NOT NULL DEFAULT '',
                    stage_group TEXT NOT NULL DEFAULT '',
                    node_code TEXT NOT NULL DEFAULT '',
                    node_label TEXT NOT NULL DEFAULT '',
                    sequence INTEGER NOT NULL DEFAULT 0,
                    attempt INTEGER NOT NULL DEFAULT 0,
                    attempt_group TEXT NOT NULL DEFAULT '',
                    outcome TEXT NOT NULL DEFAULT 'info',
                    parent_event_id TEXT NOT NULL DEFAULT '',
                    root_cause_event_id TEXT NOT NULL DEFAULT '',
                    elapsed_ms INTEGER,
                    failure_json TEXT NOT NULL DEFAULT '{}',
                    transport_json TEXT NOT NULL DEFAULT '{}',
                    message TEXT NOT NULL DEFAULT '',
                    redaction_applied INTEGER NOT NULL DEFAULT 1,
                    previous_event_hash TEXT NOT NULL DEFAULT '',
                    event_hash TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (incident_id) REFERENCES diagnostic_incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS diagnostic_aliases (
                    alias_type TEXT NOT NULL,
                    alias_ref TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (alias_type, alias_ref, incident_id)
                );
                CREATE TABLE IF NOT EXISTS diagnostic_tasks (
                    task_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT '',
                    batch_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (task_id, incident_id),
                    FOREIGN KEY (incident_id) REFERENCES diagnostic_incidents(incident_id)
                );
                CREATE TABLE IF NOT EXISTS diagnostic_access_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    incident_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS diagnostic_incident_ids (
                    incident_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    deleted_at TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_diag_events_incident ON diagnostic_events(incident_id, occurred_at);
                CREATE INDEX IF NOT EXISTS idx_diag_events_task ON diagnostic_events(task_id, occurred_at);
                CREATE INDEX IF NOT EXISTS idx_diag_events_batch ON diagnostic_events(batch_id, occurred_at);
                CREATE INDEX IF NOT EXISTS idx_diag_events_node ON diagnostic_events(node_code, occurred_at);
                CREATE INDEX IF NOT EXISTS idx_diag_incidents_updated ON diagnostic_incidents(updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_diag_incidents_task ON diagnostic_incidents(task_id, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_diag_events_received ON diagnostic_events(received_at);
                CREATE INDEX IF NOT EXISTS idx_diag_aliases_ref ON diagnostic_aliases(alias_ref, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_diag_tasks_task ON diagnostic_tasks(task_id, updated_at DESC);
                """
            )
            # Existing installations predate schema_version and the tombstone
            # table. Migrate in place without touching business data.
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(diagnostic_events)").fetchall()}
            if "schema_version" not in columns:
                db.execute("ALTER TABLE diagnostic_events ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1")
            db.execute(
                "INSERT OR IGNORE INTO diagnostic_incident_ids(incident_id,created_at,deleted_at) "
                "SELECT incident_id,created_at,'' FROM diagnostic_incidents"
            )
        # Older releases updated an incident's first-failure columns whenever
        # a later event arrived. Rebuild those derived columns once at startup
        # from the append-only event chain so existing incidents become
        # consistent without rewriting any event or business data.
        self.rebuild_incident_summaries()
        self.prune()

    def rebuild_incident_summaries(self) -> dict[str, int]:
        """Idempotently restore first-failure summaries from verified events.

        Event rows are immutable and their hash chain remains the source of
        truth. Only the denormalized incident summary and event count are
        repaired. Cleanup/recovery nodes are deliberately excluded from root
        cause selection; if an incident has no business failure we leave its
        existing summary untouched rather than inventing a cause.
        """
        repaired = 0
        skipped_integrity = 0
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            incidents = db.execute("SELECT * FROM diagnostic_incidents ORDER BY rowid ASC").fetchall()
            for incident in incidents:
                incident_id = str(incident["incident_id"] or "")
                events = db.execute(
                    "SELECT * FROM diagnostic_events WHERE incident_id=? ORDER BY rowid ASC",
                    (incident_id,),
                ).fetchall()
                # Reuse the already-fetched rows for the chain verification
                # instead of re-querying and re-parsing every event a second
                # time inside ``verify_incident``.
                integrity = self._verify_event_rows(db, incident_id, events)
                # Retention deliberately leaves a verifiable suffix marked
                # unverified because its original chain anchor is gone. It is
                # incomplete history, not evidence of tampering.
                if integrity == "unverified":
                    # The suffix is still safe to count even though its root
                    # cause cannot be trusted. Keep all first_* columns and
                    # the explicit unverified marker unchanged.
                    expected_count = len(events)
                    if int(incident["event_count"] or 0) != expected_count:
                        db.execute(
                            "UPDATE diagnostic_incidents SET event_count=? WHERE incident_id=?",
                            (expected_count, incident_id),
                        )
                        repaired += 1
                    skipped_integrity += 1
                    continue
                if integrity == "failed":
                    skipped_integrity += 1
                    if str(incident["integrity_status"] or "") != "failed":
                        db.execute(
                            "UPDATE diagnostic_incidents SET integrity_status=? WHERE incident_id=?",
                            ("failed", incident_id),
                        )
                    continue
                summary = self._startup_failure_summary(events)
                if summary is None:
                    # Keep event_count accurate even when this incident only
                    # contains cleanup or informational events. A cleanup
                    # node selected by an older release is not a valid root;
                    # clear that stale denormalized summary during migration.
                    expected_count = len(events)
                    clear_cleanup_root = _is_cleanup_root(incident, events)
                    if clear_cleanup_root or int(incident["event_count"] or 0) != expected_count or str(incident["integrity_status"] or "") != "verified":
                        db.execute(
                            "UPDATE diagnostic_incidents SET first_node_code=?, first_node_label=?, first_error_code=?, retryable=?, failure_json=?, event_count=?, integrity_status=? WHERE incident_id=?",
                            (
                                "" if clear_cleanup_root else incident["first_node_code"],
                                "" if clear_cleanup_root else incident["first_node_label"],
                                "" if clear_cleanup_root else incident["first_error_code"],
                                0 if clear_cleanup_root else int(incident["retryable"] or 0),
                                "{}" if clear_cleanup_root else str(incident["failure_json"] or "{}"),
                                expected_count,
                                "verified",
                                incident_id,
                            ),
                        )
                        repaired += 1
                    continue

                first_node_code, first_node_label, first_error_code, retryable, merged_failure = summary

                expected_count = len(events)
                changed = any((
                    str(incident["first_node_code"] or "") != first_node_code,
                    str(incident["first_node_label"] or "") != first_node_label,
                    str(incident["first_error_code"] or "") != first_error_code,
                    bool(incident["retryable"]) != retryable,
                    _parse_failure(incident["failure_json"]) != merged_failure,
                    int(incident["event_count"] or 0) != expected_count,
                    str(incident["integrity_status"] or "") != "verified",
                ))
                if changed:
                    db.execute(
                        "UPDATE diagnostic_incidents SET first_node_code=?, first_node_label=?, first_error_code=?, retryable=?, failure_json=?, event_count=?, integrity_status=? WHERE incident_id=?",
                        (
                            first_node_code,
                            first_node_label,
                            first_error_code,
                            int(retryable),
                            json.dumps(merged_failure, ensure_ascii=False, sort_keys=True),
                            expected_count,
                            "verified",
                            incident_id,
                        ),
                    )
                    repaired += 1
            if repaired or skipped_integrity:
                db.execute(
                    "INSERT INTO diagnostic_access_audit(action,incident_count,created_at,detail) VALUES(?,?,?,?)",
                    (
                        "rebuild_incident_summaries",
                        repaired + skipped_integrity,
                        utc_now(),
                        f"repaired={repaired};integrity_skipped={skipped_integrity}",
                    ),
                )
            db.execute("COMMIT")
        return {"repaired": repaired, "integrity_skipped": skipped_integrity}

    def prune(self, *, now: str | None = None) -> dict[str, int]:
        """Apply retention to diagnostics only; business data is untouched."""
        reference = now or utc_now()
        try:
            current = datetime.fromisoformat(str(reference).replace("Z", "+00:00"))
        except (TypeError, ValueError, OverflowError):
            current = datetime.now(timezone.utc)
        event_cutoff = (current - timedelta(days=self.event_retention_days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        incident_cutoff = (current - timedelta(days=self.incident_retention_days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            event_rows = db.execute("SELECT event_id, incident_id FROM diagnostic_events WHERE received_at<?", (event_cutoff,)).fetchall()
            event_count = int(db.execute("DELETE FROM diagnostic_events WHERE received_at<?", (event_cutoff,)).rowcount or 0)
            touched_incidents = {str(row[1]) for row in event_rows}
            if touched_incidents:
                # One grouped COUNT replaces the per-incident round trip;
                # idx_diag_events_incident covers the GROUP BY scan.
                placeholders = ",".join("?" for _ in touched_incidents)
                remaining = {
                    str(row[0]): int(row[1])
                    for row in db.execute(
                        f"SELECT incident_id, COUNT(*) FROM diagnostic_events WHERE incident_id IN ({placeholders}) GROUP BY incident_id",
                        tuple(touched_incidents),
                    ).fetchall()
                }
                db.executemany(
                    "UPDATE diagnostic_incidents SET event_count=?, integrity_status=? WHERE incident_id=?",
                    [
                        (remaining.get(incident_id, 0), "unverified" if event_count else "verified", incident_id)
                        for incident_id in touched_incidents
                    ],
                )
            old_incidents = db.execute("SELECT incident_id FROM diagnostic_incidents WHERE updated_at<?", (incident_cutoff,)).fetchall()
            old_ids = [str(row[0]) for row in old_incidents]
            if old_ids:
                placeholders = ",".join("?" for _ in old_ids)
                for table in ("diagnostic_aliases", "diagnostic_tasks", "diagnostic_events", "diagnostic_incidents"):
                    db.execute(f"DELETE FROM {table} WHERE incident_id IN ({placeholders})", tuple(old_ids))
                db.executemany("UPDATE diagnostic_incident_ids SET deleted_at=? WHERE incident_id=?", [(reference, value) for value in old_ids])
            if event_count or old_ids:
                db.execute(
                    "INSERT INTO diagnostic_access_audit(action,incident_count,created_at,detail) VALUES(?,?,?,?)",
                    ("prune", len(old_ids), reference, f"events={event_count}"),
                )
            db.execute("COMMIT")
        return {"events": event_count, "incidents": len(old_ids)}

    def fingerprint(self, value: Any) -> str:
        normalized = _safe_text(value, 500).strip().lower()
        if not normalized:
            return ""
        return hmac.new(self._key, normalized.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    @staticmethod
    def _incident_id(now: str) -> str:
        date = now[:10].replace("-", "")
        suffix = "".join(secrets.choice(_INCIDENT_ALPHABET) for _ in range(8))
        return f"LOG-{date}-{suffix}"

    def _next_incident_id(self, db: sqlite3.Connection, now: str) -> str:
        # Keep deleted IDs in diagnostic_incident_ids forever. The loop also
        # makes deterministic test/fault-injected randomness safe.
        for _ in range(32):
            candidate = self._incident_id(now)
            exists = db.execute(
                "SELECT 1 FROM diagnostic_incident_ids WHERE incident_id=?",
                (candidate,),
            ).fetchone()
            if exists is None:
                db.execute(
                    "INSERT INTO diagnostic_incident_ids(incident_id,created_at,deleted_at) VALUES(?,?,?)",
                    (candidate, now, ""),
                )
                return candidate
        raise RuntimeError("diagnostic incident id allocation exhausted")

    def _hash_event(self, payload: Mapping[str, Any], previous: str) -> str:
        body = json.dumps({"previous": previous, **payload}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hmac.new(self._key, body.encode("utf-8"), hashlib.sha256).hexdigest()

    def _incident_for(
        self,
        db: sqlite3.Connection,
        *,
        task_id: str,
        subject_ref: str,
        incident_id: str,
        run_id: str,
        batch_id: str,
        chain: str,
        workflow: str,
        driver: str,
        now: str,
    ) -> str:
        if incident_id:
            row = db.execute("SELECT incident_id FROM diagnostic_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if row:
                return incident_id
            # The async writer pre-allocates ids before the first event is
            # persisted. A pre-registered id (tombstone row without an
            # incident row yet) is reserved for this process and safe to use.
            reserved = db.execute(
                "SELECT deleted_at FROM diagnostic_incident_ids WHERE incident_id=?",
                (incident_id,),
            ).fetchone()
            if reserved is not None and not str(reserved[0] or ""):
                return incident_id
        if task_id:
            # Task IDs are generated by the current runtimes, but old and
            # injected integrations are allowed to choose their own IDs. Do
            # not merge a reused ID across registration/rebind workflows or
            # drivers; the diagnostic timeline must remain scoped to one
            # execution contract.
            scope = "chain=? AND workflow=? AND driver=?"
            scope_params: tuple[Any, ...] = (chain, workflow, driver)
            if run_id or batch_id:
                row = db.execute(
                    "SELECT incident_id FROM diagnostic_incidents WHERE task_id=? AND "
                    f"{scope} AND ((run_id=? AND ?!='') OR (batch_id=? AND ?!='')) "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (task_id, *scope_params, run_id, run_id, batch_id, batch_id),
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT incident_id FROM diagnostic_incidents WHERE task_id=? AND "
                    f"{scope} ORDER BY updated_at DESC LIMIT 1",
                    (task_id, *scope_params),
                ).fetchone()
            if row:
                return str(row[0])
            # Cleanup/recovery is an associated lifecycle phase, not a new
            # business execution. It may be emitted after the business event
            # (or, during startup failure handling, before it). Search only
            # the same chain/driver and, when present, the same run/batch;
            # this keeps registration and rebind timelines isolated even if a
            # caller accidentally reuses a task ID.
            fallback_where = "task_id=? AND chain=? AND driver=?"
            fallback_params: list[Any] = [task_id, chain, driver]
            if run_id or batch_id:
                fallback_where += " AND ((run_id=? AND ?!='') OR (batch_id=? AND ?!=''))"
                fallback_params.extend((run_id, run_id, batch_id, batch_id))
            candidates = db.execute(
                f"SELECT incident_id,workflow FROM diagnostic_incidents WHERE {fallback_where} "
                "ORDER BY updated_at DESC LIMIT 32",
                tuple(fallback_params),
            ).fetchall()
            current_is_cleanup = _is_cleanup_node(workflow)
            for candidate in candidates:
                # If the incoming event is cleanup, it belongs to the latest
                # same-task execution. For a business event, only a prior
                # cleanup provisional incident may be adopted.
                if current_is_cleanup or _is_cleanup_node(candidate[1]):
                    return str(candidate[0])
        # Do not merge unrelated tasks merely because they share an email or
        # account fingerprint. Email search is an alias lookup, not grouping.
        return self._next_incident_id(db, now)

    def _record(self, fields: Mapping[str, Any]) -> str:
        """Append one redacted event and return its incident ID.

        Events with a task ID share an incident so retries can be inspected as
        one record. Non-task errors receive their own stable incident.
        """
        now = utc_now()
        level = _safe_text(fields.get("level") or fields.get("outcome") or "info", 24).lower()
        outcome = _safe_text(fields.get("outcome") or ("error" if level in {"error", "danger"} else level), 32).lower()
        node_code = _safe_id(fields.get("node_code") or fields.get("stage"), 160)
        task_id = _safe_id(fields.get("task_id"), 180)
        batch_id = _safe_id(fields.get("batch_id"), 180)
        run_id = _safe_id(fields.get("run_id"), 180)
        supplied_fingerprint = _safe_text(fields.get("subject_ref_fingerprint"), 80).lower()
        if not re.fullmatch(r"[0-9a-f]{32}", supplied_fingerprint):
            supplied_fingerprint = ""
        subject_ref = supplied_fingerprint or self.fingerprint(fields.get("subject_ref") or fields.get("email") or fields.get("account"))
        subject_kind = _safe_id(fields.get("subject_kind") or ("email" if subject_ref else ""), 32)
        subject_display = _masked_subject(
            fields.get("subject_display") or fields.get("email_masked") or fields.get("email") or fields.get("account_masked"),
            subject_kind,
        )
        # Information rows are retained only when they belong to a known task;
        # this keeps the diagnostic index useful without becoming a duplicate
        # of the high-volume GUI log.
        is_error = outcome in {"error", "failed", "failure", "stopped"} or level in {"error", "danger"}
        if not is_error and not task_id:
            return ""
        message = _safe_message(fields.get("message"), 800)
        failure = _safe_failure_mapping(fields.get("failure"))
        transport = _safe_transport_mapping(fields.get("transport"))
        incident_hint = _safe_id(fields.get("incident_id"), 64).upper()
        if not re.fullmatch(r"LOG-\d{8}-[A-Z0-9]{8}", incident_hint):
            incident_hint = ""
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            # Event IDs are globally idempotent. Check before allocating an
            # incident so a retried write cannot create a phantom archive.
            supplied_event_id = _safe_id(fields.get("event_id"), 80)
            if supplied_event_id:
                duplicate = db.execute(
                    "SELECT incident_id FROM diagnostic_events WHERE event_id=?",
                    (supplied_event_id,),
                ).fetchone()
                if duplicate:
                    db.execute("COMMIT")
                    return str(duplicate[0])
            incident_id = self._incident_for(
                db,
                task_id=task_id,
                subject_ref=subject_ref,
                incident_id=incident_hint,
                run_id=run_id,
                batch_id=batch_id,
                chain=_safe_id(fields.get("chain") or "unknown", 48),
                workflow=_safe_id(fields.get("workflow") or "run", 64),
                driver=_safe_id(fields.get("driver") or "unknown", 48),
                now=now,
            )
            existing = db.execute("SELECT * FROM diagnostic_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if existing is None:
                db.execute(
                    "INSERT INTO diagnostic_incidents (incident_id,created_at,updated_at,chain,workflow,driver,run_id,batch_id,task_id,subject_kind,subject_ref,subject_display,status,outcome,integrity_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        incident_id, now, now, _safe_id(fields.get("chain") or "unknown", 48),
                        _safe_id(fields.get("workflow") or "run", 64), _safe_id(fields.get("driver") or "unknown", 48),
                        run_id, batch_id, task_id, subject_kind,
                        subject_ref, subject_display,
                        _status_for_outcome(outcome), outcome, "verified",
                    ),
                )
            elif subject_ref and not str(existing["subject_ref"] or ""):
                # A task's early informational events may not carry an account
                # reference. Enrich that same incident when its terminal
                # failure arrives, without ever persisting the raw value.
                db.execute(
                    "UPDATE diagnostic_incidents SET subject_kind=?, subject_ref=?, subject_display=? WHERE incident_id=?",
                    (subject_kind, subject_ref, subject_display, incident_id),
                )
            if task_id:
                db.execute(
                    "INSERT INTO diagnostic_tasks(task_id,incident_id,run_id,batch_id,created_at,updated_at) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(task_id,incident_id) DO UPDATE SET run_id=excluded.run_id,batch_id=excluded.batch_id,updated_at=excluded.updated_at",
                    (task_id, incident_id, run_id, batch_id, now, now),
                )
            previous_row = db.execute(
                "SELECT event_hash FROM diagnostic_events WHERE incident_id=? ORDER BY rowid DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            previous_hash = str(previous_row[0]) if previous_row else ""
            history_fully_pruned = False
            # Retention can remove every earlier event. Keep that missing
            # prefix visible when the next event is appended, rather than
            # making the truncated incident appear fully verified.
            if (
                previous_row is None
                and existing is not None
                and str(existing["integrity_status"] or "") == "unverified"
            ):
                previous_hash = _MISSING_HISTORY_HASH
                history_fully_pruned = True
            event_id = supplied_event_id or uuid.uuid4().hex
            if db.execute("SELECT 1 FROM diagnostic_events WHERE event_id=?", (event_id,)).fetchone():
                db.execute("COMMIT")
                return incident_id
            try:
                sequence = int(fields.get("sequence") or 0)
            except (TypeError, ValueError):
                sequence = 0
            try:
                attempt = int(fields.get("attempt") or 0)
            except (TypeError, ValueError):
                attempt = 0
            try:
                elapsed_ms = int(fields.get("duration_ms") or fields.get("elapsed_ms"))
            except (TypeError, ValueError):
                elapsed_ms = None
            event_payload = {
                "schema_version": SCHEMA_VERSION,
                "event_id": event_id,
                "incident_id": incident_id,
                "occurred_at": _safe_occurred_at(fields.get("occurred_at") or now, now),
                "received_at": now,
                "chain": _safe_id(fields.get("chain") or "unknown", 48),
                "workflow": _safe_id(fields.get("workflow") or "run", 64),
                "driver": _safe_id(fields.get("driver") or "unknown", 48),
                "run_id": run_id,
                "batch_id": batch_id,
                "task_id": task_id,
                "subject_kind": subject_kind,
                "subject_ref": subject_ref,
                "subject_display": subject_display,
                "stage_group": _safe_id(fields.get("stage_group"), 64),
                "node_code": node_code,
                "node_label": _safe_message(fields.get("node_label"), 160),
                "sequence": max(0, sequence),
                "attempt": max(0, attempt),
                "attempt_group": _safe_id(fields.get("attempt_group"), 120),
                "outcome": outcome,
                "parent_event_id": _safe_id(fields.get("parent_event_id"), 80),
                "root_cause_event_id": _safe_id(fields.get("root_cause_event_id"), 80),
                "elapsed_ms": elapsed_ms,
                "failure": failure,
                "transport": transport,
                "message": message,
                "redaction_applied": True,
            }
            event_hash = self._hash_event(event_payload, previous_hash)
            db.execute(
                "INSERT INTO diagnostic_events (event_id,schema_version,incident_id,occurred_at,received_at,chain,workflow,driver,run_id,batch_id,task_id,subject_kind,subject_ref,subject_display,stage_group,node_code,node_label,sequence,attempt,attempt_group,outcome,parent_event_id,root_cause_event_id,elapsed_ms,failure_json,transport_json,message,redaction_applied,previous_event_hash,event_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id, SCHEMA_VERSION, incident_id, event_payload["occurred_at"], event_payload["received_at"], event_payload["chain"], event_payload["workflow"],
                    event_payload["driver"], run_id, batch_id, task_id, subject_kind, subject_ref,
                    subject_display, event_payload["stage_group"], node_code,
                    event_payload["node_label"], event_payload["sequence"], event_payload["attempt"], event_payload["attempt_group"],
                    outcome, event_payload["parent_event_id"], event_payload["root_cause_event_id"], elapsed_ms,
                    json.dumps(failure, ensure_ascii=False, sort_keys=True), json.dumps(transport, ensure_ascii=False, sort_keys=True),
                    message, 1, previous_hash, event_hash,
                ),
            )
            current_outcome = str(existing["outcome"] or "") if existing is not None else ""
            incoming_status = _status_for_outcome(outcome)
            next_status = incoming_status
            next_outcome = outcome
            if existing is not None:
                if current_outcome in _FAILURE_OUTCOMES and outcome not in _SUCCESS_OUTCOMES | _PARTIAL_OUTCOMES:
                    # Keep a real failure terminal until an explicit success
                    # or partial result resolves it.
                    next_outcome = current_outcome
                    next_status = _status_for_outcome(current_outcome)
                elif incoming_status == "open":
                    # Informational/lifecycle events after a terminal
                    # success/partial result must not downgrade the incident
                    # outcome to ``info``. A later explicit failure can still
                    # change the outcome because it has a non-open status.
                    if current_outcome in _SUCCESS_OUTCOMES | _PARTIAL_OUTCOMES:
                        next_outcome = current_outcome
                        next_status = _status_for_outcome(current_outcome)
                    else:
                        next_status = str(existing["status"] or "open")
                        if next_status in {"success", "partial", "failed", "stopped"}:
                            next_outcome = next_status

            # Chain status is carried forward instead of re-hashing the whole
            # event chain on every append (that O(N) re-verification made
            # steady-state appends quadratic). The append-only chain keeps the
            # linkage intact by construction here; a previously detected
            # ``failed``/``unverified`` state stays sticky, and startup
            # ``rebuild_incident_summaries`` remains the whole-chain verifier.
            existing_status = str(existing["integrity_status"] or "") if existing is not None else ""
            if history_fully_pruned or (existing is not None and existing_status == "unverified"):
                integrity_status = "unverified"
            elif existing_status == "failed":
                integrity_status = "failed"
            else:
                integrity_status = "verified"
            # Derive first-failure columns incrementally (O(1) per append).
            # The persisted summary is authoritative: the append-only chain
            # means the earliest business failure never changes, so at most
            # the new event can enrich it. A ``failed`` chain keeps the last
            # known summary, mirroring the former whole-verify behavior.
            existing_node = str(existing["first_node_code"] or "") if existing is not None else ""
            existing_label = str(existing["first_node_label"] or "") if existing is not None else ""
            existing_error_code = _safe_id(existing["first_error_code"], 120) if existing is not None else ""
            existing_retryable = bool(existing["retryable"]) if existing is not None else False
            existing_failure = _parse_failure(existing["failure_json"]) if existing is not None else {}
            # A pre-migration incident may have selected a cleanup event as
            # its root; cleanup is never a business cause. The single row
            # carries that evidence in its outcome/label, so the check stays
            # O(1) without loading the whole history.
            existing_is_cleanup_root = existing is not None and (
                _is_cleanup_event(existing)
                or any(
                    _is_cleanup_node(str(existing[key] or ""))
                    for key in ("first_node_code",)
                )
            )
            new_is_business_failure = (
                _is_business_failure_event(event_payload)
                and not _is_cleanup_event(event_payload)
            )
            if integrity_status == "failed" or history_fully_pruned:
                # A broken chain is not trustworthy input for repairing the
                # denormalized root-cause summary; a fully pruned history
                # proves nothing about the previously recorded root cause.
                first_node_code = "" if history_fully_pruned else existing_node
                first_node_label = "" if history_fully_pruned else existing_label
                first_error_code = "" if history_fully_pruned else existing_error_code
                first_retryable = False if history_fully_pruned else existing_retryable
                first_failure = {} if history_fully_pruned else dict(existing_failure)
            elif existing_is_cleanup_root and new_is_business_failure:
                # Repair the legacy cleanup root from the first real business
                # failure, matching the former whole-history realtime pass.
                first_node_code = str(event_payload["node_code"] or "")
                first_node_label = str(event_payload["node_label"] or "")
                first_failure = dict(event_payload["failure"])
                first_error_code = _safe_id(first_failure.get("error_code"), 120)
                first_retryable = (
                    _retryable_value(first_failure.get("retryable"))
                    if "retryable" in first_failure
                    else False
                )
            elif existing_is_cleanup_root:
                # A legacy release could persist a cleanup-only event as the
                # root; clear that invalid summary as soon as the incident is
                # touched, while leaving ordinary informational incidents
                # untouched (same semantics as the former realtime pass).
                first_node_code = first_node_label = first_error_code = ""
                first_retryable = False
                first_failure = {}
            elif not existing_node:
                first_node_code = existing_node
                first_node_label = existing_label
                first_error_code = existing_error_code
                first_retryable = existing_retryable
                first_failure = dict(existing_failure)
                if new_is_business_failure:
                    first_node_code = str(event_payload["node_code"] or "")
                    first_node_label = str(event_payload["node_label"] or "")
                    first_failure = dict(event_payload["failure"])
                    first_error_code = _safe_id(first_failure.get("error_code"), 120)
                    first_retryable = (
                        _retryable_value(first_failure.get("retryable"))
                        if "retryable" in first_failure
                        else False
                    )
            else:
                first_node_code = existing_node
                first_node_label = existing_label
                first_error_code = existing_error_code
                first_failure = dict(existing_failure)
                if new_is_business_failure and str(event_payload["node_code"] or "") == existing_node:
                    # Merge only keys missing from the persisted summary; the
                    # cumulative effect equals the former whole-history merge
                    # because every earlier same-node enrichment is already
                    # persisted in ``failure_json``.
                    first_failure = _merge_missing_failure_fields(
                        existing_failure,
                        [dict(event_payload["failure"])],
                    )
                    if not first_node_label:
                        first_node_label = str(event_payload["node_label"] or "")
                if "retryable" in existing_failure:
                    first_retryable = _retryable_value(existing_failure.get("retryable"))
                elif existing_retryable:
                    first_retryable = True
                else:
                    first_retryable = (
                        _retryable_value(first_failure.get("retryable"))
                        if "retryable" in first_failure
                        else False
                    )
                if not first_error_code:
                    first_error_code = _safe_id(first_failure.get("error_code"), 120)
            db.execute(
                "UPDATE diagnostic_incidents SET updated_at=?, status=?, outcome=?, first_node_code=?, first_node_label=?, first_error_code=?, retryable=?, failure_json=?, event_count=event_count+1, integrity_status=? WHERE incident_id=?",
                (
                    now, next_status, next_outcome, first_node_code, first_node_label,
                    first_error_code, int(first_retryable), json.dumps(first_failure, ensure_ascii=False, sort_keys=True),
                    integrity_status, incident_id,
                ),
            )
            aliases = [("task", task_id), ("batch", batch_id), ("run", run_id), (subject_kind, subject_ref)]
            for alias_type, alias_ref in aliases:
                if alias_type and alias_ref:
                    db.execute("INSERT OR IGNORE INTO diagnostic_aliases(alias_type,alias_ref,incident_id,created_at) VALUES(?,?,?,?)", (alias_type, alias_ref, incident_id, now))
            db.execute("COMMIT")
            return incident_id

    def record(self, fields: Mapping[str, Any]) -> str:
        """Append one event and retain a safe health signal on write failure."""
        try:
            return self._record(fields)
        except Exception as exc:
            try:
                setattr(exc, "_diagnostic_store_noted", True)
            except Exception as exc:
                # Marking the exception must not mask the write failure below.
                _note_stderr("L765", exc)
            self.note_write_failure("record", exc)
            raise

    def reserve_incident(self, incident_id: str) -> bool:
        """Reserve a pre-allocated incident id without creating its row.

        The async writer allocates ids on the hot path and persists events
        later. Registering the id in the tombstone table up front keeps the
        allocator collision-safe and lets ``_incident_for`` honor the hint
        before any event exists. Returns False when the id is unknown or
        already deleted.
        """
        candidate = _safe_text(incident_id, 80).upper()
        if not re.fullmatch(r"LOG-\d{8}-[A-Z0-9]{8}", candidate):
            return False
        now = utc_now()
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            deleted = db.execute(
                "SELECT deleted_at FROM diagnostic_incident_ids WHERE incident_id=?",
                (candidate,),
            ).fetchone()
            if deleted is not None and str(deleted[0] or ""):
                db.execute("COMMIT")
                return False
            if deleted is None:
                db.execute(
                    "INSERT INTO diagnostic_incident_ids(incident_id,created_at,deleted_at) VALUES(?,?,?)",
                    (candidate, now, ""),
                )
            db.execute("COMMIT")
            return True

    def note_write_failure(self, operation: str = "write", error: BaseException | None = None) -> None:
        """Record a credential-free diagnostic storage failure.

        This path is deliberately best-effort: when the database is locked or
        damaged, the in-memory counters still make the condition visible via
        ``health()`` and no raw exception/path is exposed.
        """
        operation_code = _safe_id(operation, 64) or "write"
        error_code = _safe_id(type(error).__name__ if error is not None else "unknown", 64)
        detail = f"operation={operation_code};error={error_code}"
        occurred_at = utc_now()
        with self._lock:
            self._write_failures += 1
            self._last_write_failure = detail
            self._last_write_failure_at = occurred_at
        connection: sqlite3.Connection | None = None
        try:
            # Use a short timeout so a blocked diagnostic database never stalls
            # the registration worker that is trying to report the outage.
            connection = sqlite3.connect(self.path, timeout=0.2, isolation_level=None)
            connection.execute(
                "INSERT INTO diagnostic_access_audit(action,incident_count,created_at,detail) VALUES(?,?,?,?)",
                ("write_failure", 0, occurred_at, detail),
            )
        except Exception:
            with self._lock:
                self._audit_write_failures += 1
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception as exc:
                    # Best-effort connection close during store shutdown.
                    _note_stderr("L832", exc)

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        if "event_id" in result:
            result.setdefault("schema_version", SCHEMA_VERSION)
            result["redaction_applied"] = bool(result.get("redaction_applied", True))
        for key in ("failure_json", "transport_json"):
            raw = result.pop(key, "{}")
            try:
                parsed = json.loads(raw) if raw else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = {}
            result[key.removesuffix("_json")] = (
                _safe_failure_mapping(parsed)
                if key == "failure_json"
                else _safe_transport_mapping(parsed)
            )
        return result

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        incident_id = _safe_text(incident_id, 80).upper()
        with self._lock, self._connection() as db:
            row = db.execute("SELECT * FROM diagnostic_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            # Hashes and root-cause selection follow append order. Keeping the
            # same order in the returned timeline avoids assigning a later
            # event as the root merely because it has an older client clock.
            events = db.execute("SELECT * FROM diagnostic_events WHERE incident_id=? ORDER BY rowid ASC", (incident_id,)).fetchall()
            payload = self._row(row)
            payload["events"] = [self._row(event) for event in events]
            payload["root_cause_event_id"] = next(
                (
                    str(event["event_id"])
                    for event in events
                    if str(event["node_code"] or "") == str(row["first_node_code"] or "")
                    and _is_business_failure_event(event)
                    and not _is_cleanup_event(event)
                ),
                "",
            )
            payload["integrity_status"] = self._verify_event_rows(db, incident_id, events)
            return payload

    def incident_events(self, incident_id: str) -> list[dict[str, Any]] | None:
        """Return the append-order event timeline without re-verifying hashes.

        Polling hot paths (dashboard snapshots) only need the event rows;
        per-event HMAC recomputation over the whole store is reserved for
        ``incident()`` and the explicit integrity views.
        """
        incident_id = _safe_text(incident_id, 80).upper()
        with self._lock, self._connection() as db:
            row = db.execute("SELECT 1 FROM diagnostic_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            events = db.execute("SELECT * FROM diagnostic_events WHERE incident_id=? ORDER BY rowid ASC", (incident_id,)).fetchall()
            return [self._row(event) for event in events]

    def verify_incident(self, db: sqlite3.Connection, incident_id: str) -> str:
        rows = db.execute("SELECT * FROM diagnostic_events WHERE incident_id=? ORDER BY rowid ASC", (incident_id,)).fetchall()
        return self._verify_event_rows(db, incident_id, rows)

    def _verify_event_rows(self, db: sqlite3.Connection, incident_id: str, rows: Sequence[sqlite3.Row]) -> str:
        status_row = db.execute(
            "SELECT integrity_status FROM diagnostic_incidents WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
        status_unverified = bool(status_row and str(status_row[0] or "") == "unverified")
        # A normal intact incident starts with an empty predecessor hash and
        # verifies normally. Retention-pruned suffixes carry a non-empty
        # predecessor marker below; that is the only case treated as an
        # incomplete prefix here.
        incomplete_prefix = False
        if not rows:
            if status_row is not None and str(status_row[0] or "") in {"failed", "unverified"}:
                return str(status_row[0] or "unverified")
            return "verified"
        previous = ""
        if rows and str(rows[0]["previous_event_hash"] or ""):
            if not status_unverified:
                return "failed"
            # Retention removed the leading events. Validate the remaining
            # suffix from its persisted predecessor while retaining an
            # explicit unverified status for the missing history.
            previous = str(rows[0]["previous_event_hash"] or "")
            incomplete_prefix = True
        previous_occurred_at = ""
        for row in rows:
            try:
                payload = {
                    "schema_version": SCHEMA_VERSION,
                    "event_id": row["event_id"], "incident_id": row["incident_id"], "occurred_at": row["occurred_at"],
                    "received_at": row["received_at"], "chain": row["chain"], "workflow": row["workflow"], "driver": row["driver"],
                    "run_id": row["run_id"], "batch_id": row["batch_id"], "task_id": row["task_id"],
                    "subject_kind": row["subject_kind"], "subject_ref": row["subject_ref"], "subject_display": row["subject_display"],
                    "stage_group": row["stage_group"], "node_code": row["node_code"], "node_label": row["node_label"],
                    "sequence": row["sequence"], "attempt": row["attempt"], "attempt_group": row["attempt_group"],
                    "outcome": row["outcome"], "parent_event_id": row["parent_event_id"], "root_cause_event_id": row["root_cause_event_id"],
                    "elapsed_ms": row["elapsed_ms"], "failure": json.loads(row["failure_json"] or "{}"),
                    "transport": json.loads(row["transport_json"] or "{}"), "message": row["message"],
                    "redaction_applied": bool(row["redaction_applied"]),
                }
            except (TypeError, ValueError, json.JSONDecodeError):
                return "failed"
            if row["previous_event_hash"] != previous or row["event_hash"] != self._hash_event(payload, previous):
                return "failed"
            if previous_occurred_at and str(row["occurred_at"] or "") < previous_occurred_at:
                return "failed"
            previous_occurred_at = str(row["occurred_at"] or "")
            previous = row["event_hash"]
        return "unverified" if incomplete_prefix else "verified"

    def delete(self, incident_ids: Sequence[str]) -> int:
        values = {str(value or "").strip().upper() for value in incident_ids if str(value or "").strip()}
        if not values:
            return 0
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in values)
            db.execute(f"DELETE FROM diagnostic_aliases WHERE incident_id IN ({placeholders})", tuple(values))
            db.execute(f"DELETE FROM diagnostic_tasks WHERE incident_id IN ({placeholders})", tuple(values))
            db.execute(f"DELETE FROM diagnostic_events WHERE incident_id IN ({placeholders})", tuple(values))
            deleted = db.execute(f"DELETE FROM diagnostic_incidents WHERE incident_id IN ({placeholders})", tuple(values)).rowcount
            db.executemany(
                "UPDATE diagnostic_incident_ids SET deleted_at=? WHERE incident_id=?",
                [(utc_now(), value) for value in values],
            )
            db.execute("INSERT INTO diagnostic_access_audit(action,incident_count,created_at,detail) VALUES(?,?,?,?)", ("delete", deleted, utc_now(), "selected incidents"))
            db.execute("COMMIT")
            return int(deleted or 0)

    def delete_by_tasks(self, task_ids: Sequence[str]) -> int:
        values = {str(value or "").strip() for value in task_ids if str(value or "").strip()}
        if not values:
            return 0
        with self._lock, self._connection() as db:
            placeholders = ",".join("?" for _ in values)
            rows = db.execute(
                f"SELECT incident_id FROM diagnostic_incidents WHERE task_id IN ({placeholders})",
                tuple(values),
            ).fetchall()
        return self.delete([str(row[0]) for row in rows])

    def clear(self) -> int:
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            count = int(db.execute("SELECT COUNT(*) FROM diagnostic_incidents").fetchone()[0])
            for table in ("diagnostic_aliases", "diagnostic_tasks", "diagnostic_events", "diagnostic_incidents"):
                db.execute(f"DELETE FROM {table}")
            db.execute("INSERT INTO diagnostic_access_audit(action,incident_count,created_at,detail) VALUES(?,?,?,?)", ("clear_all", count, utc_now(), "all diagnostic incidents"))
            db.execute("COMMIT")
            try:
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                db.execute("VACUUM")
            except sqlite3.DatabaseError:
                pass
            return count

    def health(self) -> dict[str, Any]:
        read_error = ""
        incidents = events = failed = 0
        cached = self._health_counts_cache
        if cached is not None and (time.monotonic() - cached[0]) < 1.0:
            _, incidents, events, failed = cached
        else:
            try:
                with self._lock, self._connection() as db:
                    incidents = int(db.execute("SELECT COUNT(*) FROM diagnostic_incidents").fetchone()[0])
                    events = int(db.execute("SELECT COUNT(*) FROM diagnostic_events").fetchone()[0])
                    failed = int(db.execute("SELECT COUNT(*) FROM diagnostic_incidents WHERE integrity_status='failed'").fetchone()[0])
                self._health_counts_cache = (time.monotonic(), incidents, events, failed)
            except Exception as exc:
                # Keep health useful even when the database cannot be opened. Only
                # the exception class is exposed; paths, SQL and payloads stay
                # private to the local process.
                read_error = _safe_id(type(exc).__name__, 64) or "database_error"
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        try:
            wal_size = self.path.with_name(f"{self.path.name}-wal").stat().st_size
        except OSError:
            wal_size = 0
        with self._lock:
            write_failures = int(self._write_failures)
            audit_write_failures = int(self._audit_write_failures)
            last_write_failure = self._last_write_failure
            last_write_failure_at = self._last_write_failure_at
            key_load_failure = self._key_load_failure
            key_load_attempts = int(self._key_load_attempts)
        return {
            "ok": not bool(read_error),
            "schema_version": SCHEMA_VERSION,
            "incidents": incidents,
            "events": events,
            "integrity_failures": failed,
            "database_bytes": size,
            "wal_bytes": wal_size,
            "write_status": "degraded" if write_failures else "ok",
            "write_failures": write_failures,
            "audit_write_failures": audit_write_failures,
            "last_write_failure": last_write_failure,
            "last_write_failure_at": last_write_failure_at,
            "key_status": "degraded" if key_load_failure else "ok",
            "key_load_failures": key_load_attempts,
            "key_load_error": key_load_failure,
            "index_status": "unavailable" if read_error else "degraded" if audit_write_failures else "ok",
            "hash_status": "failed" if failed else "verified",
            "storage_status": "unavailable" if read_error else "degraded" if write_failures or key_load_failure else "ok",
            "read_error": read_error,
            "path": "diagnostics/diagnostics.sqlite3",
        }


__all__ = ["DiagnosticStore"]
