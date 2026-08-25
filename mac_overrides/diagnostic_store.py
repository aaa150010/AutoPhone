"""Local append-only diagnostic index used by the Log Center.

The store deliberately accepts only a small, redacted field set. It is a
diagnostic index, not a second task/result database, so deleting it never
touches account, mailbox, proxy, or registration state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import string
import threading
import uuid
from contextlib import contextmanager
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

try:
    from .diagnostic_contract import DiagnosticEvent, SCHEMA_VERSION, utc_now
    from .error_observability import sanitize_failure_detail
    from .free_register_common import safe_log_message
except ImportError:  # pragma: no cover
    from diagnostic_contract import DiagnosticEvent, SCHEMA_VERSION, utc_now  # type: ignore[no-redef]
    from error_observability import sanitize_failure_detail  # type: ignore[no-redef]
    from free_register_common import safe_log_message  # type: ignore[no-redef]


_INCIDENT_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_SAFE_ID = set(string.ascii_letters + string.digits + "_.:-")
_SAFE_CHAIN = set(string.ascii_letters + string.digits + "_.:-")
_SENSITIVE_KEYS = {
    "password", "passwd", "token", "access_token", "refresh_token", "id_token",
    "admin_token", "cookie", "set-cookie", "authorization", "api_key", "sms_key",
    "totp", "totp_secret", "otp", "otp_code", "email_code", "phone", "phone_number",
    "proxy_password", "proxy_username", "oauth_state", "code_verifier",
}


def _safe_text(value: Any, limit: int = 500) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    return " ".join(text.split())[:limit]


def _safe_message(value: Any, limit: int = 500) -> str:
    text = _safe_text(value, limit)
    if not text:
        return ""
    try:
        redacted = sanitize_failure_detail(safe_log_message(text), limit=limit)
    except Exception:
        return "[已省略未通过脱敏校验的内容]"
    # The shared redactor intentionally keeps some transport context for the
    # ordinary log panel. The diagnostic index is stricter: no raw email,
    # bearer value, URL query credential, proxy credential, or phone number.
    redacted = re.sub(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}", "<credential>", redacted)
    redacted = re.sub(r"(?i)(authorization\s*=\s*\*+\s+)[^\s]+", r"\1<credential>", redacted)
    redacted = re.sub(
        r"(?i)([?&](?:code|state|token|access_token|refresh_token|id_token|authorization|client_secret|otp|email|phone)=[^&\s]+)",
        lambda match: f"{match.group(1).split('=', 1)[0]}=********",
        redacted,
    )
    redacted = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", redacted)
    redacted = re.sub(r"(?i)(https?://)([^\s/@:]+):([^\s/@]+)@", r"\1<credential>@", redacted)
    redacted = re.sub(r"(?i)\b(?:https?|socks[45h]?)://[^\s]+", "<url>", redacted)
    redacted = re.sub(r"(?<![A-Za-z0-9])\+?\d[\d ()-]{7,}\d(?![A-Za-z0-9])", "<phone>", redacted)
    return redacted[:limit]


def _safe_id(value: Any, limit: int = 180) -> str:
    text = _safe_text(value, limit)
    return "".join(char for char in text if char in _SAFE_ID)[:limit]


def _safe_mapping(value: Any, *, limit: int = 20, depth: int = 0) -> dict[str, Any]:
    if not isinstance(value, Mapping) or depth > 2:
        return {}
    result: dict[str, Any] = {}
    for raw_key, raw_value in list(value.items())[:limit]:
        key = _safe_id(raw_key, 64).lower().replace("-", "_")
        if not key or key in _SENSITIVE_KEYS or any(part in key for part in ("secret", "credential", "bearer")):
            continue
        if isinstance(raw_value, Mapping):
            result[key] = _safe_mapping(raw_value, limit=limit, depth=depth + 1)
        elif isinstance(raw_value, (bool, int, float)) or raw_value is None:
            result[key] = raw_value
        else:
            result[key] = _safe_message(raw_value, 300)
    return result


def _masked_subject(value: Any, kind: str = "") -> str:
    """Return a display-only subject mask; raw account identifiers never persist."""
    text = _safe_text(value, 160)
    if not text:
        return ""
    normalized_kind = str(kind or "").strip().lower()
    if "@" in text and normalized_kind in {"", "email", "account"}:
        local, domain = text.split("@", 1)
        if not local or not domain:
            return "已脱敏账号"
        return f"{local[:1]}***@{domain[:80]}"
    if normalized_kind in {"phone", "phone_number"} or text.isdigit():
        return f"***{text[-4:]}"
    if len(text) <= 8:
        return f"{text[:1]}***"
    return f"{text[:2]}***{text[-2:]}"


def _is_cleanup_node(value: Any) -> bool:
    code = str(value or "").strip().lower()
    return any(token in code for token in ("cleanup", "close", "shutdown", "recovery", "restore", "process_recover"))


def _failure_priority(value: Any) -> int:
    return 2 if _is_cleanup_node(value) else 1


def _status_for_outcome(outcome: str) -> str:
    normalized = str(outcome or "").strip().lower()
    if normalized in {"success", "succeeded", "complete", "completed"}:
        return "success"
    if normalized in {"partial", "partial_success"}:
        return "partial"
    if normalized in {"stopped", "cancelled", "canceled"}:
        return "stopped"
    if normalized in {"error", "failed", "failure"}:
        return "failed"
    return "open"


def _search_bound(value: Any, *, end_of_day: bool = False) -> str:
    """Normalize date/time-only filters to UTC ISO bounds."""
    text = _safe_text(value, 40)
    if not text:
        return ""
    local_zone = datetime.now().astimezone().tzinfo or timezone.utc
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            parsed = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=local_zone)
            if end_of_day:
                parsed += timedelta(days=1, milliseconds=-1)
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if re.fullmatch(r"\d{1,2}:\d{2}(?::\d{2})?", text):
            parts = [int(part) for part in text.split(":")]
            now = datetime.now(local_zone)
            parsed = now.replace(hour=parts[0], minute=parts[1], second=parts[2] if len(parts) > 2 else 0, microsecond=0)
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return text
    return text


class DiagnosticStore:
    """Thread-safe SQLite store for incidents and append-only events."""

    def __init__(self, data_dir: str | Path, *, event_retention_days: int = 30, incident_retention_days: int = 180) -> None:
        self.root = Path(data_dir).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "diagnostics.sqlite3"
        self.key_path = self.root / "diagnostic.key"
        self.event_retention_days = max(1, int(event_retention_days))
        self.incident_retention_days = max(self.event_retention_days, int(incident_retention_days))
        self._lock = threading.RLock()
        self._key = self._load_key()
        self._initialize()

    def _load_key(self) -> bytes:
        try:
            value = self.key_path.read_bytes()
            if len(value) >= 32:
                try:
                    os.chmod(self.key_path, 0o600)
                except OSError:
                    pass
                return value
        except OSError:
            pass
        value = secrets.token_bytes(32)
        self.key_path.write_bytes(value)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return value

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            yield connection
        finally:
            connection.close()

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
        self.prune()

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
            for incident_id in touched_incidents:
                remaining = int(db.execute("SELECT COUNT(*) FROM diagnostic_events WHERE incident_id=?", (incident_id,)).fetchone()[0])
                db.execute(
                    "UPDATE diagnostic_incidents SET event_count=?, integrity_status=? WHERE incident_id=?",
                    (remaining, "unverified" if event_count else "verified", incident_id),
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
        now: str,
    ) -> str:
        if incident_id:
            row = db.execute("SELECT incident_id FROM diagnostic_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if row:
                return incident_id
        if task_id:
            if run_id or batch_id:
                row = db.execute(
                    "SELECT incident_id FROM diagnostic_incidents WHERE task_id=? AND "
                    "((run_id=? AND ?!='') OR (batch_id=? AND ?!='')) "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (task_id, run_id, run_id, batch_id, batch_id),
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT incident_id FROM diagnostic_incidents WHERE task_id=? ORDER BY updated_at DESC LIMIT 1",
                    (task_id,),
                ).fetchone()
            if row:
                return str(row[0])
        # Do not merge unrelated tasks merely because they share an email or
        # account fingerprint. Email search is an alias lookup, not grouping.
        return self._next_incident_id(db, now)

    def record(self, fields: Mapping[str, Any]) -> str:
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
        failure = _safe_mapping(fields.get("failure"))
        transport = _safe_mapping(fields.get("transport"))
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
                now=now,
            )
            existing = db.execute("SELECT * FROM diagnostic_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if existing is None:
                db.execute(
                    "INSERT INTO diagnostic_incidents (incident_id,created_at,updated_at,chain,workflow,driver,run_id,batch_id,task_id,subject_kind,subject_ref,subject_display,status,outcome) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        incident_id, now, now, _safe_id(fields.get("chain") or "unknown", 48),
                        _safe_id(fields.get("workflow") or "run", 64), _safe_id(fields.get("driver") or "unknown", 48),
                        run_id, batch_id, task_id, subject_kind,
                        subject_ref, subject_display,
                        _status_for_outcome(outcome), outcome,
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
                "occurred_at": _safe_text(fields.get("occurred_at") or now, 40),
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
                "node_label": _safe_text(fields.get("node_label"), 160),
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
                    subject_display, _safe_id(fields.get("stage_group"), 64), node_code,
                    _safe_text(fields.get("node_label"), 160), max(0, sequence), max(0, attempt), _safe_id(fields.get("attempt_group"), 120),
                    outcome, _safe_id(fields.get("parent_event_id"), 80), _safe_id(fields.get("root_cause_event_id"), 80), elapsed_ms,
                    json.dumps(failure, ensure_ascii=False, sort_keys=True), json.dumps(transport, ensure_ascii=False, sort_keys=True),
                    message, 1, previous_hash, event_hash,
                ),
            )
            current_first = str(existing["first_node_code"] or "") if existing is not None else ""
            current_outcome = str(existing["outcome"] or "") if existing is not None else ""
            next_status = _status_for_outcome(outcome)
            if next_status == "open" and existing is not None:
                next_status = str(existing["status"] or "open")
            current_priority = _failure_priority(current_first)
            new_priority = _failure_priority(node_code)
            should_promote_failure = is_error and (
                not existing
                or not current_first
                or current_outcome not in {"error", "failed", "failure", "stopped"}
                or new_priority < current_priority
            )
            if should_promote_failure:
                db.execute(
                    "UPDATE diagnostic_incidents SET updated_at=?, status=?, outcome=?, first_node_code=?, first_node_label=?, first_error_code=?, retryable=?, failure_json=?, event_count=event_count+1, integrity_status='verified' WHERE incident_id=?",
                    (now, next_status, outcome, node_code, _safe_text(fields.get("node_label"), 160), _safe_id(failure.get("error_code"), 120), int(bool(failure.get("retryable"))), json.dumps(failure, ensure_ascii=False, sort_keys=True), incident_id),
                )
            else:
                next_outcome = outcome
                if current_outcome in {"error", "failed", "failure", "stopped"} and outcome not in {"success", "succeeded", "complete", "completed", "partial", "partial_success"}:
                    next_outcome = current_outcome
                next_status = _status_for_outcome(current_outcome) if current_outcome in {"error", "failed", "failure", "stopped"} else next_status
                db.execute("UPDATE diagnostic_incidents SET updated_at=?, status=?, outcome=?, event_count=event_count+1, integrity_status='verified' WHERE incident_id=?", (now, next_status, next_outcome, incident_id))
            aliases = [("task", task_id), ("batch", batch_id), ("run", run_id), (subject_kind, subject_ref)]
            for alias_type, alias_ref in aliases:
                if alias_type and alias_ref:
                    db.execute("INSERT OR IGNORE INTO diagnostic_aliases(alias_type,alias_ref,incident_id,created_at) VALUES(?,?,?,?)", (alias_type, alias_ref, incident_id, now))
            db.execute("COMMIT")
            return incident_id

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        if "event_id" in result:
            result.setdefault("schema_version", SCHEMA_VERSION)
            result["redaction_applied"] = bool(result.get("redaction_applied", True))
        for key in ("failure_json", "transport_json"):
            raw = result.pop(key, "{}")
            try:
                result[key.removesuffix("_json")] = json.loads(raw) if raw else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                result[key.removesuffix("_json")] = {}
        return result

    def search(self, query: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        query = query or {}
        clauses: list[str] = []
        params: list[Any] = []
        exact = _safe_text(query.get("incident_id"), 80).upper()
        if exact:
            clauses.append("i.incident_id=?")
            params.append(exact)
        for key in (() if exact else ("task_id", "batch_id", "run_id", "chain", "driver", "status", "outcome", "first_node_code")):
            value = _safe_text(query.get(key), 180)
            if value:
                if key == "outcome" and value == "open":
                    column = "i.status"
                else:
                    column = {"first_node_code": "i.first_node_code"}.get(key, f"i.{key}")
                clauses.append(f"{column}=?")
                params.append(value)
        subject = _safe_text(query.get("subject") or query.get("email") or query.get("account"), 500)
        if subject and not exact:
            ref = self.fingerprint(subject)
            clauses.append("(i.subject_ref=? OR EXISTS (SELECT 1 FROM diagnostic_aliases a WHERE a.incident_id=i.incident_id AND a.alias_ref=?))")
            params.extend((ref, ref))
        time_point = _safe_text(query.get("time_point") or query.get("time"), 40)
        if time_point and not exact and re.fullmatch(r"\d{1,2}:\d{2}(?::\d{2})?", time_point):
            try:
                center = datetime.fromisoformat(_search_bound(time_point).replace("Z", "+00:00"))
                clauses.append("i.updated_at>=?")
                params.append((center - timedelta(minutes=30)).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
                clauses.append("i.updated_at<=?")
                params.append((center + timedelta(minutes=30)).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
            except (TypeError, ValueError, OverflowError):
                pass
        date_only = _safe_text(query.get("date"), 40)
        if date_only and not exact and not time_point and not query.get("from") and not query.get("to"):
            clauses.append("i.updated_at>=?")
            params.append(_search_bound(date_only))
            clauses.append("i.updated_at<=?")
            params.append(_search_bound(date_only, end_of_day=True))
        if query.get("from") and not exact and not time_point:
            clauses.append("i.updated_at>=?")
            params.append(_search_bound(query.get("from")))
        if query.get("to") and not exact and not time_point:
            clauses.append("i.updated_at<=?")
            params.append(_search_bound(query.get("to"), end_of_day=True))
        limit_value = query.get("limit") or 100
        try:
            limit = min(max(int(limit_value), 1), 500)
        except (TypeError, ValueError):
            limit = 100
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock, self._connection() as db:
            rows = db.execute(f"SELECT i.* FROM diagnostic_incidents i {where} ORDER BY CASE WHEN i.outcome IN ('error','failed','failure') THEN 0 ELSE 1 END, i.updated_at DESC LIMIT ?", (*params, limit)).fetchall()
            results = [self._row(row) for row in rows]
            basis: list[str] = []
            if exact:
                basis.append("日志 ID 精确匹配")
            for key, label in (("task_id", "任务 ID"), ("batch_id", "批次 ID"), ("run_id", "运行 ID"), ("subject", "账号 HMAC 指纹"), ("email", "邮箱 HMAC 指纹"), ("account", "账号 HMAC 指纹"), ("date", "日期全天"), ("from", "开始时间"), ("to", "结束时间"), ("time_point", "时间点 ±30 分钟")):
                if query.get(key):
                    basis.append(label)
            for result in results:
                result["match_basis"] = basis or ["最近发生时间"]
                if time_point:
                    try:
                        center = datetime.fromisoformat(_search_bound(time_point).replace("Z", "+00:00"))
                        updated = datetime.fromisoformat(str(result.get("updated_at") or "").replace("Z", "+00:00"))
                        result["time_distance_seconds"] = abs((updated - center).total_seconds())
                    except (TypeError, ValueError, OverflowError):
                        result["time_distance_seconds"] = None
            return results

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        incident_id = _safe_text(incident_id, 80).upper()
        with self._lock, self._connection() as db:
            row = db.execute("SELECT * FROM diagnostic_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            events = db.execute("SELECT * FROM diagnostic_events WHERE incident_id=? ORDER BY occurred_at ASC, rowid ASC", (incident_id,)).fetchall()
            payload = self._row(row)
            payload["events"] = [self._row(event) for event in events]
            payload["root_cause_event_id"] = next(
                (
                    str(event["event_id"])
                    for event in events
                    if str(event["node_code"] or "") == str(row["first_node_code"] or "")
                    and str(event["outcome"] or "").lower() in {"error", "failed", "failure", "stopped"}
                    and not _is_cleanup_node(event["node_code"])
                ),
                "",
            )
            payload["integrity_status"] = self.verify_incident(db, incident_id)
            return payload

    def verify_incident(self, db: sqlite3.Connection, incident_id: str) -> str:
        rows = db.execute("SELECT * FROM diagnostic_events WHERE incident_id=? ORDER BY rowid ASC", (incident_id,)).fetchall()
        previous = ""
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
        return "verified"

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
        with self._lock, self._connection() as db:
            incidents = int(db.execute("SELECT COUNT(*) FROM diagnostic_incidents").fetchone()[0])
            events = int(db.execute("SELECT COUNT(*) FROM diagnostic_events").fetchone()[0])
            failed = int(db.execute("SELECT COUNT(*) FROM diagnostic_incidents WHERE integrity_status='failed'").fetchone()[0])
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        try:
            wal_size = self.path.with_name(f"{self.path.name}-wal").stat().st_size
        except OSError:
            wal_size = 0
        return {
            "ok": True,
            "schema_version": SCHEMA_VERSION,
            "incidents": incidents,
            "events": events,
            "integrity_failures": failed,
            "database_bytes": size,
            "wal_bytes": wal_size,
            "write_status": "ok",
            "index_status": "ok",
            "hash_status": "failed" if failed else "verified",
            "storage_status": "ok",
            "path": "diagnostics/diagnostics.sqlite3",
        }

    def export(self, incident_ids: Sequence[str], fmt: str = "json") -> str:
        rows = [self.incident(value) for value in incident_ids]
        incidents = [row for row in rows if row is not None]
        if str(fmt).lower() != "markdown":
            return json.dumps({
                "schema_version": SCHEMA_VERSION,
                "redaction_applied": True,
                "incidents": incidents,
                "facts": "仅包含本地诊断索引中已记录的脱敏事件。",
                "analysis": "首个真实失败节点按事件链和节点优先级归纳；不代表未记录的外部事实。",
                "unknowns": "保留策略清理、写入前丢失或未接入统一契约的历史事件无法恢复。",
                "redaction_removed": ["邮箱原文", "手机号", "密码", "Token", "Cookie", "验证码", "TOTP 秘密", "代理凭据"],
            }, ensure_ascii=False, indent=2)
        lines = ["# GPTPhone 脱敏日志诊断", "", "> 仅包含本地诊断索引中的脱敏事件；事实、归因和未知项分开。", ""]
        for incident in incidents:
            lines.extend([
                f"## 1. 日志 ID\n{incident['incident_id']}",
                "", "## 2. 查询和匹配依据",
                f"- 任务 ID：{incident.get('task_id') or '-'}；批次 ID：{incident.get('batch_id') or '-'}",
                f"- 账号显示：{incident.get('subject_display') or '-'}；链路：{incident.get('chain') or '-'} / {incident.get('driver') or '-'}",
                "", "## 3. 已确认事实",
                f"- 状态：{incident.get('status') or incident.get('outcome') or '-'}；事件数：{incident.get('event_count') or 0}",
                f"- 首个失败节点：{incident.get('first_node_label') or '-'} ({incident.get('first_node_code') or '-'})",
                "", "## 4. 首个真实失败",
                f"- 错误代码：{incident.get('first_error_code') or '-'}；可重试：{'是' if incident.get('retryable') else '否'}；HTTP 状态：{incident.get('failure', {}).get('http_status') or '-'}；Provider Code：{incident.get('failure', {}).get('provider_code') or '-'}",
                "", "## 5. 关键时间线",
            ])
            for event in incident.get("events") or []:
                lines.append(f"- {event.get('occurred_at')} [{event.get('outcome')}] {event.get('node_label') or event.get('node_code') or '-'}：{event.get('message') or '-'}")
            lines.extend([
                "", "## 6. 重试和连带错误", "- 事件中的 attempt、attempt_group 和后续清理事件仅作为关联记录，不覆盖首因。",
                "", "## 7. 脱敏环境摘要", f"- 工作流：{incident.get('workflow') or '-'}；运行标识：{incident.get('run_id') or '-'}",
                "", "## 8. 完整性校验结果", f"- {incident.get('integrity_status') or '-'}",
                "", "## 9. 当前最可能根因", f"- {incident.get('failure', {}).get('public_message') or incident.get('failure', {}).get('technical_summary') or '当前证据不足以进一步归因。'}",
                "", "## 10. 未确认信息", "- 仅根据当前诊断索引判断；被保留策略清理、写入前丢失或未接入契约的历史事件无法恢复。",
                "", "## 11. 建议下一步", f"- {incident.get('failure', {}).get('action_hint') or '按首个真实失败节点继续排查，并保留本日志 ID。'}",
                "", "## 12. 已移除的敏感字段", "- 邮箱原文、手机号、密码、Token、Cookie、验证码、TOTP 秘密、代理凭据。", "",
            ])
        return "\n".join(lines)


__all__ = ["DiagnosticStore"]
