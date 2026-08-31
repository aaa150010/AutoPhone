"""Local append-only diagnostic index used by the Log Center.

The store deliberately accepts only a small, redacted field set. It is a
diagnostic index, not a second task/result database, so deleting it never
touches account, mailbox, proxy, or registration state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
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
# Marker carried by the first retained event when every predecessor was
# removed by retention. It preserves an explicit incomplete-history signal
# without adding a schema column or fabricating a real event hash.
_MISSING_HISTORY_HASH = "history_pruned"
_FAILURE_MAPPING_KEYS = (
    "node_code", "node_label", "error_code", "provider_code",
    "public_message", "technical_summary", "retryable", "http_status",
    "action_hint", "diagnostic_action", "diagnostic", "page_type",
    "safe_page", "content_type", "session_rebuilds", "retry_after_seconds",
    "declared_scheme", "transport_scheme", "target_domain", "request_stage",
    "retry_count", "transport_error_code",
    "debug_session_id", "debug_artifact_id", "artifact_id",
    # Mailbox parser diagnostics reference a separate redacted sample store.
    "sample_id", "reason",
)
_TRANSPORT_MAPPING_KEYS = (
    "failure_count", "total_count", "target_domain", "nodes",
    "http_statuses", "provider_statuses", "provider_codes",
    "declared_schemes", "effective_schemes", "proxy_fingerprints",
    "health_write_failures", "request_stage", "http_status", "content_type",
    "authorize_url_present", "final_host", "final_path",
)


def _safe_text(value: Any, limit: int = 500) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    return " ".join(text.split())[:limit]


def _safe_occurred_at(value: Any, fallback: str) -> str:
    """Keep event timestamps parseable so arbitrary input cannot be persisted."""
    text = _safe_text(value, 40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return fallback


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


def _safe_mapping(value: Any, *, allowed_keys: Sequence[str]) -> dict[str, Any]:
    """Project an untrusted diagnostic map through a scalar allowlist.

    Diagnostic JSON is deliberately not a general-purpose metadata channel.
    Iterating the allowlist (rather than the input order) also prevents a set
    of unknown keys from crowding canonical fields out of the stored record.
    """
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in allowed_keys:
        if key not in value:
            continue
        raw_value = value.get(key)
        if isinstance(raw_value, bool) or isinstance(raw_value, int):
            result[key] = raw_value
            continue
        if isinstance(raw_value, float):
            if math.isfinite(raw_value):
                result[key] = raw_value
            continue
        if isinstance(raw_value, (list, tuple)):
            # Canonical transport summaries may use bounded arrays for node,
            # status or fingerprint sets. Preserve that shape while projecting
            # every member through the same scalar/redaction rules.
            items: list[Any] = []
            for item in list(raw_value)[:32]:
                if isinstance(item, bool) or isinstance(item, int):
                    items.append(item)
                elif isinstance(item, float):
                    if math.isfinite(item):
                        items.append(item)
                elif isinstance(item, str):
                    text = _safe_message(item, 120)
                    if text:
                        items.append(text)
            if items:
                result[key] = items
            continue
        if not isinstance(raw_value, str):
            # Unknown containers could contain response bodies, headers or
            # credentials. They are never serialized into the index.
            continue
        text = _safe_message(raw_value, 300)
        if text:
            result[key] = text
    return result


def _safe_failure_mapping(value: Any) -> dict[str, Any]:
    return _safe_mapping(value, allowed_keys=_FAILURE_MAPPING_KEYS)


def _safe_transport_mapping(value: Any) -> dict[str, Any]:
    return _safe_mapping(value, allowed_keys=_TRANSPORT_MAPPING_KEYS)


def _masked_subject(value: Any, kind: str = "") -> str:
    """Return a display-only subject mask; raw account identifiers never persist."""
    text = _safe_text(value, 160)
    if not text:
        return ""
    normalized_kind = str(kind or "").strip().lower()
    if normalized_kind in {"", "email", "account"} and re.fullmatch(
        r"[^@\s]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",
        text,
    ):
        local, domain = text.split("@", 1)
        if "." not in domain or ".." in domain:
            return "已脱敏账号"
        return f"{local[:1]}***@{domain[:80]}"
    if normalized_kind in {"phone", "phone_number"} or re.fullmatch(r"\d{8,15}", text):
        if not re.fullmatch(r"\+?\d{8,15}", text):
            return "已脱敏账号"
        return f"***{text[-4:]}"
    # Generic account IDs are allowed only as opaque identifier text. Reject
    # credential/URL-looking values rather than exposing a masked substring.
    if (
        len(text) > 160
        or not re.fullmatch(r"[A-Za-z0-9_.:-]+", text)
        or any(marker in text.lower() for marker in ("token", "secret", "password", "credential", "auth", "key"))
    ):
        return "已脱敏账号"
    if len(text) <= 8:
        return f"{text[:1]}***"
    return f"{text[:2]}***{text[-2:]}"


def _is_cleanup_node(value: Any) -> bool:
    code = str(value or "").strip().lower()
    return any(token in code for token in (
        "cleanup", "close", "shutdown", "recovery", "restore", "process_recover",
        # Startup/maintenance handlers use a neutral ``maintenance`` workflow
        # while still belonging to the task's existing diagnostic timeline.
        "maintenance",
        # Lease/health bookkeeping is emitted after the business result and
        # must remain an associated cleanup event, never a new root cause.
        "proxy_release", "lease_release", "mailbox_release", "task_release",
    ))


def _is_cleanup_event(event: Any) -> bool:
    """Classify cleanup/recovery events from their full diagnostic context.

    Cleanup writes are often emitted with a neutral node (for example a pool
    health write) and identify themselves through ``workflow`` or an outcome
    such as ``cleanup_failed``.  Root-cause selection must exclude those
    events even when the node code itself does not contain a cleanup marker.
    """
    if event is None:
        return False
    for key in ("node_code", "first_node_code", "workflow", "outcome"):
        if _is_cleanup_node(_event_value(event, key)):
            return True
    label = str(
        _event_value(event, "node_label")
        or _event_value(event, "first_node_label")
        or ""
    ).strip().lower()
    return any(token in label for token in ("清理", "关闭", "恢复", "释放", "回收"))


_FAILURE_OUTCOMES = frozenset({"error", "failed", "failure", "stopped"})
_SUCCESS_OUTCOMES = frozenset({"success", "succeeded", "complete", "completed"})
_PARTIAL_OUTCOMES = frozenset({"partial", "partial_success"})


def _is_failure_outcome(outcome: Any, level: Any = "") -> bool:
    return str(outcome or "").strip().lower() in _FAILURE_OUTCOMES or str(level or "").strip().lower() in {"error", "danger"}


def _event_value(event: Any, key: str, default: Any = "") -> Any:
    """Read both sqlite rows and ordinary mappings."""
    try:
        return event[key]
    except (KeyError, IndexError, TypeError):
        if isinstance(event, Mapping):
            return event.get(key, default)
        return default


def _is_business_failure_event(event: Any) -> bool:
    """Identify failure candidates without losing non-standard structured outcomes."""
    outcome = str(_event_value(event, "outcome") or "").strip().lower()
    if _is_failure_outcome(outcome, _event_value(event, "level")):
        return True
    if outcome in {"", "info", "started", "success", "succeeded", "complete", "completed", "partial", "partial_success", "retry"}:
        # A legacy writer may have persisted structured failure details while
        # leaving the lifecycle outcome at ``info``. Preserve those details
        # for startup root-cause reconstruction without treating ordinary
        # informational rows as failures.
        return bool(_parse_failure(_event_value(event, "failure_json")))
    return bool(_parse_failure(_event_value(event, "failure_json")))


def _parse_failure(value: Any) -> dict[str, Any]:
    """Read a persisted failure map without allowing malformed JSON to leak."""
    if isinstance(value, Mapping):
        return _safe_failure_mapping(value)
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return _safe_failure_mapping(parsed)


def _retryable_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0", ""}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _business_failure_events(events: Sequence[Any]) -> list[Any]:
    """Return business failure events in append order, excluding cleanup."""
    return [
        event for event in events
        if _is_business_failure_event(event)
        and not _is_cleanup_event(event)
    ]


def _failure_summary(event: Any, failure: Mapping[str, Any] | None = None) -> tuple[str, str, str, bool, dict[str, Any]]:
    """Build the denormalized summary tuple for one failure event."""
    normalized = dict(failure or _parse_failure(_event_value(event, "failure_json")))
    node_code = str(_event_value(event, "node_code") or "")
    node_label = str(_event_value(event, "node_label") or "")
    error_code = _safe_id(normalized.get("error_code"), 120)
    retryable = (
        _retryable_value(normalized.get("retryable"))
        if "retryable" in normalized
        else False
    )
    return node_code, node_label, error_code, retryable, normalized


def _merge_missing_failure_fields(
    base: Mapping[str, Any] | None,
    candidates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Enrich a failure map without replacing fields already selected.

    A later structured event can contain details that were unavailable when
    the first event was appended.  Merge only absent keys; in particular,
    ``False`` and numeric zero are valid values and must not be treated as
    missing.
    """
    merged = dict(base or {})
    for candidate in candidates:
        for key, value in candidate.items():
            if key not in merged:
                merged[key] = value
    return merged


def _same_node_failure_maps(events: Sequence[Any], node_code: str) -> list[dict[str, Any]]:
    """Return structured failures for one node in append order."""
    maps: list[dict[str, Any]] = []
    for event in events:
        if str(_event_value(event, "node_code") or "") != node_code:
            continue
        failure = _parse_failure(_event_value(event, "failure_json"))
        if failure:
            maps.append(failure)
    return maps


def _is_cleanup_root(existing: Any, events: Sequence[Any]) -> bool:
    """Detect a stale cleanup root even when the incident row lost context."""
    if _is_cleanup_event(existing):
        return True
    root_code = str(_event_value(existing, "first_node_code") or "")
    if not root_code:
        return False
    return any(
        str(_event_value(event, "node_code") or "") == root_code
        and _is_cleanup_event(event)
        for event in events
    )


def _startup_failure_summary(events: Sequence[Any]) -> tuple[str, str, str, bool, dict[str, Any]] | None:
    """Rebuild a legacy incident using its earliest structured failure.

    Older releases could append a bare failure before the structured failure
    was available.  During startup migration we prefer the first event that
    contains structured failure details; only an incident with no structured
    failure falls back to its earliest bare business failure.
    """
    business_events = _business_failure_events(events)
    if not business_events:
        return None
    structured = next(
        (event for event in business_events if _parse_failure(_event_value(event, "failure_json"))),
        None,
    )
    selected = structured or business_events[0]
    node_code = str(_event_value(selected, "node_code") or "")
    selected_failure = _parse_failure(_event_value(selected, "failure_json"))
    merged_failure = _merge_missing_failure_fields(
        selected_failure,
        _same_node_failure_maps(business_events, node_code),
    )
    return _failure_summary(selected, merged_failure)


def _realtime_failure_summary(
    existing: Any,
    events: Sequence[Any],
) -> tuple[str, str, str, bool, dict[str, Any]] | None:
    """Keep a live incident's chosen root cause stable while enriching it.

    Once an incident has a first node, later events cannot promote another
    node.  A structured failure may only fill a missing failure (or label) on
    that same node.  For a newly-created incident, append order determines the
    first event, intentionally differing from startup migration semantics.
    """
    existing_node = str(_event_value(existing, "first_node_code") or "") if existing is not None else ""
    business_events = _business_failure_events(events)
    if not business_events:
        # A legacy release could persist a cleanup-only event as the root.
        # Clear that invalid denormalized summary as soon as the incident is
        # touched, while leaving ordinary informational incidents untouched.
        if existing is not None and _is_cleanup_root(existing, events):
            return "", "", "", False, {}
        return None

    # A pre-migration incident may have selected a cleanup node as its root.
    # Cleanup is never a business cause; once a real failure is appended,
    # repair that legacy summary from the earliest business event.
    if existing is not None and _is_cleanup_root(existing, events):
        existing_node = ""
    if not existing_node:
        selected = business_events[0]
        node_code = str(_event_value(selected, "node_code") or "")
        selected_failure = _parse_failure(_event_value(selected, "failure_json"))
        merged_failure = _merge_missing_failure_fields(
            selected_failure,
            _same_node_failure_maps(business_events, node_code),
        )
        summary = _failure_summary(selected, merged_failure)
        if not summary[1]:
            for candidate in business_events:
                if str(_event_value(candidate, "node_code") or "") == node_code:
                    summary = (summary[0], str(_event_value(candidate, "node_label") or ""), summary[2], summary[3], summary[4])
                    if summary[1]:
                        break
        return summary

    # An existing summary is authoritative. Read its persisted failure map
    # and only fill missing fields from a structured same-node event.
    first_node_label = str(_event_value(existing, "first_node_label") or "")
    existing_failure = _parse_failure(_event_value(existing, "failure_json"))
    first_failure = _merge_missing_failure_fields(
        existing_failure,
        _same_node_failure_maps(business_events, existing_node),
    )
    first_event = next(
        (event for event in business_events if str(_event_value(event, "node_code") or "") == existing_node),
        None,
    )
    if first_event is not None and not first_node_label:
        first_node_label = str(_event_value(first_event, "node_label") or "")
    if not first_node_label:
        for candidate in business_events:
            if str(_event_value(candidate, "node_code") or "") != existing_node:
                continue
            candidate_label = str(_event_value(candidate, "node_label") or "")
            if candidate_label:
                first_node_label = candidate_label
                break
    existing_error_code = _safe_id(_event_value(existing, "first_error_code"), 120)
    first_error_code = existing_error_code or _safe_id(first_failure.get("error_code"), 120)
    if "retryable" in existing_failure:
        retryable = _retryable_value(existing_failure.get("retryable"))
    elif bool(_event_value(existing, "retryable")):
        retryable = True
    else:
        retryable = _retryable_value(first_failure.get("retryable")) if "retryable" in first_failure else False
    return existing_node, first_node_label, first_error_code, retryable, first_failure


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
        # Keep a process-local record even when SQLite itself is unavailable;
        # the health endpoint can then report dropped diagnostic writes instead
        # of presenting a misleading all-clear status.
        self._write_failures = 0
        self._audit_write_failures = 0
        self._last_write_failure = ""
        self._last_write_failure_at = ""
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
                integrity = self.verify_incident(db, incident_id)
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
                summary = _startup_failure_summary(events)
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
        chain: str,
        workflow: str,
        driver: str,
        now: str,
    ) -> str:
        if incident_id:
            row = db.execute("SELECT incident_id FROM diagnostic_incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if row:
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
                    subject_display, _safe_id(fields.get("stage_group"), 64), node_code,
                    _safe_message(fields.get("node_label"), 160), max(0, sequence), max(0, attempt), _safe_id(fields.get("attempt_group"), 120),
                    outcome, _safe_id(fields.get("parent_event_id"), 80), _safe_id(fields.get("root_cause_event_id"), 80), elapsed_ms,
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

            # Derive first-failure columns from the immutable event order. A
            # later success, cleanup, or bare failure therefore cannot erase a
            # previously recorded business root cause. If the earliest event
            # was written by an older release without details, enrich it only
            # when a later event at the same node carries structured failure.
            history = db.execute(
                "SELECT * FROM diagnostic_events WHERE incident_id=? ORDER BY rowid ASC",
                (incident_id,),
            ).fetchall()
            # Once retention removed every event, the denormalized root cause
            # can no longer be proven by the append-only chain. Do not carry
            # that stale summary into the newly visible suffix.
            summary_source = None if history_fully_pruned else existing
            first_node_code = str(summary_source["first_node_code"] or "") if summary_source is not None else ""
            first_node_label = str(summary_source["first_node_label"] or "") if summary_source is not None else ""
            first_error_code = str(summary_source["first_error_code"] or "") if summary_source is not None else ""
            first_retryable = bool(summary_source["retryable"]) if summary_source is not None else False
            first_failure = _parse_failure(summary_source["failure_json"]) if summary_source is not None else {}
            event_count = len(history)
            integrity_status = self.verify_incident(db, incident_id)
            # A broken hash chain is not trustworthy input for repairing the
            # denormalized root-cause summary. Keep the last known summary and
            # expose the integrity failure until an operator resolves it.
            summary = _realtime_failure_summary(existing, history) if integrity_status == "verified" else None
            if summary is not None:
                first_node_code, first_node_label, first_error_code, first_retryable, first_failure = summary
            db.execute(
                "UPDATE diagnostic_incidents SET updated_at=?, status=?, outcome=?, first_node_code=?, first_node_label=?, first_error_code=?, retryable=?, failure_json=?, event_count=?, integrity_status=? WHERE incident_id=?",
                (
                    now, next_status, next_outcome, first_node_code, first_node_label,
                    first_error_code, int(first_retryable), json.dumps(first_failure, ensure_ascii=False, sort_keys=True),
                    event_count, integrity_status, incident_id,
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
            except Exception:
                pass
            self.note_write_failure("record", exc)
            raise

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
                except Exception:
                    pass

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

    def search(self, query: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        query = query or {}
        clauses: list[str] = []
        params: list[Any] = []
        exact = _safe_text(query.get("incident_id"), 80).upper()
        if exact:
            clauses.append("i.incident_id=?")
            params.append(exact)
        for key in (() if exact else ("task_id", "batch_id", "run_id", "chain", "workflow", "driver", "status", "outcome", "first_node_code")):
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
                start_bound = (center - timedelta(minutes=30)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                end_bound = (center + timedelta(minutes=30)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                clauses.append(
                    "((i.updated_at>=? AND i.updated_at<=?) OR EXISTS ("
                    "SELECT 1 FROM diagnostic_events et WHERE et.incident_id=i.incident_id "
                    "AND et.occurred_at>=? AND et.occurred_at<=?))"
                )
                params.extend((start_bound, end_bound, start_bound, end_bound))
            except (TypeError, ValueError, OverflowError):
                pass
        date_only = _safe_text(query.get("date"), 40)
        if date_only and not exact and not time_point and not query.get("from") and not query.get("to"):
            start_bound = _search_bound(date_only)
            end_bound = _search_bound(date_only, end_of_day=True)
            clauses.append(
                "((i.updated_at>=? AND i.updated_at<=?) OR EXISTS ("
                "SELECT 1 FROM diagnostic_events ed WHERE ed.incident_id=i.incident_id "
                "AND ed.occurred_at>=? AND ed.occurred_at<=?))"
            )
            params.extend((start_bound, end_bound, start_bound, end_bound))
        from_value = query.get("from")
        to_value = query.get("to")
        if from_value and to_value and not exact and not time_point:
            start_bound = _search_bound(from_value)
            end_bound = _search_bound(to_value, end_of_day=True)
            clauses.append(
                "((i.updated_at>=? AND i.updated_at<=?) OR EXISTS ("
                "SELECT 1 FROM diagnostic_events ef WHERE ef.incident_id=i.incident_id "
                "AND ef.occurred_at>=? AND ef.occurred_at<=?))"
            )
            params.extend((start_bound, end_bound, start_bound, end_bound))
        elif from_value and not exact and not time_point:
            start_bound = _search_bound(from_value)
            clauses.append("(i.updated_at>=? OR EXISTS (SELECT 1 FROM diagnostic_events ef WHERE ef.incident_id=i.incident_id AND ef.occurred_at>=?))")
            params.extend((start_bound, start_bound))
        elif to_value and not exact and not time_point:
            end_bound = _search_bound(to_value, end_of_day=True)
            clauses.append("(i.updated_at<=? OR EXISTS (SELECT 1 FROM diagnostic_events et WHERE et.incident_id=i.incident_id AND et.occurred_at<=?))")
            params.extend((end_bound, end_bound))
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
            for key, label in (("task_id", "任务 ID"), ("batch_id", "批次 ID"), ("run_id", "运行 ID"), ("chain", "链路"), ("workflow", "工作流"), ("driver", "驱动"), ("subject", "账号 HMAC 指纹"), ("email", "邮箱 HMAC 指纹"), ("account", "账号 HMAC 指纹"), ("date", "日期全天"), ("from", "开始时间"), ("to", "结束时间"), ("time_point", "时间点 ±30 分钟")):
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
            payload["integrity_status"] = self.verify_incident(db, incident_id)
            return payload

    def verify_incident(self, db: sqlite3.Connection, incident_id: str) -> str:
        rows = db.execute("SELECT * FROM diagnostic_events WHERE incident_id=? ORDER BY rowid ASC", (incident_id,)).fetchall()
        previous = ""
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
        try:
            with self._lock, self._connection() as db:
                incidents = int(db.execute("SELECT COUNT(*) FROM diagnostic_incidents").fetchone()[0])
                events = int(db.execute("SELECT COUNT(*) FROM diagnostic_events").fetchone()[0])
                failed = int(db.execute("SELECT COUNT(*) FROM diagnostic_incidents WHERE integrity_status='failed'").fetchone()[0])
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
            "index_status": "unavailable" if read_error else "degraded" if audit_write_failures else "ok",
            "hash_status": "failed" if failed else "verified",
            "storage_status": "unavailable" if read_error else "degraded" if write_failures else "ok",
            "read_error": read_error,
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
