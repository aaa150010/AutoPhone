"""Persistent, credential-redacted logs for the isolated Free runtime."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from .free_failure_runtime import sanitize_failure_text, sanitize_log_message, sanitize_safe_page
    from .free_register_common import FREE_STAGE_LABELS, atomic_write, fingerprint, safe_log_message
    from .diagnostic_writer import DiagnosticEventWriter, LogContext
except ImportError:
    from free_failure_runtime import sanitize_failure_text, sanitize_log_message, sanitize_safe_page  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FREE_STAGE_LABELS,
        atomic_write,
        fingerprint,
        safe_log_message,
    )
    from diagnostic_writer import DiagnosticEventWriter, LogContext  # type: ignore[no-redef]


_CANONICAL_INCIDENT_RE = re.compile(
    r"^LOG-(?P<date>\d{8})-(?P<suffix>[A-Z0-9]{8})$",
    re.IGNORECASE,
)
_LEGACY_INCIDENT_RE = re.compile(
    r"^LOG-(?P<phone>\+?\d{8,15})-(?P<suffix>[A-Z0-9]{8})$",
    re.IGNORECASE,
)


def _incident_date_from_time(value: Any) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
        text,
    ):
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%Y%m%d")
    except (TypeError, ValueError, OverflowError):
        return ""


def _valid_incident_date(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y%m%d")
    except (TypeError, ValueError):
        return False
    return True


class FreeLogStore:
    """Persist one stable, credential-safe shape for every Free log row.

    The log file predates the structured diagnostics fields, so reads also
    normalize and migrate legacy rows.  This keeps the public API predictable
    after an upgrade without exposing arbitrary legacy keys that may contain
    credentials.
    """

    REQUIRED_FIELDS = (
        "time", "level", "task_id", "node_code", "node_label", "attempt",
        "duration_ms", "page_type", "safe_page", "http_status", "provider_code",
        "outcome", "diagnostic", "action_hint", "result", "incident_id",
        "debug_session_id", "debug_artifact_id", "artifact_id",
    )
    _KNOWN_FIELDS = frozenset({
        "time", "level", "message", "task_id", "stage", "stage_label",
        "node_code", "node_label", "error_code", "provider_code", "page",
        "safe_page", "page_type", "content_type", "session_rebuilds",
        "http_status", "attempt", "duration_ms", "outcome", "diagnostic",
        "technical_summary", "action_hint", "retryable", "result", "incident_id",
        "declared_scheme", "transport_scheme", "target_domain", "request_stage",
        "retry_count", "transport_error_code",
        "debug_session_id", "debug_artifact_id", "artifact_id",
        "retry_after_seconds",
        "substep_code", "substep_label",
    })
    _SCHEMES = frozenset({"http", "https", "socks4", "socks5", "socks5h"})
    _TRANSPORT_CODES = frozenset({
        "proxy_protocol_mismatch", "proxy_auth_rejected", "proxy_dns_failed",
        "proxy_connect_timeout", "proxy_connection_reset",
        "proxy_tls_certificate_error", "proxy_connect_failed", "tls_connection_failed",
    })

    def __init__(
        self,
        data_dir: str | Path,
        *,
        limit: int = 5000,
        task_limit: int = 5000,
        diagnostic_store: Any = None,
        diagnostic_writer: Any = None,
        legacy_projection: bool | None = None,
        cleanup_legacy: bool = False,
        strict_diagnostic_reads: bool = False,
        workflow: str | None = None,
        driver: str | None = None,
    ) -> None:
        """Create the Free log facade.

        ``legacy_projection`` controls whether the obsolete JSON compatibility
        projection is written/read.  New runtime assembly should set it to
        ``False`` so SQLite diagnostics are the sole source of truth.  When the
        option is omitted, a diagnostic-backed store defaults to structured
        mode unless old JSON files are present (which preserves a safe upgrade
        path for an operator who has not run the cleanup command yet); callers
        without a diagnostic store retain the historical JSON behavior.
        """
        # Keep the caller's lexical root for the one-shot maintenance helper.
        # Resolving it before cleanup would bypass that helper's symlink guard
        # and could make a link named ``free_register`` point deletion at an
        # unrelated directory.  The resolved path remains the compatibility
        # location used for normal legacy reads/writes.
        self._data_dir_input = Path(data_dir).expanduser()
        self.path = self._data_dir_input.resolve() / "logs.json"
        self.task_dir = self.path.parent / "task_logs"
        self.limit = max(50, int(limit))
        self.task_limit = max(100, int(task_limit))
        self.diagnostic_store = diagnostic_store or getattr(diagnostic_writer, "store", None)
        self.legacy_projection = bool(legacy_projection) if legacy_projection is not None else True
        self.strict_diagnostic_reads = bool(strict_diagnostic_reads)
        self.diagnostic_writer = diagnostic_writer
        if self.diagnostic_writer is None and diagnostic_store is not None:
            self.diagnostic_writer = DiagnosticEventWriter(
                diagnostic_store,
                context=LogContext(chain="free", workflow="register", driver="free"),
            )
        writer_context = getattr(self.diagnostic_writer, "context", None)
        inferred_workflow = getattr(writer_context, "workflow", "") if writer_context is not None else ""
        inferred_driver = getattr(writer_context, "driver", "") if writer_context is not None else ""
        # ``free`` is the historical generic driver used by manager-level
        # events; it must not hide concrete protocol/Camoufox events.
        self.workflow_scope = str(workflow or inferred_workflow or "").strip().lower()
        self.driver_scope = str(driver or (inferred_driver if inferred_driver not in {"", "free", "unknown"} else "")).strip().lower()
        self.legacy_cleanup_result: Any = None
        if cleanup_legacy:
            # Startup cleanup is opt-in at this compatibility boundary so
            # library users can still inspect an old installation before
            # migrating. The production Free assembly enables it explicitly.
            try:
                from .free_log_migration import cleanup_legacy_logs
            except ImportError:  # pragma: no cover
                from free_log_migration import cleanup_legacy_logs  # type: ignore[no-redef]
            try:
                self.legacy_cleanup_result = cleanup_legacy_logs(
                    self._data_dir_input,
                    diagnostic_store=self.diagnostic_store,
                )
            except Exception as exc:
                # A cleanup problem must never prevent the registration UI
                # from starting; callers can inspect this result and emit a
                # structured system event.
                self.legacy_cleanup_result = {
                    "failed": True,
                    "error_type": type(exc).__name__,
                }
                self._record_cleanup_failure(type(exc).__name__)
        if legacy_projection is None and diagnostic_store is not None:
            try:
                has_legacy_files = self.path.is_file() or any(
                    self.task_dir.glob("*.json")
                )
            except OSError:
                has_legacy_files = False
            self.legacy_projection = bool(has_legacy_files)
        self._lock = threading.RLock()
        self._legacy_incident_map: dict[str, str] | None = None
        self._legacy_files_migrated = False

    def _record_cleanup_failure(self, error_type: str = "unknown") -> None:
        """Best-effort structured event for a maintenance failure.

        ``cleanup_legacy_logs`` records filesystem failures itself when it can
        reach its normal error boundary.  This fallback covers constructor
        errors (for example a rejected/non-isolated path) without allowing a
        maintenance problem to abort Free startup.
        """
        writer = self.diagnostic_writer
        if writer is None:
            return
        try:
            writer.record({
                "chain": "free",
                "workflow": "maintenance",
                "driver": "free",
                "node_code": "free_log_cleanup",
                "node_label": "清理 Free 旧日志",
                "outcome": "failed",
                "level": "error",
                "message": "旧日志清理未完成",
                "failure": {
                    "error_code": "free_log_cleanup_failed",
                    "retryable": True,
                    "technical_summary": "旧日志清理未完成",
                    "transport_error_code": str(error_type or "unknown")[:80],
                },
            })
        except Exception:
            pass

    @staticmethod
    def _number(value: Any, *, maximum: int = 1_000_000) -> int | None:
        if isinstance(value, bool) or value in (None, ""):
            return None
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            return None
        return max(0, min(maximum, number))

    @staticmethod
    def _safe_time(value: Any) -> str:
        text = str(value or "").strip()
        if re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
            text,
        ):
            return text
        return ""

    @classmethod
    def _normalize_incident_id(
        cls,
        value: Any,
        row_time: Any = "",
        legacy_map: Mapping[str, str] | None = None,
    ) -> str:
        """Return only a valid date-based incident ID.

        Very old Free logs used ``LOG-<phone>-<suffix>``. The phone portion
        must never reach the public log shape. When a legacy ID can be mapped
        to exactly one UTC date from the row timestamp (and all rows carrying
        that ID agree), it is rewritten to the current date-based format;
        ambiguous or malformed IDs are discarded.
        """
        text = str(value or "").strip().upper()
        canonical = _CANONICAL_INCIDENT_RE.fullmatch(text)
        if canonical and _valid_incident_date(canonical.group("date")):
            return f"LOG-{canonical.group('date')}-{canonical.group('suffix')}"
        legacy = _LEGACY_INCIDENT_RE.fullmatch(text)
        if not legacy:
            return ""
        row_date = _incident_date_from_time(row_time)
        mapped = str((legacy_map or {}).get(text) or "")
        if not row_date or not mapped or row_date != mapped:
            return ""
        suffix = legacy.group("suffix").upper()
        return f"LOG-{mapped}-{suffix}" if _valid_incident_date(mapped) else ""

    @classmethod
    def _normalize_row(
        cls,
        value: Mapping[str, Any],
        *,
        legacy_map: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        raw = dict(value)
        message = sanitize_log_message(raw.get("message"), 800)
        level = sanitize_failure_text(raw.get("level"), 32) or "info"
        # Generated task IDs intentionally contain numeric shards.  Keep the
        # identifier joinable while allowing only identifier characters, so a
        # malicious legacy value cannot carry a URL or credential.
        task_id = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(raw.get("task_id") or "")).strip("_.:-")[:160]
        if task_id and not task_id.startswith("free-"):
            task_id = ""
        node_code = sanitize_failure_text(raw.get("node_code") or raw.get("stage"), 160)
        node_label = sanitize_failure_text(raw.get("node_label") or raw.get("stage_label"), 160)
        if node_code and not node_label:
            node_label = sanitize_failure_text(FREE_STAGE_LABELS.get(node_code, node_code), 160)
        safe_page = sanitize_safe_page(raw.get("safe_page") or raw.get("page"))
        technical_summary = sanitize_failure_text(raw.get("technical_summary"), 800)
        diagnostic = sanitize_failure_text(raw.get("diagnostic") or technical_summary, 800)
        declared_scheme = sanitize_failure_text(raw.get("declared_scheme"), 20).lower()
        transport_scheme = sanitize_failure_text(raw.get("transport_scheme"), 20).lower()
        transport_error_code = sanitize_failure_text(raw.get("transport_error_code"), 80)
        target_domain = sanitize_failure_text(raw.get("target_domain"), 255).lower()
        try:
            target_domain = str(urlsplit(target_domain).hostname or target_domain).lower()
        except (TypeError, ValueError):
            target_domain = ""
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?", target_domain):
            target_domain = ""
        debug_fields: dict[str, str] = {}
        for key in ("debug_session_id", "debug_artifact_id", "artifact_id"):
            candidate = str(raw.get(key) or "").strip()
            debug_fields[key] = (
                candidate
                if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}", candidate)
                else ""
            )
        row: dict[str, Any] = {
            "time": cls._safe_time(raw.get("time")),
            "level": level,
            "message": message,
            "task_id": task_id,
            "stage": sanitize_failure_text(raw.get("stage") or node_code, 160),
            "stage_label": sanitize_failure_text(raw.get("stage_label") or node_label, 160),
            "node_code": node_code,
            "node_label": node_label,
            "error_code": sanitize_failure_text(raw.get("error_code"), 160),
            "provider_code": sanitize_failure_text(raw.get("provider_code"), 160),
            "page": safe_page,
            "safe_page": safe_page,
            "page_type": sanitize_failure_text(raw.get("page_type"), 120),
            "content_type": sanitize_failure_text(raw.get("content_type"), 160),
            "session_rebuilds": cls._number(raw.get("session_rebuilds"), maximum=100),
            "http_status": cls._number(raw.get("http_status"), maximum=999),
            "attempt": cls._number(raw.get("attempt"), maximum=100_000),
            "duration_ms": cls._number(raw.get("duration_ms"), maximum=86_400_000),
            "outcome": sanitize_failure_text(raw.get("outcome"), 80),
            "diagnostic": diagnostic,
            "technical_summary": technical_summary,
            "action_hint": sanitize_failure_text(raw.get("action_hint"), 400),
            "result": sanitize_failure_text(raw.get("result"), 800),
            "incident_id": cls._normalize_incident_id(raw.get("incident_id"), raw.get("time"), legacy_map),
            "declared_scheme": declared_scheme if declared_scheme in cls._SCHEMES else "",
            "transport_scheme": transport_scheme if transport_scheme in cls._SCHEMES else "",
            "target_domain": target_domain,
            "request_stage": sanitize_failure_text(raw.get("request_stage"), 120),
            "retry_count": cls._number(raw.get("retry_count"), maximum=100),
            "retry_after_seconds": cls._number(raw.get("retry_after_seconds"), maximum=86400),
            "transport_error_code": transport_error_code if transport_error_code in cls._TRANSPORT_CODES else "",
            **debug_fields,
            "substep_code": sanitize_failure_text(raw.get("substep_code"), 120),
            "substep_label": sanitize_failure_text(raw.get("substep_label"), 160),
        }
        retryable = raw.get("retryable")
        if isinstance(retryable, bool):
            row["retryable"] = retryable
        elif isinstance(retryable, str) and retryable.strip().lower() in {"true", "false"}:
            row["retryable"] = retryable.strip().lower() == "true"
        # Keep only known, redacted fields.  In particular, do not carry an
        # unknown legacy ``token``/``cookie`` key into the public API.
        return {key: item for key, item in row.items() if key in cls._KNOWN_FIELDS}

    @classmethod
    def _load(
        cls,
        path: Path,
        *,
        legacy_map: Mapping[str, str] | None = None,
        migration_state: dict[str, bool] | None = None,
    ) -> list[dict[str, Any]]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return []
        if not isinstance(value, list):
            return []
        rows = [cls._normalize_row(item, legacy_map=legacy_map) for item in value if isinstance(item, dict)]
        # Migrate old rows on read so the persisted file and the API have the
        # same complete shape.  A failed best-effort migration must not make
        # log viewing fail.
        if rows != [item for item in value if isinstance(item, dict)]:
            try:
                atomic_write(path, rows)
            except Exception:
                if migration_state is not None:
                    migration_state["write_failed"] = True
        return rows

    def _task_path(self, task_id: str) -> Path:
        return self.task_dir / f"{fingerprint(task_id)}.json"

    def _legacy_incident_mapping(self) -> dict[str, str]:
        """Build a deterministic mapping for legacy IDs across all log files."""
        if self._legacy_incident_map is not None:
            return self._legacy_incident_map
        candidates: dict[str, set[str]] = {}
        canonical_ids: set[str] = set()
        diagnostic_index_unavailable = False
        paths = [self.path]
        try:
            # ``Path.glob`` follows a symlinked directory.  Legacy files are
            # untrusted input, so never inspect a task-log directory that
            # resolves outside this Free-owned directory.
            if not self.task_dir.is_symlink():
                paths.extend(sorted(self.task_dir.glob("*.json")))
        except OSError:
            pass
        for path in paths:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(raw, list):
                continue
            for item in raw:
                if not isinstance(item, Mapping):
                    continue
                incident = str(item.get("incident_id") or "").strip().upper()
                canonical = _CANONICAL_INCIDENT_RE.fullmatch(incident)
                if canonical and _valid_incident_date(canonical.group("date")):
                    canonical_ids.add(f"LOG-{canonical.group('date')}-{canonical.group('suffix')}")
                legacy = _LEGACY_INCIDENT_RE.fullmatch(incident)
                if not legacy:
                    continue
                date = _incident_date_from_time(item.get("time"))
                if date and _valid_incident_date(date):
                    candidates.setdefault(incident, set()).add(date)
                else:
                    # A malformed or missing timestamp makes the legacy ID
                    # impossible to map safely. Keep an explicit sentinel so
                    # another valid row cannot accidentally authorize a
                    # partial migration.
                    candidates.setdefault(incident, set()).add("")
        # A legacy row must not be rewritten to an ID already owned by the
        # structured diagnostic index.  Otherwise a phone-bearing log could
        # silently alias an unrelated incident (or merge two histories).
        diagnostic_paths: list[Path] = []
        store_path = getattr(self.diagnostic_store, "path", None)
        if store_path:
            diagnostic_paths.append(Path(store_path).expanduser())
        diagnostic_paths.extend(edited for edited in (
            self.path.parent / "diagnostics.sqlite3",
            self.path.parent / "diagnostics" / "diagnostics.sqlite3",
            self.path.parent.parent / "diagnostics" / "diagnostics.sqlite3",
        ))
        seen_diagnostic_paths: set[str] = set()
        for diagnostic_path in diagnostic_paths:
            try:
                resolved = diagnostic_path.resolve()
            except OSError:
                continue
            key = str(resolved)
            if key in seen_diagnostic_paths or not resolved.is_file():
                continue
            seen_diagnostic_paths.add(key)
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(
                    f"file:{resolved.as_posix()}?mode=ro",
                    uri=True,
                    timeout=0.2,
                )
                readable_tables = 0
                for table in ("diagnostic_incidents", "diagnostic_events", "diagnostic_incident_ids"):
                    try:
                        rows = connection.execute(f"SELECT incident_id FROM {table}").fetchall()
                    except sqlite3.Error:
                        continue
                    readable_tables += 1
                    for row in rows:
                        value = str(row[0] or "").strip().upper()
                        match = _CANONICAL_INCIDENT_RE.fullmatch(value)
                        if match and _valid_incident_date(match.group("date")):
                            canonical_ids.add(f"LOG-{match.group('date')}-{match.group('suffix')}")
                if readable_tables == 0:
                    diagnostic_index_unavailable = True
            except (OSError, sqlite3.Error):
                # Legacy migration remains best effort. If the independent
                # diagnostic index cannot be read, do not guess a mapping from
                # a potentially conflicting ID.
                diagnostic_index_unavailable = True
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except sqlite3.Error:
                        pass
        if diagnostic_index_unavailable:
            # A legacy phone-bearing ID is never safe to correlate while an
            # existing diagnostic index is unreadable. Returning no mappings
            # causes the normalizer to clear the ID instead of guessing.
            self._legacy_incident_map = {}
            return self._legacy_incident_map
        proposed = {
            incident: next(iter(dates))
            for incident, dates in candidates.items()
            if len(dates) == 1 and next(iter(dates))
        }
        # Two distinct phone-bearing legacy IDs can share a suffix. Mapping
        # both to one canonical ID would merge unrelated history, so reject
        # every colliding target instead of guessing.
        targets: dict[str, list[str]] = {}
        for incident, date in proposed.items():
            suffix = incident.rsplit("-", 1)[-1]
            targets.setdefault(f"LOG-{date}-{suffix}", []).append(incident)
        colliding = {
            target
            for target, incidents in targets.items()
            if len(incidents) > 1
        }
        colliding.update(target for target in targets if target in canonical_ids)
        self._legacy_incident_map = {
            incident: date
            for incident, date in proposed.items()
            if f"LOG-{date}-{incident.rsplit('-', 1)[-1]}" not in colliding
        }
        return self._legacy_incident_map

    def _migrate_legacy_files(self) -> None:
        """Normalize both the global file and every task log in one pass."""
        if self._legacy_files_migrated:
            return
        mapping = self._legacy_incident_mapping()
        migration_state = {"write_failed": False}
        paths = [self.path]
        try:
            paths.extend(sorted(self.task_dir.glob("*.json")))
        except OSError:
            pass
        for path in paths:
            self._load(path, legacy_map=mapping, migration_state=migration_state)
        self._legacy_files_migrated = not migration_state["write_failed"]
        if migration_state["write_failed"]:
            # Re-scan the files on the next access in case the diagnostic
            # index or another external dependency became available.
            self._legacy_incident_map = None

    def _load_for_store(self, path: Path) -> list[dict[str, Any]]:
        self._migrate_legacy_files()
        return self._load(path, legacy_map=self._legacy_incident_mapping())

    @classmethod
    def _event_row(cls, event: Mapping[str, Any], incident_id: str = "") -> dict[str, Any]:
        """Project one structured diagnostic event to the legacy log shape.

        This projection is intentionally one-way: it is used only by old API
        consumers when ``legacy_projection`` is disabled.  Unknown event
        fields and private subject references never cross this boundary.
        """
        failure = event.get("failure")
        if not isinstance(failure, Mapping):
            failure = {}
        transport = event.get("transport")
        if not isinstance(transport, Mapping):
            transport = {}
        outcome = sanitize_failure_text(event.get("outcome"), 80)
        level = "error" if outcome in {"error", "failed", "failure", "stopped"} else outcome or "info"
        row: dict[str, Any] = {
            "time": str(event.get("occurred_at") or event.get("received_at") or ""),
            "level": level,
            "message": event.get("message") or "",
            "task_id": event.get("task_id") or "",
            "stage": event.get("stage_group") or event.get("node_code") or "",
            "stage_label": event.get("node_label") or "",
            "node_code": event.get("node_code") or "",
            "node_label": event.get("node_label") or "",
            "error_code": failure.get("error_code") or "",
            "provider_code": failure.get("provider_code") or "",
            "safe_page": failure.get("safe_page") or "",
            "page": failure.get("safe_page") or "",
            "page_type": failure.get("page_type") or "",
            "content_type": failure.get("content_type") or "",
            "session_rebuilds": failure.get("session_rebuilds"),
            "http_status": failure.get("http_status") or transport.get("http_status"),
            "attempt": event.get("attempt"),
            "duration_ms": event.get("elapsed_ms"),
            "outcome": outcome,
            "diagnostic": failure.get("diagnostic") or failure.get("technical_summary") or "",
            "technical_summary": failure.get("technical_summary") or "",
            "action_hint": failure.get("action_hint") or "",
            "retryable": failure.get("retryable"),
            "result": "",
            "incident_id": incident_id or event.get("incident_id") or "",
            "debug_session_id": failure.get("debug_session_id") or "",
            "debug_artifact_id": failure.get("debug_artifact_id") or "",
            "artifact_id": failure.get("artifact_id") or "",
            "declared_scheme": failure.get("declared_scheme") or "",
            "transport_scheme": failure.get("transport_scheme") or "",
            "target_domain": failure.get("target_domain") or transport.get("target_domain") or "",
            "request_stage": failure.get("request_stage") or transport.get("request_stage") or "",
            "retry_count": failure.get("retry_count"),
            "transport_error_code": failure.get("transport_error_code") or "",
            "retry_after_seconds": failure.get("retry_after_seconds"),
        }
        return cls._normalize_row(row)

    def _diagnostic_snapshot(
        self,
        task_id: str = "",
        *,
        workflow: str = "",
        driver: str = "",
    ) -> list[dict[str, Any]]:
        """Read compatibility rows from the structured diagnostic source."""
        if self.diagnostic_store is None:
            return []
        try:
            query: dict[str, Any] = {"limit": min(self.limit, 500)}
            if task_id:
                query["task_id"] = task_id
            workflow_scope = str(workflow or self.workflow_scope or "").strip().lower()
            driver_scope = str(driver or self.driver_scope or "").strip().lower()
            if workflow_scope:
                query["workflow"] = workflow_scope
            if driver_scope:
                query["driver"] = driver_scope
            incidents = self.diagnostic_store.search(query)
            rows: list[dict[str, Any]] = []
            for summary in incidents:
                if not isinstance(summary, Mapping):
                    continue
                incident_id = str(summary.get("incident_id") or "")
                detail = self.diagnostic_store.incident(incident_id) if incident_id else None
                events = detail.get("events") if isinstance(detail, Mapping) else None
                if not isinstance(events, list):
                    # A compatible/injected store may return event rows directly.
                    events = [summary]
                for event in events:
                    if not isinstance(event, Mapping):
                        continue
                    if task_id and str(event.get("task_id") or "") != task_id:
                        continue
                    if workflow_scope and str(event.get("workflow") or "").strip().lower() != workflow_scope:
                        continue
                    if driver_scope and str(event.get("driver") or "").strip().lower() != driver_scope:
                        continue
                    rows.append(self._event_row(event, incident_id))
            rows.sort(key=lambda row: str(row.get("time") or ""))
            return rows[-self.task_limit:] if task_id else rows[-self.limit:]
        except Exception:
            # Public log reads must retain the existing best-effort behavior;
            # route-level code reports a structured failure when a strict
            # diagnostic read is required.
            if self.strict_diagnostic_reads:
                raise
            return []

    def add(self, message: Any, level: str = "info", **fields: Any) -> None:
        with self._lock:
            rows = self._load_for_store(self.path) if self.legacy_projection else []
            source_text = safe_log_message(message)
            text = sanitize_log_message(source_text)
            # Transport observations are kept in the append-only diagnostic
            # index, where its strict scalar allowlist can redact them.  Do
            # not copy this map into the legacy Free log row or merge it into
            # the failure payload: a successful HTTP observation is not a
            # business failure.
            transport_payload = fields.get("transport")
            if not isinstance(transport_payload, Mapping):
                transport_payload = {}
            match = re.search(r"\[([^\]/]{1,160})/([^\]/]{1,160})(?:/([^\]]{1,160}))?\]", source_text)
            task_id = str(fields.get("task_id") or "")
            if not task_id:
                task_id = match.group(1) if match and match.group(1).startswith("free-") else ""
            # Runtime callbacks historically accepted only (message, level).
            # Accept optional safe metadata as well, so newer account logs can
            # expose timing/page/HTTP summaries without changing that contract.
            metadata = {}
            for key in (
                "stage", "stage_label", "node_code", "node_label", "error_code",
                "provider_code", "page", "safe_page", "http_status", "attempt",
                "outcome", "duration_ms", "result", "diagnostic", "technical_summary",
                "action_hint", "retryable", "page_type", "content_type", "session_rebuilds",
                "declared_scheme", "transport_scheme", "target_domain", "request_stage",
                "retry_count", "transport_error_code",
                "retry_after_seconds",
                "debug_session_id", "debug_artifact_id", "artifact_id",
                "substep_code", "substep_label",
            ):
                value = fields.get(key)
                if value not in (None, ""):
                    # Metadata can arrive from recovered exceptions as well as
                    # hand-written stage logs. Apply the same redactor as the
                    # message so a diagnostic field cannot bypass log safety.
                    if key in {"session_rebuilds", "retry_count", "retry_after_seconds"}:
                        try:
                            metadata[key] = max(0, min(100, int(value)))
                        except (TypeError, ValueError):
                            continue
                    elif isinstance(value, bool) or isinstance(value, (int, float)):
                        metadata[key] = value
                    elif key in {"page", "safe_page"}:
                        metadata[key] = sanitize_safe_page(value)
                    else:
                        metadata[key] = sanitize_failure_text(value)
            for key, value in re.findall(
                r"(?:^|\s)(page|safe_page|page_type|content_type|session_rebuilds|http_status|attempt|outcome|duration_ms|result|diagnostic|action_hint|provider_code|declared_scheme|transport_scheme|target_domain|request_stage|retry_count|retry_after_seconds|transport_error_code)=([^\s]+)",
                source_text,
            ):
                if key not in metadata:
                    if key in {"page", "safe_page"}:
                        metadata[key] = sanitize_safe_page(value)
                    elif key in {"session_rebuilds", "http_status", "attempt", "duration_ms", "retry_count", "retry_after_seconds"}:
                        try:
                            metadata[key] = max(0, int(value))
                        except (TypeError, ValueError):
                            continue
                    else:
                        metadata[key] = sanitize_failure_text(value)
            page_match = re.search(r"(?:页面|位置)[= 为：]+(https?://[^\s，）]+|页面地址未知)", source_text)
            http_match = re.search(r"\bHTTP\s+(\d{3})\b", source_text, re.IGNORECASE)
            attempt_match = re.search(r"第\s*(\d+)\s*次", source_text)
            duration_match = re.search(r"耗时[=：]\s*(\d+)\s*ms", source_text, re.IGNORECASE)
            if page_match and "page" not in metadata:
                metadata["page"] = sanitize_safe_page(page_match.group(1))
            if http_match and "http_status" not in metadata:
                metadata["http_status"] = int(http_match.group(1))
            if attempt_match and "attempt" not in metadata:
                metadata["attempt"] = int(attempt_match.group(1))
            if duration_match and "duration_ms" not in metadata:
                metadata["duration_ms"] = int(duration_match.group(1))
            if "outcome" not in metadata and str(level or "info") in {"success", "warn", "error"}:
                metadata["outcome"] = str(level or "info")
            prefix_task = bool(match and match.group(1).startswith("free-"))
            node_code = str(metadata.get("node_code") or (match.group(3) if match else "") or (match.group(2) if match and not match.group(3) else ""))
            node_label = str(
                metadata.get("node_label")
                or (match.group(2) if match and match.group(3) else "")
                or (match.group(1) if match and not prefix_task else "")
            )
            row = self._normalize_row({
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "level": str(level or "info"),
                "message": text,
                "task_id": task_id,
                "stage": str(metadata.get("stage") or node_code),
                "stage_label": str(metadata.get("stage_label") or node_label),
                "node_code": node_code,
                "node_label": node_label,
                **metadata,
            })
            structured_failure: dict[str, Any] = {}
            raw_failure = fields.get("failure")
            if isinstance(raw_failure, Mapping):
                for key in (
                    "error_code", "provider_code", "public_message", "technical_summary",
                    "diagnostic", "action_hint", "retryable", "http_status", "page_type",
                    "safe_page", "debug_session_id", "debug_artifact_id", "artifact_id",
                ):
                    value = raw_failure.get(key)
                    if value in (None, ""):
                        continue
                    if isinstance(value, bool) or isinstance(value, (int, float)):
                        structured_failure[key] = value
                    elif key == "safe_page":
                        structured_failure[key] = sanitize_safe_page(value)
                    else:
                        structured_failure[key] = sanitize_failure_text(value)
            if self.diagnostic_store is not None or self.diagnostic_writer is not None:
                try:
                    failure_payload = dict(structured_failure)
                    failure_outcome = str(row.get("outcome") or level or "").strip().lower()
                    failure_signal = bool(structured_failure) or failure_outcome in {
                        "error", "failed", "failure", "stopped",
                    } or str(level or "").strip().lower() in {"error", "danger"}
                    if not failure_signal:
                        # HTTP/media-type observations are transport evidence,
                        # not business failures. Keep them in ``transport`` so
                        # a successful 200 response cannot become the incident
                        # root cause through the legacy row metadata path.
                        failure_payload = {}
                    else:
                        failure_payload.update({
                            key: row.get(key)
                            for key in (
                                "error_code", "provider_code", "technical_summary", "diagnostic",
                                "action_hint", "retryable", "http_status", "debug_session_id",
                                "debug_artifact_id", "artifact_id",
                            )
                            if row.get(key) not in (None, "")
                        })
                    writer = self.diagnostic_writer
                    if writer is None:
                        writer = DiagnosticEventWriter(self.diagnostic_store)
                    incident_id = writer.record({
                        "level": level,
                        "outcome": row.get("outcome") or level,
                        "message": row.get("message"),
                        "task_id": task_id,
                        "node_code": row.get("node_code"),
                        "node_label": row.get("node_label"),
                        "failure": failure_payload,
                        "duration_ms": row.get("duration_ms"),
                        "chain": fields.get("chain") or "free",
                        "workflow": fields.get("workflow") or "register",
                        "driver": fields.get("driver") or "free",
                        "batch_id": fields.get("batch_id") or "",
                        # Accept the complete subject vocabulary used by the
                        # structured writer.  Rebind and transport callers
                        # commonly provide ``subject_ref`` (or ``account``)
                        # instead of the legacy ``email`` key; dropping it
                        # here would split one task across unrelated
                        # diagnostic incidents and lose the safe display
                        # mask.  The writer hashes/redacts the value before
                        # it reaches the diagnostic store.
                        "subject_kind": fields.get("subject_kind") or (
                            "email"
                            if fields.get("email") or fields.get("subject_ref") or fields.get("account")
                            else ""
                        ),
                        "subject_ref": fields.get("subject_ref") or fields.get("email") or fields.get("account") or "",
                        "subject_ref_fingerprint": fields.get("subject_ref_fingerprint") or "",
                        "subject_display": fields.get("subject_display") or fields.get("email_masked") or "",
                        "stage_group": row.get("stage") or "",
                        "attempt": row.get("attempt"),
                        "transport": transport_payload,
                    })
                    if incident_id:
                        row["incident_id"] = self._normalize_incident_id(
                            incident_id,
                            row.get("time"),
                            self._legacy_incident_mapping() if self.legacy_projection else None,
                        )
                except Exception as exc:
                    # Diagnostics must never stop the registration worker.
                    # DiagnosticStore records this failure in its health
                    # counters; keep compatibility with injected legacy
                    # stores that do not expose that hook.
                    diagnostic_note = getattr(self.diagnostic_store, "note_write_failure", None)
                    if callable(diagnostic_note):
                        try:
                            if not getattr(exc, "_diagnostic_store_noted", False):
                                diagnostic_note("free_log_record", exc)
                        except Exception:
                            pass
            if self.legacy_projection:
                rows.append(row)
                atomic_write(self.path, rows[-self.limit:])
                if task_id:
                    task_path = self._task_path(task_id)
                    task_rows = self._load_for_store(task_path)
                    task_rows.append(row)
                    atomic_write(task_path, task_rows[-self.task_limit:])

    def snapshot(
        self,
        task_id: str = "",
        *,
        workflow: str | None = None,
        driver: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            normalized = str(task_id or "").strip()
            if not self.legacy_projection:
                return self._diagnostic_snapshot(
                    normalized,
                    workflow=str(workflow or "").strip().lower(),
                    driver=str(driver or "").strip().lower(),
                )
            if normalized:
                rows = self._load_for_store(self._task_path(normalized))
                if rows:
                    return rows[-self.task_limit:]
                return [row for row in self._load_for_store(self.path) if row.get("task_id") == normalized][-self.task_limit:]
            return self._load_for_store(self.path)[-self.limit:]

    def delete_tasks(self, task_ids: list[str]) -> int:
        normalized = {str(task_id or "").strip() for task_id in task_ids}
        normalized.discard("")
        if not normalized:
            return 0
        with self._lock:
            if self.legacy_projection:
                rows = [row for row in self._load_for_store(self.path) if str(row.get("task_id") or "") not in normalized]
                atomic_write(self.path, rows[-self.limit:])
            deleted = 0
            if self.legacy_projection:
                for task_id in normalized:
                    path = self._task_path(task_id)
                    try:
                        path.unlink()
                        deleted += 1
                    except FileNotFoundError:
                        continue
            if self.diagnostic_store is not None:
                try:
                    diagnostic_deleted = self.diagnostic_store.delete_by_tasks(sorted(normalized))
                    if not self.legacy_projection:
                        deleted = int(diagnostic_deleted or 0)
                except Exception as exc:
                    # Business task deletion remains successful even if the
                    # independent diagnostic index is temporarily unavailable.
                    diagnostic_note = getattr(self.diagnostic_store, "note_write_failure", None)
                    if callable(diagnostic_note):
                        try:
                            diagnostic_note("free_log_delete", exc)
                        except Exception:
                            pass
        return deleted

    def clear(self) -> None:
        with self._lock:
            if self.legacy_projection:
                atomic_write(self.path, [])
                try:
                    if not self.task_dir.is_symlink():
                        for task_path in self.task_dir.glob("*.json"):
                            # Do not follow a file-level symlink either.  A
                            # maintenance clear must only remove files that
                            # physically live below this exact directory.
                            if task_path.is_symlink():
                                continue
                            try:
                                task_path.unlink()
                            except FileNotFoundError:
                                continue
                except OSError:
                    # Keep the historical best-effort clear contract.  The
                    # explicit maintenance command records a structured
                    # failure when operators need to investigate permissions.
                    pass
            elif self.diagnostic_store is not None:
                self.diagnostic_store.clear()

    def cleanup_legacy_logs(self, *, dry_run: bool = False, force: bool = False) -> Any:
        """Run the explicit one-shot cleanup helper for this Free directory."""
        try:
            from .free_log_migration import cleanup_legacy_logs
        except ImportError:  # pragma: no cover
            from free_log_migration import cleanup_legacy_logs  # type: ignore[no-redef]
        result = cleanup_legacy_logs(
            self._data_dir_input,
            dry_run=dry_run,
            force=force,
            diagnostic_store=self.diagnostic_store,
        )
        self.legacy_cleanup_result = result
        return result


__all__ = ["FreeLogStore"]
