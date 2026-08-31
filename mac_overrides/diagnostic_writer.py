"""Small, safe adapter for writing structured diagnostic events.

The runtime has many callback-shaped log functions (``message, level``), while
``DiagnosticStore`` accepts a structured mapping.  This module is the single
translation boundary between those two APIs.  It deliberately projects input
through a fixed allowlist before handing it to the store; raw mailbox/account
identifiers are converted to a store-owned HMAC fingerprint and are never
included in the mapping sent to SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
import threading
import uuid
from typing import Any, Mapping

try:
    from .diagnostic_store import (
        _safe_failure_mapping,
        _safe_transport_mapping,
        _masked_subject,
    )
    from .free_failure_runtime import (
        sanitize_failure_text,
        sanitize_safe_page,
    )
except ImportError:  # pragma: no cover - direct module loading compatibility
    from diagnostic_store import (  # type: ignore[no-redef]
        _safe_failure_mapping,
        _safe_transport_mapping,
        _masked_subject,
    )
    from free_failure_runtime import (  # type: ignore[no-redef]
        sanitize_failure_text,
        sanitize_safe_page,
    )


_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}$")
_INCIDENT_RE = re.compile(r"^LOG-\d{8}-[A-Z0-9]{8}$", re.IGNORECASE)
_HEX_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
_ISO_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
_ALLOWED_FIELDS = frozenset(
    {
        "event_id",
        "incident_id",
        "occurred_at",
        "chain",
        "workflow",
        "driver",
        "run_id",
        "batch_id",
        "task_id",
        "subject_kind",
        "subject_ref",
        "subject_ref_fingerprint",
        "subject_display",
        "stage_group",
        "stage",
        "node_code",
        "node_label",
        "sequence",
        "attempt",
        "attempt_group",
        "safe_page",
        "outcome",
        "parent_event_id",
        "root_cause_event_id",
        "elapsed_ms",
        "duration_ms",
        "failure",
        "transport",
        "message",
        "level",
    }
)
_ID_FIELDS = frozenset(
    {
        "event_id",
        "run_id",
        "batch_id",
        "task_id",
        "stage_group",
        "stage",
        "node_code",
        "attempt_group",
    }
)
_TEXT_FIELDS = frozenset(
    {
        "chain",
        "workflow",
        "driver",
        "outcome",
        "node_label",
    }
)
_INTEGER_FIELDS = frozenset({"sequence", "attempt", "elapsed_ms", "duration_ms"})


def _safe_id(value: Any, *, limit: int = 180) -> str:
    text = str(value or "").replace("\x00", " ").strip()[:limit]
    return text if _SAFE_ID_RE.fullmatch(text) else ""


def _safe_message(value: Any, *, limit: int = 800) -> str:
    """Redact message text while retaining generated structured prefixes."""
    raw = str(value or "").replace("\x00", " ").strip()
    prefix = re.match(r"^\[([^\]]{1,500})\]", raw)
    if prefix is None:
        return sanitize_failure_text(raw, limit)
    parts = prefix.group(1).split("/")[:3]
    safe_parts: list[str] = []
    for index, part in enumerate(parts):
        candidate = part.strip()
        preserve_id = (
            (_SAFE_ID_RE.fullmatch(candidate) is not None)
            and (
                (index == 0 and (candidate.startswith("free-") or candidate.startswith("T")))
                or (index == len(parts) - 1 and (len(parts) >= 2))
            )
        )
        safe_parts.append(candidate[:160] if preserve_id else sanitize_failure_text(candidate, 160))
    head = f"[{'/'.join(safe_parts)}]"
    raw_tail = raw[prefix.end():]
    separator = " " if raw_tail[:1].isspace() else ""
    tail = sanitize_failure_text(raw_tail, max(0, limit - len(head) - len(separator)))
    return (head + separator + tail)[:limit]


class _SequenceState:
    def __init__(self) -> None:
        self.value = 0
        self.lock = threading.Lock()

    def next(self) -> int:
        with self.lock:
            self.value += 1
            return self.value


@dataclass(frozen=True, slots=True)
class LogContext:
    """Stable context inherited by every event emitted by a writer."""

    chain: str = "free"
    workflow: str = "register"
    driver: str = "free"
    run_id: str = ""
    batch_id: str = ""
    task_id: str = ""
    subject_kind: str = ""
    subject_ref: str = ""
    subject_display: str = ""
    stage_group: str = ""
    attempt: int = 0
    attempt_group: str = ""

    def as_fields(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "chain": self.chain,
                "workflow": self.workflow,
                "driver": self.driver,
                "run_id": self.run_id,
                "batch_id": self.batch_id,
                "task_id": self.task_id,
                "subject_kind": self.subject_kind,
                "subject_ref": self.subject_ref,
                "subject_display": self.subject_display,
                "stage_group": self.stage_group,
                "attempt": self.attempt,
                "attempt_group": self.attempt_group,
            }.items()
            if value not in (None, "")
        }

    def bind(self, **overrides: Any) -> "LogContext":
        """Return a child context without mutating an active task context."""
        known = {
            key: value
            for key, value in overrides.items()
            if key in self.__dataclass_fields__
        }
        return replace(self, **known)

    # ``child`` reads naturally at call sites that enter a nested stage.
    child = bind


class DiagnosticEventWriter:
    """Translate callback logs into redacted, append-only diagnostic events.

    ``best_effort`` defaults to true because a diagnostic outage must not stop
    a registration worker.  The underlying ``DiagnosticStore`` still records
    its health counters; callers that need strict behavior can opt into
    ``best_effort=False`` for tests or administrative operations.
    """

    def __init__(
        self,
        store: Any,
        *,
        context: LogContext | Mapping[str, Any] | None = None,
        best_effort: bool = True,
        _sequence_state: _SequenceState | None = None,
    ) -> None:
        self.store = store
        if isinstance(context, LogContext):
            self.context = context
        elif isinstance(context, Mapping):
            self.context = LogContext().bind(**dict(context))
        else:
            self.context = LogContext()
        self.best_effort = bool(best_effort)
        self._sequence_state = _sequence_state or _SequenceState()

    def bind(self, **overrides: Any) -> "DiagnosticEventWriter":
        """Create a writer sharing the store with an overridden context."""
        return DiagnosticEventWriter(
            self.store,
            context=self.context.bind(**overrides),
            best_effort=self.best_effort,
            _sequence_state=self._sequence_state,
        )

    child = bind

    def _next_sequence(self) -> int:
        return self._sequence_state.next()

    def _subject_fields(self, fields: Mapping[str, Any]) -> dict[str, Any]:
        """Convert raw subject input to a fingerprint and display mask."""
        result: dict[str, Any] = {}
        raw_subject = fields.get("subject_ref") or fields.get("email") or fields.get("account")
        supplied = str(fields.get("subject_ref_fingerprint") or "").strip().lower()
        if _HEX_FINGERPRINT_RE.fullmatch(supplied):
            result["subject_ref_fingerprint"] = supplied[:64]
        elif raw_subject not in (None, ""):
            fingerprint = getattr(self.store, "fingerprint", None)
            if callable(fingerprint):
                try:
                    value = str(fingerprint(raw_subject) or "").strip().lower()
                except Exception:
                    value = ""
                if _HEX_FINGERPRINT_RE.fullmatch(value):
                    result["subject_ref_fingerprint"] = value
        kind = str(fields.get("subject_kind") or ("email" if raw_subject else "")).strip().lower()
        if kind:
            result["subject_kind"] = _safe_id(kind, limit=32)
        display = fields.get("subject_display") or fields.get("email_masked") or fields.get("account_masked")
        if display in (None, "") and raw_subject not in (None, ""):
            try:
                display = _masked_subject(raw_subject, kind)
            except Exception:
                display = "已脱敏账号"
        if display not in (None, ""):
            # ``subject_display`` is still untrusted input.  Callers often
            # pass an address here under the assumption that the field name
            # makes it safe; normalize it through the same masking routine as
            # a raw subject before handing the projected mapping to an
            # injected/fake store.  This keeps the writer itself a hard
            # redaction boundary, even when the underlying store is not the
            # built-in DiagnosticStore.
            try:
                masked = _masked_subject(display, kind)
            except Exception:
                masked = "已脱敏账号"
            result["subject_display"] = sanitize_failure_text(masked or "已脱敏账号", 160)
        return result

    def _project(self, fields: Mapping[str, Any]) -> dict[str, Any]:
        merged = self.context.as_fields()
        merged.update(
            {
                key: value
                for key, value in dict(fields).items()
                if key in _ALLOWED_FIELDS
                or key in {"email", "account", "email_masked", "account_masked"}
            }
        )
        projected: dict[str, Any] = {}
        for key, value in merged.items():
            if key in {
                "subject_ref", "email", "account", "email_masked", "account_masked",
                "subject_ref_fingerprint", "subject_display", "subject_kind",
            }:
                continue
            if key not in _ALLOWED_FIELDS:
                continue
            if key in _ID_FIELDS:
                safe = _safe_id(value)
                if safe:
                    projected[key] = safe
            elif key in _TEXT_FIELDS:
                safe = sanitize_failure_text(value, 160)
                if safe:
                    projected[key] = safe.lower() if key in {"chain", "workflow", "driver", "outcome"} else safe
            elif key == "message":
                projected[key] = _safe_message(value, limit=800)
            elif key in _INTEGER_FIELDS:
                try:
                    number = int(value)
                except (TypeError, ValueError):
                    continue
                projected[key] = max(0, min(86_400_000, number))
            elif key == "level":
                safe = sanitize_failure_text(value, 24).lower()
                if safe:
                    projected[key] = safe
            elif key == "incident_id":
                candidate = str(value or "").strip().upper()
                if _INCIDENT_RE.fullmatch(candidate):
                    projected[key] = candidate
            elif key in {"parent_event_id", "root_cause_event_id"}:
                safe = _safe_id(value, limit=80)
                if safe:
                    projected[key] = safe
            elif key in {"failure", "transport"}:
                # The store applies the same allowlist again. Doing it here
                # ensures injected/fake stores receive no arbitrary payload.
                projected[key] = (
                    _safe_failure_mapping(value)
                    if key == "failure"
                    else _safe_transport_mapping(value)
                )
            elif key == "safe_page":
                projected[key] = sanitize_safe_page(value)
            elif key == "occurred_at":
                safe = str(value or "").strip()[:40]
                if _ISO_TIME_RE.fullmatch(safe):
                    projected[key] = safe
        projected.update(self._subject_fields(merged))
        projected.setdefault("event_id", uuid.uuid4().hex)
        if "sequence" not in projected:
            projected["sequence"] = self._next_sequence()
        projected["redaction_applied"] = True
        return projected

    def record(self, fields: Mapping[str, Any] | None = None, **kwargs: Any) -> str:
        payload: dict[str, Any] = {}
        if isinstance(fields, Mapping):
            payload.update(fields)
        payload.update(kwargs)
        projected = self._project(payload)
        try:
            value = self.store.record(projected)
            return str(value or "")
        except Exception as exc:
            if not self.best_effort:
                raise
            note = getattr(self.store, "note_write_failure", None)
            if callable(note) and not getattr(exc, "_diagnostic_store_noted", False):
                try:
                    note("writer_record", exc)
                except Exception:
                    pass
            return ""

    emit = record
    write = record

    def add(self, message: Any, level: str = "info", **fields: Any) -> str:
        fields = dict(fields)
        fields.setdefault("message", message)
        fields.setdefault("level", level)
        fields.setdefault("outcome", level)
        return self.record(fields)

    def __call__(self, message: Any, level: str = "info", **fields: Any) -> str:
        return self.add(message, level, **fields)


__all__ = ["DiagnosticEventWriter", "LogContext"]
