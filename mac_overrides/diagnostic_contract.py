"""Shared, credential-safe contracts for the local log center."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class DiagnosticEvent:
    """A normalized append-only event accepted by the diagnostic store."""

    event_id: str
    incident_id: str
    occurred_at: str
    received_at: str
    chain: str
    workflow: str
    driver: str
    run_id: str = ""
    batch_id: str = ""
    task_id: str = ""
    subject_kind: str = ""
    subject_ref: str = ""
    subject_display: str = ""
    stage_group: str = ""
    node_code: str = ""
    node_label: str = ""
    sequence: int = 0
    attempt: int = 0
    attempt_group: str = ""
    outcome: str = "info"
    parent_event_id: str = ""
    root_cause_event_id: str = ""
    elapsed_ms: int | None = None
    failure: Mapping[str, Any] | None = None
    transport: Mapping[str, Any] = field(default_factory=dict)
    message: str = ""
    redaction_applied: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "event_id": self.event_id,
            "incident_id": self.incident_id,
            "occurred_at": self.occurred_at,
            "received_at": self.received_at,
            "elapsed_ms": self.elapsed_ms,
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
            "node_code": self.node_code,
            "node_label": self.node_label,
            "sequence": self.sequence,
            "attempt": self.attempt,
            "attempt_group": self.attempt_group,
            "outcome": self.outcome,
            "parent_event_id": self.parent_event_id,
            "root_cause_event_id": self.root_cause_event_id,
            "failure": dict(self.failure or {}),
            "transport": dict(self.transport or {}),
            "message": self.message,
            "redaction_applied": bool(self.redaction_applied),
        }


__all__ = ["DiagnosticEvent", "SCHEMA_VERSION", "utc_now"]
