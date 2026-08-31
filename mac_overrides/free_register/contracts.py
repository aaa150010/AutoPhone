"""Dependency-free contracts for Free task orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import copy
import time
from typing import Any, Mapping


class FreeTaskStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    STOPPED = "stopped"
    TWOFA_PENDING = "twofa_pending"


ACTIVE_TASK_STATUSES = frozenset({
    FreeTaskStatus.QUEUED.value,
    FreeTaskStatus.RUNNING.value,
})
TERMINAL_TASK_STATUSES = frozenset({
    FreeTaskStatus.SUCCESS.value,
    FreeTaskStatus.PARTIAL_SUCCESS.value,
    FreeTaskStatus.FAILED.value,
    FreeTaskStatus.STOPPED.value,
    FreeTaskStatus.TWOFA_PENDING.value,
})


def normalize_task_status(value: Any, default: str = "queued") -> str:
    candidate = str(value or default).strip().lower()
    try:
        return FreeTaskStatus(candidate).value
    except ValueError:
        return str(default or "queued").strip().lower()


def _nonnegative_int(value: Any, default: int = 0) -> int:
    """Coerce persisted counters without letting malformed legacy data escape.

    Task snapshots are read at process startup and also through public API
    projections.  A hand-edited/partially-written JSON payload must therefore
    degrade to a safe counter value instead of raising ``ValueError`` (or
    ``OverflowError`` for non-finite numeric values) and preventing the
    manager from loading altogether.
    """
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return max(0, int(default))
    return max(0, parsed)


@dataclass(frozen=True, slots=True)
class MailboxLease:
    """Two-phase mailbox ownership.

    A claimed lease protects a row while transport setup runs.  ``confirmed``
    becomes true only immediately before the email is submitted to OpenAI.
    """

    row_id: str
    owner: str
    lease_until: float
    revision: int = 0
    confirmed: bool = False
    confirmed_at: float | None = None

    @property
    def expired(self) -> bool:
        return self.lease_until <= time.time()

    def as_dict(self) -> dict[str, Any]:
        return {
            "row_id": self.row_id,
            "owner": self.owner,
            "lease_until": self.lease_until,
            "revision": self.revision,
            "confirmed": self.confirmed,
            "confirmed_at": self.confirmed_at,
        }


@dataclass(frozen=True, slots=True)
class TaskTransition:
    task_id: str
    previous_status: str
    status: str
    revision: int
    updated_at: Any
    snapshot: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "previous_status": self.previous_status,
            "status": self.status,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "snapshot": copy.deepcopy(dict(self.snapshot)),
        }


@dataclass(frozen=True, slots=True)
class FreeTaskSnapshot:
    task_id: str
    status: str = FreeTaskStatus.QUEUED.value
    revision: int = 0
    batch_id: str = ""
    row_id: str = ""
    driver: str = "protocol"
    stage: str = ""
    attempt: int = 0
    created_at: Any = None
    updated_at: Any = None
    payload: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FreeTaskSnapshot":
        payload = copy.deepcopy(dict(value))
        return cls(
            task_id=str(value.get("task_id") or ""),
            status=normalize_task_status(value.get("status")),
            revision=_nonnegative_int(value.get("revision"), 0),
            batch_id=str(value.get("batch_id") or ""),
            row_id=str(value.get("row_id") or ""),
            driver=str(value.get("driver") or "protocol"),
            stage=str(value.get("stage") or ""),
            attempt=_nonnegative_int(
                value.get("attempt") or value.get("retry_attempt") or 0,
                0,
            ),
            created_at=value.get("created_at"),
            updated_at=value.get("updated_at"),
            payload=payload,
        )

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_TASK_STATUSES

    def as_dict(self) -> dict[str, Any]:
        result = copy.deepcopy(dict(self.payload))
        result.update({
            "task_id": self.task_id,
            "status": self.status,
            "revision": self.revision,
            "batch_id": self.batch_id,
            "row_id": self.row_id,
            "driver": self.driver,
            "stage": self.stage,
            "retry_attempt": self.attempt,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return result


__all__ = [
    "ACTIVE_TASK_STATUSES",
    "TERMINAL_TASK_STATUSES",
    "FreeTaskSnapshot",
    "FreeTaskStatus",
    "MailboxLease",
    "TaskTransition",
    "normalize_task_status",
]
