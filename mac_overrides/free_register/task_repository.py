"""Revisioned task and mailbox-lease repository on the Free SQLite store."""

from __future__ import annotations

import copy
import time
from typing import Any, Mapping, Sequence

try:
    from ..free_storage import FreeSQLiteStore, RevisionConflict
except ImportError:  # pragma: no cover - top-level recovery imports
    from free_storage import FreeSQLiteStore, RevisionConflict  # type: ignore[no-redef]

from .contracts import (
    ACTIVE_TASK_STATUSES,
    TERMINAL_TASK_STATUSES,
    FreeTaskSnapshot,
    MailboxLease,
    TaskTransition,
    normalize_task_status,
)


class TaskConflictError(RuntimeError):
    """A transition lost a revision or terminal-state race."""


class FreeTaskRepository:
    """Narrow repository used by managers, schedulers, and workers.

    The repository never exposes a SQLite connection.  Every operation uses a
    short-lived connection owned by :class:`FreeSQLiteStore`.
    """

    def __init__(self, data_dir: Any, *, storage: FreeSQLiteStore | None = None) -> None:
        self.storage = storage or FreeSQLiteStore(data_dir)

    @property
    def path(self) -> Any:
        return self.storage.path

    @staticmethod
    def _payload(row: Mapping[str, Any] | None) -> dict[str, Any]:
        if not isinstance(row, Mapping):
            return {}
        payload = row.get("payload")
        result = copy.deepcopy(dict(payload)) if isinstance(payload, Mapping) else {}
        for key in ("task_id", "status", "revision", "created_at", "updated_at"):
            if key in row:
                result[key] = row.get(key)
        return result

    def create(self, task: Mapping[str, Any]) -> FreeTaskSnapshot:
        task_id = str(task.get("task_id") or "").strip()
        if not task_id:
            raise ValueError("task_id is required")
        status = normalize_task_status(task.get("status"))
        row = self.storage.create_task(task_id, task, status=status)
        return FreeTaskSnapshot.from_mapping(self._payload(row))

    def get(self, task_id: str) -> FreeTaskSnapshot | None:
        row = self.storage.get_task(task_id)
        return FreeTaskSnapshot.from_mapping(self._payload(row)) if row else None

    def list(
        self,
        *,
        status: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[FreeTaskSnapshot]:
        rows = self.storage.list_tasks(status=status, limit=limit, offset=offset)
        return [FreeTaskSnapshot.from_mapping(self._payload(row)) for row in rows]

    def save(
        self,
        task: Mapping[str, Any],
        *,
        expected_revision: int | None = None,
    ) -> FreeTaskSnapshot:
        task_id = str(task.get("task_id") or "").strip()
        if not task_id:
            raise ValueError("task_id is required")
        try:
            row = self.storage.save_task(
                task_id,
                task,
                expected_revision=expected_revision,
                status=normalize_task_status(task.get("status")),
            )
        except RevisionConflict as exc:
            raise TaskConflictError(str(exc)) from exc
        return FreeTaskSnapshot.from_mapping(self._payload(row))

    def transition(
        self,
        task_id: str,
        status: str,
        *,
        expected_revision: int,
        expected_statuses: Sequence[str] | None = None,
        updates: Mapping[str, Any] | None = None,
    ) -> TaskTransition:
        normalized_task_id = str(task_id or "").strip()
        current = self.get(normalized_task_id)
        if current is None:
            raise TaskConflictError(f"task not found: {task_id}")
        normalized = normalize_task_status(status)
        requested_allowed = tuple(
            normalize_task_status(item) for item in (expected_statuses or ())
        )
        if requested_allowed:
            allowed = tuple(dict.fromkeys(requested_allowed))
        else:
            # An omitted/empty expected-status set has historically meant
            # "allow the current state".  Include the known states so a
            # concurrent normal transition is still handled by the store's
            # compare-and-set, while retaining an unknown legacy state seen in
            # the initial snapshot for compatibility.
            known = ACTIVE_TASK_STATUSES | TERMINAL_TASK_STATUSES
            allowed = tuple(sorted(known | {current.status}))

        try:
            # The status predicate, terminal-state guard, revision check and
            # payload update must be one SQLite transaction.  A preceding
            # ``get`` is only used to retain the historical not-found error
            # and to populate ``previous_status`` for the compatibility
            # result; it is never treated as authorization for the write.
            row = self.storage.transition_task(
                normalized_task_id,
                allowed,
                normalized,
                payload_patch=copy.deepcopy(dict(updates or {})),
                expected_revision=expected_revision,
            )
        except RevisionConflict as exc:
            raise TaskConflictError(str(exc)) from exc
        if row is None:
            latest = self.get(normalized_task_id)
            actual_status = latest.status if latest is not None else current.status
            if requested_allowed and actual_status not in requested_allowed:
                raise TaskConflictError(
                    f"status conflict: expected={sorted(set(requested_allowed))}, actual={actual_status}"
                )
            if actual_status in TERMINAL_TASK_STATUSES and normalized != actual_status:
                raise TaskConflictError(f"terminal task cannot transition: {actual_status}")
            raise TaskConflictError(f"status conflict: actual={actual_status}")
        saved = FreeTaskSnapshot.from_mapping(self._payload(row))
        return TaskTransition(
            task_id=normalized_task_id,
            previous_status=current.status,
            status=saved.status,
            revision=saved.revision,
            updated_at=saved.updated_at,
            snapshot=saved.as_dict(),
        )

    def claim(self, task_id: str, *, owner: str, lease_seconds: int = 180) -> FreeTaskSnapshot | None:
        row = self.storage.claim_task(
            task_id,
            owner=owner,
            lease_seconds=lease_seconds,
            statuses=tuple(ACTIVE_TASK_STATUSES),
        )
        return FreeTaskSnapshot.from_mapping(self._payload(row)) if row else None

    def claim_mailbox(
        self,
        *,
        owner: str,
        row_id: str | None = None,
        lease_seconds: int = 180,
    ) -> MailboxLease | None:
        row = self.storage.claim_mailbox(
            owner=owner,
            row_id=row_id,
            lease_seconds=lease_seconds,
            claimed_status="reserved",
        )
        if row is None:
            return None
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
        return MailboxLease(
            row_id=str(row.get("row_id") or ""),
            owner=owner,
            lease_until=float(row.get("lease_until") or 0),
            revision=int(row.get("revision") or 0),
            confirmed=bool(payload.get("lease_confirmed", False)),
            confirmed_at=payload.get("lease_confirmed_at"),
        )

    def confirm_mailbox(
        self,
        lease: MailboxLease,
        *,
        task_id: str,
        batch_id: str = "",
        driver: str = "protocol",
    ) -> MailboxLease:
        row = self.storage.confirm_mailbox_lease(
            lease.row_id,
            owner=lease.owner,
            task_id=task_id,
            batch_id=batch_id,
            driver=driver,
            expected_revision=lease.revision,
        )
        if row is None:
            raise TaskConflictError("mailbox lease is stale or owned by another task")
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
        return MailboxLease(
            row_id=str(row.get("row_id") or ""),
            owner=lease.owner,
            lease_until=float(row.get("lease_until") or 0),
            revision=int(row.get("revision") or 0),
            confirmed=True,
            confirmed_at=float(payload.get("lease_confirmed_at") or time.time()),
        )

    def release_mailbox(self, lease: MailboxLease, *, reusable: bool = True) -> bool:
        status = "available" if reusable and not lease.confirmed else None
        return self.storage.release_lease(
            "mailbox", lease.row_id, owner=lease.owner, status=status
        )

    def recover(self) -> dict[str, int]:
        return self.storage.recover_expired_leases()

    def delete(self, task_ids: Sequence[str]) -> int:
        return self.storage.delete_tasks(task_ids, terminal_only=True)

    def load_map(self) -> dict[str, dict[str, Any]]:
        return {item.task_id: item.as_dict() for item in self.list(limit=10_000)}

    def health(self) -> dict[str, Any]:
        return self.storage.health()


__all__ = [
    "FreeTaskRepository",
    "TaskConflictError",
    "TERMINAL_TASK_STATUSES",
]
