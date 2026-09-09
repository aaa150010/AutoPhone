"""SQLite-backed adapter for the historical Free task-store API."""

from __future__ import annotations

from collections.abc import MutableMapping
import copy
from pathlib import Path
from typing import Any, Mapping

try:
    from .free_register_store import FreeTaskStore as _LegacyTaskStoreBase
    from .free_storage import FreeSQLiteStore, RevisionConflict
    from .free_storage_adapter_common import (
        _TERMINAL_TASK_STATUSES,
        _compat_timestamp,
        _json_payload,
    )
except ImportError:  # pragma: no cover - recovery imports
    from free_register_store import FreeTaskStore as _LegacyTaskStoreBase  # type: ignore[no-redef]
    from free_storage import FreeSQLiteStore, RevisionConflict  # type: ignore[no-redef]
    from free_storage_adapter_common import (  # type: ignore[no-redef]
        _TERMINAL_TASK_STATUSES,
        _compat_timestamp,
        _json_payload,
    )


class SQLiteFreeTaskStore(_LegacyTaskStoreBase):
    """SQLite-backed implementation of the historical task-store API."""

    def __init__(self, data_dir: str | Path, *, storage: FreeSQLiteStore | None = None) -> None:
        super().__init__(data_dir)
        self.storage = storage or FreeSQLiteStore(self.path.parent)
        self.path = self.storage.path
        # ``save`` historically accepted a complete JSON snapshot and pruned
        # terminal rows that disappeared from it.  SQLite is shared by
        # multiple workers/processes, so only rows observed by this adapter's
        # last ``load`` (and still at the same revision) are safe to prune.
        # Rows created by another process after that snapshot are retained.
        self._known_task_revisions: dict[str, int] = {}

    @staticmethod
    def _task_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
        payload = _json_payload(row.get("payload"))
        payload.update({
            "task_id": str(row.get("task_id") or payload.get("task_id") or ""),
            "status": str(row.get("status") or payload.get("status") or "queued"),
            "revision": int(row.get("revision") or payload.get("revision") or 0),
            "created_at": _compat_timestamp(
                payload.get("created_at", row.get("created_at")),
                _compat_timestamp(row.get("created_at")),
            ),
            "updated_at": _compat_timestamp(
                payload.get("updated_at", row.get("updated_at")),
                _compat_timestamp(row.get("updated_at")),
            ),
        })
        if row.get("lease_owner"):
            payload["lease_owner"] = row.get("lease_owner")
            payload["lease_until"] = row.get("lease_until")
        return payload

    def load(self) -> dict[str, dict[str, Any]]:
        rows = self.storage.list_tasks(limit=10_000)
        loaded = {
            str(row.get("task_id")): self._task_from_row(row)
            for row in rows
            if str(row.get("task_id") or "")
        }
        self._known_task_revisions = {
            task_id: int(value.get("revision") or 0)
            for task_id, value in loaded.items()
            if isinstance(value, Mapping)
        }
        return loaded

    def _remember_revision(self, task_id: str, row: Mapping[str, Any]) -> None:
        try:
            self._known_task_revisions[str(task_id)] = int(row.get("revision") or 0)
        except (TypeError, ValueError):
            pass

    @staticmethod
    def _sync_saved_value(value: Mapping[str, Any], row: Mapping[str, Any]) -> None:
        """Return SQLite CAS metadata to the manager's mutable snapshot."""
        if not isinstance(value, MutableMapping):
            return
        value["revision"] = int(row.get("revision") or 0)
        if row.get("status") is not None:
            value["status"] = str(row.get("status") or "queued")
        if row.get("created_at") is not None:
            value["created_at"] = _compat_timestamp(row.get("created_at"))
        if row.get("updated_at") is not None:
            value["updated_at"] = _compat_timestamp(row.get("updated_at"))

    def _save_one(self, task_id: str, value: Mapping[str, Any]) -> None:
        """Save one legacy snapshot with a bounded CAS refresh.

        The compatibility manager owns a full in-memory task map and does not
        perform repository transitions yet.  Timing checkpoints can advance a
        row revision between two full saves, so one stale revision is refreshed
        from the durable row and retried.  A durable terminal task always wins
        over a late active snapshot.
        """
        prefer_latest_revision = False
        for attempt in range(3):
            current = self.storage.get_task(task_id)
            if current is None:
                created = self.storage.create_task(
                    task_id,
                    value,
                    status=str(value.get("status") or "queued"),
                )
                self._sync_saved_value(value, created)
                self._remember_revision(task_id, created)
                return
            current_status = str(current.get("status") or "queued")
            incoming_status = str(value.get("status") or current_status or "queued")
            if current_status in _TERMINAL_TASK_STATUSES and incoming_status != current_status:
                self._sync_saved_value(value, current)
                self._remember_revision(task_id, current)
                return
            current_payload = current.get("payload")
            merged = _json_payload(current_payload)
            merged.update(copy.deepcopy(dict(value)))
            raw_expected = value.get("revision")
            if prefer_latest_revision or raw_expected is None:
                expected_revision = int(current.get("revision") or 0)
            else:
                try:
                    expected_revision = int(raw_expected)
                except (TypeError, ValueError):
                    expected_revision = int(current.get("revision") or 0)
            try:
                saved = self.storage.save_task(
                    task_id,
                    merged,
                    expected_revision=expected_revision,
                    status=incoming_status,
                )
            except RevisionConflict:
                if attempt >= 2:
                    raise
                prefer_latest_revision = True
                continue
            self._sync_saved_value(value, saved)
            self._remember_revision(task_id, saved)
            return

    def save(self, tasks: Mapping[str, Mapping[str, Any]], *, partial_snapshot: bool = False) -> None:
        known_before = dict(self._known_task_revisions)
        incoming_ids: set[str] = set()
        for key, value in tasks.items():
            if not isinstance(value, Mapping):
                continue
            task_id = str(value.get("task_id") or key or "").strip()
            if not task_id:
                continue
            incoming_ids.add(task_id)
            self._save_one(task_id, value)
        # Preserve the legacy explicit-delete behavior for rows this adapter
        # actually observed, while preventing a stale snapshot from deleting
        # terminal rows created or advanced by another process. A partial
        # (dirty-only) snapshot deliberately omits untouched rows, so pruning
        # is skipped entirely — otherwise every dirty save would delete the
        # omitted terminal rows and the next full save would re-create them
        # with a fresh created_at, scrambling task ordering.
        if partial_snapshot:
            return
        stale_revisions = {
            task_id: revision
            for task_id, revision in known_before.items()
            if task_id not in incoming_ids
        }
        if stale_revisions:
            self.storage.delete_tasks(
                tuple(stale_revisions),
                terminal_only=True,
                expected_revisions=stale_revisions,
            )

    def save_timing(self, task_id: str, timing: Mapping[str, Any], *, skip_terminal: bool = True) -> bool:
        target = str(task_id or "").strip()
        if not target or not isinstance(timing, Mapping):
            return False
        current = self.storage.get_task(target)
        if current is None:
            return False
        status = str(current.get("status") or "").strip().lower()
        if skip_terminal and status in _TERMINAL_TASK_STATUSES:
            return False
        payload = current.get("payload") if isinstance(current.get("payload"), Mapping) else {}
        merged = copy.deepcopy(dict(payload))
        # Use the parent class's pure monotonic timing merge; it performs no
        # filesystem access and keeps stage/substep history from rolling back.
        merged["timing"] = self._merge_timing(merged.get("timing"), timing)
        try:
            self.storage.save_task(
                target,
                merged,
                expected_revision=int(current.get("revision") or 0),
                status=status or "queued",
            )
        except Exception:
            # Swallow persistence failures here on purpose: timing telemetry
            # is best-effort and must never change the task's business result
            # or surface as a registration failure.  Real persistence errors
            # still surface through ``save``/``_save_one``.
            return False
        return True


__all__ = ["SQLiteFreeTaskStore"]
