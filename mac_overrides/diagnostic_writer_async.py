"""Async batched front for diagnostic event persistence.

Wraps a ``DiagnosticStore`` so registration workers enqueue redacted events
and never wait on the store's per-event SQLite transaction.  One background
writer thread drains the queue, groups events per incident, and persists them
through the wrapped store.  Incident ids are pre-allocated at enqueue time
with the store's own allocator-compatible shape and reused for every event of
the same task, so callers can bind the returned id immediately — the durable
row appears under the same id at most one flush interval later.

Redaction stays on the synchronous path: every field passes the normal
allowlist projection before entering the queue, so a crash can only lose
already-redacted events, never expose raw values.
"""

from __future__ import annotations

import queue
import secrets
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

try:
    from .diagnostic_writer import DiagnosticEventWriter
except ImportError:  # pragma: no cover - top-level recovery import
    from diagnostic_writer import DiagnosticEventWriter  # type: ignore[no-redef]

_INCIDENT_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_DEFAULT_FLUSH_INTERVAL = 1.0
_DEFAULT_MAX_BATCH = 64
_DEFAULT_QUEUE_SIZE = 4096



try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('diagnostic_writer_async', where, exc)


def _new_incident_id() -> str:
    """Allocate an id in the store's ``LOG-YYYYMMDD-XXXXXXXX`` shape."""
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = "".join(secrets.choice(_INCIDENT_ALPHABET) for _ in range(8))
    return f"LOG-{date}-{suffix}"


def _is_error_event(projected: Mapping[str, Any]) -> bool:
    outcome = str(projected.get("outcome") or "").lower()
    level = str(projected.get("level") or "").lower()
    return (
        outcome in {"error", "failed", "failure", "stopped"}
        or level in {"error", "danger"}
    )


class AsyncDiagnosticWriter(DiagnosticEventWriter):
    """Queue events in the foreground; persist them on one background thread.

    The writer inherits ``DiagnosticEventWriter`` so every existing projection
    (field allowlist, subject fingerprinting, masking) runs unchanged before
    an event is queued.  ``record`` returns a stable incident id immediately;
    the durable event lands when the background thread next drains the queue.
    """

    def __init__(
        self,
        store: Any,
        *,
        context: Any = None,
        best_effort: bool = True,
        flush_interval: float = _DEFAULT_FLUSH_INTERVAL,
        max_batch: int = _DEFAULT_MAX_BATCH,
        queue_size: int = _DEFAULT_QUEUE_SIZE,
        _sequence_state: Any = None,
    ) -> None:
        super().__init__(store, context=context, best_effort=best_effort, _sequence_state=_sequence_state)
        self.flush_interval = max(0.05, float(flush_interval))
        self.max_batch = max(1, int(max_batch))
        self._queue: queue.Queue[tuple[bool, dict[str, Any], str]] = queue.Queue(maxsize=max(1, queue_size))
        # task_id -> pre-allocated incident id. Mirrors the store's task
        # grouping so one task keeps a single diagnostic timeline without
        # querying SQLite on the hot path.
        self._incident_by_task: dict[str, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._drain_wakeup = threading.Event()
        self._thread = threading.Thread(target=self._drain_loop, name="diagnostic-async-writer", daemon=True)
        self._thread.start()

    def _incident_hint(self, projected: Mapping[str, Any]) -> str:
        """Resolve the incident id for one projected event.

        An explicit hint (retry continuation) always wins. Events without a
        task id get their own fresh incident, matching the store's grouping.
        New ids are reserved in the store's tombstone table immediately so
        the allocator stays collision-safe across restarts.
        """
        hint = str(projected.get("incident_id") or "").strip().upper()
        if hint:
            return hint
        task_id = str(projected.get("task_id") or "").strip()
        if task_id:
            with self._lock:
                existing = self._incident_by_task.get(task_id)
                if existing is not None:
                    return existing
        incident = _new_incident_id()
        reserve = getattr(self.store, "reserve_incident", None)
        if callable(reserve):
            try:
                reserve(incident)
            except Exception as exc:
                # Reservation is a collision guard only; the store's
                # allocator still owns final id uniqueness.
                _note_stderr("L121", exc)
        if not task_id:
            # The store assigns taskless events their own incident; the id is
            # still pre-allocated so ``record`` can return it immediately.
            return incident
        with self._lock:
            self._incident_by_task[task_id] = incident
        return incident

    def record(self, fields: Mapping[str, Any] | None = None, **kwargs: Any) -> str:
        payload: dict[str, Any] = {}
        if isinstance(fields, Mapping):
            payload.update(fields)
        payload.update(kwargs)
        projected = self._project(payload)
        incident_hint = self._incident_hint(projected)
        if incident_hint:
            projected["incident_id"] = incident_hint
        error_priority = _is_error_event(projected)
        try:
            self._queue.put_nowait((error_priority, projected, incident_hint))
        except queue.Full:
            # The queue is bounded; dropping the newest info event keeps the
            # registration worker unblocked while errors still get through.
            if error_priority:
                try:
                    self._queue.put((error_priority, projected, incident_hint), timeout=2.0)
                except queue.Full:
                    self._note_drop(projected)
            else:
                self._note_drop(projected)
            return str(incident_hint or "")
        return str(incident_hint or "")

    emit = record
    write = record

    def _note_drop(self, projected: Mapping[str, Any]) -> None:
        note = getattr(self.store, "note_write_failure", None)
        if callable(note):
            try:
                note("async_queue_full", RuntimeError("diagnostic async queue full"))
            except Exception as exc:
                _note_stderr("L164", exc)

    def _drain_once(self, *, wait: bool) -> None:
        batch: list[tuple[bool, dict[str, Any], str]] = []
        if wait:
            self._drain_wakeup.wait(self.flush_interval)
            self._drain_wakeup.clear()
        while len(batch) < self.max_batch:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if not batch:
            return
        # Errors first so a first real business failure lands before the
        # informational tail if the process dies mid-batch.
        batch.sort(key=lambda item: not item[0])
        for _priority, projected, _hint in batch:
            try:
                self.store.record(projected)
            except Exception as exc:
                if not self.best_effort:
                    raise
                note = getattr(self.store, "note_write_failure", None)
                if callable(note) and not getattr(exc, "_diagnostic_store_noted", False):
                    try:
                        note("async_drain", exc)
                    except Exception as exc:
                        _note_stderr("L192", exc)

    def _drain_loop(self) -> None:
        while not self._stop.is_set():
            self._drain_once(wait=True)

    def flush(self, timeout: float = 5.0) -> int:
        """Drain every queued event synchronously and return the drained count."""
        drained = 0
        deadline = time.monotonic() + max(0.1, float(timeout))
        while time.monotonic() < deadline:
            before = self._queue.qsize()
            if before == 0:
                break
            self._drain_once(wait=False)
            drained += before - self._queue.qsize()
        return drained

    def close(self) -> None:
        """Stop the background thread after flushing the pending queue."""
        self.flush()
        self._stop.set()
        self._drain_wakeup.set()
        self._thread.join(timeout=3.0)

    def forget_task(self, task_id: str) -> None:
        """Drop a finished task's incident binding to bound the cache."""
        with self._lock:
            self._incident_by_task.pop(str(task_id or ""), None)


__all__ = ["AsyncDiagnosticWriter"]
