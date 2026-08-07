"""Adaptive admission control for registration workers."""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Callable, Iterator
import math
import threading
import time
from typing import Any


def _notify(observer: Any, value: dict[str, Any]) -> None:
    if not callable(observer):
        return
    try:
        observer(dict(value))
    except Exception:
        pass


class AdaptiveConcurrencyGate:
    """Bound active work and adjust capacity from redacted health signals."""

    def __init__(
        self,
        base_limit: int = 5,
        *,
        ceiling: int = 8,
        minimum: int = 1,
        restore_successes: int = 6,
        pressure_threshold: int = 2,
        pressure_window_seconds: float = 60.0,
        pause_seconds: float = 15.0,
        now_fn: Callable[[], float] = time.monotonic,
        on_change: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.minimum = max(1, int(minimum))
        self.ceiling = max(self.minimum, int(ceiling))
        self.base_limit = max(self.minimum, min(self.ceiling, int(base_limit)))
        self.limit = self.base_limit
        self.restore_successes = max(1, int(restore_successes))
        self.pressure_threshold = max(1, int(pressure_threshold))
        self.pressure_window_seconds = max(1.0, float(pressure_window_seconds))
        self.pause_seconds = max(0.0, float(pause_seconds))
        self.now_fn = now_fn
        self.on_change = on_change
        self.condition = threading.Condition()
        self.active = 0
        self.waiting = 0
        self.pause_until = 0.0
        self.success_streak = 0
        self.pressure_events: list[tuple[float, str]] = []
        self.last_pressure_at: float | None = None
        self.seen_pressure_keys: set[str] = set()
        self.finished_tasks: set[str] = set()
        self.peak_limit = self.limit
        self.degradations = 0
        self.restorations = 0
        self.pressure_count = 0
        self.success_count = 0
        self.failure_count = 0
        self.total_wait_seconds = 0.0

    @staticmethod
    def _stopped(stop_event: Any) -> bool:
        if stop_event is None:
            return False
        checker = getattr(stop_event, "is_set", None)
        if callable(checker):
            return bool(checker())
        return bool(stop_event()) if callable(stop_event) else bool(stop_event)

    def _prune_pressure_locked(self, now: float) -> None:
        self.pressure_events = [
            (observed, key)
            for observed, key in self.pressure_events
            if 0 <= now - observed <= self.pressure_window_seconds
        ]

    @contextmanager
    def acquire(
        self,
        *,
        stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
        queued_at: float | None = None,
    ) -> Iterator[None]:
        now = float(self.now_fn())
        try:
            candidate = float(queued_at) if queued_at is not None else now
        except (TypeError, ValueError):
            candidate = now
        wait_started = candidate if math.isfinite(candidate) else now
        acquired = False
        with self.condition:
            self.waiting += 1
            try:
                while True:
                    if self._stopped(stop_event):
                        raise RuntimeError("task_stopped")
                    now = float(self.now_fn())
                    pause_remaining = max(0.0, self.pause_until - now)
                    if self.active < self.limit and pause_remaining <= 0:
                        self.active += 1
                        acquired = True
                        break
                    self.condition.wait(
                        timeout=min(0.25, pause_remaining) if pause_remaining else 0.25
                    )
            finally:
                self.waiting = max(0, self.waiting - 1)
        waited = max(0.0, float(self.now_fn()) - wait_started)
        with self.condition:
            self.total_wait_seconds += waited
        if callable(on_wait):
            try:
                on_wait(waited)
            except Exception:
                pass
        try:
            yield
        finally:
            if acquired:
                with self.condition:
                    self.active = max(0, self.active - 1)
                    self.condition.notify_all()

    def wake_all(self) -> None:
        with self.condition:
            self.condition.notify_all()

    def report_success(self, task_id: Any) -> int:
        identifier = str(task_id or "").strip()
        event: dict[str, Any] | None = None
        with self.condition:
            if not identifier or identifier in self.finished_tasks:
                return self.limit
            self.finished_tasks.add(identifier)
            self.success_count += 1
            now = float(self.now_fn())
            self._prune_pressure_locked(now)
            pressure_free = (
                self.last_pressure_at is None
                or now - self.last_pressure_at > self.pressure_window_seconds
            )
            if not pressure_free:
                self.success_streak = 0
                return self.limit
            self.success_streak += 1
            if (
                self.limit < self.ceiling
                and self.success_streak >= self.restore_successes
            ):
                old_limit = self.limit
                self.limit += 1
                self.peak_limit = max(self.peak_limit, self.limit)
                self.success_streak = 0
                self.restorations += 1
                self.condition.notify_all()
                event = {
                    "kind": "restored",
                    "old_limit": old_limit,
                    "new_limit": self.limit,
                    "ceiling": self.ceiling,
                    "reason": "success_streak",
                    "pause_seconds": 0,
                }
            limit = self.limit
        if event is not None:
            _notify(self.on_change, event)
        return limit

    def report_failure(self, task_id: Any) -> int:
        identifier = str(task_id or "").strip()
        with self.condition:
            if not identifier or identifier in self.finished_tasks:
                return self.limit
            self.finished_tasks.add(identifier)
            self.failure_count += 1
            self.success_streak = 0
            return self.limit

    def report_pressure(self, task_id: Any, node_code: Any) -> int:
        task = str(task_id or "").strip()
        node = str(node_code or "").strip().lower()
        if not task or not node:
            return self.limit
        pressure_key = f"{task}:{node}"
        event: dict[str, Any] | None = None
        with self.condition:
            if pressure_key in self.seen_pressure_keys:
                return self.limit
            self.seen_pressure_keys.add(pressure_key)
            self.pressure_count += 1
            self.success_streak = 0
            now = float(self.now_fn())
            self.last_pressure_at = now
            self._prune_pressure_locked(now)
            self.pressure_events.append((now, pressure_key))
            if len(self.pressure_events) >= self.pressure_threshold:
                old_limit = self.limit
                self.limit = max(self.minimum, self.limit - 1)
                self.pause_until = max(self.pause_until, now + self.pause_seconds)
                self.pressure_events.clear()
                self.degradations += 1
                self.condition.notify_all()
                event = {
                    "kind": "degraded" if self.limit < old_limit else "paused",
                    "old_limit": old_limit,
                    "new_limit": self.limit,
                    "ceiling": self.ceiling,
                    "reason": "infrastructure_pressure",
                    "pause_seconds": int(math.ceil(self.pause_seconds)),
                }
            limit = self.limit
        if event is not None:
            _notify(self.on_change, event)
        return limit

    def snapshot(self) -> dict[str, Any]:
        with self.condition:
            now = float(self.now_fn())
            self._prune_pressure_locked(now)
            return {
                "base": self.base_limit,
                "limit": self.limit,
                "ceiling": self.ceiling,
                "active": self.active,
                "waiting": self.waiting,
                "paused": self.pause_until > now,
                "pause_remaining_seconds": max(0, int(math.ceil(self.pause_until - now))),
                "success_streak": self.success_streak,
                "recent_pressure_events": len(self.pressure_events),
                "seconds_since_pressure": (
                    None
                    if self.last_pressure_at is None
                    else max(0, int(math.floor(now - self.last_pressure_at)))
                ),
                "peak_limit": self.peak_limit,
                "degradations": self.degradations,
                "restorations": self.restorations,
                "pressure_count": self.pressure_count,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "total_wait_seconds": round(self.total_wait_seconds, 3),
            }


__all__ = ["AdaptiveConcurrencyGate"]
