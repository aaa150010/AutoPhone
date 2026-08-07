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
        restore_ceiling: int | None = None,
        minimum: int = 1,
        restore_successes: int = 6,
        pressure_threshold: int = 2,
        pressure_window_seconds: float = 60.0,
        pause_seconds: float = 15.0,
        banned_burst_threshold: int = 4,
        banned_window_seconds: float = 90.0,
        burst_step: int = 2,
        burst_hold_seconds: float = 90.0,
        now_fn: Callable[[], float] = time.monotonic,
        on_change: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.minimum = max(1, int(minimum))
        self.ceiling = max(self.minimum, int(ceiling))
        requested_restore_ceiling = (
            self.ceiling if restore_ceiling is None else int(restore_ceiling)
        )
        self.restore_ceiling = max(
            self.minimum,
            min(self.ceiling, requested_restore_ceiling),
        )
        self.base_limit = max(
            self.minimum,
            min(self.restore_ceiling, int(base_limit)),
        )
        self.limit = self.base_limit
        self.restore_successes = max(1, int(restore_successes))
        self.pressure_threshold = max(1, int(pressure_threshold))
        self.pressure_window_seconds = max(1.0, float(pressure_window_seconds))
        self.pause_seconds = max(0.0, float(pause_seconds))
        self.banned_burst_threshold = max(1, int(banned_burst_threshold))
        self.banned_window_seconds = max(1.0, float(banned_window_seconds))
        self.burst_step = max(1, int(burst_step))
        self.burst_hold_seconds = max(0.0, float(burst_hold_seconds))
        self.burst_enabled = self.ceiling > self.restore_ceiling
        self.now_fn = now_fn
        self.on_change = on_change
        self.condition = threading.Condition()
        self.active = 0
        self.waiting = 0
        self.pending = 0
        self.pause_until = 0.0
        self.success_streak = 0
        self.pressure_events: list[tuple[float, str]] = []
        self.last_pressure_at: float | None = None
        self.seen_pressure_levels: dict[str, int] = {}
        self.banned_events: list[tuple[float, str]] = []
        self.burst_until = 0.0
        self.finished_tasks: set[str] = set()
        self.peak_limit = self.limit
        self.degradations = 0
        self.restorations = 0
        self.burst_promotions = 0
        self.burst_revocations = 0
        self.burst_expirations = 0
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

    def _prune_banned_locked(self, now: float) -> None:
        self.banned_events = [
            (observed, task_id)
            for observed, task_id in self.banned_events
            if 0 <= now - observed <= self.banned_window_seconds
        ]

    def _expire_burst_locked(self, now: float) -> dict[str, Any] | None:
        if self.burst_until <= 0 or now < self.burst_until:
            return None
        old_limit = self.limit
        self.limit = min(self.limit, self.restore_ceiling)
        self.burst_until = 0.0
        self.banned_events.clear()
        if old_limit <= self.limit:
            return None
        self.burst_expirations += 1
        return {
            "kind": "burst_expired",
            "old_limit": old_limit,
            "new_limit": self.limit,
            "ceiling": self.ceiling,
            "restore_ceiling": self.restore_ceiling,
            "reason": "account_banned_burst_expired",
            "pause_seconds": 0,
        }

    def _revoke_burst_locked(self) -> bool:
        was_active = self.burst_until > 0 or self.limit > self.restore_ceiling
        self.limit = min(self.limit, self.restore_ceiling)
        self.burst_until = 0.0
        self.banned_events.clear()
        if was_active:
            self.burst_revocations += 1
        return was_active

    def register_pending(self, count: Any = 1) -> None:
        try:
            amount = max(0, int(count))
        except (TypeError, ValueError):
            amount = 0
        if amount <= 0:
            return
        with self.condition:
            self.pending += amount

    def discard_pending(self, count: Any = 1) -> None:
        try:
            amount = max(0, int(count))
        except (TypeError, ValueError):
            amount = 0
        if amount <= 0:
            return
        with self.condition:
            self.pending = max(0, self.pending - amount)

    def clear_pending(self) -> None:
        with self.condition:
            self.pending = 0

    def _consume_pending_locked(self, registered_pending: bool) -> bool:
        if not registered_pending:
            return False
        self.pending = max(0, self.pending - 1)
        return True

    @contextmanager
    def acquire(
        self,
        *,
        stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
        queued_at: float | None = None,
        registered_pending: bool = False,
    ) -> Iterator[None]:
        now = float(self.now_fn())
        try:
            candidate = float(queued_at) if queued_at is not None else now
        except (TypeError, ValueError):
            candidate = now
        wait_started = candidate if math.isfinite(candidate) else now
        acquired = False
        registered_waiter = True
        pending_consumed = False
        with self.condition:
            self.waiting += 1
        try:
            while not acquired:
                event: dict[str, Any] | None = None
                stopped = False
                with self.condition:
                    now = float(self.now_fn())
                    event = self._expire_burst_locked(now)
                    if self._stopped(stop_event):
                        pending_consumed = self._consume_pending_locked(
                            registered_pending,
                        )
                        self.waiting = max(0, self.waiting - 1)
                        registered_waiter = False
                        stopped = True
                    else:
                        pause_remaining = max(0.0, self.pause_until - now)
                        if self.active < self.limit and pause_remaining <= 0:
                            self.active += 1
                            pending_consumed = self._consume_pending_locked(
                                registered_pending,
                            )
                            self.waiting = max(0, self.waiting - 1)
                            registered_waiter = False
                            acquired = True
                        else:
                            self.condition.wait(
                                timeout=min(0.25, pause_remaining)
                                if pause_remaining
                                else 0.25
                            )
                if event is not None:
                    _notify(self.on_change, event)
                if stopped:
                    raise RuntimeError("task_stopped")
        except BaseException:
            if registered_waiter or (registered_pending and not pending_consumed):
                with self.condition:
                    if registered_waiter:
                        self.waiting = max(0, self.waiting - 1)
                    if registered_pending and not pending_consumed:
                        self._consume_pending_locked(True)
            raise
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
        events: list[dict[str, Any]] = []
        with self.condition:
            now = float(self.now_fn())
            expired = self._expire_burst_locked(now)
            if expired is not None:
                events.append(expired)
            if not identifier or identifier in self.finished_tasks:
                limit = self.limit
            else:
                self.finished_tasks.add(identifier)
                self.success_count += 1
                self._prune_pressure_locked(now)
                pressure_free = (
                    self.last_pressure_at is None
                    or now - self.last_pressure_at > self.pressure_window_seconds
                )
                if not pressure_free:
                    self.success_streak = 0
                else:
                    self.success_streak += 1
                    if (
                        self.limit < self.restore_ceiling
                        and self.success_streak >= self.restore_successes
                    ):
                        old_limit = self.limit
                        self.limit += 1
                        self.peak_limit = max(self.peak_limit, self.limit)
                        self.success_streak = 0
                        self.restorations += 1
                        self.condition.notify_all()
                        events.append({
                            "kind": "restored",
                            "old_limit": old_limit,
                            "new_limit": self.limit,
                            "ceiling": self.ceiling,
                            "restore_ceiling": self.restore_ceiling,
                            "reason": "success_streak",
                            "pause_seconds": 0,
                        })
                limit = self.limit
        for event in events:
            _notify(self.on_change, event)
        return limit

    def report_failure(self, task_id: Any) -> int:
        identifier = str(task_id or "").strip()
        event: dict[str, Any] | None = None
        with self.condition:
            event = self._expire_burst_locked(float(self.now_fn()))
            if not identifier or identifier in self.finished_tasks:
                limit = self.limit
            else:
                self.finished_tasks.add(identifier)
                self.failure_count += 1
                self.success_streak = 0
                limit = self.limit
        if event is not None:
            _notify(self.on_change, event)
        return limit

    def report_account_banned(self, task_id: Any) -> int:
        identifier = str(task_id or "").strip()
        events: list[dict[str, Any]] = []
        with self.condition:
            now = float(self.now_fn())
            expired = self._expire_burst_locked(now)
            if expired is not None:
                events.append(expired)
            if not identifier or identifier in self.finished_tasks:
                limit = self.limit
            else:
                self.finished_tasks.add(identifier)
                self.failure_count += 1
                self.success_streak = 0
                self._prune_pressure_locked(now)
                self._prune_banned_locked(now)
                pressure_free = (
                    self.last_pressure_at is None
                    or now - self.last_pressure_at > self.pressure_window_seconds
                )
                burst_active = (
                    self.burst_until > now
                    and self.limit > self.restore_ceiling
                )
                queued_work = self.pending > 0 or self.waiting > 0
                can_burst = (
                    self.burst_enabled
                    and queued_work
                    and self.limit >= self.restore_ceiling
                    and pressure_free
                )
                if can_burst and self.limit >= self.ceiling:
                    self.burst_until = now + self.burst_hold_seconds
                    self.banned_events.clear()
                elif can_burst:
                    self.banned_events.append((now, identifier))
                    if self.limit > self.restore_ceiling:
                        self.burst_until = now + self.burst_hold_seconds
                    if len(self.banned_events) >= self.banned_burst_threshold:
                        old_limit = self.limit
                        self.limit = min(self.ceiling, self.limit + self.burst_step)
                        self.banned_events.clear()
                        if self.limit > old_limit:
                            self.burst_until = now + self.burst_hold_seconds
                            self.peak_limit = max(self.peak_limit, self.limit)
                            self.burst_promotions += 1
                            self.condition.notify_all()
                            events.append({
                                "kind": "burst_activated",
                                "old_limit": old_limit,
                                "new_limit": self.limit,
                                "ceiling": self.ceiling,
                                "restore_ceiling": self.restore_ceiling,
                                "reason": "account_banned_fast_terminal",
                                "pause_seconds": 0,
                                "hold_seconds": int(
                                    math.ceil(self.burst_hold_seconds)
                                ),
                            })
                elif burst_active and pressure_free:
                    self.burst_until = now + self.burst_hold_seconds
                limit = self.limit
        for event in events:
            _notify(self.on_change, event)
        return limit

    def report_pressure(
        self,
        task_id: Any,
        node_code: Any,
        *,
        immediate: bool = False,
    ) -> int:
        task = str(task_id or "").strip()
        node = str(node_code or "").strip().lower()
        pressure_key = f"{task}:{node}"
        events: list[dict[str, Any]] = []
        with self.condition:
            now = float(self.now_fn())
            expired = self._expire_burst_locked(now)
            if expired is not None:
                events.append(expired)
            severity = 2 if immediate else 1
            valid_pressure = bool(task and node)
            accepted = valid_pressure and (
                self.seen_pressure_levels.get(pressure_key, 0) < severity
            )
            if not accepted:
                if valid_pressure:
                    self.last_pressure_at = now
                    self.success_streak = 0
                    self._prune_pressure_locked(now)
                    self.banned_events.clear()
                limit = self.limit
            else:
                old_limit = self.limit
                self.seen_pressure_levels[pressure_key] = severity
                self.pressure_count += 1
                self.success_streak = 0
                self.last_pressure_at = now
                self._prune_pressure_locked(now)
                if not immediate:
                    self.pressure_events.append((now, pressure_key))
                should_degrade = immediate or (
                    len(self.pressure_events) >= self.pressure_threshold
                )
                if should_degrade:
                    revoked = self._revoke_burst_locked()
                    if revoked:
                        self.pause_until = max(
                            self.pause_until,
                            now + self.pause_seconds,
                        )
                        self.pressure_events.clear()
                        self.condition.notify_all()
                        events.append({
                            "kind": "burst_revoked",
                            "old_limit": old_limit,
                            "new_limit": self.limit,
                            "ceiling": self.ceiling,
                            "restore_ceiling": self.restore_ceiling,
                            "reason": "infrastructure_pressure_immediate"
                            if immediate
                            else "infrastructure_pressure",
                            "pause_seconds": int(math.ceil(self.pause_seconds)),
                        })
                    else:
                        degrade_from = self.limit
                        self.limit = max(self.minimum, self.limit - 1)
                        self.pause_until = max(
                            self.pause_until,
                            now + self.pause_seconds,
                        )
                        self.pressure_events.clear()
                        self.degradations += 1
                        self.condition.notify_all()
                        events.append({
                            "kind": "degraded"
                            if self.limit < degrade_from
                            else "paused",
                            "old_limit": degrade_from,
                            "new_limit": self.limit,
                            "ceiling": self.ceiling,
                            "restore_ceiling": self.restore_ceiling,
                            "reason": "infrastructure_pressure_immediate"
                            if immediate
                            else "infrastructure_pressure",
                            "pause_seconds": int(math.ceil(self.pause_seconds)),
                            "immediate": bool(immediate),
                            "burst_revoked": False,
                        })
                else:
                    self.banned_events.clear()
                limit = self.limit
        for event in events:
            _notify(self.on_change, event)
        return limit

    def snapshot(self) -> dict[str, Any]:
        event: dict[str, Any] | None = None
        with self.condition:
            now = float(self.now_fn())
            event = self._expire_burst_locked(now)
            self._prune_pressure_locked(now)
            self._prune_banned_locked(now)
            value = {
                "base": self.base_limit,
                "limit": self.limit,
                "ceiling": self.ceiling,
                "restore_ceiling": self.restore_ceiling,
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
                "burst_enabled": self.burst_enabled,
                "burst_active": self.burst_until > now,
                "burst_remaining_seconds": max(
                    0,
                    int(math.ceil(self.burst_until - now)),
                ),
                "recent_account_banned": len(self.banned_events),
                "burst_promotions": self.burst_promotions,
                "burst_revocations": self.burst_revocations,
                "burst_expirations": self.burst_expirations,
                "pressure_count": self.pressure_count,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "total_wait_seconds": round(self.total_wait_seconds, 3),
            }
        if event is not None:
            _notify(self.on_change, event)
        return value


__all__ = ["AdaptiveConcurrencyGate"]
