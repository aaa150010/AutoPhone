"""Adjustable phase admission used by the Node portion of registration."""

from __future__ import annotations

import math
import threading
import time
from typing import Any, Callable


class AdjustablePhaseGate:
    """Match the recovered phase-gate contract while allowing bounded updates."""

    def __init__(
        self,
        base_limit: int,
        *,
        ceiling: int | None = None,
        now_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base_limit = max(1, int(base_limit))
        self.ceiling = max(
            self.base_limit,
            int(ceiling if ceiling is not None else self.base_limit),
        )
        self.limit = self.base_limit
        self.now_fn = now_fn
        self.condition = threading.Condition()
        self.active = 0
        self.waiting = 0
        self.pause_until = 0.0
        self.last_reason = "configured_baseline"

    @staticmethod
    def _stopped(stop_event: Any) -> bool:
        if stop_event is None:
            return False
        checker = getattr(stop_event, "is_set", None)
        if callable(checker):
            return bool(checker())
        return bool(stop_event()) if callable(stop_event) else bool(stop_event)

    def acquire(self, stop_event: Any = None) -> None:
        registered_waiter = True
        with self.condition:
            self.waiting += 1
        try:
            while True:
                with self.condition:
                    if self._stopped(stop_event):
                        raise RuntimeError("task_stopped")
                    now = float(self.now_fn())
                    pause_remaining = max(0.0, self.pause_until - now)
                    if self.active < self.limit and pause_remaining <= 0:
                        self.active += 1
                        self.waiting = max(0, self.waiting - 1)
                        registered_waiter = False
                        return
                    self.condition.wait(
                        timeout=min(0.25, pause_remaining)
                        if pause_remaining
                        else 0.25
                    )
        except BaseException:
            if registered_waiter:
                with self.condition:
                    self.waiting = max(0, self.waiting - 1)
            raise

    def release(self) -> None:
        with self.condition:
            self.active = max(0, self.active - 1)
            self.condition.notify_all()

    def set_capacity(
        self,
        limit: Any,
        *,
        ceiling: Any = None,
        pause_seconds: Any = 0,
        reason: Any = "",
    ) -> int:
        with self.condition:
            if ceiling is not None:
                self.ceiling = max(self.base_limit, int(ceiling))
            requested = max(1, min(self.ceiling, int(limit)))
            self.limit = requested
            try:
                pause = max(0.0, float(pause_seconds))
            except (TypeError, ValueError):
                pause = 0.0
            if pause:
                self.pause_until = max(
                    self.pause_until,
                    float(self.now_fn()) + pause,
                )
            clean_reason = str(reason or "").strip().lower()
            if clean_reason:
                self.last_reason = clean_reason[:80]
            self.condition.notify_all()
            return self.limit

    def status(self) -> dict[str, Any]:
        with self.condition:
            now = float(self.now_fn())
            return {
                "base": self.base_limit,
                "active": self.active,
                "limit": self.limit,
                "ceiling": self.ceiling,
                "waiting": self.waiting,
                "paused": self.pause_until > now,
                "pause_remaining_seconds": max(
                    0,
                    int(math.ceil(self.pause_until - now)),
                ),
                "last_reason": self.last_reason,
            }


__all__ = ["AdjustablePhaseGate"]
