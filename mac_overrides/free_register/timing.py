"""Bounded task timing recorder independent from transport implementations."""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Mapping


class TaskTimingRecorder:
    def __init__(self, *, max_stages: int = 200, clock: Any = time.monotonic) -> None:
        self.max_stages = max(10, int(max_stages))
        self.clock = clock
        self._started = float(clock())
        self._active: dict[str, tuple[float, int]] = {}
        self._stages: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    def enter(self, code: str, *, attempt: int = 1) -> None:
        normalized = str(code or "").strip()
        if not normalized:
            return
        with self._lock:
            self._active[normalized] = (float(self.clock()), max(1, int(attempt)))

    def leave(
        self,
        code: str,
        *,
        outcome: str = "success",
        failure_code: str = "",
        retryable: bool | None = None,
    ) -> dict[str, Any] | None:
        normalized = str(code or "").strip()
        with self._lock:
            started = self._active.pop(normalized, None)
            if started is None:
                return None
            now = float(self.clock())
            row = {
                "code": normalized,
                "attempt": started[1],
                "duration_ms": max(0, int((now - started[0]) * 1000)),
                "outcome": str(outcome or "success")[:40],
            }
            if failure_code:
                row["failure_code"] = str(failure_code)[:120]
            if isinstance(retryable, bool):
                row["retryable"] = retryable
            self._stages.append(row)
            self._stages = self._stages[-self.max_stages:]
            return copy.deepcopy(row)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            elapsed_ms = max(0, int((float(self.clock()) - self._started) * 1000))
            stages = copy.deepcopy(self._stages)
        slowest = max(stages, key=lambda row: int(row.get("duration_ms") or 0), default=None)
        return {
            "elapsed_ms": elapsed_ms,
            "elapsed_seconds": round(elapsed_ms / 1000.0, 3),
            "stages": stages,
            "slowest_node": copy.deepcopy(slowest),
        }


__all__ = ["TaskTimingRecorder"]
