"""Time-based retention for the recovered in-memory GUI log."""

from __future__ import annotations

import time
from typing import Any, Callable


LOG_RETENTION_SECONDS = 2 * 24 * 60 * 60
LOG_CLEANUP_INTERVAL_SECONDS = 5 * 60


class GuiLogRetention:
    def __init__(
        self,
        *,
        retention_seconds: float = LOG_RETENTION_SECONDS,
        cleanup_interval_seconds: float = LOG_CLEANUP_INTERVAL_SECONDS,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.retention_seconds = max(1.0, float(retention_seconds))
        self.cleanup_interval_seconds = max(1.0, float(cleanup_interval_seconds))
        self.now_fn = now_fn

    @staticmethod
    def _timestamp(value: Any, default: float) -> float:
        try:
            result = float(value)
        except (TypeError, ValueError):
            return default
        return result if result > 0 else default

    def _cleanup_locked(self, target: Any, now: float, *, force: bool = False) -> None:
        last_cleanup = self._timestamp(
            getattr(target, "_gptphone_log_cleanup_at", 0),
            0,
        )
        cutoff = now - self.retention_seconds
        if not force and last_cleanup and now - last_cleanup < self.cleanup_interval_seconds:
            has_expired = any(
                self._timestamp(
                    value.get("created_at") if isinstance(value, dict) else None,
                    now,
                ) < cutoff
                for value in list(getattr(target, "items", ()) or ())
            )
            if not has_expired:
                return
        retained: list[dict[str, Any]] = []
        for value in list(getattr(target, "items", ()) or ()):
            row = dict(value) if isinstance(value, dict) else {"message": str(value or "")}
            created_at = self._timestamp(row.get("created_at"), now)
            row["created_at"] = int(created_at)
            if created_at >= cutoff:
                retained.append(row)
        target.items = retained
        target._gptphone_log_cleanup_at = now

    def add(
        self,
        target: Any,
        message: Any,
        level: str = "info",
        *,
        safe_fn: Callable[[Any], str] = str,
        max_items: int = 240,
    ) -> None:
        now = float(self.now_fn())
        with target.lock:
            target.items.append(
                {
                    "time": time.strftime("%H:%M:%S", time.localtime(now)),
                    "level": str(level or "info"),
                    "message": safe_fn(message),
                    "created_at": int(now),
                }
            )
            self._cleanup_locked(target, now)
            target.items = target.items[-max(1, int(max_items)):]

    def snapshot(self, target: Any) -> list[dict[str, Any]]:
        now = float(self.now_fn())
        with target.lock:
            self._cleanup_locked(target, now)
            return [dict(row) for row in target.items]


__all__ = [
    "GuiLogRetention",
    "LOG_CLEANUP_INTERVAL_SECONDS",
    "LOG_RETENTION_SECONDS",
]
