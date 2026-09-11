"""Dynamic batch concurrency gate driven by the shared healthy proxy pool."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

__all__ = ["ProxyPoolConcurrencyGate"]


class ProxyPoolConcurrencyGate:
    """Gate batch workers to the current healthy proxy pool size.

    Batch account operations (fast/deep live checks, plan checks, rebinds)
    each consume one healthy proxy per in-flight task.  The gate recomputes
    the in-flight ceiling from the pool on every acquire, so growing or
    shrinking the pool resizes the running batch without restarting the
    queue; waiters wake up on a short poll so they observe pool changes even
    when no worker releases.
    """

    def __init__(self, limit_fn: Callable[[], int], *, poll_seconds: float = 0.5) -> None:
        self._limit_fn = limit_fn
        self._poll_seconds = max(0.05, float(poll_seconds))
        self._condition = threading.Condition()
        self._active = 0

    def current_limit(self) -> int:
        """Return the effective in-flight ceiling right now."""
        try:
            return max(1, min(int(self._limit_fn() or 1), 1_024))
        except Exception:
            # A broken pool projection must not wedge the queue; fall back to
            # serial execution until the store answers again.
            return 1

    def active(self) -> int:
        with self._condition:
            return self._active

    def __enter__(self) -> "ProxyPoolConcurrencyGate":
        with self._condition:
            while True:
                if self._active < self.current_limit():
                    self._active += 1
                    return self
                self._condition.wait(timeout=self._poll_seconds)

    def __exit__(self, *exc_info: object) -> None:
        with self._condition:
            self._active = max(0, self._active - 1)
            self._condition.notify_all()
