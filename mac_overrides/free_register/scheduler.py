"""Bounded scheduling facade for Free workers."""

from __future__ import annotations

from concurrent.futures import Future
import threading
from typing import Any, Callable

try:
    from ..free_priority_executor import PriorityExecutor
except ImportError:  # pragma: no cover
    from free_priority_executor import PriorityExecutor  # type: ignore[no-redef]


class FreeTaskScheduler:
    def __init__(self, workers: int, *, executor_factory: Callable[..., Any] = PriorityExecutor) -> None:
        self.workers = max(1, int(workers))
        self.executor_factory = executor_factory
        self._executor: Any | None = None
        self._futures: set[Future[Any]] = set()
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            if self._executor is None:
                self._executor = self.executor_factory(max_workers=self.workers)

    def submit(self, callback: Callable[..., Any], *args: Any, priority: int = 10, **kwargs: Any) -> Future[Any]:
        self.start()
        with self._lock:
            assert self._executor is not None
            try:
                future = self._executor.submit(priority, callback, *args, **kwargs)
            except TypeError:
                future = self._executor.submit(callback, *args, **kwargs)
            self._futures.add(future)
            future.add_done_callback(self._discard)
            return future

    def _discard(self, future: Future[Any]) -> None:
        with self._lock:
            self._futures.discard(future)

    def stop(self, *, cancel_pending: bool = True, wait: bool = False) -> None:
        with self._lock:
            executor = self._executor
            futures = tuple(self._futures)
            self._executor = None
        if cancel_pending:
            for future in futures:
                future.cancel()
        if executor is not None:
            try:
                executor.shutdown(wait=wait, cancel_futures=cancel_pending)
            except TypeError:
                executor.shutdown(wait=wait)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            futures = tuple(self._futures)
        return {
            "workers": self.workers,
            "pending": sum(not item.done() for item in futures),
            "done": sum(item.done() for item in futures),
        }


__all__ = ["FreeTaskScheduler"]
