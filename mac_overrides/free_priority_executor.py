"""Priority-aware executor for the unified Free registration queue."""

from __future__ import annotations

from concurrent.futures import Future
import itertools
import queue
import threading
from typing import Any, Callable


class PriorityExecutor:
    """Run callables under one worker ceiling with stable queue priority.

    Lower numeric priorities run first. Already-running work is never
    interrupted, and equal-priority work retains FIFO order.
    """

    def __init__(self, max_workers: int, *, thread_name_prefix: str = "free") -> None:
        self._max_workers = max(1, int(max_workers))
        self._prefix = str(thread_name_prefix or "free")
        self._queue: queue.PriorityQueue[tuple[int, int, Any]] = queue.PriorityQueue()
        self._counter = itertools.count()
        self._lock = threading.RLock()
        self._shutdown = False
        self._threads: list[threading.Thread] = []
        for index in range(self._max_workers):
            worker = threading.Thread(
                target=self._worker,
                name=f"{self._prefix}_{index}",
                daemon=True,
            )
            worker.start()
            self._threads.append(worker)

    def submit(
        self,
        fn: Callable[..., Any],
        /,
        *args: Any,
        priority: int = 10,
        **kwargs: Any,
    ) -> Future[Any]:
        future: Future[Any] = Future()
        with self._lock:
            if self._shutdown:
                raise RuntimeError("cannot schedule new futures after shutdown")
            self._queue.put((int(priority), next(self._counter), (future, fn, args, kwargs)))
        return future

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        with self._lock:
            if not self._shutdown:
                self._shutdown = True
                if cancel_futures:
                    self._cancel_queued()
                for _ in self._threads:
                    self._queue.put((10**9, next(self._counter), None))
        if wait:
            current = threading.current_thread()
            for worker in self._threads:
                if worker is not current:
                    worker.join()

    def _cancel_queued(self) -> None:
        retained: list[tuple[int, int, Any]] = []
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            payload = item[2]
            if payload is None:
                retained.append(item)
            else:
                payload[0].cancel()
            self._queue.task_done()
        for item in retained:
            self._queue.put(item)

    def _worker(self) -> None:
        while True:
            _priority, _sequence, payload = self._queue.get()
            try:
                if payload is None:
                    return
                future, fn, args, kwargs = payload
                if not future.set_running_or_notify_cancel():
                    continue
                try:
                    result = fn(*args, **kwargs)
                except BaseException as exc:
                    future.set_exception(exc)
                else:
                    future.set_result(result)
            finally:
                self._queue.task_done()


__all__ = ["PriorityExecutor"]
