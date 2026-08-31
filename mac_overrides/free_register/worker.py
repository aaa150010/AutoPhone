"""Transport-neutral Free worker composition."""

from __future__ import annotations

from dataclasses import dataclass, field
import copy
from typing import Any, Callable, Mapping

from .retry_policy import FreeRetryPolicy, RetryDecision
from .timing import TaskTimingRecorder


@dataclass(frozen=True, slots=True)
class WorkerResult:
    status: str
    result: Mapping[str, Any] = field(default_factory=dict, repr=False)
    error: BaseException | None = field(default=None, repr=False)
    retry: RetryDecision = field(default_factory=lambda: RetryDecision(False))


class FreeTaskWorker:
    """Invoke one adapter without owning scheduling or persistence."""

    def __init__(
        self,
        runner: Callable[..., Mapping[str, Any]],
        *,
        retry_policy: FreeRetryPolicy | None = None,
        timing_factory: Callable[[], TaskTimingRecorder] = TaskTimingRecorder,
    ) -> None:
        self.runner = runner
        self.retry_policy = retry_policy or FreeRetryPolicy()
        self.timing_factory = timing_factory

    def run(
        self,
        task: Mapping[str, Any],
        config: Mapping[str, Any],
        stop_event: Any,
        stage: Callable[..., Any],
        log: Callable[..., Any],
        **kwargs: Any,
    ) -> WorkerResult:
        timing = self.timing_factory()
        timing.enter("free_worker", attempt=int(task.get("retry_attempt") or 0) + 1)
        try:
            result = dict(self.runner(task, config, stop_event, stage, log, **kwargs))
            timing.leave("free_worker", outcome="success")
            result.setdefault("timing", timing.snapshot())
            return WorkerResult(str(result.get("status") or "success"), result)
        except BaseException as exc:
            timing.leave(
                "free_worker",
                outcome="failed",
                failure_code=str(getattr(exc, "error_code", "") or type(exc).__name__),
                retryable=getattr(exc, "retryable", None),
            )
            failure = {
                "node_code": str(getattr(exc, "node_code", "") or "free_worker"),
                "error_code": str(getattr(exc, "error_code", "") or "free_worker_failed"),
                "retryable": getattr(exc, "retryable", True),
                "http_status": getattr(exc, "provider_status", None),
            }
            decision = self.retry_policy.decide(
                failure,
                attempt=int(task.get("retry_attempt") or 0),
            )
            return WorkerResult(
                "failed",
                {"failure": copy.deepcopy(failure), "timing": timing.snapshot()},
                exc,
                decision,
            )


__all__ = ["FreeTaskWorker", "WorkerResult"]
