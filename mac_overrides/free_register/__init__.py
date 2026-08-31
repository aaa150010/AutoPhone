"""Composable services for the isolated Free registration runtime.

The historical :mod:`mac_overrides.free_register_runtime` module remains the
public compatibility facade.  New code should depend on this package for task
contracts, persistence, scheduling, retry classification, worker execution,
and timing.
"""

from .contracts import (
    ACTIVE_TASK_STATUSES,
    TERMINAL_TASK_STATUSES,
    FreeTaskSnapshot,
    MailboxLease,
    TaskTransition,
    normalize_task_status,
)
from .manager import FreeManagerComponents, build_manager_components
from .retry_policy import FreeRetryPolicy, RetryDecision
from .task_repository import FreeTaskRepository, TaskConflictError
from .timing import TaskTimingRecorder
from .worker import FreeTaskWorker, WorkerResult


def __getattr__(name: str):
    """Resolve legacy manager symbols lazily to avoid an import cycle.

    ``FreeRegisterManager`` still lives in the compatibility runtime while
    the smaller services migrate into this package.  Keeping the lookup lazy
    means importing contracts/repositories does not eagerly initialize the
    legacy runtime (or its optional integrations).
    """

    if name == "FreeRegisterManager":
        from .manager import legacy_manager_class

        return legacy_manager_class()
    raise AttributeError(name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"FreeRegisterManager"})

__all__ = [
    "ACTIVE_TASK_STATUSES",
    "TERMINAL_TASK_STATUSES",
    "FreeManagerComponents",
    "FreeRegisterManager",
    "FreeRetryPolicy",
    "FreeTaskRepository",
    "FreeTaskSnapshot",
    "FreeTaskWorker",
    "MailboxLease",
    "RetryDecision",
    "TaskConflictError",
    "TaskTimingRecorder",
    "TaskTransition",
    "WorkerResult",
    "build_manager_components",
    "normalize_task_status",
]
