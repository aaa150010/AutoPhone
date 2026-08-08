"""Failure-isolated importer watcher finalization."""

from __future__ import annotations

import time
from typing import Any, Callable


def _log_failure(importer: Any, node_code: str, label: str, cause: str, error: BaseException) -> None:
    """Log only the exception type so cleanup diagnostics cannot leak credentials."""

    try:
        importer._log(
            f"[{label}/{node_code}] {cause}（{type(error).__name__}）",
            "error",
        )
    except Exception:
        # There is no remaining local diagnostic sink if the importer's own
        # logger is unavailable. This must never block later cleanup steps.
        return


def _finished_aggregate(
    importer: Any,
    context: dict[str, Any],
    aggregate_fn: Callable[..., Any],
) -> Any | None:
    try:
        aggregate, last_activity_at = aggregate_fn(importer, context, finished=True)
    except Exception as exc:
        _log_failure(
            importer,
            "run_notification_snapshot",
            "运行结束通知",
            "汇总任务终态失败，批次对账将继续",
            exc,
        )
        return None
    context["last_activity_at"] = last_activity_at or context.get("last_activity_at", 0)
    return aggregate


def _unfinished_tasks(
    importer: Any,
    unfinished_fn: Callable[[Any], Any],
) -> tuple[str, ...] | None:
    try:
        return tuple(unfinished_fn(importer))
    except Exception as exc:
        _log_failure(
            importer,
            "run_notification_task_snapshot",
            "运行结束通知",
            "读取未完成任务失败，禁止发送错误的完成通知",
            exc,
        )
        return None


def _observe_notification(
    importer: Any,
    context: dict[str, Any],
    aggregate: Any,
    sms_exhausted_fn: Callable[[], bool],
) -> None:
    try:
        context["service"].observe_run(
            context["run_id"],
            aggregate,
            sms_exhausted=sms_exhausted_fn(),
        )
    except Exception as exc:
        _log_failure(
            importer,
            "run_notification_observe",
            "运行结束通知",
            "更新运行通知状态失败，批次对账不受影响",
            exc,
        )


def _finalize_notification(
    importer: Any,
    context: dict[str, Any],
    aggregate: Any,
    *,
    completed: bool,
    unfinished_task_ids: tuple[str, ...] = (),
    termination_reason: str = "",
) -> None:
    try:
        kwargs: dict[str, Any] = {
            "completed": completed,
            "batch_id": context.get("batch_id"),
        }
        if not completed:
            kwargs["unfinished_task_ids"] = unfinished_task_ids
            kwargs["termination_reason"] = termination_reason
        context["service"].finalize_run(context["run_id"], aggregate, **kwargs)
    except Exception as exc:
        _log_failure(
            importer,
            "run_notification_finalize",
            "运行结束通知",
            "发送最终运行通知失败，批次对账不受影响",
            exc,
        )


def finalize_importer_watch(
    importer: Any,
    context: dict[str, Any],
    *,
    watch_failed: bool,
    aggregate_fn: Callable[..., Any],
    unfinished_fn: Callable[[Any], Any],
    reconcile_fn: Callable[[Any, dict[str, Any]], Any],
    sms_exhausted_fn: Callable[[], bool],
    now_fn: Callable[[], float] = time.time,
) -> None:
    """Finalize notifications and reconciliation without cross-stage failures."""

    try:
        context["finished_at"] = int(now_fn())
        context["stop_event"].set()
    except Exception as exc:
        _log_failure(
            importer,
            "run_watch_cleanup",
            "运行结束清理",
            "停止通知监视器失败，后续批次对账将继续",
            exc,
        )

    aggregate = _finished_aggregate(importer, context, aggregate_fn)
    unfinished = _unfinished_tasks(importer, unfinished_fn)
    if aggregate is not None:
        _observe_notification(importer, context, aggregate, sms_exhausted_fn)
        if watch_failed or unfinished:
            _finalize_notification(
                importer,
                context,
                aggregate,
                completed=False,
                unfinished_task_ids=unfinished or (),
                termination_reason=(
                    "watch_failed" if watch_failed else "watch_returned_with_unfinished_tasks"
                ),
            )

    should_reconcile = not watch_failed
    if watch_failed:
        try:
            futures = list(getattr(importer, "futures", ()) or ())
            should_reconcile = all(future.done() for future in futures)
        except Exception as exc:
            should_reconcile = False
            _log_failure(
                importer,
                "run_batch_reconcile_readiness",
                "运行批次对账",
                "检查任务结束状态失败，暂不提前补写终态",
                exc,
            )
    reconciliation_succeeded = False
    if should_reconcile:
        try:
            reconcile_fn(importer, context)
        except Exception as exc:
            _log_failure(
                importer,
                "run_batch_manifest",
                "运行批次对账",
                "批次结束对账失败，清单保留待恢复状态",
                exc,
            )
            if aggregate is not None:
                _finalize_notification(
                    importer,
                    context,
                    aggregate,
                    completed=False,
                    unfinished_task_ids=unfinished or (),
                    termination_reason="batch_reconcile_failed",
                )
        else:
            reconciliation_succeeded = True

        refreshed = _finished_aggregate(importer, context, aggregate_fn)
        if refreshed is not None:
            aggregate = refreshed

    remaining = _unfinished_tasks(importer, unfinished_fn)
    if reconciliation_succeeded and remaining == () and aggregate is not None:
        _observe_notification(importer, context, aggregate, sms_exhausted_fn)
        _finalize_notification(importer, context, aggregate, completed=True)


__all__ = ["finalize_importer_watch"]
