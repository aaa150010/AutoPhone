"""Coordinate mailbox imports with the currently active registration batch."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from typing import Any


def append_imported_mailboxes(
    source_rows: Sequence[str],
    *,
    importer: Any,
    row_id_from_source: Callable[[Any], str],
    reserve_specific_available: Callable[..., list[Any]],
    release_owned_batch_leases: Callable[..., Mapping[str, Any]],
    mailbox_error_type: type[Exception],
    next_batch_priority: Any,
    notification_context_for: Callable[[Any], Any],
) -> dict[str, Any]:
    rows = [str(row or "").strip() for row in source_rows if str(row or "").strip()]
    if not rows:
        return {"joined_current_batch": 0, "queued_current_batch": 0, "next_batch": 0}
    with importer.lock:
        running = bool(getattr(importer, "running", False))
        accepting = bool(getattr(importer, "_gptphone_append_accepting", False))
        append_entries = getattr(importer, "_gptphone_append_entries", None)
        run_settings = copy.deepcopy(getattr(importer, "_gptphone_run_settings", None) or {})
    run_mode = str(run_settings.get("run_mode") or "register").strip().lower()
    if not running:
        return {"joined_current_batch": 0, "queued_current_batch": 0, "next_batch": 0}
    if run_mode == "relogin":
        return _next_batch(len(rows), "当前为重登批次，新增邮箱已转入下一批注册优先队列")
    if not accepting or not callable(append_entries):
        return _next_batch(len(rows), "当前批次已关闭，新增邮箱已转入下一批优先队列")

    batch_id = str(run_settings.get("batch_id") or "").strip()
    pool = importer._pool(run_settings)
    leased: list[Any] = []
    try:
        leased = reserve_specific_available(
            pool,
            [row_id_from_source(row) for row in rows],
            lease_seconds=3600,
            lease_owner_batch_id=batch_id,
            mailbox_error_type=mailbox_error_type,
        )
        result = dict(append_entries(leased))
    except Exception:
        _release_failed_append(
            leased,
            pool=pool,
            batch_id=batch_id,
            row_id_from_source=row_id_from_source,
            release_owned_batch_leases=release_owned_batch_leases,
        )
        return _next_batch(
            len(rows),
            "当前批次已结束或邮箱状态已变化，新增邮箱已转入下一批优先队列",
        )

    for row in rows:
        try:
            next_batch_priority.consume(row)
        except Exception:
            pass
    context = notification_context_for(importer)
    if isinstance(context, dict):
        joined = int(result.get("joined_current_batch") or 0)
        context["target"] = max(
            int(context.get("target") or 0) + joined,
            len(getattr(importer, "tasks", {}) or {}),
        )
    result["next_batch"] = 0
    return result


def _next_batch(count: int, reason: str) -> dict[str, Any]:
    return {
        "joined_current_batch": 0,
        "queued_current_batch": 0,
        "next_batch": max(int(count), 0),
        "append_node_code": "current_batch_closed",
        "append_node_label": "追加当前运行批次",
        "append_reason": reason,
    }


def _release_failed_append(
    leased: Sequence[Any],
    *,
    pool: Any,
    batch_id: str,
    row_id_from_source: Callable[[Any], str],
    release_owned_batch_leases: Callable[..., Mapping[str, Any]],
) -> None:
    if not leased or not batch_id:
        return
    try:
        release_owned_batch_leases(
            pool,
            batch_id,
            [
                {
                    "row_id": row_id_from_source(getattr(entry, "source_row", "")),
                    "line_no": int(getattr(entry, "line_no", 0) or 0),
                }
                for entry in leased
            ],
            reason="current_batch_append_failed",
        )
    except Exception:
        pass


__all__ = ["append_imported_mailboxes"]
