"""Pure Pixel upload batch aggregation for public queue state."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def build_pixel_batch_summary(
    batch_id: str,
    records: Iterable[Mapping[str, Any]],
    target_ids: Iterable[str],
) -> dict[str, Any]:
    """Aggregate durable upload records without reading queue runtime state."""
    record_values = list(records)
    targets_in_scope = tuple(target_ids)
    source_total = sum(
        max(_safe_int(record.get("source_count")), 1)
        for record in record_values
    )
    source_success = 0
    source_completed = 0
    source_processing = 0
    source_pending = 0
    source_failed = 0
    source_needs_confirmation = 0
    deliveries = {
        "total": source_total * len(targets_in_scope),
        "success": 0,
        "pending": 0,
        "processing": 0,
        "failed": 0,
        "needs_confirmation": 0,
    }
    updated_at = 0
    started_at = 0

    for record in record_values:
        record_source_count = max(_safe_int(record.get("source_count")), 1)
        updated_at = max(updated_at, _safe_int(record.get("updated_at")))
        started_at = max(
            started_at,
            _safe_int(record.get("batch_started_at")),
            _safe_int(record.get("created_at")),
        )
        targets = record.get("targets") if isinstance(record.get("targets"), Mapping) else {}
        categories: list[str] = []
        for target_id in targets_in_scope:
            target = targets.get(target_id) if isinstance(targets, Mapping) else None
            if not isinstance(target, Mapping):
                category = "pending"
            else:
                state = _clean(target.get("state")).lower() or "pending"
                if state == "success":
                    category = "success"
                elif state == "needs_confirmation":
                    category = "needs_confirmation"
                elif state == "importing":
                    category = "processing"
                elif state == "pending" or bool(target.get("retry_requested")):
                    category = "pending"
                else:
                    category = "failed"
            categories.append(category)
            deliveries[category] += record_source_count

        if categories and all(value == "success" for value in categories):
            source_success += record_source_count
            source_completed += record_source_count
        elif "processing" in categories:
            source_processing += record_source_count
        elif "pending" in categories:
            source_pending += record_source_count
        else:
            source_completed += record_source_count
            source_failed += record_source_count
        if "needs_confirmation" in categories:
            source_needs_confirmation += record_source_count

    deliveries["completed"] = (
        deliveries["success"]
        + deliveries["failed"]
        + deliveries["needs_confirmation"]
    )
    source = {
        "total": source_total,
        "completed": source_completed,
        "success": source_success,
        "pending": source_pending,
        "processing": source_processing,
        "failed": source_failed,
        "needs_confirmation": source_needs_confirmation,
    }
    if source_total and source_success == source_total:
        status = "success"
    elif source_pending or source_processing:
        status = "processing"
    elif source_success:
        status = "partial"
    elif source_total:
        status = "failed"
    else:
        status = "empty"
    return {
        "batch_id": batch_id,
        "batch_started_at": started_at,
        "updated_at": updated_at,
        "status": status,
        "source": source,
        "deliveries": deliveries,
    }


__all__ = ["build_pixel_batch_summary"]
