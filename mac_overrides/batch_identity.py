"""Stable human-readable identifiers for one registration run."""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from typing import Any


_SUFFIX_RE = re.compile(r"^(?P<base>\d{8}-\d{4})(?:-(?P<suffix>\d{2,}))?$")


def batch_minute_key(started_at: float | int | None = None) -> str:
    """Return the local `YYYYMMDD-HHMM` identity for a start timestamp."""
    value = time.time() if started_at is None else started_at
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        timestamp = time.time()
    return time.strftime("%Y%m%d-%H%M", time.localtime(timestamp))


def allocate_batch_id(
    started_at: float | int | None = None,
    existing_ids: Iterable[Any] = (),
) -> str:
    """Allocate the first unused ID for the local minute.

    The first run in a minute keeps the compact minute key.  A second run in
    that same minute gets `-02`, then `-03`, and so on.  Older random or
    second-based IDs are intentionally ignored because they cannot collide
    with the new identity format.
    """
    base = batch_minute_key(started_at)
    used = set()
    for raw in existing_ids:
        match = _SUFFIX_RE.fullmatch(str(raw or "").strip())
        if not match or match.group("base") != base:
            continue
        suffix = match.group("suffix")
        used.add(1 if suffix is None else int(suffix))

    if 1 not in used:
        return base
    suffix = 2
    while suffix in used:
        suffix += 1
    return f"{base}-{suffix:02d}"


def allocate_run_batch_id(context: Any, started_at: int, logs: Any = None) -> str:
    """Allocate a minute-based run ID without colliding with persisted runs."""
    existing_ids: list[str] = []
    manifest = getattr(context, "run_batch_manifest", None)
    records = getattr(manifest, "records", None)
    if callable(records):
        try:
            existing_ids = [
                str(item.get("batch_id") or "")
                for item in records(limit=500, include_members=False)
                if isinstance(item, Mapping)
            ]
        except Exception:
            try:
                logs.add(
                    "运行批次号去重读取历史清单失败，将使用当前分钟号",
                    "warn",
                )
            except Exception:
                pass
    return allocate_batch_id(started_at, existing_ids)


__all__ = ["allocate_batch_id", "allocate_run_batch_id", "batch_minute_key"]
