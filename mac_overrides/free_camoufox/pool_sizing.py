"""Derive Camoufox browser-pool sizing from the batch start configuration.

Authoritative implementation for the ``camoufox_pool_auto`` mode: the
operator only sets the registration target count and concurrency, and the
pool parameters are derived here at batch start.  The frontend mirrors this
formula in ``frontend/src/utils/camoufoxSizing.ts`` for preview only.

Sizing rules:
- ``workers`` equals the real executor width (``min(concurrency,
  target_count, 16)``, mirroring ``free_register_startup``);
- contexts per process stay at 3 while the pool is small and rise to 4 for
  larger batches;
- one extra context of headroom covers per-slot recycle windows and debug
  retention, and the process count is capped at 4 (memory guard), so the
  maximum capacity is 4 x 4 = 16, exactly the concurrency ceiling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


MAX_POOL_SIZE = 4
MAX_CONTEXTS_SMALL = 3
MAX_CONTEXTS_LARGE = 4
_LARGE_POOL_WORKERS_THRESHOLD = 6
_WORKERS_CEILING = 16


@dataclass(frozen=True, slots=True)
class CamoufoxPoolSizing:
    """Derived pool parameters for one batch start."""

    workers: int
    pool_size: int
    max_contexts: int

    @property
    def capacity(self) -> int:
        return self.pool_size * self.max_contexts


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def derive_camoufox_pool_sizing(config: Mapping[str, Any]) -> CamoufoxPoolSizing | None:
    """Derive pool sizing for a camoufox batch start.

    Returns None when auto mode is off (operator's manual ``pool_size`` /
    ``max_contexts_per_browser`` stay authoritative) or when the driver is
    not camoufox; callers then skip the injection entirely.
    """
    if str(config.get("driver") or "protocol").strip().lower() != "camoufox":
        return None
    camoufox = config.get("camoufox") if isinstance(config.get("camoufox"), Mapping) else {}
    if not camoufox.get("camoufox_pool_auto", True):
        return None
    workers = max(1, min(
        _safe_int(config.get("concurrency"), 3),
        _safe_int(config.get("target_count"), 1),
        _WORKERS_CEILING,
    ))
    max_contexts = MAX_CONTEXTS_SMALL if workers <= _LARGE_POOL_WORKERS_THRESHOLD else MAX_CONTEXTS_LARGE
    headroom_target = workers + 1
    pool_size = -(-headroom_target // max_contexts)  # ceil division
    pool_size = max(1, min(MAX_POOL_SIZE, pool_size))
    return CamoufoxPoolSizing(workers=workers, pool_size=pool_size, max_contexts=max_contexts)


__all__ = [
    "CamoufoxPoolSizing",
    "MAX_CONTEXTS_LARGE",
    "MAX_CONTEXTS_SMALL",
    "MAX_POOL_SIZE",
    "derive_camoufox_pool_sizing",
]
