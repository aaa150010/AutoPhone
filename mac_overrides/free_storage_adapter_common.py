"""Shared helpers and constants for the Free SQLite storage adapters."""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any, Mapping

try:
    from .free_register_common import TERMINAL_STATUSES
except ImportError:  # pragma: no cover - recovery imports
    from free_register_common import TERMINAL_STATUSES  # type: ignore[no-redef]


_ACTIVE_MAILBOX_STATUSES = frozenset({"reserved", "queued", "running"})
# The mailbox ``update`` adapter treats a worker's terminal transition as
# authoritative even while its lease is still held.  ``pending_rerun`` is not
# a terminal task status but is written through the same lifecycle-protected
# path (a confirmed row keeps that marker until explicit rerun), so it joins
# the allowed set here.
_ACTIVE_STATUS_OVERRIDE = frozenset(TERMINAL_STATUSES | {"pending_rerun"})
_TERMINAL_TASK_STATUSES = frozenset(TERMINAL_STATUSES)
_MAILBOX_TRANSIENT_KEYS = frozenset({
    "lease_confirmed",
    "lease_confirmed_at",
    "task_id",
    "batch_id",
    "driver",
})


def _json_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return {}


def _compat_timestamp(value: Any, default: int = 0) -> int:
    """Normalize SQLite ISO timestamps to the legacy manager's epoch shape."""
    if isinstance(value, bool):
        return int(value)
    try:
        return int(float(value))
    except (TypeError, ValueError):
        pass
    text = str(value or "").strip()
    if text:
        try:
            return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
        except (TypeError, ValueError, OverflowError):
            pass
    return int(default)


# Sibling adapter modules import these private helpers explicitly.  The
# module intentionally exposes no public names, so ``__all__`` stays empty
# (per project convention private names are never registered in ``__all__``).
__all__: list[str] = []
