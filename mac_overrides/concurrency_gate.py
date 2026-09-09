"""Shared primitives for the Condition-based concurrency admission gates.

Four gates (phase, adaptive, inflight, protocol) repeat the same stop-event
predicate and wait-timeout constants. They keep their own acquire loops
because their admission semantics differ; only the truly identical pieces
live here.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "GATE_WAIT_TIMEOUT_SECONDS",
    "GATE_WAIT_MAX_SECONDS",
    "gate_wait_slice",
    "stop_event_is_set",
]


# Upper bound for one Condition.wait slice inside every admission loop.
GATE_WAIT_TIMEOUT_SECONDS = 0.25
# Fallback poll ceiling for time-driven predicates (pause/launch-interval
# expiry). Capacity changes themselves are event-driven via notify_all, so a
# waiting thread only needs to re-check at a coarse cadence for clock-driven
# conditions — 1s bounds stop-free drift without the old 4x wake-up cost.
GATE_WAIT_MAX_SECONDS = 1.0


def gate_wait_slice(remaining: float) -> float:
    """Choose the next Condition.wait timeout.

    ``remaining`` is an optional time-driven deadline (pause expiry, launch
    spacing). The slice never exceeds the caller's deadline, falls back to
    the shared fine slice for fine-grained predicates, and caps at the coarse
    ceiling otherwise.
    """
    if remaining > 0:
        return min(GATE_WAIT_TIMEOUT_SECONDS, remaining)
    return GATE_WAIT_MAX_SECONDS


def stop_event_is_set(stop_event: Any) -> bool:
    """Shared stop-event predicate for gate loops and wait helpers."""
    if stop_event is None:
        return False
    checker = getattr(stop_event, "is_set", None)
    if callable(checker):
        return bool(checker())
    return bool(stop_event()) if callable(stop_event) else bool(stop_event)
