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
# Coarse slice used only when a gate acquires WITHOUT a stop event. A stop
# event lives outside the gate's Condition, so it can only be observed across
# wait timeouts — those loops keep the fine slice. Capacity changes themselves
# are event-driven via notify_all.
GATE_WAIT_MAX_SECONDS = 1.0


def gate_wait_slice(remaining: float, *, stop_observed: bool = True) -> float:
    """Choose the next Condition.wait timeout.

    ``remaining`` is an optional time-driven deadline (pause expiry, launch
    spacing); the slice never exceeds it. Loops that must observe an external
    stop event through wait timeouts keep the fine slice; a loop without any
    stop signal may sleep up to the coarse ceiling because only time-driven
    predicates can change its fate.
    """
    if remaining > 0:
        return min(GATE_WAIT_TIMEOUT_SECONDS, remaining)
    if stop_observed:
        return GATE_WAIT_TIMEOUT_SECONDS
    return GATE_WAIT_MAX_SECONDS


def stop_event_is_set(stop_event: Any) -> bool:
    """Shared stop-event predicate for gate loops and wait helpers."""
    if stop_event is None:
        return False
    checker = getattr(stop_event, "is_set", None)
    if callable(checker):
        return bool(checker())
    return bool(stop_event()) if callable(stop_event) else bool(stop_event)
