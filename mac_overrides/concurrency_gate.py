"""Shared primitives for the Condition-based concurrency admission gates.

Four gates (phase, adaptive, inflight, protocol) repeat the same stop-event
predicate and wait-timeout constants. They keep their own acquire loops
because their admission semantics differ; only the truly identical pieces
live here.
"""

from __future__ import annotations

from typing import Any

__all__ = ["GATE_WAIT_TIMEOUT_SECONDS", "stop_event_is_set"]


# Upper bound for one Condition.wait slice inside every admission loop.
GATE_WAIT_TIMEOUT_SECONDS = 0.25


def stop_event_is_set(stop_event: Any) -> bool:
    """Shared stop-event predicate for gate loops and wait helpers."""
    if stop_event is None:
        return False
    checker = getattr(stop_event, "is_set", None)
    if callable(checker):
        return bool(checker())
    return bool(stop_event()) if callable(stop_event) else bool(stop_event)
