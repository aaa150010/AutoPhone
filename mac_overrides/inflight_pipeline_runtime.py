"""Short-lived protocol leases for optional staged task admission."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, TypeVar


Result = TypeVar("Result")
_PROTOCOL_LEASE_DEPTH: ContextVar[int] = ContextVar(
    "gptphone_protocol_lease_depth",
    default=0,
)


def optimization_active(gate: Any) -> bool:
    """Return whether this batch may use staged task admission."""
    snapshot = getattr(gate, "snapshot", None)
    if not callable(snapshot):
        return False
    try:
        state = snapshot()
    except Exception:
        return False
    return bool(isinstance(state, dict) and state.get("optimized"))


@contextmanager
def protocol_session_scope(
    *,
    staged: bool,
    gate: Any,
    proxy: Any,
    stop_event: Any,
    on_wait: Callable[[float], Any] | None = None,
) -> Iterator[None]:
    """Keep the legacy full-session lease only outside staged mode."""
    if staged:
        yield
        return
    with gate.acquire(proxy, stop_event=stop_event, on_wait=on_wait):
        yield


def call_with_protocol_lease(
    callback: Callable[[], Result],
    *,
    staged: bool,
    gate: Any,
    proxy: Any,
    stop_event: Any,
    on_wait: Callable[[float], Any] | None = None,
    success_fn: Callable[[Result], bool] | None = None,
    on_result: Callable[[Any, bool], Any] | None = None,
) -> Result:
    """Run one OpenAI request under a short lease in staged mode."""
    if not staged:
        return callback()
    if _PROTOCOL_LEASE_DEPTH.get() > 0:
        return callback()
    try:
        with gate.acquire(proxy, stop_event=stop_event, on_wait=on_wait):
            token = _PROTOCOL_LEASE_DEPTH.set(_PROTOCOL_LEASE_DEPTH.get() + 1)
            try:
                result = callback()
            finally:
                _PROTOCOL_LEASE_DEPTH.reset(token)
    except Exception as exc:
        if callable(on_result):
            try:
                on_result(exc, False)
            except Exception:
                pass
        raise
    if callable(on_result):
        try:
            succeeded = bool(success_fn(result)) if callable(success_fn) else False
            on_result(result, succeeded)
        except Exception:
            pass
    return result


__all__ = [
    "call_with_protocol_lease",
    "optimization_active",
    "protocol_session_scope",
]
