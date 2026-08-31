"""Explicit Camoufox page state machine.

The legacy runner still owns the live browser algorithm.  This class provides
the durable transition contract that new adapters can use without embedding
state decisions in locator code.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import inspect
import time
from types import MappingProxyType
from typing import Any, Mapping

from .contracts import (
    CamoufoxFlowState,
    TERMINAL_FLOW_STATES,
    normalize_flow_state,
)


class InvalidTransitionError(ValueError):
    """Raised when a flow attempts an impossible state transition."""

    def __init__(self, current: CamoufoxFlowState, requested: CamoufoxFlowState) -> None:
        super().__init__(f"invalid Camoufox transition: {current.value} -> {requested.value}")
        self.current = current
        self.requested = requested


_ALLOWED_TRANSITIONS: Mapping[CamoufoxFlowState, frozenset[CamoufoxFlowState]] = MappingProxyType({
    CamoufoxFlowState.UNKNOWN: frozenset(CamoufoxFlowState),
    CamoufoxFlowState.ENTRY: frozenset({
        CamoufoxFlowState.ENTRY,
        CamoufoxFlowState.EMAIL_VERIFICATION,
        CamoufoxFlowState.OTP,
        CamoufoxFlowState.SIGNUP_PASSWORD,
        CamoufoxFlowState.LOGIN_PASSWORD,
        CamoufoxFlowState.PROFILE,
        CamoufoxFlowState.CONSENT,
        CamoufoxFlowState.SECURITY,
        CamoufoxFlowState.EXTERNAL_AUTH,
    }),
    CamoufoxFlowState.EMAIL_VERIFICATION: frozenset({
        CamoufoxFlowState.EMAIL_VERIFICATION,
        CamoufoxFlowState.OTP,
        CamoufoxFlowState.SIGNUP_PASSWORD,
        CamoufoxFlowState.LOGIN_PASSWORD,
        CamoufoxFlowState.PROFILE,
        CamoufoxFlowState.CONSENT,
        CamoufoxFlowState.SECURITY,
    }),
    CamoufoxFlowState.OTP: frozenset({
        CamoufoxFlowState.OTP,
        CamoufoxFlowState.EMAIL_VERIFICATION,
        CamoufoxFlowState.SIGNUP_PASSWORD,
        CamoufoxFlowState.LOGIN_PASSWORD,
        CamoufoxFlowState.PROFILE,
        CamoufoxFlowState.CONSENT,
        CamoufoxFlowState.OAUTH_CALLBACK,
        CamoufoxFlowState.HOME,
        CamoufoxFlowState.SECURITY,
    }),
    CamoufoxFlowState.SIGNUP_PASSWORD: frozenset({
        CamoufoxFlowState.SIGNUP_PASSWORD,
        CamoufoxFlowState.OTP,
        CamoufoxFlowState.PROFILE,
        CamoufoxFlowState.CONSENT,
        CamoufoxFlowState.OAUTH_CALLBACK,
        CamoufoxFlowState.HOME,
        CamoufoxFlowState.SECURITY,
    }),
    CamoufoxFlowState.LOGIN_PASSWORD: frozenset({
        CamoufoxFlowState.LOGIN_PASSWORD,
        CamoufoxFlowState.OTP,
        CamoufoxFlowState.PROFILE,
        CamoufoxFlowState.CONSENT,
        CamoufoxFlowState.OAUTH_CALLBACK,
        CamoufoxFlowState.HOME,
        CamoufoxFlowState.SECURITY,
    }),
    CamoufoxFlowState.PROFILE: frozenset({
        CamoufoxFlowState.PROFILE,
        CamoufoxFlowState.CONSENT,
        CamoufoxFlowState.OAUTH_CALLBACK,
        CamoufoxFlowState.HOME,
        CamoufoxFlowState.SECURITY,
    }),
    # A terms/authorization page is a distinct, non-terminal step.  It may
    # finish directly at home or hand off through the OAuth callback.
    CamoufoxFlowState.CONSENT: frozenset({
        CamoufoxFlowState.CONSENT,
        CamoufoxFlowState.OAUTH_CALLBACK,
        CamoufoxFlowState.HOME,
        CamoufoxFlowState.SECURITY,
    }),
    CamoufoxFlowState.OAUTH_CALLBACK: frozenset({
        CamoufoxFlowState.OAUTH_CALLBACK,
        CamoufoxFlowState.HOME,
        CamoufoxFlowState.SECURITY,
    }),
    CamoufoxFlowState.HOME: frozenset({CamoufoxFlowState.HOME}),
    CamoufoxFlowState.SECURITY: frozenset({
        CamoufoxFlowState.SECURITY,
    }),
    CamoufoxFlowState.EXTERNAL_AUTH: frozenset({CamoufoxFlowState.EXTERNAL_AUTH}),
})


@dataclass(frozen=True, slots=True)
class StateTransition:
    previous: CamoufoxFlowState
    current: CamoufoxFlowState
    at: float
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "previous": self.previous.value,
            "current": self.current.value,
            "at": self.at,
            **({"reason": self.reason} if self.reason else {}),
        }


@dataclass(frozen=True, slots=True)
class FlowWaitResult:
    """Outcome of waiting for one or more page states."""

    state: CamoufoxFlowState
    matched: bool
    elapsed_seconds: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "matched": self.matched,
            "elapsed_seconds": self.elapsed_seconds,
        }


class CamoufoxStateMachine:
    """Validated, append-only state history for one registration attempt."""

    ALLOWED_TRANSITIONS = _ALLOWED_TRANSITIONS

    def __init__(
        self,
        initial: CamoufoxFlowState | str = CamoufoxFlowState.UNKNOWN,
        *,
        strict: bool = True,
    ) -> None:
        self.strict = bool(strict)
        self._state = normalize_flow_state(initial)
        self._history: list[StateTransition] = []

    @property
    def state(self) -> CamoufoxFlowState:
        return self._state

    @property
    def terminal(self) -> bool:
        return self._state in TERMINAL_FLOW_STATES

    @property
    def history(self) -> tuple[StateTransition, ...]:
        return tuple(self._history)

    @property
    def last_transition(self) -> StateTransition | None:
        return self._history[-1] if self._history else None

    def can_transition(self, requested: CamoufoxFlowState | str) -> bool:
        target = normalize_flow_state(requested)
        return target in _ALLOWED_TRANSITIONS.get(self._state, frozenset())

    def transition(
        self,
        requested: CamoufoxFlowState | str,
        *,
        reason: str = "",
        at: float | None = None,
    ) -> StateTransition:
        target = normalize_flow_state(requested)
        if self.strict and not self.can_transition(target):
            raise InvalidTransitionError(self._state, target)
        item = StateTransition(
            previous=self._state,
            current=target,
            at=time.time() if at is None else float(at),
            reason=str(reason or "")[:240],
        )
        self._state = target
        self._history.append(item)
        return item

    def observe(self, requested: CamoufoxFlowState | str, *, reason: str = "") -> StateTransition:
        """Record a classifier observation, tolerating unknown intermediate UI."""

        target = normalize_flow_state(requested)
        # A terminal business outcome must remain terminal until the caller
        # explicitly starts a new attempt with ``reset``.  In particular, a
        # detached page is commonly classified as ``unknown`` during cleanup;
        # allowing that observation to transition away from ``home`` or a
        # security challenge would make a cleanup/transport event look like a
        # new business failure and could enable an accidental retry.
        if self.terminal and target is not self._state and self.strict:
            raise InvalidTransitionError(self._state, target)
        if target is CamoufoxFlowState.UNKNOWN and self.strict:
            # Unknown is diagnostic evidence, not a transition that should
            # permanently poison the flow; record it in permissive mode.
            old_strict = self.strict
            self.strict = False
            try:
                return self.transition(target, reason=reason)
            finally:
                self.strict = old_strict
        return self.transition(target, reason=reason)

    def reset(self, state: CamoufoxFlowState | str = CamoufoxFlowState.UNKNOWN) -> None:
        self._state = normalize_flow_state(state)
        self._history.clear()


class CamoufoxFlowCoordinator:
    """Connect a page transport to the validated state machine.

    This coordinator contains only polling and transition bookkeeping.  OTP,
    mailbox, retry and security-challenge decisions remain in the runner, so
    adding a new page selector cannot silently change business semantics.
    """

    def __init__(self, transport: Any, *, machine: CamoufoxStateMachine | None = None) -> None:
        self.transport = transport
        self.machine = machine or CamoufoxStateMachine()

    async def observe(self, *, reason: str = "page_observed") -> StateTransition:
        reader = getattr(self.transport, "page_state", None)
        if not callable(reader):
            raise TypeError("transport must provide page_state()")
        value = reader()
        if inspect.isawaitable(value):
            value = await value
        return self.machine.observe(value, reason=reason)

    async def wait_for(
        self,
        states: set[CamoufoxFlowState | str] | tuple[CamoufoxFlowState | str, ...],
        *,
        timeout: float,
        poll_interval: float = 0.35,
    ) -> FlowWaitResult:
        wanted = {normalize_flow_state(item) for item in states}
        started = time.monotonic()
        deadline = started + max(0.0, float(timeout))
        while True:
            transition = await self.observe(reason="page_state_poll")
            if transition.current in wanted:
                return FlowWaitResult(transition.current, True, time.monotonic() - started)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return FlowWaitResult(self.machine.state, False, time.monotonic() - started)
            await asyncio.sleep(min(max(0.01, float(poll_interval)), remaining))


def __getattr__(name: str) -> Any:
    """Expose the live flow coroutine as a lazy compatibility symbol."""

    if name in {"_browser_flow", "browser_flow"}:
        try:
            from .. import free_camoufox_runtime
            return getattr(free_camoufox_runtime, "_browser_flow")
        except Exception as exc:  # pragma: no cover - top-level recovery import
            raise AttributeError(name) from exc
    raise AttributeError(name)


__all__ = [
    "CamoufoxStateMachine",
    "CamoufoxFlowCoordinator",
    "FlowWaitResult",
    "InvalidTransitionError",
    "StateTransition",
    "_browser_flow",
    "browser_flow",
]
