"""Bounded registration budget with manual-OTP pause support.

``RegistrationDeadline`` is owned by one registration invocation: while paused,
``remaining`` is frozen and ``is_expired`` is false; resuming shifts the
absolute deadline by the time spent in the manual window.  The browser flow,
its worker watchdog and the mailbox provider observe one budget without
extending ordinary waits.

This module imports only the standard library, so it stays safe to load
without the optional Camoufox package.
"""

from __future__ import annotations

import math
import threading
import time
from typing import Any, Callable, Mapping


MANUAL_OTP_WINDOW_SECONDS = 300
MANUAL_OTP_HANDOFF_GRACE_SECONDS = 2.0
MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS = 30.0
MAX_MANUAL_OTP_WINDOWS = 3

_DEADLINE_CONTROLLER_MISSING = object()


def deadline_controller_call(
    controller: Any,
    name: str,
    *args: Any,
    default: Any = _DEADLINE_CONTROLLER_MISSING,
) -> Any:
    """Invoke an optional controller hook without making it a failure node."""
    if controller is None:
        return default
    try:
        method = getattr(controller, name, None)
        if not callable(method):
            return default
        return method(*args)
    except Exception:
        # Older recovered adapters can expose only a partial controller. The
        # absolute monotonic deadline remains the compatibility fallback.
        return default


def deadline_controller_bool(controller: Any, name: str) -> bool:
    value = deadline_controller_call(controller, name, default=False)
    try:
        return bool(value)
    except Exception:
        return False


class RegistrationDeadline:
    """A monotonic registration budget that can pause for manual OTP input.

    The controller is intentionally in-memory and owned by one registration
    invocation.  While paused, ``remaining`` is frozen and ``is_expired`` is
    false; resuming shifts the absolute deadline by the time spent in the
    manual window.  This lets the browser flow, its worker watchdog and the
    mailbox provider observe one budget without extending ordinary waits.
    """

    def __init__(
        self,
        timeout_seconds: float,
        *,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._monotonic = monotonic_fn
        now = float(monotonic_fn())
        try:
            timeout = max(0.0, float(timeout_seconds))
        except (TypeError, ValueError):
            timeout = 0.0
        self._deadline = now + timeout
        self._paused_at: float | None = None
        self._paused_remaining = 0.0
        self._last_outcome = ""
        self._manual_prompt_active = False
        self._manual_handoff_until = 0.0
        self._post_submit_grace_until = 0.0
        self._otp_wait_depth = 0
        self._lock = threading.RLock()

    def is_paused(self) -> bool:
        with self._lock:
            return self._paused_at is not None

    def remaining(self) -> float:
        with self._lock:
            if self._paused_at is not None:
                return max(0.0, self._paused_remaining)
            return max(0.0, self._deadline - float(self._monotonic()))

    def deadline(self) -> float:
        with self._lock:
            return float(self._deadline)

    def is_expired(self) -> bool:
        with self._lock:
            return self._paused_at is None and self._deadline <= float(self._monotonic())

    def begin_otp_wait(self) -> None:
        """Mark a task-scoped OTP callback as active for watchdog handoff."""
        with self._lock:
            self._otp_wait_depth += 1

    def end_otp_wait(self) -> None:
        with self._lock:
            self._otp_wait_depth = max(0, self._otp_wait_depth - 1)

    def otp_wait_active(self) -> bool:
        with self._lock:
            return self._otp_wait_depth > 0

    def request_manual_handoff(self) -> None:
        """Pause briefly so an OTP worker can open its manual prompt."""
        with self._lock:
            self._pause_manual_locked()
            self._manual_handoff_until = max(
                self._manual_handoff_until,
                float(self._monotonic()) + MANUAL_OTP_HANDOFF_GRACE_SECONDS,
            )

    def manual_handoff_active(self) -> bool:
        with self._lock:
            return self._manual_handoff_until > float(self._monotonic())

    def manual_handoff_remaining(self) -> float:
        """Return the remaining short scheduling handoff allowance."""
        with self._lock:
            return max(0.0, self._manual_handoff_until - float(self._monotonic()))

    def manual_prompt_opened(self) -> None:
        """Record that the broker prompt is visible to the operator."""
        with self._lock:
            self._pause_manual_locked()
            self._manual_prompt_active = True
            self._manual_handoff_until = 0.0

    def manual_prompt_active(self) -> bool:
        with self._lock:
            return bool(self._manual_prompt_active)

    def manual_submission_grace_active(self) -> bool:
        with self._lock:
            return self._post_submit_grace_until > float(self._monotonic())

    def manual_submission_grace_remaining(self) -> float:
        """Return the finite post-submit handoff allowance, if any."""
        with self._lock:
            return max(0.0, self._post_submit_grace_until - float(self._monotonic()))

    def _pause_manual_locked(self) -> None:
        if self._paused_at is not None:
            return
        now = float(self._monotonic())
        self._paused_at = now
        self._paused_remaining = max(0.0, self._deadline - now)

    def pause_manual(self) -> None:
        with self._lock:
            self._pause_manual_locked()

    def resume_manual(self, outcome: str = "") -> None:
        with self._lock:
            paused_at = self._paused_at
            if paused_at is None:
                return
            now = float(self._monotonic())
            # Preserve the exact budget left at prompt open and add back the
            # elapsed manual interval, including an interval that crossed the
            # original deadline.
            self._deadline = now + max(0.0, self._paused_remaining)
            self._paused_at = None
            self._paused_remaining = 0.0
            self._manual_prompt_active = False
            self._manual_handoff_until = 0.0
            normalized_outcome = str(outcome or "")[:32]
            self._last_outcome = normalized_outcome
            # If the prompt opened after the active budget had already
            # reached zero, let the submitted code traverse the page/API
            # handoff before the watchdog reports a real timeout. This grace
            # is finite and applies only to an actually consumed submission.
            self._post_submit_grace_until = (
                now + MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS
                if normalized_outcome == "submitted" and self._deadline <= now
                else 0.0
            )

    def sync_manual_prompt(self, prompt: Mapping[str, Any] | None = None) -> None:
        """Synchronize an optional broker prompt without requiring a broker.

        The provider invokes ``pause_manual``/``resume_manual`` directly. This
        helper exists for watchdogs and compatibility adapters that can expose
        a public prompt snapshot; it is deliberately conservative and never
        opens or closes a prompt itself.
        """
        if isinstance(prompt, Mapping) and str(prompt.get("input_kind") or "") == "email_otp":
            phase = str(prompt.get("phase") or "manual").casefold()
            if phase == "manual":
                self.manual_prompt_opened()


def profile_transition_timing_outcome(state: str) -> str:
    """Return a public timing outcome for an about-you page transition.

    Only the states that prove the request was accepted by the auth flow are
    successful.  In particular, a security challenge or an unknown shell must
    never be presented as a successful profile submission.
    """
    normalized = str(state or "").strip().lower()
    if normalized in {"home", "oauth_callback"}:
        return "success"
    if normalized == "security":
        return "security_challenge"
    return "unexpected_state"


class ProfileTimingTracker:
    """Own the two non-overlapping about-you timing intervals.

    The browser flow used to keep four ``nonlocal`` cursors plus two closures
    for this state machine inside ``_browser_flow``.  Extracting it keeps the
    exact semantics: interval one covers the profile async submit request and
    only closes on an observable transition; interval two starts exactly when
    the first ends and closes on ``home``, a security challenge, or a
    terminal outcome.  ``unknown`` deliberately leaves both open because
    auth.openai.com can render a transient navigation shell.
    """

    def __init__(self) -> None:
        self.transition_recorded = False
        self.home_state_started_at = 0.0
        self.home_state_recorded = False

    def record(
        self,
        state: str,
        *,
        submitted: bool,
        submitted_at: float,
        async_started_at: float,
        emit_timing: Callable[..., None],
        stage_code: str,
        terminal_outcome: str = "",
    ) -> None:
        """Close interval one / advance interval two for a polled state."""
        if not submitted:
            return
        normalized_state = str(state or "").strip().lower()
        if not self.transition_recorded:
            if normalized_state in {"profile", "unknown"}:
                return
            started = async_started_at or submitted_at
            if not started:
                return
            outcome = str(terminal_outcome or profile_transition_timing_outcome(normalized_state))
            emit_timing(stage_code, "profile_async_submit_wait", started, outcome)
            self.transition_recorded = True
            # Only an accepted auth transition opens the home-confirmation
            # interval.  Security/unexpected outcomes are terminal for this
            # branch and must not manufacture a zero-length home success.
            if outcome != "success":
                self.home_state_started_at = 0.0
                self.home_state_recorded = True
                return
            # Start the second interval exactly when the first one ends.
            self.home_state_started_at = time.monotonic()
            if normalized_state == "home":
                emit_timing(stage_code, "profile_home_state_wait", self.home_state_started_at, "success")
                self.home_state_recorded = True
            return
        if self.home_state_recorded or not self.home_state_started_at:
            return
        if normalized_state == "home":
            emit_timing(stage_code, "profile_home_state_wait", self.home_state_started_at, "success")
            self.home_state_recorded = True
        elif normalized_state == "security":
            emit_timing(stage_code, "profile_home_state_wait", self.home_state_started_at, "security_challenge")
            self.home_state_recorded = True
        elif terminal_outcome:
            emit_timing(stage_code, "profile_home_state_wait", self.home_state_started_at, terminal_outcome)
            self.home_state_recorded = True

    def close(self, outcome: str, *, submitted: bool, submitted_at: float, async_started_at: float, emit_timing: Callable[..., None], stage_code: str) -> None:
        """Close any pending profile intervals before a terminal failure."""
        if not submitted:
            return
        if not self.transition_recorded:
            started = async_started_at or submitted_at
            if started:
                emit_timing(stage_code, "profile_async_submit_wait", started, outcome)
                self.transition_recorded = True
        if self.home_state_started_at and not self.home_state_recorded:
            emit_timing(stage_code, "profile_home_state_wait", self.home_state_started_at, outcome)
            self.home_state_recorded = True


class RegistrationBudget:
    """Read-only budget probes over one controller with a wall-clock fallback.

    The browser flow used to keep six ``_browser_flow`` closures for these
    probes.  Every controller hook is resolved through the hosting runtime
    module at call time, so tests keep patching
    ``free_camoufox_runtime.<name>`` globals without noticing this facade.
    """

    def __init__(self, host: Any, controller: Any, *, fallback_deadline: float) -> None:
        self._host = host
        self._controller = controller
        self._fallback_deadline = float(fallback_deadline)

    def deadline(self) -> float:
        value = self._host._deadline_controller_call(self._controller, "deadline")
        if value is not self._host._DEADLINE_CONTROLLER_MISSING:
            try:
                candidate = float(value)
                if math.isfinite(candidate):
                    return candidate
            except (TypeError, ValueError, OverflowError):
                pass
        return self._fallback_deadline

    def remaining(self) -> float:
        value = self._host._deadline_controller_call(self._controller, "remaining")
        if value is not self._host._DEADLINE_CONTROLLER_MISSING:
            try:
                candidate = float(value)
                if math.isfinite(candidate):
                    return max(0.0, candidate)
            except (TypeError, ValueError, OverflowError):
                pass
        return max(0.0, self.deadline() - time.monotonic())

    def paused(self) -> bool:
        return self._host._deadline_controller_bool(self._controller, "is_paused")

    def grace_active(self) -> bool:
        return self._host._deadline_controller_bool(self._controller, "manual_submission_grace_active")

    def grace_remaining(self) -> float:
        value = self._host._deadline_controller_call(self._controller, "manual_submission_grace_remaining")
        if value is not self._host._DEADLINE_CONTROLLER_MISSING:
            try:
                candidate = float(value)
                if math.isfinite(candidate):
                    return max(0.0, candidate)
            except (TypeError, ValueError, OverflowError):
                pass
        return MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS if self.grace_active() else 0.0

    def expired(self) -> bool:
        value = self._host._deadline_controller_call(self._controller, "is_expired")
        if value is not self._host._DEADLINE_CONTROLLER_MISSING:
            if bool(value):
                return not self.grace_active()
            return False
        return not self.paused() and self.remaining() <= 0


__all__ = [
    "MANUAL_OTP_HANDOFF_GRACE_SECONDS",
    "MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS",
    "MANUAL_OTP_WINDOW_SECONDS",
    "MAX_MANUAL_OTP_WINDOWS",
    "ProfileTimingTracker",
    "RegistrationBudget",
    "RegistrationDeadline",
    "deadline_controller_bool",
    "deadline_controller_call",
    "profile_transition_timing_outcome",
]
