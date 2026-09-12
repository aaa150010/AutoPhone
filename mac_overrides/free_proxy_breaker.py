"""Pool-level circuit breaker for security-challenge proxy burns.

A burst of challenges on distinct exits means the target site tightened or
the provider subnet is flagged; minting replacements and switching proxies
would then only burn traffic.  The breaker trips on ``threshold`` distinct
proxy ids inside the sliding window and stays tripped until an explicit
operator reset, mirroring the same-error short-circuit philosophy at pool
granularity.  State is intentionally in-memory: a restart clears it and the
structured diagnostic timeline remains the audit record.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time


CHALLENGE_BREAKER_WINDOW_SECONDS = 1800
CHALLENGE_BREAKER_THRESHOLD = 3


@dataclass(frozen=True, slots=True)
class BreakerState:
    """Immutable snapshot of the challenge breaker for diagnostics/UI."""

    tripped: bool
    recent_distinct_burns: int
    window_seconds: int
    threshold: int


class ChallengeBreaker:
    """Trip when too many distinct exits burn within the sliding window."""

    def __init__(
        self,
        *,
        window_seconds: int = CHALLENGE_BREAKER_WINDOW_SECONDS,
        threshold: int = CHALLENGE_BREAKER_THRESHOLD,
    ) -> None:
        self._window_seconds = max(1, int(window_seconds))
        self._threshold = max(1, int(threshold))
        self._lock = threading.Lock()
        self._burns: dict[str, float] = {}
        self._tripped = False

    def record_burn(self, proxy_id: str, *, now: float | None = None) -> BreakerState:
        """Record one burned exit; distinct ids accumulate inside the window."""
        current_time = time.time() if now is None else float(now)
        with self._lock:
            self._prune(current_time)
            key = str(proxy_id or "").strip()
            if key:
                self._burns[key] = current_time
            if len(self._burns) >= self._threshold:
                self._tripped = True
            return self._state_locked()

    def tripped(self, *, now: float | None = None) -> bool:
        current_time = time.time() if now is None else float(now)
        with self._lock:
            self._prune(current_time)
            return self._tripped

    def state(self, *, now: float | None = None) -> BreakerState:
        current_time = time.time() if now is None else float(now)
        with self._lock:
            self._prune(current_time)
            return self._state_locked()

    def reset(self) -> None:
        """Operator-confirmed reset; the only way to clear a tripped breaker."""
        with self._lock:
            self._burns.clear()
            self._tripped = False

    def _state_locked(self) -> BreakerState:
        return BreakerState(
            tripped=self._tripped,
            recent_distinct_burns=len(self._burns),
            window_seconds=self._window_seconds,
            threshold=self._threshold,
        )

    def _prune(self, now: float) -> None:
        cutoff = now - self._window_seconds
        for key in [key for key, burned_at in self._burns.items() if burned_at <= cutoff]:
            del self._burns[key]


__all__ = [
    "BreakerState",
    "CHALLENGE_BREAKER_THRESHOLD",
    "CHALLENGE_BREAKER_WINDOW_SECONDS",
    "ChallengeBreaker",
]
