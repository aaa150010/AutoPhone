"""Pool-level circuit breaker for security-challenge proxy burns.

A burst of challenges on distinct exits means the target site tightened or
the provider subnet is flagged; minting replacements and switching proxies
would then only burn traffic.  The breaker trips on ``threshold`` distinct
exits (observed egress IP first, proxy id fallback) inside the sliding
window and stays tripped until an explicit operator reset, mirroring the
same-error short-circuit philosophy at pool granularity.  Tunnel minting
carries a second, finer layer: when one gateway credential fingerprint burns
``gateway_threshold`` freshly minted rows inside its own window, that
template is flagged gateway-blocked and stops minting while the rest of the
shared pool keeps serving.  State is intentionally in-memory: a restart
clears it and the structured diagnostic timeline remains the audit record.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time

try:
    from .free_proxy_tunnel import TUNNEL_SOURCE_LABEL
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_proxy_tunnel import TUNNEL_SOURCE_LABEL  # type: ignore[no-redef]


CHALLENGE_BREAKER_WINDOW_SECONDS = 1800
CHALLENGE_BREAKER_THRESHOLD = 3
GATEWAY_BLOCK_WINDOW_SECONDS = 900
GATEWAY_BLOCK_THRESHOLD = 3


@dataclass(frozen=True, slots=True)
class BreakerState:
    """Immutable snapshot of the challenge breaker for diagnostics/UI."""

    tripped: bool
    recent_distinct_burns: int
    window_seconds: int
    threshold: int
    gateway_blocked: bool = False
    recent_new_mint_challenges: int = 0
    gateway_window_seconds: int = GATEWAY_BLOCK_WINDOW_SECONDS
    gateway_threshold: int = GATEWAY_BLOCK_THRESHOLD


class ChallengeBreaker:
    """Trip when too many distinct exits burn within the sliding window."""

    def __init__(
        self,
        *,
        window_seconds: int = CHALLENGE_BREAKER_WINDOW_SECONDS,
        threshold: int = CHALLENGE_BREAKER_THRESHOLD,
        gateway_window_seconds: int = GATEWAY_BLOCK_WINDOW_SECONDS,
        gateway_threshold: int = GATEWAY_BLOCK_THRESHOLD,
    ) -> None:
        self._window_seconds = max(1, int(window_seconds))
        self._threshold = max(1, int(threshold))
        self._gateway_window_seconds = max(1, int(gateway_window_seconds))
        self._gateway_threshold = max(1, int(gateway_threshold))
        self._lock = threading.Lock()
        self._burns: dict[str, float] = {}
        self._tripped = False
        # fingerprint -> {exit identity: first-challenge time of a minted row}
        self._gateway_new_mints: dict[str, dict[str, float]] = {}
        self._gateway_blocked = False

    def record_burn(
        self,
        proxy_id: str,
        *,
        exit_ip: str | None = None,
        source_label: str | None = None,
        minted_at: float | None = None,
        gateway_fingerprint: str | None = None,
        now: float | None = None,
    ) -> BreakerState:
        """Record one burned exit inside the sliding window.

        Distinct-exit accounting prefers the observed egress IP so the same
        physical exit reached through different proxy rows counts once, and
        falls back to ``proxy_id`` when no IP was observed.  Rows minted from
        a credential tunnel additionally feed the per-gateway new-mint
        challenge window.
        """
        current_time = time.time() if now is None else float(now)
        with self._lock:
            self._prune(current_time)
            identity = str(exit_ip or "").strip() or str(proxy_id or "").strip()
            if identity:
                self._burns[identity] = current_time
            if len(self._burns) >= self._threshold:
                self._tripped = True
            self._record_gateway_locked(
                identity=identity,
                source_label=source_label,
                minted_at=minted_at,
                gateway_fingerprint=gateway_fingerprint,
                now=current_time,
            )
            return self._state_locked()

    def tripped(self, *, now: float | None = None) -> bool:
        current_time = time.time() if now is None else float(now)
        with self._lock:
            self._prune(current_time)
            return self._tripped

    def gateway_blocked(self, *, now: float | None = None) -> bool:
        """True once a gateway fingerprint hit the new-mint challenge gate.

        Like the pool trip this flag is sticky; only ``reset`` clears it.
        """
        with self._lock:
            return self._gateway_blocked

    def state(self, *, now: float | None = None) -> BreakerState:
        current_time = time.time() if now is None else float(now)
        with self._lock:
            self._prune(current_time)
            self._prune_gateway(current_time)
            return self._state_locked()

    def reset(self) -> None:
        """Operator-confirmed reset; the only way to clear a trip or block."""
        with self._lock:
            self._burns.clear()
            self._tripped = False
            self._gateway_new_mints.clear()
            self._gateway_blocked = False

    def _record_gateway_locked(
        self,
        *,
        identity: str,
        source_label: str | None,
        minted_at: float | None,
        gateway_fingerprint: str | None,
        now: float,
    ) -> None:
        if str(source_label or "") != TUNNEL_SOURCE_LABEL:
            return
        try:
            minted = float(minted_at or 0)
        except (TypeError, ValueError):
            minted = 0.0
        fingerprint = str(gateway_fingerprint or "").strip().lower()
        if minted <= 0 or not fingerprint or not identity:
            return
        challenges = self._gateway_new_mints.setdefault(fingerprint, {})
        # First challenge of this minted row wins; repeats do not count twice.
        challenges.setdefault(identity, now)
        self._prune_gateway(now)
        for row_times in self._gateway_new_mints.values():
            if len(row_times) >= self._gateway_threshold:
                self._gateway_blocked = True

    def _prune_gateway(self, now: float) -> None:
        cutoff = now - self._gateway_window_seconds
        for fingerprint in list(self._gateway_new_mints):
            rows = self._gateway_new_mints[fingerprint]
            for row_key in [row_key for row_key, burned_at in rows.items() if burned_at <= cutoff]:
                del rows[row_key]
            if not rows:
                del self._gateway_new_mints[fingerprint]

    def _state_locked(self) -> BreakerState:
        return BreakerState(
            tripped=self._tripped,
            recent_distinct_burns=len(self._burns),
            window_seconds=self._window_seconds,
            threshold=self._threshold,
            gateway_blocked=self._gateway_blocked,
            recent_new_mint_challenges=max(
                (len(rows) for rows in self._gateway_new_mints.values()),
                default=0,
            ),
            gateway_window_seconds=self._gateway_window_seconds,
            gateway_threshold=self._gateway_threshold,
        )

    def _prune(self, now: float) -> None:
        cutoff = now - self._window_seconds
        for key in [key for key, burned_at in self._burns.items() if burned_at <= cutoff]:
            del self._burns[key]


__all__ = [
    "BreakerState",
    "CHALLENGE_BREAKER_THRESHOLD",
    "CHALLENGE_BREAKER_WINDOW_SECONDS",
    "GATEWAY_BLOCK_THRESHOLD",
    "GATEWAY_BLOCK_WINDOW_SECONDS",
    "ChallengeBreaker",
]
