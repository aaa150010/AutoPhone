"""Contract tests for the pool-level challenge circuit breaker."""

from __future__ import annotations

import unittest

try:
    from mac_overrides.free_proxy_breaker import (
        CHALLENGE_BREAKER_THRESHOLD,
        CHALLENGE_BREAKER_WINDOW_SECONDS,
        ChallengeBreaker,
    )
except ImportError:
    from free_proxy_breaker import (
        CHALLENGE_BREAKER_THRESHOLD,
        CHALLENGE_BREAKER_WINDOW_SECONDS,
        ChallengeBreaker,
    )


class ChallengeBreakerTests(unittest.TestCase):
    def test_trips_on_threshold_distinct_exits_within_window(self) -> None:
        breaker = ChallengeBreaker(threshold=3, window_seconds=1800)
        self.assertFalse(breaker.tripped(now=1000.0))
        breaker.record_burn("a", now=1000.0)
        breaker.record_burn("b", now=1100.0)
        self.assertFalse(breaker.tripped(now=1200.0))
        breaker.record_burn("c", now=1200.0)
        self.assertTrue(breaker.tripped(now=1300.0))
        # Repeated burns on an already-tripped breaker stay tripped.
        self.assertTrue(breaker.record_burn("d", now=1400.0).tripped)

    def test_same_exit_reburn_does_not_count_twice(self) -> None:
        breaker = ChallengeBreaker(threshold=3, window_seconds=1800)
        breaker.record_burn("a", now=1000.0)
        breaker.record_burn("a", now=1100.0)
        breaker.record_burn("a", now=1200.0)
        self.assertFalse(breaker.tripped(now=1300.0))

    def test_burn_accounting_ages_out_but_trip_flag_is_sticky(self) -> None:
        # Distinct-burn accounting ages out of the window; the trip flag
        # itself is sticky until reset() (manual confirmation semantics).
        breaker = ChallengeBreaker(threshold=3, window_seconds=1800)
        breaker.record_burn("a", now=1000.0)
        breaker.record_burn("b", now=1100.0)
        breaker.record_burn("c", now=1200.0)
        self.assertTrue(breaker.tripped(now=1300.0))
        state = breaker.state(now=9999.0)
        self.assertEqual(state.recent_distinct_burns, 0)
        self.assertTrue(state.tripped)
        breaker.reset()
        self.assertFalse(breaker.tripped(now=10000.0))

    def test_reset_is_the_only_way_to_clear_a_trip(self) -> None:
        breaker = ChallengeBreaker(threshold=CHALLENGE_BREAKER_THRESHOLD, window_seconds=CHALLENGE_BREAKER_WINDOW_SECONDS)
        for index in range(CHALLENGE_BREAKER_THRESHOLD):
            breaker.record_burn(f"exit-{index}", now=1000.0 + index)
        self.assertTrue(breaker.tripped(now=2000.0))
        breaker.reset()
        self.assertFalse(breaker.tripped(now=2000.0))

    def test_state_snapshot_is_immutable_projection(self) -> None:
        breaker = ChallengeBreaker(threshold=2, window_seconds=60)
        breaker.record_burn("a", now=10.0)
        state = breaker.state(now=20.0)
        self.assertEqual(state.recent_distinct_burns, 1)
        self.assertEqual(state.window_seconds, 60)
        self.assertEqual(state.threshold, 2)
        with self.assertRaises(Exception):
            state.tripped = True  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
