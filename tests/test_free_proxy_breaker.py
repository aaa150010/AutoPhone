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

    def test_distinct_exit_identity_prefers_egress_ip_over_proxy_id(self) -> None:
        # One physical exit reached through two proxy rows (same observed
        # egress IP) counts once; without an IP the proxy id is the fallback.
        breaker = ChallengeBreaker(threshold=3, window_seconds=1800)
        breaker.record_burn("p1", exit_ip="1.2.3.4", now=1000.0)
        state = breaker.record_burn("p2", exit_ip="1.2.3.4", now=1010.0)
        self.assertEqual(state.recent_distinct_burns, 1)
        breaker.record_burn("p3", exit_ip="", now=1020.0)
        breaker.record_burn("p4", now=1030.0)
        state = breaker.state(now=1040.0)
        self.assertEqual(state.recent_distinct_burns, 3)
        self.assertTrue(state.tripped)

    def test_gateway_block_counts_new_mint_tunnel_challenges_per_fingerprint(self) -> None:
        breaker = ChallengeBreaker(threshold=99, gateway_window_seconds=900, gateway_threshold=3)
        common = {
            "source_label": "tunnel-auto",
            "minted_at": 500.0,
            "gateway_fingerprint": "gw-a",
        }
        for index in range(2):
            state = breaker.record_burn(f"sid-{index}", exit_ip=f"10.0.0.{index}", now=1000.0 + index, **common)
            self.assertFalse(state.gateway_blocked)
        state = breaker.record_burn("sid-2", exit_ip="10.0.0.2", now=1002.0, **common)
        self.assertTrue(state.gateway_blocked)
        self.assertEqual(state.recent_new_mint_challenges, 3)
        # The pool-level trip is independent: a healthy manual pool under the
        # pool threshold is not blocked by this layer.
        self.assertFalse(state.tripped)
        self.assertTrue(breaker.gateway_blocked())

    def test_gateway_block_ignores_manual_rows_and_pre_mint_rows(self) -> None:
        breaker = ChallengeBreaker(threshold=99, gateway_window_seconds=900, gateway_threshold=3)
        for index in range(3):
            breaker.record_burn(
                f"manual-{index}", exit_ip=f"9.9.9.{index}", source_label="vendor-x",
                minted_at=500.0, gateway_fingerprint="gw-a", now=1000.0 + index,
            )
            breaker.record_burn(
                f"legacy-{index}", exit_ip=f"8.8.8.{index}", source_label="tunnel-auto",
                minted_at=0.0, gateway_fingerprint="gw-a", now=1100.0 + index,
            )
        self.assertFalse(breaker.gateway_blocked())

    def test_gateway_block_is_sticky_and_other_fingerprints_do_not_count(self) -> None:
        breaker = ChallengeBreaker(threshold=99, gateway_window_seconds=900, gateway_threshold=3)
        for index in range(2):
            breaker.record_burn(f"a-{index}", exit_ip=f"1.1.1.{index}", source_label="tunnel-auto", minted_at=500.0, gateway_fingerprint="gw-a", now=1000.0 + index)
        breaker.record_burn("b-0", exit_ip="2.2.2.0", source_label="tunnel-auto", minted_at=500.0, gateway_fingerprint="gw-b", now=1050.0)
        self.assertFalse(breaker.gateway_blocked())
        breaker.record_burn("a-2", exit_ip="1.1.1.2", source_label="tunnel-auto", minted_at=500.0, gateway_fingerprint="gw-a", now=1060.0)
        self.assertTrue(breaker.gateway_blocked())
        # The window aging out does not lift the block; only reset clears it.
        self.assertTrue(breaker.gateway_blocked(now=99999.0))
        breaker.reset()
        self.assertFalse(breaker.gateway_blocked())

    def test_reset_clears_both_pool_trip_and_gateway_block(self) -> None:
        breaker = ChallengeBreaker(threshold=2, gateway_window_seconds=900, gateway_threshold=2)
        breaker.record_burn("p1", exit_ip="1.1.1.1", source_label="tunnel-auto", minted_at=500.0, gateway_fingerprint="gw-a", now=1000.0)
        breaker.record_burn("p2", exit_ip="1.1.1.2", source_label="tunnel-auto", minted_at=500.0, gateway_fingerprint="gw-a", now=1010.0)
        self.assertTrue(breaker.tripped())
        self.assertTrue(breaker.gateway_blocked())
        breaker.reset()
        self.assertFalse(breaker.tripped())
        self.assertFalse(breaker.gateway_blocked())
        state = breaker.state()
        self.assertEqual(state.recent_new_mint_challenges, 0)


if __name__ == "__main__":
    unittest.main()
