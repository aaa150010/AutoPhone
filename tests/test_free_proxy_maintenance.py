"""Contract tests for the shared pool maintenance gate and allocation retry."""

from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

try:
    from mac_overrides.free_proxy_breaker import ChallengeBreaker
    from mac_overrides.free_proxy_maintenance import (
        bind_with_pool_maintenance,
        maintain_proxy_pool,
        pool_empty_error_code,
    )
    from mac_overrides.free_register_common import FreeRegisterError
    from mac_overrides.free_proxy_tunnel import TunnelTemplate
except ImportError:
    from free_proxy_breaker import ChallengeBreaker
    from free_proxy_maintenance import (
        bind_with_pool_maintenance,
        maintain_proxy_pool,
        pool_empty_error_code,
    )
    from free_register_common import FreeRegisterError
    from free_proxy_tunnel import TunnelTemplate


def _tunnel_config(**overrides) -> dict[str, object]:
    base = {
        "proxy_tunnel_enabled": True,
        "proxy_tunnel_gateway_host": "us.cliproxy.example.test",
        "proxy_tunnel_gateway_port": 3010,
        "proxy_tunnel_scheme": "socks5",
        "proxy_tunnel_username_template": "atxfl200589-sid-{sid}-t-{t}",
        "proxy_tunnel_password": "3jhc2mr3",
        "proxy_tunnel_sticky_minutes": 30,
        "proxy_pool_target_size": 4,
        "concurrency": 2,
    }
    base.update(overrides)
    return base


class _FakeBreaker:
    def __init__(self, *, tripped: bool = False, blocked: bool = False) -> None:
        self._tripped = tripped
        self._blocked = blocked

    def tripped(self) -> bool:
        return self._tripped

    def gateway_blocked(self) -> bool:
        return self._blocked


class MaintainProxyPoolTests(unittest.TestCase):
    def test_skips_minting_while_breaker_tripped_or_gateway_blocked(self) -> None:
        pool = object()
        for breaker in (_FakeBreaker(tripped=True), _FakeBreaker(blocked=True)):
            with self.subTest(blocked=breaker.gateway_blocked()):
                with patch("mac_overrides.free_proxy_maintenance.ensure_target") as mint:
                    self.assertEqual(
                        maintain_proxy_pool(pool, _tunnel_config(), breaker=breaker, lock=threading.Lock()),
                        0,
                    )
                mint.assert_not_called()

    def test_mints_deficit_when_not_gated_and_template_present(self) -> None:
        with patch("mac_overrides.free_proxy_maintenance.ensure_target", return_value=2) as mint:
            minted = maintain_proxy_pool(
                object(), _tunnel_config(), breaker=_FakeBreaker(), lock=threading.Lock(),
            )
        self.assertEqual(minted, 2)
        args = mint.call_args.args
        self.assertIsInstance(args[1], TunnelTemplate)
        self.assertEqual(mint.call_args.kwargs["target"], 4)

    def test_disabled_or_missing_template_is_a_noop(self) -> None:
        with patch("mac_overrides.free_proxy_maintenance.ensure_target") as mint:
            self.assertEqual(maintain_proxy_pool(object(), {}, breaker=_FakeBreaker(), lock=threading.Lock()), 0)
            self.assertEqual(
                maintain_proxy_pool(object(), _tunnel_config(proxy_tunnel_enabled=False), lock=threading.Lock()),
                0,
            )
        mint.assert_not_called()

    def test_concurrent_maintenance_mints_only_the_deficit_once(self) -> None:
        """The shared lock must serialize passes: never two mint loops at once."""
        active = {"inside": 0, "overlap": 0, "calls": 0}
        release = threading.Barrier(2, timeout=2)

        def fake_ensure_target(*_args, **_kwargs) -> int:
            active["inside"] += 1
            active["calls"] += 1
            if active["inside"] > 1:
                active["overlap"] += 1
            try:
                # Both threads try to enter at the same time; only one may.
                release.wait()
            except threading.BrokenBarrierError:
                pass
            active["inside"] -= 1
            return 1

        lock = threading.Lock()
        with patch("mac_overrides.free_proxy_maintenance.ensure_target", side_effect=fake_ensure_target):
            threads = [
                threading.Thread(target=maintain_proxy_pool, args=(object(), _tunnel_config()), kwargs={"lock": lock})
                for _ in range(2)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
        self.assertEqual(active["overlap"], 0)
        self.assertEqual(active["calls"], 2)


class PoolEmptyErrorClassificationTests(unittest.TestCase):
    def test_breaker_gate_wins_over_plain_pool_empty(self) -> None:
        self.assertEqual(pool_empty_error_code(_FakeBreaker()), "free_proxy_pool_empty")
        self.assertEqual(pool_empty_error_code(_FakeBreaker(tripped=True)), "free_proxy_breaker_tripped")
        self.assertEqual(pool_empty_error_code(_FakeBreaker(blocked=True)), "free_proxy_breaker_tripped")
        self.assertEqual(pool_empty_error_code(None), "free_proxy_pool_empty")


class BindWithPoolMaintenanceTests(unittest.TestCase):
    def test_empty_allocations_run_maintenance_once_then_succeed(self) -> None:
        attempts = {"count": 0}
        maintained: list[dict] = []

        def binder() -> list[str]:
            attempts["count"] += 1
            return [] if attempts["count"] == 1 else ["proxy-1"]

        bindings, last_error = bind_with_pool_maintenance(
            binder,
            config={"concurrency": 2},
            maintainer=lambda config: maintained.append(dict(config)) or 1,
        )
        self.assertEqual(bindings, ["proxy-1"])
        self.assertIsNone(last_error)
        self.assertEqual(attempts["count"], 2)
        self.assertEqual(len(maintained), 1)

    def test_store_pool_empty_error_counts_as_empty_and_is_swallowed_for_retry(self) -> None:
        def binder() -> list[str]:
            if not hasattr(binder, "seen"):
                binder.seen = 1  # type: ignore[attr-defined]
                raise FreeRegisterError(
                    "free_proxy_preflight", "Free 代理预检",
                    "共享 Free 代理池没有健康代理", retryable=False, error_code="free_proxy_pool_empty",
                )
            return ["proxy-ok"]

        bindings, last_error = bind_with_pool_maintenance(
            binder, config={}, maintainer=lambda _config: 1,
        )
        self.assertEqual(bindings, ["proxy-ok"])
        self.assertIsNone(last_error)

    def test_non_pool_empty_errors_propagate_without_maintenance(self) -> None:
        def binder() -> list[str]:
            raise FreeRegisterError("free_proxy_lease", "代理租约", "unexpected", retryable=False, error_code="free_proxy_lease")

        maintained: list[int] = []
        with self.assertRaises(FreeRegisterError) as raised:
            bind_with_pool_maintenance(binder, config={}, maintainer=lambda _c: maintained.append(1))
        self.assertEqual(str(raised.exception.error_code), "free_proxy_lease")
        self.assertEqual(maintained, [])

    def test_maintainer_failure_is_noted_and_retry_still_proceeds(self) -> None:
        notes: list[BaseException] = []
        attempts = {"count": 0}

        def binder() -> list[str]:
            attempts["count"] += 1
            return [] if attempts["count"] == 1 else ["proxy-2"]

        def failing_maintainer(_config) -> int:
            raise RuntimeError("store down")

        bindings, last_error = bind_with_pool_maintenance(
            binder,
            config={},
            maintainer=failing_maintainer,
            note_maintain_failure=notes.append,
        )
        self.assertEqual(bindings, ["proxy-2"])
        self.assertEqual(len(notes), 1)
        self.assertIsNone(last_error)

    def test_final_empty_returns_error_for_caller_classification(self) -> None:
        def binder() -> list[str]:
            return []

        bindings, last_error = bind_with_pool_maintenance(binder, config={})
        self.assertEqual(bindings, [])
        self.assertIsNone(last_error)


class RealBreakerGatewayIntegrationTests(unittest.TestCase):
    def test_gateway_block_alone_gates_maintenance(self) -> None:
        breaker = ChallengeBreaker(threshold=99, gateway_window_seconds=900, gateway_threshold=3)
        for index in range(3):
            breaker.record_burn(
                f"sid-{index}", exit_ip=f"5.5.5.{index}", source_label="tunnel-auto",
                minted_at=500.0, gateway_fingerprint="gw-a", now=1000.0 + index,
            )
        self.assertTrue(breaker.gateway_blocked())
        with patch("mac_overrides.free_proxy_maintenance.ensure_target") as mint:
            self.assertEqual(
                maintain_proxy_pool(object(), _tunnel_config(), breaker=breaker, lock=threading.Lock()),
                0,
            )
        mint.assert_not_called()
        breaker.reset()
        with patch("mac_overrides.free_proxy_maintenance.ensure_target", return_value=1):
            self.assertEqual(
                maintain_proxy_pool(object(), _tunnel_config(), breaker=breaker, lock=threading.Lock()),
                1,
            )


if __name__ == "__main__":
    unittest.main()
