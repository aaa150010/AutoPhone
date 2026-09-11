"""Contract tests for the healthy-pool-driven batch concurrency gate."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from mac_overrides.free_batch_concurrency import ProxyPoolConcurrencyGate
from mac_overrides.free_live_check import FreeLiveCheckService
from mac_overrides.free_plan_check import FreePlanCheckService
from mac_overrides.free_register_store import FreeMailboxPool, FreeProxyPool


class _FakeProxies:
    """Minimal proxy-store double exposing only the pool projection."""

    def __init__(self, healthy: int, *, broken: bool = False) -> None:
        self.healthy = healthy
        self.broken = broken
        self.calls = 0

    def healthy_count(self) -> int:
        self.calls += 1
        if self.broken:
            raise RuntimeError("pool unavailable")
        return self.healthy


class ProxyPoolConcurrencyGateTests(unittest.TestCase):
    def test_gate_blocks_waiters_until_the_pool_grows(self):
        healthy = {"count": 2}
        gate = ProxyPoolConcurrencyGate(lambda: healthy["count"], poll_seconds=0.05)
        observed: list[int] = []
        peak = {"value": 0}
        lock = threading.Lock()

        def worker() -> None:
            with gate:
                with lock:
                    observed.append(1)
                    peak["value"] = max(peak["value"], gate.active())
                time.sleep(0.15)
                with lock:
                    observed.pop()

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads[:4]:
            thread.start()
        # Two slots fill immediately; waiters must stay queued.
        time.sleep(0.05)
        self.assertEqual(gate.active(), 2)
        # Growing the pool lets the queued workers in without any release.
        healthy["count"] = 4
        for thread in threads[4:]:
            thread.start()
        deadline = time.time() + 2.0
        while time.time() < deadline and gate.active() < 4:
            time.sleep(0.02)
        self.assertEqual(gate.active(), 4)
        for thread in threads:
            thread.join(timeout=3.0)
        self.assertEqual(peak["value"], 4)

    def test_gate_never_exceeds_the_cap_and_falls_back_to_one_on_errors(self):
        gate = ProxyPoolConcurrencyGate(lambda: 500)
        self.assertEqual(gate.current_limit(), 500)

        def broken() -> int:
            raise RuntimeError("no pool")

        self.assertEqual(ProxyPoolConcurrencyGate(broken).current_limit(), 1)
        self.assertEqual(ProxyPoolConcurrencyGate(lambda: 0).current_limit(), 1)


class FreeLiveCheckDynamicConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp.name)
        self.services: list[FreeLiveCheckService] = []

    def tearDown(self) -> None:
        for service in self.services:
            service.shutdown(wait=True)
        self.temp.cleanup()

    def _service(self, proxies: _FakeProxies) -> FreeLiveCheckService:
        service = FreeLiveCheckService(
            self.data_dir,
            pool=None,
            proxies=proxies,
            log_store=None,
            recover=False,
        )
        self.services.append(service)
        return service

    def test_concurrency_follows_healthy_proxy_count(self):
        service = self._service(_FakeProxies(6))
        self.assertEqual(service._dynamic_concurrency(), 6)

    def test_concurrency_caps_at_max_concurrency(self):
        service = self._service(_FakeProxies(50))
        self.assertEqual(service._dynamic_concurrency(), service.max_concurrency)

    def test_concurrency_falls_back_when_the_pool_is_unavailable(self):
        service = self._service(_FakeProxies(0, broken=True))
        self.assertEqual(service._dynamic_concurrency(), service.workers)

    def test_public_state_reports_the_dynamic_ceiling(self):
        service = self._service(_FakeProxies(9))
        self.assertEqual(service.public_state()["workers"], 9)
        self.assertEqual(service.public_state()["max_concurrency"], service.max_concurrency)


class FreePlanCheckDynamicConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _service(self, proxies: _FakeProxies) -> FreePlanCheckService:
        return FreePlanCheckService(
            self.data_dir,
            pool=None,
            proxies=proxies,
            recover=False,
        )

    def test_concurrency_follows_healthy_proxy_count(self):
        service = self._service(_FakeProxies(6))
        self.assertEqual(service._dynamic_concurrency(), 6)
        self.assertEqual(service.public_state()["workers"], 6)


class HealthyProxyCountTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_healthy_count_tracks_imported_pool_rows(self):
        pool = FreeProxyPool(self.data_dir)
        self.assertEqual(pool.healthy_count(), 0)
        pool.import_text(
            "\n".join(
                f"http://user{index}:secret@proxy{index}.example.test:{9000 + index}"
                for index in range(1, 4)
            ),
            country="US",
            group="gate-test",
            scheme="http",
        )
        self.assertEqual(pool.healthy_count(), 3)
        pool.import_text("http://user9:secret@proxy9.example.test:9009", country="US", group="gate-test", scheme="http")
        self.assertEqual(pool.healthy_count(), 4)


if __name__ == "__main__":
    unittest.main()
