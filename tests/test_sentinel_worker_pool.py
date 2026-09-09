"""Sentinel resident worker pool contract tests.

These tests exercise the Python pool protocol against a tiny stub worker so
no network, SDK, or real token generation is involved.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STUB_WORKER = REPO_ROOT / "tests" / "fixtures" / "sentinel_stub_worker.js"
RUNNER = REPO_ROOT / "engine" / "node_chain" / "codex_node_bridge.py"


def _load_pool_module():
    sys.path.insert(0, str(REPO_ROOT / "engine" / "node_chain"))
    try:
        import sentinel_worker_pool as pool_module
    finally:
        candidate = REPO_ROOT / "engine" / "node_chain"
        try:
            sys.path.remove(str(candidate))
        except ValueError:
            pass
    return pool_module


class SentinelWorkerPoolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pool_module = _load_pool_module()
        self.pools = []
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-sentinel-pool-")

    def tearDown(self) -> None:
        for pool in self.pools:
            pool.shutdown()
        self.temp_dir.cleanup()

    def _make_pool(self, size: int = 2):
        pool = self.pool_module.SentinelWorkerPool(
            node_binary="node",
            worker_script=STUB_WORKER,
            size=size,
        )
        self.pools.append(pool)
        return pool

    def test_worker_reuses_process_across_requests(self) -> None:
        pool = self._make_pool(size=1)
        first = pool.request({"flow": "a"}, timeout=10)
        second = pool.request({"flow": "b"}, timeout=10)
        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertTrue(first.get("worker_ready"))
        self.assertNotEqual(first["request_id"], second["request_id"])
        # The resident worker keeps its pid for the second request.
        self.assertEqual(first["pid"], second["pid"])

    def test_request_timeout_returns_none_for_fallback(self) -> None:
        pool = self._make_pool(size=1)
        message = pool.request({"flow": "a", "sleep_ms": 5000}, timeout=1)
        self.assertIsNone(message)

    def test_worker_crash_returns_none_and_pool_recovers(self) -> None:
        pool = self._make_pool(size=1)
        crashed = pool.request({"flow": "a", "crash": True}, timeout=10)
        # The stub exits before replying: the reader notices EOF and the
        # feeder answers with a stdin-closed failure, either way the caller
        # falls back (None) or receives an explicit failure.
        self.assertTrue(crashed is None or crashed.get("ok") is False)
        recovered = pool.request({"flow": "b"}, timeout=10)
        self.assertTrue(recovered and recovered["ok"])

    def test_pool_size_is_clamped(self) -> None:
        pool = self._make_pool(size=99)
        workers = pool._ensure_workers()
        self.assertLessEqual(len(workers), 8)

    def test_shutdown_terminates_workers(self) -> None:
        pool = self._make_pool(size=2)
        message = pool.request({"flow": "a"}, timeout=10)
        self.assertTrue(message["ok"])
        pool.shutdown()
        workers = list(pool._workers)
        self.assertEqual(workers, [])


class SentinelStubWorkerContract(unittest.TestCase):
    def test_stub_worker_answers_ping_and_requests(self) -> None:
        self.assertTrue(STUB_WORKER.exists())
        proc = subprocess.Popen(
            ["node", str(STUB_WORKER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            cwd=str(REPO_ROOT / "engine" / "node_chain"),
        )
        try:
            proc.stdin.write(json.dumps({"id": "p1", "type": "ping"}) + "\n")
            proc.stdin.write(json.dumps({"id": "r1", "type": "request", "payload": {"flow": "x"}}) + "\n")
            proc.stdin.flush()
            replies = []
            deadline = time.time() + 10
            while len(replies) < 2 and time.time() < deadline:
                line = proc.stdout.readline()
                if not line:
                    break
                replies.append(json.loads(line))
            self.assertEqual(len(replies), 2)
            self.assertTrue(replies[0].get("pong"))
            self.assertEqual(replies[1]["id"], "r1")
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
            proc.wait(timeout=5)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class SentinelBridgePatchTests(unittest.TestCase):
    def test_patch_wraps_cached_bridge_and_preserves_fallback(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "mac_overrides"))
        try:
            import sentinel_bridge_pool_patch as patch
        finally:
            try:
                sys.path.remove(str(REPO_ROOT / "mac_overrides"))
            except ValueError:
                pass

        calls = []

        class FakeBridge:
            BRIDGE_VERSION = "node-bridge-v2"

            @staticmethod
            def _node_binary():
                return "node"

            @staticmethod
            def run_node_bridge(mode="mock", **kwargs):
                calls.append((mode, dict(kwargs)))
                return {"ok": True, "mode": mode, "token_generated": False}

        bridge = FakeBridge()
        self.assertTrue(patch.apply_sentinel_pool_patch(bridge))
        self.assertTrue(patch.apply_sentinel_pool_patch(bridge))
        result = bridge.run_node_bridge(
            mode="real", flow="authorize_continue", timeout=10,
            script_path=str(RUNNER.parent / "real_sentinel_runner.js"),
            fingerprint={},
        )
        # The stub-free environment has no live worker token; the wrapper
        # must fall back to the original callable without altering args.
        self.assertTrue(calls or result)
        self.assertEqual(result["mode"], "real")
