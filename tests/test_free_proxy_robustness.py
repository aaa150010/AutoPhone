from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.free_proxy_store import FreeProxyPool
from mac_overrides.free_register_runtime import FreeRegisterManager


class FreeProxyRobustnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-free-proxy-robustness-")
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_preflight_does_not_probe_chatgpt_login(self) -> None:
        chatgpt_calls: list[str] = []
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.80",
            proxy_chatgpt_probe=lambda proxy: chatgpt_calls.append(proxy) or 200,
        )

        roxy = manager.preflight_proxies(
            proxy_content="socks5://user:private@proxy.example.test:3000\n",
            driver="roxybrowser",
        )
        self.assertEqual(roxy["proxies"], 1)
        self.assertEqual(chatgpt_calls, [])

        protocol = manager.preflight_proxies(
            proxy_content="socks5://user:private@proxy.example.test:3000\n",
            driver="protocol",
        )
        self.assertEqual(protocol["proxies"], 1)
        self.assertEqual(chatgpt_calls, [])
        self.assertNotIn("private", str(protocol))

    def test_chatgpt_page_is_not_part_of_proxy_preflight(self) -> None:
        pool = FreeProxyPool(self.data_dir, failure_threshold=1)
        pool.import_text("http://proxy.example.test:8000\n")
        bindings = pool.bind(
            1,
            driver="protocol",
            probe=lambda _proxy, _url: "203.0.113.80",
            chatgpt_probe=lambda _proxy: 403,
            check_chatgpt=True,
        )
        self.assertEqual(len(bindings), 1)
        row = pool.public()["rows"][0]
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertNotEqual(row["status"], "quarantined")

    def test_transport_preflight_failure_still_updates_proxy_health(self) -> None:
        pool = FreeProxyPool(self.data_dir, failure_threshold=1)
        pool.import_text("http://proxy.example.test:8000\n")

        def fail_probe(_proxy, _url):
            raise ConnectionError("proxy CONNECT timeout")

        with self.assertRaises(FreeRegisterError):
            pool.bind(
                1,
                driver="protocol",
                probe=fail_probe,
            )

        row = pool.public()["rows"][0]
        self.assertEqual(row["consecutive_failures"], 1)
        self.assertEqual(row["status"], "quarantined")

    def test_effective_scheme_survives_pool_reload(self) -> None:
        pool = FreeProxyPool(self.data_dir)
        pool.import_text("socks5h://probe-user:probe-pass@proxy.example.test:3000\n")
        proxy_id = pool.public()["rows"][0]["proxy_id"]

        pool.record_success(
            proxy_id,
            latency_ms=42,
            effective_scheme="socks5",
        )

        reloaded = FreeProxyPool(self.data_dir)
        row = reloaded.public()["rows"][0]
        self.assertEqual(row["scheme"], "socks5h")
        self.assertEqual(row["effective_scheme"], "socks5")

    def test_stale_pool_candidate_gets_one_bounded_refresh_before_bind(self) -> None:
        pool = FreeProxyPool(self.data_dir, health_probe_ttl_seconds=300)
        pool.import_text("http://proxy.example.test:8000\n")
        calls: list[tuple[str, str]] = []

        def probe(proxy: str, target: str) -> str:
            calls.append((proxy, target))
            return "203.0.113.81"

        binding = pool.bind(
            1,
            probe=probe,
            probe_url="https://chatgpt.com/",
            perform_probe=False,
            health_probe_ttl_seconds=300,
        )[0]
        self.assertEqual(binding.exit_ip, "203.0.113.81")
        self.assertEqual(len(calls), 1)
        self.assertEqual(pool.public()["rows"][0]["probe_successes"], 1)

    def test_chatgpt_probe_is_recorded_when_explicitly_requested(self) -> None:
        pool = FreeProxyPool(self.data_dir)
        pool.import_text("http://proxy.example.test:8000\n")
        calls: list[str] = []
        binding = pool.bind(
            1,
            probe=lambda _proxy, _target: "203.0.113.82",
            chatgpt_probe=lambda proxy: calls.append(proxy) or 403,
            check_chatgpt=True,
        )[0]
        self.assertEqual(calls, [binding.proxy])
        self.assertEqual(binding.chatgpt_login_status, 403)
        row = pool.public()["rows"][0]
        self.assertEqual(row["last_chatgpt_login_status"], 403)

    def test_layered_probe_reports_each_transport_boundary_without_body(self) -> None:
        pool = FreeProxyPool(self.data_dir)
        proxy = "socks5h://probe-user:probe-pass@proxy.example.test:3000"

        fake_socket = patch(
            "mac_overrides.free_proxy_store.socket.create_connection",
        )
        with fake_socket as create_connection:
            create_connection.return_value.__enter__.return_value = object()
            with patch.object(pool, "_probe_with_policy", return_value=("", "strict")) as https_probe:
                with patch.object(pool, "_chatgpt_login_with_policy", return_value=(200, "strict")) as login_probe:
                    result = pool.layered_probe(proxy, "https://chatgpt.com/")

        self.assertTrue(result["ok"])
        self.assertEqual(result["declared_scheme"], "socks5h")
        self.assertEqual(result["effective_scheme"], "socks5h")
        self.assertIsInstance(result["tcp_connect_ms"], int)
        self.assertIsInstance(result["https_request_ms"], int)
        self.assertIsInstance(result["chatgpt_request_ms"], int)
        self.assertEqual(result["chatgpt_status"], 200)
        https_probe.assert_called_once_with(proxy, "https://chatgpt.com/")
        login_probe.assert_called_once_with(proxy)
        # Diagnostic output must stay metadata-only; response bodies are never
        # returned by the layered probe contract.
        self.assertNotIn("probe-pass", repr(result))

    def test_malformed_persisted_numeric_fields_are_safely_normalized(self) -> None:
        secret_values = (
            "valid-password-private",
            "invalid-password-private",
            "status-secret-private",
            "lease-secret-private",
        )
        path = self.data_dir / "free_proxy_pool.json"
        path.write_text(json.dumps({
            "version": float("inf"),
            "proxies": [
                {
                    "proxy": "socks5://valid-user:valid-password-private@proxy-a.example.test:3000",
                    "port": "invalid-redundant-port",
                    "status": "available",
                    "last_checked_at": float("inf"),
                    "latency_ms": "slow",
                    "last_chatgpt_login_checked_at": [],
                    "last_chatgpt_login_status": {"value": "status-secret-private"},
                    "consecutive_failures": "not-a-count",
                    "quarantined_until": float("nan"),
                    "leases": [
                        {"owner": "valid-owner", "task_id": "task-1", "until": time.time() + 300},
                        {"owner": "infinite-owner", "until": float("inf")},
                        {"owner": "invalid-owner", "until": {"value": "lease-secret-private"}},
                    ],
                    "lease_owner": "legacy-owner",
                    "lease_until": "not-a-lease",
                },
                {
                    "host": "proxy-b.example.test",
                    "port": "invalid-port",
                    "username": "invalid-user",
                    "password": "invalid-password-private",
                    "scheme": "http",
                },
                {
                    "host": "proxy-c.example.test",
                    "port": "3001",
                    "scheme": "http",
                    "last_chatgpt_login_status": "403",
                    "consecutive_failures": "2",
                },
            ],
        }), encoding="utf-8")

        pool = FreeProxyPool(self.data_dir)
        rows = pool.entries()
        self.assertEqual(len(rows), 2)
        first, second = rows
        self.assertEqual(first["port"], 3000)
        self.assertIsNone(first["last_checked_at"])
        self.assertIsNone(first["latency_ms"])
        self.assertIsNone(first["last_chatgpt_login_checked_at"])
        self.assertEqual(first["last_chatgpt_login_status"], 0)
        self.assertEqual(first["consecutive_failures"], 0)
        self.assertEqual(first["quarantined_until"], 0)
        self.assertEqual([lease["owner"] for lease in first["leases"]], ["valid-owner"])
        self.assertEqual(second["port"], 3001)
        self.assertEqual(second["last_chatgpt_login_status"], 403)
        self.assertEqual(second["consecutive_failures"], 2)

        public = pool.public()
        self.assertEqual(public["count"], 2)
        self.assertEqual(public["rows"][0]["active_lease_count"], 1)
        for secret in secret_values:
            self.assertNotIn(secret, str(public))


if __name__ == "__main__":
    unittest.main()
