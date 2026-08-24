from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.free_proxy_store import FreeProxyPool
from mac_overrides.free_register_runtime import FreeRegisterManager


class FreeProxyRobustnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-free-proxy-robustness-")
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_roxy_preflight_does_not_probe_chatgpt_login(self) -> None:
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
        self.assertEqual(len(chatgpt_calls), 1)
        self.assertTrue(chatgpt_calls[0].startswith("socks5h://"))
        self.assertNotIn("private", str(protocol))

    def test_chatgpt_page_rejection_does_not_quarantine_proxy(self) -> None:
        pool = FreeProxyPool(self.data_dir, failure_threshold=1)
        pool.import_text("http://proxy.example.test:8000\n")
        with self.assertRaises(FreeRegisterError) as raised:
            pool.bind(
                1,
                driver="protocol",
                probe=lambda _proxy, _url: "203.0.113.80",
                chatgpt_probe=lambda _proxy: 403,
                check_chatgpt=True,
            )
        self.assertEqual(raised.exception.provider_status, 403)
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
