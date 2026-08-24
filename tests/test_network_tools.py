from __future__ import annotations

import tempfile
import unittest

from mac_overrides.network_tools import NetworkToolsService


class _Socket:
    def close(self):
        pass


class _Response:
    status_code = 204
    text = ""

    def json(self):
        return {"ip": "198.51.100.9"}


class _Session:
    def __init__(self):
        self.calls = []
        self.trust_env = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Response()

    def close(self):
        pass


class NetworkToolsTests(unittest.TestCase):
    def test_import_deduplicates_and_public_rows_are_redacted(self):
        with tempfile.TemporaryDirectory() as root:
            service = NetworkToolsService(root, socket_factory=lambda *args, **kwargs: _Socket())
            result = service.import_text(
                "http://user:secret@proxy.example:8080\nproxy.example:8080:user:secret",
                country="us", group="住宅 A", scheme="http",
            )
            self.assertEqual(result["total"], 1)
            row = result["rows"][0]
            self.assertNotIn("secret", str(row))
            self.assertEqual(row["country"], "US")

    def test_reimport_updates_endpoint_protocol_but_preserves_runtime_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            service = NetworkToolsService(root, socket_factory=lambda *args, **kwargs: _Socket())
            service.import_text("proxy.example:8080:user:secret", country="JP", group="住宅 A", scheme="http")
            proxy_id = service.public()["rows"][0]["proxy_id"]

            # Simulate state accumulated by a prior health check/lease.
            with service._lock:
                service._proxies[proxy_id].update({
                    "status": "available",
                    "lease_owner": "worker-1",
                    "lease_until": 1234567890,
                    "last_checked_at": 1234567800,
                    "last_exit_ip": "198.51.100.9",
                    "latency_ms": 42.5,
                    "consecutive_failures": 0,
                })

            service.import_text("proxy.example:8080:user:secret", country="JP", group="住宅 A", scheme="socks5")
            row = service.public()["rows"][0]
            self.assertEqual(row["scheme"], "socks5")
            self.assertEqual(row["status"], "available")
            self.assertEqual(row["lease_owner"], "worker-1")
            self.assertEqual(row["lease_until"], 1234567890)
            self.assertEqual(row["last_checked_at"], 1234567800)
            self.assertEqual(row["last_exit_ip"], "198.51.100.9")
            self.assertEqual(row["latency_ms"], 42.5)

    def test_quick_and_deep_use_selected_proxy_without_environment_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            sessions = []

            def make_session():
                item = _Session()
                sessions.append(item)
                return item

            service = NetworkToolsService(root, session_factory=make_session, socket_factory=lambda *args, **kwargs: _Socket())
            service.import_text("socks5://proxy.example:1080", country="JP", group="住宅 B")
            proxy_id = service.public()["rows"][0]["proxy_id"]
            quick = service.test(proxy_id, mode="quick")
            self.assertTrue(quick["ok"])
            deep = service.test(proxy_id, mode="deep", target_url="https://target.example", exit_url="https://ip.example")
            self.assertEqual(deep["exit_ip"], "198.51.100.9")
            self.assertEqual(len(sessions), 1)
            self.assertTrue(all(call[1]["proxies"]["https"].startswith("socks5://") for call in sessions[0].calls))

    def test_subscription_metadata_without_supported_mihomo_is_safe(self):
        with tempfile.TemporaryDirectory() as root:
            service = NetworkToolsService(root)
            service.save_config({"mihomo_path": "/tmp/gptphone-test-mihomo-missing"})
            result = service.import_subscription("https://sub.example/list", "http://proxy.example:8080", country="GB", group="订阅")
            self.assertEqual(result["node_count"], 1)
            self.assertFalse(result["mihomo"]["available"])
            tested = service.test_subscription(result["subscription_id"])
            self.assertFalse(tested["tested"])
            self.assertNotIn("sub.example", str(service.public()))

    def test_clash_yaml_is_parsed_without_exposing_credentials(self):
        with tempfile.TemporaryDirectory() as root:
            service = NetworkToolsService(root)
            service.save_config({"mihomo_path": "/tmp/gptphone-test-mihomo-missing"})
            content = """proxies:\n  - name: home\n    type: socks5\n    server: proxy.example\n    port: 1080\n    username: user\n    password: secret\n  - name: vless-node\n    type: vless\n    server: edge.example\n    port: 443\n"""
            result = service.import_subscription("https://sub.example/clash", content, country="US", group="Clash")
            self.assertEqual(result["node_count"], 2)
            self.assertEqual(result["imported"], 1)
            self.assertEqual(result["parsed_nodes"][1]["scheme"], "vless")
            self.assertNotIn("secret", str(result["parsed_nodes"]))


if __name__ == "__main__":
    unittest.main()
