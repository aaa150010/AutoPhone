from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.diagnostic_store import DiagnosticStore
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

    def test_failed_proxy_rows_share_one_credential_safe_preflight_incident(self) -> None:
        diagnostic_store = DiagnosticStore(self.data_dir / "diagnostics")

        def fail_probe(_proxy: str, _url: str) -> str:
            raise TimeoutError("proxy password should-not-persist")

        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=fail_probe,
            diagnostic_store=diagnostic_store,
        )
        result = manager.preflight_proxies(
            proxy_content=(
                "socks5://user-one:private-one@proxy-a.example.test:3000\n"
                "socks5://user-two:private-two@proxy-b.example.test:3000\n"
            ),
            probe_url="https://chatgpt.com/",
            socks5_dns_mode="remote",
        )

        incident_id = str(result.get("incident_id") or "")
        self.assertRegex(incident_id, r"^LOG-\d{8}-[A-Z0-9]{8}$")
        self.assertEqual(result["failure_count"], 2)
        self.assertEqual({row.get("incident_id") for row in result["rows"]}, {incident_id})
        self.assertTrue(all(isinstance(row.get("failure"), dict) for row in result["rows"]))
        incident = diagnostic_store.incident(incident_id)
        assert incident is not None
        self.assertEqual(incident["task_id"], "")
        self.assertEqual(incident["event_count"], 1)
        exported = diagnostic_store.export([incident_id], "json")
        for secret in ("user-one", "private-one", "user-two", "private-two"):
            self.assertNotIn(secret, exported)
        transport = incident["events"][0]["transport"]
        self.assertEqual(transport["failure_count"], 2)
        self.assertEqual(transport["target_domain"], "chatgpt.com")

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

    def test_chatgpt_connectivity_probe_accepts_anonymous_401_and_403(self) -> None:
        """An edge authorization response proves the proxy path reached ChatGPT."""
        for status in (401, 403):
            with self.subTest(status=status), patch(
                "mac_overrides.free_proxy_store.get_via_proxy",
                return_value=SimpleNamespace(status_code=status, content=b""),
            ) as request:
                self.assertEqual(
                    FreeProxyPool._probe(
                        "socks5h://proxy.example.test:8000",
                        "https://chatgpt.com/",
                    ),
                    "",
                )
                request.assert_called_once()

    def test_chatgpt_challenge_page_is_rejected_for_200_401_and_403(self) -> None:
        """A challenge document must win over every otherwise plausible status."""
        marker = b"Just a moment... /cdn-cgi/challenge-platform/"
        for status in (200, 401, 403):
            with self.subTest(status=status), patch(
                "mac_overrides.free_proxy_store.get_via_proxy",
                return_value=SimpleNamespace(status_code=status, content=marker),
            ):
                with self.assertRaises(FreeRegisterError) as raised:
                    FreeProxyPool._probe(
                        "http://proxy.example.test:8000",
                        "https://chatgpt.com/",
                    )
                error = raised.exception
                self.assertEqual(error.node_code, "free_proxy_preflight")
                self.assertEqual(error.error_code, "free_proxy_chatgpt_security_challenge")
                self.assertEqual(error.provider_status, status)
                self.assertFalse(error.retryable)
                self.assertEqual(error.page_type, "security_challenge")
                self.assertNotIn("challenge-platform", str(error))

    def test_probe_status_is_kept_in_bind_diagnostics_and_health_snapshot(self) -> None:
        pool = FreeProxyPool(self.data_dir)
        pool.import_text("http://proxy.example.test:8000\n")
        with patch(
            "mac_overrides.free_proxy_store.get_via_proxy",
            return_value=SimpleNamespace(status_code=403, content=b"anonymous edge denial"),
        ):
            bindings = pool.bind(1, probe_url="https://chatgpt.com/")

        self.assertEqual(len(bindings), 1)
        self.assertEqual(pool._last_bind_diagnostics[0]["http_status"], 403)
        row = pool.public()["rows"][0]
        self.assertEqual(row["last_probe_http_status"], 403)

    def test_chatgpt_challenge_does_not_quarantine_saved_proxy(self) -> None:
        pool = FreeProxyPool(self.data_dir, failure_threshold=1)
        pool.import_text("http://proxy.example.test:8000\n")
        with patch(
            "mac_overrides.free_proxy_store.get_via_proxy",
            return_value=SimpleNamespace(
                status_code=403,
                content=b"<html>Just a moment... /cdn-cgi/challenge-platform/</html>",
            ),
        ):
            with self.assertRaises(FreeRegisterError) as raised:
                pool.bind(1, probe_url="https://chatgpt.com/")

        self.assertEqual(raised.exception.error_code, "free_proxy_chatgpt_security_challenge")
        row = pool.public()["rows"][0]
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertNotEqual(row["status"], "quarantined")

    def test_non_chatgpt_http_403_remains_a_failed_probe(self) -> None:
        with patch(
            "mac_overrides.free_proxy_store.get_via_proxy",
            return_value=SimpleNamespace(status_code=403, content=b""),
        ):
            with self.assertRaisesRegex(ValueError, "HTTP 403"):
                FreeProxyPool._probe(
                    "http://proxy.example.test:8000",
                    "https://probe.example.test/",
                )

    def test_expired_quarantine_is_not_reported_as_active(self) -> None:
        pool = FreeProxyPool(self.data_dir, failure_threshold=1)
        pool.import_text("http://proxy.example.test:8000\n")
        proxy_id = pool.public()["rows"][0]["proxy_id"]
        pool.record_failure(
            proxy_id,
            node_code="proxy_connect_failed",
            message="temporary transport failure",
            threshold=1,
            quarantine_seconds=600,
        )
        rows = pool._load()
        rows[0]["quarantined_until"] = time.time() - 1
        pool._save(rows)

        row = pool.public()["rows"][0]
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["stored_status"], "quarantined")
        self.assertFalse(row["quarantine_active"])
        self.assertTrue(row["quarantine_expired"])
        self.assertTrue(row["eligible"])
        self.assertTrue(row["dispatchable"])

    def test_disabled_proxy_is_never_reported_as_dispatchable(self) -> None:
        pool = FreeProxyPool(self.data_dir)
        pool.import_text("http://proxy.example.test:8000\n")
        pool.update_group("", "", enabled=False)

        row = pool.public()["rows"][0]
        self.assertFalse(row["enabled"])
        self.assertEqual(row["status"], "disabled")
        self.assertFalse(row["eligible"])
        self.assertFalse(row["dispatchable"])

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

    def test_stale_refresh_challenge_is_not_quarantined(self) -> None:
        pool = FreeProxyPool(self.data_dir, failure_threshold=1, health_probe_ttl_seconds=1)
        pool.import_text("http://proxy.example.test:8000\n")
        proxy_id = pool.public()["rows"][0]["proxy_id"]
        rows = pool._load()
        rows[0]["last_checked_at"] = time.time() - 10
        rows[0]["last_probe_ok"] = True
        pool._save(rows)

        def challenge(_proxy: str, _target: str) -> str:
            raise FreeRegisterError(
                "free_proxy_preflight",
                "Free 代理预检",
                "ChatGPT 代理预检返回安全挑战页面",
                provider_status=403,
                retryable=False,
                error_code="free_proxy_chatgpt_security_challenge",
                page_type="security_challenge",
            )

        with self.assertRaises(FreeRegisterError):
            pool.bind(
                1,
                probe=challenge,
                perform_probe=False,
                health_probe_ttl_seconds=1,
            )
        row = pool.public()["rows"][0]
        self.assertEqual(row["proxy_id"], proxy_id)
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertNotEqual(row["status"], "quarantined")

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
