from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from mac_overrides.free_register_runtime import (
    FIXED_PASSWORD,
    FreeMailboxPool,
    FreeProxyPool,
    FreeRegisterError,
    FreeRegisterManager,
    FreeTwoFaPending,
)
from mac_overrides.free_log_runtime import FreeLogStore
from mac_overrides.free_proxy_store import FreeProxyPool as StructuredFreeProxyPool


class FakeResponse:
    def __init__(self, payload, status_code: int = 200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)


class FakeTransport:
    def __init__(self, session):
        self.session = session


class FreeRegisterRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-free-test-")
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_free_pool_uses_separate_files_and_masks_public_secrets(self):
        pool = FreeMailboxPool(self.data_dir)
        imported = pool.import_text(
            "first@example.test----https://mail.example.test/a?token=private\n"
            "second@example.test----https://mail.example.test/b\n"
        )

        self.assertEqual(imported, 2)
        self.assertTrue(pool.pool_path.name.startswith("free_"))
        self.assertEqual(pool.results_dir.name, "free_register_results")
        self.assertFalse((self.data_dir / "mailbox_pool.txt").exists())
        rows = pool.public_rows()
        self.assertEqual(rows[0]["email"], "first@example.test")
        self.assertNotIn("private", str(rows))
        self.assertNotIn("https://", str(rows))
        self.assertNotIn("private", str(rows))

    def test_free_pool_accepts_three_dash_mailbox_delimiter(self):
        pool = FreeMailboxPool(self.data_dir)
        imported = pool.import_text(
            "first@example.test---https://mail.example.test/a?key=private\n"
            "second@example.test|https://mail.example.test/b\n"
        )

        self.assertEqual(imported, 2)
        self.assertEqual([row["email"] for row in pool.public_rows()], [
            "first@example.test",
            "second@example.test",
        ])

    def test_free_logs_keep_account_and_stage_identity_under_concurrency(self):
        logs = FreeLogStore(self.data_dir)
        logs.add(
            "[free-batch-1-1/等待 Free 邮箱验证码/free_email_otp_wait] "
            "账号 first@example.test code=123456 mailbox_url=https://mail.example.test/pickup",
            "info",
        )
        logs.add(
            "[free-batch-1-2/获取 Free access token/free_access_token] "
            "账号 second@example.test access_token=private-token",
            "info",
        )

        rows = logs.snapshot()
        self.assertEqual([row["task_id"] for row in rows], ["free-batch-1-1", "free-batch-1-2"])
        self.assertEqual(rows[0]["stage"], "free_email_otp_wait")
        self.assertEqual(rows[1]["stage"], "free_access_token")
        self.assertNotIn("123456", rows[0]["message"])
        self.assertNotIn("mail.example.test/pickup", rows[0]["message"])
        self.assertNotIn("private-token", rows[1]["message"])
        self.assertEqual(len(logs.snapshot("free-batch-1-1")), 1)
        self.assertEqual(logs.snapshot("free-batch-1-1")[0]["task_id"], "free-batch-1-1")

    def test_free_logs_preserve_numeric_task_ids_while_redacting_body_codes(self):
        logs = FreeLogStore(self.data_dir)
        logs.add("[free-batch-bd402220-1/获取 Token/free_access_token] code=123456", "info")

        row = logs.snapshot()[0]
        self.assertEqual(row["task_id"], "free-batch-bd402220-1")
        self.assertIn("free-batch-bd402220-1", row["message"])
        self.assertNotIn("123456", row["message"])

    def test_free_pool_import_appends_and_deduplicates_existing_rows(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("first@example.test----https://mail.example.test/a\n")

        added, skipped = pool.import_text_with_stats(
            "first@example.test----https://mail.example.test/a\n"
            "second@example.test----https://mail.example.test/b\n"
        )

        self.assertEqual((added, skipped), (1, 1))
        self.assertEqual([row.email for row in pool.entries()], [
            "first@example.test",
            "second@example.test",
        ])

    def test_free_pool_delete_rejects_active_rows_and_keeps_history_files(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text(
            "first@example.test----https://mail.example.test/a\n"
            "second@example.test----https://mail.example.test/b\n"
        )
        first, second = pool.entries()
        pool.update(first.row_id, status="running")

        with self.assertRaisesRegex(FreeRegisterError, "排队或运行中"):
            pool.delete([first.row_id, second.row_id])
        self.assertEqual(len(pool.entries()), 2)

        pool.update(first.row_id, status="failed")
        pool.save_result(first.row_id, {"status": "failed"})
        self.assertEqual(pool.delete([first.row_id]), 1)
        self.assertEqual([row.email for row in pool.entries()], ["second@example.test"])
        self.assertTrue(pool.result(first.row_id))

    def test_proxy_binding_rejects_duplicate_exit_ip_before_tasks_start(self):
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n")

        with self.assertRaisesRegex(FreeRegisterError, "一号一 IP"):
            proxies.bind(
                2,
                probe=lambda _proxy, _url: "203.0.113.10",
            )

    def test_proxy_preflight_probes_pasted_pool_without_consuming_mailboxes(self):
        manager = FreeRegisterManager(
            self.data_dir,
            proxy_probe=lambda proxy, _url: "203.0.113." + ("10" if "proxy-a" in proxy else "11"),
        )
        result = manager.preflight_proxies(
            proxy_content="proxy-a.test:8000\nproxy-b.test:8000\n",
            probe_url="https://api.ipify.org",
        )

        self.assertEqual(result["proxies"], 2)
        self.assertEqual(result["exit_ips"], 2)
        self.assertEqual([row["exit_ip"] for row in result["rows"]], ["203.0.113.10", "203.0.113.11"])
        self.assertEqual(manager.pool.entries(), [])
        self.assertNotIn("https://", str(result))

    def test_proxy_binding_reports_the_failed_row_without_exposing_credentials(self):
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text(
            "proxy-a.test:8000:user-a:private-a\n"
            "proxy-b.test:8000:user-b:private-b\n"
        )

        with self.assertRaisesRegex(FreeRegisterError, r"第 2 条.*Timeout"):
            proxies.bind(
                2,
                probe=lambda proxy, _url: (_ for _ in ()).throw(TimeoutError()) if "proxy-b" in proxy else "203.0.113.10",
            )

    def test_proxy_binding_keeps_original_protocol_after_socks_tls_failure(self):
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("proxy.example.test:8000:user-a:pass-a\n")
        calls = []

        class SSLError(RuntimeError):
            pass

        def probe(proxy, _url):
            calls.append(proxy)
            raise SSLError("TLS handshake failed")

        with self.assertRaisesRegex(FreeRegisterError, r"第 1 条.*SSLError") as raised:
            proxies.bind(1, probe=probe)

        self.assertEqual(calls, ["http://user-a:pass-a@proxy.example.test:8000"])
        self.assertNotIn("pass-a", str(raised.exception))

    def test_proxy_pool_accepts_host_port_username_password_rows(self):
        proxies = FreeProxyPool(self.data_dir)
        imported = proxies.import_text(
            "proxy.example.test:3000:user-a:pass-a\n"
            "proxy.example.test:3001:user-b:pass:b\n"
        )

        self.assertEqual(imported, 1)
        values = proxies.values()
        self.assertEqual(values, ["http://user-a:pass-a@proxy.example.test:3000"])

    def test_proxy_pool_protocolless_rows_follow_autoregister_http_rule(self):
        proxies = FreeProxyPool(self.data_dir)
        imported = proxies.import_text(
            "proxy-a.test 3000 user-a pass-a\n"
            "socks4://user-b:pass-b@proxy-b.test:3001\n"
        )

        self.assertEqual(imported, 2)
        self.assertEqual(proxies.values(), [
            "http://user-a:pass-a@proxy-a.test:3000",
            "socks4://user-b:pass-b@proxy-b.test:3001",
        ])

    def test_proxy_pool_preserves_explicit_http_and_socks5_protocols(self):
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text(
            "http://user-a:pass-a@proxy.example.test:3000\n"
            "socks5://user-b:pass-b@proxy.example.test:3001\n"
        )

        self.assertEqual(proxies.values(), [
            "http://user-a:pass-a@proxy.example.test:3000",
            "socks5://user-b:pass-b@proxy.example.test:3001",
        ])

    def test_proxy_probe_matches_autoregister_session_settings(self):
        calls = {}

        class FakeSession:
            def __init__(self, **kwargs):
                calls["init"] = kwargs
                self.proxies = {}

            def get(self, url, **kwargs):
                calls["get"] = (url, kwargs, dict(self.proxies))
                return SimpleNamespace(status_code=200, content=b"203.0.113.40")

            def close(self):
                calls["closed"] = True

        curl_module = ModuleType("curl_cffi")
        curl_module.requests = SimpleNamespace(Session=FakeSession)
        with patch.dict(sys.modules, {"curl_cffi": curl_module}):
            self.assertEqual(
                FreeProxyPool._probe("socks5h://proxy.test:8000", "https://api.ipify.org"),
                "203.0.113.40",
            )

        self.assertEqual(calls["init"], {"impersonate": "chrome", "verify": False})
        self.assertEqual(calls["get"][2], {
            "http": "socks5h://proxy.test:8000",
            "https": "socks5h://proxy.test:8000",
        })
        self.assertEqual(calls["get"][1]["timeout"], 12)
        self.assertTrue(calls["closed"])

    def test_structured_free_proxy_pool_tracks_country_group_scheme_and_migrates_legacy(self):
        legacy = self.data_dir / "free_proxy_pool.txt"
        legacy.write_text("proxy-region-US.example:3000:user:pass\n", encoding="utf-8")
        pool = StructuredFreeProxyPool(self.data_dir)
        self.assertEqual(pool.records()[0]["country"], "US")
        self.assertTrue((self.data_dir / "free_proxy_pool.json").exists())
        pool.import_text("socks5://user:pass@proxy-region-US.example:3000\n", country="US", group="住宅 A")
        public = pool.public()
        self.assertEqual(public["count"], 1)
        self.assertEqual(public["rows"][0]["scheme"], "socks5")
        self.assertEqual(public["rows"][0]["group"], "住宅 A")
        self.assertNotIn("pass", str(public))

    def test_structured_proxy_pool_filters_roxy_compatible_groups_and_quarantines_failures(self):
        pool = StructuredFreeProxyPool(self.data_dir, failure_threshold=2, quarantine_seconds=600)
        pool.import_text(
            "socks4://user:pass@proxy-region-US.example:3000\n"
            "socks5://user:pass@proxy-region-US.example:3001\n",
            country="US", group="住宅 A",
        )
        self.assertEqual(len(pool.records(country="US", group="住宅 A", driver="roxybrowser")), 1)
        proxy_id = pool.records(country="US", group="住宅 A", driver="roxybrowser")[0]["proxy_id"]
        pool.record_failure(proxy_id, node_code="free_roxy_open", message="连接失败")
        pool.record_failure(proxy_id, node_code="free_roxy_open", message="连接失败")
        self.assertEqual(pool.records(country="US", group="住宅 A", driver="roxybrowser"), [])
        self.assertEqual(pool.public()["groups"][0]["quarantined"], 1)

    def test_pasted_proxy_preflight_honors_country_group_and_roxy_protocol(self):
        manager = FreeRegisterManager(
            self.data_dir,
            proxy_probe=lambda proxy, _url: "203.0.113.50" if "proxy-region-US" in proxy else "203.0.113.51",
        )
        with self.assertRaisesRegex(FreeRegisterError, "代理数量不足"):
            manager.preflight_proxies(
                proxy_content="socks4://proxy-region-US.example:3000\nsocks5://proxy-region-US.example:3001\n",
                driver="roxybrowser",
                country="US",
                group="住宅 A",
            )
        result = manager.preflight_proxies(
            proxy_content="socks5://proxy-region-US.example:3001\n",
            driver="roxybrowser",
            country="US",
            group="住宅 A",
        )
        self.assertEqual(result["rows"][0]["scheme"], "socks5")
        self.assertEqual(result["rows"][0]["country"], "US")
        self.assertEqual(result["rows"][0]["group"], "住宅 A")

    def test_mailbox_otp_provider_uses_proxy_aware_fetcher(self):
        from mac_overrides.free_register_runtime import MailboxUrlOtpProvider

        provider = MailboxUrlOtpProvider(
            "https://mail.example.test/pickup",
            "socks5h://user:pass@proxy.example.test:3000",
            timeout=10,
        )

        self.assertTrue(callable(provider.client.fetcher))
        self.assertEqual(provider.client.proxy, "socks5h://user:pass@proxy.example.test:3000")

    def test_manager_binds_mailboxes_and_proxies_in_order_under_concurrency(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text(
            "a@example.test----https://mail.example.test/a\n"
            "b@example.test----https://mail.example.test/b\n"
        )
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n")
        seen = []

        def probe(proxy, _url):
            return "203.0.113." + ("10" if "proxy-a" in proxy else "11")

        def runner(task, _config, _stop, stage, log, *, twofa_retry=False):
            seen.append((task["ordinal"], task["email"], task["proxy"], twofa_retry))
            stage(task["task_id"], "free_access_token")
            log("[协议内部/free_access_token] 当前账号已进入 Token 节点")
            return {
                "access_token": f"token-{task['ordinal']}",
                "password": FIXED_PASSWORD,
                "plan_type": "free",
                "plus_trial_eligible": task["ordinal"] == 1,
                "twofa_status": "enabled",
                "totp_secret": "JBSWY3DPEHPK3PXP",
                "credential_line": f"{task['email']}----{FIXED_PASSWORD}----JBSWY3DPEHPK3PXP",
            }

        manager = FreeRegisterManager(self.data_dir, runner=runner, proxy_probe=probe)
        result = manager.start({"target_count": 2, "free_concurrency": 2})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        self.assertFalse(manager.public_state()["running"])
        self.assertEqual({row[1]: row[2] for row in seen}, {
            "a@example.test": "http://proxy-a.test:8000",
            "b@example.test": "http://proxy-b.test:8000",
        })
        self.assertEqual({row[0] for row in seen}, {1, 2})
        public = manager.public_tasks()
        self.assertTrue(all("token-" not in str(row) for row in public))
        self.assertTrue(all(FIXED_PASSWORD not in str(row) for row in public))
        self.assertEqual(manager.secret([public[0]["task_id"]], "token"), "token-1")
        detail_logs = [row for row in manager.public_logs() if "当前账号已进入 Token 节点" in row["message"]]
        self.assertEqual({row["task_id"] for row in detail_logs}, {row["task_id"] for row in public})
        self.assertTrue(all(row["stage"] == "free_access_token" for row in detail_logs))

    def test_free_start_ignores_larger_shared_oauth_target_count(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text(
            "a@example.test----https://mail.example.test/a\n"
            "b@example.test----https://mail.example.test/b\n"
        )
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text(
            "http://proxy-a.test:8000\n"
            "http://proxy-b.test:8000\n"
        )
        seen = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            seen.append(task["email"])
            return {"access_token": f"token-{task['ordinal']}", "twofa_status": "enabled"}

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda proxy, _url: "203.0.113." + ("10" if "proxy-a" in proxy else "11"),
        )
        manager.start({"target_count": 100, "free_concurrency": 2})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        self.assertCountEqual(seen, ["a@example.test", "b@example.test"])

    def test_free_start_honors_explicit_target_count_and_auto_zero(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text(
            "a@example.test----https://mail.example.test/a\n"
            "b@example.test----https://mail.example.test/b\n"
        )
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n")
        seen = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            seen.append(task["email"])
            return {"access_token": f"token-{task['ordinal']}", "twofa_status": "enabled"}

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda proxy, _url: "203.0.113." + ("10" if "proxy-a" in proxy else "11"),
        )
        manager.start({"free_target_count": 1, "free_concurrency": 2})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(seen, ["a@example.test"])

    def test_plan_check_reports_plus_trial_and_structured_failures(self):
        account_response = FakeResponse({
            "accounts": {
                "default": {
                    "account": {"plan_type": "free"},
                    "eligible_promo_campaigns": {"plus": {"duration": 30}},
                },
            },
        })
        eligibility_response = FakeResponse({"health": False, "finances": False})
        session = FakeSession([account_response, eligibility_response])
        manager = FreeRegisterManager(self.data_dir)
        plan, eligible = manager._plan_check(FakeTransport(session), "token-redacted")

        self.assertEqual((plan, eligible), ("free", True))
        self.assertEqual(len(session.calls), 2)
        self.assertIn("timezone_offset_min=", session.calls[0][1])

        failing = FakeSession([FakeResponse({}, 503)])
        with self.assertRaises(FreeRegisterError) as raised:
            manager._plan_check(FakeTransport(failing), "token-redacted")
        self.assertEqual(raised.exception.node_code, "free_plan_check")
        self.assertNotIn("token-redacted", str(raised.exception))

    def test_twofa_pending_can_be_retried_after_task_result_is_persisted(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\n")
        retry_flags = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            retry_flags.append(twofa_retry)
            if not twofa_retry:
                return {"access_token": "token-private", "password": FIXED_PASSWORD, "twofa_status": "pending"}
            return {"access_token": "token-private", "password": FIXED_PASSWORD, "twofa_status": "enabled", "totp_secret": "JBSWY3DPEHPK3PXP"}

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.20",
        )
        manager.start({"target_count": 1})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        pending = manager.public_tasks()[0]
        self.assertEqual(pending["status"], "twofa_pending")
        self.assertNotIn("token-private", str(pending))

        manager.retry_twofa(pending["task_id"], {})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(retry_flags, [False, True])
        row_id = manager.pool.entries()[0].row_id
        self.assertEqual(manager.secret([], "totp", row_ids=[row_id]), "JBSWY3DPEHPK3PXP")

    def test_failed_twofa_retry_preserves_pending_state_and_token(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\n")
        retry_flags = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            retry_flags.append(twofa_retry)
            if not twofa_retry:
                return {"access_token": "token-private", "password": FIXED_PASSWORD, "twofa_status": "pending"}
            raise FreeTwoFaPending("activate timeout", token="token-private", plan_type="free", plus_trial_eligible=True)

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.21",
        )
        manager.start({"target_count": 1})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        pending = manager.public_tasks()[0]
        manager.retry_twofa(pending["task_id"], {})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        result = manager.public_tasks()[0]
        self.assertEqual(retry_flags, [False, True])
        self.assertEqual(result["status"], "twofa_pending")
        self.assertTrue(result["result"]["has_access_token"])
        self.assertNotIn("token-private", str(result))
        self.assertEqual(manager.secret([result["task_id"]], "token"), "token-private")

    def test_proxy_secret_can_be_read_from_private_pool_state_before_result(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        row_id = pool.entries()[0].row_id
        pool.update(row_id, proxy="http://user:pass@proxy.test:8080", proxy_masked="http://proxy.test:8080")
        manager = FreeRegisterManager(self.data_dir)
        self.assertEqual(manager.secret([], "proxy", row_ids=[row_id]), "http://user:pass@proxy.test:8080")

    def test_free_logs_redact_protocol_secrets_before_writing(self):
        logs = []
        manager = FreeRegisterManager(self.data_dir, log_fn=lambda message, level: logs.append((message, level)))
        manager._log(
            "password=nuHf5UFg2vtCW!/ access_token=token-private "
            "totp_secret=JBSWY3DPEHPK3PXP proxy=https://user:pass@proxy.test:8080 "
            "mailbox_url=https://mail.test/inbox?token=mail-private",
        )
        serialized = str(logs)
        for secret in (FIXED_PASSWORD, "token-private", "JBSWY3DPEHPK3PXP", "user:pass", "mail-private"):
            self.assertNotIn(secret, serialized)
        self.assertIn("********", serialized)

    def test_free_logs_redact_bare_urls_bearer_tokens_and_codes(self):
        logs = []
        manager = FreeRegisterManager(self.data_dir, log_fn=lambda message, level: logs.append((message, level)))
        manager._log(
            "GET https://mail.test/inbox?token=mail-private#code=123456 "
            "proxy=https://user:pass@proxy.test:8080 Bearer token-private 123456",
        )
        serialized = str(logs)
        for secret in ("mail-private", "user:pass", "token-private", "123456"):
            self.assertNotIn(secret, serialized)


if __name__ == "__main__":
    unittest.main()
