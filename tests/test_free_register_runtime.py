from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import threading
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
from mac_overrides.free_register_config import FreeConfigStore
from mac_overrides.free_protocol_runtime import FreeProtocolMixin, resolve_auth_impersonates
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
    def test_protocol_uses_reference_impersonation_rotation_order(self):
        self.assertEqual(
            resolve_auth_impersonates({}),
            ["chrome", "chrome136", "chrome133a", "safari15_3", "safari17_0"],
        )
        self.assertEqual(
            resolve_auth_impersonates({"auth_impersonates": [" chrome", "chrome", "safari17_0"]}),
            ["chrome", "safari17_0"],
        )
        self.assertEqual(
            resolve_auth_impersonates({"chatgpt_impersonates": ["firefox"]}),
            ["firefox"],
        )
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

    def test_free_logs_backfill_node_label_for_two_part_prefix(self):
        logs = FreeLogStore(self.data_dir)
        logs.add("[free-batch-1/free_oauth_session] 开始", "info")

        row = logs.snapshot("free-batch-1")[0]
        self.assertEqual(row["node_code"], "free_oauth_session")
        self.assertEqual(row["node_label"], "Free OAuth 会话")
        self.assertEqual(row["stage_label"], "Free OAuth 会话")

    def test_free_logs_write_uniform_context_defaults(self):
        logs = FreeLogStore(self.data_dir)
        logs.add("普通阶段日志", "info")

        row = logs.snapshot()[0]
        for field in FreeLogStore.REQUIRED_FIELDS:
            self.assertIn(field, row)
        self.assertTrue(row["time"])
        self.assertEqual(row["level"], "info")
        self.assertEqual(row["task_id"], "")
        self.assertEqual(row["node_code"], "")
        self.assertEqual(row["node_label"], "")
        self.assertIsNone(row["attempt"])
        self.assertIsNone(row["duration_ms"])
        self.assertEqual(row["page_type"], "")
        self.assertEqual(row["safe_page"], "")
        self.assertIsNone(row["http_status"])
        self.assertEqual(row["provider_code"], "")
        self.assertEqual(row["outcome"], "")
        self.assertEqual(row["diagnostic"], "")
        self.assertEqual(row["action_hint"], "")
        self.assertEqual(row["result"], "")

    def test_free_logs_migrate_legacy_rows_and_drop_unknown_secrets(self):
        logs = FreeLogStore(self.data_dir)
        logs.path.parent.mkdir(parents=True, exist_ok=True)
        logs.path.write_text(
            json.dumps([{
                "time": "2026-08-24T01:02:03+00:00",
                "level": "error",
                "message": "password=legacy-password token=legacy-token",
                "task_id": "free-legacy-1",
                "stage": "free_oauth_session",
                "stage_label": "Free OAuth 会话",
                "page": "https://auth.openai.com/login?state=private",
                "http_status": "502",
                "token": "unknown-secret-must-drop",
                "time": "password=legacy-time-secret",
            }], ensure_ascii=False),
            encoding="utf-8",
        )

        rows = logs.snapshot("free-legacy-1")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        for field in FreeLogStore.REQUIRED_FIELDS:
            self.assertIn(field, row)
        self.assertEqual(row["node_code"], "free_oauth_session")
        self.assertEqual(row["node_label"], "Free OAuth 会话")
        self.assertEqual(row["safe_page"], "https://auth.openai.com/login")
        self.assertEqual(row["http_status"], 502)
        self.assertIsNone(row["attempt"])
        self.assertNotIn("legacy-password", str(row))
        self.assertNotIn("legacy-token", str(row))
        self.assertNotIn("unknown-secret-must-drop", str(row))
        self.assertNotIn("legacy-time-secret", str(row))

        persisted = json.loads(logs.path.read_text(encoding="utf-8"))
        self.assertEqual(len(persisted), 1)
        for field in FreeLogStore.REQUIRED_FIELDS:
            self.assertIn(field, persisted[0])
        self.assertNotIn("token", persisted[0])
        self.assertNotIn("legacy-password", logs.path.read_text(encoding="utf-8"))

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

    def test_proxy_binding_allows_shared_exit_ip_before_tasks_start(self):
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n")

        bindings = proxies.bind(2, probe=lambda _proxy, _url: "203.0.113.10")
        self.assertEqual(len(bindings), 2)
        self.assertEqual({binding.exit_ip for binding in bindings}, {"203.0.113.10"})

    def test_proxy_lease_supports_multiple_tasks_and_independent_release(self):
        proxies = StructuredFreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\n")
        first, second = proxies.bind(2, probe=lambda _proxy, _url: "203.0.113.10")
        proxies.lease(first, owner="task-a", batch_id="batch-a", task_id="task-a")
        proxies.lease(second, owner="task-b", batch_id="batch-a", task_id="task-b")
        self.assertEqual(proxies.public()["rows"][0]["active_lease_count"], 2)
        self.assertEqual(proxies.public()["groups"][0]["leased"], 2)
        self.assertEqual(proxies.public()["groups"][0]["available"], 1)
        proxies.release(first, owner="task-a")
        self.assertEqual(proxies.public()["rows"][0]["active_lease_count"], 1)
        proxies.release(second, owner="task-b")
        self.assertEqual(proxies.public()["rows"][0]["active_lease_count"], 0)

    def test_legacy_exclusive_mode_is_shared_and_allows_second_lease(self):
        proxies = StructuredFreeProxyPool(self.data_dir)
        proxies.configure_policy(allocation_mode="exclusive")
        proxies.import_text("http://proxy-a.test:8000\n")
        binding = proxies.bind(1, probe=lambda _proxy, _url: "203.0.113.20")[0]
        proxies.lease(binding, owner="task-a", batch_id="batch-a", task_id="task-a")
        rebound = proxies.bind(1, probe=lambda _proxy, _url: "203.0.113.20")
        proxies.lease(binding, owner="task-b", batch_id="batch-b", task_id="task-b")
        self.assertEqual(rebound[0].proxy_id, binding.proxy_id)
        self.assertEqual(proxies.allocation_mode, "healthy_random")
        self.assertEqual(proxies.public()["groups"][0]["available"], 1)

    def test_shared_mode_allows_duplicate_exit_ip_on_another_proxy(self):
        proxies = StructuredFreeProxyPool(self.data_dir)
        proxies.configure_policy(allocation_mode="exclusive")
        proxies.import_text("http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n")
        first = proxies.bind(
            1,
            content="http://proxy-a.test:8000\n",
            probe=lambda _proxy, _url: "203.0.113.21",
        )[0]
        proxies.lease(first, owner="task-a", batch_id="batch-a", task_id="task-a")
        rebound = proxies.bind(
            1,
            content="http://proxy-b.test:8000\n",
            probe=lambda _proxy, _url: "203.0.113.21",
        )
        self.assertEqual(rebound[0].exit_ip, "203.0.113.21")

    def test_pasted_proxy_content_remains_available_during_active_lease(self):
        proxies = StructuredFreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\n")
        binding = proxies.bind(1, probe=lambda _proxy, _url: "203.0.113.12")[0]
        proxies.lease(binding, owner="task-a", batch_id="batch-a", task_id="task-a")
        rebound = proxies.bind(
            1,
            content="http://proxy-a.test:8000\n",
            probe=lambda _proxy, _url: "203.0.113.12",
        )
        self.assertEqual(rebound[0].proxy_id, binding.proxy_id)

    def test_pasted_single_proxy_can_bind_multiple_tasks_with_replacement(self):
        proxies = StructuredFreeProxyPool(self.data_dir)
        bindings = proxies.bind(
            3,
            content="socks5://user:pass@proxy-a.test:8000\n",
            probe=lambda proxy, _url: "203.0.113.13" if proxy.startswith("socks5h://") else "",
        )
        self.assertEqual(len(bindings), 3)
        self.assertEqual({binding.proxy for binding in bindings}, {"socks5h://user:pass@proxy-a.test:8000"})

    def test_free_state_and_preflight_publish_runtime_and_otp_revisions(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-a.test:8000\n")
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.20",
        )
        self.assertEqual(manager.public_state()["runtime_version"], "1.6.70")
        self.assertEqual(manager.preflight({"target_count": 1})["otp_parser_revision"], "pickup-dynamic-v4-roxy-otp-v2")

    def test_manager_preflight_applies_proxy_allocation_mode_from_config(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.20",
        )

        with patch.object(manager.proxies, "configure_policy", wraps=manager.proxies.configure_policy) as configure:
            manager.preflight(
                {
                    "driver": "protocol",
                    "target_count": 1,
                    "proxy_allocation_mode": "exclusive",
                },
                proxy_content="http://proxy-a.test:8000\n",
            )

        self.assertEqual(manager.proxies.allocation_mode, "healthy_random")
        self.assertEqual(configure.call_args.kwargs["allocation_mode"], "healthy_random")

    def test_manager_clamps_free_target_count_to_one_through_two_hundred(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("\n".join(
            f"account-{index}@example.test----https://mail.example.test/pickup/{index}"
            for index in range(250)
        ))
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.20",
        )

        result = manager.preflight(
            {"driver": "protocol", "target_count": 999},
            proxy_content="http://proxy-a.test:8000\n",
        )
        self.assertEqual(result["target_count"], 200)

        for requested, expected in ((0, 1), (999, 200)):
            with self.subTest(requested=requested):
                with patch.object(manager.proxies, "bind", side_effect=RuntimeError("stop-before-dispatch")) as bind:
                    with self.assertRaisesRegex(RuntimeError, "stop-before-dispatch"):
                        manager.start({"driver": "protocol", "target_count": requested})
                self.assertEqual(bind.call_args.args[0], expected)

    def test_protocol_start_runs_node_preflight_before_importing_or_leasing(self):
        manager = FreeRegisterManager(self.data_dir)
        failure = FreeRegisterError(
            "oauth_create_node", "初始化 Node/Sentinel",
            "SentinelRunner 文件缺失或路径无效", retryable=False,
            error_code="node_runner_missing",
        )
        with patch.object(manager, "protocol_preflight", side_effect=failure) as preflight:
            with self.assertRaisesRegex(FreeRegisterError, "SentinelRunner 文件缺失"):
                manager.start(
                    {"driver": "protocol", "target_count": 1},
                    pool_content="a@example.test----https://mail.example.test/pickup\n",
                    proxy_content="proxy.test:8000\n",
                )
        preflight.assert_called_once()
        self.assertFalse((self.data_dir / "free_mailbox_pool.txt").exists())
        self.assertFalse((self.data_dir / "free_proxy_pool.json").exists())

    def test_empty_protocol_result_stays_at_protocol_result_node(self):
        with self.assertRaises(FreeRegisterError) as raised:
            FreeProtocolMixin._protocol_result({})
        self.assertEqual(raised.exception.node_code, "free_protocol_result")
        self.assertEqual(raised.exception.error_code, "free_protocol_result_empty")

    def test_protocol_result_preserves_recovered_node_failure(self):
        with self.assertRaises(FreeRegisterError) as raised:
            FreeProtocolMixin._protocol_result({
                "ok": False, "node_code": "free_oauth_callback",
                "node_label": "Free OAuth 回调", "provider_status": 504,
                "error_code": "callback_timeout", "error": "callback failed",
            })
        self.assertEqual(raised.exception.node_code, "free_oauth_callback")
        self.assertEqual(raised.exception.node_label, "Free OAuth 回调")
        self.assertEqual(raised.exception.provider_status, 504)
        self.assertEqual(raised.exception.error_code, "callback_timeout")

    def test_protocol_result_requires_explicit_completion_before_token_fallback(self):
        self.assertFalse(FreeProtocolMixin._registration_completion_confirmed({"ok": True}))
        self.assertTrue(FreeProtocolMixin._registration_completion_confirmed({"ok": True, "oauth_callback_completed": True}))
        self.assertTrue(FreeProtocolMixin._registration_completion_confirmed({"ok": True, "access_token_present": True}))
        self.assertTrue(FreeProtocolMixin._registration_completion_confirmed({"ok": True, "phase2_status": "completed"}))

    def test_protocol_result_does_not_treat_string_false_as_completion(self):
        self.assertFalse(FreeProtocolMixin._registration_completion_confirmed({
            "registration_completed": "false",
            "signup_completed": "0",
            "oauth_callback_completed": "no",
            "status": "pending",
        }))

    def test_protocol_result_rejects_string_false_ok_marker(self):
        with self.assertRaises(FreeRegisterError) as raised:
            FreeProtocolMixin._protocol_result({
                "ok": "false",
                "error": "oauth callback was not completed",
            })
        self.assertEqual(raised.exception.node_code, "free_oauth_callback")

    def test_protocol_result_rejects_token_without_completion_marker(self):
        with self.assertRaises(FreeRegisterError) as raised:
            FreeProtocolMixin._protocol_result({"ok": True, "access_token": "token-private"})
        self.assertEqual(raised.exception.error_code, "free_registration_completion_unconfirmed")

    def test_protocol_runner_explicit_invalid_path_does_not_fall_back_to_cache(self):
        self.assertEqual(
            FreeProtocolMixin.resolve_node_runner({"protocol": {"node_runner": "/definitely/missing/runner.js"}}),
            "",
        )

    def test_protocol_runner_resolution_prefers_start_command_engine_path(self):
        with patch.dict("os.environ", {"CODEX_NODE_RUNNER": ""}, clear=False):
            resolved = FreeProtocolMixin.resolve_node_runner({})
        expected = (Path(__file__).resolve().parent.parent / "engine" / "node_chain" / "real_sentinel_runner.js").resolve()
        if expected.is_file():
            self.assertEqual(Path(resolved), expected)

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
        self.assertGreaterEqual(result["exit_ips"], 1)
        self.assertLessEqual(result["exit_ips"], 2)
        self.assertTrue({row["exit_ip"] for row in result["rows"]} <= {"203.0.113.10", "203.0.113.11"})
        self.assertEqual(manager.pool.entries(), [])
        self.assertNotIn("https://", str(result))

    def test_proxy_binding_reports_the_failed_row_without_exposing_credentials(self):
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text(
            "proxy-a.test:8000:user-a:private-a\n"
            "proxy-b.test:8000:user-b:private-b\n"
        )

        selected = []

        def choose_in_order(rows):
            selected.append(rows[len(selected) % len(rows)])
            return selected[-1]

        with patch("mac_overrides.free_proxy_store.random.SystemRandom") as random_source:
            random_source.return_value.choice.side_effect = choose_in_order
            with self.assertRaisesRegex(FreeRegisterError, r"第 2 条.*Timeout"):
                proxies.bind(
                    2,
                    content="proxy-a.test:8000:user-a:private-a\nproxy-b.test:8000:user-b:private-b\n",
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

    def test_proxy_pool_accepts_all_supported_auth_layouts(self):
        proxies = FreeProxyPool(self.data_dir)
        imported = proxies.import_text(
            "socks5://u:p@proxy-a.test:3000\n"
            "proxy-b.test:3001:u:p\n"
            "u:p@proxy-c.test:3002\n"
            "proxy-d.test:3003@u:p\n"
        )
        self.assertEqual(imported, 4)
        self.assertEqual(
            proxies.values(),
            [
                "socks5://u:p@proxy-a.test:3000",
                "http://u:p@proxy-b.test:3001",
                "http://u:p@proxy-c.test:3002",
                "http://u:p@proxy-d.test:3003",
            ],
        )

    def test_proxy_transport_maps_socks5_for_protocol_probe_and_roxy(self):
        from mac_overrides.free_register_common import proxy_transport_value

        value = "socks5://u:p@proxy.test:3000"
        self.assertEqual(proxy_transport_value(value, driver="protocol"), "socks5h://u:p@proxy.test:3000")
        self.assertEqual(proxy_transport_value(value, driver="probe"), "socks5h://u:p@proxy.test:3000")
        self.assertEqual(proxy_transport_value(value, driver="roxybrowser"), value)

    def test_proxy_pool_migrates_legacy_single_lease_to_multi_owner_state(self):
        path = self.data_dir / "free_proxy_pool.json"
        path.write_text(json.dumps({
            "version": 2,
            "proxies": [{
                "proxy": "http://proxy.test:3000",
                "proxy_id": "legacy-id",
                "host": "proxy.test",
                "port": 3000,
                "scheme": "http",
                "lease_owner": "old-task",
                "lease_until": time.time() + 300,
                "lease_batch_id": "old-batch",
                "lease_task_id": "old-task",
            }],
        }), encoding="utf-8")
        pool = StructuredFreeProxyPool(self.data_dir)
        binding = pool.bind(1, probe=lambda _proxy, _url: "203.0.113.90")[0]
        pool.lease(binding, owner="new-task", batch_id="new-batch", task_id="new-task")
        persisted = json.loads(path.read_text(encoding="utf-8"))
        row = persisted["proxies"][0]
        self.assertEqual(persisted["version"], 4)
        self.assertEqual({lease["owner"] for lease in row["leases"]}, {"old-task", "new-task"})

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

        self.assertEqual(calls["init"], {"impersonate": "chrome", "verify": True})
        self.assertEqual(calls["get"][2], {
            "http": "socks5h://proxy.test:8000",
            "https": "socks5h://proxy.test:8000",
        })
        self.assertEqual(calls["get"][1]["timeout"], 12)
        self.assertTrue(calls["closed"])

    def test_proxy_probe_retries_same_proxy_for_tls_compatibility(self):
        calls = []

        class ProxyError(RuntimeError):
            pass

        class FakeSession:
            def __init__(self, **kwargs):
                calls.append(("init", kwargs))
                self.verify = kwargs.get("verify")
                self.proxies = {}

            def get(self, url, **kwargs):
                calls.append(("get", url, kwargs, dict(self.proxies)))
                if self.verify is not False:
                    raise ProxyError("proxy CONNECT failed")
                return SimpleNamespace(status_code=200, content=b"203.0.113.41")

            def close(self):
                calls.append(("close",))

        curl_module = ModuleType("curl_cffi")
        curl_module.requests = SimpleNamespace(Session=FakeSession)
        with patch.dict(sys.modules, {"curl_cffi": curl_module}):
            pool = StructuredFreeProxyPool(self.data_dir)
            pool.import_text("socks5h://user:pass@proxy.example.test:8000")
            result = pool.bind(1)

        self.assertEqual(result[0].exit_ip, "203.0.113.41")
        self.assertEqual([item[1]["verify"] for item in calls if item[0] == "init"], [True, False])
        self.assertEqual(pool.public()["rows"][0]["last_probe_mode"], "compat")

    def test_proxy_probe_retries_libcurl_97_but_not_proxy_authentication(self):
        class ProxyError(RuntimeError):
            pass

        def run(message):
            calls = []

            class FakeSession:
                def __init__(self, **kwargs):
                    calls.append(("init", kwargs))
                    self.verify = kwargs.get("verify")
                    self.proxies = {}

                def get(self, _url, **_kwargs):
                    calls.append(("get", self.verify))
                    raise ProxyError(message)

                def close(self):
                    calls.append(("close", self.verify))

            curl_module = ModuleType("curl_cffi")
            curl_module.requests = SimpleNamespace(Session=FakeSession)
            with patch.dict(sys.modules, {"curl_cffi": curl_module}):
                pool = StructuredFreeProxyPool(self.data_dir)
                pool.import_text("socks5h://user:pass@proxy.example.test:8000")
                with self.assertRaises(FreeRegisterError):
                    pool.bind(1)
            return calls

        retry_calls = run("curl: (97) proxy connect failed")
        self.assertEqual([item[1]["verify"] for item in retry_calls if item[0] == "init"], [True, False])

        auth_calls = run("Proxy authentication failed (407)")
        self.assertEqual([item[1]["verify"] for item in auth_calls if item[0] == "init"], [True])

    def test_proxy_probe_accepts_legacy_ipinfo_json_response(self):
        calls = {}

        class FakeSession:
            def __init__(self, **kwargs):
                calls["init"] = kwargs
                self.proxies = {}

            def get(self, url, **kwargs):
                calls["get"] = (url, kwargs, dict(self.proxies))
                return SimpleNamespace(status_code=200, content=b'{"ip":"198.51.100.22","country":"US"}')

            def close(self):
                calls["closed"] = True

        curl_module = ModuleType("curl_cffi")
        curl_module.requests = SimpleNamespace(Session=FakeSession)
        with patch.dict(sys.modules, {"curl_cffi": curl_module}):
            self.assertEqual(
                StructuredFreeProxyPool._probe("socks5h://proxy.test:8000", "https://ipinfo.io/json"),
                "198.51.100.22",
            )

        self.assertIn("application/json", calls["get"][1]["headers"]["Accept"])
        self.assertTrue(calls["closed"])

    def test_protocol_proxy_preflight_ignores_chatgpt_login_http(self):
        proxies = StructuredFreeProxyPool(self.data_dir)
        bindings = proxies.bind(
            1,
            content="socks5://user:secret@proxy.example.test:8000\n",
            probe=lambda _proxy, _url: "203.0.113.44",
            chatgpt_probe=lambda _proxy: 403,
            check_chatgpt=True,
        )
        self.assertEqual(bindings[0].exit_ip, "203.0.113.44")
        self.assertNotIn("secret", bindings[0].masked)

    def test_chatgpt_login_probe_uses_same_proxy_and_disables_environment_proxy(self):
        calls = {}

        class FakeSession:
            def __init__(self, **kwargs):
                calls["init"] = kwargs
                self.proxies = {}
                self.trust_env = True

            def get(self, url, **kwargs):
                calls["get"] = (url, kwargs, dict(self.proxies), self.trust_env)
                return SimpleNamespace(status_code=200)

            def close(self):
                calls["closed"] = True

        curl_module = ModuleType("curl_cffi")
        curl_module.requests = SimpleNamespace(Session=FakeSession)
        with patch.dict(sys.modules, {"curl_cffi": curl_module}):
            self.assertEqual(
                StructuredFreeProxyPool._chatgpt_login_probe("socks5h://proxy.test:8000"),
                200,
            )
        self.assertEqual(calls["init"], {"impersonate": "chrome146", "verify": True})
        self.assertEqual(calls["get"][0], "https://chatgpt.com/login")
        self.assertEqual(calls["get"][2], {
            "http": "socks5h://proxy.test:8000",
            "https": "socks5h://proxy.test:8000",
        })
        self.assertFalse(calls["get"][3])
        self.assertTrue(calls["closed"])

    def test_proxy_probe_migrates_legacy_ipinfo_text_target(self):
        calls = []

        class FakeSession:
            def __init__(self, **_kwargs):
                self.proxies = {}

            def get(self, url, **_kwargs):
                calls.append(url)
                return SimpleNamespace(status_code=200, content=b"203.0.113.42")

            def close(self):
                pass

        curl_module = ModuleType("curl_cffi")
        curl_module.requests = SimpleNamespace(Session=FakeSession)
        with patch.dict(sys.modules, {"curl_cffi": curl_module}):
            self.assertEqual(
                StructuredFreeProxyPool._probe("socks5h://proxy.test:8000", "https://ipinfo.io/ip"),
                "203.0.113.42",
            )
        self.assertEqual(calls, ["https://api.ipify.org"])

    def test_legacy_ipinfo_probe_url_is_preserved_by_free_config(self):
        store = FreeConfigStore(self.data_dir)
        normalized = store.normalize({"proxy_probe_url": "https://ipinfo.io/json"})
        self.assertEqual(normalized["proxy_probe_url"], "https://ipinfo.io/json")

    def test_legacy_ipinfo_text_default_is_migrated_to_stable_probe(self):
        store = FreeConfigStore(self.data_dir)
        normalized = store.normalize({"proxy_probe_url": "https://ipinfo.io/ip"})
        self.assertEqual(normalized["proxy_probe_url"], "https://api.ipify.org")

    def test_probe_url_normalization_keeps_explicit_query_and_custom_hosts(self):
        store = FreeConfigStore(self.data_dir)
        self.assertEqual(
            store.normalize({"proxy_probe_url": "https://ipinfo.io/ip?token=custom"})["proxy_probe_url"],
            "https://ipinfo.io/ip?token=custom",
        )
        self.assertEqual(
            store.normalize({"proxy_probe_url": "https://probe.example.test/ip"})["proxy_probe_url"],
            "https://probe.example.test/ip",
        )

    def test_structured_free_proxy_pool_tracks_country_group_scheme_and_migrates_legacy(self):
        legacy = self.data_dir / "free_proxy_pool.txt"
        legacy.write_text("proxy-region-US.example:3000:user:pass\n", encoding="utf-8")
        pool = StructuredFreeProxyPool(self.data_dir)
        self.assertEqual(pool.records()[0]["country"], "")
        self.assertTrue((self.data_dir / "free_proxy_pool.json").exists())
        pool.import_text("socks5://user:pass@proxy-region-US.example:3000\n", country="US", group="住宅 A")
        public = pool.public()
        self.assertEqual(public["count"], 1)
        self.assertEqual(public["rows"][0]["scheme"], "socks5")
        self.assertEqual(public["rows"][0]["group"], "")
        self.assertNotIn("pass", str(public))

    def test_structured_proxy_pool_filters_roxy_compatible_groups_and_quarantines_failures(self):
        pool = StructuredFreeProxyPool(self.data_dir, failure_threshold=2, quarantine_seconds=600)
        pool.import_text(
            "socks4://user:pass@proxy-region-US.example:3000\n"
            "socks5://user:pass@proxy-region-US.example:3001\n",
            country="US", group="住宅 A",
        )
        self.assertEqual(len(pool.records(driver="roxybrowser")), 1)
        proxy_id = pool.records(driver="roxybrowser")[0]["proxy_id"]
        pool.record_failure(proxy_id, node_code="free_roxy_open", message="连接失败")
        pool.record_failure(proxy_id, node_code="free_roxy_open", message="连接失败")
        self.assertEqual(pool.records(driver="roxybrowser"), [])
        self.assertEqual(pool.public()["groups"][0]["quarantined"], 1)

    def test_pasted_proxy_preflight_honors_country_group_and_roxy_protocol(self):
        manager = FreeRegisterManager(
            self.data_dir,
            proxy_probe=lambda proxy, _url: "203.0.113.50" if "proxy-region-US" in proxy else "203.0.113.51",
        )
        shared = manager.preflight_proxies(
            proxy_content="socks4://proxy-region-US.example:3000\nsocks5://proxy-region-US.example:3001\n",
            driver="roxybrowser",
            country="US",
            group="住宅 A",
        )
        self.assertEqual(shared["proxies"], 2)
        self.assertEqual(shared["exit_ips"], 1)
        result = manager.preflight_proxies(
            proxy_content="socks5://proxy-region-US.example:3001\n",
            driver="roxybrowser",
            country="US",
            group="住宅 A",
        )
        self.assertEqual(result["rows"][0]["scheme"], "socks5")
        self.assertNotIn("country", result["rows"][0])
        self.assertNotIn("group", result["rows"][0])

    def test_proxy_health_only_changes_for_proxy_and_exit_ip_failures(self):
        manager = FreeRegisterManager(self.data_dir)
        manager.proxies.import_text("http://proxy-a.test:8000\n")
        proxy_id = manager.proxies.public()["rows"][0]["proxy_id"]
        task = {"task_id": "free-task", "proxy_id": proxy_id}
        manager._tasks["free-task"] = dict(task)

        manager._record_proxy_failure(
            task,
            FreeRegisterError("free_roxy_signup_email_submit", "提交 Free 注册邮箱", "页面未进入下一步"),
        )
        self.assertEqual(manager.proxies.public()["rows"][0]["consecutive_failures"], 0)

        manager._record_proxy_failure(task, FreeRegisterError("free_proxy_drift", "校验 Free 代理出口", "固定代理出口发生变化"))
        proxy = manager.proxies.public()["rows"][0]
        self.assertEqual(proxy["consecutive_failures"], 0)
        self.assertEqual(proxy["status"], "unknown")

    def test_start_with_pasted_proxy_persists_exit_ip_before_worker_progress(self):
        worker_entered = threading.Event()
        release_worker = threading.Event()

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            worker_entered.set()
            release_worker.wait(2)
            return {"access_token": "token-private", "twofa_status": "enabled"}

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.76",
        )
        manager.start(
            {"target_count": 1, "concurrency": 1},
            pool_content="a@example.test----https://mail.example.test/a\n",
            proxy_content="http://proxy-a.test:8000\n",
        )
        self.assertTrue(worker_entered.wait(1))
        proxy = manager.proxies.public()["rows"][0]
        self.assertEqual(proxy["last_exit_ip"], "203.0.113.76")
        self.assertEqual(proxy["status"], "available")
        release_worker.set()
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(manager.public_state()["running"])

    def test_mailbox_otp_provider_separates_registration_and_mailbox_proxies(self):
        from mac_overrides.free_register_runtime import MailboxUrlOtpProvider
        from mac_overrides.mailbox_url_runtime import MailboxResponse

        provider = MailboxUrlOtpProvider(
            "https://mail.example.test/pickup",
            "socks5h://user:pass@proxy.example.test:3000",
            timeout=10,
            fetcher=lambda url: MailboxResponse(url, b"[]", "application/json", 200),
        )

        self.assertTrue(callable(provider.client.fetcher))
        self.assertEqual(provider.registration_proxy, "socks5h://user:pass@proxy.example.test:3000")
        self.assertEqual(provider.client.proxy, "http://127.0.0.1:7897")
        self.assertFalse(provider.state.active)
        provider.prepare()
        self.assertTrue(provider.state.active)
        provider.close()

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
        self.assertEqual({row[1] for row in seen}, {"a@example.test", "b@example.test"})
        self.assertTrue({row[2] for row in seen} <= {"http://proxy-a.test:8000", "http://proxy-b.test:8000"})
        self.assertEqual({row[0] for row in seen}, {1, 2})
        public = manager.public_tasks()
        self.assertTrue(all("token-" not in str(row) for row in public))
        self.assertTrue(all(FIXED_PASSWORD not in str(row) for row in public))
        self.assertEqual(manager.secret([public[0]["task_id"]], "token"), "token-1")
        detail_logs = [row for row in manager.public_logs() if "当前账号已进入 Token 节点" in row["message"]]
        self.assertEqual({row["task_id"] for row in detail_logs}, {row["task_id"] for row in public})
        self.assertTrue(all(row["stage"] == "free_access_token" for row in detail_logs))

    def test_pre_registration_roxy_failure_restores_mailbox_but_keeps_failed_task(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-a.test:8000\n")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            raise FreeRegisterError(
                "free_roxy_connect", "连接 RoxyBrowser", "缺少 Selenium 连接地址"
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.20",
        )
        manager.start({"driver": "roxybrowser", "target_count": 1, "proxy_retry_count": 0})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "failed")
        self.assertEqual(task["failure"]["node_code"], "free_roxy_connect")
        self.assertEqual(mailbox["status"], "available")
        self.assertEqual(mailbox["proxy_masked"], "")
        self.assertEqual(manager.public_state()["pool"]["available"], 1)
        self.assertTrue(any(row["stage"] == "free_mailbox_released" for row in manager.public_logs(task["task_id"])))

    def test_non_network_roxy_failure_never_switches_registration_proxy(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        FreeProxyPool(self.data_dir).import_text(
            "http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n"
        )
        attempts = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            attempts.append(task["proxy_id"])
            raise FreeRegisterError(
                "free_roxy_connect", "连接 RoxyBrowser", "缺少 Roxy ChromeDriver 路径",
                error_code="free_roxy_driver_unavailable",
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda proxy, _url: "203.0.113." + ("20" if "proxy-a" in proxy else "21"),
        )
        manager.start({"driver": "roxybrowser", "target_count": 1, "proxy_retry_count": 3})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(len(attempts), 1)
        task = manager.public_tasks()[0]
        self.assertEqual(task["failure"]["error_code"], "free_roxy_driver_unavailable")
        self.assertFalse(any(row.get("outcome") == "switched" for row in task["proxy_attempts"]))

    def test_failure_after_email_submission_does_not_restore_mailbox(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-a.test:8000\n")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            raise FreeRegisterError(
                "free_roxy_signup_email_submit", "提交 Free 注册邮箱", "页面未进入下一步"
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.21",
        )
        manager.start({"driver": "roxybrowser", "target_count": 1})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(manager.public_tasks()[0]["status"], "failed")
        self.assertEqual(manager.pool.public_rows()[0]["status"], "pending_rerun")
        self.assertEqual(manager.public_state()["pool"]["available"], 0)
        retry = manager.rerun(manager.public_tasks()[0]["task_id"], {"target_count": 1})
        self.assertTrue(retry["batch_id"])
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(manager.public_state()["running"])

    def test_pre_email_rate_limit_restores_mailbox_for_retry(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-a.test:8000\n")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            raise FreeRegisterError(
                "free_email_identifier", "识别 Free 注册邮箱",
                "邮箱识别被服务端限流",
                provider_status=429,
                provider_code="rate_limit_exceeded",
                error_code="free_email_identifier_failed",
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.22",
        )
        manager.start({"driver": "protocol", "target_count": 1})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["failure"]["error_code"], "free_email_identifier_failed")
        self.assertEqual(mailbox["status"], "available")
        self.assertEqual(mailbox["failure"]["error_code"], "free_email_identifier_failed")

    def test_public_tasks_group_newest_batch_before_older_batch(self):
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks = {
            "old-2": {"task_id": "old-2", "batch_id": "old", "created_at": 100, "ordinal": 2},
            "new-2": {"task_id": "new-2", "batch_id": "new", "created_at": 200, "ordinal": 2},
            "old-1": {"task_id": "old-1", "batch_id": "old", "created_at": 100, "ordinal": 1},
            "new-1": {"task_id": "new-1", "batch_id": "new", "created_at": 200, "ordinal": 1},
        }
        self.assertEqual(
            [task["task_id"] for task in manager.public_tasks()],
            ["new-1", "new-2", "old-1", "old-2"],
        )

    def test_delete_terminal_task_history_preserves_mailbox_and_removes_task_log(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks = {
            "free-terminal": {"task_id": "free-terminal", "status": "failed", "email": "a@example.test"},
            "free-active": {"task_id": "free-active", "status": "running", "email": "b@example.test"},
        }
        manager.task_store.save(manager._tasks)
        manager._task_log("free-terminal", "终态任务日志")
        deleted = manager.delete_tasks(["free-terminal"])
        self.assertEqual(deleted, 1)
        self.assertNotIn("free-terminal", manager.task_store.load())
        self.assertEqual(manager.public_logs("free-terminal"), [])
        self.assertEqual(manager.pool.public_rows()[0]["email"], "a@example.test")

    def test_delete_tasks_rejects_queued_or_running_history_atomically(self):
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks = {
            "free-done": {"task_id": "free-done", "status": "failed"},
            "free-running": {"task_id": "free-running", "status": "running"},
        }
        manager.task_store.save(manager._tasks)
        with self.assertRaises(ValueError):
            manager.delete_tasks(["free-done", "free-running"])
        self.assertEqual(set(manager.task_store.load()), {"free-done", "free-running"})

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
        # A worker marks its task terminal just before its Future callback
        # flushes the final task snapshot.  Wait for that callback too, so
        # TemporaryDirectory cleanup cannot race an in-flight atomic write.
        while manager._executor is not None and time.time() < deadline:
            time.sleep(0.01)

        self.assertCountEqual(seen, ["a@example.test", "b@example.test"])
        self.assertIsNone(manager._executor)

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

    def test_twofa_result_failure_is_persisted_as_structured_task_failure(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\n")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            return {
                "access_token": "token-private",
                "password": FIXED_PASSWORD,
                "twofa_status": "pending",
                "twofa_error": "激活超时",
                "twofa_failure": {
                    "node_code": "free_twofa_activate",
                    "node_label": "激活 Free 账号 2FA",
                    "error_code": "free_twofa_activate_timeout",
                    "public_message": "激活 Free 账号 2FA [激活 Free 账号 2FA/free_twofa_activate]：激活超时",
                    "technical_summary": "激活超时",
                    "retryable": True,
                    "http_status": 504,
                },
            }

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.40",
        )
        manager.start({"target_count": 1})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        task = manager.public_tasks()[0]
        self.assertEqual(task["status"], "twofa_pending")
        self.assertEqual(task["failure"]["error_code"], "free_twofa_activate_timeout")
        self.assertEqual(task["failure"]["http_status"], 504)
        self.assertNotIn("token-private", str(task))

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

    def test_failed_existing_account_twofa_retry_does_not_invent_password(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("existing@example.test----https://mail.example.test/a\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-a.test:8000\n")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            if not twofa_retry:
                return {
                    "access_token": "token-private", "account_flow": "existing_login",
                    "twofa_status": "pending",
                }
            raise FreeTwoFaPending(
                "activate timeout", token="fresh-token", plan_type="free",
                plus_trial_eligible=False,
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.22",
        )
        manager.start({"target_count": 1})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        manager.retry_twofa(manager.public_tasks()[0]["task_id"], {})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        self.assertFalse(task["result"]["has_password"])
        self.assertEqual(manager.secret([task["task_id"]], "password"), "")
        saved = manager.task_store.load()[task["task_id"]]["result"]
        self.assertNotIn("password", saved)
        self.assertEqual(saved["access_token"], "fresh-token")
        self.assertEqual(saved["twofa_failure"], saved["failure"])

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

    def test_legacy_log_callback_hides_mailbox_url_path(self):
        logs = []
        manager = FreeRegisterManager(self.data_dir, log_fn=lambda message, level: logs.append((message, level)))
        manager._log("邮箱取件失败：https://mail.test/inbox/tenant/private-message?token=mail-private")

        serialized = str(logs)
        self.assertNotIn("/inbox/tenant/private-message", serialized)
        self.assertNotIn("mail-private", serialized)
        self.assertIn("https://mail.test/[路径已隐藏]", serialized)


if __name__ == "__main__":
    unittest.main()
