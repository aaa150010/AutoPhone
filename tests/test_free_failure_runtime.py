from __future__ import annotations

from pathlib import Path
import tempfile
import time
import unittest

from mac_overrides.free_failure_runtime import canonical_failure, first_failure, sanitize_failure_text
from mac_overrides.free_log_runtime import FreeLogStore
from mac_overrides.free_register_common import (
    FIXED_PASSWORD,
    FreeRegisterError,
    fingerprint,
    safe_log_message,
)
from mac_overrides.free_register_runtime import FreeMailboxPool, FreeProxyPool, FreeRegisterManager
from mac_overrides.free_register_store import FreeTaskStore


class FreeFailureRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-free-failure-")
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _wait(self, manager: FreeRegisterManager) -> None:
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(manager.public_state()["running"])

    def test_canonical_failure_redacts_all_public_credentials(self) -> None:
        raw = {
            "node_code": "free_oauth_callback",
            "node_label": "Free OAuth 回调",
            "error_code": "callback_timeout",
            "public_message": (
                "回调失败 socks5://user:pass@proxy.test:3000 "
                "user-a:pass-a@proxy-a.test:3001 "
                "proxy-b.test:3002@user-b:pass-b "
                "proxy-c.test:3003:user-c:pass-c "
                "https://mail.test/private-pickup?token=mail-secret "
                "wss://debug:secret@127.0.0.1/devtools/private "
                f"password={FIXED_PASSWORD} otp_code=123456 state=oauth-state "
                "proxy_username=proxy-user a@example.test +15551234567"
            ),
            "technical_summary": "access_token=token-private mailbox_key=mail-key",
            "retryable": "false",
            "http_status": "504",
            "provider_code": "callback_timeout",
            "action_hint": "打开 https://auth.test/callback?code=oauth-private 检查",
            "page_type": "email_otp",
            "safe_page": "https://user:pass@auth.openai.com/log-in/otp?code=123456#secret",
            "content_type": "text/html; token=content-secret",
            "session_rebuilds": "2",
            "raw_body": "must-not-be-copied",
        }

        failure = canonical_failure(raw)

        self.assertIsNotNone(failure)
        assert failure is not None
        rendered = str(failure)
        for secret in (
            "user:pass", "private-pickup", "mail-secret", "debug:secret",
            "user-a", "pass-a", "user-b", "pass-b", "user-c", "pass-c",
            "devtools/private", FIXED_PASSWORD, "123456", "oauth-state",
            "token-private", "mail-key", "oauth-private", "must-not-be-copied",
            "proxy-user", "a@example.test", "+15551234567", "content-secret",
        ):
            self.assertNotIn(secret, rendered)
        self.assertEqual(failure["http_status"], 504)
        self.assertFalse(failure["retryable"])
        self.assertEqual(failure["node_code"], "free_oauth_callback")
        self.assertIn("[Free OAuth 回调/free_oauth_callback]", failure["public_message"])
        self.assertEqual(failure["page_type"], "email_otp")
        self.assertEqual(failure["safe_page"], "https://auth.openai.com/log-in/otp")
        self.assertEqual(failure["content_type"], "text/html; token=********")
        self.assertEqual(failure["session_rebuilds"], 2)

    def test_safe_log_message_redacts_every_supported_proxy_auth_layout(self) -> None:
        rendered = safe_log_message(
            "socks5://scheme-user:scheme-pass@proxy.test:3000 "
            "host-a.test:3001:host-user:host-pass "
            "at-user:at-pass@host-b.test:3002 "
            "host-c.test:3003@tail-user:tail-pass"
        )

        for secret in (
            "scheme-user", "scheme-pass", "host-user", "host-pass",
            "at-user", "at-pass", "tail-user", "tail-pass",
        ):
            self.assertNotIn(secret, rendered)

    def test_safe_log_message_redacts_generic_token_assignment(self) -> None:
        rendered = safe_log_message(
            "reader failed token=private-value; plain token wording remains"
        )

        self.assertEqual(
            rendered,
            "reader failed token=********; plain token wording remains",
        )

    def test_sanitizer_preserves_generated_incident_id_dates(self) -> None:
        rendered = sanitize_failure_text(
            "日志 LOG-20260827-29G56LXV 需要稍后重试，手机号 +15551234567 仍需隐藏",
        )

        self.assertIn("LOG-20260827-29G56LXV", rendered)
        self.assertIn("<手机号>", rendered)
        self.assertNotIn("LOG-<手机号>-29G56LXV", rendered)
        self.assertEqual(sanitize_failure_text("phone-15551234567"), "phone-<手机号>")

    def test_proxy_bind_explains_quarantined_saved_pool(self) -> None:
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("proxy.example.test:8000\n")
        proxy_id = proxies.entries()[0]["proxy_id"]
        proxies.record_failure(
            proxy_id,
            node_code="proxy_connect_failed",
            message="代理探测请求返回 HTTP 403",
            threshold=1,
        )

        with self.assertRaises(FreeRegisterError) as raised:
            proxies.bind(1, perform_probe=False)

        error = raised.exception
        self.assertEqual(error.error_code, "free_proxy_pool_empty")
        self.assertTrue(error.retryable)
        self.assertIn("有 1 条记录", str(error))
        self.assertIn("可分配健康代理为 0 条", str(error))
        self.assertIn("已隔离 1 条", str(error))
        self.assertIn("proxy_connect_failed", str(error))

    def test_safe_page_hides_third_party_paths_and_non_page_addresses(self) -> None:
        hidden = canonical_failure({
            "node_code": "free_roxy_connect",
            "safe_page": "https://user:pass@example.test/private/123456?token=secret#fragment",
        })
        websocket = canonical_failure({
            "node_code": "free_roxy_connect",
            "safe_page": "wss://user:pass@127.0.0.1/devtools/browser/secret",
        })

        assert hidden is not None and websocket is not None
        self.assertEqual(hidden["safe_page"], "https://example.test/[路径已隐藏]")
        self.assertEqual(websocket["safe_page"], "[非页面地址已隐藏]")

    def test_first_business_failure_wins_over_cleanup_failure(self) -> None:
        business = canonical_failure({
            "node_code": "free_email_otp_wait",
            "node_label": "等待 Free 邮箱验证码",
            "error_code": "otp_timeout",
            "public_message": "验证码等待超时",
            "technical_summary": "三轮取件均无新邮件",
            "retryable": True,
        })
        cleanup = {
            "node_code": "free_roxy_cleanup",
            "node_label": "清理 RoxyBrowser 环境",
            "error_code": "cleanup_failed",
            "public_message": "Profile 删除失败",
            "technical_summary": "timeout",
            "retryable": True,
        }

        self.assertEqual(first_failure(business, cleanup), business)

    def test_terminal_failure_has_one_identity_in_task_result_mailbox_and_restart(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/private?key=mail-secret\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-user:proxy-pass@proxy.test:8000\n")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            raise FreeRegisterError(
                "free_email_otp_wait",
                "等待 Free 邮箱验证码",
                "等待超时 otp_code=123456 mailbox_url=https://mail.example.test/private?key=mail-secret",
                provider_status=504,
                provider_code="otp_timeout",
                action_hint="检查 mailbox_key=mail-secret 后重试",
                page_type="email_otp",
                safe_page="https://auth.openai.com/email-verification?otp_code=123456#private",
                content_type="application/json; mailbox_key=mail-secret",
                session_rebuilds=1,
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.40",
        )
        manager.start({"target_count": 1})
        self._wait(manager)

        task = manager.public_tasks()[0]
        row_id = manager.pool.entries()[0].row_id
        result = manager.pool.result(row_id)
        mailbox = manager.pool.public_rows()[0]
        self.assertTrue((manager.pool.results_dir / f"{fingerprint(row_id)}.json").exists())
        self.assertEqual(task["failure"], result["failure"])
        self.assertEqual(task["failure"], mailbox["failure"])
        self.assertEqual(mailbox["error"], task["failure"]["public_message"])
        self.assertNotIn("123456", str(task["failure"]))
        self.assertNotIn("mail-secret", str(task["failure"]))
        self.assertEqual(task["failure"]["page_type"], "email_otp")
        self.assertEqual(task["failure"]["safe_page"], "https://auth.openai.com/email-verification")
        self.assertEqual(task["failure"]["content_type"], "application/json; mailbox_key=********")
        self.assertEqual(task["failure"]["session_rebuilds"], 1)

        restarted = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.40",
        )
        self.assertEqual(restarted.public_tasks()[0]["failure"], task["failure"])
        self.assertEqual(restarted.pool.public_rows()[0]["failure"], task["failure"])

        cleanup = {
            "node_code": "free_roxy_cleanup",
            "node_label": "清理 RoxyBrowser 环境",
            "error_code": "cleanup_failed",
            "public_message": "清理失败",
            "technical_summary": "timeout",
            "retryable": True,
        }
        internal = restarted._tasks[task["task_id"]]
        kept, _ = restarted._persist_task_failure(
            task["task_id"], internal, status="failed", failure=cleanup,
        )
        self.assertEqual(kept["node_code"], "free_email_otp_wait")
        self.assertEqual(restarted.pool.result(row_id)["failure"], kept)

    def test_unexpected_error_keeps_current_stage_and_safe_diagnostic(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy.test:8000\n")

        def runner(task, _config, _stop, stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            stage(task["task_id"], "free_email_otp_wait")
            raise RuntimeError(
                "取件解析失败 mailbox_key=mail-private "
                "at-user:at-pass@proxy.test:3000"
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.60",
        )
        manager.start({"target_count": 1})
        self._wait(manager)

        task = manager.public_tasks()[0]
        row_id = manager.pool.entries()[0].row_id
        result = manager.pool.result(row_id)
        mailbox = manager.pool.public_rows()[0]
        failure = task["failure"]
        self.assertEqual(failure["node_code"], "free_email_otp_wait")
        self.assertEqual(failure["node_label"], "等待 Free 邮箱验证码")
        self.assertIn("取件解析失败", failure["technical_summary"])
        self.assertTrue(failure["action_hint"])
        self.assertEqual(failure, result["failure"])
        self.assertEqual(failure, mailbox["failure"])
        self.assertEqual(mailbox["status"], "pending_rerun")
        self.assertEqual(manager.proxies.public()["rows"][0]["consecutive_failures"], 0)
        rendered = str({"task": task, "result": result, "mailbox": mailbox})
        for secret in ("mail-private", "at-user", "at-pass"):
            self.assertNotIn(secret, rendered)

    def test_log_context_is_redacted_and_survives_reload(self) -> None:
        store = FreeLogStore(self.data_dir)
        store.add(
            "OTP 请求失败 password=private-value",
            "error",
            task_id="free-log-context",
            node_code="free_email_otp_submit",
            node_label="提交 Free 邮箱验证码",
            page_type="email_otp",
            safe_page="https://user:pass@auth.openai.com/email-verification?code=123456#private",
            content_type="application/json; token=content-secret",
            session_rebuilds="1",
        )

        reloaded = FreeLogStore(self.data_dir).snapshot("free-log-context")

        self.assertEqual(len(reloaded), 1)
        row = reloaded[0]
        self.assertEqual(row["page_type"], "email_otp")
        self.assertEqual(row["safe_page"], "https://auth.openai.com/email-verification")
        self.assertEqual(row["content_type"], "application/json; token=********")
        self.assertEqual(row["session_rebuilds"], 1)
        persisted = (self.data_dir / "logs.json").read_text(encoding="utf-8")
        task_persisted = next((self.data_dir / "task_logs").glob("*.json")).read_text(encoding="utf-8")
        for secret in ("private-value", "user:pass", "123456", "content-secret"):
            self.assertNotIn(secret, persisted)
            self.assertNotIn(secret, task_persisted)

    def test_clear_logs_removes_global_and_per_task_history(self) -> None:
        store = FreeLogStore(self.data_dir)
        store.add("第一条", task_id="free-clear-a")
        store.add("第二条", task_id="free-clear-b")
        self.assertEqual(len(list((self.data_dir / "task_logs").glob("*.json"))), 2)

        store.clear()

        self.assertEqual(store.snapshot(), [])
        self.assertEqual(store.snapshot("free-clear-a"), [])
        self.assertEqual(store.snapshot("free-clear-b"), [])
        self.assertEqual(list((self.data_dir / "task_logs").glob("*.json")), [])

    def test_lifecycle_log_keeps_iso_time_and_resolves_two_part_node_label(self) -> None:
        store = FreeLogStore(self.data_dir)

        store.add("[free-lifecycle/free_oauth_session] 开始")
        store.add("[启动 Free 注册/free_run_start] 已开始")

        row = store.snapshot("free-lifecycle")[0]
        self.assertRegex(
            row["time"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$",
        )
        self.assertEqual(row["node_code"], "free_oauth_session")
        self.assertEqual(row["node_label"], "Free OAuth 会话")
        self.assertEqual(row["stage_label"], "Free OAuth 会话")
        global_row = store.snapshot()[1]
        self.assertEqual(global_row["task_id"], "")
        self.assertEqual(global_row["node_code"], "free_run_start")
        self.assertEqual(global_row["node_label"], "启动 Free 注册")
        self.assertEqual(global_row["stage_label"], "启动 Free 注册")

    def test_legacy_public_task_and_mailbox_diagnostics_are_redacted(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row = pool.entries()[0]
        private_proxy = "legacy-user:legacy-pass@proxy.test:3000"
        pool.update(row.row_id, status="twofa_pending", proxy_masked=private_proxy)
        pool.save_result(row.row_id, {
            "status": "twofa_pending",
            "twofa_status": "pending",
            "twofa_error": f"激活失败 {private_proxy} token=legacy-token",
            "profile_summary": f"旧摘要 {private_proxy}",
        })
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.61",
        )
        manager._tasks = {
            "free-legacy-public": {
                "task_id": "free-legacy-public",
                "status": "failed",
                "profile_summary": f"旧摘要 {private_proxy}",
                "proxy_masked": private_proxy,
                "proxy_attempts": [{
                    "proxy_id": "legacy-proxy",
                    "stage": "free_proxy_binding",
                    "message": f"连接失败 {private_proxy}",
                    "unknown_secret": "must-not-publish",
                }],
                "result": {
                    "twofa_status": "pending",
                    "twofa_error": f"激活失败 {private_proxy} password=legacy-password",
                },
            }
        }

        rendered = str({
            "tasks": manager.public_tasks(),
            "mailboxes": manager.pool.public_rows(),
        })
        for secret in (
            "legacy-user", "legacy-pass", "legacy-token",
            "legacy-password", "must-not-publish",
        ):
            self.assertNotIn(secret, rendered)

    def test_interrupted_task_writes_recovery_failure_result(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row = pool.entries()[0]
        pool.update(row.row_id, status="running", task_id="free-interrupted")
        FreeTaskStore(self.data_dir).save({
            "free-interrupted": {
                "task_id": "free-interrupted",
                "row_id": row.row_id,
                "status": "running",
                "driver": "protocol",
                "created_at": 1,
                "updated_at": 1,
                "progress": {"stage": "free_email_otp_wait", "started_at": 1},
            }
        })

        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.41",
        )

        task = manager.public_tasks()[0]
        result = manager.pool.result(row.row_id)
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "failed")
        self.assertEqual(task["failure"]["node_code"], "free_process_recovery")
        self.assertEqual(task["failure"], result["failure"])
        self.assertEqual(task["failure"], mailbox["failure"])

    def test_stopping_queued_task_writes_structured_result(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row = pool.entries()[0]
        pool.update(row.row_id, status="queued", batch_id="free-batch")
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.42",
        )
        manager._batch_id = "free-batch"
        manager._tasks = {
            "free-queued": {
                "task_id": "free-queued",
                "row_id": row.row_id,
                "batch_id": "free-batch",
                "status": "queued",
                "driver": "protocol",
                "progress": {"stage": "free_proxy_binding", "started_at": 1},
            }
        }

        manager.stop()

        task = manager.public_tasks()[0]
        result = manager.pool.result(row.row_id)
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "stopped")
        self.assertEqual(task["failure"]["node_code"], "free_run_stop")
        self.assertEqual(task["failure"], result["failure"])
        self.assertEqual(task["failure"], mailbox["failure"])

    def test_new_reservation_does_not_publish_previous_attempt_failure(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row = pool.entries()[0]
        previous = {
            "node_code": "free_roxy_connect",
            "node_label": "连接 RoxyBrowser",
            "error_code": "free_roxy_connect_failed",
            "public_message": "上一次连接失败",
            "technical_summary": "timeout",
            "retryable": True,
        }
        pool.update(
            row.row_id,
            status="available",
            failure=previous,
            error="上一次连接失败",
        )
        pool.save_result(row.row_id, {"status": "failed", "failure": previous})

        pool.reserve([row], "free-new-batch")

        public = pool.public_rows()[0]
        self.assertEqual(public["status"], "reserved")
        self.assertIsNone(public["failure"])
        self.assertEqual(public["error"], "")

    def test_post_registration_proxy_observation_is_removed_from_success_path(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy.test:8000\n")
        probe_calls = 0

        def probe(_proxy: str, _url: str) -> str:
            nonlocal probe_calls
            probe_calls += 1
            if probe_calls >= 3:
                raise TimeoutError("post-registration probe timeout")
            return "203.0.113.50"

        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {
                "access_token": "token-private",
                "twofa_status": "enabled",
            },
            proxy_probe=probe,
        )
        manager.start({"target_count": 1})
        self._wait(manager)

        task = manager.public_tasks()[0]
        row_id = manager.pool.entries()[0].row_id
        result = manager.pool.result(row_id)
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "success")
        self.assertEqual(result["status"], "success")
        self.assertEqual(mailbox["status"], "success")
        self.assertNotIn("failure", task)
        self.assertNotIn("failure", result)
        self.assertIsNone(mailbox["failure"])
        self.assertTrue(task["result"]["has_access_token"])
        self.assertEqual(manager.secret([task["task_id"]], "token"), "token-private")
        self.assertEqual(manager.proxies.public()["rows"][0]["consecutive_failures"], 0)

    def test_twofa_pending_stays_primary_when_post_registration_probe_fails(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy.test:8000\n")
        probe_calls = 0

        def probe(_proxy: str, _url: str) -> str:
            nonlocal probe_calls
            probe_calls += 1
            if probe_calls >= 3:
                raise TimeoutError("post-registration probe timeout")
            return "203.0.113.54"

        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {
                "access_token": "token-private",
                "twofa_status": "pending",
                "twofa_error": "激活超时",
                "twofa_failure": {
                    "node_code": "free_twofa_activate",
                    "node_label": "激活 Free 账号 2FA",
                    "error_code": "free_twofa_activate_timeout",
                    "technical_summary": "激活超时",
                    "retryable": False,
                },
            },
            proxy_probe=probe,
        )
        manager.start({"target_count": 1})
        self._wait(manager)

        task = manager.public_tasks()[0]
        row_id = manager.pool.entries()[0].row_id
        result = manager.pool.result(row_id)
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "twofa_pending")
        self.assertEqual(result["status"], "twofa_pending")
        self.assertEqual(mailbox["status"], "twofa_pending")
        self.assertEqual(task["failure"]["node_code"], "free_twofa_activate")
        self.assertTrue(task["failure"]["retryable"])
        self.assertEqual(task["failure"], result["failure"])
        self.assertEqual(task["failure"], mailbox["failure"])
        self.assertNotIn("post_registration_failure", result)

        restarted = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.54",
        )
        restarted_result = restarted.pool.result(row_id)
        self.assertEqual(restarted.public_tasks()[0]["status"], "twofa_pending")
        self.assertNotIn("post_registration_failure", restarted_result)

    def test_successful_twofa_retry_removes_previous_failure_everywhere(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy.test:8000\n")
        attempts = 0

        def runner(*_args, twofa_retry=False, **_kwargs):
            nonlocal attempts
            attempts += 1
            if not twofa_retry:
                return {
                    "access_token": "token-private",
                    "twofa_status": "pending",
                    "twofa_error": "激活超时",
                    "twofa_failure": {
                        "node_code": "free_twofa_activate",
                        "node_label": "激活 Free 账号 2FA",
                        "error_code": "free_twofa_activate_timeout",
                        "technical_summary": "激活超时",
                        "retryable": True,
                    },
                }
            return {
                "access_token": "token-private",
                "twofa_status": "enabled",
                "totp_secret": "JBSWY3DPEHPK3PXP",
            }

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.51",
        )
        manager.start({"target_count": 1})
        self._wait(manager)
        pending = manager.public_tasks()[0]
        self.assertEqual(pending["status"], "twofa_pending")
        self.assertIn("failure", pending)

        manager.retry_twofa(pending["task_id"], {})
        self._wait(manager)

        task = manager.public_tasks()[0]
        row_id = manager.pool.entries()[0].row_id
        result = manager.pool.result(row_id)
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(attempts, 2)
        self.assertEqual(task["status"], "success")
        self.assertNotIn("failure", task)
        self.assertNotIn("failure", result)
        self.assertNotIn("twofa_failure", result)
        self.assertNotIn("twofa_error", result)
        self.assertIsNone(mailbox["failure"])
        self.assertEqual(mailbox["error"], "")

    def test_plan_failure_identity_matches_task_mailbox_result_and_restart(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy.test:8000\n")
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {
                "access_token": "token-private",
                "twofa_status": "enabled",
                "plan_check_status": "failed",
                "plan_error_code": "free_plan_accounts_unavailable",
                "plan_http_status": 503,
                "plan_error_detail": "套餐接口暂时不可用 mailbox_key=plan-private",
            },
            proxy_probe=lambda _proxy, _url: "203.0.113.52",
        )
        manager.start({"target_count": 1})
        self._wait(manager)

        task = manager.public_tasks()[0]
        row_id = manager.pool.entries()[0].row_id
        result = manager.pool.result(row_id)
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "partial_success")
        self.assertEqual(task["failure"]["node_code"], "free_plan_check")
        self.assertEqual(task["failure"]["error_code"], "free_plan_accounts_unavailable")
        self.assertEqual(task["failure"]["http_status"], 503)
        self.assertEqual(task["failure"], result["failure"])
        self.assertEqual(task["failure"], mailbox["failure"])
        self.assertEqual(mailbox["plan_error_code"], "free_plan_accounts_unavailable")
        self.assertEqual(mailbox["plan_http_status"], 503)
        self.assertEqual(mailbox["plan_failure"], task["failure"])
        self.assertNotIn("plan-private", str(result))
        self.assertNotIn("plan_error_detail", result)

        restarted = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.52",
        )
        self.assertEqual(restarted.public_tasks()[0]["failure"], task["failure"])
        self.assertEqual(restarted.pool.public_rows()[0]["failure"], task["failure"])

    def test_success_result_drops_historical_failure_fields(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy.test:8000\n")
        old_failure = {
            "node_code": "free_twofa_activate",
            "node_label": "激活 Free 账号 2FA",
            "error_code": "old_failure",
            "technical_summary": "上一次失败",
            "retryable": True,
        }
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {
                "access_token": "token-private",
                "twofa_status": "enabled",
                "failure": old_failure,
                "twofa_failure": old_failure,
                "twofa_error": "上一次失败",
                "plan_check_status": "success",
                "plan_error_code": "stale_plan_error",
                "plan_http_status": 503,
                "plan_provider_code": "stale_provider_error",
                "plan_error": "历史套餐错误",
                "plan_error_detail": "历史套餐错误详情",
                "plan_failure": {
                    "node_code": "free_plan_check",
                    "technical_summary": "历史套餐失败",
                },
            },
            proxy_probe=lambda _proxy, _url: "203.0.113.53",
        )
        manager.start({"target_count": 1})
        self._wait(manager)

        task = manager.public_tasks()[0]
        result = manager.pool.result(manager.pool.entries()[0].row_id)
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "success")
        self.assertNotIn("failure", task)
        for key in (
            "failure", "twofa_failure", "twofa_error", "plan_failure",
            "plan_error", "plan_error_detail", "plan_error_code",
            "plan_http_status", "plan_provider_code",
        ):
            self.assertNotIn(key, result)
        self.assertIsNone(mailbox["failure"])
        self.assertEqual(mailbox["error"], "")


if __name__ == "__main__":
    unittest.main()
