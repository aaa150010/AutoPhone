from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

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
from mac_overrides.diagnostic_store import DiagnosticStore


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

    def test_safe_log_message_redacts_complete_authorization_header(self) -> None:
        rendered = safe_log_message(
            "Authorization: Basic abc123456789==; Authorization: Bearer bearer-secret"
        )
        self.assertNotIn("abc123456789", rendered)
        self.assertNotIn("bearer-secret", rendered)
        self.assertIn("Authorization:********", rendered)

    def test_sanitizers_redact_quoted_json_and_camel_case_secrets(self) -> None:
        raw = (
            '{"accessToken":"access-private", "refreshToken": "refresh-private", '
            '"idToken":"id-private", "adminToken":"admin-private", '
            '"csrfToken":"csrf-private", "totpSecret":"totp-private", '
            '"otpCode":"123456"}'
        )

        for rendered in (safe_log_message(raw), sanitize_failure_text(raw)):
            self.assertIn('"accessToken":"********"', rendered)
            self.assertIn('"refreshToken": "********"', rendered)
            self.assertIn('"csrfToken":"********"', rendered)
            for secret in (
                "access-private", "refresh-private", "id-private", "admin-private",
                "csrf-private", "totp-private", "123456",
            ):
                self.assertNotIn(secret, rendered)

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

    def test_task_failure_persistence_outage_does_not_raise_or_skip_result(self) -> None:
        manager = FreeRegisterManager(self.data_dir)
        task = {"task_id": "persist-outage", "status": "running"}
        manager._tasks[task["task_id"]] = dict(task)

        with patch.object(manager.task_store, "save", side_effect=OSError("disk full")):
            failure, payload = manager._persist_task_failure(
                task["task_id"],
                task,
                status="failed",
                failure={
                    "node_code": "free_proxy_connect",
                    "node_label": "代理连接",
                    "error_code": "proxy_connect_failed",
                    "technical_summary": "连接失败",
                    "public_message": "代理连接失败",
                    "retryable": True,
                },
            )

        self.assertEqual(failure["error_code"], "proxy_connect_failed")
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(manager._tasks[task["task_id"]]["status"], "failed")

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

    def test_legacy_phone_incident_ids_are_migrated_in_global_and_task_logs(self) -> None:
        task_id = "free-legacy-incident"
        legacy_id = "LOG-13800138000-ABC12345"
        row = {
            "time": "2026-08-27T08:30:00Z",
            "level": "error",
            "task_id": task_id,
            "node_code": "free_protocol",
            "incident_id": legacy_id,
        }
        (self.data_dir / "logs.json").write_text(json.dumps([row]), encoding="utf-8")
        task_dir = self.data_dir / "task_logs"
        task_dir.mkdir(parents=True)
        (task_dir / f"{fingerprint(task_id)}.json").write_text(json.dumps([row]), encoding="utf-8")

        store = FreeLogStore(self.data_dir)
        self.assertEqual(store.snapshot(task_id)[0]["incident_id"], "LOG-20260827-ABC12345")
        self.assertEqual(store.snapshot()[0]["incident_id"], "LOG-20260827-ABC12345")
        self.assertNotIn("13800138000", (self.data_dir / "logs.json").read_text(encoding="utf-8"))
        self.assertNotIn("13800138000", (task_dir / f"{fingerprint(task_id)}.json").read_text(encoding="utf-8"))

    def test_ambiguous_legacy_phone_incident_id_is_cleared(self) -> None:
        legacy_id = "LOG-13800138000-ABC12345"
        rows = [
            {"time": "2026-08-27T08:30:00Z", "level": "error", "task_id": "free-ambiguous", "node_code": "x", "incident_id": legacy_id},
            {"time": "2026-08-28T08:30:00Z", "level": "error", "task_id": "free-ambiguous", "node_code": "x", "incident_id": legacy_id},
        ]
        (self.data_dir / "logs.json").write_text(json.dumps(rows), encoding="utf-8")

        snapshot = FreeLogStore(self.data_dir).snapshot()
        self.assertEqual([row["incident_id"] for row in snapshot], ["", ""])
        self.assertNotIn("13800138000", (self.data_dir / "logs.json").read_text(encoding="utf-8"))

    def test_legacy_phone_ids_with_colliding_canonical_suffix_are_cleared(self) -> None:
        rows = [
            {"time": "2026-08-27T08:30:00Z", "level": "error", "task_id": "free-a", "node_code": "x", "incident_id": "LOG-13800138000-ABC12345"},
            {"time": "2026-08-27T08:31:00Z", "level": "error", "task_id": "free-b", "node_code": "x", "incident_id": "LOG-13900139000-ABC12345"},
        ]
        (self.data_dir / "logs.json").write_text(json.dumps(rows), encoding="utf-8")
        snapshot = FreeLogStore(self.data_dir).snapshot()
        self.assertEqual([row["incident_id"] for row in snapshot], ["", ""])

    def test_legacy_phone_incident_with_missing_timestamp_is_cleared(self) -> None:
        legacy_id = "LOG-13800138000-ABC12345"
        rows = [
            {"level": "error", "task_id": "free-missing-time", "node_code": "x", "incident_id": legacy_id},
            {"time": "2026-08-27T08:30:00Z", "level": "error", "task_id": "free-missing-time", "node_code": "x", "incident_id": legacy_id},
        ]
        (self.data_dir / "logs.json").write_text(json.dumps(rows), encoding="utf-8")

        snapshot = FreeLogStore(self.data_dir).snapshot()
        self.assertEqual([row["incident_id"] for row in snapshot], ["", ""])

    def test_legacy_phone_id_is_cleared_when_canonical_id_exists_in_diagnostics(self) -> None:
        diagnostic_store = DiagnosticStore(self.data_dir / "diagnostics")
        with patch.object(DiagnosticStore, "_incident_id", return_value="LOG-20260827-ABC12345"):
            existing_id = diagnostic_store.record({
                "event_id": "diagnostic-canonical-owner",
                "level": "error", "outcome": "error", "node_code": "existing",
            })
        self.assertEqual(existing_id, "LOG-20260827-ABC12345")
        legacy_id = "LOG-13800138000-ABC12345"
        (self.data_dir / "logs.json").write_text(json.dumps([{
            "time": "2026-08-27T08:30:00Z", "level": "error",
            "task_id": "free-diagnostic-collision", "node_code": "x",
            "incident_id": legacy_id,
        }]), encoding="utf-8")

        snapshot = FreeLogStore(self.data_dir, diagnostic_store=diagnostic_store).snapshot()
        self.assertEqual(snapshot[0]["incident_id"], "")
        self.assertNotIn("13800138000", (self.data_dir / "logs.json").read_text(encoding="utf-8"))

    def test_legacy_phone_id_is_cleared_when_diagnostic_index_is_unreadable(self) -> None:
        legacy_id = "LOG-13800138000-ABC12345"
        (self.data_dir / "logs.json").write_text(json.dumps([{
            "time": "2026-08-27T08:30:00Z", "level": "error",
            "task_id": "free-diagnostic-unreadable", "node_code": "x",
            "incident_id": legacy_id,
        }]), encoding="utf-8")
        diagnostic_path = self.data_dir / "diagnostics.sqlite3"
        diagnostic_path.write_bytes(b"present-but-unreadable")
        with patch("mac_overrides.free_log_runtime.sqlite3.connect", side_effect=OSError("locked")):
            snapshot = FreeLogStore(self.data_dir).snapshot()
        self.assertEqual(snapshot[0]["incident_id"], "")
        self.assertNotIn("13800138000", (self.data_dir / "logs.json").read_text(encoding="utf-8"))

    def test_legacy_id_migration_retries_after_atomic_write_failure(self) -> None:
        legacy_id = "LOG-13800138000-ABC12345"
        (self.data_dir / "logs.json").write_text(json.dumps([{
            "time": "2026-08-27T08:30:00Z", "level": "error",
            "task_id": "free-migration-retry", "node_code": "x",
            "incident_id": legacy_id,
        }]), encoding="utf-8")
        store = FreeLogStore(self.data_dir)
        with patch("mac_overrides.free_log_runtime.atomic_write", side_effect=OSError("disk busy")):
            first = store.snapshot()
        self.assertEqual(first[0]["incident_id"], "LOG-20260827-ABC12345")
        self.assertIn("13800138000", (self.data_dir / "logs.json").read_text(encoding="utf-8"))

        second = store.snapshot()
        self.assertEqual(second[0]["incident_id"], "LOG-20260827-ABC12345")
        self.assertNotIn("13800138000", (self.data_dir / "logs.json").read_text(encoding="utf-8"))

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

    def test_failure_only_result_save_preserves_account_credentials(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row_id = pool.entries()[0].row_id
        previous = {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "id_token": "old-id",
            "password": "old-password",
            "totp_secret": "old-totp",
            "credential_line": "old-credential",
            "status": "success",
        }
        pool.save_result(row_id, previous)

        failure = {
            "node_code": "free_email_otp_wait",
            "node_label": "等待 Free 邮箱验证码",
            "error_code": "free_email_otp_wait_failed",
            "public_message": "等待验证码失败",
            "technical_summary": "邮箱取件超时",
            "retryable": True,
        }
        pool.save_result(row_id, {"status": "failed", "failure": failure})

        saved = pool.result(row_id)
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(saved["failure"]["error_code"], "free_email_otp_wait_failed")
        for key, value in previous.items():
            if key != "status":
                self.assertEqual(saved[key], value)

        pool.save_result(row_id, {"access_token": "new-access", "status": "success"})
        self.assertEqual(pool.result(row_id)["access_token"], "new-access")
        self.assertEqual(pool.result(row_id)["refresh_token"], "old-refresh")

    def test_task_failure_snapshot_preserves_durable_account_fields(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row_id = pool.entries()[0].row_id
        pool.save_result(row_id, {
            "access_token": "durable-access",
            "password": "durable-password",
            "totp_secret": "durable-totp",
            "status": "twofa_pending",
        })
        manager = FreeRegisterManager(self.data_dir, runner=lambda *_args, **_kwargs: {})
        manager._tasks = {
            "failed-task": {
                "task_id": "failed-task",
                "row_id": row_id,
                "status": "running",
                "stage": "free_email_otp_wait",
                "result": {"status": "running"},
            },
        }
        failure = {
            "node_code": "free_email_otp_wait",
            "node_label": "等待 Free 邮箱验证码",
            "error_code": "free_email_otp_wait_failed",
            "public_message": "等待验证码失败",
            "technical_summary": "邮箱取件超时",
            "retryable": True,
        }
        manager._persist_task_failure(
            "failed-task",
            manager._tasks["failed-task"],
            status="failed",
            failure=failure,
        )
        snapshot = manager._tasks["failed-task"]["result"]
        self.assertEqual(snapshot["access_token"], "durable-access")
        self.assertEqual(snapshot["password"], "durable-password")
        self.assertEqual(snapshot["totp_secret"], "durable-totp")
        self.assertEqual(snapshot["status"], "failed")
        self.assertEqual(snapshot["failure"]["error_code"], "free_email_otp_wait_failed")

    def test_rerun_rejects_durable_account_before_any_pool_side_effect(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row_id = pool.entries()[0].row_id
        pool.update(row_id, status="pending_rerun", batch_id="old-batch")
        pool.save_result(row_id, {"access_token": "existing-access", "status": "failed"})
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: self.fail("runner must not be called"),
            proxy_probe=lambda _proxy, _url: "203.0.113.90",
        )
        manager._tasks = {
            "failed-task": {
                "task_id": "failed-task",
                "row_id": row_id,
                "status": "failed",
                "stage": "free_email_otp_wait",
                "result": {"status": "failed"},
            },
        }
        with patch.object(manager.pool, "reserve") as reserve, patch.object(manager.proxies, "bind") as bind:
            with self.assertRaisesRegex(FreeRegisterError, "已有已保存") as raised:
                manager.rerun("failed-task", {})
        reserve.assert_not_called()
        bind.assert_not_called()
        self.assertEqual(raised.exception.error_code, "free_rerun_account_result_exists")
        self.assertEqual(pool._row_state(row_id)["status"], "pending_rerun")

    def test_rerun_checks_historical_success_task_when_result_file_is_missing(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row_id = pool.entries()[0].row_id
        pool.update(row_id, status="pending_rerun")
        FreeTaskStore(self.data_dir).save({
            "old-success": {
                "task_id": "old-success",
                "row_id": row_id,
                "status": "success",
                "result": {"status": "success", "account_flow": "signup"},
            },
            "failed-task": {
                "task_id": "failed-task",
                "row_id": row_id,
                "status": "failed",
                "result": {"status": "failed"},
            },
        })
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: self.fail("runner must not be called"),
            proxy_probe=lambda _proxy, _url: "203.0.113.91",
        )
        with self.assertRaisesRegex(FreeRegisterError, "已有已保存"):
            manager.rerun("failed-task", {})

    def test_start_rejects_manually_restored_account_before_pool_side_effects(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row_id = pool.entries()[0].row_id
        pool.save_result(row_id, {
            "access_token": "existing-access",
            "registration_completed": True,
            "status": "success",
        })
        # Simulate an operator manually restoring a completed row to available.
        pool.set_status([row_id], "available")
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: self.fail("runner must not be called"),
        )
        with patch.object(manager.pool, "reserve") as reserve, patch.object(manager.proxies, "bind") as bind, patch.object(manager.proxies, "import_text") as import_text:
            with self.assertRaisesRegex(FreeRegisterError, "已有已保存") as raised:
                manager.start(
                    {"target_count": 1},
                    proxy_content="http://proxy-a.test:8000\n",
                )
        reserve.assert_not_called()
        bind.assert_not_called()
        import_text.assert_not_called()
        self.assertEqual(raised.exception.error_code, "free_run_account_result_exists")
        self.assertEqual(manager.pool._row_state(row_id)["status"], "available")

    def test_account_completion_guard_requires_strong_evidence(self) -> None:
        manager = FreeRegisterManager(self.data_dir, runner=lambda *_args, **_kwargs: {})
        self.assertFalse(manager._has_existing_account_result({"account_flow": "signup"}))
        self.assertFalse(manager._has_existing_account_result({"registration_password_used": True}))
        self.assertTrue(manager._has_existing_account_result({"registration_completed": True}))
        self.assertTrue(manager._has_existing_account_result({"has_access_token": "true"}))

    def test_corrupt_result_fails_closed_before_start_side_effects(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row_id = pool.entries()[0].row_id
        pool.set_status([row_id], "available")
        result_path = pool.results_dir / f"{fingerprint(row_id)}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text("{not-json", encoding="utf-8")
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: self.fail("runner must not be called"),
        )
        with patch.object(manager.pool, "reserve") as reserve, patch.object(manager.proxies, "bind") as bind:
            with self.assertRaises(FreeRegisterError) as raised:
                manager.start(
                    {"target_count": 1},
                    proxy_content="http://proxy-a.test:8000\n",
                )
        reserve.assert_not_called()
        bind.assert_not_called()
        self.assertEqual(raised.exception.error_code, "free_result_read_failed")

    def test_startup_reconciles_missing_durable_credentials_from_task_history(self) -> None:
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row_id = pool.entries()[0].row_id
        FreeTaskStore(self.data_dir).save({
            "old-success": {
                "task_id": "old-success",
                "row_id": row_id,
                "status": "twofa_pending",
                "updated_at": 20,
                "result": {
                    "status": "twofa_pending",
                    "access_token": "restored-access",
                    "password": "restored-password",
                },
            },
        })
        manager = FreeRegisterManager(self.data_dir, runner=lambda *_args, **_kwargs: {})
        saved = manager.pool.result(row_id)
        self.assertEqual(saved["access_token"], "restored-access")
        self.assertEqual(saved["password"], "restored-password")


if __name__ == "__main__":
    unittest.main()
