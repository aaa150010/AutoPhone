from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest


class WebGuiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.previous_data_dir = os.environ.get("GPTPHONE_DATA_DIR")
        os.environ["GPTPHONE_DATA_DIR"] = cls.tempdir.name
        root = Path(__file__).resolve().parents[1]
        cls.import_paths = [str(root / "mac_overrides"), str(root / "business_pyc")]
        for path in reversed(cls.import_paths):
            sys.path.insert(0, path)
        cls.module = importlib.import_module("web_gui")

    @classmethod
    def tearDownClass(cls):
        if cls.previous_data_dir is None:
            os.environ.pop("GPTPHONE_DATA_DIR", None)
        else:
            os.environ["GPTPHONE_DATA_DIR"] = cls.previous_data_dir
        for path in cls.import_paths:
            try:
                sys.path.remove(path)
            except ValueError:
                pass
        cls.tempdir.cleanup()

    def test_masked_draft_preserves_existing_sms_and_smtp_secrets(self):
        existing = {
            "performance_policy_version": 5,
            "sms_api_keys": ["sms-secret-a", "sms-secret-b"],
            "proxy": "http://proxy-user:proxy-pass@127.0.0.1:7890",
            "email_notification": {
                "enabled": False,
                "provider": "qq",
                "password": "smtp-secret",
            },
        }
        draft = {
            "performance_policy_version": 5,
            "sms_api_keys": ["********", "********"],
            "proxy": "********",
            "email_notification": {"password": "********"},
        }

        resolved = self.module._local_config_from_runtime(draft, existing)

        self.assertEqual(resolved["sms_api_keys"], ["sms-secret-a", "sms-secret-b"])
        self.assertEqual(resolved["proxy"], existing["proxy"])
        self.assertEqual(resolved["email_notification"]["password"], "smtp-secret")

    def test_public_config_masks_all_supported_secrets(self):
        config = {
            "sms_api_keys": ["sms-secret"],
            "proxy": "http://proxy-user:proxy-pass@127.0.0.1:7890",
            "sub2api": {"password": "sub2-secret"},
            "email_notification": {"password": "smtp-secret"},
        }

        masked = self.module._masked_local_config(config)
        serialized = json.dumps(masked)

        for secret in ("sms-secret", "proxy-pass", "sub2-secret", "smtp-secret"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(masked["email_notification"]["password"], "********")

    def test_task_config_allows_fifteen_attempts_per_enabled_sms_platform(self):
        module = self.module
        original_task_config = module._ORIGINAL_TASK_CONFIG
        fake_self = SimpleNamespace()

        def build(pools):
            return module._patched_task_config(
                fake_self,
                {
                    "phone_attempts_per_provider": 15,
                    "sms_provider_pools": pools,
                },
                "user@example.test",
                "task-attempts",
            )

        try:
            module._ORIGINAL_TASK_CONFIG = lambda *_args, **_kwargs: {"code_timeout": 30}
            three_platforms = build([
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-key"]},
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-key"]},
                {"provider": "5sim", "enabled": True, "api_keys": ["five-key"]},
            ])
            two_platforms = build([
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-key"]},
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-key"]},
                {"provider": "5sim", "enabled": False, "api_keys": ["five-key"]},
            ])
            one_platform = build([
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-key-a", "bower-key-b"]},
                {"provider": "herosms", "enabled": True, "api_keys": []},
                {"provider": "5sim", "enabled": False, "api_keys": ["five-key"]},
            ])
        finally:
            module._ORIGINAL_TASK_CONFIG = original_task_config

        self.assertEqual(three_platforms["phone_max_attempts"], 45)
        self.assertEqual(two_platforms["phone_max_attempts"], 30)
        self.assertEqual(one_platform["phone_max_attempts"], 15)
        self.assertEqual(three_platforms["phone_attempts_per_provider"], 15)
        self.assertEqual(three_platforms["phone_session_max_seconds"], 1800)

    def test_phone_send_payload_keeps_browser_channel_parameter(self):
        calls = []

        class FakeTransport:
            def _post_auth_json(self, path, payload, **kwargs):
                calls.append((path, dict(payload), dict(kwargs)))
                return {"_status": 200}

        self.module._real_send_phone_number_otp(FakeTransport(), "+1 (555) 000-1234", "sms")

        self.assertEqual(calls[0][0], "/api/accounts/add-phone/send")
        self.assertEqual(calls[0][1]["channel"], "sms")
        self.assertEqual(calls[0][2]["referer"], "https://auth.openai.com/add-phone")

    def test_public_task_drops_composite_account_tokens_and_source_row(self):
        task = {
            "task_id": "task-1",
            "account": "user@example.test---mail-pass",
            "email": "user@example.test",
            "source_row": "user@example.test----mail-pass----client-id----refresh-token",
            "status": "failed",
            "error": "mail-pass client-id refresh-token",
            "result": {"access_token": "access-secret", "sms_cost_cny": 1.23},
        }

        public = self.module._public_task(task)
        serialized = json.dumps(public)

        self.assertEqual(public["account"], "user@example.test")
        self.assertNotIn("source_row", public)
        self.assertNotIn("access_token", serialized)
        for secret in ("mail-pass", "client-id", "refresh-token", "access-secret"):
            self.assertNotIn(secret, serialized)

    def test_public_task_exposes_only_sanitized_structured_failure(self):
        task = {
            "task_id": "T001-safe",
            "email": "user@example.test",
            "source_row": "user@example.test----mail-pass----client-id----refresh-token",
            "status": "failed",
            "error": "refresh-token",
            "technical_error": "access_token=raw-access-token",
            "failure": {
                "node_code": "finalizing_token",
                "node_label": "untrusted label",
                "error_code": "invalid_grant",
                "public_message": "交换 OAuth Token失败：refresh-token 已失效",
                "technical_summary": "HTTP 400 access_token=raw-access-token password=mail-pass",
                "retryable": True,
                "http_status": 400,
                "raw_response": {"access_token": "raw-access-token"},
            },
        }

        public = self.module._public_task(task)
        serialized = json.dumps(public, ensure_ascii=False)

        self.assertEqual(public["failure"]["node_code"], "finalizing_token")
        self.assertEqual(public["failure"]["node_label"], "交换 OAuth Token")
        self.assertEqual(public["error"], public["failure"]["public_message"])
        self.assertNotIn("raw_response", public["failure"])
        for secret in ("mail-pass", "client-id", "refresh-token", "raw-access-token"):
            self.assertNotIn(secret, serialized)

    def test_success_task_historical_sub2_event_is_not_exposed_as_failure_explanation(self):
        task = {
            "task_id": "T-success-history",
            "email": "user@example.test",
            "status": "success",
            "error": "sub2_uploaded",
            "reason": "sub2_uploaded",
        }

        public = self.module._public_task(task)

        self.assertEqual(public["status"], "success")
        self.assertNotIn("error", public)
        self.assertNotIn("reason", public)

    def test_terminal_task_state_replaces_generic_error_with_current_node_diagnostic(self):
        module = self.module
        original_state = module._ORIGINAL_TASK_STATE
        captured = []
        fake_self = SimpleNamespace()
        try:
            module._ORIGINAL_TASK_STATE = lambda _self, task_id, **values: captured.append((task_id, values))
            module._TASK_PROGRESS.reset()
            module._TASK_PROGRESS.set_stage("T002-safe", "finalizing_callback")

            module._patched_task_state(
                fake_self,
                "T002-safe",
                status="failed",
                error="授权或上传未完成",
                result={"codex_chain_events": [{"state": "CONSENT_REQUIRED"}]},
            )
        finally:
            module._ORIGINAL_TASK_STATE = original_state
            module._TASK_PROGRESS.reset()

        values = captured[0][1]
        self.assertEqual(values["failure"]["node_code"], "finalizing_callback")
        self.assertIn("获取 OAuth 回调失败", values["error"])
        self.assertNotIn("授权或上传未完成", values["error"])
        self.assertEqual(values["technical_error"], "服务端未返回错误详情")

    def test_oauth_and_sub2_wrappers_enter_the_failing_stage_before_network_call(self):
        module = self.module
        originals = {
            "session": module._ORIGINAL_GENERATE_SUB2_OAUTH_SESSION,
            "authorize": module._ORIGINAL_REAL_INITIATE_OAUTH,
            "callback": module._ORIGINAL_REAL_FOLLOW_CONTINUE_UNTIL_CODE,
            "token": module._ORIGINAL_REAL_EXCHANGE_CODE,
            "upload": module._ORIGINAL_REAL_SUB2_UPLOAD,
        }
        observed = []

        def fail_at(expected):
            def fail(*_args, **_kwargs):
                observed.append(module._TASK_PROGRESS.progress("T005-safe")["code"])
                raise RuntimeError(expected)

            return fail

        token = module._TASK_CONTEXT.set("T005-safe")
        try:
            cases = (
                (
                    "oauth_session",
                    "_ORIGINAL_GENERATE_SUB2_OAUTH_SESSION",
                    lambda: module._generate_sub2_oauth_session({}, upload_proxy="", log_fn=None),
                ),
                (
                    "oauth_authorize_node",
                    "_ORIGINAL_REAL_INITIATE_OAUTH",
                    lambda: module._real_initiate_oauth(SimpleNamespace(config={}), "/authorize"),
                ),
                (
                    "finalizing_callback",
                    "_ORIGINAL_REAL_FOLLOW_CONTINUE_UNTIL_CODE",
                    lambda: module._real_follow_continue_until_code(SimpleNamespace(), "/continue", {}, _reauth=False),
                ),
                (
                    "finalizing_token",
                    "_ORIGINAL_REAL_EXCHANGE_CODE",
                    lambda: module._real_exchange_code(SimpleNamespace(), "code", "verifier", "client", "redirect", "mail"),
                ),
                (
                    "finalizing_upload",
                    "_ORIGINAL_REAL_SUB2_UPLOAD",
                    lambda: module._real_sub2_upload(SimpleNamespace(), credentials={}, email="mail"),
                ),
            )
            for expected, original_name, invoke in cases:
                with self.subTest(stage=expected):
                    module._TASK_PROGRESS.reset()
                    setattr(module, original_name, fail_at(expected))
                    with self.assertRaisesRegex(RuntimeError, expected):
                        invoke()
                    self.assertEqual(observed[-1], expected)
        finally:
            module._ORIGINAL_GENERATE_SUB2_OAUTH_SESSION = originals["session"]
            module._ORIGINAL_REAL_INITIATE_OAUTH = originals["authorize"]
            module._ORIGINAL_REAL_FOLLOW_CONTINUE_UNTIL_CODE = originals["callback"]
            module._ORIGINAL_REAL_EXCHANGE_CODE = originals["token"]
            module._ORIGINAL_REAL_SUB2_UPLOAD = originals["upload"]
            module._TASK_CONTEXT.reset(token)
            module._TASK_PROGRESS.reset()

    def test_sub2_oauth_session_retries_one_transient_disconnect_with_safe_log(self):
        module = self.module
        original = module._ORIGINAL_GENERATE_SUB2_OAUTH_SESSION
        calls = []
        logs = []

        def generate(*_args, **_kwargs):
            calls.append("call")
            if len(calls) == 1:
                raise ConnectionError(
                    "remote end closed connection without response access_token=private-token"
                )
            return {"session_id": "safe-session"}

        try:
            module._ORIGINAL_GENERATE_SUB2_OAUTH_SESSION = generate
            result = module._generate_sub2_oauth_session(
                {"_stop_requested": lambda: False},
                log_fn=lambda message, level="info": logs.append((message, level)),
            )
        finally:
            module._ORIGINAL_GENERATE_SUB2_OAUTH_SESSION = original

        self.assertEqual(result, {"session_id": "safe-session"})
        self.assertEqual(calls, ["call", "call"])
        self.assertEqual(len(logs), 1)
        self.assertIn("oauth_session", logs[0][0])
        self.assertIn("remote_disconnected", logs[0][0])
        self.assertNotIn("private-token", logs[0][0])

    def test_openai_oauth_retry_preserves_completed_node_and_sub2_setup(self):
        module = self.module
        original = module._ORIGINAL_REAL_INITIATE_OAUTH
        calls = []
        logs = []
        transport = SimpleNamespace(
            config={"_stop_requested": lambda: False},
            log_fn=lambda message, level="info": logs.append((message, level)),
        )

        def initiate(_self, _oauth_url):
            calls.append("call")
            if len(calls) == 1:
                return {
                    "_status": 0,
                    "error": "curl: (35) TLS connect error access_token=private-token",
                }
            return {"_status": 200, "page": {"type": "login"}}

        try:
            module._ORIGINAL_REAL_INITIATE_OAUTH = initiate
            result = module._real_initiate_oauth(transport, "/authorize")
        finally:
            module._ORIGINAL_REAL_INITIATE_OAUTH = original

        self.assertEqual(result["_status"], 200)
        self.assertEqual(calls, ["call", "call"])
        self.assertEqual(len(logs), 1)
        self.assertIn("oauth_authorize_node", logs[0][0])
        self.assertIn("保留 Node/SUB2 前置状态", logs[0][0])
        self.assertNotIn("private-token", logs[0][0])

    def test_failed_result_persists_same_structured_failure_used_by_public_state(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        result_dir = Path(self.tempdir.name) / "structured-results"
        entry = SimpleNamespace(email="oauth@example.test")

        def persist(fake_self, settings, task_id, value, result, *, error="", status="failed"):
            target = Path(settings["results_dir"]) / f"{task_id}_{value.email.replace('@', '_at_')}.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps({
                    "task_id": task_id,
                    "status": status,
                    "error": error,
                    "technical_error": error,
                    "result": result,
                }),
                encoding="utf-8",
            )

        fake_self = SimpleNamespace(
            data_dir=self.tempdir.name,
            _source_row=lambda _entry: "oauth@example.test----mail-pass----client-id----refresh-token",
            _log=lambda *_args, **_kwargs: None,
        )
        try:
            module._ORIGINAL_PERSIST_RESULT = persist
            module._TASK_PROGRESS.reset()
            module._TASK_PROGRESS.set_stage("T003-safe", "finalizing_token")
            result = {"phase2_error": "sub2_exchange_failed: HTTP 401 OPENAI_OAUTH_SESSION_NOT_FOUND"}
            module._patched_persist_result(
                fake_self,
                {"results_dir": str(result_dir)},
                "T003-safe",
                entry,
                result,
                error="授权或上传未完成",
                status="repair_pending",
            )
        finally:
            module._ORIGINAL_PERSIST_RESULT = original_persist
            module._TASK_PROGRESS.reset()

        payload = json.loads((result_dir / "T003-safe_oauth_at_example.test.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["failure"]["node_code"], "finalizing_token")
        self.assertEqual(payload["error"], payload["failure"]["public_message"])
        self.assertEqual(payload["technical_error"], payload["failure"]["technical_summary"])
        self.assertEqual(payload["result"]["failure"], payload["failure"])

    def test_persistence_exception_reports_save_node_with_sanitized_cause(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        entry = SimpleNamespace(email="save@example.test")
        fake_self = SimpleNamespace(
            data_dir=self.tempdir.name,
            _source_row=lambda _entry: "save@example.test----mail-pass----client-id----refresh-token",
        )
        try:
            module._ORIGINAL_PERSIST_RESULT = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("permission denied password=mail-pass")
            )
            module._TASK_PROGRESS.reset()
            module._TASK_PROGRESS.set_stage("T006-safe", "email_login")
            with self.assertRaisesRegex(RuntimeError, "保存任务结果失败") as raised:
                module._patched_persist_result(
                    fake_self,
                    {},
                    "T006-safe",
                    entry,
                    {},
                    error="mailbox_imap_error",
                    status="failed",
                )
        finally:
            module._ORIGINAL_PERSIST_RESULT = original_persist
            module._TASK_PROGRESS.reset()

        self.assertNotIn("mail-pass", str(raised.exception))
        failure = module._known_task_failure("T006-safe")
        self.assertEqual(failure["node_code"], "finalizing_save")
        self.assertIn("permission denied", failure["technical_summary"])
        self.assertNotIn("mail-pass", failure["technical_summary"])

    def test_public_failure_log_matches_task_diagnostic_and_drops_raw_cause(self):
        task = {
            "task_id": "T004-safe",
            "source_row": "user@example.test----mail-pass----client-id----refresh-token",
            "status": "failed",
            "failure": {
                "node_code": "finalizing_token",
                "node_label": "交换 OAuth Token",
                "error_code": "sub2_exchange_failed",
                "public_message": "交换 OAuth Token失败：SUB2 OAuth 会话已过期",
                "technical_summary": "sub2_exchange_failed",
                "retryable": True,
                "http_status": 401,
            },
        }
        logs = [{"level": "error", "message": "T004-safe 失败: refresh_token=refresh-token"}]

        public = self.module._public_logs(logs, [task])
        message = public[0]["message"]

        self.assertEqual(
            message,
            "T004-safe [交换 OAuth Token/finalizing_token] 交换 OAuth Token失败：SUB2 OAuth 会话已过期",
        )
        self.assertNotIn("refresh-token", message)

    def test_public_logs_redact_proxy_username_and_password_fragments(self):
        self.module._write_local_config({
            "proxy": "http://proxy%40user:p%40ss-word@127.0.0.1:7890",
        })
        logs = [{"message": "proxy%40user p%40ss-word proxy@user p@ss-word"}]

        public = self.module._public_logs(logs, [])
        serialized = json.dumps(public)

        for secret in ("proxy%40user", "p%40ss-word", "proxy@user", "p@ss-word"):
            self.assertNotIn(secret, serialized)
        self.assertIn("********", serialized)

    def test_local_config_migration_removes_nvtoken_fields_atomically(self):
        path = self.module._LOCAL_CONFIG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "nvtoken": {"api_key": "legacy-secret"},
                "nvtoken_upload": True,
                "pixel_upload_enabled": False,
            }),
            encoding="utf-8",
        )

        loaded = self.module._read_local_config()
        persisted = json.loads(path.read_text(encoding="utf-8"))

        for value in (loaded, persisted):
            self.assertNotIn("nvtoken", value)
            self.assertNotIn("nvtoken_upload", value)
            self.assertFalse(value["pixel_upload_enabled"])

    def test_result_file_persists_batch_identity(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        result_dir = Path(self.tempdir.name) / "batch-results"
        entry = SimpleNamespace(email="batch@example.test")

        def persist(fake_self, settings, task_id, value, result, *, error="", status="failed"):
            target = Path(settings["results_dir"]) / f"{task_id}_{value.email.replace('@', '_at_')}.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps({"task_id": task_id, "status": status, "result": result}),
                encoding="utf-8",
            )

        fake_self = SimpleNamespace(
            data_dir=self.tempdir.name,
            _log=lambda *_args, **_kwargs: None,
        )
        settings = {
            "results_dir": str(result_dir),
            "pixel_upload_enabled": False,
            "batch_id": "20260804-140000-abc123",
            "batch_started_at": 1785823200,
        }
        result = {}
        try:
            module._ORIGINAL_PERSIST_RESULT = persist
            module._patched_persist_result(
                fake_self,
                settings,
                "task-batch",
                entry,
                result,
                status="success",
            )
        finally:
            module._ORIGINAL_PERSIST_RESULT = original_persist
            module._TASK_PROGRESS.reset()

        payload = json.loads(
            (result_dir / "task-batch_batch_at_example.test.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["batch_id"], settings["batch_id"])
        self.assertEqual(payload["batch_started_at"], settings["batch_started_at"])
        self.assertEqual(payload["result"]["batch_id"], settings["batch_id"])
        self.assertEqual(payload["result"]["batch_started_at"], settings["batch_started_at"])

    def test_runtime_summary_only_counts_current_batch(self):
        module = self.module
        previous_context = module._RUN_NOTIFICATION_CONTEXT
        try:
            with module._RUN_NOTIFICATION_LOCK:
                module._RUN_NOTIFICATION_CONTEXT = {
                    "run_id": "batch-current",
                    "batch_id": "batch-current",
                    "batch_started_at": 200,
                    "started_at": 200,
                    "target": 2,
                }
            summary = module._runtime_summary([
                {
                    "task_id": "old-success",
                    "batch_id": "batch-old",
                    "status": "success",
                    "result": {"sms_cost_cny": 8.8},
                },
                {
                    "task_id": "current-pending",
                    "batch_id": "batch-current",
                    "status": "running",
                    "updated_at": 210,
                },
            ])
        finally:
            with module._RUN_NOTIFICATION_LOCK:
                module._RUN_NOTIFICATION_CONTEXT = previous_context

        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["success"], 0)
        self.assertEqual(summary["active"], 1)
        self.assertEqual(summary["sms_cost_cny"], 0)

    def test_success_result_is_persisted_before_pixel_enqueue_and_enqueue_failure_is_isolated(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        original_queue = module._PIXEL_UPLOAD_QUEUE
        result_dir = Path(self.tempdir.name) / "results"
        calls = []

        def persist(fake_self, settings, task_id, entry, result, *, error="", status="failed"):
            target = Path(settings["results_dir"]) / f"{task_id}_{entry.email.replace('@', '_at_')}.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('{"status":"success"}', encoding="utf-8")
            return "persisted"

        class Queue:
            def __init__(self, fail=False):
                self.fail = fail

            def enqueue(self, task_id, path):
                calls.append((task_id, Path(path), Path(path).is_file()))
                if self.fail:
                    raise RuntimeError("private transport failure")
                return {"record_id": "record-a"}

        fake_self = SimpleNamespace(
            data_dir=self.tempdir.name,
            _log=lambda message, level="info": calls.append((message, level)),
        )
        entry = SimpleNamespace(email="success@example.test")
        try:
            module._ORIGINAL_PERSIST_RESULT = persist
            module._PIXEL_UPLOAD_QUEUE = Queue()
            returned = module._patched_persist_result(
                fake_self,
                {"results_dir": str(result_dir), "pixel_upload_enabled": True},
                "task-1",
                entry,
                {"access_token": "not-used"},
                status="success",
            )
            self.assertEqual(returned, "persisted")
            self.assertEqual(calls[0][0:2], ("task-1", result_dir / "task-1_success_at_example.test.json"))
            self.assertTrue(calls[0][2])

            calls.clear()
            module._PIXEL_UPLOAD_QUEUE = Queue(fail=True)
            module._patched_persist_result(
                fake_self,
                {"results_dir": str(result_dir), "pixel_upload_enabled": True},
                "task-2",
                entry,
                {},
                status="success",
            )
            self.assertTrue(any("Pixel 自动上传记录创建失败" in item[0] for item in calls if isinstance(item, tuple)))

            calls.clear()
            module._PIXEL_UPLOAD_QUEUE = Queue()
            module._patched_persist_result(
                fake_self,
                {"results_dir": str(result_dir), "pixel_upload_enabled": False},
                "task-3",
                entry,
                {},
                status="success",
            )
            self.assertEqual(calls, [])
        finally:
            module._ORIGINAL_PERSIST_RESULT = original_persist
            module._PIXEL_UPLOAD_QUEUE = original_queue

    def test_explicit_password_rejection_damages_mailbox_and_skips_generic_retirement(self):
        module = self.module
        original_retire = module._ORIGINAL_RETIRE_AFTER_FAILURE
        persisted = []
        task_states = []
        logs = []

        class Pool:
            def __init__(self):
                self.damaged = []

            def mark_damaged_entry(self, entry, *, reason=""):
                self.damaged.append((entry.email, reason))

        fake_self = SimpleNamespace(
            _password_credentials_rejected=lambda result: (
                "password_verify_failed" in str(result.get("error") or "").lower()
                and "invalid password" in str(result.get("error") or "").lower()
            ),
            _persist_result=lambda settings, task_id, entry, result, **kwargs: persisted.append(
                (task_id, entry.email, kwargs)
            ),
            _task_state=lambda task_id, **values: task_states.append((task_id, values)),
            _log=lambda message, level="info": logs.append((message, level)),
        )
        entry = SimpleNamespace(email="rejected@example.test")
        pool = Pool()
        try:
            module._ORIGINAL_RETIRE_AFTER_FAILURE = lambda *_args, **_kwargs: self.fail(
                "explicit password rejection must not return to the generic retry pool"
            )
            module._patched_retire_after_failure(
                fake_self,
                {},
                pool,
                entry,
                "task-password",
                {"error": "password_verify_failed: invalid password"},
                "password_verify_failed: invalid password",
            )
        finally:
            module._ORIGINAL_RETIRE_AFTER_FAILURE = original_retire

        message = module._PASSWORD_DAMAGED_MESSAGE
        self.assertEqual(pool.damaged, [(entry.email, message)])
        self.assertEqual(persisted[0][2]["status"], "email_damaged")
        self.assertEqual(task_states[0][1]["status"], "email_damaged")
        self.assertEqual(task_states[0][1]["error"], message)
        self.assertEqual(logs, [(f"task-password [验证邮箱密码/email_password] {message}", "error")])

    def test_account_banned_failure_is_terminal_damages_pool_and_never_enqueues_pixel(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        original_retire = module._ORIGINAL_RETIRE_AFTER_FAILURE
        original_queue = module._PIXEL_UPLOAD_QUEUE
        original_sms_web = module._SMS_WEB
        result_dir = Path(self.tempdir.name) / "banned-results"
        persisted = []
        task_states = []
        logs = []
        enqueued = []

        def persist(fake_self, settings, task_id, entry, result, *, error="", status="failed"):
            target = Path(settings["results_dir"]) / f"{task_id}_{entry.email.replace('@', '_at_')}.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps({"status": status, "error": error, "technical_error": error, "result": result}),
                encoding="utf-8",
            )
            persisted.append((status, error))

        class Pool:
            def __init__(self):
                self.damaged = []

            def mark_damaged_entry(self, entry, *, reason=""):
                self.damaged.append((entry.email, reason))

        class Queue:
            def enqueue(self, *args):
                enqueued.append(args)

        fake_self = SimpleNamespace(
            data_dir=self.tempdir.name,
            _log=lambda message, level="info": logs.append((message, level)),
            _task_state=lambda task_id, **values: task_states.append((task_id, values)),
        )
        fake_self._persist_result = lambda settings, task_id, entry, result, **kwargs: (
            module._patched_persist_result(
                fake_self,
                settings,
                task_id,
                entry,
                result,
                **kwargs,
            )
        )
        entry = SimpleNamespace(email="banned@example.test")
        pool = Pool()
        message = module._runtime_policy_ext.ACCOUNT_BANNED_MESSAGE
        try:
            module._ORIGINAL_PERSIST_RESULT = persist
            module._ORIGINAL_RETIRE_AFTER_FAILURE = lambda *_args, **_kwargs: self.fail(
                "explicit account ban must not use generic retirement"
            )
            module._PIXEL_UPLOAD_QUEUE = Queue()
            module._SMS_WEB = SimpleNamespace(
                pop_account_banned_detail=lambda _task_id: "status=403 code=account_banned"
            )

            module._patched_retire_after_failure(
                fake_self,
                {"results_dir": str(result_dir), "pixel_upload_enabled": True},
                pool,
                entry,
                "task-ban",
                {"error": {"code": "account_banned"}, "access_token": "private-token"},
                "account_banned",
            )
        finally:
            module._ORIGINAL_PERSIST_RESULT = original_persist
            module._ORIGINAL_RETIRE_AFTER_FAILURE = original_retire
            module._PIXEL_UPLOAD_QUEUE = original_queue
            module._SMS_WEB = original_sms_web

        target = result_dir / "task-ban_banned_at_example.test.json"
        local_payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(pool.damaged, [(entry.email, message)])
        self.assertEqual(persisted, [("account_banned", message)])
        self.assertEqual(local_payload["error"], message)
        self.assertEqual(local_payload["technical_error"], message)
        self.assertEqual(
            local_payload["account_banned_local_diagnostic"],
            "status=403 code=account_banned",
        )
        self.assertEqual(task_states[0][1]["status"], "account_banned")
        self.assertEqual(task_states[0][1]["error"], message)
        self.assertNotIn("private-token", json.dumps(task_states[0][1]))
        self.assertEqual(logs, [(message, "error")])
        self.assertEqual(enqueued, [])


if __name__ == "__main__":
    unittest.main()
