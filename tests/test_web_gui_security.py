from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
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

    def test_task_config_enables_one_email_otp_resend_by_default(self):
        module = self.module
        original_task_config = module._ORIGINAL_TASK_CONFIG
        try:
            module._ORIGINAL_TASK_CONFIG = lambda *_args, **_kwargs: {"code_timeout": 30}
            default_config = module._patched_task_config(
                SimpleNamespace(data_dir=self.tempdir.name),
                {},
                "user@example.test",
                "email-retry-default",
            )
            explicit_config = module._patched_task_config(
                SimpleNamespace(data_dir=self.tempdir.name),
                {
                    "email_otp_verify_attempts": 3,
                    "email_otp_resend_on_retry": False,
                },
                "user@example.test",
                "email-retry-explicit",
            )
        finally:
            module._ORIGINAL_TASK_CONFIG = original_task_config

        self.assertEqual(default_config["email_otp_verify_attempts"], 2)
        self.assertTrue(default_config["email_otp_resend_on_retry"])
        self.assertEqual(explicit_config["email_otp_verify_attempts"], 3)
        self.assertFalse(explicit_config["email_otp_resend_on_retry"])

    def test_baseline_fallback_snapshot_bypasses_only_original_baseline_guard(self):
        module = self.module
        baseline = SimpleNamespace(
            hash="baseline-fingerprint",
            code="673931",
            received_at="2026-08-05 00:09:13",
        )
        fallback = SimpleNamespace(
            hash="baseline-fallback:baseline-fingerprint",
            code="673931",
            received_at="2026-08-05 00:09:13",
        )
        normal = SimpleNamespace(
            hash="baseline-fingerprint",
            code="673931",
            received_at="2026-08-05 00:09:13",
        )

        self.assertFalse(module._mailbox_url_same_as_baseline(fallback, baseline))
        self.assertTrue(module._mailbox_url_same_as_baseline(normal, baseline))

    def test_email_timeout_uses_final_baseline_fallback(self):
        module = self.module
        original_wait_code = module._ORIGINAL_URL_MAILBOX_WAIT_CODE
        original_final_fallback = module._mailbox_url_runtime_ext.final_runtime_baseline_fallback
        provider = SimpleNamespace(mailbox_url="https://mail.example.test/messages/test")
        otp_provider = SimpleNamespace(
            timeout=90,
            max_attempts=30,
            provider=provider,
            entry=SimpleNamespace(oauth_client_id="", oauth_refresh_token=""),
            log_fn=lambda *_args: None,
        )
        try:
            module._ORIGINAL_URL_MAILBOX_WAIT_CODE = lambda *_args: (_ for _ in ()).throw(
                module._runtime.MailboxPoolError(
                    "mailbox_code_timeout: attempts=18/30: mailbox still returns baseline code"
                )
            )
            module._mailbox_url_runtime_ext.final_runtime_baseline_fallback = (
                lambda _provider: SimpleNamespace(code="682672")
            )

            code = module._url_mailbox_wait_code(otp_provider, "user@example.test")
        finally:
            module._ORIGINAL_URL_MAILBOX_WAIT_CODE = original_wait_code
            module._mailbox_url_runtime_ext.final_runtime_baseline_fallback = original_final_fallback

        self.assertEqual(code, "682672")
        self.assertTrue(otp_provider._chatgpt_email_otp_verified)

    def test_email_otp_resend_uses_remaining_total_timeout_budget(self):
        module = self.module
        original_mark_sent = module._ORIGINAL_URL_MAILBOX_MARK_SENT
        original_wait_code = module._ORIGINAL_URL_MAILBOX_WAIT_CODE
        observed_timeouts = []
        observed_intervals = []
        provider = SimpleNamespace(mailbox_url="https://mail.example.test/messages/test")
        otp_provider = SimpleNamespace(
            timeout=90,
            interval=5,
            max_attempts=30,
            provider=provider,
        )
        try:
            module._ORIGINAL_URL_MAILBOX_MARK_SENT = lambda _self: None
            module._ORIGINAL_URL_MAILBOX_WAIT_CODE = (
                lambda value, _email: (
                    observed_timeouts.append(value.timeout),
                    observed_intervals.append(value.interval),
                    "123456",
                )[-1]
            )
            module._url_mailbox_mark_sent(otp_provider)
            first_deadline = otp_provider._gptphone_email_code_deadline
            module._url_mailbox_mark_sent(otp_provider)
            self.assertEqual(otp_provider._gptphone_email_code_deadline, first_deadline)

            otp_provider._gptphone_email_code_deadline = time.monotonic() + 74
            code = module._url_mailbox_wait_code(otp_provider, "user@example.test")
        finally:
            module._ORIGINAL_URL_MAILBOX_MARK_SENT = original_mark_sent
            module._ORIGINAL_URL_MAILBOX_WAIT_CODE = original_wait_code

        self.assertEqual(code, "123456")
        self.assertEqual(len(observed_timeouts), 1)
        self.assertGreaterEqual(observed_timeouts[0], 72)
        self.assertLessEqual(observed_timeouts[0], 74)
        self.assertEqual(observed_intervals, [3])
        self.assertEqual(otp_provider.timeout, 90)
        self.assertEqual(otp_provider.interval, 5)

    def test_email_otp_page_explicitly_sends_before_waiting(self):
        module = self.module
        original_submit = module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER
        sent = []
        logs = []
        response = {
            "_status": 200,
            "page": {"type": "email_otp_verification"},
            "continue_url": "https://auth.openai.com/email-verification?state=secret",
        }
        transport = SimpleNamespace(
            send_email_otp=lambda continue_url: sent.append(continue_url) or {"_status": 200},
            log_fn=lambda message, level="info": logs.append((message, level)),
        )
        try:
            module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER = lambda _self, _email: response
            result = module._real_submit_email_identifier(transport, "user@example.test")
        finally:
            module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER = original_submit

        self.assertIs(result, response)
        self.assertEqual(sent, [response["continue_url"]])
        self.assertTrue(transport._gptphone_initial_email_otp_send_confirmed)
        self.assertTrue(any("首次邮箱验证码发送接口已确认" in message for message, _level in logs))

    def test_non_email_otp_page_does_not_send_email_code(self):
        module = self.module
        original_submit = module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER
        sent = []
        response = {"_status": 200, "page": {"type": "password_verification"}}
        transport = SimpleNamespace(send_email_otp=lambda value: sent.append(value))
        try:
            module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER = lambda _self, _email: response
            result = module._real_submit_email_identifier(transport, "user@example.test")
        finally:
            module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER = original_submit

        self.assertIs(result, response)
        self.assertEqual(sent, [])

    def test_initial_email_code_send_failure_stops_before_polling(self):
        module = self.module
        original_submit = module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER
        response = {
            "_status": 200,
            "page": {"type": "email_otp_verification"},
            "continue_url": "/email-verification",
        }
        transport = SimpleNamespace(
            send_email_otp=lambda _continue_url: {
                "_status": 429,
                "error": {"code": "rate_limited", "message": "try later"},
            },
            log_fn=None,
        )
        try:
            module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER = lambda _self, _email: response
            with self.assertRaisesRegex(Exception, "email_otp_send_failed"):
                module._real_submit_email_identifier(transport, "user@example.test")
        finally:
            module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER = original_submit

    def test_task_config_binds_401_rerun_to_historical_sub2_account(self):
        module = self.module
        original_task_config = module._ORIGINAL_TASK_CONFIG
        original_sub2_runtime = module._SUB2_RUNTIME
        result_dir = Path(self.tempdir.name) / "sub2-update-results"
        result_dir.mkdir(parents=True, exist_ok=True)
        (result_dir / "old-success.json").write_text(
            json.dumps({
                "status": "success",
                "source_row": "rerun@example.test----mail-password",
                "created_at": 100,
                "result": {"sub2api_account_id": "501"},
            }),
            encoding="utf-8",
        )
        fake_runtime = SimpleNamespace(
            status_for=lambda account_id: {
                "kind": "unauthorized",
                "status_code": 401,
                "needs_rerun": True,
            }
        )
        try:
            module._ORIGINAL_TASK_CONFIG = lambda *_args, **_kwargs: {"code_timeout": 30}
            module._SUB2_RUNTIME = fake_runtime
            config = module._patched_task_config(
                SimpleNamespace(data_dir=self.tempdir.name),
                {"results_dir": str(result_dir)},
                "rerun@example.test",
                "task-rerun",
            )
        finally:
            module._ORIGINAL_TASK_CONFIG = original_task_config
            module._SUB2_RUNTIME = original_sub2_runtime

        self.assertEqual(config["_sub2_update_existing"]["account_id"], "501")
        self.assertEqual(config["_sub2_update_existing"]["status_code"], 401)
        self.assertEqual(config["_sub2_update_existing"]["email"], "rerun@example.test")

    def test_sub2_upload_wrapper_uses_update_branch_and_clears_old_status(self):
        module = self.module
        original_upload = module._ORIGINAL_REAL_SUB2_UPLOAD
        original_update = module._sub2_update_runtime_ext.update_existing_sub2_account
        original_sub2_runtime = module._SUB2_RUNTIME
        calls = []
        cleared = []

        def update_existing(**kwargs):
            calls.append(kwargs)
            return {
                "ok": True,
                "sub2api_account_id": kwargs["account_id"],
                "sub2_update_existing": True,
                "sub2_upload_created": False,
            }

        uploader = SimpleNamespace(
            config={
                "_sub2_update_existing": {
                    "account_id": "501",
                    "email": "rerun@example.test",
                    "status_code": 401,
                }
            },
            upload_proxy="",
            log_fn=None,
        )
        try:
            module._ORIGINAL_REAL_SUB2_UPLOAD = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("create path must not run")
            )
            module._sub2_update_runtime_ext.update_existing_sub2_account = update_existing
            module._SUB2_RUNTIME = SimpleNamespace(clear_status=lambda account_id: cleared.append(account_id))
            result = module._real_sub2_upload(
                uploader,
                credentials={"access_token": "token"},
                email="rerun@example.test",
            )
        finally:
            module._ORIGINAL_REAL_SUB2_UPLOAD = original_upload
            module._sub2_update_runtime_ext.update_existing_sub2_account = original_update
            module._SUB2_RUNTIME = original_sub2_runtime

        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["account_id"], "501")
        self.assertEqual(cleared, ["501"])

    def test_sub2_upload_wrapper_keeps_create_path_for_first_run(self):
        module = self.module
        original_upload = module._ORIGINAL_REAL_SUB2_UPLOAD
        calls = []
        try:
            module._ORIGINAL_REAL_SUB2_UPLOAD = lambda _self, **kwargs: calls.append(kwargs) or {
                "ok": True,
                "sub2api_account_id": "new-account",
                "sub2_upload_created": True,
            }
            result = module._real_sub2_upload(
                SimpleNamespace(config={}, upload_proxy="", log_fn=None),
                credentials={"access_token": "token"},
                email="first@example.test",
            )
        finally:
            module._ORIGINAL_REAL_SUB2_UPLOAD = original_upload

        self.assertTrue(result["ok"])
        self.assertTrue(result["sub2_upload_created"])
        self.assertEqual(len(calls), 1)

    def test_real_phone_send_matches_browser_contract_and_refreshes_sentinel(self):
        calls = []
        sentinel_calls = []

        class FakeSession:
            cookies = {"session": "present"}

            def post(self, url, **kwargs):
                calls.append((url, kwargs))
                return {"_status": 200, "page": {"type": "add_phone"}}

        class FakeSentinel:
            def reset(self, flow=""):
                sentinel_calls.append(("reset", flow))

            def token_for(self, flow, context):
                sentinel_calls.append(("token_for", flow, dict(context)))
                return {"token": "sentinel-value"}

        transport = SimpleNamespace(
            config={"sms_task_id": "task-phone", "_auth_account_email": "user@example.test"},
            account_email="user@example.test",
            session=FakeSession(),
            sentinel_provider=FakeSentinel(),
            device_id="device-1",
            proxy="http://127.0.0.1:7897",
            _gptphone_page_type="add_phone",
        )
        self.module._AUTH_SESSIONS.clear("task-phone")
        try:
            result = self.module._real_send_phone_number_otp(
                transport,
                "+1 (555) 000-1234",
                "sms",
            )
        finally:
            self.module._AUTH_SESSIONS.clear("task-phone")

        self.assertEqual(result["_status"], 200)
        self.assertEqual(calls[0][0], "https://auth.openai.com/api/accounts/add-phone/send")
        self.assertEqual(calls[0][1]["json"], {"phone_number": "+15550001234"})
        headers = {key.lower(): value for key, value in calls[0][1]["headers"].items()}
        self.assertNotIn("openai-sentinel-token", headers)
        self.assertNotIn("openai-sentinel-so-token", headers)
        self.assertEqual(headers["referer"], "https://auth.openai.com/add-phone")
        self.assertTrue(headers["x-access-flow-invocation-id"])
        self.assertEqual(sentinel_calls[0][0], "reset")
        self.assertEqual(sentinel_calls[1][0], "token_for")

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

    def test_node_bridge_retry_event_is_persisted_without_terminal_log(self):
        module = self.module
        original_event = module._ORIGINAL_CHAIN_EVENT
        original_context = module._TASK_CONTEXT.set("T-node-retry")
        captured = []
        logs = []
        try:
            module._ORIGINAL_CHAIN_EVENT = lambda *args, **kwargs: captured.append((args, kwargs))
            module._patched_chain_event(
                [],
                "FAILED",
                detail="node_sentinel_failed: node_bridge_timeout",
                log_fn=lambda *args: logs.append(args),
            )
        finally:
            module._ORIGINAL_CHAIN_EVENT = original_event
            module._TASK_CONTEXT.reset(original_context)

        self.assertEqual(len(captured), 1)
        self.assertIsNone(captured[0][1]["log_fn"])
        self.assertEqual(len(logs), 1)
        self.assertIn("Node/Sentinel 重试", logs[0][0])
        self.assertIn("正在自动重试", logs[0][0])
        self.assertEqual(logs[0][1], "warn")

    def test_mfa_request_enters_verification_stage_before_transport_failure(self):
        module = self.module
        original_post = module._ORIGINAL_REAL_POST_AUTH_JSON
        original_begin = module._auth_request_runtime_ext.begin_request
        token = module._TASK_CONTEXT.set("T-mfa-stage")
        module._TASK_PROGRESS.reset()
        try:
            module._auth_request_runtime_ext.begin_request = (
                lambda *_args, **kwargs: {"stage": kwargs["stage"]}
            )
            module._ORIGINAL_REAL_POST_AUTH_JSON = (
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("node_sentinel_failed:mfa_otp_verify: node_bridge_timeout")
                )
            )

            with self.assertRaisesRegex(RuntimeError, "node_bridge_timeout"):
                module._real_post_auth_json(
                    SimpleNamespace(),
                    "/api/accounts/mfa/verify",
                    {"code": "redacted"},
                    flow="mfa_otp_verify",
                    referer="https://auth.openai.com/mfa-challenge/redacted",
                )

            self.assertEqual(
                module._TASK_PROGRESS.progress("T-mfa-stage")["code"],
                "email_code_verifying",
            )
        finally:
            module._ORIGINAL_REAL_POST_AUTH_JSON = original_post
            module._auth_request_runtime_ext.begin_request = original_begin
            module._TASK_PROGRESS.reset()
            module._TASK_CONTEXT.reset(token)

    def test_sentinel_emit_formats_internal_failure_as_non_terminal_retry(self):
        module = self.module
        original_emit = module._ORIGINAL_CHAIN_EMIT
        captured = []
        try:
            module._ORIGINAL_CHAIN_EMIT = lambda *args: captured.append(args)
            module._patched_chain_emit(
                lambda *_args: None,
                "  [SentinelRunner] token 生成失败，重试 flow=chat-requirements: timeout",
                "info",
            )
        finally:
            module._ORIGINAL_CHAIN_EMIT = original_emit

        self.assertEqual(len(captured), 1)
        self.assertIn("[Node/Sentinel 重试/oauth_create_node]", captured[0][1])
        self.assertIn("正在自动重试", captured[0][1])
        self.assertEqual(captured[0][2], "warn")

    def test_sentinel_success_clears_only_stale_node_failure(self):
        module = self.module
        original_emit = module._ORIGINAL_CHAIN_EMIT
        token = module._TASK_CONTEXT.set("T-node-success")
        try:
            module._remember_task_failure(
                "T-node-success",
                module._error_observability_ext.classify_failure(
                    error="node_sentinel_failed: node bridge timeout"
                ),
            )
            module._ORIGINAL_CHAIN_EMIT = lambda *_args: None
            module._patched_chain_emit(
                lambda *_args: None,
                "  [SentinelRunner] token 生成成功, flow=chat-requirements, 包含 so=True",
                "info",
            )
            self.assertIsNone(module._known_task_failure("T-node-success"))
        finally:
            module._ORIGINAL_CHAIN_EMIT = original_emit
            module._TASK_CONTEXT.reset(token)

    def test_expected_pkce_runtime_context_is_persisted_without_public_warning(self):
        module = self.module
        original_event = module._ORIGINAL_CHAIN_EVENT
        captured = []
        logs = []
        try:
            module._ORIGINAL_CHAIN_EVENT = lambda *args, **kwargs: captured.append((args, kwargs))
            module._patched_chain_event(
                [],
                "RUNTIME_CONTEXT_ISSUE",
                detail="warn:code_verifier_present",
                log_fn=lambda *args: logs.append(args),
                tag="warn",
            )
        finally:
            module._ORIGINAL_CHAIN_EVENT = original_event

        self.assertEqual(len(captured), 1)
        self.assertIsNone(captured[0][1]["log_fn"])
        self.assertEqual(logs, [])

    def test_public_logs_do_not_rewrite_node_retry_as_terminal_failure(self):
        module = self.module
        retry = (
            "T001-safe [Node/Sentinel 重试/oauth_create_node] "
            "本次尝试未完成，正在自动重试：Node/Sentinel 请求超时"
        )
        terminal = module._error_observability_ext.classify_failure(
            error="node_sentinel_failed: node bridge timeout"
        )

        public = module._public_logs(
            [{"level": "error", "message": retry}],
            [{"task_id": "T001-safe", "failure": terminal}],
        )

        self.assertEqual(public[0]["message"], retry)
        self.assertEqual(public[0]["level"], "warn")
        self.assertNotIn("初始化 Node/Sentinel失败", public[0]["message"])

    def test_public_logs_rewrite_historical_node_failure_after_task_success(self):
        module = self.module
        public = module._public_logs(
            [{
                "level": "error",
                "message": (
                    "T001-success [初始化 Node/Sentinel/oauth_create_node] "
                    "初始化 Node/Sentinel失败：Node bridge timeout"
                ),
            }],
            [{"task_id": "T001-success", "status": "success"}],
        )

        self.assertEqual(public[0]["level"], "warn")
        self.assertIn("Node/Sentinel 重试/oauth_create_node", public[0]["message"])
        self.assertIn("正在自动重试", public[0]["message"])
        self.assertNotIn("初始化 Node/Sentinel失败", public[0]["message"])

    def test_public_logs_rewrite_node_failure_for_active_or_later_email_failure(self):
        module = self.module
        raw_log = {
            "level": "error",
            "message": (
                "T003-d36c48 [初始化 Node/Sentinel/oauth_create_node] "
                "初始化 Node/Sentinel失败：Node bridge timeout"
            ),
        }
        email_failure = module._error_observability_ext.classify_failure(
            error="mailbox_code_timeout: attempts=30/30"
        )
        tasks = (
            {"task_id": "T003-d36c48", "status": "running"},
            {
                "task_id": "T003-d36c48",
                "status": "retryable_email",
                "failure": email_failure,
            },
        )

        for task in tasks:
            with self.subTest(status=task["status"]):
                public = module._public_logs([raw_log], [task])
                self.assertEqual(public[0]["level"], "warn")
                self.assertIn("Node/Sentinel 重试/oauth_create_node", public[0]["message"])
                self.assertNotIn("初始化 Node/Sentinel失败", public[0]["message"])

    def test_public_logs_keep_true_terminal_node_failure_red(self):
        module = self.module
        terminal = module._error_observability_ext.classify_failure(
            error="node_sentinel_failed: node bridge timeout"
        )

        public = module._public_logs(
            [{
                "level": "error",
                "message": (
                    "T001-terminal [初始化 Node/Sentinel/oauth_create_node] "
                    "初始化 Node/Sentinel失败：Node bridge timeout"
                ),
            }],
            [{"task_id": "T001-terminal", "status": "failed", "failure": terminal}],
        )

        self.assertEqual(public[0]["level"], "error")
        self.assertIn("初始化 Node/Sentinel/oauth_create_node", public[0]["message"])

    def test_public_logs_rewrite_orphaned_node_line_without_terminal_evidence(self):
        module = self.module
        module._TASK_FAILURES.pop("T003-d36c48", None)

        public = module._public_logs(
            [{
                "level": "error",
                "message": (
                    "T003-d36c48 [初始化 Node/Sentinel/oauth_create_node] "
                    "初始化 Node/Sentinel失败：Node/Sentinel 授权桥接初始化失败"
                ),
            }],
            [],
        )

        self.assertEqual(public[0]["level"], "warn")
        self.assertIn("Node/Sentinel 重试/oauth_create_node", public[0]["message"])
        self.assertNotIn("初始化 Node/Sentinel失败", public[0]["message"])

    def test_public_task_repairs_stale_node_failure_after_mfa_started(self):
        module = self.module
        stale_failure = module._error_observability_ext.classify_failure(
            error="node_sentinel_failed: node_bridge_timeout"
        )
        task = {
            "task_id": "T010-stale",
            "status": "failed",
            "technical_error": (
                "mfa_otp_failed: node_sentinel_failed:mfa_otp_verify: "
                "node_bridge_timeout"
            ),
            "failure": stale_failure,
            "result": {
                "technical_error": (
                    "mfa_otp_failed: node_sentinel_failed:mfa_otp_verify: "
                    "node_bridge_timeout"
                ),
                "failure": stale_failure,
                "codex_chain_events": [
                    {"state": "SENTINEL_READY"},
                    {"state": "PASSWORD_VERIFIED"},
                    {"state": "MFA_OTP_REQUIRED"},
                ],
            },
        }

        public = module._public_task(task)

        self.assertEqual(public["failure"]["node_code"], "email_code_verifying")
        self.assertEqual(public["failure"]["error_code"], "node_sentinel_timeout")
        self.assertNotIn("初始化 Node/Sentinel失败", public["error"])

    def test_recovered_web_safe_log_uses_the_diagnostic_mapper(self):
        message = self.module._module._safe(
            "T001-safe [SentinelRunner] token 生成失败，重试 flow=chat-requirements"
        )

        self.assertIn("Node/Sentinel 重试", message)
        self.assertIn("正在自动重试", message)
        self.assertNotIn("初始化 Node/Sentinel/oauth_create_node", message)

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

    def test_public_logs_do_not_treat_masked_task_source_as_a_secret(self):
        task = {
            "task_id": "T001-masked",
            "source_row": "user@example.test----***----***----***",
            "status": "success",
        }

        public = self.module._public_logs(
            [{"level": "info", "message": "credential=********"}],
            [task],
        )

        self.assertEqual(public[0]["message"], "credential=********")

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

    def test_email_timeout_migration_updates_legacy_default_and_preserves_custom_value(self):
        module = self.module
        legacy, legacy_changed = module._migrate_email_timeout_config(
            {"email_code_timeout": 150}
        )
        custom, custom_changed = module._migrate_email_timeout_config(
            {"email_code_timeout": 90}
        )

        self.assertTrue(legacy_changed)
        self.assertEqual(legacy["email_code_timeout"], 90)
        self.assertEqual(legacy["email_timeout_strategy_version"], 2)
        self.assertTrue(custom_changed)
        self.assertEqual(custom["email_code_timeout"], 90)
        self.assertEqual(custom["email_timeout_strategy_version"], 2)

    def test_config_store_persists_migrated_and_explicit_email_timeout(self):
        module = self.module
        config_dir = Path(self.tempdir.name) / "email-timeout-config"
        store = module._runtime.ImporterConfigStore(config_dir)
        Path(store.path).parent.mkdir(parents=True, exist_ok=True)
        Path(store.path).write_text(
            json.dumps({"email_code_timeout": 150}),
            encoding="utf-8",
        )

        loaded = store.load()
        persisted = json.loads(Path(store.path).read_text(encoding="utf-8"))

        self.assertEqual(loaded["email_code_timeout"], 90)
        self.assertEqual(loaded["email_otp_verify_attempts"], 2)
        self.assertTrue(loaded["email_otp_resend_on_retry"])
        self.assertEqual(persisted["email_timeout_strategy_version"], 2)

        saved = store.save({
            **loaded,
            "email_code_timeout": 90,
            "email_otp_verify_attempts": 3,
            "email_otp_resend_on_retry": False,
        })

        self.assertEqual(saved["email_code_timeout"], 90)
        self.assertEqual(saved["email_timeout_strategy_version"], 2)
        self.assertEqual(saved["email_otp_verify_attempts"], 3)
        self.assertFalse(saved["email_otp_resend_on_retry"])

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
