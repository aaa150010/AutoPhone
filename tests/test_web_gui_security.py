from __future__ import annotations

import copy
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import MethodType, SimpleNamespace
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

    def test_multi_platform_key_counts_survive_masked_save_and_reload(self):
        existing = {
            "sms_provider": "smsbower",
            "sms_provider_pools": [
                {
                    "provider": "smsbower",
                    "enabled": True,
                    "api_keys": ["bower-a", "bower-b"],
                    "service": "dr",
                },
                {
                    "provider": "herosms",
                    "enabled": True,
                    "api_keys": ["hero-a"],
                    "service": "dr",
                },
            ],
        }
        masked = self.module._masked_local_config(existing)

        resolved = self.module._local_config_from_runtime(masked, existing)
        reloaded = self.module._local_config_from_runtime(
            self.module._masked_local_config(resolved),
            resolved,
        )

        for config in (resolved, reloaded):
            pools = {row["provider"]: row["api_keys"] for row in config["sms_provider_pools"]}
            self.assertEqual(pools["smsbower"], ["bower-a", "bower-b"])
            self.assertEqual(pools["herosms"], ["hero-a"])
            self.assertEqual(config["sms_api_keys"], ["bower-a", "bower-b"])
            self.assertNotIn("hero-a", config["sms_api_keys"])

    def test_sms_provider_aliases_preserve_new_key_when_masked_config_is_saved(self):
        existing = {
            "sms_provider": "herosms",
            "sms_provider_pools": [
                {
                    "provider": "herosms",
                    "enabled": True,
                    "api_keys": ["hero-a"],
                    "service": "dr",
                },
            ],
        }
        draft = {
            "sms_provider": "hero-sms",
            "sms_provider_pools": [
                {
                    "provider": "hero-sms",
                    "enabled": True,
                    "api_keys": ["********", "hero-b"],
                    "service": "dr",
                },
            ],
        }

        resolved = self.module._local_config_from_runtime(draft, existing)

        self.assertEqual(resolved["sms_provider"], "herosms")
        pools = {row["provider"]: row["api_keys"] for row in resolved["sms_provider_pools"]}
        self.assertEqual(pools["herosms"], ["hero-a", "hero-b"])

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

    def test_sms_transport_registry_recovers_when_contextvar_is_empty(self):
        transport = SimpleNamespace(config={"sms_task_id": "task-transport"})
        self.module._register_sms_transport("task-transport", transport)
        try:
            self.assertIs(
                self.module._transport_for_task("task-transport"),
                transport,
            )
        finally:
            self.module._unregister_sms_transport("task-transport", transport)

    def test_sms_transport_registry_does_not_cross_task_boundaries(self):
        transport = SimpleNamespace(config={"sms_task_id": "task-a"})
        self.module._register_sms_transport("task-a", transport)
        try:
            self.assertIsNone(self.module._transport_for_task("task-b"))
        finally:
            self.module._unregister_sms_transport("task-a", transport)

    def test_sms_transport_registry_cleanup_is_identity_safe(self):
        first = SimpleNamespace(config={"sms_task_id": "task-identity"})
        second = SimpleNamespace(config={"sms_task_id": "task-identity"})
        self.module._register_sms_transport("task-identity", first)
        self.module._register_sms_transport("task-identity", second)
        self.module._unregister_sms_transport("task-identity", first)
        try:
            self.assertIs(self.module._transport_for_task("task-identity"), second)
        finally:
            self.module._unregister_sms_transport("task-identity", second)

    def test_sms_transport_registry_drops_reused_transport_from_old_task(self):
        transport = SimpleNamespace(config={"sms_task_id": "task-old"})
        self.module._register_sms_transport("task-old", transport)
        transport.config = {"sms_task_id": "task-new"}
        self.module._register_sms_transport("task-new", transport)
        try:
            self.assertIsNone(self.module._transport_for_task("task-old"))
            self.assertIs(self.module._transport_for_task("task-new"), transport)
        finally:
            self.module._unregister_sms_transport("task-new", transport)

    def test_sms_preflight_missing_transport_blocks_paid_allocation(self):
        module = self.module
        original_preflight = module._SMS_WEB.phone_context_preflight
        original_allocate = module._SMS_WEB.original_adapter_get_number
        calls = []
        token = module._ACTIVE_SMS_TRANSPORT.set(None)
        try:
            module._SMS_WEB.phone_context_preflight = module._preflight_sms_phone_context
            module._SMS_WEB.original_adapter_get_number = (
                lambda *_args, **_kwargs: calls.append(True)
            )
            adapter = SimpleNamespace(
                config={"sms_task_id": "task-no-transport"},
                provider=SimpleNamespace(),
                selector=None,
            )
            with self.assertRaisesRegex(Exception, "auth_context_transport_missing"):
                module._SMS_WEB.adapter_get_number(adapter)
        finally:
            module._SMS_WEB.phone_context_preflight = original_preflight
            module._SMS_WEB.original_adapter_get_number = original_allocate
            module._ACTIVE_SMS_TRANSPORT.reset(token)
        self.assertEqual(calls, [])

    def test_sms_preflight_regressions_block_paid_allocation_and_mark_risk(self):
        module = self.module
        original_preflight = module._SMS_WEB.phone_context_preflight
        original_allocate = module._SMS_WEB.original_adapter_get_number
        try:
            module._SMS_WEB.phone_context_preflight = module._preflight_sms_phone_context
            for suffix, page_type, cookies, expected_code in (
                ("unknown", "unknown", {"session": "present"}, "auth_context_page_mismatch"),
                ("mfa", "mfa_otp_verification", {"session": "present"}, "phone_flow_mfa_regressed"),
                ("login", "password_verification", {"session": "present"}, "phone_flow_login_regressed"),
                ("cookies", "add_phone", {}, "auth_context_cookies_missing"),
            ):
                with self.subTest(page_type=page_type):
                    calls = []
                    task_id = f"task-preflight-{suffix}"
                    email = f"preflight-{suffix}@example.test"
                    transport = SimpleNamespace(
                        config={
                            "sms_task_id": task_id,
                            "_auth_account_email": email,
                        },
                        account_email=email,
                        session=SimpleNamespace(cookies=dict(cookies)),
                        sentinel_provider=SimpleNamespace(reset=lambda: None),
                        proxy="",
                        _gptphone_page_type=page_type,
                    )
                    module._register_sms_transport(task_id, transport)
                    token = module._ACTIVE_SMS_TRANSPORT.set(None)
                    module._SMS_WEB.original_adapter_get_number = (
                        lambda *_args, **_kwargs: calls.append(True)
                    )
                    adapter = SimpleNamespace(
                        config={"sms_task_id": task_id},
                        provider=SimpleNamespace(),
                        selector=None,
                    )
                    try:
                        with self.assertRaisesRegex(Exception, expected_code):
                            module._SMS_WEB.adapter_get_number(adapter)
                        marker = module._PHONE_RISK_STORE.status(email)
                    finally:
                        module._ACTIVE_SMS_TRANSPORT.reset(token)
                        module._unregister_sms_transport(task_id, transport)
                        module._AUTH_SESSIONS.clear(task_id)
                        module._PHONE_RISK_STORE.clear(email)
                    self.assertEqual(calls, [])
                    self.assertTrue(marker["active"])
                    self.assertEqual(marker["reason_code"], expected_code)
        finally:
            module._SMS_WEB.phone_context_preflight = original_preflight
            module._SMS_WEB.original_adapter_get_number = original_allocate

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
        self.assertEqual(three_platforms["sms_smart"]["route_lease_seconds"], 80)

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

    def test_phone_risk_marker_restores_reliability_mode_across_tasks(self):
        module = self.module
        original_task_config = module._ORIGINAL_TASK_CONFIG
        email = "persisted-risk@example.test"
        module._PHONE_RISK_STORE.mark(
            email,
            reason_code="oauth_session_invalid",
            stage="phone_submitting",
        )
        try:
            module._ORIGINAL_TASK_CONFIG = lambda *_args, **_kwargs: {"code_timeout": 30}
            first = module._patched_task_config(
                SimpleNamespace(data_dir=self.tempdir.name),
                {},
                email,
                "risk-task-1",
            )
            second = module._patched_task_config(
                SimpleNamespace(data_dir=self.tempdir.name),
                {},
                email.upper(),
                "risk-task-2",
            )
        finally:
            module._ORIGINAL_TASK_CONFIG = original_task_config
            module._PHONE_RISK_STORE.clear(email)

        for config in (first, second):
            self.assertTrue(config["_phone_risk_retry"])
            self.assertEqual(
                config["_phone_risk_reason_code"],
                "oauth_session_invalid",
            )

    def test_register_start_applies_one_run_mailbox_selection_filter(self):
        module = self.module
        original_start = module._importer_scheduler_ext.start_bounded_importer
        original_notifications = module._begin_notification_run
        observed = []
        importer = SimpleNamespace(status=lambda _settings: {"running": False})
        try:
            module._begin_notification_run = lambda *_args: None
            module._importer_scheduler_ext.start_bounded_importer = (
                lambda *_args, **_kwargs: observed.append(
                    module._MAILBOX_LEASE_FILTER_ACTIVE.get()
                )
            )
            module._patched_importer_start(importer, {"concurrency": 2})
            module._patched_importer_start(importer, {"concurrency": 2, "run_mode": "relogin"})
        finally:
            module._importer_scheduler_ext.start_bounded_importer = original_start
            module._begin_notification_run = original_notifications

        self.assertEqual(observed, [True, False])
        self.assertFalse(module._MAILBOX_LEASE_FILTER_ACTIVE.get())

    def test_register_start_caps_total_auth_sessions_at_five(self):
        module = self.module
        original_start = module._importer_scheduler_ext.start_bounded_importer
        original_notifications = module._begin_notification_run
        observed = []
        importer = SimpleNamespace(status=lambda _settings: {"running": False})
        try:
            module._begin_notification_run = lambda *_args: None
            module._importer_scheduler_ext.start_bounded_importer = (
                lambda _importer, settings, **_kwargs: observed.append(
                    settings["auth_session_retries"]
                )
            )
            module._patched_importer_start(importer, {"auth_session_retries": 99})
        finally:
            module._importer_scheduler_ext.start_bounded_importer = original_start
            module._begin_notification_run = original_notifications

        self.assertEqual(observed, [5])

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

    def test_imap_email_otp_resend_excludes_the_previously_submitted_code(self):
        module = self.module
        calls = []
        logs = []

        class FakePoller:
            last_error = ""

            def poll_code(self, **kwargs):
                excluded = set(kwargs.get("exclude_codes") or ())
                calls.append(excluded)
                for candidate in ("111111", "222222"):
                    if candidate not in excluded:
                        return candidate
                return None

        otp_provider = SimpleNamespace(
            entry=SimpleNamespace(email="user@example.test"),
            poller=FakePoller(),
            timeout=90,
            interval=5,
            sent_at=time.time() - 5,
            log_fn=lambda message, level="info": logs.append((message, level)),
        )

        first = module._outlook_mailbox_wait_code(otp_provider, "user@example.test")
        otp_provider.sent_at = time.time() - 5
        second = module._outlook_mailbox_wait_code(otp_provider, "user@example.test")

        self.assertEqual(first, "111111")
        self.assertEqual(second, "222222")
        self.assertEqual(calls, [set(), {"111111"}])
        self.assertNotIn("poll_code", otp_provider.poller.__dict__)
        serialized_logs = json.dumps(logs, ensure_ascii=False)
        self.assertIn("上一轮验证码", serialized_logs)
        self.assertNotIn("111111", serialized_logs)
        self.assertNotIn("222222", serialized_logs)

    def test_imap_email_otp_first_attempt_preserves_original_polling(self):
        module = self.module
        calls = []

        class FakePoller:
            last_error = ""

            def poll_code(self, **kwargs):
                calls.append(dict(kwargs))
                return "333333"

        otp_provider = SimpleNamespace(
            entry=SimpleNamespace(email="user@example.test"),
            poller=FakePoller(),
            timeout=90,
            interval=5,
            sent_at=time.time() - 5,
            log_fn=lambda *_args: None,
        )

        code = module._outlook_mailbox_wait_code(otp_provider, "user@example.test")

        self.assertEqual(code, "333333")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("exclude_codes", calls[0])

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

    def test_relogin_task_config_uses_only_server_validated_sub2_binding(self):
        module = self.module
        original_task_config = module._ORIGINAL_TASK_CONFIG
        settings = {
            "run_mode": "relogin",
            "_gptphone_relogin_rows": [
                {
                    "email": "Relogin@Example.Test",
                    "sub2api_account_id": "sub2-account-501",
                    "status_code": 404,
                    "status_kind": "not_found",
                }
            ],
        }
        try:
            module._ORIGINAL_TASK_CONFIG = lambda *_args, **_kwargs: {"code_timeout": 30}
            config = module._patched_task_config(
                SimpleNamespace(data_dir=self.tempdir.name),
                settings,
                "relogin@example.test",
                "task-relogin-binding",
            )
        finally:
            module._ORIGINAL_TASK_CONFIG = original_task_config

        self.assertEqual(config["run_mode"], "relogin")
        self.assertEqual(config["_sub2_update_existing"]["account_id"], "sub2-account-501")
        self.assertEqual(config["_sub2_update_existing"]["status_code"], 404)
        self.assertEqual(config["sms_api_key"], "relogin-disabled")

    def test_relogin_task_config_rejects_missing_server_binding(self):
        module = self.module
        original_task_config = module._ORIGINAL_TASK_CONFIG
        try:
            module._ORIGINAL_TASK_CONFIG = lambda *_args, **_kwargs: {"code_timeout": 30}
            with self.assertRaisesRegex(RuntimeError, "relogin_sub2_binding_missing"):
                module._patched_task_config(
                    SimpleNamespace(data_dir=self.tempdir.name),
                    {"run_mode": "relogin", "_gptphone_relogin_rows": []},
                    "relogin@example.test",
                    "task-relogin-missing",
                )
        finally:
            module._ORIGINAL_TASK_CONFIG = original_task_config

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

    def test_relogin_sub2_upload_missing_binding_never_calls_create_path(self):
        module = self.module
        original_upload = module._ORIGINAL_REAL_SUB2_UPLOAD
        calls = []
        try:
            module._ORIGINAL_REAL_SUB2_UPLOAD = lambda *_args, **_kwargs: calls.append(kwargs)
            result = module._real_sub2_upload(
                SimpleNamespace(config={"run_mode": "relogin"}),
                credentials={"access_token": "must-not-be-sent"},
                email="relogin@example.test",
            )
        finally:
            module._ORIGINAL_REAL_SUB2_UPLOAD = original_upload

        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "relogin_sub2_binding_missing")
        self.assertFalse(result["sub2_upload_created"])
        self.assertEqual(calls, [])

    def test_relogin_phone_page_stops_before_original_sms_provider_call(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION

        class SmsProvider:
            def __init__(self):
                self.get_number_calls = 0

            def get_number(self, **_kwargs):
                self.get_number_calls += 1
                raise AssertionError("real SMS provider must not run")

        provider = SmsProvider()

        def enter_phone_page(**kwargs):
            return kwargs["phone_otp_provider"].get_number()

        try:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = enter_phone_page
            with self.assertRaisesRegex(Exception, "relogin_phone_required"):
                module._run_codex_after_registration(
                    oauth_url="https://auth.example.test/authorize",
                    account_email="relogin@example.test",
                    sms_provider=provider,
                    phone_otp_provider=provider,
                    config={
                        "run_mode": "relogin",
                        "sms_task_id": "task-relogin-phone",
                    },
                )
        finally:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = original_run

        self.assertEqual(provider.get_number_calls, 0)

    def test_relogin_supported_email_providers_pass_through_existing_auth_chain(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION

        class EmailProvider:
            def __init__(self, kind):
                self.kind = kind

            def wait_code(self, _email):
                return "123456"

        def succeed(**kwargs):
            provider = kwargs["email_otp_provider"]
            return {
                "ok": provider.wait_code(kwargs["account_email"]) == "123456",
                "provider_kind": provider.kind,
                "phone_guarded": isinstance(
                    kwargs["phone_otp_provider"], module._ReloginPhoneOtpProvider
                ),
            }

        try:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = succeed
            for provider_kind in ("totp", "mailbox_url", "outlook_oauth"):
                with self.subTest(provider_kind=provider_kind):
                    result = module._run_codex_after_registration(
                        oauth_url="https://auth.example.test/authorize",
                        account_email=f"{provider_kind}@example.test",
                        email_otp_provider=EmailProvider(provider_kind),
                        config={
                            "run_mode": "relogin",
                            "sms_task_id": f"task-relogin-{provider_kind}",
                        },
                    )
                    self.assertTrue(result["ok"])
                    self.assertEqual(result["provider_kind"], provider_kind)
                    self.assertTrue(result["phone_guarded"])
        finally:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = original_run

    def test_protocol_wait_and_limit_changes_are_recorded_without_proxy_details(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION
        original_gate = module._PROTOCOL_GATE
        outcomes = [
            {"ok": False, "error": "TLS connection reset"},
            {"ok": True},
        ]
        logs = []

        class Lease:
            def __init__(self, on_wait):
                self.on_wait = on_wait

            def __enter__(self):
                self.on_wait(1.25)
                return "proxy:masked"

            def __exit__(self, *_args):
                return False

        class Gate:
            def acquire(self, _proxy, *, stop_event=None, on_wait=None):
                del stop_event
                return Lease(on_wait)

            def report(
                self,
                _proxy,
                _value=None,
                *,
                success=False,
                on_limit_change=None,
            ):
                event = {
                    "kind": "restored" if success else "degraded",
                    "old_limit": 4 if success else 5,
                    "new_limit": 5 if success else 4,
                    "ceiling": 5,
                    "proxy_key": "proxy:masked",
                }
                on_limit_change(event)
                return event["new_limit"]

        module._TASK_PROGRESS.reset()
        try:
            module._PROTOCOL_GATE = Gate()
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = lambda **_kwargs: outcomes.pop(0)
            for task_id in ("task-protocol-down", "task-protocol-up"):
                module._TASK_PROGRESS.set_stage(task_id, "oauth_create_node")
                module._run_codex_after_registration(
                    oauth_url="https://auth.example.test/authorize",
                    account_email="timing@example.test",
                    proxy="http://private-user:private-pass@127.0.0.1:7897",
                    config={"sms_task_id": task_id},
                    log_fn=lambda message, level="info": logs.append((message, level)),
                )
        finally:
            segments = {
                task_id: (module._TASK_PROGRESS.progress(task_id) or {}).get("timing", {}).get(
                    "segments", []
                )
                for task_id in ("task-protocol-down", "task-protocol-up")
            }
            module._TASK_PROGRESS.reset()
            module._PROTOCOL_GATE = original_gate
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = original_run

        for rows in segments.values():
            self.assertEqual(rows[0]["code"], "protocol_slot_waiting")
            self.assertEqual(rows[0]["elapsed_seconds"], 1.25)
        self.assertTrue(any("5 -> 4" in message for message, _level in logs))
        self.assertTrue(any("4 -> 5" in message for message, _level in logs))
        self.assertNotIn("private-user", str(logs))
        self.assertNotIn("private-pass", str(logs))

    def test_relogin_whole_chain_retry_policy_rejects_credential_and_state_failures(self):
        module = self.module
        token = module._RUN_MODE_CONTEXT.set("relogin")
        try:
            self.assertTrue(
                module._patched_pre_auth_session_retryable(
                    {"_status": 429, "error": "too many requests"}
                )
            )
            self.assertTrue(
                module._patched_pre_auth_session_retryable(
                    {"error": "curl: (35) TLS connect error"}
                )
            )
            for error in (
                "password_verify_failed: invalid password",
                "mfa_otp_failed: invalid code",
                "oauth_callback_state_mismatch: invalid_state",
                "account_deactivated",
                "relogin_phone_required",
            ):
                with self.subTest(error=error):
                    self.assertFalse(
                        module._patched_pre_auth_session_retryable({"error": error})
                    )
        finally:
            module._RUN_MODE_CONTEXT.reset(token)

    def test_register_session_invalid_retry_respects_importer_configured_limit(self):
        module = self.module
        task_token = module._TASK_CONTEXT.set("task-phone-session-retry")
        mode_token = module._RUN_MODE_CONTEXT.set("register")
        try:
            context = module._AUTH_SESSIONS.get("task-phone-session-retry")
            context.current_stage = "phone_submitting"
            context.invalidations = 7

            self.assertTrue(
                module._patched_pre_auth_session_retryable(
                    {"error": "oauth_session_invalid: sign-in session is no longer valid"}
                )
            )
        finally:
            module._AUTH_SESSIONS.clear("task-phone-session-retry")
            module._RUN_MODE_CONTEXT.reset(mode_token)
            module._TASK_CONTEXT.reset(task_token)

    def test_relogin_password_error_does_not_trigger_password_to_otp_fallback(self):
        module = self.module
        original = module._ORIGINAL_PASSWORD_CREDENTIALS_REJECTED
        calls = []
        try:
            module._ORIGINAL_PASSWORD_CREDENTIALS_REJECTED = (
                lambda result: calls.append(result) or True
            )
            token = module._RUN_MODE_CONTEXT.set("relogin")
            try:
                self.assertFalse(
                    module._patched_password_credentials_rejected(
                        {"error": "password_verify_failed: invalid password"}
                    )
                )
            finally:
                module._RUN_MODE_CONTEXT.reset(token)

            self.assertTrue(module._patched_password_credentials_rejected({"error": "normal"}))
        finally:
            module._ORIGINAL_PASSWORD_CREDENTIALS_REJECTED = original

        self.assertEqual(calls, [{"error": "normal"}])

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
        self.module._TASK_PROGRESS.reset()
        self.module._TASK_PROGRESS.set_stage("task-phone", "phone_submitting")
        other_token = self.module._TASK_CONTEXT.set("task-other")
        try:
            result = self.module._real_send_phone_number_otp(
                transport,
                "+1 (555) 000-1234",
                "sms",
            )
        finally:
            timing = self.module._TASK_PROGRESS.progress("task-phone")["timing"]
            other_progress = self.module._TASK_PROGRESS.progress("task-other")
            self.module._TASK_CONTEXT.reset(other_token)
            self.module._TASK_PROGRESS.reset()
            self.module._AUTH_SESSIONS.clear("task-phone")

        self.assertEqual(result["_status"], 200)
        self.assertEqual(calls[0][0], "https://auth.openai.com/api/accounts/add-phone/send")
        self.assertEqual(
            calls[0][1]["json"],
            {"phone_number": "+15550001234", "channel": "sms"},
        )
        headers = {key.lower(): value for key, value in calls[0][1]["headers"].items()}
        self.assertNotIn("openai-sentinel-token", headers)
        self.assertNotIn("openai-sentinel-so-token", headers)
        self.assertEqual(headers["referer"], "https://auth.openai.com/add-phone")
        self.assertTrue(headers["x-access-flow-invocation-id"])
        self.assertEqual(sentinel_calls[0][0], "reset")
        self.assertEqual(sentinel_calls[1][0], "token_for")
        segments = {row["code"]: row for row in timing["segments"]}
        self.assertEqual(segments["phone_submit_http"]["visits"], 1)
        self.assertEqual(segments["sentinel_refresh"]["visits"], 1)
        self.assertNotIn("segments", (other_progress or {}).get("timing", {}))

    def test_real_phone_send_rejects_forced_whatsapp_channel(self):
        calls = []

        class FakeResponse:
            status_code = 200
            headers = {"content-type": "application/json"}
            url = "https://auth.openai.com/api/accounts/add-phone/send"
            payload = {
                "page": {"type": "phone_otp_verification"},
                "channel": "whatsapp",
            }
            text = json.dumps(payload)

            def json(self):
                return dict(self.payload)

        class FakeSession:
            cookies = {"session": "present"}

            def post(self, url, **kwargs):
                calls.append((url, kwargs))
                return FakeResponse()

        class FakeSentinel:
            def reset(self, flow=""):
                del flow

            def token_for(self, flow, context):
                del flow, context
                return {"token": "sentinel-value"}

        transport = SimpleNamespace(
            config={"sms_task_id": "task-forced-whatsapp"},
            session=FakeSession(),
            sentinel_provider=FakeSentinel(),
            device_id="device-1",
            proxy="",
            _gptphone_page_type="add_phone",
        )
        self.module._AUTH_SESSIONS.clear("task-forced-whatsapp")
        self.module._TASK_PROGRESS.reset()
        self.module._TASK_PROGRESS.set_stage(
            "task-forced-whatsapp",
            "phone_submitting",
        )
        task_token = self.module._TASK_CONTEXT.set("task-forced-whatsapp")
        try:
            result = self.module._real_send_phone_number_otp(
                transport,
                "+15550001234",
                "sms",
            )
        finally:
            timing = self.module._TASK_PROGRESS.progress("task-forced-whatsapp")[
                "timing"
            ]
            self.module._TASK_CONTEXT.reset(task_token)
            self.module._TASK_PROGRESS.reset()
            self.module._AUTH_SESSIONS.clear("task-forced-whatsapp")

        self.assertEqual(
            calls[0][1]["json"],
            {"phone_number": "+15550001234", "channel": "sms"},
        )
        self.assertEqual(result["_status"], 409)
        self.assertEqual(result["_upstream_status"], 200)
        self.assertEqual(result["error"]["code"], "phone_channel_mismatch")
        self.assertIn("phone_channel_mismatch", result["error"]["message"])
        self.assertIn("channel", result["_body_summary"])
        self.assertEqual(result["requested_channel"], "sms")
        self.assertEqual(result["actual_channel"], "whatsapp")
        error_text = self.module._codex_oauth_chain._error_text(result)
        self.assertIn("phone_channel_mismatch", error_text)
        self.assertEqual(self.module._SMS_WEB.classify_error(error_text), "phone_rejected")
        segment_codes = [row["code"] for row in timing["segments"]]
        self.assertEqual(segment_codes, ["phone_submit_http"])

    def test_phone_http_and_sentinel_failures_still_record_their_segments(self):
        module = self.module

        class FailingSession:
            cookies = {"session": "present"}

            def post(self, _url, **_kwargs):
                raise RuntimeError("private HTTP failure")

        def transport_for(task_id, session):
            return SimpleNamespace(
                config={"sms_task_id": task_id, "_auth_account_email": "user@example.test"},
                account_email="user@example.test",
                session=session,
                sentinel_provider=SimpleNamespace(),
                device_id="device-1",
                proxy="",
                _gptphone_page_type="add_phone",
            )

        task_id = "task-phone-http-failure"
        module._AUTH_SESSIONS.clear(task_id)
        module._TASK_PROGRESS.reset()
        module._TASK_PROGRESS.set_stage(task_id, "phone_submitting")
        token = module._TASK_CONTEXT.set(task_id)
        try:
            result = module._real_send_phone_number_otp(
                transport_for(task_id, FailingSession()),
                "+15550001234",
                "sms",
            )
            timing = module._TASK_PROGRESS.progress(task_id)["timing"]
        finally:
            module._TASK_CONTEXT.reset(token)
            module._TASK_PROGRESS.reset()
            module._AUTH_SESSIONS.clear(task_id)

        self.assertEqual(result["_status"], 0)
        self.assertEqual(
            [row["code"] for row in timing["segments"]],
            ["phone_submit_http"],
        )

        class SuccessfulSession:
            cookies = {"session": "present"}

            def post(self, _url, **_kwargs):
                return {"_status": 200, "page": {"type": "add_phone"}}

        task_id = "task-sentinel-failure"
        original_refresh = module._auth_request_runtime_ext.refresh_sentinel
        module._AUTH_SESSIONS.clear(task_id)
        module._TASK_PROGRESS.reset()
        module._TASK_PROGRESS.set_stage(task_id, "phone_submitting")
        token = module._TASK_CONTEXT.set(task_id)
        try:
            module._auth_request_runtime_ext.refresh_sentinel = lambda *_args, **_kwargs: (
                _ for _ in ()
            ).throw(
                module._auth_request_runtime_ext.AuthRequestContextError(
                    "sentinel_refresh_failed",
                    "private sentinel failure",
                )
            )
            with self.assertRaisesRegex(
                module._codex_oauth_chain.CodexChainError,
                "sentinel_refresh_failed",
            ):
                module._real_send_phone_number_otp(
                    transport_for(task_id, SuccessfulSession()),
                    "+15550001234",
                    "sms",
                )
            timing = module._TASK_PROGRESS.progress(task_id)["timing"]
        finally:
            module._auth_request_runtime_ext.refresh_sentinel = original_refresh
            module._TASK_CONTEXT.reset(token)
            module._TASK_PROGRESS.reset()
            module._AUTH_SESSIONS.clear(task_id)

        self.assertEqual(
            [row["code"] for row in timing["segments"]],
            ["phone_submit_http", "sentinel_refresh"],
        )

    def test_real_phone_send_requires_entry_page_recovery_before_replacement(self):
        calls = []
        sentinel_calls = []

        class FakeSession:
            cookies = {"session": "present"}

            def post(self, url, **kwargs):
                calls.append((url, kwargs))
                return {"_status": 200, "page": {"type": "phone_otp_verification"}}

        class FakeSentinel:
            def reset(self, flow=""):
                sentinel_calls.append(("reset", flow))

            def token_for(self, flow, context):
                sentinel_calls.append(("token_for", flow, dict(context)))
                return {"token": "sentinel-value"}

        transport = SimpleNamespace(
            config={"sms_task_id": "task-phone-retry", "_auth_account_email": "user@example.test"},
            account_email="user@example.test",
            session=FakeSession(),
            sentinel_provider=FakeSentinel(),
            device_id="device-1",
            proxy="http://127.0.0.1:7897",
            _gptphone_page_type="add_phone",
        )
        self.module._AUTH_SESSIONS.clear("task-phone-retry")
        try:
            self.module._auth_request_runtime_ext.mark_phone_ready(
                transport,
                self.module._AUTH_SESSIONS,
                {"_status": 200, "page": {"type": "add_phone"}},
                continue_url="https://auth.openai.com/add-phone?state=private",
            )
            first = self.module._real_send_phone_number_otp(transport, "+15550001234", "sms")
            self.assertEqual(transport._gptphone_page_type, "phone_otp_verification")
            self.module._auth_request_runtime_ext.recover_phone_entry_context(
                transport,
                self.module._AUTH_SESSIONS,
                expected_task_id="task-phone-retry",
                visit_fn=lambda _url, **_kwargs: {
                    "_status": 200,
                    "page": {"type": "add_phone"},
                },
            )
            second = self.module._real_send_phone_number_otp(transport, "+15550005678", "sms")
        finally:
            self.module._AUTH_SESSIONS.clear("task-phone-retry")

        self.assertEqual(first["_status"], 200)
        self.assertEqual(second["_status"], 200)
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            calls[0][1]["json"],
            {"phone_number": "+15550001234", "channel": "sms"},
        )
        self.assertEqual(
            calls[1][1]["json"],
            {"phone_number": "+15550005678", "channel": "sms"},
        )
        headers = [
            {key.lower(): value for key, value in call[1]["headers"].items()}
            for call in calls
        ]
        self.assertNotEqual(
            headers[0]["x-access-flow-invocation-id"],
            headers[1]["x-access-flow-invocation-id"],
        )
        self.assertTrue(all("openai-sentinel-token" not in row for row in headers))
        self.assertEqual([item[0] for item in sentinel_calls], ["reset", "token_for"] * 2)

    def test_real_phone_send_invalid_context_stops_before_http_and_requires_fresh_oauth(self):
        calls = []

        class FakeSession:
            cookies = {"session": "present"}

            def post(self, url, **kwargs):
                calls.append((url, kwargs))
                return {"_status": 200}

        transport = SimpleNamespace(
            config={"sms_task_id": "task-phone-invalid", "_auth_account_email": "user@example.test"},
            account_email="user@example.test",
            session=FakeSession(),
            proxy="",
            _gptphone_page_type="consent",
        )
        self.module._AUTH_SESSIONS.clear("task-phone-invalid")
        try:
            with self.assertRaisesRegex(
                self.module._codex_oauth_chain.CodexChainError,
                "auth_context_page_mismatch",
            ) as raised:
                self.module._real_send_phone_number_otp(transport, "+15550001234", "sms")
            snapshot = self.module._AUTH_SESSIONS.public_snapshot("task-phone-invalid")
        finally:
            self.module._AUTH_SESSIONS.clear("task-phone-invalid")
            self.module._PHONE_RISK_STORE.clear("user@example.test")

        self.assertEqual(calls, [])
        self.assertTrue(snapshot["invalid"])
        self.assertTrue(snapshot["fresh_oauth_required"])
        self.assertEqual(snapshot["current_stage"], "phone_submitting")
        self.assertIn("page_type=consent", str(raised.exception))
        self.assertTrue(
            self.module._is_auth_session_reset_failure(
                error="auth_context_page_mismatch: stale page"
            )
        )

    def test_phone_stage_invalidation_marks_current_transport_immediately(self):
        module = self.module
        task_id = "task-risk-immediate"
        email = "immediate-risk@example.test"
        sentinel_resets = []
        transport = SimpleNamespace(
            config={
                "sms_task_id": task_id,
                "_auth_account_email": email,
                "phase1_active_session": "discard-me",
            },
            account_email=email,
            session=SimpleNamespace(cookies={"session": "present"}),
            sentinel_provider=SimpleNamespace(reset=lambda: sentinel_resets.append(True)),
            proxy="",
            _gptphone_page_type="add_phone",
        )
        module._AUTH_SESSIONS.clear(task_id)
        module._register_sms_transport(task_id, transport)
        try:
            module._auth_request_runtime_ext.ensure_transport_context(
                transport,
                module._AUTH_SESSIONS,
                force_new=True,
            )
            module._auth_request_runtime_ext.invalidate_auth_session(
                transport,
                module._AUTH_SESSIONS,
                "oauth_session_invalid: sign-in session is no longer valid",
                stage="phone_submitting",
            )
            marker = module._PHONE_RISK_STORE.status(email)
        finally:
            module._unregister_sms_transport(task_id, transport)
            module._AUTH_SESSIONS.clear(task_id)
            module._PHONE_RISK_STORE.clear(email)

        self.assertTrue(marker["active"])
        self.assertEqual(marker["stage"], "phone_submitting")
        self.assertTrue(transport.config["_phone_risk_retry"])
        self.assertNotIn("phase1_active_session", transport.config)
        self.assertEqual(transport.session.cookies, {})
        self.assertEqual(sentinel_resets, [True])

    def test_phone_otp_session_invalidation_aborts_before_another_number_attempt(self):
        module = self.module
        task_id = "task-risk-sms-verify"
        email = "sms-verify-risk@example.test"
        original_post = module._ORIGINAL_REAL_POST_AUTH_JSON
        sentinel_resets = []
        transport = SimpleNamespace(
            config={
                "sms_task_id": task_id,
                "_auth_account_email": email,
                "phase1_active_session": "discard-me",
            },
            account_email=email,
            session=SimpleNamespace(cookies={"session": "present"}),
            sentinel_provider=SimpleNamespace(
                reset=lambda flow="": sentinel_resets.append(flow),
            ),
            proxy="",
            _gptphone_page_type="phone_otp_verification",
        )
        transport._post_auth_json = MethodType(module._real_post_auth_json, transport)
        module._AUTH_SESSIONS.clear(task_id)
        module._register_sms_transport(task_id, transport)
        try:
            module._ORIGINAL_REAL_POST_AUTH_JSON = lambda *_args, **_kwargs: {
                "_status": 401,
                "error": {
                    "code": "oauth_session_invalid",
                    "message": "sign-in session is no longer valid",
                },
            }
            with self.assertRaisesRegex(
                module._codex_oauth_chain.CodexChainError,
                "oauth_session_invalid",
            ):
                module._real_verify_phone_otp(transport, "123456")
            marker = module._PHONE_RISK_STORE.status(email)
            snapshot = module._AUTH_SESSIONS.public_snapshot(task_id)
        finally:
            module._ORIGINAL_REAL_POST_AUTH_JSON = original_post
            module._unregister_sms_transport(task_id, transport)
            module._AUTH_SESSIONS.clear(task_id)
            module._PHONE_RISK_STORE.clear(email)

        self.assertTrue(marker["active"])
        self.assertEqual(marker["reason_code"], "oauth_session_invalid")
        self.assertEqual(marker["stage"], "sms_verifying")
        self.assertEqual(snapshot["invalidations"], 1)
        self.assertEqual(snapshot["current_stage"], "sms_verifying")
        self.assertTrue(transport.config["_phone_risk_retry"])
        self.assertNotIn("phase1_active_session", transport.config)
        self.assertEqual(transport.session.cookies, {})
        self.assertEqual(sentinel_resets, [""])

    def test_non_phone_session_invalidation_does_not_create_phone_risk_marker(self):
        email = "oauth-only@example.test"

        self.module._persist_phone_risk_marker(
            "task-oauth-only",
            email,
            "oauth_session_invalid",
            "oauth_authorize_node",
        )

        self.assertEqual(self.module._PHONE_RISK_STORE.status(email), {})

    def test_phone_risk_marker_clears_only_after_phone_otp_is_accepted(self):
        module = self.module
        task_id = "task-risk-clear"
        email = "risk-clear@example.test"
        responses = [
            {"_status": 200, "page": {"type": "phone_otp_verification"}},
            {
                "_status": 200,
                "page": {"type": "sign_in_with_chatgpt_codex_consent"},
                "continue_url": "/sign-in-with-chatgpt/codex/consent",
            },
        ]
        transport = SimpleNamespace(
            config={
                "sms_task_id": task_id,
                "_auth_account_email": email,
                "_phone_risk_retry": True,
                "_phone_risk_reason_code": "oauth_session_invalid",
            },
            account_email=email,
            session=SimpleNamespace(cookies={"session": "present"}),
            sentinel_provider=SimpleNamespace(reset=lambda *_args: None),
            proxy="",
            _gptphone_page_type="phone_otp_verification",
            _post_auth_json=lambda *_args, **_kwargs: responses.pop(0),
        )
        module._PHONE_RISK_STORE.mark(email)
        module._AUTH_SESSIONS.clear(task_id)
        try:
            module._real_verify_phone_otp(transport, "111111")
            self.assertTrue(module._PHONE_RISK_STORE.is_active(email))
            self.assertTrue(transport.config["_phone_risk_retry"])

            module._real_verify_phone_otp(transport, "222222")
            self.assertFalse(module._PHONE_RISK_STORE.is_active(email))
            self.assertNotIn("_phone_risk_retry", transport.config)
            self.assertNotIn("_phone_risk_reason_code", transport.config)
        finally:
            module._AUTH_SESSIONS.clear(task_id)
            module._PHONE_RISK_STORE.clear(email)

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

    def test_public_task_exposes_only_safe_phone_risk_fields(self):
        task = {
            "task_id": "task-risk-public",
            "email": "risk@example.test",
            "status": "failed",
            "result": {
                "phone_risk_retry": True,
                "phone_risk_label": "手机号风控重试：已启用成熟线路优先",
                "phone_risk_reason_code": "oauth_session_invalid",
                "phone_risk_private": {
                    "email": "risk@example.test",
                    "phone": "+15550001111",
                },
            },
        }

        public = self.module._public_task(task)
        serialized = json.dumps(public, ensure_ascii=False)

        self.assertTrue(public["result"]["phone_risk_retry"])
        self.assertEqual(
            public["result"]["phone_risk_label"],
            "手机号风控重试：已启用成熟线路优先",
        )
        self.assertEqual(
            public["result"]["phone_risk_reason_code"],
            "oauth_session_invalid",
        )
        self.assertNotIn("phone_risk_private", serialized)
        self.assertNotIn("+15550001111", serialized)

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
            module._TASK_PROGRESS.record_segment(
                "T003-safe",
                "protocol_slot_waiting",
                1.25,
            )
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
            frozen_timing = copy.deepcopy(result["timing"])
            self.assertIsNotNone(frozen_timing["finished_at"])
            self.assertFalse(module._TASK_PROGRESS.finish("T003-safe"))
            self.assertEqual(
                (module._TASK_PROGRESS.progress("T003-safe") or {})["timing"],
                frozen_timing,
            )
        finally:
            module._ORIGINAL_PERSIST_RESULT = original_persist
            module._TASK_PROGRESS.reset()

        payload = json.loads((result_dir / "T003-safe_oauth_at_example.test.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["failure"]["node_code"], "finalizing_token")
        self.assertEqual(payload["error"], payload["failure"]["public_message"])
        self.assertEqual(payload["technical_error"], payload["failure"]["technical_summary"])
        self.assertEqual(payload["result"]["failure"], payload["failure"])
        self.assertEqual(payload["timing"], frozen_timing)
        self.assertEqual(payload["result"]["timing"], frozen_timing)
        self.assertEqual(
            payload["timing"]["segments"],
            [
                {
                    "code": "protocol_slot_waiting",
                    "label": "等待协议槽",
                    "elapsed_seconds": 1.25,
                    "visits": 1,
                }
            ],
        )

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

    def test_persisted_result_keeps_safe_phone_risk_retry_fields(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        email = "persist-risk-result@example.test"
        captured = []
        result = {}
        fake_self = SimpleNamespace(data_dir=self.tempdir.name)
        entry = SimpleNamespace(email=email)
        module._PHONE_RISK_STORE.mark(
            email,
            reason_code="oauth_session_invalid",
            stage="sms_verifying",
        )
        try:
            module._ORIGINAL_PERSIST_RESULT = (
                lambda _self, _settings, _task_id, _entry, value, **_kwargs: (
                    captured.append(copy.deepcopy(value)) or "persisted"
                )
            )
            returned = module._patched_persist_result(
                fake_self,
                {"pixel_upload_enabled": False},
                "task-persist-risk",
                entry,
                result,
                status="stopped",
            )
        finally:
            module._ORIGINAL_PERSIST_RESULT = original_persist
            module._PHONE_RISK_STORE.clear(email)
            module._TASK_PROGRESS.reset()

        self.assertEqual(returned, "persisted")
        self.assertTrue(captured[0]["phone_risk_retry"])
        self.assertEqual(
            captured[0]["phone_risk_label"],
            "手机号风控重试：已启用成熟线路优先",
        )
        self.assertEqual(
            captured[0]["phone_risk_reason_code"],
            "oauth_session_invalid",
        )
        serialized = json.dumps(captured[0], ensure_ascii=False)
        self.assertNotIn(email, serialized)

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

    def test_account_banned_failure_is_terminal_removes_pool_row_and_never_enqueues_pixel(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        original_retire = module._ORIGINAL_RETIRE_AFTER_FAILURE
        original_remove = module._ORIGINAL_POOL_REMOVE_ENTRY
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
                self.removed = []

            def mark_damaged_entry(self, entry, *, reason=""):
                self.damaged.append((entry.email, reason))

            def _update(self, callback):
                return callback({"items": {}}, [])

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
        entry = SimpleNamespace(key="banned-row", email="banned@example.test")
        pool = Pool()
        message = module._runtime_policy_ext.ACCOUNT_BANNED_MESSAGE
        try:
            module._ORIGINAL_PERSIST_RESULT = persist
            module._ORIGINAL_RETIRE_AFTER_FAILURE = lambda *_args, **_kwargs: self.fail(
                "explicit account ban must not use generic retirement"
            )
            module._ORIGINAL_POOL_REMOVE_ENTRY = lambda target, removed, **_kwargs: (
                target.removed.append(removed.key) or True
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
            module._ORIGINAL_POOL_REMOVE_ENTRY = original_remove
            module._PIXEL_UPLOAD_QUEUE = original_queue
            module._SMS_WEB = original_sms_web

        target = result_dir / "task-ban_banned_at_example.test.json"
        local_payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(pool.removed, [entry.key])
        self.assertEqual(pool.damaged, [])
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
        self.assertEqual(logs, [(f"{message}；已从邮箱池移除", "error")])
        self.assertEqual(enqueued, [])


if __name__ == "__main__":
    unittest.main()
