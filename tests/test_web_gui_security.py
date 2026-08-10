from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import MethodType, SimpleNamespace
import unittest

from tests.web_gui_test_runtime import RecoveredWebGuiImport


class WebGuiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.previous_data_dir = os.environ.get("GPTPHONE_DATA_DIR")
        os.environ["GPTPHONE_DATA_DIR"] = cls.tempdir.name
        cls.web_gui_import = RecoveredWebGuiImport(Path(__file__).resolve().parents[1])
        cls.module = cls.web_gui_import.load()

    @classmethod
    def tearDownClass(cls):
        if cls.previous_data_dir is None:
            os.environ.pop("GPTPHONE_DATA_DIR", None)
        else:
            os.environ["GPTPHONE_DATA_DIR"] = cls.previous_data_dir
        cls.web_gui_import.cleanup()
        cls.tempdir.cleanup()

    def test_successful_totp_trace_is_not_rewritten_as_oauth_failure(self):
        message = (
            "T002-ab12cd [CodexTOTP] password_verify endpoint=/api/accounts/password/verify "
            "_status=200 page_type=mfa_challenge continue_path=/mfa-challenge/******** "
            "error=- factor_id_present=1"
        )

        formatted = self.module._diagnostic_friendly_log_message(message)

        self.assertEqual(formatted, message)
        self.assertNotIn("OpenAI OAuth 授权失败", formatted)

    def test_batch_reconcile_marks_missing_runtime_task_terminal(self):
        module = self.module
        updates = []

        class Manifest:
            def finalize(self, batch_id, *, tasks, reason):
                self.batch_id = batch_id
                self.tasks = tasks
                self.reason = reason
                return {
                    "members": [
                        {
                            "task_id": "T002-ab12cd",
                            "status": "failed",
                            "reconciled_missing": True,
                        }
                    ]
                }

        importer = SimpleNamespace(
            lock=threading.RLock(),
            tasks={
                "T002-ab12cd": {
                    "task_id": "T002-ab12cd",
                    "status": "authorizing",
                    "result": {},
                }
            },
            _gptphone_batch_manifest=Manifest(),
            _log=lambda *_args: None,
        )

        def task_state(task_id, **values):
            updates.append((task_id, copy.deepcopy(values)))
            importer.tasks[task_id].update(values)

        importer._task_state = task_state
        summary = module._reconcile_finished_batch(
            importer,
            {"batch_id": "20260808-150600-b20be0"},
        )

        self.assertEqual(len(summary["members"]), 1)
        self.assertEqual(updates[0][0], "T002-ab12cd")
        self.assertEqual(updates[0][1]["status"], "failed")
        self.assertEqual(
            updates[0][1]["failure"]["node_code"],
            "batch_member_missing_terminal",
        )
        serialized = json.dumps(updates, ensure_ascii=False)
        self.assertNotIn("@", serialized)

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
            "online_mailbox": {
                "base_url": "https://lynote.xyz/token-tool",
                "api_token": "online-mailbox-secret",
            },
            "nv_import": {
                "endpoint": "https://nv.example.test/import",
                "api_key": "nv-secret",
            },
        }
        draft = {
            "performance_policy_version": 5,
            "sms_api_keys": ["********", "********"],
            "proxy": "********",
            "email_notification": {"password": "********"},
            "online_mailbox": {"api_token": "********"},
            "nv_import": {"api_key": "********"},
        }

        resolved = self.module._local_config_from_runtime(draft, existing)

        self.assertEqual(resolved["sms_api_keys"], ["sms-secret-a", "sms-secret-b"])
        self.assertEqual(resolved["proxy"], existing["proxy"])
        self.assertEqual(resolved["email_notification"]["password"], "smtp-secret")
        self.assertEqual(resolved["online_mailbox"]["api_token"], "online-mailbox-secret")
        self.assertEqual(resolved["nv_import"]["api_key"], "nv-secret")

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
            "online_mailbox": {"api_token": "online-mailbox-secret"},
            "nv_import": {"api_key": "nv-secret"},
        }

        masked = self.module._masked_local_config(config)
        serialized = json.dumps(masked)

        for secret in (
            "sms-secret",
            "proxy-pass",
            "sub2-secret",
            "smtp-secret",
            "online-mailbox-secret",
            "nv-secret",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(masked["email_notification"]["password"], "********")
        self.assertEqual(masked["online_mailbox"]["api_token"], "********")
        self.assertEqual(masked["nv_import"]["api_key"], "********")

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
                    "dynamic_auth_challenges": False,
                },
                "user@example.test",
                "email-retry-explicit",
            )
        finally:
            module._ORIGINAL_TASK_CONFIG = original_task_config

        self.assertEqual(default_config["email_otp_verify_attempts"], 2)
        self.assertTrue(default_config["email_otp_resend_on_retry"])
        self.assertTrue(default_config["dynamic_auth_challenges"])
        self.assertEqual(explicit_config["email_otp_verify_attempts"], 3)
        self.assertFalse(explicit_config["email_otp_resend_on_retry"])
        self.assertFalse(explicit_config["dynamic_auth_challenges"])

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

    def test_run_selection_matches_raw_row_hash_and_public_line_number(self):
        module = self.module
        pool_path = Path(self.tempdir.name) / "run-selection-pool.txt"
        first_row = "first@example.test----first-password"
        selected_row = "selected@example.test----private-password"
        pool_path.write_text(f"{first_row}\n\n  {selected_row}  \n", encoding="utf-8")
        entries = [
            SimpleNamespace(line_no=1, source_row=first_row),
            SimpleNamespace(line_no=3, source_row="selected@example.test----********"),
        ]
        original_patches = module._TOTP_PATCHES
        selection_token = module._MAILBOX_RUN_SELECTION.set(frozenset({
            (module._mailbox_admin_ext.row_id_from_source(selected_row), 2),
        }))
        filter_token = module._MAILBOX_LEASE_FILTER_ACTIVE.set(True)
        try:
            module._TOTP_PATCHES = SimpleNamespace(
                entries_unlocked=lambda _pool: (list(entries), []),
            )
            filtered, errors = module._mailbox_entries_for_run_selection(
                SimpleNamespace(pool_path=pool_path),
            )
        finally:
            module._MAILBOX_LEASE_FILTER_ACTIVE.reset(filter_token)
            module._MAILBOX_RUN_SELECTION.reset(selection_token)
            module._TOTP_PATCHES = original_patches

        self.assertEqual(errors, [])
        self.assertEqual(filtered, [entries[1]])

    def test_run_selection_rejects_replaced_content_at_same_public_line(self):
        module = self.module
        pool_path = Path(self.tempdir.name) / "stale-run-selection-pool.txt"
        current_row = "replacement@example.test----current-password"
        pool_path.write_text(f"{current_row}\n", encoding="utf-8")
        entry = SimpleNamespace(line_no=1, source_row=current_row)
        original_patches = module._TOTP_PATCHES
        stale_row_id = module._mailbox_admin_ext.row_id_from_source(
            "previous@example.test----previous-password",
        )
        selection_token = module._MAILBOX_RUN_SELECTION.set(frozenset({(stale_row_id, 1)}))
        filter_token = module._MAILBOX_LEASE_FILTER_ACTIVE.set(True)
        try:
            module._TOTP_PATCHES = SimpleNamespace(
                entries_unlocked=lambda _pool: ([entry], []),
            )
            filtered, errors = module._mailbox_entries_for_run_selection(
                SimpleNamespace(pool_path=pool_path),
            )
        finally:
            module._MAILBOX_LEASE_FILTER_ACTIVE.reset(filter_token)
            module._MAILBOX_RUN_SELECTION.reset(selection_token)
            module._TOTP_PATCHES = original_patches

        self.assertEqual(errors, [])
        self.assertEqual(filtered, [])

    def test_batch_priority_is_consumed_only_after_manifest_commit(self):
        module = self.module
        original_reserve = module._mailbox_priority_runtime_ext.reserve_available_batch
        original_priority = module._MAILBOX_NEXT_BATCH_PRIORITY
        events = []
        entries = [SimpleNamespace(source_row="priority-row")]

        def reserve(_pool, _target, **options):
            options["before_reserve"](entries)
            options["after_reserve"](entries)
            return entries

        token = module._MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.set(True)
        try:
            module._mailbox_priority_runtime_ext.reserve_available_batch = reserve
            module._MAILBOX_NEXT_BATCH_PRIORITY = SimpleNamespace(
                consume=lambda source_row: events.append(("consume", source_row)),
            )
            selected = module._reserve_mailbox_batch(
                object(),
                1,
                before_reserve=lambda _rows: events.append(("prepare", "")),
                after_reserve=lambda _rows: events.append(("commit", "")),
            )
        finally:
            module._MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.reset(token)
            module._MAILBOX_NEXT_BATCH_PRIORITY = original_priority
            module._mailbox_priority_runtime_ext.reserve_available_batch = original_reserve

        self.assertEqual(selected, entries)
        self.assertEqual(
            events,
            [("prepare", ""), ("commit", ""), ("consume", "priority-row")],
        )

    def test_batch_recovery_uses_manifest_private_pool_paths(self):
        module = self.module
        original_pool = module._runtime.MailboxPool
        original_release = module._mailbox_priority_runtime_ext.release_owned_batch_leases
        observed = {}
        custom_pool = Path(self.tempdir.name) / "custom-pool.txt"
        custom_state = Path(self.tempdir.name) / "custom-state.json"

        try:
            module._runtime.MailboxPool = lambda pool_path, state_path: observed.update(
                pool_path=Path(pool_path),
                state_path=Path(state_path),
            ) or "pool"
            module._mailbox_priority_runtime_ext.release_owned_batch_leases = (
                lambda pool, batch_id, members: observed.update(
                    pool=pool,
                    batch_id=batch_id,
                    member_count=len(list(members)),
                ) or {"released": 1}
            )
            result = module._release_recovered_batch_leases(
                "batch-custom",
                [{"row_id": "a" * 64, "line_no": 1}],
                pool_path=custom_pool,
                state_path=custom_state,
            )
        finally:
            module._runtime.MailboxPool = original_pool
            module._mailbox_priority_runtime_ext.release_owned_batch_leases = original_release

        self.assertEqual(result, {"released": 1})
        self.assertEqual(observed["pool_path"], custom_pool)
        self.assertEqual(observed["state_path"], custom_state)
        self.assertEqual(observed["pool"], "pool")
        self.assertEqual(observed["batch_id"], "batch-custom")
        self.assertEqual(observed["member_count"], 1)

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

    def test_task_admission_adapts_only_for_register_concurrency_eight(self):
        module = self.module
        original_start = module._importer_scheduler_ext.start_bounded_importer
        original_notifications = module._begin_notification_run
        original_admission = module._CURRENT_TASK_ADMISSION
        observed = []
        importer = SimpleNamespace(status=lambda _settings: {"running": False})
        try:
            module._begin_notification_run = lambda *_args: None
            module._importer_scheduler_ext.start_bounded_importer = (
                lambda _importer, settings, **kwargs: observed.append(
                    (
                        dict(settings),
                        kwargs["task_admission"].snapshot(),
                        kwargs["task_admission"].require_backlog_for_restore,
                    )
                )
            )
            module._patched_importer_start(importer, {"concurrency": 8})
            module._patched_importer_start(importer, {"concurrency": 7})
            module._patched_importer_start(
                importer,
                {"concurrency": 8, "run_mode": "relogin"},
            )
            module._patched_importer_start(
                importer,
                {"concurrency": 8, "adaptive_task_concurrency": False},
            )
        finally:
            module._CURRENT_TASK_ADMISSION = original_admission
            module._importer_scheduler_ext.start_bounded_importer = original_start
            module._begin_notification_run = original_notifications

        register_eight, register_seven, relogin_eight, disabled_eight = observed
        self.assertEqual(
            {
                key: register_eight[1][key]
                for key in ("base", "limit", "restore_ceiling", "ceiling", "burst_enabled")
            },
            {
                "base": 8,
                "limit": 8,
                "restore_ceiling": 10,
                "ceiling": 10,
                "burst_enabled": False,
            },
        )
        self.assertEqual(register_seven[1]["ceiling"], 7)
        self.assertFalse(register_seven[1]["burst_enabled"])
        self.assertEqual(relogin_eight[1]["ceiling"], 8)
        self.assertFalse(relogin_eight[1]["burst_enabled"])
        self.assertEqual(disabled_eight[1]["ceiling"], 8)
        self.assertFalse(disabled_eight[1]["burst_enabled"])
        self.assertTrue(all(item[2] for item in observed))

    def test_inflight_gate_reuses_sms_baseline_unless_explicitly_overridden(self):
        module = self.module
        original_start = module._importer_scheduler_ext.start_bounded_importer
        original_notifications = module._begin_notification_run
        original_guard = module._SMS_QUALITY_GUARD
        original_inflight = module._CURRENT_INFLIGHT_GATE
        observed = []
        importer = SimpleNamespace(status=lambda _settings: {"running": False})
        baseline_path = Path(self.tempdir.name) / "inflight-shared-baseline.json"
        shared = {
            "cancellation_rate": 0.02,
            "duplicate_order_rate": 0.01,
            "cost_per_success_usd": 0.10,
            "provider_key": "must-not-leak",
        }
        baseline_path.write_text(json.dumps(shared), encoding="utf-8")
        try:
            module._SMS_QUALITY_GUARD = (
                module._sms_optimization_guard_ext.SmsOptimizationGuard(
                    baseline_path=baseline_path,
                )
            )
            module._begin_notification_run = lambda *_args: None
            module._importer_scheduler_ext.start_bounded_importer = (
                lambda _importer, _settings, **kwargs: observed.append(
                    kwargs["inflight_gate"].baseline
                )
            )
            module._patched_importer_start(
                importer,
                {"concurrency": 8},
            )
            module._patched_importer_start(
                importer,
                {
                    "concurrency": 8,
                    "task_inflight_baseline": {"cancellation_rate": 0.05},
                },
            )
        finally:
            module._CURRENT_INFLIGHT_GATE = original_inflight
            module._SMS_QUALITY_GUARD = original_guard
            module._importer_scheduler_ext.start_bounded_importer = original_start
            module._begin_notification_run = original_notifications

        fallback, explicit = observed
        self.assertEqual(fallback.cancellation_rate, 0.02)
        self.assertEqual(fallback.duplicate_order_rate, 0.01)
        self.assertEqual(fallback.cost_per_success_usd, 0.10)
        self.assertNotIn("must-not-leak", str(fallback))
        self.assertEqual(explicit.cancellation_rate, 0.05)
        self.assertIsNone(explicit.duplicate_order_rate)
        self.assertIsNone(explicit.cost_per_success_usd)

    def test_adaptive_task_events_sync_node_and_protocol_capacity(self):
        module = self.module
        original_start = module._importer_scheduler_ext.start_bounded_importer
        original_notifications = module._begin_notification_run
        original_admission = module._CURRENT_TASK_ADMISSION
        original_protocol = module._PROTOCOL_GATE
        observed = []
        importer = SimpleNamespace(status=lambda _settings: {"running": False})

        def capture(_importer, settings, **kwargs):
            node_limit = int(settings.get("node_concurrency") or settings["concurrency"])
            node_gate = kwargs["node_phase_gate_factory"](node_limit)
            admission = kwargs["task_admission"]
            admission.on_change({
                "kind": "restored",
                "old_limit": 8,
                "new_limit": 9,
                "reason": "success_streak",
            })
            promoted = (
                node_gate.status(),
                module._PROTOCOL_GATE.snapshot("proxy-test"),
            )
            admission.on_change({
                "kind": "resource_exhausted",
                "old_limit": 9,
                "new_limit": 4,
                "reason": "resource_fd_exhausted",
                "pause_seconds": 15,
            })
            observed.append((
                promoted,
                node_gate.status(),
                module._PROTOCOL_GATE.snapshot("proxy-test"),
            ))

        try:
            module._begin_notification_run = lambda *_args: None
            module._PROTOCOL_GATE = module._sms_runtime_ext.ProxyProtocolGate(
                default_limit=8,
                launch_interval_seconds=0,
            )
            module._importer_scheduler_ext.start_bounded_importer = capture
            module._patched_importer_start(
                importer,
                {"concurrency": 8, "node_concurrency": 8},
            )
            module._patched_importer_start(
                importer,
                {"concurrency": 8, "node_concurrency": 7},
            )
        finally:
            module._CURRENT_TASK_ADMISSION = original_admission
            module._PROTOCOL_GATE = original_protocol
            module._importer_scheduler_ext.start_bounded_importer = original_start
            module._begin_notification_run = original_notifications

        promoted, node_reduced, protocol_reduced = observed[0]
        promoted_node, promoted_protocol = promoted
        self.assertEqual((promoted_node["limit"], promoted_node["ceiling"]), (9, 10))
        self.assertEqual((promoted_protocol["limit"], promoted_protocol["ceiling"]), (9, 9))
        self.assertEqual(node_reduced["limit"], 4)
        self.assertEqual((protocol_reduced["limit"], protocol_reduced["ceiling"]), (4, 4))

        fixed_promoted, fixed_node, fixed_protocol = observed[1]
        self.assertEqual(fixed_promoted[0]["limit"], 7)
        self.assertEqual(fixed_promoted[1]["limit"], 7)
        self.assertEqual(fixed_node["limit"], 7)
        self.assertEqual((fixed_protocol["limit"], fixed_protocol["ceiling"]), (7, 7))

    def test_running_fd_sampler_feeds_current_admission_without_subprocess_snapshot(self):
        module = self.module
        original_ratio = module._transport_lifecycle_ext.process_fd_ratio
        observed = []
        importer = SimpleNamespace(
            task_admission=SimpleNamespace(
                observe_resource_ratio=lambda ratio: observed.append(ratio) or 4,
            )
        )
        try:
            module._transport_lifecycle_ext.process_fd_ratio = lambda: 0.81
            result = module._observe_runtime_fd_pressure(importer)
        finally:
            module._transport_lifecycle_ext.process_fd_ratio = original_ratio

        self.assertEqual(result, 4)
        self.assertEqual(observed, [0.81])

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
            with self.assertRaisesRegex(Exception, "email_otp_send_failed") as caught:
                module._real_submit_email_identifier(transport, "user@example.test")
        finally:
            module._ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER = original_submit

        detail = str(caught.exception)
        self.assertIn("HTTP 429", detail)
        self.assertIn("rate_limited", detail)
        self.assertTrue(module._sms_runtime_ext.is_protocol_pressure_error(detail))

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

    def test_phase1_snapshot_is_removed_from_task_config_after_chain_exit(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION
        try:
            for raises in (False, True):
                with self.subTest(raises=raises):
                    config = {
                        "sms_task_id": f"task-phase1-private-{int(raises)}",
                        "phase1_active_session": {
                            "ready": True,
                            "cookies": [{"name": "session", "value": "private"}],
                        },
                    }

                    def run(**kwargs):
                        self.assertIn("phase1_active_session", kwargs["config"])
                        if raises:
                            raise RuntimeError("expected-chain-failure")
                        return {"ok": True}

                    module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = run
                    if raises:
                        with self.assertRaisesRegex(RuntimeError, "expected-chain-failure"):
                            module._run_codex_after_registration(
                                oauth_url="https://auth.example.test/authorize",
                                account_email="masked@example.test",
                                config=config,
                            )
                    else:
                        module._run_codex_after_registration(
                            oauth_url="https://auth.example.test/authorize",
                            account_email="masked@example.test",
                            config=config,
                        )
                    self.assertNotIn("phase1_active_session", config)
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

    def test_mailbox_transport_error_does_not_report_global_protocol_pressure(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION
        original_gate = module._PROTOCOL_GATE
        reports = []
        limits = []

        class Admission:
            def report_pressure(self, task_id, node_code, *, immediate=False):
                reports.append((task_id, node_code, immediate))

        outcomes = iter(
            (
                RuntimeError("mailbox_request_failed: TLS connection closed"),
                RuntimeError("mailbox_request_failed: TLS connection closed"),
                RuntimeError("ProxyError: tunnel failed"),
                RuntimeError("ProxyError: tunnel failed"),
            )
        )

        def fail_run(**_kwargs):
            raise next(outcomes)

        admission_token = module._TASK_ADMISSION_CONTEXT.set(Admission())
        try:
            module._PROTOCOL_GATE = module._sms_runtime_ext.ProxyProtocolGate(
                default_limit=5,
                launch_interval_seconds=0,
            )
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = fail_run
            for task_id, stage in (
                ("T-mailbox-transport-1", "email_login"),
                ("T-mailbox-transport-2", "email_login"),
                ("T-oauth-proxy-1", "oauth_authorize_node"),
                ("T-oauth-proxy-2", "oauth_authorize_node"),
            ):
                module._TASK_PROGRESS.set_stage(task_id, stage)
                with self.assertRaises(RuntimeError):
                    module._run_codex_after_registration(
                        oauth_url="https://auth.example.test/authorize",
                        account_email="masked@example.test",
                        config={"sms_task_id": task_id},
                    )
                limits.append(module._PROTOCOL_GATE.snapshot("")["limit"])
        finally:
            module._TASK_ADMISSION_CONTEXT.reset(admission_token)
            module._TASK_PROGRESS.reset()
            module._PROTOCOL_GATE = original_gate
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = original_run

        self.assertEqual(
            reports,
            [
                ("T-oauth-proxy-1", "protocol_pressure", True),
                ("T-oauth-proxy-2", "protocol_pressure", True),
            ],
        )
        self.assertEqual(limits, [5, 5, 5, 4])

    def test_sms_provider_pressure_does_not_touch_task_or_main_proxy_gates(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION
        original_gate = module._PROTOCOL_GATE
        reports = []

        class Admission:
            def report_pressure(self, task_id, node_code, *, immediate=False):
                reports.append((task_id, node_code, immediate))

        outcomes = iter(
            (
                RuntimeError("HTTPError: 429 Client Error"),
                RuntimeError("sms_provider_poll_failed: TLS connection closed"),
            )
        )

        admission_token = module._TASK_ADMISSION_CONTEXT.set(Admission())
        try:
            module._PROTOCOL_GATE = module._sms_runtime_ext.ProxyProtocolGate(
                default_limit=5,
                launch_interval_seconds=0,
            )
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = lambda **_kwargs: (_ for _ in ()).throw(
                next(outcomes)
            )
            for task_id, stage in (
                ("T-sms-provider-rate", "phone_acquiring"),
                ("T-sms-provider-tls", "sms_waiting"),
            ):
                module._TASK_PROGRESS.set_stage(task_id, stage)
                with self.assertRaises(RuntimeError):
                    module._run_codex_after_registration(
                        oauth_url="https://auth.example.test/authorize",
                        account_email="masked@example.test",
                        config={"sms_task_id": task_id},
                    )
        finally:
            protocol_limit = module._PROTOCOL_GATE.snapshot("")["limit"]
            module._TASK_ADMISSION_CONTEXT.reset(admission_token)
            module._TASK_PROGRESS.reset()
            module._PROTOCOL_GATE = original_gate
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = original_run

        self.assertEqual(reports, [])
        self.assertEqual(protocol_limit, 5)

    def test_structured_oauth_429_degrades_protocol_gate_and_success_restores_it(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION
        original_gate = module._PROTOCOL_GATE
        reports = []

        class Admission:
            def report_pressure(self, task_id, node_code, *, immediate=False):
                reports.append((task_id, node_code, immediate))

        outcomes = [
            {"ok": False, "status_code": 429},
            {"ok": False, "status_code": 429},
            *({"ok": True} for _index in range(6)),
        ]
        admission_token = module._TASK_ADMISSION_CONTEXT.set(Admission())
        try:
            module._PROTOCOL_GATE = module._sms_runtime_ext.ProxyProtocolGate(
                default_limit=5,
                launch_interval_seconds=0,
            )
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = lambda **_kwargs: outcomes.pop(0)
            for index in range(2):
                task_id = f"T-structured-rate-{index}"
                module._TASK_PROGRESS.set_stage(task_id, "oauth_authorize_node")
                module._run_codex_after_registration(
                    oauth_url="https://auth.example.test/authorize",
                    account_email="masked@example.test",
                    config={"sms_task_id": task_id},
                )
            degraded_limit = module._PROTOCOL_GATE.snapshot("")["limit"]
            for index in range(6):
                task_id = f"T-protocol-success-{index}"
                module._TASK_PROGRESS.set_stage(task_id, "oauth_authorize_node")
                module._run_codex_after_registration(
                    oauth_url="https://auth.example.test/authorize",
                    account_email="masked@example.test",
                    config={"sms_task_id": task_id},
                )
            restored_limit = module._PROTOCOL_GATE.snapshot("")["limit"]
        finally:
            module._TASK_ADMISSION_CONTEXT.reset(admission_token)
            module._TASK_PROGRESS.reset()
            module._PROTOCOL_GATE = original_gate
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = original_run

        self.assertEqual(degraded_limit, 4)
        self.assertEqual(restored_limit, 5)
        self.assertEqual(
            reports,
            [
                ("T-structured-rate-0", "protocol_pressure", True),
                ("T-structured-rate-1", "protocol_pressure", True),
            ],
        )

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
                "mfa_otp_failed: Invalid authorization step.",
                "Invalid authorization step.",
                "mfa_authorization_step_expired",
            ):
                with self.subTest(error=error):
                    self.assertTrue(
                        module._patched_pre_auth_session_retryable({"error": error})
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

            result = {"error": "oauth_session_invalid: sign-in session is no longer valid"}
            self.assertTrue(module._patched_pre_auth_session_retryable(result))
            self.assertTrue(module._patched_pre_auth_session_retryable(result))
        finally:
            module._AUTH_SESSIONS.clear("task-phone-session-retry")
            module._RUN_MODE_CONTEXT.reset(mode_token)
            module._TASK_CONTEXT.reset(task_token)

    def test_account_banned_never_enters_whole_session_retry(self):
        module = self.module
        original = module._ORIGINAL_PRE_AUTH_SESSION_RETRYABLE
        try:
            module._ORIGINAL_PRE_AUTH_SESSION_RETRYABLE = lambda _result: True
            result = {
                "error": {
                    "code": "account_deactivated",
                    "message": "This account was deleted or deactivated.",
                }
            }

            self.assertFalse(module._patched_pre_auth_session_retryable(result))
        finally:
            module._ORIGINAL_PRE_AUTH_SESSION_RETRYABLE = original

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
        checkpoint_deletes = []
        original_checkpoint_coordinator = module._PHASE1_CHECKPOINTS_COORDINATOR
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
            module._PHASE1_CHECKPOINTS_COORDINATOR = SimpleNamespace(
                delete=lambda current: checkpoint_deletes.append(current)
            )
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
            module._PHASE1_CHECKPOINTS_COORDINATOR = original_checkpoint_coordinator
            module._unregister_sms_transport(task_id, transport)
            module._AUTH_SESSIONS.clear(task_id)
            module._PHONE_RISK_STORE.clear(email)

        self.assertTrue(marker["active"])
        self.assertEqual(marker["stage"], "phone_submitting")
        self.assertTrue(transport.config["_phone_risk_retry"])
        self.assertNotIn("phase1_active_session", transport.config)
        self.assertEqual(transport.session.cookies, {})
        self.assertEqual(sentinel_resets, [True])
        self.assertEqual(checkpoint_deletes, [transport])

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

    def test_runtime_task_waiting_count_includes_executor_backlog(self):
        module = self.module
        original_admission = module._CURRENT_TASK_ADMISSION
        gate = module._adaptive_concurrency_ext.AdaptiveConcurrencyGate(5, ceiling=8)
        try:
            module._CURRENT_TASK_ADMISSION = gate
            public = module._masked_state({
                "runtime": {
                    "running": True,
                    "concurrency": {},
                    "tasks": [
                        *(
                            {"task_id": f"queued-{index}", "status": "queued", "created_at": 100}
                            for index in range(45)
                        ),
                        *(
                            {"task_id": f"active-{index}", "status": "authorizing", "created_at": 100}
                            for index in range(5)
                        ),
                    ],
                }
            })
        finally:
            module._CURRENT_TASK_ADMISSION = original_admission

        self.assertEqual(public["runtime"]["concurrency"]["task"]["waiting"], 45)

    def test_fast_account_banned_progress_requires_short_pre_phone_execution(self):
        module = self.module

        def progress(*, group="email", elapsed=50, stage_groups=("queue", "oauth", "email")):
            return {
                "group": group,
                "timing": {
                    "execution_started_at": 100,
                    "finished_at": 100 + elapsed,
                    "execution_elapsed_seconds": elapsed,
                    "stages": [
                        {"group": stage_group}
                        for stage_group in stage_groups
                    ],
                },
            }

        self.assertTrue(module._is_fast_account_banned_progress(progress()))
        for value in (
            None,
            {"group": "email", "timing": {}},
            progress(elapsed=91),
            progress(group="phone"),
            progress(stage_groups=("queue", "oauth", "phone")),
            progress(stage_groups=("queue", "email", "sms")),
            progress(stage_groups=("queue", "email", "finalizing")),
            progress(stage_groups=()),
        ):
            with self.subTest(progress=value):
                self.assertFalse(module._is_fast_account_banned_progress(value))

    def test_only_eligible_account_banned_terminal_reports_burst_signal(self):
        module = self.module
        original_state = module._ORIGINAL_TASK_STATE
        original_progress = module._TASK_PROGRESS
        reports = []
        gate = SimpleNamespace(
            report_account_banned=lambda task_id: reports.append(("banned", task_id)),
            report_failure=lambda task_id: reports.append(("failure", task_id)),
        )
        tracker = module._task_progress_ext.TaskProgressTracker(clock=lambda: 150)
        tracker.set_stage("T-fast-banned", "queue_waiting", now=100)
        tracker.mark_execution_started("T-fast-banned", now=100)
        tracker.set_stage("T-fast-banned", "oauth_authorize_node", now=110)
        tracker.set_stage("T-fast-banned", "email_code_verifying", now=120)
        try:
            module._ORIGINAL_TASK_STATE = lambda *_args, **_kwargs: None
            module._TASK_PROGRESS = tracker
            module._patched_task_state(
                SimpleNamespace(task_admission=gate),
                "T-fast-banned",
                status="account_banned",
                error="account_banned: account has been banned",
            )
        finally:
            module._ORIGINAL_TASK_STATE = original_state
            module._TASK_PROGRESS = original_progress

        self.assertEqual(
            reports,
            [("banned", "T-fast-banned"), ("failure", "T-fast-banned")],
        )

    def test_sms_rollback_guard_excludes_stopped_and_cancelled_tasks(self):
        module = self.module
        original_state = module._ORIGINAL_TASK_STATE
        original_guard = module._SMS_QUALITY_GUARD
        observed = []
        guard = SimpleNamespace(
            observe_task=lambda task_id, status, result: observed.append(
                (task_id, status, result)
            )
        )
        try:
            module._ORIGINAL_TASK_STATE = lambda *_args, **_kwargs: None
            module._SMS_QUALITY_GUARD = guard
            for status in ("stopped", "stopped_before_start", "cancelled", "canceled"):
                module._patched_task_state(
                    SimpleNamespace(task_admission=None),
                    f"T-{status}",
                    status=status,
                    result={"sms_cost_usd": 1.0},
                )
            module._patched_task_state(
                SimpleNamespace(task_admission=None),
                "T-completed",
                status="failed",
                result={"sms_cost_usd": 1.0},
            )
        finally:
            module._ORIGINAL_TASK_STATE = original_state
            module._SMS_QUALITY_GUARD = original_guard

        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][:2], ("T-completed", "failed"))
        self.assertEqual(observed[0][2]["sms_cost_usd"], 1.0)

    def test_oauth_rate_limit_is_strong_pressure_but_mailbox_failure_is_not(self):
        module = self.module
        original_state = module._ORIGINAL_TASK_STATE
        original_admission = module._CURRENT_TASK_ADMISSION
        pressure = []
        failures = []

        class Gate:
            def report_pressure(self, task_id, node_code, *, immediate=False):
                pressure.append((task_id, node_code, immediate))

            def report_failure(self, task_id):
                failures.append(task_id)

        gate = Gate()
        try:
            module._ORIGINAL_TASK_STATE = lambda *_args, **_kwargs: None
            module._CURRENT_TASK_ADMISSION = gate
            module._TASK_PROGRESS.reset()
            module._TASK_PROGRESS.set_stage("T-rate-limit", "oauth_authorize_node")
            module._patched_task_state(
                SimpleNamespace(task_admission=gate),
                "T-rate-limit",
                status="retryable_infra",
                error="email_identifier_failed: Too many requests. Please try again later.",
            )
            module._TASK_PROGRESS.set_stage("T-mailbox-origin", "email_login")
            module._patched_task_state(
                SimpleNamespace(task_admission=gate),
                "T-mailbox-origin",
                status="retryable_infra",
                error="mailbox_cross_origin_redirect: mailbox source changed",
            )
            module._TASK_PROGRESS.set_stage("T-mailbox-tls", "email_login")
            module._patched_task_state(
                SimpleNamespace(task_admission=gate),
                "T-mailbox-tls",
                status="retryable_infra",
                error="mailbox_request_failed: TLS connection closed",
            )
            module._TASK_PROGRESS.set_stage("T-email-send-rate", "email_code_waiting")
            module._patched_task_state(
                SimpleNamespace(task_admission=gate),
                "T-email-send-rate",
                status="retryable_infra",
                error="email_otp_send_failed: Too many requests",
            )
        finally:
            module._ORIGINAL_TASK_STATE = original_state
            module._CURRENT_TASK_ADMISSION = original_admission
            module._TASK_PROGRESS.reset()

        self.assertEqual(
            pressure,
            [
                ("T-rate-limit", "protocol_pressure", True),
                ("T-email-send-rate", "protocol_pressure", True),
            ],
        )
        self.assertEqual(
            failures,
            [
                "T-rate-limit",
                "T-mailbox-origin",
                "T-mailbox-tls",
                "T-email-send-rate",
            ],
        )

    def test_terminal_oauth_429_variants_are_all_strong_pressure(self):
        module = self.module
        original_state = module._ORIGINAL_TASK_STATE
        original_admission = module._CURRENT_TASK_ADMISSION
        pressure = []

        class Gate:
            def report_pressure(self, task_id, node_code, *, immediate=False):
                pressure.append((task_id, node_code, immediate))

            def report_failure(self, _task_id):
                return None

        gate = Gate()
        cases = (
            ("T-status-code-429", "status_code: 429"),
            ("T-http-status-429", "HTTP status: 429"),
            ("T-http-error-429", "HTTPError: 429 Client Error"),
        )
        try:
            module._ORIGINAL_TASK_STATE = lambda *_args, **_kwargs: None
            module._CURRENT_TASK_ADMISSION = gate
            module._TASK_PROGRESS.reset()
            for task_id, detail in cases:
                module._TASK_PROGRESS.set_stage(task_id, "oauth_authorize_node")
                module._patched_task_state(
                    SimpleNamespace(task_admission=gate),
                    task_id,
                    status="retryable_infra",
                    error=detail,
                )
        finally:
            module._ORIGINAL_TASK_STATE = original_state
            module._CURRENT_TASK_ADMISSION = original_admission
            module._TASK_PROGRESS.reset()

        self.assertEqual(
            pressure,
            [(task_id, "protocol_pressure", True) for task_id, _detail in cases],
        )

    def test_terminal_local_provider_node_markers_do_not_create_global_pressure(self):
        module = self.module
        original_state = module._ORIGINAL_TASK_STATE
        original_admission = module._CURRENT_TASK_ADMISSION
        pressure = []
        failures = []

        class Gate:
            def report_pressure(self, task_id, node_code, *, immediate=False):
                pressure.append((task_id, node_code, immediate))

            def report_failure(self, task_id):
                failures.append(task_id)

        gate = Gate()
        cases = (
            (
                "T-mailbox-node-marker",
                "email_login",
                "mailbox_request_failed: node_sentinel_failed: TLS connection closed",
            ),
            (
                "T-sms-node-marker",
                "sms_waiting",
                "sms_provider_poll_failed: node_sentinel_failed: HTTPError: 429 Client Error",
            ),
        )
        try:
            module._ORIGINAL_TASK_STATE = lambda *_args, **_kwargs: None
            module._CURRENT_TASK_ADMISSION = gate
            module._TASK_PROGRESS.reset()
            for task_id, stage, detail in cases:
                module._TASK_PROGRESS.set_stage(task_id, stage)
                module._patched_task_state(
                    SimpleNamespace(task_admission=gate),
                    task_id,
                    status="retryable_infra",
                    error=detail,
                )
        finally:
            module._ORIGINAL_TASK_STATE = original_state
            module._CURRENT_TASK_ADMISSION = original_admission
            module._TASK_PROGRESS.reset()

        self.assertEqual(pressure, [])
        self.assertEqual(failures, [task_id for task_id, _stage, _detail in cases])

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

    def test_terminal_node_pressure_upgrades_the_nonterminal_retry_signal(self):
        module = self.module
        gate = module._adaptive_concurrency_ext.AdaptiveConcurrencyGate(5, ceiling=8)
        fake_self = SimpleNamespace(task_admission=gate)
        original_state = module._ORIGINAL_TASK_STATE
        original_event = module._ORIGINAL_CHAIN_EVENT
        original_admission = module._CURRENT_TASK_ADMISSION
        task_token = module._TASK_CONTEXT.set("T-pressure-node")
        try:
            module._CURRENT_TASK_ADMISSION = gate
            module._ORIGINAL_TASK_STATE = lambda *_args, **_kwargs: None
            module._ORIGINAL_CHAIN_EVENT = lambda *_args, **_kwargs: None
            module._TASK_PROGRESS.reset()
            module._patched_chain_event(
                [],
                "FAILED",
                detail="node_sentinel_failed: node_bridge_timeout",
            )
            module._patched_task_state(
                fake_self,
                "T-pressure-node",
                status="failed",
                error="node_sentinel_failed: node_bridge_timeout",
            )
        finally:
            module._TASK_CONTEXT.reset(task_token)
            module._ORIGINAL_TASK_STATE = original_state
            module._ORIGINAL_CHAIN_EVENT = original_event
            module._CURRENT_TASK_ADMISSION = original_admission
            module._TASK_PROGRESS.reset()

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["pressure_count"], 2)
        self.assertEqual(snapshot["limit"], 4)
        gate.report_pressure("T-pressure-other", "oauth_create_node")
        self.assertEqual(gate.snapshot()["limit"], 4)

    def test_node_transport_failure_is_not_double_degraded_by_wrapper_and_terminal(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION
        original_state = module._ORIGINAL_TASK_STATE
        original_gate = module._PROTOCOL_GATE
        original_admission = module._CURRENT_TASK_ADMISSION
        cases = (
            ("node_sentinel_failed: TLS handshake failed", True),
            ("node_sentinel_failed: Proxy CONNECT aborted", False),
        )
        try:
            module._ORIGINAL_TASK_STATE = lambda *_args, **_kwargs: None
            for index, (detail, raises) in enumerate(cases):
                task_id = f"T-node-transport-{index}"
                gate = module._adaptive_concurrency_ext.AdaptiveConcurrencyGate(
                    8,
                    ceiling=12,
                    restore_ceiling=8,
                )
                with gate.condition:
                    gate.waiting = 1
                for banned_index in range(4):
                    gate.report_account_banned(f"banned-{index}-{banned_index}")
                self.assertEqual(gate.snapshot()["limit"], 10)

                module._CURRENT_TASK_ADMISSION = gate
                module._PROTOCOL_GATE = module._sms_runtime_ext.ProxyProtocolGate(
                    default_limit=5,
                    launch_interval_seconds=0,
                )
                if raises:
                    module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = (
                        lambda failure=detail, **_kwargs: (_ for _ in ()).throw(
                            RuntimeError(failure)
                        )
                    )
                else:
                    module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = (
                        lambda failure=detail, **_kwargs: {
                            "ok": False,
                            "error": failure,
                        }
                    )
                module._TASK_PROGRESS.reset()
                module._TASK_PROGRESS.set_stage(task_id, "oauth_create_node")
                admission_token = module._TASK_ADMISSION_CONTEXT.set(gate)
                try:
                    if raises:
                        with self.assertRaises(RuntimeError):
                            module._run_codex_after_registration(
                                oauth_url="https://auth.example.test/authorize",
                                account_email="masked@example.test",
                                config={"sms_task_id": task_id},
                            )
                    else:
                        module._run_codex_after_registration(
                            oauth_url="https://auth.example.test/authorize",
                            account_email="masked@example.test",
                            config={"sms_task_id": task_id},
                        )
                finally:
                    module._TASK_ADMISSION_CONTEXT.reset(admission_token)
                module._patched_task_state(
                    SimpleNamespace(task_admission=gate),
                    task_id,
                    status="retryable_infra",
                    error=detail,
                )

                snapshot = gate.snapshot()
                self.assertEqual(snapshot["limit"], 8)
                self.assertEqual(snapshot["pressure_count"], 1)
                self.assertEqual(snapshot["burst_revocations"], 1)
                self.assertEqual(snapshot["degradations"], 0)
        finally:
            module._TASK_PROGRESS.reset()
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = original_run
            module._ORIGINAL_TASK_STATE = original_state
            module._PROTOCOL_GATE = original_gate
            module._CURRENT_TASK_ADMISSION = original_admission

    def test_business_terminal_failures_do_not_create_admission_pressure(self):
        module = self.module
        gate = module._adaptive_concurrency_ext.AdaptiveConcurrencyGate(5, ceiling=8)
        fake_self = SimpleNamespace(task_admission=gate)
        original_state = module._ORIGINAL_TASK_STATE
        try:
            module._ORIGINAL_TASK_STATE = lambda *_args, **_kwargs: None
            module._TASK_PROGRESS.reset()
            for task_id, status, detail in (
                ("T-sms-timeout", "failed", "sms_timeout: no code received"),
                ("T-mailbox", "failed", "mailbox_code_timeout: no new code"),
                ("T-banned", "account_banned", "account disabled"),
            ):
                module._patched_task_state(
                    fake_self,
                    task_id,
                    status=status,
                    error=detail,
                )
        finally:
            module._ORIGINAL_TASK_STATE = original_state
            module._TASK_PROGRESS.reset()

        snapshot = gate.snapshot()
        self.assertEqual(snapshot["pressure_count"], 0)
        self.assertEqual(snapshot["limit"], 5)
        self.assertEqual(snapshot["failure_count"], 3)

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
                "mfa_otp_verifying",
            )
        finally:
            module._ORIGINAL_REAL_POST_AUTH_JSON = original_post
            module._auth_request_runtime_ext.begin_request = original_begin
            module._TASK_PROGRESS.reset()
            module._TASK_CONTEXT.reset(token)

    def test_expired_mfa_step_never_reenters_dynamic_challenge(self):
        module = self.module
        original_patches = module._TOTP_PATCHES
        original_observe = module._observe_auth_step
        challenge_calls = []
        expired = {
            "_status": 401,
            "error": {"code": "mfa_authorization_step_expired"},
            "page": {"type": "mfa_challenge"},
        }
        transport = SimpleNamespace(
            send_mfa_otp=lambda *_args: challenge_calls.append("send"),
            verify_mfa_otp=lambda *_args: challenge_calls.append("verify"),
        )
        module._auth_challenge_runtime_ext.bind_transport_context(
            transport,
            account_email="masked@example.test",
            email_otp_provider=SimpleNamespace(),
            config={"dynamic_auth_challenges": True},
        )
        try:
            module._TOTP_PATCHES = SimpleNamespace(
                verify_mfa_otp=lambda *_args: expired,
            )
            module._observe_auth_step = lambda *_args: None
            result = module._real_verify_mfa_otp(transport, "private-code")
        finally:
            module._TOTP_PATCHES = original_patches
            module._observe_auth_step = original_observe
            module._auth_challenge_runtime_ext.clear_transport_context(transport)

        self.assertIs(result, expired)
        self.assertEqual(challenge_calls, [])
        self.assertFalse(hasattr(transport, "_gptphone_auth_challenge_context"))

    def test_incorrect_totp_never_opens_manual_code_prompt(self):
        module = self.module
        secret = "JBSWY3DPEHPK3PXP"
        logs = []
        seen_codes = []
        originals = {
            "patches": module._TOTP_PATCHES,
            "wait": module._manual_verification_runtime_ext.wait_for_manual,
            "observe": module._observe_auth_step,
            "checkpoint": module._checkpoint_save_after_auth,
            "continue": module._auth_challenge_runtime_ext.continue_if_needed,
        }
        token = module._TASK_CONTEXT.set("T-manual-totp")
        transport = SimpleNamespace(
            _gptphone_totp_manual_secret=secret,
            config={"sms_task_id": "T-manual-totp"},
            log_fn=lambda message, level="info": logs.append((message, level)),
        )
        try:
            def verify(_transport, value):
                seen_codes.append(value)
                return {"_status": 403, "error": {"code": "incorrect_code"}}

            module._TOTP_PATCHES = SimpleNamespace(verify_mfa_otp=verify)
            module._manual_verification_runtime_ext.wait_for_manual = (
                lambda **_kwargs: self.fail("manual prompt must not open")
            )
            module._observe_auth_step = lambda *_args: None
            module._checkpoint_save_after_auth = lambda *_args: None
            module._auth_challenge_runtime_ext.continue_if_needed = lambda _transport, response, **_kwargs: response

            result = module._real_verify_mfa_otp(transport, "123456")
        finally:
            module._TOTP_PATCHES = originals["patches"]
            module._manual_verification_runtime_ext.wait_for_manual = originals["wait"]
            module._observe_auth_step = originals["observe"]
            module._checkpoint_save_after_auth = originals["checkpoint"]
            module._auth_challenge_runtime_ext.continue_if_needed = originals["continue"]
            module._TASK_CONTEXT.reset(token)

        self.assertEqual(result["_status"], 403)
        self.assertEqual(seen_codes, ["123456"])
        self.assertFalse(hasattr(transport, "_gptphone_totp_manual_secret"))
        self.assertNotIn(secret, repr(logs))
        self.assertIn("不打开人工输入", repr(logs))

    def test_repeated_incorrect_totp_still_skips_manual_prompt(self):
        module = self.module
        secret = "JBSWY3DPEHPK3PXP"
        logs = []
        originals = {
            "patches": module._TOTP_PATCHES,
            "wait": module._manual_verification_runtime_ext.wait_for_manual,
            "observe": module._observe_auth_step,
            "checkpoint": module._checkpoint_save_after_auth,
            "continue": module._auth_challenge_runtime_ext.continue_if_needed,
        }
        token = module._TASK_CONTEXT.set("T-manual-timeout")
        transport = SimpleNamespace(
            _gptphone_totp_manual_secret=secret,
            config={"sms_task_id": "T-manual-timeout"},
            log_fn=lambda message, level="info": logs.append((message, level)),
        )
        rejected = {"_status": 403, "error": {"code": "incorrect_code"}}
        try:
            module._TOTP_PATCHES = SimpleNamespace(verify_mfa_otp=lambda *_args: rejected)
            module._manual_verification_runtime_ext.wait_for_manual = (
                lambda **_kwargs: self.fail("manual prompt must not open")
            )
            module._observe_auth_step = lambda *_args: None
            module._checkpoint_save_after_auth = lambda *_args: None
            module._auth_challenge_runtime_ext.continue_if_needed = lambda _transport, response, **_kwargs: response

            result = module._real_verify_mfa_otp(transport, "123456")
            repeated = module._real_verify_mfa_otp(transport, "123456")
        finally:
            module._TOTP_PATCHES = originals["patches"]
            module._manual_verification_runtime_ext.wait_for_manual = originals["wait"]
            module._observe_auth_step = originals["observe"]
            module._checkpoint_save_after_auth = originals["checkpoint"]
            module._auth_challenge_runtime_ext.continue_if_needed = originals["continue"]
            module._TASK_CONTEXT.reset(token)

        self.assertIs(result, rejected)
        self.assertIs(repeated, rejected)
        self.assertFalse(hasattr(transport, "_gptphone_totp_manual_secret"))
        self.assertIn("不打开人工输入", repr(logs))
        self.assertNotIn(secret, repr(logs))

    def test_sms_wait_code_uses_provider_only_without_manual_prompt(self):
        module = self.module
        originals = {
            "adapter_wait_code": module._SMS_WEB.adapter_wait_code,
            "fallback": module._manual_verification_runtime_ext.wait_with_manual_fallback,
        }
        provider = SimpleNamespace(task_id="T-sms", log_fn=lambda *_args: None)
        lease = SimpleNamespace(task_id="T-sms")
        try:
            module._SMS_WEB.adapter_wait_code = lambda _provider, _lease, timeout=180: "246810"
            module._manual_verification_runtime_ext.wait_with_manual_fallback = (
                lambda *_args, **_kwargs: self.fail("manual prompt must not open")
            )

            result = module._sms_adapter_wait_code(provider, lease, timeout=90)
        finally:
            module._SMS_WEB.adapter_wait_code = originals["adapter_wait_code"]
            module._manual_verification_runtime_ext.wait_with_manual_fallback = originals["fallback"]

        self.assertEqual(result, "246810")

    def test_session_invalid_incorrect_totp_never_opens_manual_prompt(self):
        module = self.module
        secret = "JBSWY3DPEHPK3PXP"
        originals = {
            "patches": module._TOTP_PATCHES,
            "wait": module._manual_verification_runtime_ext.wait_for_manual,
            "observe": module._observe_auth_step,
            "checkpoint": module._checkpoint_save_after_auth,
            "continue": module._auth_challenge_runtime_ext.continue_if_needed,
        }
        token = module._TASK_CONTEXT.set("T-manual-invalid")
        transport = SimpleNamespace(
            _gptphone_totp_manual_secret=secret,
            config={"sms_task_id": "T-manual-invalid"},
        )
        invalid = {
            "_status": 401,
            "error": {"code": "incorrect_code", "message": "oauth_session_invalid"},
        }
        try:
            module._TOTP_PATCHES = SimpleNamespace(verify_mfa_otp=lambda *_args: invalid)
            module._manual_verification_runtime_ext.wait_for_manual = lambda **_kwargs: self.fail("manual prompt must not open")
            module._observe_auth_step = lambda *_args: None
            module._checkpoint_save_after_auth = lambda *_args: None
            module._auth_challenge_runtime_ext.continue_if_needed = lambda _transport, response, **_kwargs: response

            result = module._real_verify_mfa_otp(transport, "123456")
        finally:
            module._TOTP_PATCHES = originals["patches"]
            module._manual_verification_runtime_ext.wait_for_manual = originals["wait"]
            module._observe_auth_step = originals["observe"]
            module._checkpoint_save_after_auth = originals["checkpoint"]
            module._auth_challenge_runtime_ext.continue_if_needed = originals["continue"]
            module._TASK_CONTEXT.reset(token)

        self.assertIs(result, invalid)
        self.assertFalse(hasattr(transport, "_gptphone_totp_manual_secret"))

    def test_post_auth_mfa_expiry_refreshes_once_and_returns_fresh_success(self):
        module = self.module
        secret = "JBSWY3DPEHPK3PXP"
        factor = "factor-private"
        logs = []
        calls = []
        originals = {
            "post": module._ORIGINAL_REAL_POST_AUTH_JSON,
            "begin": module._auth_request_runtime_ext.begin_request,
            "finish": module._auth_request_runtime_ext.finish_request,
        }
        transport = SimpleNamespace(_gptphone_totp_secret=secret, log_fn=lambda message, level="info": logs.append((message, level)))
        expired = {"_status": 403, "error": {"code": "mfa_authorization_step_expired"}}
        try:
            def post(_transport, path, payload, **_kwargs):
                calls.append((path, dict(payload)))
                if len(calls) == 1:
                    return expired
                if path.endswith("issue_challenge"):
                    return {"_status": 200}
                return {"_status": 200, "page": {"type": "add_phone"}}

            module._ORIGINAL_REAL_POST_AUTH_JSON = post
            module._auth_request_runtime_ext.begin_request = lambda *_args, **kwargs: {
                "stage": kwargs["stage"], "session_generation": 5,
            }
            module._auth_request_runtime_ext.finish_request = lambda *_args, **_kwargs: {}

            result = module._real_post_auth_json(
                transport,
                "/api/accounts/mfa/verify",
                {"id": factor, "type": "totp", "code": "123456"},
                flow="mfa_otp_verify",
                referer="https://auth.openai.com/mfa-challenge/redacted",
            )
        finally:
            module._ORIGINAL_REAL_POST_AUTH_JSON = originals["post"]
            module._auth_request_runtime_ext.begin_request = originals["begin"]
            module._auth_request_runtime_ext.finish_request = originals["finish"]

        self.assertEqual(result["_status"], 200)
        self.assertEqual([path for path, _payload in calls], [
            "/api/accounts/mfa/verify",
            "/api/accounts/mfa/issue_challenge",
            "/api/accounts/mfa/verify",
        ])
        self.assertTrue(calls[1][1]["force_fresh_challenge"])
        self.assertNotIn(secret, repr(logs))
        self.assertNotIn(factor, repr(logs))

    def test_post_auth_second_mfa_expiry_invalidates_the_session_with_safe_stage(self):
        module = self.module
        secret = "JBSWY3DPEHPK3PXP"
        invalidations = []
        originals = {
            "post": module._ORIGINAL_REAL_POST_AUTH_JSON,
            "begin": module._auth_request_runtime_ext.begin_request,
            "finish": module._auth_request_runtime_ext.finish_request,
            "invalidate": module._auth_request_runtime_ext.invalidate_auth_session,
            "checkpoint": module._checkpoint_delete_after_auth,
        }
        transport = SimpleNamespace(_gptphone_totp_secret=secret)
        expired = {"_status": 403, "error": {"code": "mfa_authorization_step_expired"}}
        calls = []
        try:
            def post(_transport, path, payload, **_kwargs):
                calls.append((path, dict(payload)))
                return {"_status": 200} if path.endswith("issue_challenge") else expired

            module._ORIGINAL_REAL_POST_AUTH_JSON = post
            module._auth_request_runtime_ext.begin_request = lambda *_args, **kwargs: {
                "stage": kwargs["stage"], "session_generation": 5,
            }
            module._auth_request_runtime_ext.finish_request = lambda *_args, **_kwargs: {}
            module._auth_request_runtime_ext.invalidate_auth_session = lambda *_args, **kwargs: invalidations.append(kwargs)
            module._checkpoint_delete_after_auth = lambda *_args: None

            result = module._real_post_auth_json(
                transport,
                "/api/accounts/mfa/verify",
                {"id": "factor-private", "type": "totp", "code": "123456"},
                flow="mfa_otp_verify",
                referer="https://auth.openai.com/mfa-challenge/redacted",
            )
        finally:
            module._ORIGINAL_REAL_POST_AUTH_JSON = originals["post"]
            module._auth_request_runtime_ext.begin_request = originals["begin"]
            module._auth_request_runtime_ext.finish_request = originals["finish"]
            module._auth_request_runtime_ext.invalidate_auth_session = originals["invalidate"]
            module._checkpoint_delete_after_auth = originals["checkpoint"]

        self.assertIs(result, expired)
        self.assertEqual(len(calls), 3)
        self.assertEqual(invalidations, [{"stage": "mfa_otp_verifying"}])

    def test_url_mailbox_totp_is_generated_after_slow_header_preparation(self):
        module = self.module
        secret = "JBSWY3DPEHPK3PXP"
        clock = [1.0]
        sent_payloads = []
        logs = []
        observed_stages = []
        originals = {
            "verify_email": module._ORIGINAL_REAL_VERIFY_EMAIL_OTP,
            "headers": module._ORIGINAL_REAL_HEADERS,
            "request_headers": module._auth_request_runtime_ext.request_headers,
            "observe": module._observe_auth_step,
            "refresh": module._chatgpt_totp_ext.refresh_transport_totp_payload,
        }

        def slow_headers(_transport, _flow, _referer):
            clock[0] = 37.0
            return {"content-type": "application/json"}

        def post_auth_json(transport, _path, payload, *, flow, referer, timeout=30):
            self.assertEqual(timeout, 30)
            module._real_headers(transport, flow, referer)
            sent_payloads.append(copy.deepcopy(payload))
            return {"_status": 200, "page": {"type": "consent"}}

        transport = SimpleNamespace(
            _gptphone_totp_refresh_in_headers=True,
            log_fn=lambda message, level="info": logs.append((message, level)),
        )
        transport._post_auth_json = MethodType(post_auth_json, transport)
        module._MAILBOX_TOTP_SECRET_CONTEXT.set(secret)
        try:
            module._ORIGINAL_REAL_VERIFY_EMAIL_OTP = lambda *_args: {
                "_status": 200,
                "page": {
                    "type": "mfa_otp",
                    "payload": {"factor_id": "factor-safe"},
                },
            }
            module._ORIGINAL_REAL_HEADERS = slow_headers
            module._auth_request_runtime_ext.request_headers = (
                lambda _transport, headers: headers
            )
            module._observe_auth_step = (
                lambda _transport, _response, stage: observed_stages.append(stage)
            )
            module._chatgpt_totp_ext.refresh_transport_totp_payload = (
                lambda current_transport, flow: originals["refresh"](
                    current_transport,
                    flow,
                    now_fn=lambda: clock[0],
                    sleep_fn=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
                )
            )

            response = module._real_verify_email_otp(transport, "private-email-code")
        finally:
            module._MAILBOX_TOTP_SECRET_CONTEXT.set("")
            module._ORIGINAL_REAL_VERIFY_EMAIL_OTP = originals["verify_email"]
            module._ORIGINAL_REAL_HEADERS = originals["headers"]
            module._auth_request_runtime_ext.request_headers = originals["request_headers"]
            module._observe_auth_step = originals["observe"]
            module._chatgpt_totp_ext.refresh_transport_totp_payload = originals["refresh"]

        self.assertEqual(response["_status"], 200)
        self.assertEqual(len(sent_payloads), 1)
        self.assertEqual(
            sent_payloads[0]["code"],
            module._chatgpt_totp_ext.totp_code(secret, now=37.0),
        )
        self.assertEqual(observed_stages, ["mfa_otp_verifying"])
        self.assertFalse(hasattr(transport, "_gptphone_totp_payload"))
        self.assertFalse(hasattr(transport, "_gptphone_totp_secret"))
        serialized_logs = json.dumps(logs, ensure_ascii=False)
        self.assertNotIn(secret, serialized_logs)
        self.assertNotIn(sent_payloads[0]["code"], serialized_logs)
        self.assertNotIn("private-email-code", serialized_logs)

    def test_task_boundary_clears_url_totp_secret_after_early_exit(self):
        module = self.module
        original_run_one = module._ORIGINAL_IMPORTER_RUN_ONE
        observed = []

        def run_one(_self, _settings, ordinal, *_args):
            observed.append(module._MAILBOX_TOTP_SECRET_CONTEXT.get(""))
            if ordinal == 1:
                module._MAILBOX_TOTP_SECRET_CONTEXT.set("JBSWY3DPEHPK3PXP")
            return ordinal

        try:
            module._ORIGINAL_IMPORTER_RUN_ONE = run_one
            self.assertEqual(module._patched_importer_run_one(object(), {}, 1), 1)
            self.assertEqual(module._patched_importer_run_one(object(), {}, 2), 2)
        finally:
            module._ORIGINAL_IMPORTER_RUN_ONE = original_run_one
            module._MAILBOX_TOTP_SECRET_CONTEXT.set("")

        self.assertEqual(observed, ["", ""])
        self.assertEqual(module._MAILBOX_TOTP_SECRET_CONTEXT.get(""), "")

    def test_legacy_run_one_call_generates_cleanup_visible_task_id(self):
        module = self.module
        original_run_one = module._ORIGINAL_IMPORTER_RUN_ONE
        observed = {}

        class Session:
            close_calls = 0

            def close(self):
                self.close_calls += 1
                if self.close_calls == 1:
                    raise OSError("temporary close failure")

        def run_one(_self, _settings, _ordinal, _entry, task_id):
            observed["task_id"] = task_id
            observed["session"] = Session()
            transport = SimpleNamespace(
                config={"sms_task_id": task_id},
                session=observed["session"],
            )
            module._register_sms_transport(task_id, transport)
            return task_id

        try:
            module._ORIGINAL_IMPORTER_RUN_ONE = run_one
            result = module._patched_importer_run_one(object(), {}, 7)
        finally:
            module._ORIGINAL_IMPORTER_RUN_ONE = original_run_one

        self.assertRegex(result, r"^T007-[0-9a-f]{6}$")
        self.assertEqual(observed["task_id"], result)
        self.assertEqual(observed["session"].close_calls, 2)
        self.assertIsNone(module._transport_for_task(result))
        self.assertEqual(
            module._SMS_TRANSPORT_REGISTRY.snapshot()["pending_cleanup"],
            0,
        )

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

        self.assertEqual(public["failure"]["node_code"], "mfa_otp_verifying")
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
            self.assertNotIn("pixel_upload_enabled", value)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_email_timeout_migration_updates_legacy_default_and_preserves_custom_value(self):
        module = self.module
        legacy, legacy_changed = module._migrate_email_timeout_config(
            {"email_code_timeout": 150}
        )
        legacy_default, legacy_default_changed = module._migrate_email_timeout_config(
            {"email_code_timeout": 90}
        )
        custom, custom_changed = module._migrate_email_timeout_config(
            {
                "email_code_timeout": 90,
                "email_timeout_strategy_version": 3,
            }
        )

        self.assertTrue(legacy_changed)
        self.assertEqual(legacy["email_code_timeout"], 60)
        self.assertEqual(legacy["email_timeout_strategy_version"], 3)
        self.assertTrue(legacy_default_changed)
        self.assertEqual(legacy_default["email_code_timeout"], 60)
        self.assertEqual(legacy_default["email_timeout_strategy_version"], 3)
        self.assertFalse(custom_changed)
        self.assertEqual(custom["email_code_timeout"], 90)
        self.assertEqual(custom["email_timeout_strategy_version"], 3)

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

        self.assertEqual(loaded["email_code_timeout"], 60)
        self.assertEqual(loaded["email_otp_verify_attempts"], 2)
        self.assertTrue(loaded["email_otp_resend_on_retry"])
        self.assertEqual(loaded["email_timeout_strategy_version"], 3)
        self.assertEqual(persisted["email_timeout_strategy_version"], 3)
        self.assertEqual(Path(store.path).stat().st_mode & 0o777, 0o600)

        saved = store.save({
            **loaded,
            "email_code_timeout": 90,
            "email_timeout_strategy_version": 3,
            "email_otp_verify_attempts": 3,
            "email_otp_resend_on_retry": False,
        })

        self.assertEqual(saved["email_code_timeout"], 90)
        self.assertEqual(saved["email_timeout_strategy_version"], 3)
        self.assertEqual(saved["email_otp_verify_attempts"], 3)
        self.assertFalse(saved["email_otp_resend_on_retry"])
        self.assertEqual(Path(store.path).stat().st_mode & 0o777, 0o600)

    def test_private_json_writes_remain_atomic_under_concurrent_saves(self):
        module = self.module
        path = Path(self.tempdir.name) / "concurrent-config" / "config.json"
        barrier = threading.Barrier(5)
        errors = []

        def write(index):
            try:
                barrier.wait(timeout=2)
                module._atomic_write_private_json(
                    path,
                    {"writer": index, "secret": f"private-{index}"},
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=write, args=(index,)) for index in range(4)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)

        self.assertEqual(errors, [])
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        persisted = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(persisted["writer"], range(4))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(path.parent.glob(".*.tmp")), [])

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

    def test_relative_result_directory_is_resolved_from_importer_data_dir(self):
        module = self.module
        original_persist = module._ORIGINAL_PERSIST_RESULT
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "runtime-data"
            entry = SimpleNamespace(email="relative@example.test")
            observed = {}

            def persist(fake_self, settings, task_id, value, result, *, error="", status="failed"):
                observed["results_dir"] = settings["results_dir"]
                target = Path(settings["results_dir"]) / (
                    f"{task_id}_{value.email.replace('@', '_at_')}.json"
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    json.dumps({"task_id": task_id, "status": status, "result": result}),
                    encoding="utf-8",
                )

            fake_self = SimpleNamespace(
                data_dir=data_dir,
                _source_row=lambda _entry: "relative@example.test----private-password",
                _log=lambda *_args, **_kwargs: None,
            )
            try:
                module._ORIGINAL_PERSIST_RESULT = persist
                module._TASK_PROGRESS.reset()
                module._patched_persist_result(
                    fake_self,
                    {"results_dir": "relative-results"},
                    "T-relative",
                    entry,
                    {},
                    status="success",
                )
            finally:
                module._ORIGINAL_PERSIST_RESULT = original_persist
                module._TASK_PROGRESS.reset()

            expected_dir = (data_dir / "relative-results").resolve()
            self.assertEqual(Path(observed["results_dir"]), expected_dir)
            self.assertTrue(
                (expected_dir / "T-relative_relative_at_example.test.json").is_file()
            )

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
        lifecycle = module._NOTIFICATION_LIFECYCLE
        previous_context = lifecycle.context_for()
        try:
            with lifecycle._lock:
                lifecycle._context = {
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
            with lifecycle._lock:
                lifecycle._context = previous_context

        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["success"], 0)
        self.assertEqual(summary["active"], 1)
        self.assertEqual(summary["sms_cost_cny"], 0)

    def test_success_result_persistence_does_not_enqueue_pixel_before_batch_terminal(self):
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
            def enqueue(self, *_args, **_kwargs):
                raise AssertionError("Pixel must wait until the batch is terminal")

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
                {"results_dir": str(result_dir)},
                "task-1",
                entry,
                {"access_token": "not-used"},
                status="success",
            )
            self.assertEqual(returned, "persisted")
            self.assertEqual(calls, [])
            self.assertTrue((result_dir / "task-1_success_at_example.test.json").is_file())
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
