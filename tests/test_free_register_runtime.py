from __future__ import annotations

import json
import copy
from concurrent.futures import Future
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
from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.free_priority_executor import PriorityExecutor
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

    def test_free_adapter_substep_timing_is_aggregated_and_safe(self):
        logs = []
        manager = FreeRegisterManager(
            self.data_dir,
            log_fn=lambda message, level="info", **fields: logs.append(
                (message, level, fields)
            ),
        )
        manager._tasks["timing-task"] = {
            "task_id": "timing-task",
            "status": "running",
            "created_at": 100,
            "timing": {},
        }

        manager._record_timing_substep(
            "timing-task", "free_camoufox_profile", "profile_name_fill", 120, "success"
        )
        manager._record_timing_substep(
            "timing-task", "free_camoufox_profile", "profile_name_fill", 80, "success"
        )
        manager._record_timing_substep(
            "timing-task", "free_camoufox_profile", "profile_consent", 0, "skipped"
        )

        rows = manager._tasks["timing-task"]["timing"]["substeps"]
        name = next(row for row in rows if row["code"] == "profile_name_fill")
        consent = next(row for row in rows if row["code"] == "profile_consent")
        self.assertEqual(name["duration_ms"], 200)
        self.assertEqual(name["first_duration_ms"], 120)
        self.assertEqual(name["last_duration_ms"], 80)
        self.assertEqual(name["max_duration_ms"], 120)
        self.assertEqual(name["visits"], 2)
        self.assertEqual(consent["outcome"], "skipped")
        self.assertNotIn("654321", str(rows))
        self.assertTrue(any("子步骤完成" in message for message, _level, _fields in logs))

    def test_manager_timing_splits_queue_and_execution_and_freezes_terminal_values(self):
        manager = FreeRegisterManager(self.data_dir, log_fn=lambda *_args, **_kwargs: None)
        manager._tasks["timing-lifecycle"] = {
            "task_id": "timing-lifecycle",
            "status": "running",
            "created_at": 100,
            "stage": "free_oauth_session",
            "timing": {"started_at": 100},
            "progress": {
                "stage": "free_oauth_session",
                "stage_started_at": 112,
                "started_at": 100,
            },
        }
        with (
            patch("mac_overrides.free_register_runtime.time.time", side_effect=(112, 125)),
            patch("mac_overrides.free_register_runtime.time.monotonic", side_effect=(0.0, 13.0)),
        ):
            self.assertTrue(manager._mark_execution_started("timing-lifecycle"))
            manager._finish_progress("timing-lifecycle")

        timing = manager._tasks["timing-lifecycle"]["timing"]
        self.assertEqual(timing["queued_at"], 100)
        self.assertEqual(timing["execution_started_at"], 112)
        self.assertEqual(timing["queue_elapsed_seconds"], 12.0)
        self.assertEqual(timing["execution_elapsed_seconds"], 13.0)
        self.assertEqual(timing["finished_at"], 125)
        self.assertEqual(manager._tasks["timing-lifecycle"]["progress"]["timing"], timing)

    def test_manager_timing_record_backfills_legacy_fields(self):
        manager = FreeRegisterManager(self.data_dir)
        task = {"task_id": "legacy-timing", "status": "failed", "created_at": 100, "timing": {"elapsed_ms": 4}}
        timing = manager._timing_record(task)
        self.assertEqual(timing["started_at"], 100)
        self.assertEqual(timing["queued_at"], 100)
        self.assertIsNone(timing["execution_started_at"])
        self.assertEqual(timing["queue_elapsed_seconds"], 0.0)
        self.assertEqual(timing["execution_elapsed_seconds"], 0.0)
        manager._tasks["legacy-timing"] = task
        public_timing = manager.public_tasks()[0]["timing"]
        self.assertEqual(public_timing["queued_at"], 100)
        self.assertIsNone(public_timing.get("execution_started_at"))

    def test_task_log_infers_concrete_driver_for_diagnostic_scope(self):
        diagnostics = DiagnosticStore(self.data_dir / "diagnostics")
        manager = FreeRegisterManager(self.data_dir, diagnostic_store=diagnostics)
        manager._tasks["free-driver-scope"] = {
            "task_id": "free-driver-scope",
            "driver": "camoufox",
            "status": "running",
        }

        manager._log(
            "[free-driver-scope/Free 入口/free_entry] 开始",
            "info",
        )

        rows = diagnostics.search({"task_id": "free-driver-scope"})
        self.assertEqual(len(rows), 1)
        incident = diagnostics.incident(rows[0]["incident_id"])
        assert incident is not None
        self.assertEqual(incident["driver"], "camoufox")
        self.assertEqual(incident["events"][0]["driver"], "camoufox")

    def test_free_adapter_substeps_use_bounded_task_store_checkpoints(self):
        manager = FreeRegisterManager(
            self.data_dir,
            log_fn=lambda *_args, **_kwargs: None,
        )
        manager._tasks["timing-checkpoint"] = {
            "task_id": "timing-checkpoint",
            "status": "running",
            "created_at": 100,
            "timing": {},
        }
        clock = [0.0]
        with (
            patch.object(manager.task_store, "save_timing", return_value=True) as save_timing,
            patch(
                "mac_overrides.free_register_runtime.time.monotonic",
                side_effect=lambda: clock[0],
            ),
        ):
            manager._record_timing_substep(
                "timing-checkpoint", "free_camoufox_profile",
                "profile_name_fill", 10, "success",
            )
            manager._record_timing_substep(
                "timing-checkpoint", "free_camoufox_profile",
                "profile_age_fill", 20, "success",
            )
            self.assertEqual(save_timing.call_count, 1)
            clock[0] += 1.1
            manager._record_timing_substep(
                "timing-checkpoint", "free_camoufox_profile",
                "profile_birthday_fill", 30, "success",
            )
            self.assertEqual(save_timing.call_count, 2)
            # A failure is flushed without waiting for the next interval.
            manager._record_timing_substep(
                "timing-checkpoint", "free_camoufox_profile",
                "profile_submit_button_wait", 40, "timeout",
            )
            self.assertEqual(save_timing.call_count, 3)

    def test_timing_checkpoint_merges_only_timing_and_skips_terminal_task(self):
        store = __import__("mac_overrides.free_register_store", fromlist=["FreeTaskStore"]).FreeTaskStore(self.data_dir)
        store.save({
            "running-task": {
                "task_id": "running-task",
                "status": "running",
                "result": {"preserve": True},
                "timing": {"elapsed_ms": 1},
            },
            "other-task": {"task_id": "other-task", "status": "queued", "marker": "keep"},
        })
        self.assertTrue(store.save_timing("running-task", {"elapsed_ms": 42, "substeps": []}))
        payload = json.loads(store.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["tasks"]["running-task"]["timing"]["elapsed_ms"], 42)
        self.assertEqual(payload["tasks"]["running-task"]["result"], {"preserve": True})
        self.assertEqual(payload["tasks"]["other-task"]["marker"], "keep")

        store.save({"running-task": {"task_id": "running-task", "status": "success", "timing": {"elapsed_ms": 99}}})
        self.assertFalse(store.save_timing("running-task", {"elapsed_ms": 100}))
        terminal_payload = json.loads(store.path.read_text(encoding="utf-8"))
        self.assertEqual(terminal_payload["tasks"]["running-task"]["timing"]["elapsed_ms"], 99)

    def test_stale_timing_checkpoint_cannot_rollback_newer_running_snapshot(self):
        store = __import__("mac_overrides.free_register_store", fromlist=["FreeTaskStore"]).FreeTaskStore(self.data_dir)
        newer_timing = {
            "started_at": 100,
            "elapsed_ms": 99,
            "elapsed_seconds": 0.099,
            "finished_at": None,
            "stages": [
                {"code": "free_camoufox_profile", "attempt": 1, "started_at": 100, "finished_at": 110, "duration_ms": 10},
                {"code": "free_email_otp_wait", "attempt": 1, "started_at": 111, "finished_at": 199, "duration_ms": 88},
            ],
            "substeps": [
                {"key": "free_camoufox_profile:profile_name_fill", "stage_code": "free_camoufox_profile", "code": "profile_name_fill", "duration_ms": 30, "first_duration_ms": 10, "last_duration_ms": 20, "max_duration_ms": 20, "visits": 2, "last_recorded_at": 200, "outcome": "success"},
                {"key": "free_email_otp_wait:mailbox_poll_scan", "stage_code": "free_email_otp_wait", "code": "mailbox_poll_scan", "duration_ms": 40, "visits": 1, "last_recorded_at": 201, "outcome": "success"},
            ],
            "slowest_node": {"code": "free_email_otp_wait", "label": "等待 Free 邮箱验证码", "duration_ms": 88},
        }
        store.save({
            "timing-race": {
                "task_id": "timing-race",
                "status": "running",
                "result": {"marker": "newer-task-state"},
                "timing": newer_timing,
            },
        })

        # This is the snapshot captured before the newer stage/substep save;
        # it arrives late after the runtime manager has released its lock.
        stale_timing = {
            "started_at": 100,
            "elapsed_ms": 42,
            "elapsed_seconds": 0.042,
            "finished_at": None,
            "stages": [
                {"code": "free_camoufox_profile", "attempt": 1, "started_at": 100, "finished_at": 110, "duration_ms": 10},
            ],
            "substeps": [
                {"key": "free_camoufox_profile:profile_name_fill", "stage_code": "free_camoufox_profile", "code": "profile_name_fill", "duration_ms": 10, "first_duration_ms": 10, "last_duration_ms": 10, "max_duration_ms": 10, "visits": 1, "last_recorded_at": 150, "outcome": "success"},
            ],
            "slowest_node": {"code": "free_camoufox_profile", "label": "填写 Camoufox 账号资料", "duration_ms": 10},
        }
        self.assertTrue(store.save_timing("timing-race", stale_timing))
        payload = json.loads(store.path.read_text(encoding="utf-8"))
        task = payload["tasks"]["timing-race"]
        timing = task["timing"]
        self.assertEqual(task["status"], "running")
        self.assertEqual(task["result"], {"marker": "newer-task-state"})
        self.assertEqual(timing["elapsed_ms"], 99)
        self.assertEqual({row["code"] for row in timing["stages"]}, {"free_camoufox_profile", "free_email_otp_wait"})
        substeps = {row["key"]: row for row in timing["substeps"]}
        self.assertEqual(substeps["free_camoufox_profile:profile_name_fill"]["visits"], 2)
        self.assertEqual(substeps["free_camoufox_profile:profile_name_fill"]["duration_ms"], 30)
        self.assertEqual(substeps["free_camoufox_profile:profile_name_fill"]["last_duration_ms"], 20)
        self.assertEqual(substeps["free_camoufox_profile:profile_name_fill"]["last_recorded_at"], 200)
        self.assertIn("free_email_otp_wait:mailbox_poll_scan", substeps)
        self.assertEqual(timing["slowest_node"]["code"], "free_email_otp_wait")

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
        self.assertEqual(rows[0]["email"], "f***t@example.test")
        self.assertEqual(rows[0]["email_masked"], rows[0]["email"])
        self.assertNotIn("first@example.test", str(rows))
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
            "f***t@example.test",
            "s***d@example.test",
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

    def test_free_logs_preserve_safe_substep_metadata(self):
        logs = FreeLogStore(self.data_dir)
        logs.add(
            "[free-task-1/填写 Camoufox 账号资料/free_camoufox_profile] 子步骤完成 duration_ms=42",
            "info",
            task_id="free-task-1",
            node_code="free_camoufox_profile",
            node_label="填写 Camoufox 账号资料",
            substep_code="profile_submit_click",
            substep_label="点击资料提交",
            duration_ms=42,
            outcome="success",
        )
        row = logs.snapshot("free-task-1")[0]
        self.assertEqual(row["substep_code"], "profile_submit_click")
        self.assertEqual(row["substep_label"], "点击资料提交")
        self.assertEqual(row["duration_ms"], 42)
        self.assertNotIn("token", str(row).lower())

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

    def test_free_pool_import_prepends_new_and_deduplicates_existing_rows(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("first@example.test----https://mail.example.test/a\n")

        added, skipped = pool.import_text_with_stats(
            "first@example.test----https://mail.example.test/a\n"
            "second@example.test----https://mail.example.test/b\n"
            "third@example.test----https://mail.example.test/c\n"
        )

        self.assertEqual((added, skipped), (2, 1))
        self.assertEqual([row.email for row in pool.entries()], [
            "second@example.test",
            "third@example.test",
            "first@example.test",
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
            probe=lambda proxy, _url: "203.0.113.13" if proxy.startswith("socks5://") else "",
        )
        self.assertEqual(len(bindings), 3)
        self.assertEqual({binding.proxy for binding in bindings}, {"socks5://user:pass@proxy-a.test:8000"})

    def test_free_state_and_preflight_publish_runtime_and_otp_revisions(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-a.test:8000\n")
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.20",
        )
        self.assertEqual(manager.public_state()["runtime_version"], "1.6.103")
        self.assertEqual(manager.preflight({"target_count": 1})["otp_parser_revision"], "pickup-dynamic-v7-samples")

    def test_close_camoufox_debug_passes_current_config_to_pool_helper(self):
        config = {
            "camoufox": {
                "debug_mode": False,
                "headless": True,
                "pool_size": 1,
                "max_contexts_per_browser": 1,
            },
        }
        manager = FreeRegisterManager(self.data_dir, config_provider=lambda: config)
        session_id = "cam-debug-abc123456789"
        states = [
            {"sessions": [{"session_id": session_id}]},
            {"sessions": []},
        ]
        with (
            patch(
                "mac_overrides.free_register_runtime.camoufox_debug_state",
                side_effect=states,
            ),
            patch(
                "mac_overrides.free_register_runtime.close_camoufox_debug_browsers",
                return_value={"closed_contexts": 1},
            ) as close,
        ):
            result = manager.close_camoufox_debug(session_id)

        close.assert_called_once()
        close_config = close.call_args.kwargs.get("config")
        self.assertIsInstance(close_config, dict)
        self.assertEqual(
            close_config["camoufox"].get("_debug_artifact_dir"),
            str((self.data_dir / "camoufox_debug").resolve()),
        )
        self.assertEqual(
            {key: value for key, value in close_config.items() if key != "camoufox"},
            {key: value for key, value in config.items() if key != "camoufox"},
        )
        self.assertEqual(
            {key: value for key, value in close_config["camoufox"].items() if key != "_debug_artifact_dir"},
            config["camoufox"],
        )
        self.assertEqual(result["closed_contexts"], 1)
        self.assertEqual(result["state"], {"sessions": []})

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

    def test_protocol_result_normalizes_access_alias_and_drops_optional_tokens(self):
        result = FreeProtocolMixin._sanitize_protocol_result({
            "accessToken": "access-token-private",
            "refresh_token": "refresh-token-private",
            "idToken": "id-token-private",
            "token": "access-token-alias",
            "sessionToken": "session-token-private",
            "password_status": "enabled",
        })
        self.assertEqual(result["access_token"], "access-token-private")
        self.assertTrue(result["has_access_token"])
        self.assertEqual(result["password_status"], "enabled")
        for key in (
            "accessToken", "refresh_token", "idToken", "token", "sessionToken",
        ):
            self.assertNotIn(key, result)

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
        self.assertEqual(len(result["rows"]), 2)
        self.assertTrue(all(row["available"] for row in result["rows"]))
        self.assertTrue(all("exit_ip" not in row for row in result["rows"]))
        self.assertEqual(manager.pool.entries(), [])
        self.assertNotIn("https://", str(result))

    def test_proxy_preflight_failures_share_one_redacted_taskless_incident(self):
        diagnostic_store = DiagnosticStore(self.data_dir / "diagnostics")
        manager = FreeRegisterManager(
            self.data_dir,
            diagnostic_store=diagnostic_store,
            proxy_probe=lambda _proxy, _url: (_ for _ in ()).throw(
                TimeoutError("private-user private-password")
            ),
        )

        result = manager.preflight_proxies(
            proxy_content=(
                "socks5://private-user:private-password@proxy-a.test:8000\n"
                "socks5://second-user:second-password@proxy-b.test:8000\n"
            ),
            probe_url="https://chatgpt.com/",
            socks5_dns_mode="remote",
        )

        self.assertEqual(result["proxies"], 0)
        self.assertEqual(result["failure_count"], 2)
        self.assertRegex(result["incident_id"], r"^LOG-\d{8}-[A-Z0-9]{8}$")
        self.assertTrue(all(row["incident_id"] == result["incident_id"] for row in result["rows"]))
        self.assertTrue(all(row.get("failure", {}).get("node_code") == "proxy_connect_failed" for row in result["rows"]))
        incidents = diagnostic_store.search({"workflow": "proxy_preflight"})
        self.assertEqual(len(incidents), 1)
        detail = diagnostic_store.incident(result["incident_id"])
        self.assertIsNotNone(detail)
        serialized = json.dumps({"result": result, "detail": detail}, ensure_ascii=False)
        for secret in ("private-user", "private-password", "second-user", "second-password"):
            self.assertNotIn(secret, serialized)
        event = detail["events"][0]
        self.assertEqual(event["task_id"], "")
        self.assertEqual(event["transport"]["failure_count"], 2)
        self.assertEqual(event["transport"]["target_domain"], "chatgpt.com")
        self.assertIn("proxy_connect_failed", event["transport"]["nodes"])
        self.assertEqual(event["transport"]["declared_schemes"], "socks5")
        self.assertEqual(event["transport"]["effective_schemes"], "socks5h")

    def test_saved_proxy_preflight_releases_quarantine_after_successful_recheck(self):
        manager = FreeRegisterManager(
            self.data_dir,
            proxy_probe=lambda _proxy, _url: "203.0.113.19",
        )
        manager.proxies.import_text("proxy-a.test:8000\n")
        proxy_id = manager.proxies.entries()[0]["proxy_id"]
        manager.proxies.record_failure(
            proxy_id,
            node_code="proxy_connect_failed",
            message="代理探测请求返回 HTTP 403",
            threshold=1,
        )

        result = manager.preflight_proxies(proxy_content="", probe_url="https://probe.example.test/")

        self.assertEqual(result["proxies"], 1)
        self.assertEqual(manager.proxies.public()["rows"][0]["status"], "available")
        self.assertEqual(manager.proxies.public()["rows"][0]["consecutive_failures"], 0)

    def test_saved_proxy_preflight_health_success_write_failure_keeps_probe_available(self):
        manager = FreeRegisterManager(
            self.data_dir,
            proxy_probe=lambda _proxy, _url: "203.0.113.20",
        )
        manager.proxies.import_text("proxy-a.test:8000\n")

        with patch.object(
            manager.proxies,
            "record_success",
            side_effect=OSError("proxy health store unavailable"),
        ) as record_success:
            result = manager.preflight_proxies(
                proxy_content="",
                probe_url="https://chatgpt.com/",
            )

        record_success.assert_called_once()
        self.assertEqual(result["proxies"], 1)
        self.assertEqual(result["health_write_failures"], 1)
        self.assertTrue(result["rows"][0]["available"])
        self.assertNotIn("failure_count", result)

    def test_saved_proxy_preflight_health_write_failure_does_not_abort_batch(self):
        diagnostic_store = DiagnosticStore(self.data_dir / "diagnostics")
        manager = FreeRegisterManager(
            self.data_dir,
            diagnostic_store=diagnostic_store,
            proxy_probe=lambda _proxy, _url: (_ for _ in ()).throw(
                TimeoutError("probe timeout")
            ),
        )
        manager.proxies.import_text(
            "proxy-a.test:8000\nproxy-b.test:8000\n"
        )

        with patch.object(
            manager.proxies,
            "record_failure",
            side_effect=OSError("proxy health store unavailable"),
        ) as record_failure:
            result = manager.preflight_proxies(
                proxy_content="",
                probe_url="https://chatgpt.com/",
            )

        self.assertEqual(record_failure.call_count, 2)
        self.assertEqual(result["failure_count"], 2)
        self.assertRegex(result["incident_id"], r"^LOG-\d{8}-[A-Z0-9]{8}$")
        detail = diagnostic_store.incident(result["incident_id"])
        self.assertIsNotNone(detail)
        assert detail is not None
        self.assertEqual(detail["event_count"], 1)
        self.assertEqual(detail["events"][0]["transport"]["health_write_failures"], 2)

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

    def test_proxy_binding_uses_socks5_default_after_tls_failure(self):
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

        self.assertEqual(calls, ["socks5://user-a:pass-a@proxy.example.test:8000"])
        self.assertNotIn("pass-a", str(raised.exception))

    def test_proxy_pool_accepts_host_port_username_password_rows(self):
        proxies = FreeProxyPool(self.data_dir)
        imported = proxies.import_text(
            "proxy.example.test:3000:user-a:pass-a\n"
            "proxy.example.test:3001:user-b:pass:b\n"
        )

        self.assertEqual(imported, 1)
        values = proxies.values()
        self.assertEqual(values, ["socks5://user-a:pass-a@proxy.example.test:3000"])

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
                "socks5://u:p@proxy-b.test:3001",
                "socks5://u:p@proxy-c.test:3002",
                "socks5://u:p@proxy-d.test:3003",
            ],
        )

    def test_proxy_transport_maps_socks5_for_protocol_and_probe(self):
        from mac_overrides.free_register_common import proxy_transport_value

        value = "socks5://u:p@proxy.test:3000"
        self.assertEqual(proxy_transport_value(value, driver="protocol"), value)
        self.assertEqual(proxy_transport_value(value, driver="probe"), value)

    def test_proxy_transport_auto_uses_remote_dns_only_for_fake_ip_hosts(self):
        from mac_overrides import free_register_common

        value = "socks5://u:p@proxy.test:3000"
        with patch.object(free_register_common, "_local_dns_returns_fake_ip", return_value=True):
            self.assertEqual(
                free_register_common.proxy_transport_value(value, driver="protocol", socks5_dns_mode="auto"),
                "socks5h://u:p@proxy.test:3000",
            )
        with patch.object(free_register_common, "_local_dns_returns_fake_ip", return_value=False):
            self.assertEqual(
                free_register_common.proxy_transport_value(value, driver="protocol", socks5_dns_mode="auto"),
                value,
            )
        self.assertEqual(
            free_register_common.proxy_transport_value(value, driver="camoufox", socks5_dns_mode="auto"),
            value,
        )

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

    def test_proxy_pool_protocolless_rows_follow_free_socks5_default(self):
        proxies = FreeProxyPool(self.data_dir)
        imported = proxies.import_text(
            "proxy-a.test 3000 user-a pass-a\n"
            "socks4://user-b:pass-b@proxy-b.test:3001\n"
        )

        self.assertEqual(imported, 2)
        self.assertEqual(proxies.values(), [
            "socks5://user-a:pass-a@proxy-a.test:3000",
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
                    raise ProxyError("certificate verify failed")
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
        self.assertEqual([item[1]["verify"] for item in retry_calls if item[0] == "init"], [True])

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
        self.assertEqual(calls, ["https://chatgpt.com/"])

    def test_legacy_ipinfo_probe_url_is_preserved_by_free_config(self):
        store = FreeConfigStore(self.data_dir)
        normalized = store.normalize({"proxy_probe_url": "https://ipinfo.io/json"})
        self.assertEqual(normalized["proxy_probe_url"], "https://ipinfo.io/json")

    def test_legacy_ipinfo_text_default_is_migrated_to_stable_probe(self):
        store = FreeConfigStore(self.data_dir)
        normalized = store.normalize({"proxy_probe_url": "https://ipinfo.io/ip"})
        self.assertEqual(normalized["proxy_probe_url"], "https://chatgpt.com/")

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

    def test_structured_proxy_pool_shares_all_schemes_and_quarantines_failures(self):
        pool = StructuredFreeProxyPool(self.data_dir, failure_threshold=2, quarantine_seconds=600)
        pool.import_text(
            "socks4://user:pass@proxy-region-US.example:3000\n"
            "socks5://user:pass@proxy-region-US.example:3001\n",
            country="US", group="住宅 A",
        )
        self.assertEqual(len(pool.records(driver="protocol")), 2)
        self.assertEqual(len(pool.records(driver="camoufox")), 2)
        proxy_id = pool.records(driver="protocol")[0]["proxy_id"]
        pool.record_failure(proxy_id, node_code="proxy_connect_failed", message="连接失败")
        pool.record_failure(proxy_id, node_code="proxy_connect_failed", message="连接失败")
        self.assertEqual(len(pool.records(driver="protocol")), 1)
        self.assertEqual(len(pool.records(driver="camoufox")), 1)
        self.assertEqual(pool.public()["groups"][0]["quarantined"], 1)

    def test_pasted_proxy_preflight_uses_shared_pool_without_classification_filters(self):
        manager = FreeRegisterManager(
            self.data_dir,
            proxy_probe=lambda proxy, _url: "203.0.113.50" if "proxy-region-US" in proxy else "203.0.113.51",
        )
        shared = manager.preflight_proxies(
            proxy_content="socks4://proxy-region-US.example:3000\nsocks5://proxy-region-US.example:3001\n",
            driver="protocol",
            country="US",
            group="住宅 A",
        )
        self.assertEqual(shared["proxies"], 2)
        self.assertEqual(len(shared["rows"]), 2)
        self.assertTrue(all(row["available"] for row in shared["rows"]))
        result = manager.preflight_proxies(
            proxy_content="socks5://proxy-region-US.example:3001\n",
            driver="camoufox",
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
            FreeRegisterError("free_email_otp_wait", "等待 Free 邮箱验证码", "页面未进入下一步"),
        )
        self.assertEqual(manager.proxies.public()["rows"][0]["consecutive_failures"], 0)

        manager._record_proxy_failure(task, FreeRegisterError("free_proxy_drift", "校验 Free 代理出口", "固定代理出口发生变化"))
        proxy = manager.proxies.public()["rows"][0]
        self.assertEqual(proxy["consecutive_failures"], 0)
        self.assertEqual(proxy["status"], "unknown")

    def test_proxy_failure_and_lease_cleanup_survive_task_store_errors(self):
        diagnostic_store = DiagnosticStore(self.data_dir / "diagnostics")
        manager = FreeRegisterManager(self.data_dir, diagnostic_store=diagnostic_store)
        manager.proxies.import_text("http://proxy-a.test:8000\n")
        proxy = manager.proxies.public()["rows"][0]
        task = {
            "task_id": "free-persistence-cleanup",
            "proxy": "http://proxy-a.test:8000",
            "proxy_id": proxy["proxy_id"],
            "proxy_masked": proxy["masked"],
            "proxy_fingerprint": proxy["proxy_id"],
            "expected_exit_ip": "",
            "cleanup_status": "pending",
        }
        manager._tasks[task["task_id"]] = dict(task)

        with patch.object(manager.task_store, "save", side_effect=OSError("disk full")):
            manager._record_proxy_failure(
                task,
                FreeRegisterError("free_proxy_connect", "代理连接", "连接失败"),
            )
            manager._release_task_lease(task)

        self.assertEqual(manager._tasks[task["task_id"]]["cleanup_status"], "released")
        self.assertEqual(len(manager._tasks[task["task_id"]]["proxy_attempts"]), 1)
        incidents = diagnostic_store.search({"node_code": "free_task_store"})
        self.assertGreaterEqual(len(incidents), 1)

    def test_proxy_health_store_failure_does_not_skip_lease_release(self):
        manager = FreeRegisterManager(self.data_dir)
        manager.proxies.import_text("http://proxy-a.test:8000\n")
        proxy = manager.proxies.public()["rows"][0]
        task = {
            "task_id": "free-health-write-failure",
            "proxy": "http://proxy-a.test:8000",
            "proxy_id": proxy["proxy_id"],
            "proxy_masked": proxy["masked"],
            "proxy_fingerprint": proxy["proxy_id"],
            "expected_exit_ip": "",
        }
        manager._tasks[task["task_id"]] = dict(task)
        with patch.object(manager.proxies, "record_failure", side_effect=OSError("proxy pool unavailable")) as record:
            manager._record_proxy_failure(
                task,
                FreeRegisterError("proxy_connect_timeout", "代理连接", "连接超时", provider_status=503),
            )
            manager._release_task_lease(task)
        record.assert_called_once()
        self.assertEqual(record.call_args.kwargs["http_status"], 503)
        self.assertEqual(manager._tasks[task["task_id"]]["cleanup_status"], "released")

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
        self.assertEqual(proxy["status"], "unknown")
        release_worker.set()
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(manager.public_state()["running"])

    def test_manager_start_preserves_explicit_security_step_choices(self):
        observed: list[tuple[bool, bool]] = []

        def runner(_task, config, _stop, _stage, _log, *, twofa_retry=False):
            observed.append((bool(config.get("auto_set_password")), bool(config.get("auto_set_2fa"))))
            return {"access_token": "token-private", "twofa_status": "enabled", "totp_secret": "JBSWY3DPEHPK3PXP"}

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.77",
        )
        manager.start(
            {"auto_set_2fa": False, "target_count": 1, "concurrency": 1},
            pool_content="a@example.test----https://mail.example.test/a\n",
            proxy_content="http://proxy-a.test:8000\n",
        )
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(observed, [(False, False)])

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
        # Public rows mask mailbox identity; the on-demand secret boundary
        # still returns the raw address for explicit copy actions.
        self.assertEqual(
            manager.secret([], "email", row_ids=[public[0]["row_id"]]),
            "a@example.test",
        )
        detail_logs = [row for row in manager.public_logs() if "当前账号已进入 Token 节点" in row["message"]]
        self.assertEqual({row["task_id"] for row in detail_logs}, {row["task_id"] for row in public})
        self.assertTrue(all(row["stage"] == "free_access_token" for row in detail_logs))

    def test_pre_registration_protocol_failure_restores_mailbox_but_keeps_failed_task(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-a.test:8000\n")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            raise FreeRegisterError(
                "free_protocol_preflight", "Free 全协议预检", "协议连接不可用"
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.20",
        )
        manager.start({"driver": "protocol", "target_count": 1, "proxy_retry_count": 0})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "failed")
        self.assertEqual(task["failure"]["node_code"], "free_protocol_preflight")
        self.assertEqual(mailbox["status"], "available")
        self.assertEqual(mailbox["proxy_masked"], "")
        self.assertEqual(manager.public_state()["pool"]["available"], 1)
        self.assertTrue(any(row["stage"] == "free_mailbox_released" for row in manager.public_logs(task["task_id"])))

    def test_non_network_protocol_failure_never_switches_registration_proxy(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        FreeProxyPool(self.data_dir).import_text(
            "http://proxy-a.test:8000\nhttp://proxy-b.test:8000\n"
        )
        attempts = []

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            attempts.append(task["proxy_id"])
            raise FreeRegisterError(
                "free_protocol_preflight", "Free 全协议预检", "协议运行时不可用",
                error_code="free_protocol_unavailable",
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda proxy, _url: "203.0.113." + ("20" if "proxy-a" in proxy else "21"),
        )
        manager.start({"driver": "protocol", "target_count": 1, "proxy_retry_count": 3})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(len(attempts), 1)
        task = manager.public_tasks()[0]
        self.assertEqual(task["failure"]["error_code"], "free_protocol_unavailable")
        self.assertFalse(any(row.get("outcome") == "switched" for row in task["proxy_attempts"]))

    def test_email_submit_transition_timeout_restores_mailbox(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        FreeProxyPool(self.data_dir).import_text("http://proxy-a.test:8000\n")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            raise FreeRegisterError(
                "free_email_otp_wait", "等待 Free 邮箱验证码", "页面未进入下一步"
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.21",
        )
        manager.start({"driver": "protocol", "target_count": 1})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(manager.public_tasks()[0]["status"], "failed")
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(mailbox["status"], "pending_rerun")
        self.assertFalse(manager.pool._row_state(mailbox["row_id"])["reusable_after_failure"])
        self.assertEqual(manager.public_state()["pool"]["available"], 0)

    def test_task_twofa_is_not_pending_before_registration_result(self):
        worker_entered = threading.Event()
        release_worker = threading.Event()

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            worker_entered.set()
            release_worker.wait(2)
            return {"access_token": "token-private", "twofa_status": "enabled"}

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.23",
        )
        manager.start(
            {"target_count": 1, "concurrency": 1},
            pool_content="a@example.test----https://mail.example.test/a\n",
            proxy_content="http://proxy-a.test:8000\n",
        )
        self.assertTrue(worker_entered.wait(1))
        self.assertEqual(manager.public_tasks()[0]["result"]["twofa_status"], "")
        release_worker.set()
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
        self.assertGreaterEqual(mailbox["cooldown_remaining"], 299)
        self.assertEqual(manager.pool.available(10), [])

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

    def test_public_tasks_expose_mailbox_url_availability_without_url_value(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/pickup\n")
        row = pool.entries()[0]
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks = {
            "free-url-task": {
                "task_id": "free-url-task",
                "status": "failed",
                "email": row.email,
                "row_id": row.row_id,
            },
        }

        public = manager.public_tasks()[0]
        self.assertTrue(public["has_mailbox_url"])
        self.assertNotIn("mailbox_url", public)

    def test_public_task_masks_email_and_exposes_only_subject_fingerprint(self):
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks = {
            "free-public-email": {
                "task_id": "free-public-email",
                "status": "failed",
                "email": "private@example.test",
                "row_id": "missing-row",
            },
        }
        public = manager.public_tasks()[0]
        self.assertEqual(public["email"], "p***e@example.test")
        self.assertEqual(public["email_masked"], public["email"])
        self.assertRegex(public["subject_ref_fingerprint"], r"^[0-9a-f]{16}$")
        self.assertNotIn("private@example.test", str(public))

    def test_public_task_uses_diagnostic_hmac_subject_fingerprint_when_available(self):
        diagnostics = DiagnosticStore(self.data_dir / "diagnostics")
        manager = FreeRegisterManager(self.data_dir, diagnostic_store=diagnostics)
        manager._tasks = {
            "free-public-email-hmac": {
                "task_id": "free-public-email-hmac",
                "status": "failed",
                "email": "private@example.test",
            },
        }
        public = manager.public_tasks()[0]
        self.assertRegex(public["subject_ref_fingerprint"], r"^[0-9a-f]{32}$")
        self.assertEqual(
            public["subject_ref_fingerprint"],
            diagnostics.fingerprint("private@example.test"),
        )

    def test_transfer_skipped_items_mask_email(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("private@example.test----https://mail.example.test/pickup\n")
        row_id = pool.entries()[0].row_id
        prepared = pool.build_transfer_content([row_id])
        self.assertEqual(prepared["skipped"], 1)
        item = prepared["skipped_items"][0]
        self.assertEqual(item["email"], "p***e@example.test")
        self.assertNotIn("private@example.test", str(item))

    def test_public_tasks_normalize_legacy_progress_fields(self):
        """Legacy Free progress snapshots remain consumable by the shared UI."""
        class LegacyProgress:
            def progress(self, task_id):
                self.task_id = task_id
                return {
                    "stage": "free_email_otp_wait",
                    "stage_started_at": 123,
                    "stage_duration_ms": 456,
                    "total_elapsed_ms": 789,
                }

        progress = LegacyProgress()
        manager = FreeRegisterManager(self.data_dir, progress=progress)
        manager._tasks = {
            "free-progress-legacy": {
                "task_id": "free-progress-legacy",
                "status": "running",
                "stage": "free_email_otp_wait",
            },
        }

        public = manager.public_tasks()[0]
        self.assertEqual(progress.task_id, "free-progress-legacy")
        self.assertEqual(public["progress"]["code"], "free_email_otp_wait")
        self.assertEqual(public["progress"]["label"], "等待 Free 邮箱验证码")
        self.assertEqual(public["progress"]["entered_at"], 123)
        self.assertEqual(public["progress"]["stage_duration_ms"], 456)
        self.assertEqual(public["progress"]["total_elapsed_ms"], 789)

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
        self.assertEqual(manager.pool.public_rows()[0]["email"], "*@example.test")

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

    def test_executor_stays_owned_until_final_task_checkpoint(self):
        """An idle signal must not race the callback's last disk write."""
        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda task, *_args, **_kwargs: {
                "access_token": f"token-{task['ordinal']}",
                "twofa_status": "enabled",
            },
            proxy_probe=lambda _proxy, _url: "203.0.113.88",
        )
        manager.pool.import_text(
            "checkpoint@example.test----https://mail.example.test/checkpoint\n"
        )
        manager.proxies.import_text("http://proxy-checkpoint.test:8000\n")

        checkpoint_started = threading.Event()
        release_checkpoint = threading.Event()
        original_save = manager._save_tasks_safely

        def delayed_final_save(context="Free 任务状态"):
            if context == "批次完成回调" and not checkpoint_started.is_set():
                checkpoint_started.set()
                self.assertTrue(release_checkpoint.wait(2))
            return original_save(context)

        manager._save_tasks_safely = delayed_final_save
        manager.start({"target_count": 1})
        self.assertTrue(checkpoint_started.wait(2))
        # The callback is deliberately blocked in its final persistence step.
        # Clearing this reference earlier would let callers remove the data
        # directory while the callback can still create an atomic-write file.
        self.assertIsNotNone(manager._executor)

        release_checkpoint.set()
        deadline = time.time() + 3
        while manager._executor is not None and time.time() < deadline:
            time.sleep(0.005)
        self.assertIsNone(manager._executor)

    def test_registered_worker_cannot_finish_before_future_ownership(self):
        manager = FreeRegisterManager(self.data_dir, runner=lambda *_args, **_kwargs: {})
        manager._batch_id = "free-gate-test"
        manager._last_config = {"driver": "protocol"}
        manager._executor = PriorityExecutor(max_workers=1, thread_name_prefix="free-gate-test")
        observed: list[tuple[int, list[str]]] = []

        def instant_worker() -> None:
            observed.append((len(manager._futures), list(manager._future_drivers.values())))

        with manager._lock:
            future = manager._submit_registered_worker(
                instant_worker,
                driver="protocol",
                priority=0,
            )
        future.result(timeout=2)
        deadline = time.time() + 2
        while manager._executor is not None and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(observed, [(1, ["protocol"])])
        self.assertFalse(manager._futures)
        self.assertIsNone(manager._executor)

    def test_batch_completion_waits_for_heartbeat_teardown(self):
        """``running`` stays true while a background lease writer drains."""
        heartbeat_started = threading.Event()
        release_heartbeat = threading.Event()

        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.77",
        )

        def blocked_heartbeat(_owner, _stop_event=None):
            heartbeat_started.set()
            release_heartbeat.wait(2)

        # Replace only this instance's loop; no real network or browser work
        # is involved in the lifecycle regression.
        manager._heartbeat_loop = blocked_heartbeat
        manager.pool.import_text("heartbeat@example.test----https://mail.example.test/h\n")
        manager.proxies.import_text("http://proxy-heartbeat.test:8000\n")
        manager.start({"target_count": 1})
        self.assertTrue(heartbeat_started.wait(1))

        deadline = time.time() + 1
        while not manager._shutdown_pending and time.time() < deadline:
            time.sleep(0.005)
        self.assertTrue(manager._shutdown_pending)
        self.assertTrue(manager.public_state()["running"])

        release_heartbeat.set()
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.005)
        self.assertFalse(manager.public_state()["running"])
        self.assertIsNone(manager._executor)
        self.assertFalse(manager._heartbeat_thread is not None and manager._heartbeat_thread.is_alive())

    def test_startup_executor_failure_rolls_back_all_reserved_resources(self):
        """A failed executor construction must not strand startup leases."""
        free_root = self.data_dir / "free_register"
        free_root.mkdir()
        manager = FreeRegisterManager(
            free_root,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.78",
        )

        class FailingExecutor:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("executor construction failed")

        with patch("mac_overrides.free_register_runtime.PriorityExecutor", FailingExecutor):
            with self.assertRaisesRegex(RuntimeError, "executor construction failed"):
                manager.start(
                    {"target_count": 1, "concurrency": 1},
                    pool_content="startup-failure@example.test----https://mail.example.test/startup\n",
                    proxy_content="http://proxy-startup-failure.test:8000\n",
                )

        self.assertEqual(manager._tasks, {})
        self.assertEqual(manager.task_store.load(), {})
        self.assertEqual(manager._batch_id, "")
        self.assertIsNone(manager._executor)
        self.assertFalse(
            manager._heartbeat_thread is not None
            and manager._heartbeat_thread.is_alive()
        )
        mailbox = manager.storage.list_mailboxes(limit=10)[0]
        self.assertEqual(mailbox["status"], "available")
        self.assertFalse(mailbox["lease_owner"])
        self.assertEqual(manager.proxies.public()["rows"][0]["active_lease_count"], 0)
        with manager.storage._connection() as db:  # noqa: SLF001 - lifecycle assertion
            lease_count = db.execute("SELECT COUNT(*) FROM resource_leases").fetchone()[0]
        self.assertEqual(lease_count, 0)

    def test_startup_submit_failure_rolls_back_partial_future_and_leases(self):
        """A later submit failure must also unwind an earlier queued Future."""
        free_root = self.data_dir / "free_register"
        free_root.mkdir()
        manager = FreeRegisterManager(
            free_root,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.79",
        )

        class FailingSubmitExecutor:
            def __init__(self, *args, **kwargs):
                self.calls = 0
                self.future = None

            def submit(self, *args, **kwargs):
                self.calls += 1
                if self.calls > 1:
                    raise RuntimeError("worker submit failed")
                self.future = Future()
                return self.future

            def shutdown(self, *args, **kwargs):
                return None

        with patch("mac_overrides.free_register_runtime.PriorityExecutor", FailingSubmitExecutor):
            with self.assertRaisesRegex(RuntimeError, "worker submit failed"):
                manager.start(
                    {"target_count": 2, "concurrency": 1},
                    pool_content=(
                        "submit-failure-a@example.test----https://mail.example.test/a\n"
                        "submit-failure-b@example.test----https://mail.example.test/b\n"
                    ),
                    proxy_content="http://proxy-submit-a.test:8000\nhttp://proxy-submit-b.test:8000\n",
                )

        self.assertEqual(manager._tasks, {})
        self.assertIsNone(manager._executor)
        self.assertFalse(
            manager._heartbeat_thread is not None
            and manager._heartbeat_thread.is_alive()
        )
        self.assertTrue(all(row["status"] == "available" for row in manager.storage.list_mailboxes(limit=10)))
        self.assertTrue(all(row["active_lease_count"] == 0 for row in manager.proxies.public()["rows"]))

    def test_startup_heartbeat_thread_failure_rolls_back_resources(self):
        """A heartbeat thread start error must not strand the reserved batch."""
        free_root = self.data_dir / "free_register"
        free_root.mkdir()
        manager = FreeRegisterManager(
            free_root,
            runner=lambda *_args, **_kwargs: {},
            proxy_probe=lambda _proxy, _url: "203.0.113.80",
        )

        with patch.object(threading.Thread, "start", side_effect=RuntimeError("heartbeat start failed")):
            with self.assertRaisesRegex(RuntimeError, "heartbeat start failed"):
                manager.start(
                    {"target_count": 1, "concurrency": 1},
                    pool_content="heartbeat-failure@example.test----https://mail.example.test/hb\n",
                    proxy_content="http://proxy-heartbeat-failure.test:8000\n",
                )

        self.assertEqual(manager._tasks, {})
        self.assertIsNone(manager._executor)
        self.assertIsNone(manager._heartbeat_thread)
        self.assertEqual(manager.storage.list_mailboxes(limit=10)[0]["status"], "available")
        self.assertEqual(manager.proxies.public()["rows"][0]["active_lease_count"], 0)

    def test_worker_persists_running_state_before_invoking_transport(self):
        FreeMailboxPool(self.data_dir).import_text(
            "running@example.test----https://mail.example.test/running\n"
        )
        FreeProxyPool(self.data_dir).import_text("http://proxy-running.test:8000\n")
        persisted_statuses = []
        manager = None

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            assert manager is not None
            persisted_statuses.append(
                manager.task_store.load()[str(task["task_id"])]["status"]
            )
            return {"access_token": "token", "twofa_status": "enabled"}

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.50",
        )
        manager.start({"target_count": 1})
        deadline = time.time() + 3
        while manager._executor is not None and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(persisted_statuses, ["running"])
        self.assertIsNone(manager._executor)

    def test_safe_task_store_failure_creates_taskless_diagnostic(self):
        diagnostic_store = DiagnosticStore(self.data_dir / "diagnostics")
        manager = FreeRegisterManager(self.data_dir, diagnostic_store=diagnostic_store)
        with patch.object(manager.task_store, "save", side_effect=OSError("private path")):
            self.assertFalse(manager._save_tasks_safely("任务进入运行状态"))

        incidents = diagnostic_store.search({"node_code": "free_task_store"})
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["first_error_code"], "free_task_store_write_failed")
        self.assertEqual(incidents[0]["task_id"], "")

    def test_task_store_save_order_cannot_overwrite_newer_snapshot(self):
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks["ordered-save"] = {
            "task_id": "ordered-save",
            "status": "old",
        }
        first_save_entered = threading.Event()
        release_first_save = threading.Event()
        second_save_started = threading.Event()
        snapshots = []

        def save(snapshot):
            snapshots.append(copy.deepcopy(snapshot))
            if len(snapshots) == 1:
                first_save_entered.set()
                self.assertTrue(release_first_save.wait(2))
            else:
                second_save_started.set()

        with patch.object(manager.task_store, "save", side_effect=save):
            first = threading.Thread(
                target=manager._save_tasks_safely,
                args=("顺序保存旧状态",),
            )
            first.start()
            self.assertTrue(first_save_entered.wait(1))

            def update_and_save_new_state():
                with manager._lock:
                    manager._tasks["ordered-save"]["status"] = "new"
                manager._save_tasks_safely("顺序保存新状态")

            second = threading.Thread(target=update_and_save_new_state)
            second.start()
            # The second writer cannot capture a snapshot while the first
            # save owns the manager lock.
            self.assertFalse(second_save_started.wait(0.05))
            release_first_save.set()
            first.join(2)
            second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual([item["ordered-save"]["status"] for item in snapshots], ["old", "new"])

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

    def test_registration_retry_preserves_remail_source_and_service_token(self):
        free_root = self.data_dir / "free_register"
        free_root.mkdir()
        captured = []
        worker_finished = threading.Event()

        def runner(task, _config, _stop, _stage, _log, **_kwargs):
            captured.append(dict(task))
            worker_finished.set()
            return {"access_token": "token-private", "twofa_status": "disabled"}

        manager = FreeRegisterManager(
            free_root,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.30",
        )
        row = manager.pool.import_remail_order({
            "orderNo": "order-1",
            "deliveryEmail": "remail@example.test",
            "serviceToken": "service-token",
        })
        manager.proxies.import_text("http://proxy-remail.test:8000\n")
        manager._tasks["failed-remail"] = {
            "task_id": "failed-remail",
            "status": "failed",
            "row_id": row["row_id"],
            "driver": "camoufox",
            "failure": {"node_code": "free_camoufox_browser"},
        }

        manager.rerun("failed-remail", {"driver": "camoufox", "concurrency": 1})
        self.assertTrue(worker_finished.wait(2))
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["mailbox_source"], "remail")
        self.assertEqual(captured[0]["service_token"], "service-token")
        self.assertEqual(captured[0]["mailbox_url"], "https://remail.aishop6.com/v1/pickup")

    def test_registration_retry_keeps_regular_mailbox_url_as_url_source(self):
        free_root = self.data_dir / "free_register"
        free_root.mkdir()
        captured = []
        worker_finished = threading.Event()

        def runner(task, _config, _stop, _stage, _log, **_kwargs):
            captured.append(dict(task))
            worker_finished.set()
            return {"access_token": "token-private", "twofa_status": "disabled"}

        manager = FreeRegisterManager(
            free_root,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.31",
        )
        mailbox_url = "https://mail.example.test/pickup?email=url%40example.test&token=url-token"
        manager.pool.import_text(f"url@example.test----{mailbox_url}\n")
        manager.proxies.import_text("http://proxy-url.test:8000\n")
        row = manager.pool.entries()[0]
        manager._tasks["failed-url"] = {
            "task_id": "failed-url",
            "status": "failed",
            "row_id": row.row_id,
            "driver": "camoufox",
            "failure": {"node_code": "free_camoufox_browser"},
        }

        manager.rerun("failed-url", {"driver": "camoufox", "concurrency": 1})
        self.assertTrue(worker_finished.wait(2))
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["mailbox_source"], "url")
        self.assertEqual(captured[0]["service_token"], "")
        self.assertEqual(captured[0]["mailbox_url"], mailbox_url)

    def _seed_password_retry_task(self, manager, *, task_id="password-task"):
        """Create a durable account snapshot for continuation-only tests."""
        manager.pool.import_text(
            "password@example.test----https://mail.example.test/password\n"
        )
        manager.proxies.import_text("http://proxy-password.test:8000\n")
        row = manager.pool.entries()[0]
        proxy = manager.proxies.public()["rows"][0]
        result = {
            "access_token": "token-private",
            "password_status": "pending",
            "twofa_status": "enabled",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "plan_type": "free",
        }
        manager.pool.save_result(row.row_id, result)
        manager.pool.update(
            row.row_id,
            status="partial_success",
            stage="free_password_enroll",
            driver="protocol",
            proxy="http://proxy-password.test:8000",
            proxy_id=proxy["proxy_id"],
            proxy_masked=proxy["masked"],
            proxy_fingerprint=proxy["proxy_id"],
            expected_exit_ip="203.0.113.88",
            exit_ip="203.0.113.88",
        )
        manager._tasks = {
            task_id: {
                "task_id": task_id,
                "ordinal": 1,
                "status": "partial_success",
                "created_at": int(time.time()),
                "updated_at": int(time.time()),
                "batch_id": "password-batch",
                "driver": "protocol",
                "email": row.email,
                "row_id": row.row_id,
                "mailbox_url": row.mailbox_url,
                "proxy": "http://proxy-password.test:8000",
                "proxy_id": proxy["proxy_id"],
                "proxy_masked": proxy["masked"],
                "proxy_fingerprint": proxy["proxy_id"],
                "expected_exit_ip": "203.0.113.88",
                "exit_ip": "203.0.113.88",
                "proxy_attempts": [],
                "cleanup_status": "released",
                "result": result,
            },
        }
        return row, result

    def _wait_for_free_manager(self, manager, timeout=3):
        deadline = time.time() + timeout
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(manager.public_state()["running"])

    def test_password_retry_skips_registration_reservation_and_passes_runner_flag(self):
        runner_flags = []

        def runner(task, _config, _stop, _stage, _log, *, password_retry=False):
            runner_flags.append(password_retry)
            self.assertTrue(password_retry)
            self.assertEqual(task["result"]["access_token"], "token-private")
            return {
                "access_token": "token-private",
                "password_status": "enabled",
                "password": FIXED_PASSWORD,
                "password_set_after_registration": True,
            }

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.88",
        )
        row, _result = self._seed_password_retry_task(manager)
        with (
            patch.object(manager.pool, "reserve", side_effect=AssertionError("password retry must not reserve")) as reserve,
            patch.object(manager, "_registration_account_exists", side_effect=AssertionError("password retry must not replay signup")) as account_exists,
        ):
            queued = manager.retry_password("password-task", {})
            self._wait_for_free_manager(manager)

        reserve.assert_not_called()
        account_exists.assert_not_called()
        self.assertEqual(runner_flags, [True])
        retry_id = queued["task_id"]
        with manager._lock:
            retry_task = dict(manager._tasks[retry_id])
        self.assertEqual(retry_task["status"], "success")
        self.assertEqual(retry_task["result"]["password_status"], "enabled")
        self.assertEqual(manager.pool.result(row.row_id)["access_token"], "token-private")
        with manager._lock:
            parent_task = dict(manager._tasks["password-task"])
        parent_public = manager._public_task(parent_task)
        self.assertEqual(parent_public["result"]["password_status"], "enabled")
        self.assertTrue(parent_public["result"]["has_password"])

    def test_password_retry_accepts_disabled_passwordless_signup(self):
        runner_flags = []

        def runner(task, _config, _stop, _stage, _log, *, password_retry=False):
            runner_flags.append(password_retry)
            self.assertTrue(password_retry)
            self.assertEqual(task["result"]["account_flow"], "signup")
            return {
                "access_token": "token-private",
                "account_flow": "signup",
                "password_status": "enabled",
                "password_set_after_registration": True,
                "password": FIXED_PASSWORD,
            }

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.88",
        )
        row, result = self._seed_password_retry_task(manager)
        result.update({
            "account_flow": "signup",
            "password_status": "disabled",
            "password_set_after_registration": False,
            "registration_password_used": False,
        })
        result.pop("password", None)
        result.pop("credential_line", None)
        manager.pool.save_result(row.row_id, result)
        manager.pool.update(row.row_id, status="success", stage="free_result_save")
        manager._tasks["password-task"]["status"] = "success"
        manager._tasks["password-task"]["result"] = dict(result)

        queued = manager.retry_password("password-task", {})
        self._wait_for_free_manager(manager)

        with manager._lock:
            retry_task = dict(manager._tasks[queued["task_id"]])
        self.assertEqual(runner_flags, [True])
        self.assertEqual(retry_task["status"], "success")
        self.assertEqual(retry_task["result"]["password_status"], "enabled")
        self.assertEqual(manager.pool.result(row.row_id)["password"], FIXED_PASSWORD)

    def test_public_task_uses_durable_password_result_after_retry(self):
        manager = FreeRegisterManager(self.data_dir)
        row, result = self._seed_password_retry_task(manager)
        # Simulate the original task journal surviving while the continuation
        # has already written its successful account result to the mailbox
        # result file.
        stale = dict(result)
        stale.update({
            "account_flow": "signup",
            "password_status": "disabled",
            "password_set_after_registration": False,
            "registration_password_used": False,
        })
        stale.pop("password", None)
        manager._tasks["password-task"]["result"] = stale
        manager.pool.save_result(row.row_id, {
            **stale,
            "password_status": "enabled",
            "password_set_after_registration": True,
            "registration_password_used": True,
            "password": FIXED_PASSWORD,
        })

        public = manager.public_tasks()[0]
        self.assertEqual(public["result"]["password_status"], "enabled")
        self.assertTrue(public["result"]["has_password"])

    def test_password_retry_rejects_existing_login_even_when_pending(self):
        manager = FreeRegisterManager(self.data_dir)
        row, result = self._seed_password_retry_task(manager)
        result.update({"account_flow": "existing_login", "password_status": "pending"})
        manager.pool.save_result(row.row_id, result)
        manager._tasks["password-task"]["result"] = dict(result)

        with self.assertRaises(FreeRegisterError) as raised:
            manager.retry_password("password-task", {})
        self.assertEqual(raised.exception.error_code, "free_password_retry_not_pending")

    def test_password_retry_recovers_missing_historical_proxy_id(self):
        def runner(task, _config, _stop, _stage, _log, *, password_retry=False):
            self.assertTrue(password_retry)
            self.assertTrue(task["proxy_id"])
            return {
                "access_token": "token-private",
                "password_status": "enabled",
                "password": FIXED_PASSWORD,
                "password_set_after_registration": True,
            }

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.88",
        )
        row, _result = self._seed_password_retry_task(manager)
        proxy_id = manager.proxies.public()["rows"][0]["proxy_id"]
        # Legacy snapshots may retain only the configured address. Clear both
        # copies to exercise lookup and authoritative ID recovery.
        manager._tasks["password-task"].pop("proxy_id", None)
        manager.pool.update(row.row_id, proxy_id="")

        queued = manager.retry_password("password-task", {})
        self._wait_for_free_manager(manager)

        with manager._lock:
            retry_task = dict(manager._tasks[queued["task_id"]])
        self.assertEqual(retry_task["proxy_id"], proxy_id)
        self.assertEqual(manager.proxies.public()["rows"][0]["active_lease_count"], 0)

    def test_failed_password_retry_keeps_token_and_partial_success(self):
        def runner(_task, _config, _stop, _stage, _log, *, password_retry=False):
            self.assertTrue(password_retry)
            raise FreeRegisterError(
                "free_password_add",
                "提交 Free 账号密码",
                "密码提交超时",
                retryable=True,
                error_code="free_password_add_timeout",
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.88",
        )
        row, _result = self._seed_password_retry_task(manager)
        queued = manager.retry_password("password-task", {})
        self._wait_for_free_manager(manager)

        with manager._lock:
            retry_task = dict(manager._tasks[queued["task_id"]])
        self.assertEqual(retry_task["status"], "partial_success")
        self.assertEqual(retry_task["result"]["access_token"], "token-private")
        self.assertTrue(manager._public_task(retry_task)["result"]["has_access_token"])
        self.assertEqual(retry_task["result"]["password_status"], "pending")
        self.assertEqual(manager.pool.result(row.row_id)["access_token"], "token-private")
        self.assertEqual(manager.secret([queued["task_id"]], "token"), "token-private")

    def test_untyped_password_retry_failure_keeps_token_and_plan_context(self):
        def runner(_task, _config, _stop, _stage, _log, *, password_retry=False):
            self.assertTrue(password_retry)
            raise RuntimeError("adapter crashed")

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.88",
        )
        row, _result = self._seed_password_retry_task(manager)
        queued = manager.retry_password("password-task", {})
        self._wait_for_free_manager(manager)

        with manager._lock:
            retry_task = dict(manager._tasks[queued["task_id"]])
        self.assertEqual(retry_task["status"], "partial_success")
        self.assertEqual(retry_task["result"]["access_token"], "token-private")
        self.assertEqual(retry_task["result"]["plan_type"], "free")
        self.assertEqual(retry_task["result"]["password_status"], "pending")
        self.assertEqual(retry_task["failure"]["node_code"], "free_password_enroll")
        saved = manager.pool.result(row.row_id)
        self.assertEqual(saved["access_token"], "token-private")
        self.assertEqual(saved["plan_type"], "free")

    def test_batch_retry_routes_pending_password_to_password_continuation(self):
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks = {
            "password-batch-task": {
                "task_id": "password-batch-task",
                "status": "partial_success",
                "result": {"access_token": "token-private", "password_status": "pending"},
            },
        }
        with (
            patch.object(manager, "retry_password", return_value={"task_id": "password-retry-task"}) as retry_password,
            patch.object(manager, "retry_twofa") as retry_twofa,
            patch.object(manager, "rerun") as rerun,
        ):
            result = manager.batch_retry(["password-batch-task"], {})

        retry_password.assert_called_once_with("password-batch-task", {})
        retry_twofa.assert_not_called()
        rerun.assert_not_called()
        self.assertEqual(result["accepted_count"], 1)
        self.assertEqual(result["accepted"][0]["retry_task"]["task_id"], "password-retry-task")

    def test_removed_driver_start_is_rejected_without_runner_or_pool_mutation(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\n")
        calls = []

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            calls.append(twofa_retry)
            return {"access_token": "token-private", "twofa_status": "enabled"}

        manager = FreeRegisterManager(self.data_dir, runner=runner, proxy_probe=lambda _proxy, _url: "203.0.113.20")
        with self.assertRaises(FreeRegisterError) as raised:
            manager.start({"target_count": 1, "driver": "roxybrowser"})
        self.assertEqual(raised.exception.node_code, "free_config")
        self.assertEqual(calls, [])
        self.assertEqual(manager.public_tasks(), [])
        self.assertEqual(manager.pool.public_rows()[0]["status"], "available")
        self.assertEqual(manager.proxies.public()["rows"][0]["active_lease_count"], 0)

    def test_camoufox_twofa_retry_stays_on_camoufox_chain(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("http://proxy-a.test:8000\n")

        def runner(task, _config, _stop, _stage, _log, *, twofa_retry=False):
            if not twofa_retry:
                return {"access_token": "token-private", "twofa_status": "pending"}
            self.assertEqual(task["driver"], "camoufox")
            return {"access_token": "token-private", "twofa_status": "enabled"}

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.21",
        )
        manager.start({"target_count": 1, "driver": "camoufox"})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        pending = manager.public_tasks()[0]
        manager.retry_twofa(pending["task_id"], {"driver": "camoufox"})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(manager.public_tasks()[0]["driver"], "camoufox")

    def test_twofa_retry_applies_remote_socks5_dns_policy_before_binding(self):
        pool = FreeMailboxPool(self.data_dir)
        pool.import_text("a@example.test----https://mail.example.test/a\n")
        row_id = pool.entries()[0].row_id
        pool.update(row_id, status="twofa_pending")
        pool.save_result(row_id, {"access_token": "token-private", "twofa_status": "pending"})
        proxies = FreeProxyPool(self.data_dir)
        proxies.import_text("socks5://user:pass@proxy-a.test:8000\n")
        probed = []

        def probe(proxy, _url):
            probed.append(proxy)
            return "203.0.113.22"

        manager = FreeRegisterManager(
            self.data_dir,
            runner=lambda _task, _config, _stop, _stage, _log, **_kwargs: {
                "access_token": "token-private", "twofa_status": "enabled",
            },
            proxy_probe=probe,
        )
        manager._tasks = {
            "camoufox-pending": {
                "task_id": "camoufox-pending",
                "row_id": row_id,
                "email": "a@example.test",
                "driver": "camoufox",
                "status": "twofa_pending",
                "result": {"access_token": "token-private", "twofa_status": "pending"},
            },
        }
        config = {
            "driver": "camoufox",
            "proxy_socks5_dns_mode": "remote",
            "proxy_health_probe_ttl_seconds": 300,
            "proxy_tls_verify": True,
            "proxy_tls_compat_fallback": True,
        }
        manager.retry_twofa("camoufox-pending", config)
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        self.assertTrue(probed)
        # Camoufox accepts the declared SOCKS5 endpoint through its browser
        # transport adapter; the protocol-only socks5h DNS mapping must not
        # leak into this isolated retry path.
        self.assertTrue(probed[0].startswith("socks5://"))

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

    def test_summary_counts_boolean_proxy_switch_markers(self):
        manager = FreeRegisterManager(self.data_dir)
        manager._tasks = {
            "task-1": {
                "task_id": "task-1",
                "status": "failed",
                "created_at": 1,
                "proxy_attempts": [
                    {"stage": "free_camoufox_navigation", "retryable": True, "switched": True},
                    {"stage": "free_camoufox_navigation", "retryable": True, "switched": False},
                ],
                "timing": {"stages": []},
            },
        }
        summary = manager.public_state()["summary"]
        self.assertEqual(summary["total_retries"], 2)
        self.assertEqual(summary["proxy_switches"], 1)


if __name__ == "__main__":
    unittest.main()
