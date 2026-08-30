from __future__ import annotations

import copy
import json
import re
from types import SimpleNamespace
import unittest

from mac_overrides import error_observability
from mac_overrides import mailbox_admin
from mac_overrides import sms_runtime
from mac_overrides import task_progress
from mac_overrides.public_state_runtime import PublicStateRuntime


class _ProviderRegistry:
    def safe_error(self, value):
        return str(value or "")

    def public_statuses(self):
        return [{"provider": "smsbower", "available": True}]

    def is_exhausted(self):
        return False


class _TaskProgress:
    def decorate_runtime(self, runtime):
        runtime["progress_decorated"] = True


class _Admission:
    def __init__(self, limit):
        self.limit = limit

    def snapshot(self):
        return {"limit": self.limit}


class PublicStateRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "local_config": {},
            "context": None,
            "known_failures": {},
            "admission": _Admission(8),
            "connectivity": {
                "status": "outage",
                "enabled": True,
                "paused": True,
                "pause_reason": "openai_auth_connectivity_outage",
                "reason_code": "openai_tls_connection_failure",
                "affected_origins": ["auth.openai.com"],
                "event_id": "incident123",
                "runtime_epoch": 1_700_000_000_123,
                "revision": 4,
                "proxy_fingerprint": "sha256:0123456789abcdef",
                "failure_counts": {"auth.openai.com": 2},
                "probe_successful_rounds": 0,
                "probe_required_rounds": 2,
                "next_probe_at": 1_700_000_010,
            },
        }
        provider_registry = _ProviderRegistry()
        self.runtime = PublicStateRuntime(
            clean=lambda value: bool(str(value or "").strip()),
            secret_mask="********",
            sms_runtime=sms_runtime,
            sms_provider_pools_from_config=lambda data: sms_runtime.normalize_sms_provider_pools(
                (data or {}).get("sms_provider_pools"),
                legacy_provider=(data or {}).get("sms_provider") or "smsbower",
                legacy_keys=(data or {}).get("sms_api_keys"),
                legacy_key=(data or {}).get("sms_api_key"),
            ),
            sms_keys_from_config=lambda data: sms_runtime.flatten_sms_provider_keys(
                sms_runtime.normalize_sms_provider_pools(
                    (data or {}).get("sms_provider_pools"),
                    legacy_provider=(data or {}).get("sms_provider") or "smsbower",
                    legacy_keys=(data or {}).get("sms_api_keys"),
                    legacy_key=(data or {}).get("sms_api_key"),
                )
            ),
            read_local_config=lambda: copy.deepcopy(self.state["local_config"]),
            mailbox_admin=mailbox_admin,
            error_observability=error_observability,
            task_progress_runtime=task_progress,
            sms_provider_registry_getter=lambda: provider_registry,
            sms_alerts_getter=lambda: SimpleNamespace(snapshot=lambda: []),
            task_progress_getter=lambda: _TaskProgress(),
            current_task_admission_getter=lambda: self.state["admission"],
            openai_connectivity_getter=lambda: SimpleNamespace(
                snapshot=lambda: copy.deepcopy(self.state["connectivity"])
            ),
            protocol_gate_getter=lambda: SimpleNamespace(
                snapshot=lambda _proxy: {"limit": 5}
            ),
            sms_phone_gate_getter=lambda: SimpleNamespace(
                status=lambda: {"limit": 2}
            ),
            sms_optimization_guard_getter=lambda: SimpleNamespace(
                snapshot=lambda: {
                    "disabled": False,
                    "observed_tasks": 60,
                    "late_code_loss_auto_detection_available": False,
                }
            ),
            phone_binding_metrics_getter=lambda: SimpleNamespace(
                snapshot=lambda: {
                    "page_prepare_attempted": 4,
                    "page_prepare_succeeded": 3,
                    "channel_fallback_succeeded": 2,
                    "phone": "+15550001234",
                    "token": "private-token",
                }
            ),
            notification_context_for=lambda: self.state["context"],
            known_task_failure=lambda task_id: self.state["known_failures"].get(task_id),
            historical_success_reasons=frozenset({"sub2_uploaded"}),
            task_id_log_re=re.compile(r"\b(T\d{3}(?:-[A-Za-z0-9]+)?)\b"),
            public_log_input_limit=4096,
        )

    def test_masked_local_config_masks_every_supported_secret(self):
        masked = self.runtime.masked_local_config(
            {
                "sms_api_keys": ["sms-secret"],
                "proxy": "http://user:proxy-secret@example.test:7890",
                "free_proxy_pool_content": "http://free-user:free-secret@example.test:8000",
                "free_register_password": "free-password",
                "account_password": "custom-free-password",
                "sub2api": {"password": "sub2-secret"},
                "nv_import": {"api_key": "nv-secret"},
                "email_notification": {"password": "smtp-secret"},
                "online_mailbox": {"api_token": "mailbox-secret"},
            }
        )

        serialized = json.dumps(masked)
        for secret in (
            "sms-secret",
            "proxy-secret",
            "free-secret",
            "free-password",
            "custom-free-password",
            "sub2-secret",
            "nv-secret",
            "smtp-secret",
            "mailbox-secret",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(masked["sms_api_keys"], ["********"])
        self.assertEqual(masked["free_proxy_pool_content"], "********")
        self.assertEqual(masked["free_register_password"], "********")
        self.assertEqual(masked["account_password"], "********")

    def test_runtime_summary_only_counts_the_current_batch(self):
        self.state["context"] = {
            "run_id": "run-current",
            "batch_id": "batch-current",
            "target": 2,
            "started_at": 100,
        }

        summary = self.runtime.runtime_summary(
            [
                {
                    "batch_id": "batch-old",
                    "status": "success",
                    "result": {"sms_cost_cny": 9},
                },
                {
                    "batch_id": "batch-current",
                    "status": "running",
                    "updated_at": 120,
                },
            ]
        )

        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["active"], 1)
        self.assertEqual(summary["success"], 0)
        self.assertEqual(summary["sms_cost_cny"], 0)

    def test_masked_state_uses_mailbox_admin_pool_counts(self):
        mailbox_admin = SimpleNamespace(
            list_mailboxes=lambda: {
                "counts": {
                    "total": 9,
                    "available": 4,
                    "running": 2,
                    "success": 2,
                    "failed": 1,
                    "draft": 3,
                }
            }
        )
        runtime = PublicStateRuntime(
            clean=self.runtime.clean,
            secret_mask=self.runtime.secret_mask,
            sms_runtime=self.runtime.sms_runtime,
            sms_provider_pools_from_config=self.runtime.sms_provider_pools_from_config,
            sms_keys_from_config=self.runtime.sms_keys_from_config,
            read_local_config=self.runtime.read_local_config,
            mailbox_admin=mailbox_admin,
            error_observability=self.runtime.error_observability,
            task_progress_runtime=self.runtime.task_progress_runtime,
            sms_provider_registry_getter=self.runtime.sms_provider_registry_getter,
            sms_alerts_getter=self.runtime.sms_alerts_getter,
            task_progress_getter=self.runtime.task_progress_getter,
            current_task_admission_getter=self.runtime.current_task_admission_getter,
            protocol_gate_getter=self.runtime.protocol_gate_getter,
            sms_phone_gate_getter=self.runtime.sms_phone_gate_getter,
            notification_context_for=self.runtime.notification_context_for,
            known_task_failure=self.runtime.known_task_failure,
            historical_success_reasons=self.runtime.historical_success_reasons,
            task_id_log_re=self.runtime.task_id_log_re,
            public_log_input_limit=self.runtime.public_log_input_limit,
        )

        masked = runtime.masked_state({
            "runtime": {
                "pool": {"provider": "legacy", "available": 99, "note": "keep"},
                "tasks": [],
            }
        })

        self.assertEqual(masked["runtime"]["pool"], {
            "provider": "legacy",
            "available": 4,
            "note": "keep",
            "total": 9,
            "running": 2,
            "success": 2,
            "failed": 1,
            "draft": 3,
        })

    def test_mailbox_pool_summary_getter_uses_live_service(self):
        self.runtime.mailbox_pool_summary_getter = lambda: SimpleNamespace(
            list_mailboxes=lambda: {"counts": {"total": 2, "available": 1}}
        )

        masked = self.runtime.masked_state({
            "runtime": {"pool": {"available": 99}, "tasks": []},
        })

        self.assertEqual(masked["runtime"]["pool"]["available"], 1)
        self.assertEqual(masked["runtime"]["pool"]["total"], 2)

    def test_public_task_exposes_only_mailbox_capabilities(self):
        cases = (
            (
                "url@example.test|https://mail.example.test/inbox/private-token",
                {"has_mailbox_url": True, "has_mailbox_password": False, "has_totp": False},
                "private-token",
            ),
            (
                "password@example.test----login-password",
                {"has_mailbox_url": False, "has_mailbox_password": True, "has_totp": False},
                "login-password",
            ),
            (
                "totp@example.test|login-password|JBSWY3DPEHPK3PXP",
                {"has_mailbox_url": False, "has_mailbox_password": True, "has_totp": True},
                "JBSWY3DPEHPK3PXP",
            ),
        )

        for index, (source_row, expected, secret) in enumerate(cases, start=1):
            with self.subTest(source_row=source_row):
                public = self.runtime.public_task({
                    "task_id": f"T{index:03d}",
                    "status": "running",
                    "source_row": source_row,
                })
                for capability, enabled in expected.items():
                    self.assertEqual(public[capability], enabled)
                self.assertNotIn("source_row", public)
                self.assertNotIn(secret, json.dumps(public))

    def test_masked_state_reads_the_current_admission_object(self):
        state = {
            "runtime": {
                "concurrency": {},
                "tasks": [{"task_id": "T001", "status": "queued"}],
            }
        }

        first = self.runtime.masked_state(state)
        self.state["admission"] = _Admission(9)
        second = self.runtime.masked_state(state)

        self.assertEqual(first["runtime"]["concurrency"]["task"]["limit"], 8)
        self.assertEqual(second["runtime"]["concurrency"]["task"]["limit"], 9)
        self.assertEqual(second["runtime"]["concurrency"]["task"]["waiting"], 1)
        self.assertTrue(second["runtime"]["progress_decorated"])
        self.assertEqual(state["runtime"]["tasks"][0]["status"], "queued")

    def test_masked_state_exposes_only_aggregate_sms_optimization_status(self):
        masked = self.runtime.masked_state({"runtime": {"tasks": []}})

        public = masked["sms_quality_optimization"]
        self.assertEqual(public["observed_tasks"], 60)
        self.assertFalse(public["late_code_loss_auto_detection_available"])
        self.assertEqual(masked["runtime"]["sms_quality_optimization"], public)
        self.assertNotIn("task-", str(public).lower())

    def test_masked_state_exposes_only_safe_phone_binding_metrics(self):
        self.state["local_config"] = {"phone_binding_compatibility": True}
        masked = self.runtime.masked_state({"runtime": {"tasks": []}})

        public = masked["runtime"]["phone_binding_compatibility"]
        self.assertTrue(public["enabled"])
        self.assertEqual(public["metrics"]["page_prepare_attempted"], 4)
        self.assertEqual(public["metrics"]["page_prepare_succeeded"], 3)
        self.assertEqual(public["metrics"]["channel_fallback_succeeded"], 2)
        self.assertNotIn("phone", json.dumps(public))
        self.assertNotIn("private-token", json.dumps(public))

    def test_masked_state_exposes_safe_openai_connectivity_progress(self):
        self.state["connectivity"].update({
            "raw_proxy": "http://private-user:private-password@example.test:7890",
            "token": "private-openai-token",
            "probe": {"token": "private-probe-token"},
            "affected_origins": [
                "auth.openai.com",
                "https://private-user:private-password@example.test/private",
            ],
            "failure_counts": {
                "auth.openai.com": 2,
                "private-user:private-password@example.test": 99,
            },
        })
        masked = self.runtime.masked_state({"runtime": {"tasks": []}})

        public = masked["runtime"]["connectivity"]["openai_auth"]
        self.assertEqual(public["status"], "outage")
        self.assertTrue(public["enabled"])
        self.assertTrue(public["paused"])
        self.assertEqual(public["pause_reason"], "openai_auth_connectivity_outage")
        self.assertEqual(public["reason_code"], "openai_tls_connection_failure")
        self.assertEqual(public["reason_label"], "OpenAI TLS \u63e1\u624b\u5931\u8d25")
        self.assertEqual(public["affected_origins"], ["auth.openai.com"])
        self.assertEqual(public["event_id"], "incident123")
        self.assertEqual(public["runtime_epoch"], 1_700_000_000_123)
        self.assertEqual(public["failure_counts"]["auth.openai.com"], 2)
        self.assertEqual(public["probe_required_rounds"], 2)
        self.assertEqual(public["proxy_fingerprint"], "sha256:0123456789abcdef")
        serialized = json.dumps(public)
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("private-password", serialized)
        self.assertNotIn("private-openai-token", serialized)
        self.assertNotIn("private-probe-token", serialized)
        self.assertNotIn("raw_proxy", public)
        self.assertNotIn("token", public)


if __name__ == "__main__":
    unittest.main()
