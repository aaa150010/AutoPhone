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
            "sub2-secret",
            "nv-secret",
            "smtp-secret",
            "mailbox-secret",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(masked["sms_api_keys"], ["********"])

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

    def test_public_task_exposes_only_mailbox_url_capability(self):
        source_row = "url@example.test|https://mail.example.test/inbox/private-token"

        public = self.runtime.public_task({
            "task_id": "T001",
            "status": "running",
            "source_row": source_row,
        })

        self.assertTrue(public["has_mailbox_url"])
        self.assertNotIn("source_row", public)
        self.assertNotIn("private-token", json.dumps(public))

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


if __name__ == "__main__":
    unittest.main()
