"""Focused contract tests for the diagnostic-backed Free log store."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.free_log_runtime import FreeLogStore
from mac_overrides.free_register_bands import task_log_workflow


class _DiagnosticFreeLogStoreBase(unittest.TestCase):
    """Assemble a diagnostic-backed Free log store like production does."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="free_log_runtime_tests_")
        free_dir = Path(self._tmp.name) / "free_register"
        free_dir.mkdir(parents=True)
        self.store = FreeLogStore(
            free_dir,
            diagnostic_store=DiagnosticStore(free_dir / "diagnostics"),
            legacy_projection=False,
            strict_diagnostic_reads=True,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _add_sample_logs(self) -> None:
        self.store.add("注册任务日志行", "info", task_id="free-1757000000-ab12cd34-1")
        self.store.add(
            "[free-live-1/快速测活/free_live_fast] 测活日志行", "info",
            chain="free", workflow="live_check", driver="free", task_id="free-live-1",
            stage="free_live_fast", node_code="free_live_fast", node_label="快速测活",
        )
        self.store.add(
            "[free-plan-1/查询 Free 套餐资格/free_plan_check] 套餐日志行", "info",
            chain="free", workflow="plan_check", driver="free", task_id="free-plan-1",
            stage="free_plan_check", node_code="free_plan_check", node_label="查询 Free 套餐资格",
        )

    @staticmethod
    def _contains(rows: list[dict[str, object]], needle: str) -> bool:
        return any(needle in str(row.get("message") or "") for row in rows)


class TaskLogWorkflowTests(unittest.TestCase):
    def test_task_id_namespaces_map_to_their_own_workflow(self):
        self.assertEqual(task_log_workflow("free-1757000000-ab12cd34-1"), "register")
        self.assertEqual(task_log_workflow("free-live-fast-1757000000-ab12cd34"), "live_check")
        self.assertEqual(task_log_workflow("free-plan-1757000000-ab12cd34"), "plan_check")
        self.assertEqual(task_log_workflow(""), "register")

    def test_rebind_ids_stay_outside_the_run_log_workflows(self):
        self.assertEqual(task_log_workflow("rebind-1757000000-ab12cd34"), "register")


class FreeLogStoreVisibilityTests(_DiagnosticFreeLogStoreBase):
    def test_each_run_kind_reads_its_own_workflow_scope(self):
        self._add_sample_logs()
        self.assertTrue(self._contains(
            self.store.snapshot("free-1757000000-ab12cd34-1", workflow="register"),
            "注册任务日志行",
        ))
        self.assertTrue(self._contains(
            self.store.snapshot("free-live-1", workflow=task_log_workflow("free-live-1")),
            "测活日志行",
        ))
        self.assertTrue(self._contains(
            self.store.snapshot("free-plan-1", workflow=task_log_workflow("free-plan-1")),
            "套餐日志行",
        ))

    def test_unscoped_tail_keeps_the_register_workflow_scope(self):
        self._add_sample_logs()
        tail = self.store.snapshot()
        self.assertTrue(self._contains(tail, "注册任务日志行"))
        self.assertFalse(self._contains(tail, "测活日志行"))
        self.assertFalse(self._contains(tail, "套餐日志行"))

    def test_unknown_task_id_returns_no_rows(self):
        self._add_sample_logs()
        self.assertEqual(self.store.snapshot("free-live-missing", workflow="live_check"), [])


if __name__ == "__main__":
    unittest.main()
