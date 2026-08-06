from __future__ import annotations

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
import hashlib

from mac_overrides.importer_scheduler import start_bounded_importer, stop_bounded_importer


class FakePool:
    def __init__(self, available: int) -> None:
        self.available = available
        self.lease_calls = 0
        self.lock = threading.Lock()
        self.restored: list[int] = []

    def summary(self):
        return {"available": self.available}

    def lease(self, *, lease_seconds=3600):
        with self.lock:
            self.lease_calls += 1
            return FakeEntry(self.lease_calls)

    def _entries_unlocked(self):
        return [FakeEntry(index) for index in range(1, self.available + 1)], []

    def restore_entry(self, entry, *, reason=""):
        with self.lock:
            self.restored.append(entry.number)
        return True


class FakeEntry:
    def __init__(self, number: int) -> None:
        self.number = number
        self.email = f"mailbox-{number}@example.test"
        self.source_row = f"{self.email}----password-{number}"
        self.key = f"entry-{number}"


class FakeManualCodes:
    def cancel_all(self):
        return None


class FakePhaseGate:
    def __init__(self, concurrency: int) -> None:
        self.concurrency = concurrency


class FakeImporter:
    def __init__(self, available: int, *, blocked: bool = False) -> None:
        self.pool = FakePool(available)
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.executor = None
        self.futures = []
        self.future_assignments = {}
        self.tasks = {}
        self.active_task_ids = set()
        self.running = False
        self.cancelled_waiting = 0
        self.manual_codes = FakeManualCodes()
        self.auto_email_phase_gate = FakePhaseGate(1)
        self.node_gate = FakePhaseGate(1)
        self.task_concurrency = 1
        self.blocked = blocked
        self.release_tasks = threading.Event()
        if not blocked:
            self.release_tasks.set()
        self.two_started = threading.Event()
        self.one_started = threading.Event()
        self.finished = threading.Event()
        self.ordinals: list[int] = []
        self.entry_numbers: list[int] = []
        self.active = 0
        self.max_active = 0
        self.logs: list[tuple[str, str]] = []

    def settings_validation(self, settings, *, remote=False):
        return {"ok": True, "remote": remote}

    def _pool(self, settings):
        return self.pool

    def _run_one(self, settings, ordinal, entry=None, task_id=""):
        if self.stop_event.is_set():
            self.pool.restore_entry(entry, reason="stopped_before_start")
            return
        with self.lock:
            self.ordinals.append(ordinal)
            self.one_started.set()
            self.entry_numbers.append(entry.number)
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            if len(self.ordinals) >= 2:
                self.two_started.set()
        self.release_tasks.wait(2)
        with self.lock:
            self.active -= 1

    def _task_state(self, task_id, **values):
        self.tasks.setdefault(task_id, {}).update(values)

    @staticmethod
    def _account_label(entry):
        return entry.email

    @staticmethod
    def _source_row(entry):
        return entry.number

    def _watch(self):
        for future in list(self.futures):
            try:
                future.result()
            except Exception:
                pass
        with self.lock:
            executor = self.executor
            self.executor = None
            self.future_assignments = {}
            self.running = False
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        self.finished.set()

    def stop(self):
        stop_bounded_importer(self)

    def _log(self, message, level):
        self.logs.append((message, level))


def start(importer: FakeImporter, settings: dict, **kwargs):
    return start_bounded_importer(
        importer,
        settings,
        mailbox_error_type=ValueError,
        manual_code_factory=FakeManualCodes,
        phase_gate_factory=FakePhaseGate,
        **kwargs,
    )


class ImporterSchedulerTests(unittest.TestCase):
    def test_relogin_uses_consumed_preselected_rows_without_pool_lease(self):
        importer = FakeImporter(available=3)
        rows = [
            {
                "row_id": hashlib.sha256(FakeEntry(index).source_row.encode()).hexdigest(),
                "line_no": index,
                "email": FakeEntry(index).email,
                "sub2api_account_id": str(100 + index),
            }
            for index in range(1, 4)
        ]

        start(importer, {
            "run_mode": "relogin",
            "target_count": 3,
            "concurrency": 2,
            "_gptphone_relogin_rows": rows,
        })
        self.assertTrue(importer.finished.wait(2))

        self.assertEqual(importer.pool.lease_calls, 0)
        self.assertEqual(sorted(importer.entry_numbers), [1, 2, 3])
        self.assertEqual({task["run_mode"] for task in importer.tasks.values()}, {"relogin"})
        self.assertIn("跳过 SMS 预检和号码申请", importer.logs[-1][0])

    def test_stopping_relogin_does_not_restore_consumed_preselected_rows(self):
        importer = FakeImporter(available=3, blocked=True)
        rows = [
            {
                "row_id": hashlib.sha256(FakeEntry(index).source_row.encode()).hexdigest(),
                "line_no": index,
                "email": FakeEntry(index).email,
                "sub2api_account_id": str(100 + index),
            }
            for index in range(1, 4)
        ]
        start(importer, {
            "run_mode": "relogin",
            "target_count": 3,
            "concurrency": 1,
            "_gptphone_relogin_rows": rows,
        })
        self.assertTrue(importer.one_started.wait(1))

        importer.stop()
        importer.release_tasks.set()
        self.assertTrue(importer.finished.wait(2))

        self.assertEqual(importer.pool.lease_calls, 0)
        self.assertEqual(importer.pool.restored, [])
        self.assertEqual(importer.cancelled_waiting, 2)

    def test_relogin_rejects_a_stale_row_hash_before_starting_workers(self):
        importer = FakeImporter(available=1)
        with self.assertRaisesRegex(ValueError, "邮箱列表已变化"):
            start(importer, {
                "run_mode": "relogin",
                "target_count": 1,
                "_gptphone_relogin_rows": [{
                    "row_id": "0" * 64,
                    "line_no": 1,
                    "email": "mailbox-1@example.test",
                    "sub2api_account_id": "101",
                }],
            })
        self.assertFalse(importer.running)
        self.assertEqual(importer.pool.lease_calls, 0)

    def test_batch_identity_is_attached_to_every_reserved_task(self):
        importer = FakeImporter(2)

        start(importer, {
            "target_count": 2,
            "concurrency": 2,
            "batch_id": "20260804-140000-abc123",
            "batch_started_at": 1_785_824_800,
        })
        self.assertTrue(importer.finished.wait(2))

        self.assertEqual(len(importer.tasks), 2)
        self.assertEqual(
            {task["batch_id"] for task in importer.tasks.values()},
            {"20260804-140000-abc123"},
        )
        self.assertEqual(
            {task["batch_started_at"] for task in importer.tasks.values()},
            {1_785_824_800},
        )

    def test_target_count_reserves_unique_pool_entries_and_bounds_active_workers(self):
        importer = FakeImporter(available=20, blocked=True)
        start(importer, {"target_count": 6, "concurrency": 2, "node_concurrency": 5})

        self.assertTrue(importer.two_started.wait(1))
        self.assertEqual(importer.pool.lease_calls, 6)
        self.assertEqual(len(importer.futures), 6)
        self.assertEqual(len(importer.future_assignments), 6)
        self.assertEqual(importer.node_gate.concurrency, 2)

        importer.release_tasks.set()
        self.assertTrue(importer.finished.wait(2))
        self.assertEqual(sorted(importer.ordinals), [1, 2, 3, 4, 5, 6])
        self.assertEqual(importer.pool.lease_calls, 6)
        self.assertEqual(sorted(importer.entry_numbers), [1, 2, 3, 4, 5, 6])
        self.assertEqual(importer.max_active, 2)
        self.assertIn("目标邮箱 6/20", importer.logs[-1][0])

    def test_selected_rows_override_temporary_target_with_unique_binding_count(self):
        importer = FakeImporter(available=20)
        importer.pool.summary = lambda: {"total": 2, "available": 2}
        start(importer, {
            "target_count": 1,
            "concurrency": 5,
            "_gptphone_run_mailbox_rows": [
                {"row_id": "A" * 64, "line_no": 5},
                {"row_id": "a" * 64, "line_no": "5"},
                {"row_id": "B" * 64, "line_no": 8},
            ],
        })

        self.assertTrue(importer.finished.wait(2))
        self.assertEqual(sorted(importer.ordinals), [1, 2])
        self.assertEqual(importer.pool.lease_calls, 2)

    def test_selected_rows_must_all_exist_and_be_available_before_any_lease(self):
        summaries = (
            {"total": 0, "available": 0},
            {"total": 1, "available": 1},
            {"total": 2, "available": 1},
        )
        for summary in summaries:
            with self.subTest(summary=summary):
                importer = FakeImporter(available=2)
                importer.pool.summary = lambda summary=summary: dict(summary)

                with self.assertRaisesRegex(ValueError, "已变化、缺失或不可用"):
                    start(importer, {
                        "target_count": 9,
                        "concurrency": 2,
                        "_gptphone_run_mailbox_rows": [
                            {"row_id": "a" * 64, "line_no": 1},
                            {"row_id": "b" * 64, "line_no": 2},
                        ],
                    })

                self.assertEqual(importer.pool.lease_calls, 0)
                self.assertFalse(importer.running)
                self.assertEqual(importer.tasks, {})

    def test_invalid_selected_row_binding_fails_before_runtime_state_changes(self):
        importer = FakeImporter(available=3)
        importer.pool.summary = lambda: (_ for _ in ()).throw(
            AssertionError("invalid selection must fail before pool summary"),
        )
        with self.assertRaisesRegex(ValueError, "邮箱行绑定参数无效"):
            start(importer, {
                "target_count": 3,
                "_gptphone_run_mailbox_rows": [{"row_id": "", "line_no": 1}],
            })

        self.assertFalse(importer.running)
        self.assertEqual(importer.pool.lease_calls, 0)

    def test_target_is_capped_by_available_mailboxes(self):
        importer = FakeImporter(available=3)
        start(importer, {"target_count": 9, "concurrency": 5})

        self.assertTrue(importer.finished.wait(2))
        self.assertEqual(sorted(importer.ordinals), [1, 2, 3])
        self.assertEqual(len(importer.futures), 3)
        self.assertEqual(importer.pool.lease_calls, 3)

    def test_missing_target_defaults_to_one(self):
        importer = FakeImporter(available=10)
        start(importer, {"concurrency": 5})

        self.assertTrue(importer.finished.wait(2))
        self.assertEqual(importer.ordinals, [1])
        self.assertEqual(importer.pool.lease_calls, 1)
        self.assertEqual(importer.task_concurrency, 1)
        self.assertEqual(importer.node_gate.concurrency, 1)

    def test_stop_prevents_workers_from_claiming_more_tasks(self):
        importer = FakeImporter(available=20, blocked=True)
        start(importer, {"target_count": 10, "concurrency": 2})
        self.assertTrue(importer.two_started.wait(1))

        importer.stop()
        importer.release_tasks.set()

        self.assertTrue(importer.finished.wait(2))
        self.assertEqual(len(importer.ordinals), 2)
        self.assertEqual(importer.pool.lease_calls, 10)
        self.assertEqual(len(importer.pool.restored), 8)
        self.assertEqual(importer.cancelled_waiting, 8)

    def test_startup_failure_restores_idle_state(self):
        importer = FakeImporter(available=2)

        def fail_executor(**_kwargs):
            raise RuntimeError("executor unavailable")

        with self.assertRaisesRegex(RuntimeError, "executor unavailable"):
            start(
                importer,
                {"target_count": 2, "concurrency": 2},
                executor_factory=fail_executor,
            )

        self.assertFalse(importer.running)
        self.assertIsNone(importer.executor)
        self.assertEqual(importer.futures, [])
        self.assertEqual(importer.tasks, {})
        self.assertEqual(sorted(importer.pool.restored), [1, 2])

    def test_startup_cleanup_continues_after_one_restore_failure(self):
        importer = FakeImporter(available=2)
        restore_attempts: list[int] = []
        original_restore = importer.pool.restore_entry

        def flaky_restore(entry, *, reason=""):
            restore_attempts.append(entry.number)
            if entry.number == 1:
                raise RuntimeError("state file unavailable")
            return original_restore(entry, reason=reason)

        importer.pool.restore_entry = flaky_restore

        with self.assertRaisesRegex(RuntimeError, "executor unavailable"):
            start(
                importer,
                {"target_count": 2, "concurrency": 2},
                executor_factory=lambda **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("executor unavailable")
                ),
            )

        self.assertEqual(restore_attempts, [1, 2])
        self.assertEqual(importer.pool.restored, [2])
        self.assertFalse(importer.running)
        self.assertIsNone(importer.executor)
        self.assertEqual(importer.tasks, {})

    def test_partial_submit_failure_waits_for_wrappers_before_restoring(self):
        importer = FakeImporter(available=3)

        class FailSecondSubmitExecutor:
            def __init__(self, **kwargs):
                self.delegate = ThreadPoolExecutor(**kwargs)
                self.submit_calls = 0

            def submit(self, *args, **kwargs):
                self.submit_calls += 1
                if self.submit_calls == 2:
                    raise RuntimeError("submit unavailable")
                return self.delegate.submit(*args, **kwargs)

            def shutdown(self, **kwargs):
                return self.delegate.shutdown(**kwargs)

        with self.assertRaisesRegex(RuntimeError, "submit unavailable"):
            start(
                importer,
                {"target_count": 3, "concurrency": 1},
                executor_factory=FailSecondSubmitExecutor,
            )

        self.assertFalse(importer.running)
        self.assertEqual(importer.ordinals, [])
        self.assertEqual(sorted(importer.pool.restored), [1, 2, 3])

    def test_watcher_start_failure_cleans_executor_and_reservations(self):
        importer = FakeImporter(available=2)

        class FailedWatcher:
            def start(self):
                raise RuntimeError("watcher unavailable")

        with self.assertRaisesRegex(RuntimeError, "watcher unavailable"):
            start(
                importer,
                {"target_count": 2, "concurrency": 2},
                thread_factory=lambda **_kwargs: FailedWatcher(),
            )

        self.assertFalse(importer.running)
        self.assertEqual(importer.ordinals, [])
        self.assertEqual(sorted(importer.pool.restored), [1, 2])

    def test_stop_keeps_assignment_when_cancel_races_watcher_cleanup(self):
        importer = FakeImporter(available=1)
        entry = FakeEntry(1)
        task_id = "T001-race"

        class RacingFuture:
            def cancel(inner_self):
                importer.future_assignments.clear()
                return True

        future = RacingFuture()
        importer.futures = [future]
        importer.future_assignments = {future: (importer.pool, entry, task_id)}
        importer.tasks = {task_id: {"status": "queued"}}

        importer.stop()

        self.assertEqual(importer.pool.restored, [1])
        self.assertEqual(importer.tasks[task_id]["status"], "stopped")
        self.assertEqual(importer.cancelled_waiting, 1)

    def test_stop_cleanup_continues_after_one_restore_failure(self):
        importer = FakeImporter(available=2)
        entries = [FakeEntry(1), FakeEntry(2)]
        restore_attempts: list[int] = []
        original_restore = importer.pool.restore_entry

        def flaky_restore(entry, *, reason=""):
            restore_attempts.append(entry.number)
            if entry.number == 1:
                raise RuntimeError("state file unavailable")
            return original_restore(entry, reason=reason)

        class CancelledFuture:
            def cancel(self):
                return True

        importer.pool.restore_entry = flaky_restore
        futures = [CancelledFuture(), CancelledFuture()]
        task_ids = ["T001-fail", "T002-ok"]
        importer.futures = futures
        importer.future_assignments = {
            future: (importer.pool, entry, task_id)
            for future, entry, task_id in zip(futures, entries, task_ids)
        }
        importer.tasks = {task_id: {"status": "queued"} for task_id in task_ids}

        importer.stop()

        self.assertEqual(restore_attempts, [1, 2])
        self.assertEqual(importer.pool.restored, [2])
        self.assertEqual(importer.cancelled_waiting, 2)
        self.assertEqual([importer.tasks[task_id]["status"] for task_id in task_ids], ["stopped", "stopped"])
        self.assertIn("停止清理有 1 项未完成", importer.logs[-1][0])

    def test_empty_pool_fails_before_runtime_state_changes(self):
        importer = FakeImporter(available=0)
        with self.assertRaisesRegex(ValueError, "没有可运行的邮箱"):
            start(importer, {"target_count": 1, "concurrency": 1})
        self.assertFalse(importer.running)


if __name__ == "__main__":
    unittest.main()
