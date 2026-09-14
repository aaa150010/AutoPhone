"""Focused contract tests for the throttle-cooldown automatic retry band.

Covers the ``FreeRegisterRetryMixin`` throttle helpers (signature matching,
cooldown scheduling, budget exhaustion, guarded fire dispatch) and the worker
branch that makes a throttle failure pick the delayed cooldown path instead of
the immediate 2FA/password auto retries.  All runners and proxies are fakes;
no real mailbox, proxy or browser work happens here.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
import unittest
from unittest.mock import patch

from mac_overrides.free_register_runtime import (
    FIXED_PASSWORD,
    FreeMailboxPool,
    FreeProxyPool,
    FreeRegisterManager,
)


class ThrottleRetrySchedulerTests(unittest.TestCase):
    """Unit contracts for the throttle signature, scheduler and fire guard."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-throttle-test-")
        self.data_dir = Path(self.temp_dir.name)
        self.logs: list[tuple[str, str, dict]] = []
        self.manager = FreeRegisterManager(
            self.data_dir,
            log_fn=lambda message, level="info", **fields: self.logs.append(
                (str(message), str(level), fields)
            ),
        )
        self.manager._tasks["throttle-task"] = {
            "task_id": "throttle-task",
            "status": "failed",
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
        }

    def tearDown(self):
        for timer in list(self.manager._throttle_retry_timers):
            timer.cancel()
            self.manager._throttle_retry_timers.discard(timer)
        self.temp_dir.cleanup()

    def _config(self, attempts=2, cooldown=60) -> dict:
        return {
            "throttle_auto_retry_attempts": attempts,
            "throttle_retry_cooldown_minutes": cooldown,
        }

    def _timers(self):
        return list(self.manager._throttle_retry_timers)

    def _nodes(self):
        return [str(fields.get("node_code") or "") for _message, _level, fields in self.logs]

    def test_failure_is_throttle_matches_verification_signature_only(self):
        matches = self.manager._failure_is_throttle
        self.assertTrue(matches({"node_code": "free_email_otp_validate"}))
        self.assertTrue(matches({"node_code": "free_twofa_otp_validate"}))
        self.assertTrue(
            matches({"node_code": "free_password_enroll", "error_code": "camoufox_email_verification_timeout"})
        )
        self.assertFalse(matches({"node_code": "free_password_enroll", "error_code": "free_password_enroll_failed"}))
        self.assertFalse(matches({"error_code": "rate_limited"}))
        self.assertFalse(matches(None))
        self.assertFalse(matches("throttle"))

    def test_schedule_throttle_arms_cooldown_timer_and_persists_attempt(self):
        task_id = self.manager._schedule_throttle_retry(
            self.manager._tasks["throttle-task"], self._config()
        )
        self.assertEqual(task_id, "throttle-task")
        with self.manager._lock:
            task = dict(self.manager._tasks["throttle-task"])
        self.assertEqual(int(task["throttle_retry_attempt"]), 1)
        self.assertGreaterEqual(int(task["auto_throttle_retry_at"]), int(time.time()) + 59 * 60)
        timers = self._timers()
        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0].interval, 60 * 60)
        self.assertTrue(timers[0].daemon)
        self.assertIn("free_throttle_retry_scheduled", self._nodes())

    def test_schedule_throttle_clamps_cooldown_floor_to_five_minutes(self):
        self.manager._schedule_throttle_retry(
            self.manager._tasks["throttle-task"], self._config(cooldown=1)
        )
        timers = self._timers()
        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0].interval, 5 * 60)

    def test_schedule_throttle_budget_exhausted_keeps_manual_path(self):
        with self.manager._lock:
            self.manager._tasks["throttle-task"]["throttle_retry_attempt"] = 2
        task_id = self.manager._schedule_throttle_retry(
            self.manager._tasks["throttle-task"], self._config(attempts=2)
        )
        self.assertEqual(task_id, "")
        self.assertEqual(self._timers(), [])
        self.assertIn("free_throttle_retry_scheduled", self._nodes())
        budget_logs = [
            fields for _message, _level, fields in self.logs
            if fields.get("outcome") == "budget_exhausted"
        ]
        self.assertEqual(len(budget_logs), 1)

    def test_schedule_throttle_requires_both_explicit_config_keys(self):
        # Presence-sensitive like the password/2FA budgets: direct callers
        # that omit the keys keep the historical no-throttle-retry behavior.
        task_id = self.manager._schedule_throttle_retry(
            self.manager._tasks["throttle-task"], {"throttle_auto_retry_attempts": 2}
        )
        self.assertEqual(task_id, "")
        task_id = self.manager._schedule_throttle_retry(
            self.manager._tasks["throttle-task"], {"throttle_retry_cooldown_minutes": 60}
        )
        self.assertEqual(task_id, "")
        task_id = self.manager._schedule_throttle_retry(
            self.manager._tasks["throttle-task"], self._config(attempts=0)
        )
        self.assertEqual(task_id, "")
        self.assertEqual(self._timers(), [])

    def test_fire_throttle_retry_reenqueues_via_batch_retry(self):
        outcome = {"accepted": [{"retry_task": {"task_id": "child-1"}}], "skipped": [], "rejected": []}
        config = self._config()
        with patch.object(self.manager, "batch_retry", return_value=outcome) as batch_retry:
            self.manager._fire_throttle_retry("throttle-task", 1, config)
        batch_retry.assert_called_once_with(["throttle-task"], config)
        fired_logs = [
            fields for _message, _level, fields in self.logs
            if fields.get("outcome") == "fired"
        ]
        self.assertEqual(len(fired_logs), 1)
        self.assertEqual(fired_logs[0]["node_code"], "free_throttle_retry_scheduled")

    def test_fire_throttle_retry_skips_while_breaker_or_gateway_block_active(self):
        for tripped, blocked in ((True, False), (False, True)):
            with (
                patch.object(self.manager.proxy_breaker, "tripped", return_value=tripped),
                patch.object(self.manager.proxy_breaker, "gateway_blocked", return_value=blocked),
                patch.object(self.manager, "batch_retry") as batch_retry,
            ):
                self.manager._fire_throttle_retry("throttle-task", 1, self._config())
            batch_retry.assert_not_called()
        self.assertEqual(
            self._nodes().count("free_throttle_retry_skipped"),
            2,
        )

    def test_fire_throttle_retry_skips_non_retryable_states(self):
        for status in ("running", "queued", "stopped", "success"):
            with self.manager._lock:
                self.manager._tasks["throttle-task"]["status"] = status
            with patch.object(self.manager, "batch_retry") as batch_retry:
                self.manager._fire_throttle_retry("throttle-task", 1, self._config())
            batch_retry.assert_not_called()
        with self.manager._lock:
            self.manager._tasks.pop("throttle-task")
        with patch.object(self.manager, "batch_retry") as batch_retry:
            self.manager._fire_throttle_retry("throttle-task", 1, self._config())
        batch_retry.assert_not_called()

    def test_fire_throttle_retry_logs_rejected_reason(self):
        outcome = {
            "accepted": [],
            "skipped": [],
            "rejected": [{"task_id": "throttle-task", "reason": "Free 邮箱租约已被占用"}],
        }
        with patch.object(self.manager, "batch_retry", return_value=outcome):
            self.manager._fire_throttle_retry("throttle-task", 1, self._config())
        skipped_messages = [
            message for message, _level, fields in self.logs
            if fields.get("node_code") == "free_throttle_retry_skipped"
        ]
        self.assertTrue(any("Free 邮箱租约已被占用" in message for message in skipped_messages))

    def test_fire_throttle_retry_contains_batch_retry_errors(self):
        with patch.object(self.manager, "batch_retry", side_effect=RuntimeError("boom")):
            self.manager._fire_throttle_retry("throttle-task", 1, self._config())
        skipped_messages = [
            message for message, _level, fields in self.logs
            if fields.get("node_code") == "free_throttle_retry_skipped"
        ]
        self.assertTrue(any("自动重试触发失败" in message for message in skipped_messages))


class ThrottleRetryWorkerPathTests(unittest.TestCase):
    """Worker branch contract: a throttle-shaped failure picks the delayed
    cooldown path instead of the instant 2FA/password auto retries, and the
    fired re-dispatch reuses ``batch_retry`` while inheriting the budget."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-throttle-worker-")
        self.data_dir = Path(self.temp_dir.name)
        self.managers: list[FreeRegisterManager] = []

    def tearDown(self):
        for manager in self.managers:
            for timer in list(manager._throttle_retry_timers):
                timer.cancel()
                manager._throttle_retry_timers.discard(timer)
        self.temp_dir.cleanup()

    def _make_manager(self, runner) -> FreeRegisterManager:
        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.140",
        )
        self.managers.append(manager)
        return manager

    def _seed_pools(self, email: str, proxy_host: str) -> None:
        FreeMailboxPool(self.data_dir).import_text(
            f"{email}----https://mail.example.test/{email.split('@')[0]}\n"
        )
        FreeProxyPool(self.data_dir).import_text(f"http://{proxy_host}:8000\n")

    def _start(self, manager: FreeRegisterManager) -> None:
        manager.start({
            "target_count": 1,
            "twofa_auto_retry_attempts": 2,
            "password_auto_retry_attempts": 2,
            "throttle_auto_retry_attempts": 2,
            "throttle_retry_cooldown_minutes": 60,
        })
        deadline = time.time() + 8
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

    def _throttle_failure(self) -> dict:
        return {
            "node_code": "free_twofa_otp_validate",
            "error_code": "camoufox_email_verification_timeout",
            "retryable": True,
        }

    def _pending_twofa_result(self) -> dict:
        return {
            "access_token": "token-private",
            "password": FIXED_PASSWORD,
            "twofa_status": "pending",
            "twofa_failure": self._throttle_failure(),
        }

    def _tasks(self, manager: FreeRegisterManager) -> dict[str, dict]:
        return {task["task_id"]: task for task in manager.public_state()["tasks"]}

    def test_twofa_throttle_failure_schedules_cooldown_not_auto_twofa_retry(self):
        self._seed_pools("thr-a@example.test", "proxy-thra.test")

        def runner(_task, _config, _stop, _stage, _log):
            return self._pending_twofa_result()

        manager = self._make_manager(runner)
        with (
            patch.object(manager, "_schedule_auto_twofa_retry") as auto_twofa,
            patch.object(manager, "_schedule_auto_password_retry") as auto_password,
        ):
            self._start(manager)
        auto_twofa.assert_not_called()
        auto_password.assert_not_called()
        tasks = self._tasks(manager)
        roots = [task for task in tasks.values() if not task.get("retry_of")]
        self.assertEqual(len(roots), 1)
        root = roots[0]
        self.assertEqual(root["status"], "twofa_pending")
        with manager._lock:
            private_root = dict(manager._tasks[root["task_id"]])
        self.assertEqual(int(private_root["throttle_retry_attempt"]), 1)
        self.assertGreaterEqual(int(private_root["auto_throttle_retry_at"]), int(time.time()) + 59 * 60)
        timers = list(manager._throttle_retry_timers)
        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0].interval, 60 * 60)

    def test_fire_after_cooldown_reenqueues_child_inheriting_budget(self):
        self._seed_pools("thr-b@example.test", "proxy-thrb.test")

        def runner(_task, _config, _stop, _stage, _log, *, twofa_retry=False):
            if twofa_retry:
                return {
                    "access_token": "token-private",
                    "password": FIXED_PASSWORD,
                    "twofa_status": "enabled",
                    "totp_secret": "JBSWY3DPEHPK3PXP",
                }
            return self._pending_twofa_result()

        manager = self._make_manager(runner)
        self._start(manager)
        tasks = self._tasks(manager)
        roots = [task for task in tasks.values() if not task.get("retry_of")]
        self.assertEqual(len(roots), 1)
        root = roots[0]
        self.assertEqual(root["status"], "twofa_pending")
        # The throttle branch owns the schedule; no immediate 2FA child exists.
        self.assertEqual([task for task in tasks.values() if task.get("retry_of")], [])
        # Simulate the cooldown expiring: cancel the armed timer and fire the
        # callback path directly so the test stays deterministic.
        for timer in list(manager._throttle_retry_timers):
            timer.cancel()
            manager._throttle_retry_timers.discard(timer)
        manager._fire_throttle_retry(root["task_id"], 1, {
            "throttle_auto_retry_attempts": 2,
            "throttle_retry_cooldown_minutes": 60,
        })
        deadline = time.time() + 8
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)
        tasks = self._tasks(manager)
        children = [task for task in tasks.values() if task.get("retry_of") == root["task_id"]]
        self.assertEqual(len(children), 1)
        child = children[0]
        self.assertEqual(child["retry_mode"], "twofa")
        self.assertIn(child["status"], {"success", "partial_success"})
        # The continuation child inherits the parent's consumed budget instead
        # of resetting it, so a chain of throttle failures still stops at the
        # cap.  The counter lives on the private task (not the public shape).
        with manager._lock:
            private_child = dict(manager._tasks[child["task_id"]])
        self.assertEqual(int(private_child["throttle_retry_attempt"]), 1)


if __name__ == "__main__":
    unittest.main()
