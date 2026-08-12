import unittest
import threading
import time

from mac_overrides.performance_runtime import (
    ADAPTIVE_TASK_CONCURRENCY,
    InflightAdmissionGate,
    MAILBOX_RESULT_INDEX_CACHE,
    OPENAI_CONNECTIVITY_GUARD,
    PHONE_BINDING_COMPATIBILITY,
    SMS_QUALITY_OPTIMIZATION,
    TASK_INFLIGHT_OPTIMIZATION,
    as_bool,
    normalize_feature_flags,
    format_task_admission_event,
    migrate_performance_config,
    resolve_task_admission,
)


class PerformanceRuntimeTests(unittest.TestCase):
    def test_feature_flags_default_on_and_preserve_explicit_false(self):
        defaults = normalize_feature_flags({})
        self.assertTrue(defaults[SMS_QUALITY_OPTIMIZATION])
        self.assertTrue(defaults[ADAPTIVE_TASK_CONCURRENCY])
        self.assertTrue(defaults[TASK_INFLIGHT_OPTIMIZATION])
        self.assertTrue(defaults[OPENAI_CONNECTIVITY_GUARD])
        self.assertTrue(defaults[PHONE_BINDING_COMPATIBILITY])
        self.assertTrue(defaults[MAILBOX_RESULT_INDEX_CACHE])

        disabled = normalize_feature_flags(
            {
                SMS_QUALITY_OPTIMIZATION: "false",
                ADAPTIVE_TASK_CONCURRENCY: 0,
                TASK_INFLIGHT_OPTIMIZATION: "off",
                PHONE_BINDING_COMPATIBILITY: "disabled",
                MAILBOX_RESULT_INDEX_CACHE: "off",
                "unrelated": "kept",
            }
        )
        self.assertFalse(disabled[SMS_QUALITY_OPTIMIZATION])
        self.assertFalse(disabled[ADAPTIVE_TASK_CONCURRENCY])
        self.assertFalse(disabled[TASK_INFLIGHT_OPTIMIZATION])
        self.assertFalse(disabled[PHONE_BINDING_COMPATIBILITY])
        self.assertFalse(disabled[MAILBOX_RESULT_INDEX_CACHE])
        self.assertEqual(disabled["unrelated"], "kept")

    def test_protocol_ceiling_defaults_to_twelve_and_is_bounded_to_eight_fifteen(self):
        defaulted, _changed = migrate_performance_config({})
        low, _changed = migrate_performance_config({"protocol_concurrency_ceiling": 1})
        high, _changed = migrate_performance_config({"protocol_concurrency_ceiling": 99})

        self.assertEqual(defaulted["protocol_concurrency_ceiling"], 12)
        self.assertEqual(low["protocol_concurrency_ceiling"], 8)
        self.assertEqual(high["protocol_concurrency_ceiling"], 15)

    def test_unknown_boolean_text_uses_the_requested_default(self):
        self.assertTrue(as_bool("unexpected", True))
        self.assertFalse(as_bool("unexpected", False))
        self.assertFalse(as_bool("OFF", True))

    def test_performance_migration_preserves_explicit_zero_auth_retries(self):
        migrated, changed = migrate_performance_config(
            {
                "performance_policy_version": 10,
                "auth_session_retries": 0,
            }
        )

        self.assertTrue(changed)
        self.assertEqual(migrated["auth_session_retries"], 0)

    def test_performance_migration_repairs_unparseable_legacy_values(self):
        migrated, changed = migrate_performance_config(
            {
                "performance_policy_version": 10,
                "auth_session_retries": [],
            }
        )

        self.assertTrue(changed)
        self.assertEqual(
            migrated["auth_session_retries"],
            1,
        )

    def test_inflight_limit_defaults_and_is_clamped_without_changing_concurrency(self):
        defaulted, _changed = migrate_performance_config({"concurrency": 99})
        self.assertEqual(defaulted["concurrency"], 8)
        self.assertEqual(defaulted["task_inflight_limit"], 20)

        low, _changed = migrate_performance_config(
            {"performance_policy_version": 12, "task_inflight_limit": 0}
        )
        high, _changed = migrate_performance_config(
            {"performance_policy_version": 12, "task_inflight_limit": 99}
        )
        self.assertEqual(low["task_inflight_limit"], 1)
        self.assertEqual(high["task_inflight_limit"], 20)

    def test_version_11_migration_does_not_reset_existing_concurrency_choices(self):
        migrated, changed = migrate_performance_config(
            {
                "performance_policy_version": 11,
                "auto_email_login_concurrency": 1,
                "phone_max_attempts": 15,
            }
        )
        self.assertTrue(changed)
        self.assertEqual(migrated["auto_email_login_concurrency"], 1)
        self.assertEqual(migrated["phone_max_attempts"], 15)

    def test_adaptive_admission_is_scoped_to_register_concurrency_eight(self):
        policy = resolve_task_admission(8, run_mode="register", adaptive_enabled=True)
        self.assertEqual(
            (policy.base_limit, policy.restore_ceiling, policy.absolute_ceiling),
            (8, 10, 10),
        )
        self.assertTrue(policy.adaptive)

        for value in (
            resolve_task_admission(7, run_mode="register", adaptive_enabled=True),
            resolve_task_admission(8, run_mode="relogin", adaptive_enabled=True),
            resolve_task_admission(8, run_mode="register", adaptive_enabled=False),
        ):
            self.assertEqual(value.base_limit, value.restore_ceiling)
            self.assertEqual(value.base_limit, value.absolute_ceiling)
            self.assertFalse(value.adaptive)

    def test_admission_limit_is_bounded_and_invalid_values_use_existing_default(self):
        self.assertEqual(resolve_task_admission(100).base_limit, 8)
        self.assertEqual(resolve_task_admission(0).base_limit, 1)
        self.assertEqual(resolve_task_admission("invalid").base_limit, 5)

    def test_admission_events_are_redacted_and_invalid_events_are_ignored(self):
        message, level = format_task_admission_event(
            {"kind": "restored", "old_limit": 8, "new_limit": 9, "secret": "do-not-log"}
        )
        self.assertEqual(level, "info")
        self.assertIn("8 -> 9", message)
        self.assertNotIn("do-not-log", message)
        self.assertIsNone(format_task_admission_event({"old_limit": 0, "new_limit": 8}))

    def test_inflight_gate_reaches_twenty_and_reports_waiting(self):
        gate = InflightAdmissionGate(8, limit=20, enabled=True)
        release = threading.Event()
        entered = threading.Event()

        def worker():
            with gate.acquire():
                entered.wait(timeout=5)
                release.wait(timeout=2)

        threads = [threading.Thread(target=worker) for _ in range(21)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 2
        while gate.snapshot()["waiting"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        snapshot = gate.snapshot()
        self.assertEqual(snapshot["active"], 20)
        self.assertEqual(snapshot["waiting"], 1)
        self.assertEqual(snapshot["effective"], 20)
        entered.set()
        release.set()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(gate.snapshot()["active"], 0)

    def test_disabled_inflight_gate_is_the_configured_baseline(self):
        snapshot = InflightAdmissionGate(7, limit=20, enabled=False).snapshot()
        self.assertEqual(snapshot, {
            "configured": 7,
            "baseline_concurrency": 7,
            "requested_limit": 20,
            "effective": 7,
            "active": 0,
            "waiting": 0,
            "optimized": False,
            "staged": False,
            "rolled_back": False,
            "suspended": False,
            "sticky_baseline": False,
            "resume_eligible": False,
            "reason": "configured_baseline",
        })

    def test_inflight_gate_stop_wakes_waiters(self):
        gate = InflightAdmissionGate(1, limit=1)
        release = threading.Event()
        entered = threading.Event()
        stopped: list[str] = []

        def holder():
            with gate.acquire():
                entered.set()
                release.wait(timeout=2)

        def waiter():
            try:
                with gate.acquire():
                    pass
            except RuntimeError as exc:
                stopped.append(str(exc))

        first = threading.Thread(target=holder)
        second = threading.Thread(target=waiter)
        first.start()
        entered.wait(timeout=2)
        second.start()
        deadline = time.monotonic() + 2
        while gate.snapshot()["waiting"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        gate.stop()
        second.join(timeout=2)
        release.set()
        first.join(timeout=2)
        self.assertEqual(stopped, ["task_stopped"])
        self.assertEqual(gate.snapshot()["waiting"], 0)

    def test_inflight_gate_rolls_back_immediately_and_reason_is_redacted(self):
        gate = InflightAdmissionGate(8, limit=20)
        event = gate.report_pressure("secret-token=raw")
        self.assertEqual(event["reason"], "protocol_pressure")
        snapshot = gate.snapshot()
        self.assertEqual(snapshot["effective"], 8)
        self.assertTrue(snapshot["rolled_back"])
        self.assertNotIn("secret-token", str(snapshot))
        self.assertIsNone(gate.report_http_429())

        self.assertEqual(
            InflightAdmissionGate(8).report_http_429()["reason"],
            "http_429",
        )
        self.assertEqual(
            InflightAdmissionGate(8).report_session_invalidation()["reason"],
            "session_invalidation",
        )

    def test_inflight_connectivity_suspension_is_recoverable_until_sticky(self):
        gate = InflightAdmissionGate(8, limit=20)

        suspended = gate.suspend("openai_connectivity_suspected")
        self.assertEqual(suspended["kind"], "task_inflight_optimization_suspended")
        snapshot = gate.snapshot()
        self.assertEqual(snapshot["effective"], 8)
        self.assertTrue(snapshot["suspended"])
        self.assertTrue(snapshot["resume_eligible"])
        self.assertTrue(snapshot["staged"])
        self.assertFalse(snapshot["rolled_back"])

        restored = gate.resume()
        self.assertEqual(restored["new_limit"], 20)
        self.assertTrue(gate.snapshot()["optimized"])

        gate.suspend("openai_connectivity_outage")
        rollback = gate.report_http_429()
        self.assertEqual(rollback["reason"], "http_429")
        snapshot = gate.snapshot()
        self.assertFalse(snapshot["suspended"])
        self.assertTrue(snapshot["sticky_baseline"])
        self.assertFalse(snapshot["resume_eligible"])
        self.assertIsNone(gate.resume())

    def test_inflight_gate_rolling_window_rollbacks(self):
        success_gate = InflightAdmissionGate(8)
        for _index in range(81):
            success_gate.observe_task("success")
        for _index in range(19):
            event = success_gate.observe_task("failed")
        self.assertEqual(event["reason"], "success_rate_below_819")

        late_gate = InflightAdmissionGate(8)
        for index in range(100):
            event = late_gate.observe_task(
                "success",
                {"confirmed_late_code_loss": index in {0, 99}},
            )
        self.assertEqual(event["reason"], "two_confirmed_late_code_losses")

        rate_gate = InflightAdmissionGate(
            8,
            baseline={"cancellation_rate": 0.05, "duplicate_order_rate": 0.01},
        )
        for index in range(100):
            event = rate_gate.observe_task(
                "success",
                {"orders": 1, "cancelled": index < 6},
            )
        self.assertEqual(event["reason"], "cancellation_rate_increased")

        duplicate_gate = InflightAdmissionGate(
            8,
            baseline={"duplicate_order_rate": 0.01},
        )
        for index in range(100):
            event = duplicate_gate.observe_task(
                "success",
                {"orders": 1, "duplicates": index < 2},
            )
        self.assertEqual(event["reason"], "duplicate_order_rate_increased")

        cost_gate = InflightAdmissionGate(
            8,
            baseline={"cost_per_success_usd": 1.0},
        )
        for _index in range(100):
            event = cost_gate.observe_task("success", {"cost_usd": 1.11})
        self.assertEqual(event["reason"], "cost_per_success_above_110_percent")


if __name__ == "__main__":
    unittest.main()
