import unittest

from mac_overrides.performance_runtime import (
    ADAPTIVE_TASK_CONCURRENCY,
    SMS_QUALITY_OPTIMIZATION,
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

        disabled = normalize_feature_flags(
            {
                SMS_QUALITY_OPTIMIZATION: "false",
                ADAPTIVE_TASK_CONCURRENCY: 0,
                "unrelated": "kept",
            }
        )
        self.assertFalse(disabled[SMS_QUALITY_OPTIMIZATION])
        self.assertFalse(disabled[ADAPTIVE_TASK_CONCURRENCY])
        self.assertEqual(disabled["unrelated"], "kept")

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


if __name__ == "__main__":
    unittest.main()
