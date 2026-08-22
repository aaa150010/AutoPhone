from __future__ import annotations

import unittest

from mac_overrides.configuration_runtime import make_email_proxy_scope_migrator


class EmailProxyScopeMigrationTests(unittest.TestCase):
    def setUp(self):
        self.migrate = make_email_proxy_scope_migrator(strategy_version=1)

    def test_unversioned_legacy_false_is_enabled_once(self):
        migrated, changed = self.migrate(
            {"proxy_scope": {"sms": False, "email": False, "upload": False}}
        )

        self.assertTrue(changed)
        self.assertTrue(migrated["proxy_scope"]["email"])
        self.assertEqual(migrated["email_proxy_scope_strategy_version"], 1)

    def test_missing_scope_uses_proxy_default(self):
        migrated, changed = self.migrate({})

        self.assertTrue(changed)
        self.assertTrue(migrated["proxy_scope"]["email"])
        self.assertEqual(migrated["email_proxy_scope_strategy_version"], 1)

    def test_versioned_manual_disable_is_preserved(self):
        config = {
            "proxy_scope": {"sms": False, "email": False, "upload": False},
            "email_proxy_scope_strategy_version": 1,
        }

        migrated, changed = self.migrate(config)

        self.assertFalse(changed)
        self.assertFalse(migrated["proxy_scope"]["email"])

    def test_other_proxy_scope_choices_are_preserved(self):
        migrated, _changed = self.migrate(
            {"proxy_scope": {"sms": True, "upload": True}}
        )

        self.assertTrue(migrated["proxy_scope"]["sms"])
        self.assertTrue(migrated["proxy_scope"]["upload"])
        self.assertTrue(migrated["proxy_scope"]["email"])


if __name__ == "__main__":
    unittest.main()
