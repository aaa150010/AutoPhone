from __future__ import annotations

import unittest

from mac_overrides.failure_secrets import collect_failure_secrets


class _MailboxAdminService:
    @staticmethod
    def _row_secrets(row):
        return tuple(part for part in str(row).split("---") if part)


class _MailboxAdminModule:
    MailboxAdminService = _MailboxAdminService

    @staticmethod
    def url_credential_secrets(value):
        return (str(value),) if value else ()


class FailureSecretsTests(unittest.TestCase):
    def test_pool_content_rows_are_included_in_runtime_redaction(self):
        secrets = collect_failure_secrets(
            settings={
                "pool_content": "user@example.test---mailbox-password---mailbox-token",
                "sms_api_keys": ["sms-secret"],
            },
            mailbox_admin=_MailboxAdminModule,
            sms_keys_from_config=lambda config: config.get("sms_api_keys") or (),
        )

        self.assertIn("mailbox-password", secrets)
        self.assertIn("mailbox-token", secrets)
        self.assertIn("sms-secret", secrets)


if __name__ == "__main__":
    unittest.main()
