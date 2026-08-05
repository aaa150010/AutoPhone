from __future__ import annotations

import unittest

from mac_overrides.mailbox_url_runtime import (
    MailboxMessage,
    MailboxScan,
    MailboxScanDiagnostics,
)
from mac_overrides.mailbox_url_test_runtime import MailboxUrlTester, parse_test_input


class MailboxUrlTestRuntimeTests(unittest.TestCase):
    def test_query_url_and_expected_code_are_read_without_returning_code(self):
        url = (
            "https://mail.example.test/messages/sample-access-token/"
            "user%40example.test?all=1"
        )
        captured = []

        class FakeClient:
            def __init__(self, mailbox_url, **kwargs):
                captured.append((mailbox_url, kwargs))

            def scan(self):
                return MailboxScan(
                    messages=(MailboxMessage(
                        identity="message-1",
                        subject="OpenAI verification code",
                        body="OpenAI verification code: 654321",
                        code="654321",
                    ),),
                    page_fingerprint="page-1",
                    fetched_at=1,
                    diagnostics=MailboxScanDiagnostics(
                        listing_messages=1,
                        detail_links=1,
                        detail_refreshed=1,
                        code_messages=1,
                        openai_messages=1,
                    ),
                )

        result = MailboxUrlTester(
            client_factory=FakeClient,
            now_fn=lambda: 100,
            sleep_fn=lambda _seconds: self.fail("a code should be found on the first scan"),
        ).test(url)

        self.assertTrue(result["ok"])
        self.assertTrue(result["code_found"])
        self.assertNotIn("654321", result)
        self.assertEqual(captured[0][0], url)
        self.assertEqual(captured[0][1]["timeout_seconds"], 15)

    def test_supported_email_url_separators_are_sent_to_the_same_mailbox_client(self):
        for separator in ("---", "----", "|", "｜"):
            email, url = parse_test_input(
                f"user@example.test{separator}https://mail.example.test/messages/a?all=1"
            )
            with self.subTest(separator=separator):
                self.assertEqual(email, "user@example.test")
                self.assertEqual(url, "https://mail.example.test/messages/a?all=1")


if __name__ == "__main__":
    unittest.main()
