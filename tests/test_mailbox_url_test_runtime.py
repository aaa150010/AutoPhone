from __future__ import annotations

import unittest

from mac_overrides.mailbox_url_runtime import (
    MailboxMessage,
    MailboxScan,
    MailboxScanDiagnostics,
    MailboxUrlError,
)
from mac_overrides.mailbox_url_test_runtime import MailboxUrlTester, parse_test_input


class MailboxUrlTestRuntimeTests(unittest.TestCase):
    def test_query_url_and_extracted_code_are_returned_for_success_display(self):
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
        self.assertEqual(result["verification_code"], "654321")
        self.assertNotIn("code", result)
        self.assertEqual(captured[0][0], url)
        self.assertEqual(captured[0][1]["timeout_seconds"], 15)

    def test_timeout_exits_after_bounded_fake_clock_without_looping_forever(self):
        clock = [0.0]
        scans = [0]

        class FakeClient:
            def __init__(self, _mailbox_url, **_kwargs):
                pass

            def scan(self):
                scans[0] += 1
                return MailboxScan(
                    messages=(),
                    page_fingerprint="empty-page",
                    fetched_at=clock[0],
                    diagnostics=MailboxScanDiagnostics(
                        refresh_error_code="mailbox_http_error",
                        refresh_http_status=503,
                    ),
                )

        result = MailboxUrlTester(
            client_factory=FakeClient,
            now_fn=lambda: clock[0],
            sleep_fn=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        ).test(
            "https://mail.example.test/messages/sample-access-token/user%40example.test",
            timeout_seconds=3,
            interval_seconds=1,
            resend_after_seconds=2,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "mailbox_code_timeout")
        self.assertEqual(result["attempts"], 4)
        self.assertEqual(scans[0], 4)
        self.assertEqual(result["elapsed_seconds"], 3.0)
        self.assertEqual(result["reason"], "mailbox_refresh_request_failed")
        self.assertEqual(
            result["diagnostics"]["refresh_error_code"],
            "mailbox_http_error",
        )
        self.assertEqual(result["diagnostics"]["refresh_http_status"], 503)

    def test_supported_email_url_separators_are_sent_to_the_same_mailbox_client(self):
        for separator in ("---", "----", "|", "｜"):
            email, url = parse_test_input(
                f"user@example.test{separator}https://mail.example.test/messages/a?all=1"
            )
            with self.subTest(separator=separator):
                self.assertEqual(email, "user@example.test")
                self.assertEqual(url, "https://mail.example.test/messages/a?all=1")

    def test_url_totp_row_sends_only_middle_url_to_mailbox_client(self):
        email, url = parse_test_input(
            "User@Example.test----"
            "https://mail.example.test/latest?email=user%40example.test&auth_code=private----"
            "JBSWY3DPEHPK3PXP"
        )

        self.assertEqual(email, "user@example.test")
        self.assertEqual(
            url,
            "https://mail.example.test/latest?email=user%40example.test&auth_code=private",
        )
        self.assertNotIn("JBSWY3DPEHPK3PXP", url)

    def test_invalid_composite_row_never_becomes_a_request_url(self):
        for value in (
            "user@example.test----https://mail.example.test/latest----INVALID018",
            "user@example.test----https://mail.example.test/latest----"
            "JBSWY3DPEHPK3PXP----extra",
            "user@example.test|https://mail.example.test/latest----JBSWY3DPEHPK3PXP",
            "user@example.test|https://mail.example.test/latest----totp:JBSWY3DPEHPK3PXP",
            "user@example.test|https://mail.example.test/latest----secret:JBSWY3DPEHPK3PXP",
            "user@example.test|https://mail.example.test/latest----密钥：JBSWY3DPEHPK3PXP",
            "https://mail.example.test/latest----JBSWY3DPEHPK3PXP",
            "https://mail.example.test/latest----totp:JBSWY3DPEHPK3PXP",
        ):
            with self.subTest(value=value), self.assertRaises(MailboxUrlError):
                parse_test_input(value)


if __name__ == "__main__":
    unittest.main()
