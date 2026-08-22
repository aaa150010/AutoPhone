from __future__ import annotations

import unittest

from mac_overrides.mailbox_url_runtime import (
    MailboxMessage,
    MailboxScan,
    MailboxScanDiagnostics,
    MailboxSelection,
    MailboxUrlError,
)
from mac_overrides.mailbox_url_test_runtime import MailboxUrlTester, parse_test_input


class MailboxUrlTestRuntimeTests(unittest.TestCase):
    def test_default_path_uses_shared_service_and_displays_existing_latest_code(self):
        captured = {}

        class FakeService:
            def __init__(self, mailbox_url, **kwargs):
                captured["url"] = mailbox_url
                captured["kwargs"] = kwargs
                captured["prepared"] = False
                captured["closed"] = False
                captured["snapshots"] = 0

            def snapshot(self):
                captured["snapshots"] += 1
                message = MailboxMessage(
                    identity="latest-message",
                    sender="noreply_at_tm_openai_com@icloud.com",
                    subject="ChatGPT の一時的な認証コード",
                    body="一時検証コード: 654321",
                    code="654321",
                )
                return MailboxSelection(
                    code="654321",
                    identity=message.identity,
                    received_at="2026-08-22T09:29:00+08:00",
                    fingerprint="fingerprint",
                    scan=MailboxScan(
                        messages=(message,),
                        page_fingerprint="page",
                        fetched_at=1,
                        diagnostics=MailboxScanDiagnostics(
                            listing_messages=1,
                            openai_messages=1,
                            code_messages=1,
                            explicit_code_messages=1,
                        ),
                    ),
                    reason="code_found",
                )

            def diagnostic(self):
                return {
                    "request_attempts": 1,
                    "secret": "should-not-be-returned",
                }

            def close(self):
                captured["closed"] = True

        def service_factory(mailbox_url, **kwargs):
            service = FakeService(mailbox_url, **kwargs)
            captured["service"] = service
            return service

        url = "https://mail.example.test/pickup?email=user%40example.test&key=private"
        result = MailboxUrlTester(
            service_factory=service_factory,
            now_fn=lambda: 100,
            sleep_fn=lambda _seconds: self.fail("an existing code should be shown immediately"),
        ).test(url, proxy="http://127.0.0.1:7897")

        self.assertTrue(result["ok"])
        self.assertEqual(result["verification_code"], "654321")
        self.assertEqual(captured["url"], url)
        policy = captured["kwargs"]["network_policy"]
        self.assertEqual(policy.mode, "local_proxy")
        self.assertEqual(policy.effective_proxy, "http://127.0.0.1:7897")
        self.assertEqual(captured["snapshots"], 1)
        self.assertTrue(captured["closed"])
        self.assertNotIn("private", str(result))
        self.assertNotIn("should-not-be-returned", str(result))

    def test_default_path_returns_safe_shared_service_transport_diagnostic(self):
        class FakeService:
            def __init__(self, _mailbox_url, **_kwargs):
                pass

            def snapshot(self):
                raise MailboxUrlError(
                    "mailbox_http_error",
                    "邮箱取件请求返回 HTTP 502",
                    status=502,
                )

            def diagnostic(self):
                return {
                    "refresh_error_code": "mailbox_http_error",
                    "refresh_http_status": 502,
                    "request_attempts": 2,
                    "mailbox_key": "private-key",
                }

            def close(self):
                pass

        result = MailboxUrlTester(
            service_factory=FakeService,
            now_fn=lambda: 100,
            sleep_fn=lambda _seconds: self.fail("transport errors should return immediately"),
        ).test("https://mail.example.test/pickup?email=user%40example.test&key=private-key")

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "mailbox_http_error")
        self.assertEqual(result["diagnostics"]["refresh_http_status"], 502)
        self.assertEqual(result["diagnostics"]["request_attempts"], 2)
        self.assertNotIn("private-key", str(result))

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
