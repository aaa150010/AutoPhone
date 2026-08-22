from __future__ import annotations

import base64
import json
from html import escape
import unittest

from mac_overrides.mailbox_url_runtime import (
    MAX_MESSAGES,
    MailboxRequestState,
    MailboxResponse,
    MailboxUrlClient,
    MailboxUrlError,
    extract_openai_code,
    masked_mailbox_url_row,
    parse_mailbox_payload,
    parse_mailbox_url_row,
    parse_received_timestamp,
    select_latest_code,
)


BASE_URL = "https://mail.example.test/messages/operator-token/user@example.test"
CLIENT_SHELL_HTML = """
<html>
  <p id="mail-address">loading</p>
  <div id="message-list"></div>
  <strong id="code-box">waiting</strong>
  <script type="module" src="/static/js/weimail_customer.js"></script>
  <script>fetch('https://ignored.example.test/messages')</script>
</html>
"""

PICKUP_SHELL_HTML = """
<html><body>
  <div id="address"></div>
  <section id="list"></section>
  <script>
    const urlSearchParams = new URLSearchParams(location.search);
    fetch(`/api/messages?email=${encodeURIComponent(email)}&key=${encodeURIComponent(key)}`);
    fetch(`/api/message/${id}?email=${encodeURIComponent(email)}&key=${encodeURIComponent(key)}`);
  </script>
</body></html>
"""


def json_response(url: str, value, status: int = 200) -> MailboxResponse:
    return MailboxResponse(
        url=url,
        body=json.dumps(value).encode("utf-8"),
        content_type="application/json; charset=utf-8",
        status=status,
    )


def html_response(url: str, value: str, status: int = 200) -> MailboxResponse:
    return MailboxResponse(
        url=url,
        body=value.encode("utf-8"),
        content_type="text/html; charset=utf-8",
        status=status,
    )


def verification_body(code: str) -> str:
    html = f"<html><body><h1>OpenAI</h1><p>Your verification code is <b>{code}</b></p></body></html>"
    payload = base64.b64encode(html.encode("utf-8")).decode("ascii")
    return f"data:text/html;charset=utf-8;base64,{payload}"


class MailboxUrlRuntimeTests(unittest.TestCase):
    def test_trusted_pickup_list_only_response_accepts_bare_code(self):
        result, detail_urls = parse_mailbox_payload(
            '["654321", "not-a-code"]',
            "https://mail.example.test/pickup",
        )
        self.assertEqual(detail_urls, ())
        self.assertEqual([message.code for message in result], ["654321"])
        self.assertEqual(result[0].code_source, "bare_code")

    def test_pickup_parses_japanese_message_aliases_and_latest_timestamp(self):
        pickup_url = "https://mail.example.test/pickup?email=user@example.test&key=redacted"
        payload = {
            "data": {
                "messages": [
                    {
                        "ID": "new-jp",
                        "FROM": "noreply_at_tm_openai_com_b2j2rdvb5es0k1_p1fp2345@icloud.com",
                        "TITLE": "ChatGPT の一時的な認証コード",
                        "CONTENT_HTML": "<p>この一時検証コードを入力して続行してください: 654321</p>",
                        "SENT_AT": "2026-08-20T09:29:00+08:00",
                    },
                    {
                        "id": "old-jp",
                        "sender_email": "noreply_at_tm_openai_com@icloud.com",
                        "mail_title": "ChatGPT の一時的な認証コード",
                        "content": "この一時検証コードを入力して続行してください: 123456",
                        "sent_at": "2026-08-20T07:43:00+08:00",
                    },
                ],
            },
        }
        messages, _links = parse_mailbox_payload(json.dumps(payload, ensure_ascii=False), pickup_url)
        self.assertEqual([message.code for message in messages], ["654321", "123456"])
        self.assertEqual(messages[0].received_at, "2026-08-20T09:29:00+08:00")
        self.assertIn("body", messages[0].field_sources)
        self.assertIn("received_at", messages[0].field_sources)
        selection = select_latest_code(
            MailboxUrlClient(
                pickup_url,
                fetcher=lambda url: json_response(url, payload),
            ).scan(),
        )
        self.assertEqual(selection.code, "654321")

    def test_pickup_parses_japanese_preview_when_subject_is_not_mapped(self):
        messages, _links = parse_mailbox_payload(
            json.dumps({
                "messages": [{
                    "id": "jp-preview-only",
                    "from": "noreply_at_tm_openai_com_example@icloud.com",
                    "preview": "この一時検証コードを入力して続行してください: 654321",
                }],
            }, ensure_ascii=False),
            "https://mail.example.test/pickup",
        )
        self.assertEqual(messages[0].code, "654321")
        self.assertEqual(messages[0].code_source, "openai_context")

    def test_trusted_pickup_parses_scalar_serialized_japanese_mail_items(self):
        pickup_url = "https://mail.example.test/pickup"
        raw_item = (
            "noreply_at_tm_openai_com@icloud.com ChatGPT の一時的な認証コード "
            "この一時検証コードを入力して続行してください: 654321"
        )
        messages, _links = parse_mailbox_payload(
            json.dumps([raw_item, "not a verification message"], ensure_ascii=False),
            pickup_url,
        )
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].code, "654321")
        self.assertEqual(messages[0].code_source, "openai_context")

    def test_trusted_pickup_html_passes_source_to_code_extractor(self):
        pickup_url = "https://mail.example.test/pickup"
        html = (
            "<article data-message-id='jp-html'>"
            "<div>noreply_at_tm_openai_com@icloud.com</div>"
            "<h2>ChatGPT の一時的な認証コード</h2>"
            "<p>この一時検証コードを入力して続行してください: 654321</p>"
            "<time datetime='2026-08-20T09:29:00+08:00'>09:29</time>"
            "</article>"
        )
        messages, _links = parse_mailbox_payload(html, pickup_url)
        self.assertTrue(any(message.code == "654321" for message in messages))

    def test_trusted_pickup_html_visible_text_accepts_plain_six_digit_code(self):
        messages, _links = parse_mailbox_payload(
            "<main><div>654321</div></main>",
            "https://mail.example.test/pickup",
        )
        self.assertTrue(any(message.code == "654321" for message in messages))

        untrusted_messages, _links = parse_mailbox_payload(
            "<main><div>654321</div></main>",
            "https://mail.example.test/inbox",
        )
        self.assertFalse(any(message.code for message in untrusted_messages))

    def test_unicode_full_width_digits_are_normalized_before_otp_matching(self):
        messages, _links = parse_mailbox_payload(
            json.dumps({
                "messages": [{
                    "id": "full-width",
                    "subject": "ChatGPT の一時的な認証コード",
                    "content": "認証コード：６５４３２１",
                }],
            }, ensure_ascii=False),
            "https://mail.example.test/pickup",
        )
        self.assertEqual(messages[0].code, "654321")

    def test_untrusted_list_only_response_does_not_accept_bare_code(self):
        result, _detail_urls = parse_mailbox_payload(
            '["654321"]',
            "https://mail.example.test/inbox",
        )
        self.assertFalse(any(message.code for message in result))

    def test_parses_and_masks_all_supported_url_row_separators(self):
        for separator in ("---", "----", "|", "｜"):
            row = f"User@Example.test{separator}https://mail.example.test/inbox/a-b_c"
            with self.subTest(separator=separator):
                parsed = parse_mailbox_url_row(row)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed.email, "user@example.test")
                self.assertEqual(parsed.mailbox_url, "https://mail.example.test/inbox/a-b_c")
                self.assertEqual(
                    masked_mailbox_url_row(row),
                    separator.join(("user@example.test", "********")),
                )
        self.assertIsNone(parse_mailbox_url_row("user@example.test--https://mail.example.test/inbox"))
        self.assertIsNone(parse_mailbox_url_row("user@example.test---ftp://mail.example.test/inbox"))
        self.assertIsNone(parse_mailbox_url_row(
            "user@example.test----https://mail.example.test/inbox----INVALID018"
        ))
        for separator in ("---", "-----", "|", "｜"):
            with self.subTest(malformed_composite_separator=separator):
                self.assertIsNone(parse_mailbox_url_row(
                    f"user@example.test{separator}"
                    "https://mail.example.test/inbox----JBSWY3DPEHPK3PXP"
                ))
        encoded_delimiter = parse_mailbox_url_row(
            "user@example.test----https://mail.example.test/inbox/%2D%2D%2D%2Dtoken"
        )
        self.assertIsNotNone(encoded_delimiter)

    def test_preserves_encoded_email_and_query_parameters_in_url_input(self):
        value = (
            "https://mail.example.test/messages/sample-access-token/"
            "user%40example.test?all=1"
        )
        self.assertIsNone(parse_mailbox_url_row(value))
        from mac_overrides.mailbox_url_test_runtime import parse_test_input

        email, parsed_url = parse_test_input(value)
        self.assertEqual(email, "")
        self.assertEqual(parsed_url, value)

    def test_generic_json_does_not_trust_explicit_code_but_reads_received_time(self):
        payload = {
            "id": "message-explicit",
            "subject": "Mailbox delivery",
            "received_time": "2026-08-07T10:30:00Z",
            "verification_code": "012345",
        }

        messages, _detail_urls = parse_mailbox_payload(json.dumps(payload), BASE_URL)

        self.assertEqual(messages[0].code, "")
        self.assertFalse(messages[0].explicit_code)
        self.assertEqual(messages[0].received_at, "2026-08-07T10:30:00Z")
        self.assertIsNotNone(messages[0].received_timestamp)

        for invalid in ("12345", "1234567", "ABC123", 123456):
            with self.subTest(invalid=invalid):
                invalid_messages, _links = parse_mailbox_payload(
                    json.dumps({"id": "invalid", "verification_code": invalid}),
                    BASE_URL,
                )
                self.assertFalse(any(message.code for message in invalid_messages))
        generic_root, _links = parse_mailbox_payload(
            json.dumps({"code": "012345"}),
            BASE_URL,
        )
        self.assertFalse(any(message.code for message in generic_root))

    def test_trusted_pickup_accepts_bare_and_case_insensitive_explicit_otp_codes(self):
        pickup_url = "https://mail.example.test/pickup/session-id"
        messages, _detail_urls = parse_mailbox_payload(
            json.dumps({
                "messages": [
                    {"id": "bare", "body": "654321"},
                    {"id": "explicit", "VerificationCode": "654321"},
                ],
            }),
            pickup_url,
        )

        by_id = {message.identity: message for message in messages}
        self.assertEqual(len(messages), 2)
        self.assertTrue(all(message.code == "654321" for message in messages))
        self.assertEqual(
            {message.code_source for message in messages},
            {"bare_code", "explicit_code"},
        )
        self.assertTrue(by_id)

        scan = MailboxUrlClient(
            pickup_url,
            fetcher=lambda url: json_response(url, {"messages": [{"id": "new", "body": "654321"}]}),
        ).scan()
        self.assertEqual(scan.diagnostics.bare_code_messages, 1)
        self.assertEqual(scan.diagnostics.code_messages, 1)

    def test_parses_mail_code_envelope_with_six_digit_code(self):
        payload = {
            "email": "user@example.test",
            "code": "716075",
            "mail": {
                "id": "1786958440308838774",
                "date": "2026-08-17T09:20:39+00:00",
                "sender": "ChatGPT <noreply@tm.openai.com>",
                "subject": "Your temporary ChatGPT login code",
            },
        }

        messages, detail_urls = parse_mailbox_payload(json.dumps(payload), BASE_URL)

        self.assertEqual(detail_urls, ())
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].code, "716075")
        self.assertTrue(messages[0].explicit_code)
        self.assertEqual(messages[0].received_at, "2026-08-17T09:20:39+00:00")
        self.assertIn("ChatGPT", messages[0].sender)

    def test_mail_code_envelope_is_consumed_by_mailbox_url_client(self):
        mailbox_url = "https://lynote.xyz/mail-code/code/sample-token"
        payload = {
            "email": "user@example.test",
            "code": "716075",
            "mail": {
                "id": "1786958440308838774",
                "date": "2026-08-17T09:20:39+00:00",
                "sender": "ChatGPT <noreply@tm.openai.com>",
                "subject": "Your temporary ChatGPT login code",
            },
        }
        calls: list[str] = []

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            return json_response(url, payload)

        selection = MailboxUrlClient(mailbox_url, fetcher=fetch).latest_code()

        self.assertEqual(selection.code, "716075")
        self.assertEqual(selection.reason, "code_found")
        self.assertEqual(calls, [mailbox_url])
        self.assertEqual(selection.scan.diagnostics.code_messages, 1)

    def test_mail_code_envelope_does_not_trust_non_six_digit_or_unscoped_code(self):
        for payload in (
            {
                "email": "user@example.test",
                "code": "3243",
                "mail": {"id": "short-code", "subject": "Login code"},
            },
            {
                "email": "user@example.test",
                "code": "716075",
                "mail": "not-a-message",
            },
            {
                "email": "user@example.test",
                "code": "716075",
                "error": "oauth_failed",
                "mail": {"id": "failed", "subject": "Login code"},
            },
        ):
            with self.subTest(payload=payload):
                messages, _links = parse_mailbox_payload(json.dumps(payload), BASE_URL)
                self.assertFalse(any(message.code for message in messages))

    def test_client_rendered_shell_uses_only_same_origin_cache_api(self):
        received_at = "2026-08-07T10:30:00Z"
        now = float(parse_received_timestamp(received_at) or 0) + 30
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample%2Faccess"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample%2Faccess/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        calls: list[str] = []

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url == cache_url:
                return json_response(url, {
                    "ok": True,
                    "code": "",
                    "messages": [{
                        "id": "message-one",
                        "subject": "Mailbox delivery",
                        "received_time": received_at,
                        "verification_code": "012345",
                    }],
                    "smtp_inbound": True,
                    "refreshing": False,
                })
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(
            MailboxUrlClient(shell_url, fetcher=fetch, now_fn=lambda: now),
            now_fn=lambda: now,
        )
        state.begin_request()

        selection = state.snapshot()

        self.assertEqual(selection.code, "012345")
        self.assertTrue(any(message.explicit_code for message in selection.scan.messages))
        self.assertEqual(calls, [shell_url, cache_url])
        self.assertTrue(all(url.startswith("https://mail.example.test/") for url in calls))

    def test_pickup_shell_uses_same_origin_messages_and_detail_api(self):
        shell_url = (
            "https://mail.example.test/pickup?"
            "email=user%40example.test&key=sample%2Faccess"
        )
        messages_url = (
            "https://mail.example.test/api/messages?"
            "email=user%40example.test&key=sample%2Faccess&force=0"
        )
        detail_url = (
            "https://mail.example.test/api/message/message-new?"
            "email=user%40example.test&key=sample%2Faccess"
        )
        old_detail_url = (
            "https://mail.example.test/api/message/message-old?"
            "email=user%40example.test&key=sample%2Faccess"
        )
        calls: list[str] = []

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            if url == shell_url:
                return html_response(url, PICKUP_SHELL_HTML)
            if url == messages_url:
                return json_response(url, {
                    "success": True,
                    "messages": [{
                        "id": "message-new",
                        "from": "noreply_at_tm_openai_com_example@icloud.com",
                        "subject": "ChatGPT の一時的な認証コード",
                        "preview": "この一時検証コードを入力して続行してください: 654321",
                        "date": "2026-08-22T09:29:00+08:00",
                    }, {
                        "id": "message-old",
                        "from": "noreply_at_tm_openai_com_example@icloud.com",
                        "subject": "ChatGPT の一時的な認証コード",
                        "preview": "この一時検証コードを入力して続行してください: 123456",
                        "date": "2026-08-22T08:29:00+08:00",
                    }],
                })
            if url == detail_url:
                return json_response(url, {
                    "success": True,
                    "message": {
                        "id": "message-new",
                        "from": "noreply_at_tm_openai_com_example@icloud.com",
                        "subject": "ChatGPT の一時的な認証コード",
                        "body": "この一時検証コードを入力して続行してください: 654321",
                        "codes": ["654321"],
                        "date": "2026-08-22T09:29:00+08:00",
                    },
                })
            if url == old_detail_url:
                return json_response(url, {
                    "success": True,
                    "message": {
                        "id": "message-old",
                        "from": "noreply_at_tm_openai_com_example@icloud.com",
                        "subject": "ChatGPT の一時的な認証コード",
                        "body": "この一時検証コードを入力して続行してください: 123456",
                        "codes": ["123456"],
                        "date": "2026-08-22T08:29:00+08:00",
                    },
                })
            self.fail(f"unexpected fetch path: {url}")

        selection = MailboxUrlClient(shell_url, fetcher=fetch).latest_code()

        self.assertEqual(selection.code, "654321")
        self.assertEqual(selection.reason, "code_found")
        self.assertEqual(calls, [shell_url, messages_url, detail_url, old_detail_url])
        self.assertTrue(all(url.startswith("https://mail.example.test/") for url in calls))

    def test_pickup_shell_detects_runtime_query_params_without_detail_literal(self):
        shell_url = (
            "https://mail.example.test/pickup?"
            "email=user%40example.test&key=sample%2Faccess"
        )
        messages_url = (
            "https://mail.example.test/api/messages?"
            "email=user%40example.test&key=sample%2Faccess&force=0"
        )
        detail_url = (
            "https://mail.example.test/api/message/runtime-id?"
            "email=user%40example.test&key=sample%2Faccess"
        )
        shell = """
        <script>
          const params = new URLSearchParams(location.search);
          fetch('/api/messages', { method: 'GET', params });
        </script>
        """
        calls: list[str] = []

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            if url == shell_url:
                return html_response(url, shell)
            if url == messages_url:
                return json_response(url, {
                    "messages": [{
                        "id": "runtime-id",
                        "from": "noreply_at_tm_openai_com@icloud.com",
                        "subject": "ChatGPT の一時的な認証コード",
                        "content": "認証コード: 654321",
                        "date": "2026-08-22T09:29:00+08:00",
                    }],
                })
            if url == detail_url:
                return json_response(url, {"message": {"id": "runtime-id", "content": "654321"}})
            self.fail(f"unexpected fetch path: {url}")

        selection = MailboxUrlClient(shell_url, fetcher=fetch).latest_code()

        self.assertEqual(selection.code, "654321")
        self.assertEqual(calls, [shell_url, messages_url, detail_url])

    def test_pickup_shell_rejects_cross_origin_api_inference(self):
        shell_url = (
            "https://mail.example.test/pickup?"
            "email=user%40example.test&key=sample%2Faccess"
        )
        # A script can mention an external API, but the adapter only derives
        # fixed same-origin endpoints and must leave the page untouched.
        html = PICKUP_SHELL_HTML.replace("/api/messages?", "https://outside.example/api/messages?")
        calls: list[str] = []

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            return html_response(url, html)

        scan = MailboxUrlClient(shell_url, fetcher=fetch).scan()

        self.assertEqual(calls, [shell_url])
        self.assertFalse(any(message.code for message in scan.messages))

    def test_client_shell_requires_every_marker_and_complete_query(self):
        values = (
            (
                "https://mail.example.test/latest?email=user%40example.test&auth_code=sample",
                CLIENT_SHELL_HTML.replace('id="code-box"', 'id="other-box"'),
            ),
            (
                "https://mail.example.test/latest?email=user%40example.test",
                CLIENT_SHELL_HTML,
            ),
            (
                "https://mail.example.test/other?email=user%40example.test&auth_code=sample",
                CLIENT_SHELL_HTML,
            ),
        )
        for url, html in values:
            with self.subTest(url=url):
                calls: list[str] = []

                def fetch(candidate: str) -> MailboxResponse:
                    calls.append(candidate)
                    return html_response(candidate, html)

                scan = MailboxUrlClient(url, fetcher=fetch).scan()
                self.assertEqual(calls, [url])
                self.assertFalse(any(message.code for message in scan.messages))

    def test_client_shell_refreshes_non_smtp_cache_at_most_every_ten_seconds(self):
        clock = [0.0]
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        refresh_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&refresh=1&async=1"
        )
        calls: list[str] = []
        payload = {
            "ok": True,
            "code": "",
            "messages": [],
            "smtp_inbound": False,
            "refreshing": False,
        }

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url in {cache_url, refresh_url}:
                return json_response(url, payload)
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(
            MailboxUrlClient(shell_url, fetcher=fetch, now_fn=lambda: clock[0]),
            now_fn=lambda: clock[0],
        )
        state.snapshot()
        state.begin_request()
        state.snapshot()
        clock[0] = 5
        state.snapshot()
        clock[0] = 10
        state.snapshot()

        self.assertEqual(calls.count(refresh_url), 2)
        self.assertEqual(calls.count(cache_url), 4)

    def test_client_shell_treats_missing_smtp_mode_as_non_smtp(self):
        clock = [0.0]
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        refresh_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&refresh=1&async=1"
        )
        calls: list[str] = []
        payload = {
            "ok": True,
            "code": "",
            "messages": [],
            "refreshing": False,
        }

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url in {cache_url, refresh_url}:
                return json_response(url, payload)
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(
            MailboxUrlClient(shell_url, fetcher=fetch, now_fn=lambda: clock[0]),
            now_fn=lambda: clock[0],
        )
        state.snapshot()
        state.begin_request()
        state.snapshot()
        clock[0] = 20
        state.snapshot()

        self.assertEqual(calls.count(refresh_url), 2)
        self.assertEqual(calls.count(cache_url), 3)

    def test_client_shell_throttles_failed_refresh_requests(self):
        clock = [0.0]
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        refresh_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&refresh=1&async=1"
        )
        calls: list[str] = []
        payload = {
            "ok": True,
            "code": "",
            "messages": [],
            "smtp_inbound": False,
            "refreshing": False,
        }

        refresh_attempts = [0]

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url == cache_url:
                return json_response(url, payload)
            if url == refresh_url:
                refresh_attempts[0] += 1
                if refresh_attempts[0] == 1:
                    return json_response(url, {}, status=503)
                return json_response(url, {"ok": True, "refresh_scheduled": True})
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(
            MailboxUrlClient(shell_url, fetcher=fetch, now_fn=lambda: clock[0]),
            now_fn=lambda: clock[0],
        )
        state.snapshot()
        state.begin_request()
        first_failure = state.snapshot()
        clock[0] = 5
        between_retries = state.snapshot()
        clock[0] = 10
        second_failure = state.snapshot()

        self.assertEqual(first_failure.reason, "mailbox_refresh_request_failed")
        self.assertEqual(between_retries.reason, "mailbox_refresh_request_failed")
        self.assertEqual(first_failure.scan.diagnostics.detail_errors, 0)
        self.assertEqual(first_failure.scan.diagnostics.refresh_error_code, "mailbox_http_error")
        self.assertEqual(first_failure.scan.diagnostics.refresh_http_status, 503)
        self.assertEqual(
            between_retries.scan.diagnostics.refresh_error_code,
            "mailbox_http_error",
        )
        self.assertEqual(second_failure.scan.diagnostics.refresh_error_code, "")
        self.assertEqual(calls.count(refresh_url), 2)

    def test_client_shell_preserves_sanitized_provider_refresh_error(self):
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        refresh_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&refresh=1&async=1"
        )
        private_error = "upstream failed for private-user@example.test token=private"

        def fetch(url: str) -> MailboxResponse:
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url == cache_url:
                return json_response(url, {
                    "ok": True,
                    "messages": [],
                    "smtp_inbound": False,
                    "refreshing": False,
                    "refresh_error": {
                        "message": private_error,
                        "status_code": 502,
                    },
                })
            if url == refresh_url:
                return json_response(url, {"ok": True, "refresh_scheduled": True})
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(MailboxUrlClient(shell_url, fetcher=fetch))
        state.begin_request()
        selection = state.snapshot()

        diagnostics = selection.scan.diagnostics
        self.assertEqual(selection.reason, "mailbox_refresh_request_failed")
        self.assertEqual(diagnostics.refresh_error_code, "mailbox_provider_refresh_error")
        self.assertEqual(diagnostics.refresh_http_status, 502)
        self.assertNotIn("private-user", repr(diagnostics))
        self.assertNotIn("token=private", repr(diagnostics))

    def test_client_shell_preserves_safe_status_from_failed_refresh_ack(self):
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        refresh_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&refresh=1&async=1"
        )

        def fetch(url: str) -> MailboxResponse:
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url == cache_url:
                return json_response(url, {
                    "ok": True,
                    "messages": [],
                    "smtp_inbound": False,
                    "refreshing": False,
                })
            if url == refresh_url:
                return json_response(url, {
                    "ok": False,
                    "status_code": 429,
                    "message": "private token must not be exposed",
                })
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(MailboxUrlClient(shell_url, fetcher=fetch))
        state.begin_request()
        selection = state.snapshot()

        self.assertEqual(selection.reason, "mailbox_refresh_request_failed")
        self.assertEqual(
            selection.scan.diagnostics.refresh_error_code,
            "mailbox_provider_error",
        )
        self.assertEqual(selection.scan.diagnostics.refresh_http_status, 429)
        self.assertNotIn("private token", repr(selection.scan.diagnostics))

    def test_client_shell_deep_refresh_runs_once_after_twenty_five_seconds(self):
        clock = [0.0]
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        refresh_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&refresh=1&async=1"
        )
        deep_refresh_url = refresh_url + "&deep=1"
        calls: list[str] = []

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url == cache_url:
                return json_response(url, {
                    "ok": True,
                    "messages": [],
                    "refreshing": True,
                })
            if url == deep_refresh_url:
                return json_response(url, {"ok": True, "refresh_scheduled": True})
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(
            MailboxUrlClient(shell_url, fetcher=fetch, now_fn=lambda: clock[0]),
            now_fn=lambda: clock[0],
        )
        state.snapshot()
        state.begin_request()
        for now in (0, 24, 25, 30, 40):
            clock[0] = now
            state.snapshot()

        self.assertEqual(calls.count(deep_refresh_url), 1)
        self.assertEqual(calls.count(refresh_url), 0)

    def test_refresh_ack_code_is_ignored_until_cache_contains_it(self):
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        refresh_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&refresh=1&async=1"
        )

        def fetch(url: str) -> MailboxResponse:
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url == cache_url:
                return json_response(url, {
                    "ok": True,
                    "messages": [],
                    "smtp_inbound": False,
                    "refreshing": False,
                })
            if url == refresh_url:
                return json_response(url, {
                    "ok": True,
                    "code": "654321",
                    "messages": [{"verification_code": "654321"}],
                })
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(MailboxUrlClient(shell_url, fetcher=fetch))
        state.begin_request()
        selection = state.snapshot()

        self.assertEqual(selection.code, "")
        self.assertFalse(any(message.code for message in selection.scan.messages))

    def test_client_top_level_code_identity_ignores_unrelated_messages(self):
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        payload = {
            "ok": True,
            "code": "012345",
            "messages": [{"id": "mail-one", "subject": "Mailbox delivery"}],
            "smtp_inbound": True,
            "refreshing": False,
        }

        def fetch(url: str) -> MailboxResponse:
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url == cache_url:
                return json_response(url, payload)
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(MailboxUrlClient(shell_url, fetcher=fetch))
        baseline = state.snapshot()
        state.begin_request()
        self.assertEqual(state.snapshot().code, "")

        payload["messages"].insert(0, {"id": "unrelated-notice", "subject": "New notice"})
        unchanged = state.snapshot()
        self.assertEqual(unchanged.code, "")
        self.assertEqual(unchanged.reason, "mailbox_only_baseline_code")

        payload["code"] = "654321"
        changed = state.snapshot()
        self.assertEqual(changed.code, "654321")
        self.assertNotEqual(changed.identity, baseline.identity)

    def test_client_refresh_keeps_unchanged_explicit_code_in_baseline(self):
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        refresh_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&refresh=1&async=1"
        )
        payload = {
            "ok": True,
            "code": "",
            "messages": [{
                "subject": "Mailbox delivery",
                "verification_code": "012345",
            }],
            "smtp_inbound": False,
            "refreshing": False,
        }

        def fetch(url: str) -> MailboxResponse:
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url in {cache_url, refresh_url}:
                return json_response(url, payload)
            self.fail(f"unexpected fetch: {url}")

        state = MailboxRequestState(MailboxUrlClient(shell_url, fetcher=fetch))
        state.snapshot()
        state.begin_request()

        selection = state.snapshot()

        self.assertEqual(selection.code, "")
        self.assertEqual(selection.reason, "mailbox_only_baseline_code")

    def test_client_shell_api_errors_do_not_expose_query_credentials(self):
        shell_url = (
            "https://mail.example.test/latest?"
            "email=private-user%40example.test&auth_code=private-access"
        )

        def fetch(url: str) -> MailboxResponse:
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            return json_response(url, {}, status=503)

        with self.assertRaises(MailboxUrlError) as raised:
            MailboxUrlClient(shell_url, fetcher=fetch).scan()

        message = str(raised.exception)
        self.assertIn("HTTP 503", message)
        self.assertNotIn("private-user", message)
        self.assertNotIn("private-access", message)

    def test_client_shell_cache_provider_error_keeps_only_safe_status(self):
        shell_url = (
            "https://mail.example.test/latest?"
            "email=private-user%40example.test&auth_code=private-access"
        )

        def fetch(url: str) -> MailboxResponse:
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            return json_response(url, {
                "ok": False,
                "status_code": 401,
                "message": "private-access was rejected",
            })

        with self.assertRaises(MailboxUrlError) as raised:
            MailboxUrlClient(shell_url, fetcher=fetch).scan()

        self.assertEqual(raised.exception.code, "mailbox_provider_error")
        self.assertEqual(raised.exception.status, 401)
        self.assertNotIn("private-access", str(raised.exception))

    def test_decodes_har_shaped_data_url_and_skips_newer_notification(self):
        code_url = "https://mail.example.test/message/code"
        notice_url = "https://mail.example.test/message/notice"
        listing = {
            "messages": [
                {
                    "id": "notice",
                    "subject": "New sign-in to your OpenAI account",
                    "receivedAt": "2026-08-04 08:39:00",
                    "href": notice_url,
                },
                {
                    "id": "code",
                    "subject": "Your temporary ChatGPT login code",
                    "receivedAt": "2026-08-04 08:37:12",
                    "href": code_url,
                },
            ]
        }
        responses = {
            BASE_URL: json_response(BASE_URL, listing),
            notice_url: json_response(
                notice_url,
                {
                    "fromAddress": "noreply@openai.example",
                    "subject": "New sign-in to your OpenAI account",
                    "receivedAt": "2026-08-04 08:39:00",
                    "html": "<p>A new sign-in was detected.</p>",
                },
            ),
            code_url: json_response(
                code_url,
                {
                    "fromAddress": "noreply@openai.example",
                    "subject": "Your temporary ChatGPT login code",
                    "receivedAt": "2026-08-04 08:37:12",
                    "body": verification_body("314159"),
                    "html": "<p>OpenAI verification code: <b>314159</b></p>",
                },
            ),
        }
        client = MailboxUrlClient(BASE_URL, fetcher=responses.__getitem__)

        selection = client.latest_code()

        self.assertEqual(selection.code, "314159")
        self.assertEqual(selection.received_at, "2026-08-04 08:37:12")

    def test_contiguous_code_wins_over_date_after_chinese_otp_label(self):
        html = """
        <article class="message-item" data-message-id="latest">
          <summary>ChatGPT 临时验证码 <span>2026-08-04 21:42:17</span></summary>
          <pre>输入此临时验证码以继续：

639204

ChatGPT 团队</pre>
        </article>
        """

        messages, _detail_urls = parse_mailbox_payload(html, BASE_URL)

        self.assertEqual(extract_openai_code(html), "639204")
        self.assertTrue(any(message.code == "639204" for message in messages))
        self.assertFalse(any(message.code == "202608" for message in messages))

    def test_extracts_code_from_iframe_srcdoc_embedded_in_message_item(self):
        body = """
        <html><body>
          <h1>OpenAI</h1>
          <p>输入此临时验证码以继续：</p>
          <strong>102131</strong>
        </body></html>
        """
        html = f'''<article class="message-item" data-message-id="srcdoc-code"
            data-received-at="2026-08-05T00:00:00Z">
          <iframe class="body-frame" sandbox="allow-same-origin"
              srcdoc="{escape(body, quote=True)}"></iframe>
        </article>'''

        messages, _detail_urls = parse_mailbox_payload(html, BASE_URL)

        self.assertTrue(any(message.code == "102131" for message in messages))

    def test_spaced_code_skips_date_and_time_fragments(self):
        text = (
            "ChatGPT 临时验证码 2026-08-04 21:42:17，"
            "输入此验证码继续：6-3-9-2-0-4"
        )

        self.assertEqual(extract_openai_code(text), "639204")

    def test_rotates_cached_details_so_ninth_updated_message_is_refreshed(self):
        detail_urls = [f"https://mail.example.test/message/{index}" for index in range(9)]
        listing = {
            "messages": [
                {
                    "id": str(index),
                    "subject": "OpenAI verification code",
                    "detailUrl": detail_url,
                }
                for index, detail_url in enumerate(detail_urls)
            ]
        }
        updated = False
        calls: list[str] = []

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            if url == BASE_URL:
                return json_response(url, listing)
            index = detail_urls.index(url)
            code = "684219" if updated and index == 8 else "111111"
            received_at = "2026-08-04 21:29:40" if updated and index == 8 else "2026-08-04 21:20:00"
            return json_response(
                url,
                {
                    "id": str(index),
                    "subject": "OpenAI verification code",
                    "receivedAt": received_at,
                    "body": f"OpenAI verification code {code}",
                },
            )

        client = MailboxUrlClient(BASE_URL, fetcher=fetch)
        baseline = client.scan()
        self.assertFalse(any(message.code == "684219" for message in baseline.messages))

        updated = True
        calls.clear()
        refreshed = client.scan()

        self.assertIn(detail_urls[8], calls)
        self.assertTrue(any(message.code == "684219" for message in refreshed.messages))
        self.assertEqual(refreshed.diagnostics.detail_refreshed, 8)

    def test_rotates_all_capped_details_when_listing_exceeds_forty_links(self):
        detail_urls = [f"https://mail.example.test/message/{index}" for index in range(45)]
        listing = {
            "messages": [
                {
                    "id": str(index),
                    "subject": "OpenAI verification code",
                    "detailUrl": detail_url,
                }
                for index, detail_url in enumerate(detail_urls)
            ]
        }
        updated = False

        def fetch(url: str) -> MailboxResponse:
            if url == BASE_URL:
                return json_response(url, listing)
            index = detail_urls.index(url)
            code = "654321" if updated and index == MAX_MESSAGES - 1 else "111111"
            return json_response(
                url,
                {
                    "id": str(index),
                    "subject": "OpenAI verification code",
                    "receivedAt": "2026-08-04 21:20:00",
                    "body": f"OpenAI verification code {code}",
                },
            )

        client = MailboxUrlClient(BASE_URL, fetcher=fetch)
        first_scan = client.scan()
        self.assertEqual(first_scan.diagnostics.detail_links, MAX_MESSAGES)
        self.assertEqual(len(client._detail_cache), MAX_MESSAGES)

        updated = True
        scans = [client.scan() for _ in range(4)]

        self.assertTrue(
            any(
                message.code == "654321"
                for scan in scans
                for message in scan.messages
            )
        )
        self.assertNotIn(detail_urls[MAX_MESSAGES], client._detail_cache)

    def test_message_identity_changes_when_detail_body_changes(self):
        first_payload = {
            "id": "stable-id",
            "subject": "OpenAI verification code",
            "receivedAt": "2026-08-04 21:20:00",
            "body": "OpenAI verification code 111111 first delivery",
        }
        second_payload = {
            **first_payload,
            "body": "OpenAI verification code 111111 resent delivery",
        }

        first_messages, _first_links = parse_mailbox_payload(
            json.dumps(first_payload),
            BASE_URL,
        )
        second_messages, _second_links = parse_mailbox_payload(
            json.dumps(second_payload),
            BASE_URL,
        )

        self.assertNotEqual(first_messages[0].identity, second_messages[0].identity)

    def test_removes_detail_cache_entries_missing_from_latest_listing(self):
        active_details = [
            "https://mail.example.test/message/one",
            "https://mail.example.test/message/two",
        ]

        def fetch(url: str) -> MailboxResponse:
            if url == BASE_URL:
                return json_response(
                    url,
                    {"messages": [{"id": item.rsplit("/", 1)[-1], "detailUrl": item} for item in active_details]},
                )
            return json_response(url, {"id": url.rsplit("/", 1)[-1], "subject": "OpenAI notice"})

        client = MailboxUrlClient(BASE_URL, fetcher=fetch)
        client.scan()
        self.assertEqual(set(client._detail_cache), set(active_details))

        removed = active_details.pop()
        client.scan()

        self.assertNotIn(removed, client._detail_cache)

    def test_request_round_rejects_baseline_and_accepts_same_digits_from_new_message(self):
        clock = [2_000_000_000.0]
        payload = {
            "messages": [
                {
                    "id": "old-code",
                    "subject": "OpenAI verification code",
                    "receivedAt": clock[0] - 60,
                    "body": "OpenAI verification code 111111",
                }
            ]
        }

        def fetch(_url: str) -> MailboxResponse:
            return json_response(BASE_URL, payload)

        state = MailboxRequestState(
            MailboxUrlClient(BASE_URL, fetcher=fetch, now_fn=lambda: clock[0]),
            now_fn=lambda: clock[0],
        )
        baseline = state.snapshot()
        self.assertEqual(baseline.code, "111111")

        state.begin_request()
        state.begin_request()
        payload["messages"] = [
            {
                "id": "notice",
                "subject": "New sign-in to your OpenAI account",
                "receivedAt": clock[0] + 20,
                "body": "OpenAI sign-in notification",
            },
            {
                "id": "first-request",
                "subject": "OpenAI verification code",
                "receivedAt": clock[0] + 10,
                "body": "OpenAI verification code 222222",
            },
            payload["messages"][-1],
        ]
        first = state.snapshot()
        self.assertEqual(first.code, "222222")

        state.finish_request()
        clock[0] += 30
        state.begin_request()
        payload["messages"].insert(
            0,
            {
                "id": "retry-request",
                "subject": "OpenAI verification code",
                "receivedAt": clock[0] + 5,
                "body": "OpenAI verification code 222222",
            },
        )
        retry = state.snapshot()
        self.assertEqual(retry.code, "222222")
        self.assertNotEqual(retry.identity, first.identity)

    def test_recent_baseline_codes_are_tried_at_poll_milestones_without_reuse(self):
        clock = [2_000_000_000.0]
        payload = {
            "messages": [
                {
                    "id": "baseline-newest-without-time",
                    "fromAddress": "noreply@openai.example",
                    "subject": "Your temporary ChatGPT login code",
                    "body": "OpenAI verification code 673931",
                },
                {
                    "id": "baseline-second-without-time",
                    "fromAddress": "noreply@openai.example",
                    "subject": "Your temporary ChatGPT login code",
                    "body": "OpenAI verification code 111111",
                },
                {
                    "id": "baseline-third-without-time",
                    "fromAddress": "noreply@openai.example",
                    "subject": "Your temporary ChatGPT login code",
                    "body": "OpenAI verification code 222222",
                },
            ]
        }
        client = MailboxUrlClient(
            BASE_URL,
            fetcher=lambda _url: json_response(BASE_URL, payload),
            now_fn=lambda: clock[0],
        )
        state = MailboxRequestState(client, now_fn=lambda: clock[0])
        baseline = state.snapshot()
        self.assertEqual(baseline.code, "673931")

        state.configure_request(max_poll_attempts=30)
        state.begin_request()
        for attempt in range(1, 10):
            with self.subTest(attempt=attempt):
                self.assertEqual(state.snapshot().code, "")

        fallback = state.snapshot()
        self.assertEqual(fallback.code, "673931")
        self.assertEqual(fallback.reason, "mailbox_baseline_code_fallback")
        self.assertEqual(state.baseline_fallback_poll, 10)
        self.assertIsNone(state.baseline_fallback_age_seconds)

        expected = ("111111", "222222")
        for expected_code in expected:
            state.finish_request()
            state.begin_request()
            for _attempt in range(9):
                self.assertEqual(state.snapshot().code, "")
            self.assertEqual(state.snapshot().code, expected_code)

        self.assertEqual(state.baseline_fallback_attempts, 3)
        self.assertEqual(state.final_baseline_fallback().code, "")

    def test_explicit_code_is_trusted_for_baseline_fallback_and_changes_identity(self):
        clock = [2_000_000_000.0]
        shell_url = (
            "https://mail.example.test/latest?"
            "email=user%40example.test&auth_code=sample-access"
        )
        cache_url = (
            "https://mail.example.test/mail-api/sample-access/user%40example.test?"
            "folder=inbox&cache_first=1"
        )
        payload = {
            "ok": True,
            "messages": [{
                "id": "provider-message",
                "subject": "Mailbox delivery",
                "received_time": clock[0] - 30,
                "verification_code": "012345",
            }],
            "smtp_inbound": True,
        }

        def fetch(url: str) -> MailboxResponse:
            if url == shell_url:
                return html_response(url, CLIENT_SHELL_HTML)
            if url == cache_url:
                return json_response(url, payload)
            self.fail(f"unexpected fetch: {url}")

        client = MailboxUrlClient(
            shell_url,
            fetcher=fetch,
            now_fn=lambda: clock[0],
        )
        state = MailboxRequestState(client, now_fn=lambda: clock[0])
        baseline = state.snapshot()
        state.configure_request(max_poll_attempts=10)
        state.begin_request()

        for _attempt in range(9):
            self.assertEqual(state.snapshot().code, "")
        fallback = state.snapshot()

        self.assertEqual(fallback.code, "012345")
        self.assertEqual(fallback.reason, "mailbox_baseline_code_fallback")

        payload["messages"][0]["verification_code"] = "654321"
        changed = client.latest_code()
        self.assertEqual(changed.code, "654321")
        self.assertNotEqual(changed.identity, baseline.identity)

    def test_baseline_fallback_rejects_reliably_old_code_but_accepts_missing_time(self):
        clock = [2_000_000_000.0]
        payload = {
            "messages": [
                {
                    "id": "older-than-ten-minutes",
                    "fromAddress": "noreply@openai.example",
                    "subject": "OpenAI verification code",
                    "receivedAt": clock[0] - 601,
                    "body": "OpenAI verification code 111111",
                },
                {
                    "id": "latest-without-time",
                    "fromAddress": "noreply@openai.example",
                    "subject": "OpenAI verification code",
                    "body": "OpenAI verification code 222222",
                },
            ]
        }
        client = MailboxUrlClient(
            BASE_URL,
            fetcher=lambda _url: json_response(BASE_URL, payload),
            now_fn=lambda: clock[0],
        )
        state = MailboxRequestState(client, now_fn=lambda: clock[0])
        state.snapshot()
        state.configure_request(max_poll_attempts=30)
        state.begin_request()

        for _attempt in range(9):
            self.assertEqual(state.snapshot().code, "")

        fallback = state.snapshot()
        self.assertEqual(fallback.code, "222222")
        self.assertIsNone(state.baseline_fallback_age_seconds)

    def test_baseline_fallback_checks_only_tenth_twentieth_and_thirtieth_polls(self):
        calls = []

        class RecordingState(MailboxRequestState):
            def _baseline_fallback(self, scan, *, reason):
                del scan, reason
                calls.append(self.poll_attempt)
                return None

        state = RecordingState(
            MailboxUrlClient(
                BASE_URL,
                fetcher=lambda _url: json_response(BASE_URL, {"messages": []}),
            )
        )
        state.snapshot()
        state.configure_request(max_poll_attempts=30)
        state.begin_request()

        for _attempt in range(30):
            self.assertEqual(state.snapshot().code, "")

        self.assertEqual(calls, [10, 20, 30])

    def test_baseline_fallback_rejects_non_openai_messages(self):
        clock = [2_000_000_000.0]
        payload = {
            "messages": [
                {
                    "id": "not-openai",
                    "fromAddress": "noreply@example.test",
                    "subject": "Your security verification code",
                    "receivedAt": clock[0] - 30,
                    "body": "Your verification code is 222222",
                },
            ]
        }
        client = MailboxUrlClient(
            BASE_URL,
            fetcher=lambda _url: json_response(BASE_URL, payload),
            now_fn=lambda: clock[0],
        )
        state = MailboxRequestState(client, now_fn=lambda: clock[0])
        state.snapshot()
        state.configure_request(max_poll_attempts=3)
        state.begin_request()
        state.snapshot()

        selection = state.snapshot()

        self.assertEqual(selection.code, "")
        self.assertEqual(selection.reason, "mailbox_messages_without_openai_otp")
        self.assertEqual(state.baseline_fallback_attempts, 0)

    def test_new_code_is_preferred_to_baseline_fallback(self):
        clock = [2_000_000_000.0]
        old_message = {
            "id": "recent-baseline",
            "fromAddress": "noreply@openai.example",
            "subject": "OpenAI verification code",
            "receivedAt": clock[0] - 50,
            "body": "OpenAI verification code 111111",
        }
        payload = {"messages": [old_message]}
        client = MailboxUrlClient(
            BASE_URL,
            fetcher=lambda _url: json_response(BASE_URL, payload),
            now_fn=lambda: clock[0],
        )
        state = MailboxRequestState(client, now_fn=lambda: clock[0])
        state.snapshot()
        state.configure_request(max_poll_attempts=3)
        state.begin_request()
        state.snapshot()
        payload["messages"].insert(
            0,
            {
                "id": "new-delivery",
                "fromAddress": "noreply@openai.example",
                "subject": "OpenAI verification code",
                "receivedAt": clock[0],
                "body": "OpenAI verification code 333333",
            },
        )

        selection = state.snapshot()

        self.assertEqual(selection.code, "333333")
        self.assertEqual(selection.reason, "code_found")
        self.assertEqual(state.baseline_fallback_attempts, 0)

    def test_embedded_title_timestamp_selects_the_latest_code(self):
        payload = {
            "messages": [
                {
                    "id": "older",
                    "fromAddress": "noreply@openai.example",
                    "subject": "OpenAI code received 2026-08-05 00:01:00",
                    "body": "OpenAI verification code 483921",
                },
                {
                    "id": "newer",
                    "fromAddress": "noreply@openai.example",
                    "subject": "OpenAI code received 2026-08-05 00:03:00",
                    "body": "OpenAI verification code 682672",
                },
            ]
        }
        client = MailboxUrlClient(BASE_URL, fetcher=lambda _url: json_response(BASE_URL, payload))

        selection = client.latest_code()

        self.assertEqual(selection.code, "682672")
        self.assertIsNotNone(parse_received_timestamp("received 2026-08-05 00:03:00 CST"))

    def test_request_cutoff_rejects_unseen_but_stale_message(self):
        now = 2_000_000_000.0
        payload = {
            "messages": [
                {
                    "id": "stale-unseen",
                    "subject": "OpenAI verification code",
                    "receivedAt": now - 121,
                    "body": "OpenAI verification code 271828",
                }
            ]
        }
        client = MailboxUrlClient(BASE_URL, fetcher=lambda _url: json_response(BASE_URL, payload), now_fn=lambda: now)
        scan = client.scan()

        selection = select_latest_code(scan, requested_at=now)

        self.assertEqual(selection.code, "")

    def test_missing_id_and_time_uses_content_change_as_new_identity(self):
        payload = {
            "subject": "OpenAI verification code",
            "body": "OpenAI verification code 123456",
        }

        def fetch(_url: str) -> MailboxResponse:
            return json_response(BASE_URL, payload)

        state = MailboxRequestState(MailboxUrlClient(BASE_URL, fetcher=fetch))
        baseline = state.snapshot()
        self.assertEqual(baseline.code, "123456")

        state.begin_request()
        self.assertEqual(state.snapshot().code, "")

        payload["body"] = "OpenAI verification code 654321"
        changed = state.snapshot()
        self.assertEqual(changed.code, "654321")
        self.assertNotEqual(changed.identity, baseline.identity)

    def test_embedded_json_and_rest_detail_inference_are_provider_neutral(self):
        html = """
        <main>
          <article class="message-item" data-message-id="42">
            <span>OpenAI verification message</span>
          </article>
          <script>const detailPath = `/message/${messageId}/${token}/${mailbox}`;</script>
          <script type="application/json">
            {"messages":[{"id":"43","subject":"OpenAI verification code","body":"OpenAI verification code 161803"}]}
          </script>
        </main>
        """

        messages, detail_urls = parse_mailbox_payload(html, BASE_URL)

        self.assertTrue(any(message.code == "161803" for message in messages))
        self.assertIn(
            "https://mail.example.test/message/42/operator-token/user@example.test",
            detail_urls,
        )

    def test_cross_origin_and_action_links_are_not_followed(self):
        listing = {
            "messages": [
                {"id": "one", "subject": "OpenAI verification code", "href": "https://other.test/message/one"},
                {"id": "two", "subject": "OpenAI verification code", "href": "/message/two/delete"},
            ]
        }
        calls = []

        def fetch(url: str) -> MailboxResponse:
            calls.append(url)
            return json_response(url, listing)

        client = MailboxUrlClient(BASE_URL, fetcher=fetch)
        client.scan()

        self.assertEqual(calls, [BASE_URL])

    def test_deep_json_fails_with_bounded_provider_error(self):
        payload: dict[str, object] = {}
        cursor = payload
        for _depth in range(80):
            child: dict[str, object] = {}
            cursor["nested"] = child
            cursor = child

        with self.assertRaises(MailboxUrlError) as raised:
            parse_mailbox_payload(json.dumps(payload), BASE_URL)

        self.assertEqual(
            raised.exception.code,
            "mailbox_provider_response_too_complex",
        )
        self.assertNotIsInstance(raised.exception, RecursionError)

    def test_limits_messages_and_sanitizes_network_errors(self):
        payload = {
            "messages": [
                {"id": str(index), "subject": "OpenAI verification code", "body": f"OpenAI code {index:06d}"}
                for index in range(MAX_MESSAGES + 10)
            ]
        }
        client = MailboxUrlClient(BASE_URL, fetcher=lambda _url: json_response(BASE_URL, payload))
        self.assertLessEqual(len(client.scan().messages), MAX_MESSAGES)

        failing = MailboxUrlClient(
            BASE_URL,
            fetcher=lambda _url: json_response(BASE_URL, {}, status=503),
        )
        with self.assertRaises(MailboxUrlError) as raised:
            failing.scan()
        self.assertIn("HTTP 503", str(raised.exception))
        self.assertNotIn("operator-token", str(raised.exception))
        self.assertNotIn("user@example.test", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
