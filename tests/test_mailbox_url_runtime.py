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


def json_response(url: str, value, status: int = 200) -> MailboxResponse:
    return MailboxResponse(
        url=url,
        body=json.dumps(value).encode("utf-8"),
        content_type="application/json; charset=utf-8",
        status=status,
    )


def verification_body(code: str) -> str:
    html = f"<html><body><h1>OpenAI</h1><p>Your verification code is <b>{code}</b></p></body></html>"
    payload = base64.b64encode(html.encode("utf-8")).decode("ascii")
    return f"data:text/html;charset=utf-8;base64,{payload}"


class MailboxUrlRuntimeTests(unittest.TestCase):
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

    def test_baseline_code_is_used_at_twentieth_of_thirty_polls_and_again_at_timeout(self):
        clock = [2_000_000_000.0]
        payload = {
            "messages": [
                {
                    "id": "baseline-without-time",
                    "fromAddress": "noreply@openai.example",
                    "subject": "Your temporary ChatGPT login code",
                    "body": "OpenAI verification code 673931",
                }
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
        for attempt in range(1, 20):
            with self.subTest(attempt=attempt):
                self.assertEqual(state.snapshot().code, "")

        fallback = state.snapshot()
        self.assertEqual(fallback.code, "673931")
        self.assertEqual(fallback.reason, "mailbox_baseline_code_fallback")
        self.assertEqual(state.baseline_fallback_poll, 20)
        self.assertIsNone(state.baseline_fallback_age_seconds)

        self.assertEqual(state.snapshot().code, "")
        state.finish_request()
        state.begin_request()
        for _attempt in range(30):
            self.assertEqual(state.snapshot().code, "")

        final_fallback = state.final_baseline_fallback()
        self.assertEqual(final_fallback.code, "673931")
        self.assertEqual(final_fallback.reason, "mailbox_final_baseline_code_fallback")
        self.assertEqual(state.baseline_fallback_attempts, 2)
        self.assertEqual(state.final_baseline_fallback().code, "")

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
