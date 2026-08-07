from __future__ import annotations

import io
import unittest
import urllib.error

from mac_overrides.online_mailbox_runtime import (
    OnlineMailboxClient,
    OnlineMailboxError,
    UrllibOnlineMailboxTransport,
    manager_url,
    normalize_base_url,
)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post_json(self, url, payload, *, token, timeout):
        self.calls.append((url, payload, token, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class RaisingOpener:
    def __init__(self, error):
        self.error = error

    def open(self, _request, timeout):
        raise self.error


class OnlineMailboxRuntimeTests(unittest.TestCase):
    def test_client_normalizes_payload_and_validates_summary(self):
        transport = FakeTransport([{
            "ok": True,
            "batch_id": "batch-1",
            "submitted": 1,
            "created": 1,
            "updated": 0,
            "duplicates": 0,
            "rejected": 0,
        }])
        client = OnlineMailboxClient(
            "https://example.test/root/",
            "api-secret",
            transport=transport,
        )

        result = client.upload(
            [{"email": "User@Example.COM", "mailbox_url": "https://mail.example.test/inbox/private"}],
            batch_id="batch-1",
        )

        self.assertEqual(result["created"], 1)
        self.assertEqual(result["manager_url"], "https://example.test/root/mailboxes/")
        url, payload, token, timeout = transport.calls[0]
        self.assertEqual(url, "https://example.test/root/api/mailboxes/import")
        self.assertEqual(payload["items"][0]["email"], "user@example.com")
        self.assertEqual(token, "api-secret")
        self.assertEqual(timeout, 30.0)

    def test_client_retries_retryable_failure_with_same_batch(self):
        failure = OnlineMailboxError(
            "连接失败",
            code="online_mailbox_network_error",
            retryable=True,
        )
        transport = FakeTransport([
            failure,
            {
                "ok": True,
                "batch_id": "batch-retry",
                "submitted": 1,
                "created": 0,
                "updated": 0,
                "duplicates": 1,
                "rejected": 0,
            },
        ])
        client = OnlineMailboxClient("https://example.test", "token", transport=transport)

        result = client.upload(
            [{"email": "user@example.com", "mailbox_url": "https://mail.example.test/inbox"}],
            batch_id="batch-retry",
        )

        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(transport.calls[0][1], transport.calls[1][1])

    def test_missing_token_and_invalid_items_fail_before_transport(self):
        with self.assertRaisesRegex(OnlineMailboxError, "API 密钥"):
            OnlineMailboxClient("https://example.test", "")

        client = OnlineMailboxClient("https://example.test", "token", transport=FakeTransport([]))
        with self.assertRaisesRegex(OnlineMailboxError, "无效邮箱"):
            client.upload([{"email": "bad", "mailbox_url": "javascript:alert(1)"}])

    def test_http_error_never_includes_provider_body_or_credentials(self):
        secret_url = "https://mail.example.test/inbox/private-token"
        secret_token = "bearer-private-token"
        error = urllib.error.HTTPError(
            "https://example.test/import",
            401,
            "unauthorized",
            {},
            io.BytesIO(f"{secret_url} {secret_token}".encode()),
        )
        transport = UrllibOnlineMailboxTransport()
        transport._opener = RaisingOpener(error)

        with self.assertRaises(OnlineMailboxError) as captured:
            transport.post_json(
                "https://example.test/import",
                {"items": []},
                token=secret_token,
                timeout=1,
            )

        message = str(captured.exception)
        self.assertNotIn(secret_url, message)
        self.assertNotIn(secret_token, message)
        self.assertEqual(captured.exception.provider_status, 401)

    def test_base_url_discards_query_and_fragment(self):
        self.assertEqual(
            normalize_base_url("https://example.test/token-tool/?secret=value#part"),
            "https://example.test/token-tool",
        )
        self.assertEqual(
            manager_url("https://example.test/token-tool"),
            "https://example.test/token-tool/mailboxes/",
        )


if __name__ == "__main__":
    unittest.main()
