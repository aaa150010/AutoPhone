from __future__ import annotations

import json
from types import SimpleNamespace
import unittest

from mac_overrides.free_mailbox_otp import MailboxUrlOtpProvider
from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.mailbox_otp_service import (
    MailboxHttpTransport,
    MailboxOtpError,
    MailboxOtpService,
    normalize_network_policy,
    runtime_diagnostic,
)
from mac_overrides.mailbox_url_runtime import MailboxResponse, MailboxUrlError, parse_received_timestamp


class _Clock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def monotonic(self) -> float:
        return self.value

    def time(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += max(0.01, float(seconds))


class _Response:
    def __init__(
        self,
        status: int = 200,
        body: bytes = b"[]",
        *,
        url: str = "https://mail.example.test/inbox",
        headers=None,
    ) -> None:
        self.status_code = status
        self.content = body
        self.url = url
        self.headers = headers or {"content-type": "application/json"}


class _Session:
    def __init__(self, outcomes) -> None:
        self.outcomes = list(outcomes)
        self.calls = []
        self.trust_env = True
        self.closed = False

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def close(self) -> None:
        self.closed = True


class SSLError(RuntimeError):
    pass


class MailboxOtpServiceTests(unittest.TestCase):
    def test_explicit_proxy_supports_all_configured_schemes_and_disables_environment(self):
        for proxy in (
            "http://127.0.0.1:7897",
            "https://proxy.example.test:8443",
            "socks5://proxy.example.test:1080",
            "socks5h://proxy.example.test:1080",
        ):
            with self.subTest(proxy=proxy):
                session = _Session([_Response()])
                transport = MailboxHttpTransport(
                    normalize_network_policy(mode="local_proxy", proxy_url=proxy, retries=0),
                    session=session,
                )
                response = transport.fetch("https://mail.example.test/inbox")
                self.assertEqual(response.status, 200)
                self.assertFalse(session.trust_env)
                self.assertEqual(session.calls[0][1]["proxies"], {"http": proxy, "https": proxy})
                transport.close()
                self.assertTrue(session.closed)

    def test_direct_mode_never_sends_a_proxy_argument(self):
        session = _Session([_Response()])
        transport = MailboxHttpTransport(
            normalize_network_policy(
                mode="direct",
                proxy_url="socks5://registration-proxy.example.test:1080",
                retries=0,
            ),
            session=session,
        )
        transport.fetch("https://mail.example.test/inbox")
        self.assertNotIn("proxies", session.calls[0][1])

    def test_ssl_and_retryable_http_failures_retry_then_recover(self):
        events = []
        session = _Session([SSLError("private tls detail"), _Response(503), _Response(200)])
        transport = MailboxHttpTransport(
            normalize_network_policy(
                mode="local_proxy",
                proxy_url="http://127.0.0.1:7897",
                retries=3,
                backoff_seconds=0,
            ),
            session=session,
            sleep_fn=lambda _seconds: None,
            event_fn=events.append,
        )
        self.assertEqual(transport.fetch("https://mail.example.test/inbox").status, 200)
        self.assertEqual(len(session.calls), 3)
        self.assertEqual([event["outcome"] for event in events], ["retry", "retry", "success"])
        self.assertNotIn("private tls detail", str(events))

    def test_non_retryable_http_status_returns_without_hidden_retry(self):
        session = _Session([_Response(403)])
        transport = MailboxHttpTransport(
            normalize_network_policy(mode="local_proxy", proxy_url="http://127.0.0.1:7897", retries=3),
            session=session,
        )
        self.assertEqual(transport.fetch("https://mail.example.test/inbox").status, 403)
        self.assertEqual(len(session.calls), 1)

    def test_cross_origin_redirect_is_rejected_before_follow_up_request(self):
        session = _Session([_Response(302, headers={"location": "https://collector.example.test/private"})])
        transport = MailboxHttpTransport(
            normalize_network_policy(mode="direct", retries=3),
            session=session,
        )
        with self.assertRaises(MailboxOtpError) as raised:
            transport.fetch("https://mail.example.test/inbox")
        self.assertEqual(raised.exception.code, "mailbox_cross_origin_redirect")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(len(session.calls), 1)

    def test_same_origin_redirect_is_followed_with_tls_and_body_limit(self):
        session = _Session([
            _Response(302, headers={"location": "/inbox/latest"}),
            _Response(200, b"[]", url="https://mail.example.test/inbox/latest"),
        ])
        transport = MailboxHttpTransport(
            normalize_network_policy(mode="direct", retries=0),
            session=session,
        )
        response = transport.fetch("https://mail.example.test/inbox")
        self.assertEqual(response.status, 200)
        self.assertEqual([call[0] for call in session.calls], [
            "https://mail.example.test/inbox",
            "https://mail.example.test/inbox/latest",
        ])
        self.assertTrue(all(call[1]["verify"] for call in session.calls))
        self.assertTrue(all(call[1]["allow_redirects"] is False for call in session.calls))

    def test_oversized_response_is_rejected(self):
        session = _Session([_Response(
            200,
            headers={"content-type": "application/json", "content-length": str(2 * 1024 * 1024 + 1)},
        )])
        transport = MailboxHttpTransport(
            normalize_network_policy(mode="direct", retries=0),
            session=session,
        )
        with self.assertRaises(MailboxOtpError) as raised:
            transport.fetch("https://mail.example.test/inbox")
        self.assertEqual(raised.exception.code, "mailbox_response_too_large")

    def test_non_retryable_baseline_failure_stops_before_sending_flow_continues(self):
        session = _Session([_Response(403)])
        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            network_policy=normalize_network_policy(
                mode="local_proxy",
                proxy_url="http://127.0.0.1:7897",
                retries=3,
            ),
            session=session,
        )
        with self.assertRaises(MailboxOtpError) as raised:
            service.prepare()
        self.assertEqual(raised.exception.code, "mailbox_http_error")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(len(session.calls), 1)
        service.close()

    def test_exhausted_network_failure_does_not_repeat_for_entire_otp_window(self):
        clock = _Clock()
        calls = 0

        def fetch(url: str) -> MailboxResponse:
            nonlocal calls
            calls += 1
            if calls == 1:
                return MailboxResponse(url, b"[]", "application/json", 200)
            raise MailboxUrlError("mailbox_ssl_error", "邮箱取件服务 TLS/SSL 连接失败")

        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=90,
            poll_interval_seconds=1,
            fetcher=fetch,
            sleep_fn=clock.sleep,
            now_fn=clock.time,
            monotonic_fn=clock.monotonic,
        )
        service.prepare()
        with self.assertRaises(MailboxOtpError) as raised:
            service.wait_code()
        self.assertEqual(raised.exception.code, "mailbox_ssl_error")
        self.assertTrue(raised.exception.retryable)
        self.assertEqual(calls, 2)
        service.close()

    def test_shared_service_extracts_chinese_six_digit_code(self):
        payloads = iter((
            MailboxResponse(
                "https://mail.example.test/inbox",
                b'{"messages": []}',
                "application/json",
                200,
            ),
            MailboxResponse(
                "https://mail.example.test/inbox",
                '{"messages":[{"id":"new","sender":"noreply@openai.com","subject":"OpenAI 验证码","body":"验证码 654321"}]}'.encode(),
                "application/json",
                200,
            ),
        ))
        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=10,
            fetcher=lambda _url: next(payloads),
        )
        service.prepare()
        self.assertEqual(service.wait_code(), "654321")
        self.assertEqual(service.diagnostic()["openai_messages"], 1)
        service.close()

    def test_timing_callback_reports_mailbox_milestones_without_code_contents(self):
        events = []
        payloads = iter((
            MailboxResponse(
                "https://mail.example.test/inbox",
                b'{"messages": []}',
                "application/json",
                200,
            ),
            MailboxResponse(
                "https://mail.example.test/inbox",
                b'{"messages":[{"id":"new","sender":"noreply@openai.com","subject":"OpenAI verification code","body":"654321"}]}',
                "application/json",
                200,
            ),
        ))
        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=10,
            fetcher=lambda _url: next(payloads),
            timing_fn=lambda stage, code, duration, outcome: events.append(
                (stage, code, duration, outcome)
            ),
        )
        service.prepare("free_email_otp_wait")
        self.assertEqual(service.wait_code(stage_code="free_email_otp_wait"), "654321")
        codes = [event[1] for event in events]
        self.assertIn("mailbox_baseline", codes)
        self.assertIn("mailbox_poll_scan", codes)
        self.assertIn("mailbox_first_listing", codes)
        self.assertIn("mailbox_first_openai", codes)
        self.assertIn("mailbox_first_code", codes)
        self.assertTrue(all(event[0] == "free_email_otp_wait" for event in events))
        self.assertTrue(all(isinstance(event[2], int) and event[2] >= 0 for event in events))
        self.assertNotIn("654321", str(events))
        service.close()

    def test_shared_service_extracts_latest_japanese_pickup_code(self):
        old_payload = {
            "data": {
                "messages": [{
                    "ID": "jp-old",
                    "FROM": "noreply_at_tm_openai_com@icloud.com",
                    "TITLE": "ChatGPT の一時的な認証コード",
                    "CONTENT": "この一時検証コードを入力して続行してください: 123456",
                    "SENT_AT": "2026-08-20T07:43:00+08:00",
                }],
            },
        }
        new_payload = {
            "data": {
                "messages": [{
                    "ID": "jp-new",
                    "FROM": "noreply_at_tm_openai_com@icloud.com",
                    "TITLE": "ChatGPT の一時的な認証コード",
                    "CONTENT": "この一時検証コードを入力して続行してください: 654321",
                    "SENT_AT": "2026-08-20T09:29:00+08:00",
                }],
            },
        }
        payloads = iter((old_payload, new_payload))
        request_now = float(parse_received_timestamp("2026-08-20T09:30:00+08:00") or 0)
        service = MailboxOtpService(
            "https://mail.example.test/pickup",
            timeout_seconds=10,
            fetcher=lambda url: MailboxResponse(url, json.dumps(next(payloads), ensure_ascii=False).encode("utf-8"), "application/json", 200),
            now_fn=lambda: request_now,
        )
        service.prepare()
        self.assertEqual(service.wait_code(), "654321")
        diagnostic = service.diagnostic()
        self.assertEqual(diagnostic["openai_messages"], 1)
        self.assertEqual(diagnostic["code_messages"], 1)
        self.assertEqual(diagnostic["body_mapped_messages"], 1)
        self.assertEqual(diagnostic["received_mapped_messages"], 1)
        self.assertNotIn("654321", str(diagnostic))
        service.close()

    def test_same_code_is_not_reused_for_a_second_request(self):
        clock = _Clock()
        calls = 0

        def fetch(url: str) -> MailboxResponse:
            nonlocal calls
            calls += 1
            body = b'{"messages": []}' if calls == 1 else b'{"messages":[{"id":"same","sender":"openai","subject":"verification code 123456"}]}'
            return MailboxResponse(url, body, "application/json", 200)

        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=5,
            poll_interval_seconds=1,
            fetcher=fetch,
            sleep_fn=clock.sleep,
            now_fn=clock.time,
            monotonic_fn=clock.monotonic,
        )
        service.prepare()
        self.assertEqual(service.wait_code(), "123456")
        service.mark_sent()
        with self.assertRaises(MailboxOtpError) as raised:
            service.wait_code()
        self.assertEqual(raised.exception.code, "mailbox_code_timeout")

    def test_same_code_from_a_new_message_identity_is_allowed(self):
        payloads = iter((
            b'{"messages": []}',
            b'{"messages":[{"id":"message-one","sender":"openai","subject":"verification code 241949"}]}',
            b'{"messages":[{"id":"message-two","sender":"openai","subject":"verification code 241949"}]}',
        ))
        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=5,
            poll_interval_seconds=1,
            fetcher=lambda url: MailboxResponse(url, next(payloads), "application/json", 200),
        )
        service.prepare("registration_otp")
        self.assertEqual(service.wait_code(stage_code="registration_otp"), "241949")
        service.mark_sent("registration_otp")
        self.assertEqual(service.wait_code(stage_code="registration_otp"), "241949")
        service.close()

    def test_prepare_can_capture_baseline_without_notifying_public_stage(self):
        stage_calls = []
        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            task_id="free-task",
            stage_fn=lambda task_id, stage: stage_calls.append((task_id, stage)),
            fetcher=lambda url: MailboxResponse(url, b'{"messages":[]}', "application/json", 200),
        )

        service.prepare("free_email_otp_wait", notify_stage=False)
        self.assertEqual(service.current_stage, "free_email_otp_wait")
        self.assertEqual(stage_calls, [])
        service.prepare("free_email_otp_wait", notify_stage=True)
        self.assertEqual(stage_calls, [("free-task", "free_email_otp_wait")])
        service.close()

    def test_twofa_stage_never_returns_a_baseline_code(self):
        clock = _Clock()
        payload = json.dumps({
            "messages": [{
                "id": "registration-code",
                "sender": "noreply@openai.com",
                "subject": "OpenAI verification code",
                "receivedAt": 999.0,
                "body": "OpenAI verification code 123456",
            }],
        }).encode()
        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=5,
            poll_interval_seconds=1,
            fetcher=lambda url: MailboxResponse(url, payload, "application/json", 200),
            sleep_fn=clock.sleep,
            now_fn=clock.time,
            monotonic_fn=clock.monotonic,
        )
        service.prepare("free_twofa_enroll", force_snapshot=True)
        with self.assertRaises(MailboxOtpError) as raised:
            service.wait_code(stage_code="free_twofa_enroll")
        self.assertEqual(raised.exception.code, "mailbox_code_timeout")
        self.assertEqual(service.diagnostic()["baseline_fallback_attempts"], 0)
        service.close()

    def test_wait_uses_one_resend_without_replacing_original_baseline(self):
        clock = _Clock()
        resent = []

        def fetch(url: str) -> MailboxResponse:
            body = (
                b'{"messages":[]}'
                if not resent
                else b'{"messages":[{"id":"after-resend","sender":"openai","subject":"verification code 654321"}]}'
            )
            return MailboxResponse(url, body, "application/json", 200)

        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=10,
            poll_interval_seconds=1,
            fetcher=fetch,
            sleep_fn=clock.sleep,
            now_fn=clock.time,
            monotonic_fn=clock.monotonic,
        )
        service.prepare()
        code = service.wait_code(
            resend_fn=lambda: resent.append(clock.time()),
            resend_after_seconds=3,
        )
        self.assertEqual(code, "654321")
        self.assertEqual(len(resent), 1)
        self.assertIn("654321", service.used_codes)

    def test_resend_preserves_any_structured_pipeline_failure(self):
        clock = _Clock()
        service = MailboxOtpService(
            "https://mail.example.test/inbox",
            timeout_seconds=5,
            poll_interval_seconds=1,
            fetcher=lambda url: MailboxResponse(url, b'{"messages":[]}', "application/json", 200),
            sleep_fn=clock.sleep,
            now_fn=clock.time,
            monotonic_fn=clock.monotonic,
        )
        service.prepare()

        def fail_resend():
            raise FreeRegisterError(
                "free_oauth_security_challenge", "等待 Free OAuth 安全验证",
                "检测到安全验证页面", retryable=False,
                error_code="free_oauth_security_challenge",
            )

        with self.assertRaises(FreeRegisterError) as raised:
            service.wait_code(resend_fn=fail_resend, resend_after_seconds=0)
        self.assertEqual(raised.exception.node_code, "free_oauth_security_challenge")

    def test_free_provider_maps_mailbox_ssl_failure_to_mailbox_stage(self):
        clock = _Clock()

        def failed_fetch(_url: str) -> MailboxResponse:
            raise MailboxUrlError("mailbox_ssl_error", "邮箱取件服务 TLS/SSL 连接失败")

        provider = MailboxUrlOtpProvider(
            "https://mail.example.test/inbox?token=private-mail-token",
            "http://user:pass@registration-proxy.example.test:8000",
            timeout=5,
            fetcher=failed_fetch,
            sleep_fn=clock.sleep,
            now_fn=clock.time,
            monotonic_fn=clock.monotonic,
        )
        provider.prepare()
        with self.assertRaises(FreeRegisterError) as raised:
            provider.wait_code("mailbox@example.test")
        self.assertEqual(raised.exception.node_code, "free_email_otp_wait")
        self.assertEqual(raised.exception.error_code, "free_email_otp_wait_mailbox_ssl_error")
        self.assertNotIn("registration-proxy", str(raised.exception))
        self.assertNotIn("private-mail-token", str(raised.exception))

    def test_regular_runtime_provider_uses_the_same_shared_service(self):
        provider = SimpleNamespace(
            mailbox_url="https://mail.example.test/inbox",
            proxy="http://127.0.0.1:7897",
            timeout=90,
            timeout_seconds=15,
        )
        diagnostic = runtime_diagnostic(provider)
        service = provider._gptphone_mailbox_otp_service
        self.assertIsInstance(service, MailboxOtpService)
        self.assertEqual(service.policy.effective_proxy, "http://127.0.0.1:7897")
        self.assertEqual(diagnostic["request_attempts"], 0)
        service.close()


if __name__ == "__main__":
    unittest.main()
