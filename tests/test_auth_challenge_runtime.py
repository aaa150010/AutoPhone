from __future__ import annotations

from collections import deque
from types import SimpleNamespace
import unittest

from mac_overrides.auth_challenge_runtime import (
    AuthChallengeError,
    bind_transport_context,
    classify_challenge,
    clear_transport_context,
    continue_if_needed,
    resolve_auth_challenges,
)


def response(page_type: str, path: str = "") -> dict:
    value = {"_status": 200, "page": {"type": page_type}}
    if path:
        value["continue_url"] = f"https://auth.openai.com{path}"
    return value


class FakeProvider:
    def __init__(self, codes):
        self.codes = deque(codes)
        self.calls = []

    def acquire_login_slot(self):
        self.calls.append("acquire")

    def mark_sent(self):
        self.calls.append("sent")

    def wait_code(self, email):
        self.calls.append(("wait", email))
        return self.codes.popleft()

    def mark_verified(self):
        self.calls.append("verified")


class FakeTransport:
    def __init__(self, transitions):
        self.transitions = deque(transitions)
        self.calls = []

    def verify_password(self, password):
        self.calls.append(("password", password))
        return self.transitions.popleft()

    def send_email_otp(self, continue_url):
        self.calls.append(("send_email", continue_url))
        return {"_status": 200}

    def verify_email_otp(self, code):
        self.calls.append(("email_otp", code))
        return self.transitions.popleft()

    def send_mfa_otp(self, continue_url):
        self.calls.append(("send_mfa", continue_url))
        return {"_status": 200}

    def verify_mfa_otp(self, code):
        self.calls.append(("totp", code))
        return self.transitions.popleft()


class AuthChallengeRuntimeTests(unittest.TestCase):
    def test_classifies_challenges_without_exposing_query_values(self):
        snapshot = classify_challenge(
            {
                "_status": 200,
                "page": {"type": "password-required"},
                "continue_url": "https://auth.openai.com/log-in/password?token=private",
            }
        )
        self.assertEqual(snapshot.kind, "password")
        self.assertEqual(snapshot.page_type, "password_required")
        self.assertEqual(snapshot.continue_path, "/log-in/password")

    def test_empty_page_type_is_not_classified_as_complete(self):
        snapshot = classify_challenge({"_status": 200})

        self.assertEqual(snapshot.kind, "unsupported")
        self.assertEqual(snapshot.page_type, "")

    def test_continue_path_matching_requires_a_complete_path_segment(self):
        recognized = classify_challenge(
            {
                "_status": 200,
                "continue_url": "https://auth.openai.com/mfa-challenge/factor",
            }
        )
        unknown = classify_challenge(
            {
                "_status": 200,
                "continue_url": "https://auth.openai.com/mfa-unrecognized",
            }
        )

        self.assertEqual(recognized.kind, "totp")
        self.assertEqual(unknown.kind, "unsupported")

    def test_empty_page_type_requires_a_successful_continue_path(self):
        transport = FakeTransport([])
        bind_transport_context(
            transport,
            account_email="user@example.test",
            config={"dynamic_auth_challenges": True},
        )

        malformed = {"_status": 200}
        with self.assertRaises(AuthChallengeError) as caught:
            resolve_auth_challenges(transport, malformed)

        self.assertEqual(caught.exception.code, "auth_challenge_unsupported")
        self.assertEqual(transport.calls, [])

        successful = {
            "_status": 200,
            "continue_url": "https://auth.openai.com/oauth/authorize?state=private",
        }
        bind_transport_context(
            transport,
            account_email="user@example.test",
            config={"dynamic_auth_challenges": True},
        )
        self.assertIs(resolve_auth_challenges(transport, successful), successful)
        self.assertFalse(hasattr(transport, "_gptphone_auth_challenge_context"))

    def test_session_invalidation_short_circuits_before_any_challenge_action(self):
        invalid_responses = (
            {
                "_status": 401,
                "page": {"type": "mfa_challenge"},
                "error": {"code": "mfa_authorization_step_expired"},
            },
            {
                "_status": 401,
                "page": {"type": "email_otp_verification"},
                "error": {"code": "oauth_session_invalid"},
            },
        )
        for invalid in invalid_responses:
            with self.subTest(code=invalid["error"]["code"]):
                provider = FakeProvider(["must-not-be-read"])
                transport = FakeTransport([])
                bind_transport_context(
                    transport,
                    account_email="user@example.test",
                    email_otp_provider=provider,
                    config={"dynamic_auth_challenges": True},
                )

                result = continue_if_needed(transport, invalid, origin="mfa")

                self.assertIs(result, invalid)
                self.assertEqual(transport.calls, [])
                self.assertEqual(provider.calls, [])
                self.assertFalse(
                    hasattr(transport, "_gptphone_auth_challenge_context")
                )

    def test_handler_session_invalidation_is_preserved_without_next_challenge(self):
        invalid = {
            "_status": 401,
            "page": {"type": "mfa_challenge"},
            "error": {"code": "mfa_authorization_step_expired"},
        }
        provider = FakeProvider(["must-not-be-read"])
        transport = FakeTransport([invalid])
        bind_transport_context(
            transport,
            account_email="user@example.test",
            password="password",
            email_otp_provider=provider,
            config={"dynamic_auth_challenges": True},
        )

        result = resolve_auth_challenges(
            transport,
            response("password_required", "/log-in/password"),
        )

        self.assertIs(result, invalid)
        self.assertEqual(transport.calls, [("password", "password")])
        self.assertEqual(provider.calls, [])

    def test_dynamic_sequence_stops_before_phone_flow(self):
        provider = FakeProvider(["email-code", "totp-code"])
        transport = FakeTransport(
            [
                response("email_otp_verification", "/email-verification"),
                response("mfa_challenge", "/mfa-challenge/factor"),
                response("add_phone", "/add-phone"),
            ]
        )
        bind_transport_context(
            transport,
            account_email="USER@example.test",
            password="mail-password",
            email_otp_provider=provider,
            config={"dynamic_auth_challenges": True},
        )

        result = resolve_auth_challenges(
            transport,
            response("password_required", "/log-in/password"),
        )

        self.assertEqual(result["page"]["type"], "add_phone")
        self.assertEqual(
            transport.calls,
            [
                ("password", "mail-password"),
                ("send_email", "https://auth.openai.com/email-verification"),
                ("email_otp", "email-code"),
                ("send_mfa", "https://auth.openai.com/mfa-challenge/factor"),
                ("totp", "totp-code"),
            ],
        )
        self.assertFalse(hasattr(transport, "_gptphone_auth_challenge_context"))

    def test_incorrect_totp_retries_once_without_reissuing_challenge(self):
        provider = FakeProvider(["first-code", "next-window-code"])
        transport = FakeTransport(
            [
                {"_status": 403, "error": {"code": "incorrect_code"}},
                response("add_phone", "/add-phone"),
            ]
        )
        bind_transport_context(
            transport,
            account_email="user@example.test",
            email_otp_provider=provider,
            config={"dynamic_auth_challenges": True},
        )

        result = resolve_auth_challenges(
            transport,
            response("mfa_challenge", "/mfa-challenge/factor"),
        )

        self.assertEqual(result["page"]["type"], "add_phone")
        self.assertEqual(
            transport.calls,
            [
                ("send_mfa", "https://auth.openai.com/mfa-challenge/factor"),
                ("totp", "first-code"),
                ("totp", "next-window-code"),
            ],
        )
        self.assertEqual(
            provider.calls,
            [
                "sent",
                ("wait", "user@example.test"),
                ("wait", "user@example.test"),
                "verified",
            ],
        )

    def test_non_incorrect_totp_failure_is_not_retried(self):
        provider = FakeProvider(["first-code", "unused-code"])
        transport = FakeTransport(
            [{"_status": 401, "error": {"code": "session_expired"}}]
        )
        bind_transport_context(
            transport,
            account_email="user@example.test",
            email_otp_provider=provider,
            config={"dynamic_auth_challenges": True},
        )

        with self.assertRaises(AuthChallengeError) as caught:
            resolve_auth_challenges(
                transport,
                response("mfa_challenge", "/mfa-challenge/factor"),
            )

        self.assertEqual(caught.exception.code, "oauth_session_invalid")
        self.assertIn("session_expired", str(caught.exception))
        self.assertEqual(
            transport.calls,
            [
                ("send_mfa", "https://auth.openai.com/mfa-challenge/factor"),
                ("totp", "first-code"),
            ],
        )
        self.assertEqual(
            provider.calls,
            ["sent", ("wait", "user@example.test")],
        )

    def test_incorrect_totp_never_resubmits_the_same_code(self):
        provider = FakeProvider(["same-code", "same-code"])
        transport = FakeTransport(
            [{"_status": 403, "error": {"code": "incorrect_code"}}]
        )
        bind_transport_context(
            transport,
            account_email="user@example.test",
            email_otp_provider=provider,
            config={"dynamic_auth_challenges": True},
        )

        with self.assertRaises(AuthChallengeError) as caught:
            resolve_auth_challenges(
                transport,
                response("mfa_challenge", "/mfa-challenge/factor"),
            )

        self.assertEqual(caught.exception.code, "mfa_otp_retry_code_unchanged")
        self.assertEqual(
            transport.calls,
            [
                ("send_mfa", "https://auth.openai.com/mfa-challenge/factor"),
                ("totp", "same-code"),
            ],
        )

    def test_incorrect_totp_retry_honors_stop_before_waiting(self):
        stopped = [False]
        provider = FakeProvider(["first-code", "unused-code"])

        class StoppingTransport(FakeTransport):
            def verify_mfa_otp(self, code):
                result = super().verify_mfa_otp(code)
                stopped[0] = True
                return result

        transport = StoppingTransport(
            [{"_status": 403, "error": {"code": "incorrect_code"}}]
        )
        bind_transport_context(
            transport,
            account_email="user@example.test",
            email_otp_provider=provider,
            config={
                "dynamic_auth_challenges": True,
                "_stop_requested": lambda: stopped[0],
            },
        )

        with self.assertRaises(AuthChallengeError) as caught:
            resolve_auth_challenges(
                transport,
                response("mfa_challenge", "/mfa-challenge/factor"),
            )

        self.assertEqual(caught.exception.code, "task_stopped")
        self.assertEqual(
            provider.calls,
            ["sent", ("wait", "user@example.test")],
        )

    def test_recovered_order_is_left_untouched(self):
        transport = FakeTransport([])
        provider = FakeProvider([])
        bind_transport_context(
            transport,
            account_email="user@example.test",
            password="password",
            email_otp_provider=provider,
            config={},
        )
        current = response("email_otp_verification", "/email-verification")

        result = continue_if_needed(transport, current, origin="password")

        self.assertIs(result, current)
        self.assertEqual(transport.calls, [])

    def test_nonstandard_email_otp_to_password_is_continued(self):
        transport = FakeTransport([response("add_phone", "/add-phone")])
        bind_transport_context(
            transport,
            account_email="user@example.test",
            password="password",
            email_otp_provider=FakeProvider([]),
            config={},
        )

        result = continue_if_needed(
            transport,
            response("password_required", "/log-in/password"),
            origin="email_otp",
        )

        self.assertEqual(result["page"]["type"], "add_phone")
        self.assertEqual(transport.calls, [("password", "password")])

    def test_repeated_challenge_fails_with_stable_loop_code(self):
        transport = FakeTransport([response("password", "/log-in/password")])
        bind_transport_context(
            transport,
            account_email="user@example.test",
            password="password",
            email_otp_provider=FakeProvider([]),
            config={},
        )

        with self.assertRaises(AuthChallengeError) as caught:
            resolve_auth_challenges(
                transport,
                response("password", "/log-in/password"),
            )

        self.assertEqual(caught.exception.code, "auth_challenge_loop_detected")
        self.assertFalse(hasattr(transport, "_gptphone_auth_challenge_context"))

    def test_unknown_challenge_is_redacted_and_actionable(self):
        transport = FakeTransport([])
        bind_transport_context(
            transport,
            account_email="user@example.test",
            password="private-password",
            email_otp_provider=FakeProvider([]),
            config={},
        )

        with self.assertRaises(AuthChallengeError) as caught:
            resolve_auth_challenges(
                transport,
                {
                    "_status": 200,
                    "page": {"type": "brand_new_challenge"},
                    "continue_url": "https://auth.openai.com/new?token=private-token",
                },
            )

        self.assertEqual(caught.exception.code, "auth_challenge_unsupported")
        self.assertIn("continue_path=/new", str(caught.exception))
        self.assertNotIn("private-token", str(caught.exception))
        self.assertNotIn("private-password", str(caught.exception))

    def test_disabled_switch_returns_to_recovered_chain(self):
        transport = FakeTransport([])
        original = response("password_required", "/log-in/password")
        bind_transport_context(
            transport,
            account_email="user@example.test",
            password="password",
            email_otp_provider=FakeProvider([]),
            config={"dynamic_auth_challenges": False},
        )

        self.assertIs(resolve_auth_challenges(transport, original), original)
        self.assertEqual(transport.calls, [])
        clear_transport_context(transport)
        clear_transport_context(transport)

    def test_handler_registry_can_add_a_new_challenge_behavior(self):
        transport = SimpleNamespace()
        bind_transport_context(
            transport,
            account_email="user@example.test",
            password="password",
            email_otp_provider=FakeProvider([]),
            config={},
        )
        calls = []

        def password_handler(_context, _current):
            calls.append("password")
            return response("complete", "/oauth/authorize")

        result = resolve_auth_challenges(
            transport,
            response("password", "/log-in/password"),
            handlers={"password": password_handler},
        )

        self.assertEqual(result["page"]["type"], "complete")
        self.assertEqual(calls, ["password"])


if __name__ == "__main__":
    unittest.main()
