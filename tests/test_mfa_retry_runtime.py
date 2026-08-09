from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
import unittest

from mac_overrides.mfa_retry_runtime import (
    mfa_factor_id_from_response,
    response_error_code,
    retry_expired_mfa_step,
    verify_email_totp_with_one_window_retry,
)


EXPIRED = {
    "_status": 403,
    "error": {"code": "mfa_authorization_step_expired"},
}


class MfaRetryRuntimeTests(unittest.TestCase):
    def test_top_level_error_code_is_normalized(self):
        self.assertEqual(
            response_error_code({"error_code": "mfa-authorization-step-expired"}),
            "mfa_authorization_step_expired",
        )

    def test_factor_id_supports_payload_factor_list_and_continue_url(self):
        self.assertEqual(
            mfa_factor_id_from_response(
                {"page": {"payload": {"factor_id": "factor-payload"}}}
            ),
            "factor-payload",
        )
        self.assertEqual(
            mfa_factor_id_from_response(
                {"mfa_factors": [{"factor_type": "totp", "id": "factor-list"}]}
            ),
            "factor-list",
        )
        self.assertEqual(
            mfa_factor_id_from_response(
                {}, continue_url_fn=lambda _value: "https://auth.test/mfa-challenge/factor-url"
            ),
            "factor-url",
        )

    def test_url_totp_waits_for_next_window_and_retries_once(self):
        now = [100.0]
        waits = []
        calls = []
        logs = []

        class StopEvent:
            def is_set(self):
                return False

            def wait(self, seconds):
                waits.append(seconds)
                now[0] += seconds
                return False

        def verify(transport, code):
            calls.append((code, transport._gptphone_totp_incorrect_retries))
            if len(calls) == 1:
                transport._gptphone_totp_incorrect_retries = 1
                return {"_status": 403, "error": {"code": "incorrect_code"}}
            return {"_status": 200, "page": {"type": "add_phone"}}

        result = verify_email_totp_with_one_window_retry(
            SimpleNamespace(),
            factor_id="factor-private",
            secret="secret-private",
            verify_fn=verify,
            manual_fallback_fn=lambda *_args: self.fail("manual fallback must not run"),
            session_invalid_fn=lambda _value: False,
            stop_event=StopEvent(),
            clock=lambda: now[0],
            log_fn=lambda message, level: logs.append((message, level)),
        )

        self.assertEqual(result["_status"], 200)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(waits), 1)
        self.assertAlmostEqual(waits[0], 20.05, places=2)
        self.assertGreaterEqual(now[0], 120.05)
        self.assertNotIn("factor-private", repr(logs))
        self.assertNotIn("secret-private", repr(logs))

    def test_url_totp_stop_interrupts_window_wait(self):
        calls = []

        class StopEvent:
            stopped = False

            def is_set(self):
                return self.stopped

            def wait(self, _seconds):
                self.stopped = True
                return True

        def verify(transport, _code):
            calls.append(1)
            transport._gptphone_totp_incorrect_retries = 1
            return {"_status": 403, "error": {"code": "incorrect_code"}}

        transport = SimpleNamespace()
        result = verify_email_totp_with_one_window_retry(
            transport,
            factor_id="factor",
            secret="secret",
            verify_fn=verify,
            manual_fallback_fn=lambda *_args: self.fail("manual fallback must not run"),
            session_invalid_fn=lambda _value: False,
            stop_event=StopEvent(),
            clock=lambda: 100.0,
        )

        self.assertEqual(result["error"]["code"], "incorrect_code")
        self.assertEqual(calls, [1])
        self.assertFalse(transport._gptphone_totp_flow)
        self.assertFalse(hasattr(transport, "_gptphone_totp_secret"))

    def test_url_totp_callable_stop_interrupts_chunked_sleep(self):
        sleeps = []
        checks = []

        def stop_requested():
            checks.append(1)
            return bool(sleeps)

        transport = SimpleNamespace()
        result = verify_email_totp_with_one_window_retry(
            transport,
            factor_id="factor",
            secret="secret",
            verify_fn=lambda current, _code: (
                setattr(current, "_gptphone_totp_incorrect_retries", 1)
                or {"_status": 403, "error": {"code": "incorrect_code"}}
            ),
            manual_fallback_fn=lambda *_args: self.fail("manual fallback must not run"),
            session_invalid_fn=lambda _value: False,
            stop_event=stop_requested,
            clock=lambda: 100.0,
            sleep_fn=lambda seconds: sleeps.append(seconds),
        )

        self.assertEqual(result["error"]["code"], "incorrect_code")
        self.assertEqual(sleeps, [0.25])
        self.assertGreaterEqual(len(checks), 2)
        self.assertFalse(hasattr(transport, "_gptphone_totp_secret"))

    def test_url_totp_second_incorrect_enters_manual_without_third_auto_retry(self):
        calls = []
        manual = []

        class StopEvent:
            def is_set(self):
                return False

            def wait(self, _seconds):
                return False

        def verify(transport, code):
            calls.append(code)
            if len(calls) == 1:
                transport._gptphone_totp_incorrect_retries = 1
            else:
                transport._gptphone_totp_manual_secret = "secret-private"
                transport._gptphone_totp_secret = ""
            return {"_status": 403, "error": {"code": "incorrect_code"}}

        def manual_fallback(transport, response):
            manual.append(transport._gptphone_totp_manual_secret)
            return {"_status": 200, "page": {"type": "add_phone"}}

        result = verify_email_totp_with_one_window_retry(
            SimpleNamespace(),
            factor_id="factor-private",
            secret="secret-private",
            verify_fn=verify,
            manual_fallback_fn=manual_fallback,
            session_invalid_fn=lambda _value: False,
            stop_event=StopEvent(),
            clock=lambda: 100.0,
        )

        self.assertEqual(result["_status"], 200)
        self.assertEqual(calls, ["", ""])
        self.assertEqual(manual, ["secret-private"])
        self.assertEqual(
            response_error_code({"error": {"error_code": "incorrect_code"}}),
            "incorrect_code",
        )

    @staticmethod
    @contextmanager
    def pending(transport, payload, secret):
        previous = getattr(transport, "_gptphone_totp_secret", "")
        transport._gptphone_totp_secret = secret
        payload["code"] = "654321"
        try:
            yield payload
        finally:
            transport._gptphone_totp_secret = previous

    def test_expired_step_issues_one_fresh_challenge_and_retries(self):
        transport = SimpleNamespace(_gptphone_totp_secret="private-base32")
        calls = []
        logs = []

        def post(_transport, path, payload, **kwargs):
            calls.append((path, dict(payload), kwargs["flow"]))
            if path.endswith("issue_challenge"):
                return {"_status": 200}
            return {"_status": 200, "page": {"type": "add_phone"}}

        payload = {"id": "factor-private", "type": "totp", "code": "123456"}
        result, attempted = retry_expired_mfa_step(
            transport,
            path="/api/accounts/mfa/verify",
            payload=payload,
            response=EXPIRED,
            generation=3,
            post_json=post,
            pending_totp_payload=self.pending,
            success_fn=lambda value: int(value.get("_status") or 0) < 400,
            auth_origin="https://auth.openai.com",
            log_fn=lambda message, level: logs.append((message, level)),
        )

        self.assertTrue(attempted)
        self.assertEqual(result["_status"], 200)
        self.assertTrue(calls[0][1]["force_fresh_challenge"])
        self.assertEqual(calls[1][1]["code"], "654321")
        self.assertEqual(payload["code"], "654321")
        self.assertNotIn("factor-private", repr(logs))
        self.assertNotIn("private-base32", repr(logs))

    def test_same_generation_never_retries_twice(self):
        transport = SimpleNamespace(_gptphone_totp_secret="secret")
        calls = []

        def post(*args, **kwargs):
            calls.append((args, kwargs))
            return {"_status": 200}

        options = dict(
            path="/api/accounts/mfa/verify",
            payload={"id": "factor", "code": "111111"},
            response=EXPIRED,
            generation=1,
            post_json=post,
            pending_totp_payload=self.pending,
            success_fn=lambda value: int(value.get("_status") or 0) < 400,
            auth_origin="https://auth.openai.com",
        )
        self.assertTrue(retry_expired_mfa_step(transport, **options)[1])
        self.assertFalse(retry_expired_mfa_step(transport, **options)[1])
        self.assertEqual(len(calls), 2)

    def test_each_factor_has_its_own_single_refresh_in_one_generation(self):
        transport = SimpleNamespace(_gptphone_totp_secret="secret")
        calls = []

        def post(*args, **kwargs):
            calls.append((args, kwargs))
            return {"_status": 200}

        base = dict(
            path="/api/accounts/mfa/verify",
            response=EXPIRED,
            generation=1,
            post_json=post,
            pending_totp_payload=self.pending,
            success_fn=lambda value: int(value.get("_status") or 0) < 400,
            auth_origin="https://auth.openai.com",
        )
        self.assertTrue(retry_expired_mfa_step(
            transport, payload={"id": "factor-a", "code": "111111"}, **base
        )[1])
        self.assertTrue(retry_expired_mfa_step(
            transport, payload={"id": "factor-b", "code": "222222"}, **base
        )[1])
        self.assertFalse(retry_expired_mfa_step(
            transport, payload={"id": "factor-a", "code": "333333"}, **base
        )[1])
        self.assertEqual(len(calls), 4)

    def test_failed_fresh_challenge_response_is_preserved_for_session_handling(self):
        transport = SimpleNamespace(_gptphone_totp_secret="secret")
        invalid = {"_status": 401, "error": {"code": "oauth_session_invalid"}}

        result, attempted = retry_expired_mfa_step(
            transport,
            path="/api/accounts/mfa/verify",
            payload={"id": "factor", "code": "111111"},
            response=EXPIRED,
            generation=1,
            post_json=lambda *_args, **_kwargs: invalid,
            pending_totp_payload=self.pending,
            success_fn=lambda value: int(value.get("_status") or 0) < 400,
            auth_origin="https://auth.openai.com",
        )

        self.assertTrue(attempted)
        self.assertIs(result, invalid)

    def test_missing_factor_or_secret_preserves_original_response(self):
        for payload, secret in (({"code": "123456"}, "secret"), ({"id": "factor"}, "")):
            transport = SimpleNamespace(_gptphone_totp_secret=secret)
            result, attempted = retry_expired_mfa_step(
                transport,
                path="/api/accounts/mfa/verify",
                payload=payload,
                response=EXPIRED,
                generation=1,
                post_json=lambda *_args, **_kwargs: self.fail("must not call provider"),
                pending_totp_payload=self.pending,
                success_fn=lambda _value: True,
                auth_origin="https://auth.openai.com",
            )
            self.assertIs(result, EXPIRED)
            self.assertFalse(attempted)

    def test_non_expired_failure_is_not_intercepted(self):
        response = {"_status": 403, "error": {"code": "incorrect_code"}}
        result, attempted = retry_expired_mfa_step(
            SimpleNamespace(_gptphone_totp_secret="secret"),
            path="/api/accounts/mfa/verify",
            payload={"id": "factor", "code": "123456"},
            response=response,
            generation=1,
            post_json=lambda *_args, **_kwargs: self.fail("must not call provider"),
            pending_totp_payload=self.pending,
            success_fn=lambda _value: True,
            auth_origin="https://auth.openai.com",
        )
        self.assertIs(result, response)
        self.assertFalse(attempted)

    def test_second_expired_response_is_returned_without_a_second_fresh_retry(self):
        transport = SimpleNamespace(_gptphone_totp_secret="private-base32")
        calls = []
        logs = []

        def post(_transport, path, payload, **_kwargs):
            calls.append((path, dict(payload)))
            if path.endswith("issue_challenge"):
                return {"_status": 200}
            return EXPIRED

        result, attempted = retry_expired_mfa_step(
            transport,
            path="/api/accounts/mfa/verify",
            payload={"id": "factor-private", "type": "totp", "code": "123456"},
            response=EXPIRED,
            generation=3,
            post_json=post,
            pending_totp_payload=self.pending,
            success_fn=lambda value: int(value.get("_status") or 0) < 400,
            auth_origin="https://auth.openai.com",
            log_fn=lambda message, level: logs.append((message, level)),
        )

        self.assertTrue(attempted)
        self.assertIs(result, EXPIRED)
        self.assertEqual([path for path, _payload in calls], [
            "/api/accounts/mfa/issue_challenge",
            "/api/accounts/mfa/verify",
        ])
        self.assertIn("provider_code=mfa_authorization_step_expired", repr(logs))
        self.assertNotIn("private-base32", repr(logs))

    def test_retry_log_replaces_unknown_provider_message(self):
        secret_message = "provider response private-token-should-not-log"
        transport = SimpleNamespace(_gptphone_totp_secret="private-base32")
        logs = []

        def post(_transport, path, _payload, **_kwargs):
            if path.endswith("issue_challenge"):
                return {"_status": 200}
            return {"_status": 403, "error": {"message": secret_message}}

        result, attempted = retry_expired_mfa_step(
            transport,
            path="/api/accounts/mfa/verify",
            payload={"id": "factor-private", "type": "totp", "code": "123456"},
            response=EXPIRED,
            generation=3,
            post_json=post,
            pending_totp_payload=self.pending,
            success_fn=lambda value: int(value.get("_status") or 0) < 400,
            auth_origin="https://auth.openai.com",
            log_fn=lambda message, level: logs.append((message, level)),
        )

        self.assertTrue(attempted)
        self.assertEqual(result["_status"], 403)
        self.assertIn("provider_code=provider_error", repr(logs))
        self.assertNotIn(secret_message, repr(logs))


if __name__ == "__main__":
    unittest.main()
