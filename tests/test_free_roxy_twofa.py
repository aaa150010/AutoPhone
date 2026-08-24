"""Fake-driver coverage for the Free Roxy 2FA callback boundary."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.free_roxy_twofa import setup_twofa


class _Driver:
    def __init__(self, reject: str = "") -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.reject = reject

    def execute_async_script(self, script: str, *args: object) -> dict:
        self.calls.append((script, args))
        if "signin/openai" in script:
            return {"ok": True, "url": "https://auth.openai.com/authorize/reauth"}
        if "/mfa/enroll" in script:
            if self.reject == "enroll":
                return {"ok": False, "status": 409, "value": {"error": {"code": "mfa_session_expired"}}}
            return {"ok": True, "status": 200, "value": {"secret": "SECRET", "session_id": "sid"}}
        if self.reject == "activate":
            return {"ok": False, "status": 422, "value": {"error_code": "invalid_totp"}}
        return {"ok": True, "status": 200, "value": {"success": True}}

    def get(self, url: str) -> None:
        self.calls.append(("get", (url,)))


class _Otp:
    def __init__(self) -> None:
        self.prepared = []
        self.marked = []

    def prepare(self, *args, **kwargs) -> None:
        self.prepared.append((args, kwargs))

    def mark_sent(self, *args) -> None:
        self.marked.append(args)

    def wait_code(self, *args, **kwargs) -> str:
        return "123456"


class FreeRoxyTwofaTests(unittest.TestCase):
    @staticmethod
    def _run(driver: _Driver) -> str:
        return setup_twofa(
            driver,
            {"task_id": "task-1", "email": "account@example.test"},
            "old-token",
            _Otp(),
            type("Human", (), {})(),
            lambda *_args: None,
            session_fn=lambda *_args: {"accessToken": "fresh-token"},
            fill_otp_fn=lambda *_args: {"submit_observed": True},
            wait_after_otp_fn=lambda *_args: "home",
            wait_home_fn=lambda *_args: None,
            totp_fn=lambda _secret: "654321",
        )

    def test_callback_is_followed_before_session_refresh_and_mfa(self) -> None:
        driver = _Driver()
        otp = _Otp()
        session_calls: list[tuple[object, int]] = []
        stages: list[str] = []
        refreshed_tokens: list[str] = []

        def session_fn(current, timeout):
            session_calls.append((current, timeout))
            return {"accessToken": "fresh-token"}

        with (
            patch("mac_overrides.free_roxy_twofa.wait_for_continue_url", return_value="https://auth.openai.com/authorize/continue?code=redacted"),
            patch("mac_overrides.free_roxy_twofa.follow_oauth_continue", return_value="home") as followed,
        ):
            secret = setup_twofa(
                driver,
                {"task_id": "task-1", "email": "account@example.test"},
                "old-token",
                otp,
                type("Human", (), {})(),
                lambda _task_id, value: stages.append(value),
                session_fn=session_fn,
                fill_otp_fn=lambda *_args: {"submit_observed": True},
                wait_after_otp_fn=lambda *_args: "oauth_callback",
                wait_home_fn=lambda *_args: None,
                totp_fn=lambda _secret: "654321",
                token_sink=refreshed_tokens.append,
            )

        self.assertEqual(secret, "SECRET")
        followed.assert_called_once()
        self.assertEqual(len(session_calls), 1)
        self.assertEqual(session_calls[0][1], 90)
        self.assertEqual(stages, ["free_twofa_enroll", "free_twofa_activate"])
        self.assertEqual(refreshed_tokens, ["fresh-token"])
        self.assertNotIn("123456", repr(driver.calls))
        self.assertIn("fresh-token", repr(driver.calls))
        self.assertNotIn("old-token", repr(driver.calls))

    def test_provider_code_and_action_are_kept_for_each_mfa_api_failure(self) -> None:
        expected = {
            "enroll": ("free_twofa_enroll", 409, "mfa_session_expired"),
            "activate": ("free_twofa_activate", 422, "invalid_totp"),
        }
        for rejected, (node_code, status, provider_code) in expected.items():
            with self.subTest(rejected=rejected):
                with self.assertRaises(FreeRegisterError) as raised:
                    self._run(_Driver(rejected))
                self.assertEqual(raised.exception.node_code, node_code)
                self.assertEqual(raised.exception.provider_status, status)
                self.assertEqual(raised.exception.provider_code, provider_code)
                self.assertTrue(raised.exception.action_hint)

    def test_refreshed_token_is_returned_before_enrollment_failure(self) -> None:
        refreshed_tokens: list[str] = []
        with self.assertRaises(FreeRegisterError):
            setup_twofa(
                _Driver("enroll"),
                {"task_id": "task-1", "email": "account@example.test"},
                "old-token",
                _Otp(),
                type("Human", (), {})(),
                lambda *_args: None,
                session_fn=lambda *_args: {"accessToken": "fresh-token"},
                fill_otp_fn=lambda *_args: {"submit_observed": True},
                wait_after_otp_fn=lambda *_args: "home",
                wait_home_fn=lambda *_args: None,
                totp_fn=lambda _secret: "654321",
                token_sink=refreshed_tokens.append,
            )
        self.assertEqual(refreshed_tokens, ["fresh-token"])


if __name__ == "__main__":
    unittest.main()
