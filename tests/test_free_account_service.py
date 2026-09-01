from __future__ import annotations

import asyncio
import threading
import time
from urllib.parse import parse_qs, urlsplit
import unittest
from unittest.mock import AsyncMock, Mock, patch

from mac_overrides import free_account_service as service


class _Page:
    def __init__(self) -> None:
        self.goto_calls: list[str] = []
        self.goto_options: list[dict] = []

    async def goto(self, url: str, **kwargs):
        self.goto_calls.append(url)
        self.goto_options.append(dict(kwargs))
        return None


class FreeAccountServiceTests(unittest.TestCase):
    def test_account_otp_worker_stops_when_async_flow_is_cancelled(self):
        started = threading.Event()
        stopped = threading.Event()

        def blocking_callback(_stage, *, stop_requested, deadline_monotonic):
            self.assertGreater(deadline_monotonic, time.monotonic())
            started.set()
            while not stop_requested():
                time.sleep(0.005)
            stopped.set()
            return ""

        async def run():
            task = asyncio.create_task(
                service._await_account_otp_callback(
                    blocking_callback,
                    "free_twofa_enroll",
                    deadline_monotonic=time.monotonic() + 30,
                )
            )
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.005)
            self.assertTrue(started.is_set())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(run())
        self.assertTrue(stopped.wait(1.0))

    def test_account_otp_worker_honors_stop_callback(self):
        started = threading.Event()
        stopped = threading.Event()
        stop = threading.Event()

        def blocking_callback(_stage, *, stop_requested):
            started.set()
            while not stop_requested():
                time.sleep(0.005)
            stopped.set()
            return ""

        async def run():
            task = asyncio.create_task(
                service._await_account_otp_callback(
                    blocking_callback,
                    "free_password_otp_wait",
                    stop_requested=stop,
                )
            )
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.005)
            self.assertTrue(started.is_set())
            stop.set()
            with self.assertRaises(service.FreeRegisterError) as raised:
                await task
            self.assertEqual(raised.exception.error_code, "free_run_stop")

        asyncio.run(run())
        self.assertTrue(stopped.wait(1.0))

    def test_account_async_otp_callback_is_closed_when_cancelled(self):
        started = threading.Event()
        closed = threading.Event()

        async def callback(_stage, *, stop_requested):
            started.set()
            try:
                await asyncio.sleep(30)
            finally:
                closed.set()

        async def run():
            task = asyncio.create_task(
                service._await_account_otp_callback(
                    callback,
                    "free_twofa_enroll",
                    deadline_monotonic=time.monotonic() + 30,
                )
            )
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.005)
            self.assertTrue(started.is_set())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(run())
        self.assertTrue(closed.wait(1.0))

    def test_account_otp_partial_deadline_controller_uses_absolute_fallback(self):
        class PartialController:
            @staticmethod
            def is_paused():
                return False

        async def run():
            return await service._await_account_otp_callback(
                lambda _stage, **_kwargs: "246810",
                "free_password_otp_wait",
                deadline_monotonic=time.monotonic() + 2,
                deadline_controller=PartialController(),
            )

        self.assertEqual(asyncio.run(run()), "246810")

    def test_account_otp_controller_failures_still_drain_worker(self):
        started = threading.Event()
        stopped = threading.Event()

        class BrokenController:
            def begin_otp_wait(self):
                raise RuntimeError("begin unavailable")

            def end_otp_wait(self):
                raise RuntimeError("end unavailable")

            def is_paused(self):
                raise RuntimeError("pause unavailable")

            def remaining(self):
                raise RuntimeError("remaining unavailable")

        def callback(_stage, *, stop_requested, **_kwargs):
            started.set()
            while not stop_requested():
                time.sleep(0.005)
            stopped.set()
            return ""

        async def run():
            with self.assertRaises(service.FreeRegisterError) as raised:
                await service._await_account_otp_callback(
                    callback,
                    "free_password_otp_wait",
                    deadline_monotonic=time.monotonic() + 0.03,
                    deadline_controller=BrokenController(),
                )
            return raised.exception

        failure = asyncio.run(run())
        self.assertTrue(started.is_set())
        self.assertTrue(stopped.wait(1.0))
        self.assertEqual(failure.error_code, "free_password_otp_wait_mailbox_code_timeout")

    def test_account_otp_callback_awaits_nested_coroutine_result(self):
        async def inner():
            return "071618"

        async def callback(_stage, **_kwargs):
            return inner()

        async def run():
            return await service._await_account_otp_callback(
                callback,
                "free_password_otp_wait",
                deadline_monotonic=time.monotonic() + 1,
            )

        self.assertEqual(asyncio.run(run()), "071618")

    def test_browser_json_fetch_records_timing_without_exposing_request_data(self):
        class EvalPage:
            async def evaluate(self, _script, _args):
                return {"ok": True, "status": 200, "payload": {"value": "safe"}}

        events: list[tuple[str, str, int, str]] = []
        result = asyncio.run(
            service.browser_json_fetch(
                EvalPage(),
                "https://chatgpt.com/backend-api/accounts/check?secret=hidden",
                token="secret-token",
                timing_fn=lambda *event: events.append(event),
                timing_stage="free_access_token",
                timing_code="plan_accounts_fetch",
            )
        )

        self.assertTrue(result["ok"])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0:2], ("free_access_token", "plan_accounts_fetch"))
        self.assertEqual(events[0][3], "success")

    def test_password_retry_allowed_for_pending_or_disabled_signup_only(self):
        self.assertTrue(service.password_retry_allowed({
            "account_flow": "signup",
            "password_status": "pending",
            "access_token": "token",
        }))
        self.assertTrue(service.password_retry_allowed({
            "account_flow": "signup",
            "password_status": "disabled",
            "registration_password_used": False,
            "access_token": "token",
        }))
        self.assertTrue(service.password_retry_allowed({
            "account_flow": "signup",
            "password_set_after_registration": False,
            "registration_password_used": False,
            "access_token": "token",
        }))
        self.assertFalse(service.password_retry_allowed({
            "account_flow": "signup",
            "password_status": "disabled",
            "registration_password_used": True,
            "password": "existing-password",
        }))
        self.assertFalse(service.password_retry_allowed({
            "account_flow": "existing_login",
            "password_status": "pending",
            "access_token": "token",
        }))

    def test_browser_twofa_reauth_otp_precedes_mfa_requests(self):
        page = _Page()
        events: list[tuple[str, str]] = []
        timing_events: list[tuple[str, str, int, str]] = []

        class DeadlineController:
            @staticmethod
            def remaining():
                return 12.0

            @staticmethod
            def is_paused():
                return False

        controller = DeadlineController()
        def record_prepare(*args, **kwargs):
            events.append(("prepare", str((args, kwargs))))

        def record_mark(*args, **kwargs):
            events.append(("mark", str((args, kwargs))))

        def return_otp(*args, **kwargs):
            events.append(("otp", str((args, kwargs))))
            return "246810"

        prepare = Mock(side_effect=record_prepare)
        mark_sent = Mock(side_effect=record_mark)
        otp = Mock(side_effect=return_otp)

        async def fetch(_page, url, **kwargs):
            events.append(("fetch", url))
            if url == service.AUTH_CSRF_URL:
                return {"ok": True, "status": 200, "payload": {"csrfToken": "csrf"}}
            if url.startswith(service.AUTH_SIGNIN_URL):
                query = parse_qs(urlsplit(url).query)
                self.assertEqual(query["connection"], ["password"])
                self.assertEqual(query["reauth"], ["password"])
                self.assertEqual(query["max_age"], ["0"])
                self.assertEqual(query["login_hint"], ["user@example.test"])
                self.assertEqual(query["ext-oai-did"], ["device-1"])
                self.assertTrue(kwargs.get("form"))
                return {
                    "ok": True,
                    "status": 200,
                    "payload": {"url": "https://auth.openai.com/authorize?state=reauth"},
                }
            if url == service.AUTH_EMAIL_OTP_VALIDATE_URL:
                return {
                    "ok": True,
                    "status": 200,
                    "payload": {
                        "page": {
                            "payload": {
                                "continue_url": "https://chatgpt.com/api/auth/callback/openai?state=done",
                            },
                        },
                    },
                }
            if url == service.MFA_INFO_URL:
                return {"ok": True, "status": 200, "payload": {"mfa_enabled": False}}
            if url == service.MFA_ENROLL_URL:
                return {
                    "ok": True,
                    "status": 200,
                    "payload": {"secret": "JBSWY3DPEHPK3PXP", "session_id": "enroll-1"},
                }
            if url == service.MFA_ACTIVATE_URL:
                return {"ok": True, "status": 200, "payload": {"success": True}}
            self.fail(f"unexpected browser JSON URL: {url}")

        async def session(_page, **_kwargs):
            events.append(("session", "refresh"))
            return {"accessToken": "fresh-token"}

        with (
            patch.object(service, "browser_json_fetch", new=fetch),
            patch.object(service, "browser_session", new=session),
            patch.object(service, "totp_code", return_value="135790"),
        ):
            result = asyncio.run(
                service.browser_twofa(
                    page,
                    "old-token",
                    "user@example.test",
                    otp_callback=otp,
                    otp_prepare=prepare,
                    otp_mark_sent=mark_sent,
                    device_id="device-1",
                    # The absolute value represents the pre-pause deadline.
                    # Once a controller is present its shifted budget is the
                    # authoritative source for post-manual navigation.
                    deadline_monotonic=0.0,
                    deadline_controller=controller,
                    timing_fn=lambda *event: timing_events.append(event),
                )
            )

        self.assertEqual(result["twofa_status"], "enabled")
        self.assertEqual(result["totp_secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(result["access_token"], "fresh-token")
        self.assertEqual(page.goto_calls[0], "https://auth.openai.com/authorize?state=reauth")
        self.assertEqual(page.goto_calls[1], "https://chatgpt.com/api/auth/callback/openai?state=done")
        self.assertEqual([item.get("timeout") for item in page.goto_options], [12_000, 12_000])
        self.assertIs(otp.call_args.kwargs.get("deadline_controller"), controller)
        self.assertTrue(
            any(event[0:2] == ("free_twofa_reauth_callback", "oauth_callback_navigation") for event in timing_events)
        )
        self.assertEqual(prepare.call_args.args, ("free_twofa_enroll",))
        self.assertTrue(prepare.call_args.kwargs.get("force_snapshot"))
        self.assertEqual(mark_sent.call_args.args, ("free_twofa_enroll",))
        urls = [value for kind, value in events if kind == "fetch"]
        self.assertLess(urls.index(service.AUTH_CSRF_URL), urls.index(service.AUTH_EMAIL_OTP_VALIDATE_URL))
        self.assertLess(urls.index(service.AUTH_EMAIL_OTP_VALIDATE_URL), urls.index(service.MFA_INFO_URL))
        self.assertLess(urls.index(service.MFA_INFO_URL), urls.index(service.MFA_ENROLL_URL))
        self.assertLess(urls.index(service.MFA_ENROLL_URL), urls.index(service.MFA_ACTIVATE_URL))
        self.assertLess(
            next(index for index, event in enumerate(events) if event[0] == "mark"),
            next(index for index, event in enumerate(events) if event[0] == "otp"),
        )

    def test_password_helper_never_queries_mfa_info(self):
        page = _Page()
        urls: list[str] = []

        async def fetch(_page, url, **kwargs):
            urls.append(url)
            if url == service.ADD_PASSWORD_ELIGIBILITY_URL:
                return {"ok": True, "status": 200, "payload": {"eligible": True}}
            if url == service.AUTH_CSRF_URL:
                return {"ok": True, "status": 200, "payload": {"csrfToken": "csrf"}}
            if url.startswith(service.AUTH_SIGNIN_URL):
                query = parse_qs(urlsplit(url).query)
                self.assertNotIn("connection", query)
                self.assertEqual(query["reauth"], ["password"])
                self.assertEqual(query["post_login_add_password"], ["true"])
                return {"ok": True, "status": 200, "payload": {"url": "https://auth.openai.com/authorize?state=pwd"}}
            if url == service.AUTH_EMAIL_OTP_VALIDATE_URL:
                return {"ok": True, "status": 200, "payload": {"continue_url": "https://auth.openai.com/reset-password/next"}}
            if url == service.AUTH_PASSWORD_ADD_URL:
                return {"ok": True, "status": 200, "payload": {"continue_url": "https://chatgpt.com/api/auth/callback/openai?state=pwd"}}
            self.fail(f"unexpected browser JSON URL: {url}")

        async def session(_page):
            return {"accessToken": "fresh-token"}

        with (
            patch.object(service, "browser_json_fetch", new=fetch),
            patch.object(service, "browser_session", new=session),
        ):
            result = asyncio.run(
                service.browser_add_password(
                    page,
                    "old-token",
                    "user@example.test",
                    "Aa150010150010",
                    otp_callback=lambda *_args, **_kwargs: "246810",
                    otp_prepare=Mock(),
                    otp_mark_sent=Mock(),
                )
            )

        self.assertEqual(result["password_status"], "enabled")
        self.assertNotIn(service.MFA_INFO_URL, urls)

    def test_nested_continue_url_is_supported(self):
        self.assertEqual(
            service._response_continue_url(
                {
                    "page": {
                        "url": "https://auth.openai.com/email-verification",
                        "payload": {"continue_url": "https://auth.openai.com/reset-password/x"},
                    },
                }
            ),
            "https://auth.openai.com/reset-password/x",
        )

    def test_registration_password_status_does_not_mean_post_registration_password(self):
        result = service.finalize_registration_result(
            {
                "account_flow": "signup",
                "password_status": "enabled",
                "password_set_after_registration": False,
                "password": "Aa150010150010",
            },
            driver="protocol",
            email="user@example.test",
            password_used=True,
        )
        self.assertTrue(result["registration_password_used"])
        self.assertFalse(result["password_set_after_registration"])
        self.assertEqual(result["password"], "Aa150010150010")

    def test_post_registration_password_marker_is_explicit(self):
        result = service.finalize_registration_result(
            {
                "account_flow": "signup",
                "password_status": "enabled",
                "password_set_after_registration": True,
                "password": "Aa150010150010",
            },
            driver="protocol",
            email="user@example.test",
            password_used=False,
        )
        self.assertTrue(result["registration_password_used"])
        self.assertTrue(result["password_set_after_registration"])


if __name__ == "__main__":
    unittest.main()
