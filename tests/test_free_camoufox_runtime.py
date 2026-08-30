from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import ANY, AsyncMock, Mock, patch

from mac_overrides import free_account_service
from mac_overrides import free_camoufox_runtime as runtime
from mac_overrides.free_proxy_bridge import Socks5HttpBridge
from mac_overrides.free_register_runtime import FreeRegisterManager


class _FakeLocator:
    first = None

    def __init__(self, *, visible=False):
        self.first = self
        self.visible = visible

    async def inner_text(self, **_kwargs):
        return ""

    async def is_visible(self, **_kwargs):
        return self.visible


class _FakePage:
    url = "https://chatgpt.com/auth/login"

    def locator(self, _selector):
        return _FakeLocator()

    async def title(self):
        return "ChatGPT"


class _EntryPage(_FakePage):
    def locator(self, selector):
        if selector == "body":
            page = self

            class BodyLocator:
                async def inner_text(self, **_kwargs):
                    return "Get started | ChatGPT"

            return BodyLocator()
        return _FakeLocator()


class _NavigationPage(_FakePage):
    def __init__(self, *, status=200, body="", retry_after="", goto_error=None, email_visible=False):
        self.status = status
        self.body = body
        self.retry_after = retry_after
        self.goto_error = goto_error
        self.email_visible = email_visible
        self.goto_calls = []

    def locator(self, selector):
        if selector == "body":
            page = self

            class BodyLocator:
                async def inner_text(self, **_kwargs):
                    return page.body

            return BodyLocator()
        return _FakeLocator(visible=self.email_visible and "email" in selector)

    async def goto(self, url, **_kwargs):
        self.goto_calls.append(url)
        if self.goto_error is not None:
            raise self.goto_error

        class Response:
            def __init__(self, page):
                self.status = page.status
                self.headers = {"retry-after": page.retry_after} if page.retry_after else {}

        return Response(self)


class _FakeContext:
    def __init__(self, *, close_error: BaseException | None = None):
        self.close_error = close_error
        self.closed = False

    async def new_page(self):
        return _FakePage()

    async def close(self):
        self.closed = True
        if self.close_error:
            raise self.close_error


class _FakeBrowser:
    def __init__(self, *, close_error: BaseException | None = None):
        self.close_error = close_error
        self.closed = False

    def is_connected(self):
        return not self.closed

    async def close(self):
        self.closed = True
        if self.close_error:
            raise self.close_error


class _FakeManager:
    instances: list[_FakeManager] = []
    context_close_error: BaseException | None = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.browser = _FakeBrowser()
        self.entered = 0
        self.exited = 0
        self.__class__.instances.append(self)

    async def __aenter__(self):
        self.entered += 1
        return self.browser

    async def __aexit__(self, *_args):
        self.exited += 1
        self.browser.closed = True


def _fake_context(browser, **_kwargs):
    async def create():
        return _FakeContext(close_error=_FakeManager.context_close_error)

    return create()


class CamoufoxRuntimeTests(unittest.TestCase):
    def setUp(self):
        _FakeManager.instances.clear()
        _FakeManager.context_close_error = None

    @staticmethod
    def _config(**overrides):
        value = {
            "headless": True,
            "pool_size": 1,
            "max_contexts_per_browser": 1,
            "context_start_interval_ms": 0,
            "startup_concurrency": 1,
            "block_images": True,
            "registration_timeout_seconds": 2,
            "context_close_timeout_seconds": 1,
            "browser_recycle_timeout_seconds": 1,
            "browser_recycle_drain_timeout_seconds": 1,
            "max_registrations_per_browser": 99,
            "browser_launch_attempts": 1,
        }
        value.update(overrides)
        return value

    def test_missing_dependency_is_explicit_and_does_not_import_browser(self):
        with patch.object(runtime, "_load_camoufox_api", side_effect=runtime.CamoufoxDependencyError()):
            with self.assertRaises(runtime.CamoufoxDependencyError) as raised:
                runtime.CamoufoxRegistrationRunner.preflight({"camoufox": self._config()})
        self.assertEqual(raised.exception.error_code, "camoufox_dependency_missing")
        self.assertEqual(raised.exception.node_code, "free_camoufox_dependency")

    def test_browser_flow_accepts_transport_proxy_argument(self):
        self.assertIn("proxy", inspect.signature(runtime._browser_flow).parameters)

    def test_otp_callback_deadline_stops_blocking_worker(self):
        """A mailbox waiter cannot outlive the Camoufox registration deadline."""
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
            with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                await runtime._await_otp_callback(
                    blocking_callback,
                    "free_email_otp_wait",
                    deadline_monotonic=time.monotonic() + 0.05,
                )
            return raised.exception

        failure = asyncio.run(run())
        self.assertTrue(started.is_set())
        self.assertTrue(stopped.wait(1.0))
        self.assertEqual(failure.error_code, "camoufox_otp_wait_timeout")

    def test_otp_callback_stop_signal_cancels_worker(self):
        """Cancelling the async page flow propagates to a mailbox callback."""
        started = threading.Event()
        stopped = threading.Event()

        def blocking_callback(_stage, *, stop_requested, deadline_monotonic):
            started.set()
            while not stop_requested():
                time.sleep(0.005)
            stopped.set()
            return ""

        async def run():
            task = asyncio.create_task(runtime._await_otp_callback(
                blocking_callback,
                "free_email_otp_wait",
                deadline_monotonic=time.monotonic() + 30,
            ))
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.005)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(run())
        self.assertTrue(started.is_set())
        self.assertTrue(stopped.wait(1.0))

    def test_profile_transition_timing_is_non_overlapping(self):
        """The async submit and home confirmation intervals are distinct."""
        class Locator:
            first = None

            def __init__(self):
                self.first = self

            async def is_visible(self, **_kwargs):
                return False

            async def count(self):
                return 0

            async def input_value(self, **_kwargs):
                return ""

        class Page:
            url = "https://auth.openai.com/about-you"

            def locator(self, _selector):
                return Locator()

        clock = [0.0]
        events = []

        async def fake_sleep(seconds):
            clock[0] += float(seconds or 0.0)

        stable_result = {
            "ok": True,
            "reason": "form_request_submit",
            "form_present": True,
            "input_selector": "input",
            "submit_selector": "submit",
        }
        with (
            patch.object(runtime.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(runtime.asyncio, "sleep", side_effect=fake_sleep),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_wait_for_any_selector", new=AsyncMock(return_value="input")),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)),
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)),
            patch.object(runtime, "_page_state", new=AsyncMock(side_effect=("profile", "oauth_callback", "home"))),
            patch.object(runtime, "_find_visible_selector", new=AsyncMock(return_value=None)),
            patch.object(runtime, "_sync_hidden_birthday_input", new=AsyncMock(return_value=False)),
            patch.object(runtime, "_accept_about_you_consents", new=AsyncMock(return_value=False)),
            patch.object(runtime, "_wait_for_submit_enabled", new=AsyncMock(return_value="submit")),
            patch.object(runtime, "_click_first", new=AsyncMock(return_value=True)),
            patch.object(runtime, "_confirm_birthday", new=AsyncMock(return_value=False)),
            patch.object(runtime, "browser_session", new=AsyncMock(return_value={"accessToken": "token"})),
            patch.object(runtime, "browser_plan_details", new=AsyncMock(return_value={"plan_type": "free"})),
            patch.object(runtime, "finalize_registration_result", side_effect=lambda result, **_kwargs: result),
        ):
            result = asyncio.run(
                runtime._browser_flow(
                    Page(), email="user@example.test", password="password",
                    otp_callback=lambda: "", config={
                        "registration_timeout_seconds": 60, "auto_set_2fa": False,
                    }, log=lambda *_args: None,
                    otp_prepare=Mock(), otp_mark_sent=Mock(),
                    timing_fn=lambda *event: events.append(event),
                )
            )

        self.assertEqual(result["twofa_status"], "disabled")
        profile_events = {
            event[1]: event for event in events
            if event[0] == "free_camoufox_profile"
        }
        self.assertEqual(profile_events["profile_async_submit_wait"][3], "success")
        self.assertEqual(profile_events["profile_home_state_wait"][3], "success")
        # The callback-to-home interval starts where async-submit ends; it must
        # not repeat the full profile-submit duration.
        self.assertEqual(profile_events["profile_async_submit_wait"][2], 1000)
        self.assertEqual(profile_events["profile_home_state_wait"][2], 1000)

    def test_profile_security_transition_is_not_reported_as_success(self):
        class Locator:
            first = None

            def __init__(self):
                self.first = self

            async def is_visible(self, **_kwargs):
                return False

            async def count(self):
                return 0

            async def input_value(self, **_kwargs):
                return ""

        class Page:
            url = "https://auth.openai.com/about-you"

            def locator(self, _selector):
                return Locator()

        clock = [0.0]
        events = []

        async def fake_sleep(seconds):
            clock[0] += float(seconds or 0.0)

        async def stop_on_challenge(*_args, **_kwargs):
            raise runtime.CamoufoxBrowserError(
                "free_camoufox_challenge", "等待安全验证", "challenge",
                error_code="challenge",
            )

        stable_result = {
            "ok": True,
            "reason": "form_request_submit",
            "form_present": True,
            "input_selector": "input",
            "submit_selector": "submit",
        }
        with (
            patch.object(runtime.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(runtime.asyncio, "sleep", side_effect=fake_sleep),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_wait_for_any_selector", new=AsyncMock(return_value="input")),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)),
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)),
            patch.object(runtime, "_page_state", new=AsyncMock(side_effect=("profile", "security"))),
            patch.object(runtime, "_find_visible_selector", new=AsyncMock(return_value=None)),
            patch.object(runtime, "_sync_hidden_birthday_input", new=AsyncMock(return_value=False)),
            patch.object(runtime, "_accept_about_you_consents", new=AsyncMock(return_value=False)),
            patch.object(runtime, "_wait_for_submit_enabled", new=AsyncMock(return_value="submit")),
            patch.object(runtime, "_click_first", new=AsyncMock(return_value=True)),
            patch.object(runtime, "_confirm_birthday", new=AsyncMock(return_value=False)),
            patch.object(runtime, "_wait_challenge_then_stop", new=stop_on_challenge),
        ):
            with self.assertRaises(runtime.CamoufoxBrowserError):
                asyncio.run(
                    runtime._browser_flow(
                        Page(), email="user@example.test", password="password",
                        otp_callback=lambda: "", config={"registration_timeout_seconds": 60},
                        log=lambda *_args: None, otp_prepare=Mock(), otp_mark_sent=Mock(),
                        timing_fn=lambda *event: events.append(event),
                    )
                )

        async_event = next(
            event for event in events
            if event[1] == "profile_async_submit_wait"
        )
        self.assertEqual(async_event[3], "security_challenge")
        self.assertNotIn(
            ("free_camoufox_profile", "profile_home_state_wait", 0, "success"),
            events,
        )

    def test_profile_transition_outcome_only_accepts_authenticated_states(self):
        self.assertEqual(runtime._profile_transition_timing_outcome("home"), "success")
        self.assertEqual(runtime._profile_transition_timing_outcome("oauth_callback"), "success")
        self.assertEqual(runtime._profile_transition_timing_outcome("security"), "security_challenge")
        self.assertEqual(runtime._profile_transition_timing_outcome("unknown"), "unexpected_state")

    def test_signup_discovery_records_otp_transition_under_existing_login_stage(self):
        class Page(_FakePage):
            url = "https://auth.openai.com/log-in"

        clock = [0.0]
        events = []
        callback_stages = []

        async def fake_sleep(seconds):
            clock[0] += float(seconds or 0.0)

        stable_result = {
            "ok": True,
            "reason": "form_request_submit",
            "form_present": True,
            "input_selector": "input",
            "submit_selector": "submit",
        }
        with (
            patch.object(runtime.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(runtime.asyncio, "sleep", side_effect=fake_sleep),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_wait_for_any_selector", new=AsyncMock(return_value="input")),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)),
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)),
            patch.object(
                runtime, "_page_state",
                new=AsyncMock(side_effect=("login_password", "otp", "otp", "otp", "home")),
            ),
            patch.object(runtime, "_find_visible_selector", new=AsyncMock(return_value="otp-input")),
            patch.object(runtime, "_fill_input_like_user", new=AsyncMock(return_value=True)),
            patch.object(runtime, "_click_first", new=AsyncMock(return_value=True)),
            patch.object(runtime, "browser_session", new=AsyncMock(return_value={"accessToken": "token"})),
            patch.object(runtime, "browser_plan_details", new=AsyncMock(return_value={})),
            patch.object(runtime, "finalize_registration_result", side_effect=lambda result, **_kwargs: result),
        ):
            result = asyncio.run(
                runtime._browser_flow(
                    Page(), email="user@example.test", password="password",
                    existing_password="saved-account-password",
                    otp_callback=lambda stage: callback_stages.append(stage) or "123456",
                    config={"registration_timeout_seconds": 60, "auto_set_2fa": False},
                    log=lambda *_args: None, otp_prepare=Mock(), otp_mark_sent=Mock(),
                    timing_fn=lambda *event: events.append(event),
                )
            )

        self.assertEqual(result["account_flow"], "existing_login")
        self.assertEqual(callback_stages, ["free_existing_login_otp"])
        transition = next(event for event in events if event[1] == "otp_submit_transition")
        self.assertEqual(transition[0], "free_existing_login_otp")
        self.assertEqual(transition[3], "success")

    def test_existing_login_requires_saved_password_before_browser_progress(self):
        with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
            asyncio.run(
                runtime._browser_flow(
                    _FakePage(), email="user@example.test", password="",
                    force_existing_login=True, otp_callback=lambda: "123456",
                    config={"registration_timeout_seconds": 60},
                    log=lambda *_args: None,
                )
            )
        self.assertEqual(raised.exception.error_code, "free_existing_login_password_missing")
        self.assertFalse(raised.exception.retryable)

    def test_email_form_submission_scopes_current_form_and_excludes_social_buttons(self):
        class Page:
            def __init__(self):
                self.script = ""
                self.arguments = None

            async def evaluate(self, script, arguments):
                self.script = script
                self.arguments = arguments
                return {
                    "ok": True,
                    "reason": "form_request_submit",
                    "form_present": True,
                    "input_selector": "input[type=\"email\"]",
                    "submit_selector": "submit",
                }

        page = Page()
        result = asyncio.run(runtime._submit_email_form_stable(page, "user@example.test"))

        self.assertTrue(result["ok"])
        self.assertTrue(result["form_present"])
        self.assertEqual(page.arguments, {"email": "user@example.test"})
        self.assertIn("closest('form')", page.script)
        self.assertIn("google|apple", page.script)
        self.assertIn("cssPath", page.script)
        self.assertIn("beforeinput", page.script)
        self.assertNotIn("button:has-text('Continue')", page.script)

    def test_entry_submission_prefers_safe_button_and_waits_for_async_navigation(self):
        stable_result = {
            "ok": True,
            "reason": "form_prepared",
            "form_present": True,
            "input_selector": "#entry-email",
            "submit_selector": "form#entry > button[type='submit']",
        }
        challenge = runtime.CamoufoxBrowserError(
            "free_camoufox_challenge", "等待安全验证", "challenge",
            error_code="challenge",
        )
        with (
            patch.object(runtime.asyncio, "sleep", new=AsyncMock()),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_wait_for_any_selector", new=AsyncMock(return_value="#entry-email")),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)) as stable,
            patch.object(runtime, "_click_visible_submit", new=AsyncMock(return_value=True)) as click_submit,
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)) as enter_submit,
            patch.object(
                runtime, "_page_state",
                new=AsyncMock(side_effect=("entry", "entry", "entry", "entry", "security")),
            ),
            patch.object(runtime, "_browser_signin_url", new=AsyncMock()) as signin,
            patch.object(runtime, "_wait_challenge_then_stop", new=AsyncMock(side_effect=challenge)),
        ):
            with self.assertRaises(runtime.CamoufoxBrowserError):
                asyncio.run(
                    runtime._browser_flow(
                        _EntryPage(), email="user@example.test", password="password",
                        existing_password="saved-account-password",
                        otp_callback=lambda: "", config={"registration_timeout_seconds": 60},
                        log=lambda *_args: None, otp_prepare=Mock(), otp_mark_sent=Mock(),
                    )
                )

        stable.assert_awaited_once()
        click_submit.assert_awaited_once_with(
            ANY, "form#entry > button[type='submit']",
        )
        enter_submit.assert_not_awaited()
        signin.assert_not_awaited()

    def test_entry_submission_click_failure_relocates_input_before_enter(self):
        stable_result = {
            "ok": True,
            "reason": "form_prepared",
            "form_present": True,
            "input_selector": "#stale-email",
            "submit_selector": "#stale-submit",
        }
        wait_selector = AsyncMock(side_effect=("#initial-email", "#fresh-email"))
        challenge = runtime.CamoufoxBrowserError(
            "free_camoufox_challenge", "等待安全验证", "challenge",
            error_code="challenge",
        )
        with (
            patch.object(runtime.asyncio, "sleep", new=AsyncMock()),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_wait_for_any_selector", new=wait_selector),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)),
            patch.object(runtime, "_click_visible_submit", new=AsyncMock(return_value=False)) as click_submit,
            patch.object(runtime, "_fill_input_like_user", new=AsyncMock(return_value=True)) as fill,
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)) as enter_submit,
            patch.object(runtime, "_page_state", new=AsyncMock(return_value="security")),
            patch.object(runtime, "_wait_challenge_then_stop", new=AsyncMock(side_effect=challenge)),
        ):
            with self.assertRaises(runtime.CamoufoxBrowserError):
                asyncio.run(
                    runtime._browser_flow(
                        _EntryPage(), email="user@example.test", password="password",
                        existing_password="saved-account-password",
                        otp_callback=lambda: "", config={"registration_timeout_seconds": 60},
                        log=lambda *_args: None, otp_prepare=Mock(), otp_mark_sent=Mock(),
                    )
                )

        click_submit.assert_awaited_once_with(ANY, "#stale-submit")
        fill.assert_awaited_once_with(ANY, "#fresh-email", "user@example.test")
        enter_submit.assert_awaited_once_with(ANY, "#fresh-email")
        self.assertEqual(wait_selector.await_count, 2)

    def test_unknown_shell_is_polled_until_auth_state_after_entry_submit(self):
        """A transient post-submit shell must not be classified as stuck."""
        stable_result = {
            "ok": True,
            "reason": "form_prepared",
            "form_present": True,
            "input_selector": "#entry-email",
            "submit_selector": "form#entry > button[type='submit']",
        }
        challenge = runtime.CamoufoxBrowserError(
            "free_camoufox_challenge", "等待安全验证", "challenge",
            error_code="challenge",
        )
        with (
            patch.object(runtime.asyncio, "sleep", new=AsyncMock()) as sleep,
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_wait_for_any_selector", new=AsyncMock(return_value="#entry-email")),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)),
            patch.object(runtime, "_click_visible_submit", new=AsyncMock(return_value=False)),
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)),
            patch.object(
                runtime,
                "_page_state",
                new=AsyncMock(side_effect=("unknown", "unknown", "unknown", "unknown", "unknown", "security")),
            ) as page_state,
            patch.object(runtime, "_browser_signin_url", new=AsyncMock()) as signin,
            patch.object(runtime, "_wait_challenge_then_stop", new=AsyncMock(side_effect=challenge)) as stop,
        ):
            with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                asyncio.run(
                    runtime._browser_flow(
                        _EntryPage(), email="user@example.test", password="password",
                        existing_password="saved-account-password",
                        otp_callback=lambda: "", config={"registration_timeout_seconds": 60},
                        log=lambda *_args: None, otp_prepare=Mock(), otp_mark_sent=Mock(),
                    )
                )

        self.assertEqual(raised.exception.error_code, "challenge")
        self.assertEqual(page_state.await_count, 6)
        self.assertGreaterEqual(sleep.await_count, 1)
        stop.assert_awaited_once()
        signin.assert_not_awaited()

    def test_entry_submission_falls_back_to_relocated_input_enter(self):
        stable_result = {
            "ok": False,
            "reason": "stale_email_input",
            "form_present": True,
            "input_selector": "#stale-email",
            "submit_selector": "",
        }
        wait_selector = AsyncMock(side_effect=("#initial-email", "#fresh-email"))
        challenge = runtime.CamoufoxBrowserError(
            "free_camoufox_challenge", "等待安全验证", "challenge",
            error_code="challenge",
        )
        with (
            patch.object(runtime.asyncio, "sleep", new=AsyncMock()),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_wait_for_any_selector", new=wait_selector),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)),
            patch.object(runtime, "_fill_input_like_user", new=AsyncMock(return_value=True)) as fill,
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)) as enter_submit,
            patch.object(runtime, "_page_state", new=AsyncMock(return_value="security")),
            patch.object(runtime, "_wait_challenge_then_stop", new=AsyncMock(side_effect=challenge)),
        ):
            with self.assertRaises(runtime.CamoufoxBrowserError):
                asyncio.run(
                    runtime._browser_flow(
                        _EntryPage(), email="user@example.test", password="password",
                        otp_callback=lambda: "", config={"registration_timeout_seconds": 60},
                        log=lambda *_args: None, otp_prepare=Mock(), otp_mark_sent=Mock(),
                    )
                )

        self.assertEqual(wait_selector.await_count, 2)
        fill.assert_awaited_once_with(ANY, "#fresh-email", "user@example.test")
        enter_submit.assert_awaited_once_with(ANY, "#fresh-email")

    def test_auth_phase_return_to_entry_is_terminal_and_legacy_prepare_is_supported(self):
        stable_result = {
            "ok": True,
            "reason": "form_prepared",
            "form_present": True,
            "input_selector": "#entry-email",
            "submit_selector": "button[type='submit']",
        }
        prepare_calls = []

        def legacy_prepare(stage_code, *, force_snapshot=False):
            prepare_calls.append((stage_code, force_snapshot))

        with (
            patch.object(runtime.asyncio, "sleep", new=AsyncMock()),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_wait_for_any_selector", new=AsyncMock(return_value="#entry-email")),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)) as stable,
            patch.object(runtime, "_click_visible_submit", new=AsyncMock(return_value=True)),
            patch.object(runtime, "_page_state", new=AsyncMock(side_effect=("login_password", "entry"))),
            patch.object(runtime, "_submit_existing_login_password", new=AsyncMock(return_value=True)),
            patch.object(runtime, "_click_first", new=AsyncMock(return_value=True)),
            patch.object(runtime, "_browser_signin_url", new=AsyncMock()) as signin,
        ):
            with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                asyncio.run(
                    runtime._browser_flow(
                        _EntryPage(), email="user@example.test", password="password",
                        existing_password="saved-account-password",
                        otp_callback=lambda: "", config={"registration_timeout_seconds": 60},
                        log=lambda *_args: None, otp_prepare=legacy_prepare, otp_mark_sent=Mock(),
                    )
                )

        self.assertEqual(raised.exception.error_code, "camoufox_entry_returned_after_otp")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(prepare_calls, [
            ("free_email_otp_wait", True),
        ])
        stable.assert_awaited_once()
        signin.assert_not_awaited()

    def test_same_origin_signin_accepts_only_auth_openai_authority(self):
        class Page:
            def __init__(self, url):
                self.url = url

            async def evaluate(self, _script, _arguments):
                return {"ok": True, "url": self.url}

        trusted = "https://auth.openai.com/authorize-start?state=opaque"
        self.assertEqual(
            asyncio.run(runtime._browser_signin_url(Page(trusted), "user@example.test")),
            trusted,
        )
        self.assertEqual(
            asyncio.run(
                runtime._browser_signin_url(
                    Page("https://accounts.google.com/o/oauth2/auth?state=opaque"),
                    "user@example.test",
                )
            ),
            "",
        )

    def test_auth_openai_email_shell_is_not_unknown(self):
        class Page(_FakePage):
            url = "https://auth.openai.com/log-in"

            def locator(self, selector):
                return _FakeLocator(visible="email" in selector)

        self.assertEqual(asyncio.run(runtime._page_state(Page())), "entry")

    def test_entry_recovery_uses_form_then_signin_once_and_preserves_timeout(self):
        class Clock:
            now = 0.0

        async def fast_sleep(seconds):
            Clock.now += max(50.0, float(seconds or 0.0))

        stable_result = {
            "ok": True,
            "reason": "form_request_submit",
            "form_present": True,
            "input_selector": "#entry-email",
            "submit_selector": "submit",
        }
        page = _EntryPage()
        with (
            patch.object(runtime.time, "monotonic", side_effect=lambda: Clock.now),
            patch.object(runtime.asyncio, "sleep", side_effect=fast_sleep),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_click_visible_submit", new=AsyncMock(return_value=False)),
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)) as submit,
            patch.object(
                runtime,
                "_wait_for_any_selector",
                new=AsyncMock(return_value="input[type='email']"),
            ),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)) as stable,
            patch.object(runtime, "_click_exact_button_text", new=AsyncMock(return_value="continue")),
            patch.object(runtime, "_browser_signin_url", new=AsyncMock(return_value="https://auth.openai.com/authorize/test")) as signin,
            patch.object(runtime, "_page_state", new=AsyncMock(return_value="entry")),
            patch.object(runtime, "_auth_error_text", new=AsyncMock(return_value="")),
            patch.object(
                runtime,
                "_snapshot",
                new=AsyncMock(return_value={
                    "url": "https://chatgpt.com/auth/login",
                    "title": "Get started user@example.test",
                    "body": "email=user@example.test",
                }),
            ),
        ):
            with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                asyncio.run(
                    runtime._browser_flow(
                        page,
                        email="user@example.test",
                        password="password",
                        proxy="",
                        otp_callback=lambda: "",
                        config={"registration_timeout_seconds": 1200},
                        log=lambda *_args: None,
                        otp_prepare=Mock(),
                        otp_mark_sent=Mock(),
                    )
                )

        self.assertEqual(raised.exception.error_code, "camoufox_entry_transition_timeout")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(stable.await_count, 2)
        self.assertEqual(submit.await_args_list[0].args[1], "input[type='email']")
        signin.assert_awaited_once_with(page, "user@example.test")
        self.assertIn('"phase": "entry"', raised.exception.diagnostic)
        self.assertIn('"submitted": true', raised.exception.diagnostic)
        self.assertIn('"recovery": "same_origin_signin"', raised.exception.diagnostic)
        self.assertIn('"form_present": true', raised.exception.diagnostic)
        self.assertNotIn("user@example.test", raised.exception.diagnostic)
        self.assertIn("<邮箱>", raised.exception.diagnostic)

    def test_entry_signin_fallback_failure_does_not_consume_otp(self):
        class Clock:
            now = 0.0

        async def fast_sleep(seconds):
            Clock.now += max(50.0, float(seconds or 0.0))

        page = _EntryPage()
        stable_result = {
            "ok": True,
            "reason": "form_request_submit",
            "form_present": True,
            "input_selector": "input[type=\"email\"]",
            "submit_selector": "submit",
        }
        otp_prepare = Mock()
        otp_mark_sent = Mock()
        with (
            patch.object(runtime.time, "monotonic", side_effect=lambda: Clock.now),
            patch.object(runtime.asyncio, "sleep", side_effect=fast_sleep),
            patch.object(runtime, "_goto_with_retry", new=AsyncMock()),
            patch.object(runtime, "_click_visible_submit", new=AsyncMock(return_value=False)),
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)),
            patch.object(
                runtime,
                "_wait_for_any_selector",
                new=AsyncMock(return_value="input[type='email']"),
            ),
            patch.object(runtime, "_submit_email_form_stable", new=AsyncMock(return_value=stable_result)),
            patch.object(runtime, "_click_exact_button_text", new=AsyncMock(return_value="continue")),
            patch.object(runtime, "_browser_signin_url", new=AsyncMock(return_value="")) as signin,
            patch.object(runtime, "_page_state", new=AsyncMock(return_value="entry")),
            patch.object(runtime, "_auth_error_text", new=AsyncMock(return_value="")),
        ):
            with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                asyncio.run(
                    runtime._browser_flow(
                        page,
                        email="user@example.test",
                        password="password",
                        proxy="",
                        otp_callback=lambda: "should-not-run",
                        config={"registration_timeout_seconds": 1200},
                        log=lambda *_args: None,
                        otp_prepare=otp_prepare,
                        otp_mark_sent=otp_mark_sent,
                    )
                )

        self.assertEqual(raised.exception.error_code, "camoufox_entry_signin_fallback_failed")
        self.assertFalse(raised.exception.retryable)
        signin.assert_awaited_once_with(page, "user@example.test")
        otp_mark_sent.assert_not_called()
        self.assertIn('"recovery": "same_origin_signin"', raised.exception.diagnostic)

    def test_missing_browser_runtime_is_explicit(self):
        with patch.object(runtime, "_check_camoufox_runtime", side_effect=runtime.CamoufoxDependencyError("CamoufoxNotInstalled")):
            with self.assertRaises(runtime.CamoufoxDependencyError) as raised:
                runtime.CamoufoxRegistrationRunner.preflight({"camoufox": self._config()})
        self.assertEqual(raised.exception.error_code, "camoufox_dependency_missing")

    def test_pool_init_preserves_nested_camoufox_diagnostic(self):
        nested = runtime.CamoufoxBrowserError(
            "free_camoufox_launch", "启动 Camoufox", "启动失败",
            error_code="camoufox_browser_launch_failed", diagnostic="CamoufoxNotInstalled",
        )
        with patch.object(runtime, "_load_camoufox_api", return_value=(object, object)), patch.object(runtime, "_check_camoufox_runtime", return_value="1"):
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool._closed = False
            pool._ready = threading.Event()
            pool._ready.set()
            pool._init_error = nested
            pool._loop = None
            with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                pool.register(email="user@example.test", password="password", proxy="")
        self.assertIs(raised.exception, nested)
        self.assertEqual(raised.exception.diagnostic, "CamoufoxNotInstalled")

    def test_navigation_429_is_structured_and_not_proxy_retryable(self):
        page = _NavigationPage(status=429, retry_after="17")
        with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
            asyncio.run(runtime._goto_with_diagnostics(page, "https://chatgpt.com/auth/login", timeout_ms=1000, proxy_retryable=True))
        self.assertEqual(raised.exception.node_code, "free_camoufox_navigation")
        self.assertEqual(raised.exception.provider_status, 429)
        self.assertEqual(raised.exception.retry_after_seconds, 17)
        self.assertFalse(getattr(raised.exception, "proxy_retryable", False))

    def test_navigation_proxy_block_is_retryable_only_before_email(self):
        page = _NavigationPage(status=403, body="Access Denied")
        with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
            asyncio.run(runtime._goto_with_diagnostics(page, "https://chatgpt.com/auth/login", timeout_ms=1000, proxy_retryable=True))
        self.assertEqual(raised.exception.error_code, "camoufox_proxy_blocked")
        self.assertTrue(getattr(raised.exception, "proxy_retryable", False))
        page = _NavigationPage(status=403, body="Access Denied")
        with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
            asyncio.run(runtime._goto_with_diagnostics(page, "https://auth.openai.com/authorize", timeout_ms=1000))
        self.assertFalse(getattr(raised.exception, "proxy_retryable", False))

    def test_navigation_cloudflare_403_is_a_stable_challenge(self):
        page = _NavigationPage(status=403, body="Just a moment... Verify you are human")
        with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
            asyncio.run(runtime._goto_with_diagnostics(page, "https://chatgpt.com/auth/login", timeout_ms=1000, proxy_retryable=True))
        self.assertEqual(raised.exception.node_code, "free_camoufox_challenge")
        self.assertEqual(raised.exception.error_code, "free_camoufox_security_challenge")
        self.assertEqual(raised.exception.provider_status, 403)
        self.assertFalse(getattr(raised.exception, "proxy_retryable", False))

    def test_navigation_timeout_keeps_a_usable_login_form(self):
        class Error(Exception):
            pass

        page = _NavigationPage(goto_error=Error("page.goto: Timeout 45000ms exceeded"), email_visible=True)
        result = asyncio.run(
            runtime._goto_with_retry(
                page,
                "https://chatgpt.com/auth/login",
                timeout_ms=1000,
                proxy_retryable=True,
            )
        )
        self.assertIsNone(result)
        self.assertEqual(len(page.goto_calls), 1)

    def test_navigation_timeout_without_form_keeps_safe_category(self):
        page = _NavigationPage(goto_error=TimeoutError("page.goto: Timeout"))
        with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
            asyncio.run(
                runtime._goto_with_retry(
                    page,
                    "https://chatgpt.com/auth/login",
                    timeout_ms=1000,
                    proxy_retryable=True,
                )
            )
        self.assertEqual(raised.exception.error_code, "camoufox_navigation_failed")
        self.assertIn("category=navigation_timeout", raised.exception.diagnostic)
        self.assertNotIn("page.goto: Timeout", raised.exception.diagnostic)
        self.assertTrue(getattr(raised.exception, "proxy_retryable", False))

    def test_firefox_connection_refused_uses_transient_navigation_category(self):
        page = _NavigationPage(
            goto_error=RuntimeError(
                "Page.goto: NS_ERROR_CONNECTION_REFUSED; target URL hidden"
            )
        )
        with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
            asyncio.run(
                runtime._goto_with_retry(
                    page,
                    "https://chatgpt.com/auth/login",
                    timeout_ms=1000,
                    proxy_retryable=True,
                )
            )
        self.assertIn("category=navigation_transient", raised.exception.diagnostic)
        self.assertIn("reason=connection_refused", raised.exception.diagnostic)
        self.assertNotIn("NS_ERROR_CONNECTION_REFUSED", raised.exception.diagnostic)

    def test_browser_process_loss_requests_pool_recycle(self):
        class Error(Exception):
            pass

        page = _NavigationPage(goto_error=Error("browser has been closed"))
        with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
            asyncio.run(
                runtime._goto_with_retry(
                    page,
                    "https://chatgpt.com/auth/login",
                    timeout_ms=1000,
                    proxy_retryable=True,
                )
            )
        self.assertEqual(raised.exception.error_code, "camoufox_browser_disconnected")
        self.assertTrue(getattr(raised.exception, "recycle_required", False))

    def test_context_creation_falls_back_when_fingerprint_helper_rejects_typeerror(self):
        captured = {}

        async def broken_fingerprint(_browser, **_kwargs):
            raise TypeError("old camoufox helper signature")

        class Browser:
            async def new_context(self, **kwargs):
                captured.update(kwargs)
                return "plain-context"

        with patch.object(runtime, "_load_camoufox_api", return_value=(object, broken_fingerprint)):
            result = asyncio.run(runtime._new_context(Browser(), proxy={"server": "http://proxy.test:8080"}))
        self.assertEqual(result, "plain-context")
        self.assertEqual(captured["proxy"]["server"], "http://proxy.test:8080")
        self.assertEqual(captured["service_workers"], "block")

    def test_context_creation_retries_core_options_when_optional_options_are_rejected(self):
        attempts = []

        async def broken_fingerprint(_browser, **_kwargs):
            raise TypeError("fingerprint helper incompatible")

        class Browser:
            async def new_context(self, **kwargs):
                attempts.append(kwargs)
                if "service_workers" in kwargs or "reduced_motion" in kwargs:
                    raise TypeError("optional context option unsupported")
                return "core-context"

        with patch.object(runtime, "_load_camoufox_api", return_value=(object, broken_fingerprint)):
            result = asyncio.run(runtime._new_context(Browser(), proxy={"server": "socks5://proxy.test:1080"}))

        self.assertEqual(result, "core-context")
        self.assertEqual(attempts[-1]["proxy"]["server"], "socks5://proxy.test:1080")
        self.assertNotIn("service_workers", attempts[-1])
        self.assertNotIn("reduced_motion", attempts[-1])

    def test_context_creation_failure_with_proxy_is_proxy_retryable(self):
        async def failing_context(_browser, **_kwargs):
            raise RuntimeError("SOCKS5 proxy connection timed out")

        async def fake_flow(_page, **_kwargs):
            return {"ok": True}

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, failing_context)),
            patch.object(runtime, "_browser_flow", side_effect=fake_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config())
            try:
                with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                    pool.register(
                        email="user@example.test",
                        password="password",
                        proxy="socks5://proxy.example.test:8000",
                    )
            finally:
                pool.shutdown()

        self.assertEqual(raised.exception.error_code, "camoufox_context_create_failed")
        self.assertTrue(getattr(raised.exception, "proxy_retryable", False))

    def test_authenticated_socks5_browser_bridge_uses_loopback_http_proxy(self):
        bridge = Socks5HttpBridge("socks5://user:password@proxy.example.test:8000")
        try:
            self.assertTrue(bridge.proxy_config["server"].startswith("http://127.0.0.1:"))
            self.assertNotIn("user", bridge.proxy_config["server"])
            self.assertNotIn("password", bridge.proxy_config["server"])
        finally:
            bridge.close()

    def test_pool_rebuilds_when_timeout_policy_changes(self):
        class FakePool:
            def __init__(self, config):
                self.config = dict(config)
                self._closed = False
                self.shutdown_called = False

            def shutdown(self):
                self.shutdown_called = True
                self._closed = True

        with runtime._POOL_LOCK:
            runtime._POOLS.clear()
        with patch.object(runtime, "CamoufoxBrowserPool", FakePool):
            try:
                first = runtime._pool_for(self._config())
                second = runtime._pool_for(self._config(context_close_timeout_seconds=2))
            finally:
                runtime.shutdown_camoufox_pools()
        self.assertIsNot(first, second)
        self.assertTrue(first.shutdown_called)

    def test_pool_for_replaces_closed_pool_without_shutdown_pending_error(self):
        class ClosedPool:
            def __init__(self):
                self._closed = True

            def has_debug_sessions(self):
                return False

            def has_active_contexts(self):
                return False

        class FreshPool:
            def __init__(self, config):
                self.config = dict(config)
                self._closed = False

        config = self._config()
        key = runtime._camoufox_pool_key(config)
        old_pool = ClosedPool()
        with runtime._POOL_LOCK:
            previous = dict(runtime._POOLS)
            runtime._POOLS.clear()
            runtime._POOLS[key] = old_pool
        with patch.object(runtime, "CamoufoxBrowserPool", FreshPool):
            try:
                replacement = runtime._pool_for(config)
                self.assertIsInstance(replacement, FreshPool)
                self.assertIsNot(replacement, old_pool)
                self.assertIs(runtime._POOLS[key], replacement)
            finally:
                with runtime._POOL_LOCK:
                    runtime._POOLS.clear()
                    runtime._POOLS.update(previous)

    def test_pool_shutdown_join_budget_scales_with_pool_size(self):
        """Serial slot teardown gets enough time before it is reported pending."""
        class Loop:
            def stop(self):
                return None

            def call_soon_threadsafe(self, callback):
                callback()

        class Thread:
            def __init__(self):
                self.join_timeout = None

            def join(self, *, timeout=None):
                self.join_timeout = timeout

            def is_alive(self):
                return False

        config = self._config(
            pool_size=3,
            context_close_timeout_seconds=2,
            browser_recycle_timeout_seconds=4,
            browser_recycle_drain_timeout_seconds=1,
        )
        pool = object.__new__(runtime.CamoufoxBrowserPool)
        pool.config = config
        pool._closed = False
        pool._lock = threading.Lock()
        pool._debug_lock = threading.RLock()
        pool._debug_sessions = {}
        pool._slots = []
        pool._loop = Loop()
        pool._thread = Thread()
        pool._shutdown_complete = threading.Event()

        self.assertTrue(pool.shutdown())
        self.assertGreaterEqual(
            pool._thread.join_timeout,
            runtime._pool_shutdown_wait_budget(config),
        )
        self.assertGreaterEqual(pool._thread.join_timeout, 3 * (4 + 2))

    def test_pool_for_detaches_shutdown_pool_before_creating_replacement(self):
        """A shutdown-in-flight pool cannot block a fresh registration pool."""
        class TrackingEvent(threading.Event):
            def __init__(self):
                super().__init__()
                self.timeout_seen = None

            def wait(self, timeout=None):
                self.timeout_seen = timeout
                return False

        class ClosedPool:
            def __init__(self, config):
                self.config = dict(config)
                self._closed = True
                self._shutdown_complete = TrackingEvent()

            def has_debug_sessions(self):
                return False

            def has_active_contexts(self):
                return False

        config = self._config(
            pool_size=3,
            context_close_timeout_seconds=2,
            browser_recycle_timeout_seconds=4,
            browser_recycle_drain_timeout_seconds=1,
        )
        key = runtime._camoufox_pool_key(config)
        old_pool = ClosedPool(config)
        with runtime._POOL_LOCK:
            previous = dict(runtime._POOLS)
            runtime._POOLS.clear()
            runtime._POOLS[key] = old_pool
        replacement = object()
        with patch.object(runtime, "CamoufoxBrowserPool", return_value=replacement) as pool_constructor:
            try:
                result = runtime._pool_for(config)
                registry_result = runtime._POOLS.get(key)
            finally:
                with runtime._POOL_LOCK:
                    runtime._POOLS.clear()
                    runtime._POOLS.update(previous)
        self.assertIs(result, replacement)
        self.assertIs(registry_result, replacement)
        self.assertIsNone(old_pool._shutdown_complete.timeout_seen)
        pool_constructor.assert_called_once_with(config)

    def test_pool_for_detaches_obsolete_closed_pool_before_new_identity(self):
        """A settings change can create a new pool while old cleanup drains."""
        class ClosedPool:
            def __init__(self, config):
                self.config = dict(config)
                self._closed = True

            def has_debug_sessions(self):
                return False

            def has_active_contexts(self):
                return False

        old_config = self._config(pool_size=2, context_close_timeout_seconds=1)
        new_config = self._config(pool_size=2, context_close_timeout_seconds=2)
        old_key = runtime._camoufox_pool_key(old_config)
        new_key = runtime._camoufox_pool_key(new_config)
        self.assertNotEqual(old_key, new_key)
        old_pool = ClosedPool(old_config)
        with runtime._POOL_LOCK:
            previous = dict(runtime._POOLS)
            runtime._POOLS.clear()
            runtime._POOLS[old_key] = old_pool
        replacement = object()
        with patch.object(runtime, "CamoufoxBrowserPool", return_value=replacement) as constructor:
            try:
                result = runtime._pool_for(new_config)
            finally:
                with runtime._POOL_LOCK:
                    runtime._POOLS.clear()
                    runtime._POOLS.update(previous)
        self.assertIs(result, replacement)
        constructor.assert_called_once_with(new_config)

    def test_admission_waits_until_all_recycling_slots_are_released(self):
        """A locked recycler must not be selected as an apparently idle slot."""
        async def exercise():
            class Browser:
                @staticmethod
                def is_connected():
                    return True

            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.config = self._config(context_close_timeout_seconds=0.1)
            pool.max_contexts = 1
            pool.context_start_interval = 0
            pool._context_start_lock = None
            pool._startup_semaphore = None
            pool._admission_lock = asyncio.Lock()
            pool._closed = False
            pool._slots = []

            slots = []
            for index in range(2):
                slot = runtime._BrowserSlot(
                    manager=None,
                    browser=Browser(),
                    semaphore=asyncio.Semaphore(1),
                    recycle_lock=asyncio.Lock(),
                    idle_event=asyncio.Event(),
                    draining=index == 0,
                )
                slot.idle_event.set()
                await slot.recycle_lock.acquire()
                slots.append(slot)
            pool._slots = slots

            async def release_recyclers():
                await asyncio.sleep(0.05)
                for slot in slots:
                    slot.draining = False
                    slot.recycle_lock.release()

            releaser = asyncio.create_task(release_recyclers())
            try:
                with (
                    patch.object(runtime, "_new_context", new=AsyncMock(return_value=_FakeContext())),
                    patch.object(runtime, "_browser_flow", new=AsyncMock(return_value={"ok": True})),
                    patch.object(runtime, "_close_context_safely", new=AsyncMock(return_value=True)),
                ):
                    started = time.monotonic()
                    result = await asyncio.wait_for(
                        pool._register_with_slot_once({"proxy": ""}),
                        timeout=1.0,
                    )
                    elapsed = time.monotonic() - started
            finally:
                await releaser

            self.assertTrue(result["ok"])
            self.assertGreaterEqual(elapsed, 0.04)

        asyncio.run(exercise())

    def test_pool_closes_context_and_recycles_after_registration_limit(self):
        async def fake_flow(_page, **_kwargs):
            return {"ok": True, "account_flow": "signup"}

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, _fake_context)),
            patch.object(runtime, "_browser_flow", side_effect=fake_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config(max_registrations_per_browser=1))
            try:
                result = pool.register(email="user@example.test", password="password", proxy="http://proxy")
            finally:
                pool.shutdown()

        self.assertTrue(result["ok"])
        self.assertGreaterEqual(len(_FakeManager.instances), 2)
        self.assertTrue(all(item.entered == 1 and item.exited == 1 for item in _FakeManager.instances))

    def test_recycle_launch_failure_is_reported_on_next_registration(self):
        class FailingRecycleManager(_FakeManager):
            enters = 0

            async def __aenter__(self):
                type(self).enters += 1
                if type(self).enters == 2:
                    raise RuntimeError("synthetic launch failure")
                return await super().__aenter__()

        async def fake_flow(_page, **_kwargs):
            return {"ok": True}

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(FailingRecycleManager, _fake_context)),
            patch.object(runtime, "_browser_flow", side_effect=fake_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config(max_registrations_per_browser=1))
            try:
                self.assertTrue(pool.register(email="one@example.test", password="password", proxy="")["ok"])
                with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                    pool.register(email="two@example.test", password="password", proxy="")
            finally:
                pool.shutdown()
        self.assertEqual(raised.exception.error_code, "camoufox_browser_recycle_failed")
        self.assertIn("camoufox_browser_launch_failed", raised.exception.diagnostic)

    def test_context_close_failure_recycles_browser_without_masking_result(self):
        _FakeManager.context_close_error = RuntimeError("context close failed")

        async def fake_flow(_page, **_kwargs):
            return {"ok": True, "account_flow": "signup"}

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, _fake_context)),
            patch.object(runtime, "_browser_flow", side_effect=fake_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config())
            try:
                result = pool.register(email="user@example.test", password="password", proxy="")
            finally:
                pool.shutdown()

        self.assertTrue(result["ok"])
        self.assertGreaterEqual(len(_FakeManager.instances), 2)

    def test_browser_flow_error_returns_safe_structured_diagnostic(self):
        async def failing_flow(_page, **_kwargs):
            raise ValueError("private page detail")

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, _fake_context)),
            patch.object(runtime, "_browser_flow", side_effect=failing_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config())
            try:
                with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                    pool.register(email="user@example.test", password="password", proxy="")
            finally:
                pool.shutdown()

        self.assertEqual(raised.exception.node_code, "free_camoufox_browser")
        self.assertEqual(raised.exception.error_code, "camoufox_browser_flow_failed")
        self.assertNotIn("private page detail", raised.exception.diagnostic)
        self.assertEqual(raised.exception.safe_page, "https://chatgpt.com/auth/login")

    def test_generic_camoufox_browser_failure_does_not_restore_mailbox(self):
        # The broad compatibility node is also used after OTP/profile actions;
        # only an explicitly pre-context launch error may restore the row.
        post_email = runtime.FreeRegisterError(
            "free_camoufox_browser", "Camoufox 注册页面", "流程失败",
            error_code="camoufox_browser_flow_failed",
        )
        disconnected_during_navigation = runtime.FreeRegisterError(
            "free_camoufox_launch", "启动 Camoufox", "浏览器断开",
            error_code="camoufox_browser_disconnected",
        )
        pre_context = runtime.FreeRegisterError(
            "free_camoufox_launch", "启动 Camoufox", "context 创建失败",
            error_code="camoufox_context_create_failed",
        )
        self.assertFalse(
            FreeRegisterManager._can_reuse_mailbox_after_failure(
                post_email.node_code, post_email,
            )
        )
        self.assertFalse(
            FreeRegisterManager._can_reuse_mailbox_after_failure(
                disconnected_during_navigation.node_code,
                disconnected_during_navigation,
            )
        )
        self.assertTrue(
            FreeRegisterManager._can_reuse_mailbox_after_failure(
                pre_context.node_code, pre_context,
            )
        )

    def test_debug_helpers_redact_encoded_urls_and_untrusted_paths(self):
        encoded = "https://chatgpt.com/auth/callback/%75ser%40example.com?code=654321&state=opaque"
        safe = runtime._safe_event_url(encoded)
        self.assertNotIn("user@example.com", safe)
        self.assertNotIn("654321", safe)
        self.assertIn("<已隐藏>", safe)
        self.assertEqual(runtime._safe_event_url("https://evil.example/a/opaque-token"), "https://evil.example/[路径已隐藏]")

    def test_debug_helper_redacts_nested_encoded_query_values(self):
        safe = runtime._safe_event_url(
            "https://chatgpt.com/x/%2525253Ftoken%2525253Dsecret-value"
        )
        self.assertNotIn("secret-value", safe)
        self.assertNotIn("token", safe.casefold())
        self.assertIn("<已隐藏>", safe)

    def test_debug_text_redacts_all_short_numeric_otps_without_erasing_security_labels(self):
        raw = "Security challenge required; codes: 1234 12345 123456 1234567"
        safe = runtime._sanitize_debug_text(raw)
        for code in ("1234", "12345", "123456", "1234567"):
            self.assertNotIn(code, safe)
        self.assertIn("Security challenge required", safe)

    def test_debug_text_redacts_common_alphanumeric_otps_but_keeps_status_identifiers(self):
        raw = "Verification code A1B2C3; OTP AB1234; HTTP403; Version v2024"
        safe = runtime._sanitize_debug_text(raw)
        for code in ("A1B2C3", "AB1234"):
            self.assertNotIn(code, safe)
        self.assertIn("Verification code", safe)
        self.assertIn("HTTP403", safe)
        self.assertIn("Version v2024", safe)

    def test_debug_text_redacts_grouped_alphanumeric_otps(self):
        raw = "Verification code A1-B2-C3; code 12 34 56; HTTP 403"
        safe = runtime._sanitize_debug_text(raw)
        for code in ("A1-B2-C3", "12 34 56"):
            self.assertNotIn(code, safe)
        self.assertIn("Verification code", safe)
        self.assertIn("HTTP 403", safe)

    def test_debug_trace_and_dom_do_not_persist_short_or_alphanumeric_otps(self):
        class OtpPage(_FakePage):
            async def evaluate(self, _script):
                return {
                    "title": "Security challenge 12345",
                    "url": self.url,
                    "elements": [{
                        "tag": "p",
                        "role": "status",
                        "aria_label": "Verification code A1B2C3",
                        "text": "Enter code 1234 or AB1234",
                        "href": "https://chatgpt.com/auth/verify/1234567",
                    }],
                }

        async def exercise():
            page = OtpPage()
            trace = runtime._DebugTrace()
            trace.add("console", text="OTP 12345 / K4P9X2; security challenge")
            dom = await runtime._capture_debug_dom(page)
            return trace.snapshot(), dom

        events, dom = asyncio.run(exercise())
        serialized = json.dumps({"events": events, "dom": dom}, ensure_ascii=False)
        for code in ("12345", "K4P9X2", "1234", "AB1234", "1234567", "A1B2C3"):
            self.assertNotIn(code, serialized)
        self.assertIn("security challenge", serialized)
        self.assertIn("Verification code", serialized)

    def test_debug_url_redacts_short_numeric_and_alphanumeric_otp_path_segments(self):
        for suffix in ("1234", "12345", "1234567", "A1B2C3"):
            safe = runtime._safe_event_url(f"https://chatgpt.com/auth/verify/{suffix}")
            self.assertNotIn(suffix, safe)
            self.assertIn("<验证码>", safe)

    def test_screenshot_safety_scans_the_complete_body_not_short_snapshot(self):
        class LongBodyPage(_FakePage):
            def locator(self, selector):
                if selector == "body":
                    class BodyLocator:
                        async def inner_text(self, **_kwargs):
                            return "x" * 2000 + " hidden@example.com"
                    return BodyLocator()
                return _FakeLocator()

        safe, reason = asyncio.run(runtime._screenshot_safety_check(LongBodyPage()))
        self.assertFalse(safe)
        self.assertIn("敏感", reason)

    def test_debug_artifact_summary_projects_only_safe_fields(self):
        class SafePage(_FakePage):
            async def evaluate(self, _script):
                return {"title": "ChatGPT", "url": self.url, "elements": []}

        trace = runtime._DebugTrace()
        trace.add("console", text='{"accessToken":"secret"}')
        with tempfile.TemporaryDirectory() as artifact_root:
            result = asyncio.run(runtime._capture_debug_artifact(
                page=SafePage(),
                artifact_root=Path(artifact_root),
                session_id="cam-debug-abcdef123456",
                artifact_id="cam-artifact-abcdef123456",
                summary={
                    "task_id": "task-1",
                    "node_label": "失败 user@example.com",
                    "created_at": 1_700_000_000,
                    "raw_response": "must-not-be-written",
                },
                trace=trace,
            ))
            payload = json.loads(Path(artifact_root, "cam-debug-abcdef123456", "summary.json").read_text())
            self.assertEqual(result["artifact_id"], "cam-artifact-abcdef123456")
            self.assertNotIn("raw_response", payload)
            self.assertNotIn("user@example.com", json.dumps(payload))
            self.assertNotIn("secret", json.dumps(payload))

    def test_debug_proxy_fingerprint_accepts_only_fixed_hex(self):
        self.assertEqual(runtime._safe_proxy_fingerprint("A" * 16, "secret-proxy"), "a" * 16)
        expected = runtime.fingerprint("secret-proxy")
        self.assertEqual(runtime._safe_proxy_fingerprint("not-a-fingerprint", "secret-proxy"), expected)

    def test_business_failure_retains_debug_context_and_writes_redacted_artifact(self):
        class DebugPage(_FakePage):
            url = "https://chatgpt.com/auth/login?private=1"

            def is_closed(self):
                return False

            async def evaluate(self, _script):
                return {
                    "title": "ChatGPT",
                    "url": self.url,
                    "elements": [{
                        "tag": "input",
                        "text": "Email",
                        "href": "https://chatgpt.com/auth/login?private=1",
                    }],
                }

            async def screenshot(self, **_kwargs):
                raise RuntimeError("screenshot unavailable in test double")

        class DebugContext(_FakeContext):
            async def new_page(self):
                return DebugPage()

        async def debug_context(_browser, **_kwargs):
            return DebugContext()

        async def failing_flow(_page, **_kwargs):
            raise ValueError("private page detail")

        with (
            tempfile.TemporaryDirectory() as artifact_root,
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, debug_context)),
            patch.object(runtime, "_browser_flow", side_effect=failing_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config(_debug_artifact_dir=artifact_root))
            try:
                with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                    pool.register(email="user@example.test", password="password", proxy="")

                failure = raised.exception
                session_id = str(getattr(failure, "debug_session_id", ""))
                artifact_id = str(getattr(failure, "debug_artifact_id", ""))
                self.assertTrue(session_id)
                self.assertTrue(artifact_id)
                state = pool.debug_state()
                self.assertEqual(state["open_contexts"], 1)
                self.assertEqual(state["used"], 1)
                self.assertFalse(state["headless"])
                self.assertEqual(state["sessions"][0]["session_id"], session_id)
                self.assertEqual(state["sessions"][0]["artifact_id"], artifact_id)

                artifact_dir = Path(artifact_root) / session_id
                summary = json.loads((artifact_dir / "summary.json").read_text(encoding="utf-8"))
                dom = json.loads((artifact_dir / "dom.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["artifact_id"], artifact_id)
                self.assertEqual(summary["safe_page"], "https://chatgpt.com/auth/login")
                self.assertEqual(dom["url"], "https://chatgpt.com/auth/login")
                self.assertEqual(dom["elements"][0]["href"], "https://chatgpt.com/auth/login")
                self.assertEqual(summary["screenshot"], "skipped")
                self.assertNotIn("private=1", json.dumps({"summary": summary, "dom": dom}))

                self.assertEqual(pool.close_debug_sessions(session_id), 1)
                self.assertEqual(pool.debug_state()["open_contexts"], 0)
            finally:
                pool.close_debug_sessions()
                pool.shutdown(force=True)

    def test_registration_timeout_cancels_flow_and_recycles_process(self):
        async def stuck_flow(_page, **_kwargs):
            await asyncio.Event().wait()

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, _fake_context)),
            patch.object(runtime, "_browser_flow", side_effect=stuck_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config(registration_timeout_seconds=0.05))
            try:
                with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                    pool.register(email="user@example.test", password="password", proxy="")
            finally:
                pool.shutdown()

        self.assertEqual(raised.exception.error_code, "camoufox_registration_timeout")
        self.assertGreaterEqual(len(_FakeManager.instances), 2)
        self.assertTrue(all(item.exited == 1 for item in _FakeManager.instances))

    def test_shutdown_drains_running_registration_before_stopping_loop(self):
        """Pool shutdown must not stop the loop underneath a live task."""
        started = threading.Event()
        errors: list[BaseException] = []

        async def stuck_flow(_page, **_kwargs):
            started.set()
            await asyncio.Event().wait()

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, _fake_context)),
            patch.object(runtime, "_browser_flow", side_effect=stuck_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config(registration_timeout_seconds=30))

            def register() -> None:
                try:
                    pool.register(email="user@example.test", password="password", proxy="")
                except BaseException as exc:  # noqa: BLE001 - assert structured cancellation below
                    errors.append(exc)

            worker = threading.Thread(target=register, daemon=True)
            worker.start()
            self.assertTrue(started.wait(timeout=2))
            try:
                self.assertTrue(pool.shutdown(force=True))
            finally:
                worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertTrue(pool._shutdown_complete.is_set())
        self.assertTrue(errors)
        self.assertIsInstance(errors[0], runtime.CamoufoxBrowserError)
        self.assertIn(
            errors[0].error_code,
            {"camoufox_pool_closed", "camoufox_registration_cancelled"},
        )
        self.assertTrue(all(item.exited == 1 for item in _FakeManager.instances))

    def test_browser_disconnect_cancellation_is_structured_and_not_a_proxy_failure(self):
        """A Playwright cancellation after process exit keeps its browser node."""
        pool_holder = {}

        async def disconnected_flow(_page, **_kwargs):
            pool = pool_holder["pool"]
            slot = pool._slots[0]
            slot.disconnect_requested = True
            slot.browser.closed = True
            raise asyncio.CancelledError()

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, _fake_context)),
            patch.object(runtime, "_browser_flow", side_effect=disconnected_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config())
            pool_holder["pool"] = pool
            try:
                with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                    pool.register(email="user@example.test", password="password", proxy="")
            finally:
                pool.shutdown(force=True)

        self.assertEqual(raised.exception.error_code, "camoufox_browser_disconnected")
        self.assertEqual(raised.exception.node_code, "free_camoufox_launch")
        self.assertEqual(raised.exception.diagnostic.split("; ")[0], "cancellation_source=browser_disconnect")
        self.assertFalse(getattr(raised.exception, "safe_restart", True))

    def test_unclassified_async_cancellation_is_structured_at_sync_boundary(self):
        """A caller cancellation is not exposed as concurrent.futures.CancelledError."""
        async def cancelled_flow(_page, **_kwargs):
            raise asyncio.CancelledError()

        with (
            patch.object(runtime, "_load_camoufox_api", return_value=(_FakeManager, _fake_context)),
            patch.object(runtime, "_browser_flow", side_effect=cancelled_flow),
        ):
            pool = runtime.CamoufoxBrowserPool(self._config())
            try:
                with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                    pool.register(email="user@example.test", password="password", proxy="")
            finally:
                pool.shutdown(force=True)

        self.assertEqual(raised.exception.error_code, "camoufox_registration_cancelled")
        self.assertEqual(raised.exception.node_code, "free_camoufox_browser")
        self.assertEqual(raised.exception.diagnostic, "cancellation_source=registration_future")
        self.assertFalse(getattr(raised.exception, "safe_restart", True))

    def test_home_confirmation_timeout_does_not_retain_debug_context(self):
        error = runtime.CamoufoxBrowserError(
            "free_camoufox_page_state", "确认 ChatGPT 登录首页", "timeout",
            error_code="camoufox_home_not_confirmed",
        )
        self.assertFalse(runtime.CamoufoxBrowserPool._debug_retain_allowed(error))

    def test_slot_admission_reserves_capacity_atomically_with_debug_holds(self):
        """Concurrent waiters cannot overbook capacity released by debug holds."""
        async def exercise():
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.max_contexts = 2
            pool._admission_lock = asyncio.Lock()
            slot = runtime._BrowserSlot(
                manager=None,
                browser=None,
                # A retained debug context has already returned the task
                # semaphore, so its value can exceed the remaining capacity.
                semaphore=asyncio.Semaphore(2),
                idle_event=asyncio.Event(),
                debug_holds=1,
            )
            slot.idle_event.set()
            permits = await asyncio.gather(
                pool._acquire_slot_permit(slot),
                pool._acquire_slot_permit(slot),
            )
            admitted = [permit for permit in permits if permit is not None]
            self.assertEqual(len(admitted), 1)
            self.assertEqual(slot.active_contexts, 1)
            self.assertEqual(slot.active_contexts + slot.debug_holds, pool.max_contexts)
            for permit in admitted:
                await pool._release_active_context(slot, debug_retained=False)
                await permit.__aexit__(None, None, None)
            self.assertEqual(slot.active_contexts, 0)
            self.assertEqual(slot.semaphore._value, 2)

        asyncio.run(exercise())

    def test_slot_admission_rejects_a_slot_that_started_draining(self):
        """A recycle that wins after selection cannot admit new work."""
        async def exercise():
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.max_contexts = 1
            pool._admission_lock = asyncio.Lock()
            slot = runtime._BrowserSlot(
                manager=None,
                browser=None,  # compatibility callers may omit a browser double
                semaphore=asyncio.Semaphore(1),
                idle_event=asyncio.Event(),
                draining=True,
            )
            slot.idle_event.set()
            permit = await pool._acquire_slot_permit(slot)
            self.assertIsNone(permit)
            self.assertEqual(slot.active_contexts, 0)
            self.assertEqual(slot.semaphore._value, 1)

        asyncio.run(exercise())

    def test_browser_disconnect_after_admission_releases_active_context(self):
        """A disconnect observed after admission must not strand a slot."""
        class FlappingBrowser:
            def __init__(self):
                self.calls = 0

            def is_connected(self):
                self.calls += 1
                return self.calls == 1

        async def exercise():
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.max_contexts = 1
            pool._admission_lock = asyncio.Lock()
            pool._closed = False
            pool.config = self._config()
            browser = FlappingBrowser()
            slot = runtime._BrowserSlot(
                manager=None,
                browser=browser,
                semaphore=asyncio.Semaphore(1),
                recycle_lock=asyncio.Lock(),
                idle_event=asyncio.Event(),
            )
            slot.idle_event.set()
            pool._slots = [slot]
            with patch.object(pool, "_recycle_slot", new=AsyncMock()) as recycle:
                with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                    await pool._register_with_slot_once({"proxy": ""})
            self.assertEqual(raised.exception.error_code, "camoufox_browser_disconnected")
            self.assertEqual(slot.active_contexts, 0)
            self.assertFalse(slot.semaphore.locked())
            self.assertTrue(slot.idle_event.is_set())
            recycle.assert_awaited_once()

        asyncio.run(exercise())

    def test_closed_debug_context_removes_session_when_bridge_cleanup_fails(self):
        """Bridge shutdown errors do not leave a phantom debug capacity hold."""
        class Bridge:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True
                raise RuntimeError("bridge thread already stopped")

        async def exercise():
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.config = self._config()
            pool._admission_lock = asyncio.Lock()
            pool._debug_lock = threading.RLock()
            pool._debug_sessions = {}
            pool._debug_closing = set()
            slot = runtime._BrowserSlot(
                manager=None,
                browser=None,
                semaphore=asyncio.Semaphore(1),
                debug_holds=1,
            )
            context = _FakeContext()
            bridge = Bridge()
            session = runtime._DebugSession(
                session_id="cam-debug-abcdef123456",
                task_id="task-1",
                context=context,
                page=_FakePage(),
                proxy_bridge=bridge,
                slot=slot,
                created_at=1.0,
                trace=runtime._DebugTrace(),
            )
            pool._debug_sessions[session.session_id] = session
            closed = await pool._close_debug_sessions_async(session.session_id)
            self.assertEqual(closed, 1)
            self.assertTrue(context.closed)
            self.assertTrue(bridge.closed)
            self.assertEqual(pool._debug_sessions, {})
            self.assertEqual(slot.debug_holds, 0)

        asyncio.run(exercise())

    def test_close_last_debug_context_recycles_browser_at_registration_limit(self):
        async def exercise():
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.config = self._config(max_registrations_per_browser=1)
            pool._admission_lock = asyncio.Lock()
            pool._debug_lock = threading.RLock()
            pool._debug_sessions = {}
            pool._debug_closing = set()
            pool._closed = False
            slot = runtime._BrowserSlot(
                manager=None,
                browser=None,
                semaphore=asyncio.Semaphore(1),
                debug_holds=1,
                completed=1,
            )
            session = runtime._DebugSession(
                session_id="cam-debug-abcdef123456",
                task_id="task-1",
                context=_FakeContext(),
                page=_FakePage(),
                proxy_bridge=None,
                slot=slot,
                created_at=1.0,
            )
            pool._debug_sessions[session.session_id] = session
            with patch.object(pool, "_recycle_slot", new=AsyncMock()) as recycle:
                closed = await pool._close_debug_sessions_async(session.session_id)
            self.assertEqual(closed, 1)
            recycle.assert_awaited_once_with(
                slot, slot.generation, "关闭最后 Camoufox 调试窗口后回收浏览器",
            )

        asyncio.run(exercise())

    def test_close_all_debug_timeout_budget_scales_with_sessions_and_slots(self):
        """close-all waits for every context and any final slot recycle."""
        pool = object.__new__(runtime.CamoufoxBrowserPool)
        pool.config = self._config(
            context_close_timeout_seconds=2,
            browser_recycle_timeout_seconds=3,
            browser_recycle_drain_timeout_seconds=4,
        )
        pool._debug_lock = threading.RLock()
        pool._debug_sessions = {}
        pool._debug_closing = set()
        slots = [
            runtime._BrowserSlot(
                manager=None,
                browser=None,
                semaphore=asyncio.Semaphore(1),
            )
            for _ in range(2)
        ]
        for index in range(3):
            slot = slots[index % 2]
            session_id = f"cam-debug-{index + 1:012x}"
            pool._debug_sessions[session_id] = runtime._DebugSession(
                session_id=session_id,
                task_id=f"task-{index}",
                context=_FakeContext(),
                page=_FakePage(),
                proxy_bridge=None,
                slot=slot,
                created_at=1.0,
            )

        budget = pool._debug_close_timeout_budget()
        expected = (3 * 2) + (2 * (4 + (2 * 3) + 2)) + 5
        self.assertGreaterEqual(budget, expected)
        self.assertGreater(budget, 2 + 5)  # not the old single-context bound
        self.assertLessEqual(
            pool._debug_close_timeout_budget("cam-debug-000000000001"),
            budget,
        )

    def test_close_debug_timeout_drains_before_cancelling_future(self):
        """A cross-thread timeout leaves async cleanup a bounded final chance."""
        pool = object.__new__(runtime.CamoufoxBrowserPool)
        pool.config = self._config(
            context_close_timeout_seconds=1,
            browser_recycle_timeout_seconds=2,
            browser_recycle_drain_timeout_seconds=3,
        )
        pool._closed = False
        pool._init_error = None
        pool._loop = object()
        pool._ready = threading.Event()
        pool._ready.set()
        pool._debug_lock = threading.RLock()
        pool._debug_sessions = {}
        pool._debug_closing = set()

        class Future:
            def __init__(self):
                self.timeouts = []
                self.cancel_calls = 0

            def result(self, timeout=None):
                self.timeouts.append(timeout)
                raise runtime.FutureTimeoutError()

            def cancel(self):
                self.cancel_calls += 1
                return True

        future = Future()

        def submit(coro, _loop):
            # The fake executor does not own the coroutine; close it to avoid
            # an unawaited-coroutine warning while testing the sync facade.
            coro.close()
            return future

        with patch.object(runtime.asyncio, "run_coroutine_threadsafe", side_effect=submit):
            with self.assertRaises(runtime.CamoufoxBrowserError) as raised:
                pool.register(email="user@example.test")

        self.assertEqual(raised.exception.error_code, "camoufox_registration_timeout")
        self.assertEqual(len(future.timeouts), 2)
        self.assertGreater(future.timeouts[0], future.timeouts[1])
        self.assertEqual(future.cancel_calls, 1)

    def test_release_skips_debug_hold_when_close_removed_session_first(self):
        """Closing a page between retention and release cannot orphan capacity."""
        async def exercise():
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool._admission_lock = asyncio.Lock()
            pool._debug_lock = threading.RLock()
            pool._debug_sessions = {}
            pool._debug_closing = set()
            slot = runtime._BrowserSlot(
                manager=None,
                browser=None,
                semaphore=asyncio.Semaphore(1),
                idle_event=asyncio.Event(),
            )
            context = _FakeContext()
            # The close coroutine has already removed the session and hold;
            # the worker's finally block must not add it back.
            await pool._release_active_context(
                slot,
                debug_retained=True,
                debug_context=context,
            )
            self.assertEqual(slot.active_contexts, 0)
            self.assertEqual(slot.debug_holds, 0)

        asyncio.run(exercise())

    def test_recycle_rechecks_debug_holds_after_drain_wait(self):
        """A hold created during drain prevents old-browser teardown."""
        async def exercise():
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.config = self._config(browser_recycle_drain_timeout_seconds=1)
            pool._closed = False
            pool._admission_lock = asyncio.Lock()
            pool._slots = []

            class Manager:
                def __init__(self):
                    self.exit_calls = 0

                async def __aexit__(self, *_args):
                    self.exit_calls += 1

            manager = Manager()
            slot = runtime._BrowserSlot(
                manager=manager,
                browser=Mock(),
                semaphore=asyncio.Semaphore(1),
                recycle_lock=asyncio.Lock(),
                idle_event=None,
                active_contexts=1,
            )
            slot.browser.is_connected.return_value = True

            class DrainEvent:
                async def wait(self):
                    # Simulate another terminal worker retaining a page while
                    # the recycler awaits the active context to drain.
                    slot.debug_holds = 1
                    slot.active_contexts = 0

            slot.idle_event = DrainEvent()
            await pool._recycle_slot(slot, slot.generation, "test")
            self.assertFalse(slot.draining)
            self.assertEqual(manager.exit_calls, 0)

        asyncio.run(exercise())

    def test_recycle_cancellation_restores_slot_admission_state(self):
        async def exercise():
            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.config = self._config(browser_recycle_drain_timeout_seconds=30)
            pool._closed = False
            pool._admission_lock = asyncio.Lock()
            browser = Mock()
            browser.is_connected.return_value = True
            manager = Mock()
            slot = runtime._BrowserSlot(
                manager=manager,
                browser=browser,
                semaphore=asyncio.Semaphore(1),
                recycle_lock=asyncio.Lock(),
                idle_event=asyncio.Event(),
                active_contexts=1,
            )
            task = asyncio.create_task(pool._recycle_slot(slot, slot.generation, "test"))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(slot.draining)
            self.assertIs(slot.browser, browser)
            self.assertIs(slot.manager, manager)
            self.assertEqual(slot.generation, 0)

        asyncio.run(exercise())

    def test_debug_retention_rejects_slot_changed_during_artifact_capture(self):
        """A stale page cannot become a hold on a replaced/draining slot."""
        async def exercise():
            class Browser:
                def __init__(self):
                    self.connected = True

                def is_connected(self):
                    return self.connected

            class Page:
                url = "https://chatgpt.com/auth/login"

                def is_closed(self):
                    return False

            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.debug_mode = True
            pool._closed = False
            pool.config = {}
            pool._admission_lock = asyncio.Lock()
            pool._debug_lock = threading.RLock()
            pool._debug_sessions = {}
            pool._debug_closing = set()
            browser = Browser()
            slot = runtime._BrowserSlot(
                manager=object(),
                browser=browser,
                semaphore=asyncio.Semaphore(1),
                generation=3,
                idle_event=asyncio.Event(),
            )
            pool._slots = [slot]
            capture_started = asyncio.Event()
            capture_release = asyncio.Event()

            async def capture(**_kwargs):
                capture_started.set()
                await capture_release.wait()
                return {"artifact_path": ""}

            error = runtime.CamoufoxBrowserError(
                "free_camoufox_browser", "Camoufox 注册页面", "failure",
                error_code="camoufox_auth_page_error",
            )
            with patch.object(runtime, "_capture_debug_artifact", side_effect=capture):
                task = asyncio.create_task(pool._retain_debug_context(
                    context=object(), page=Page(), proxy_bridge=None,
                    slot=slot, kwargs={}, error=error,
                ))
                await capture_started.wait()
                # Simulate the recycler winning while the diagnostic dump is in
                # flight.  Either generation or draining is sufficient to
                # reject the stale registration; exercise both guards.
                slot.generation += 1
                slot.draining = True
                browser.connected = False
                capture_release.set()
                retained = await task

            self.assertFalse(retained)
            self.assertEqual(pool._debug_sessions, {})
            self.assertEqual(slot.debug_holds, 0)

        asyncio.run(exercise())

    def test_recycle_cancellation_closes_detached_old_manager(self):
        """Cancellation after detach must not leak the old browser process."""
        async def exercise():
            class BlockingManager:
                def __init__(self):
                    self.started = asyncio.Event()
                    self.calls = 0

                async def __aexit__(self, *_args):
                    self.calls += 1
                    self.started.set()
                    await asyncio.Event().wait()

            class Browser:
                def __init__(self):
                    self.closed = False

                def is_connected(self):
                    return True

                async def close(self):
                    self.closed = True

            pool = object.__new__(runtime.CamoufoxBrowserPool)
            pool.config = self._config(
                browser_recycle_drain_timeout_seconds=1,
                browser_recycle_timeout_seconds=0.1,
                context_close_timeout_seconds=0.1,
            )
            pool._closed = False
            pool._admission_lock = asyncio.Lock()
            pool._slots = []
            manager = BlockingManager()
            browser = Browser()
            slot = runtime._BrowserSlot(
                manager=manager,
                browser=browser,
                semaphore=asyncio.Semaphore(1),
                recycle_lock=asyncio.Lock(),
                idle_event=asyncio.Event(),
            )
            slot.idle_event.set()

            async def launch_should_not_run():
                raise AssertionError("replacement launch should be skipped after cancellation")

            pool._launch_browser = launch_should_not_run
            task = asyncio.create_task(pool._recycle_slot(slot, slot.generation, "test"))
            await manager.started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            self.assertTrue(browser.closed)
            self.assertIsNone(slot.manager)
            self.assertIsNone(slot.browser)
            self.assertTrue(slot.draining)
            self.assertEqual(slot.recycle_error, "browser_recycle_incomplete")

        asyncio.run(exercise())

    def test_debug_state_uses_current_pool_identity_after_config_change(self):
        class FakePool:
            def __init__(self, snapshot, *, debug=False, active=False):
                self.snapshot = snapshot
                self.debug = debug
                self.active = active
                self.shutdown_calls = 0
                self._closed = False

            def debug_state(self):
                return dict(self.snapshot)

            def has_debug_sessions(self):
                return self.debug

            def has_active_contexts(self):
                return self.active

            def shutdown(self, *, force=False):
                self.shutdown_calls += 1
                self._closed = True
                return True

        old_config = self._config(debug_mode=True, headless=True)
        current_config = self._config(debug_mode=False, headless=True)
        old_key = runtime._camoufox_pool_key(old_config)
        current_key = runtime._camoufox_pool_key(current_config)
        old_pool = FakePool(
            {
                "enabled": True, "headless": False, "capacity": 1,
                "used": 1, "open_contexts": 1,
                "sessions": [{"session_id": "cam-debug-abcdef123456"}],
            },
            debug=True,
        )
        current_pool = FakePool(
            {
                "enabled": False, "headless": True, "capacity": 2,
                "used": 0, "open_contexts": 0, "sessions": [],
            }
        )
        with runtime._POOL_LOCK:
            previous = dict(runtime._POOLS)
            runtime._POOLS.clear()
            runtime._POOLS[old_key] = old_pool
            runtime._POOLS[current_key] = current_pool
        try:
            state = runtime.camoufox_debug_state(current_config)
        finally:
            with runtime._POOL_LOCK:
                runtime._POOLS.clear()
                runtime._POOLS.update(previous)
        self.assertFalse(state["enabled"])
        self.assertTrue(state["headless"])
        self.assertEqual(state["capacity"], 3)
        self.assertEqual(state["used"], 1)
        self.assertEqual(state["open_contexts"], 1)
        self.assertEqual(old_pool.shutdown_calls, 0)

    def test_debug_artifact_dir_does_not_split_pool_identity(self):
        """Diagnostic output paths must not retire the live registration pool."""
        class FakePool:
            def __init__(self):
                self.shutdown_calls = 0

            def has_debug_sessions(self):
                return False

            def has_active_contexts(self):
                return False

            def shutdown(self, *, force=False):
                self.shutdown_calls += 1
                return True

            def debug_state(self):
                return {
                    "enabled": True,
                    "headless": False,
                    "capacity": 1,
                    "used": 0,
                    "open_contexts": 0,
                    "sessions": [],
                }

        runner_config = self._config(
            debug_mode=True,
            headless=True,
            _debug_artifact_dir="/tmp/camoufox-debug",
        )
        persisted_config = self._config(debug_mode=True, headless=True)
        self.assertEqual(
            runtime._camoufox_pool_key(runner_config),
            runtime._camoufox_pool_key(persisted_config),
        )
        pool = FakePool()
        key = runtime._camoufox_pool_key(runner_config)
        with runtime._POOL_LOCK:
            previous = dict(runtime._POOLS)
            runtime._POOLS.clear()
            runtime._POOLS[key] = pool
        try:
            state = runtime.camoufox_debug_state(persisted_config)
        finally:
            with runtime._POOL_LOCK:
                runtime._POOLS.clear()
                runtime._POOLS.update(previous)
        self.assertEqual(pool.shutdown_calls, 0)
        self.assertEqual(state["pool_count"], 1)

    def test_close_debug_helper_keeps_current_config_after_last_pool_is_removed(self):
        class FakePool:
            def __init__(self):
                self._debug = True

            def has_debug_sessions(self):
                return self._debug

            def close_debug_sessions(self, _session_id=""):
                self._debug = False
                return 1

            def shutdown(self, *, force=False):
                return True

            def debug_state(self):
                return {
                    "enabled": True,
                    "headless": False,
                    "capacity": 6,
                    "used": 0,
                    "open_contexts": 0,
                    "sessions": [],
                }

        config = self._config(debug_mode=False, headless=True, pool_size=4, max_contexts_per_browser=2)
        key = runtime._camoufox_pool_key(config)
        pool = FakePool()
        with runtime._POOL_LOCK:
            previous = dict(runtime._POOLS)
            runtime._POOLS.clear()
            runtime._POOLS[key] = pool
        try:
            result = runtime.close_camoufox_debug_browsers(config=config)
        finally:
            with runtime._POOL_LOCK:
                runtime._POOLS.clear()
                runtime._POOLS.update(previous)
        self.assertEqual(result["closed_contexts"], 1)
        self.assertEqual(result["retained_contexts"], 0)
        self.assertEqual(result["remaining_contexts"], 0)
        self.assertEqual(result["retained_pools"], 0)

    def test_runner_uses_the_shared_mailbox_provider_and_normalizes_result(self):
        mailbox = Mock()
        pool = Mock()
        pool.register.return_value = {
            "access_token": "access-token",
            "account_flow": "existing_login",
            "registration_password_used": False,
        }
        task = {
            "task_id": "camoufox-task",
            "email": "user@example.test",
            "mailbox_url": "https://mail.example.test/code?private=1",
            "proxy": "http://proxy.example.test:8080",
            "exit_ip": "198.51.100.10",
        }
        config = {
            "driver": "camoufox",
            "email_code_timeout": 90,
            "camoufox": self._config(),
        }
        stage = Mock()
        log = Mock()
        with (
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=mailbox) as builder,
            patch.object(runtime, "_pool_for", return_value=pool),
        ):
            result = runtime.CamoufoxRegistrationRunner()(task, config, threading.Event(), stage, log)

        builder.assert_called_once_with(task["mailbox_url"], task["proxy"], config, log_fn=log, task_id=task["task_id"], stage_fn=stage)
        self.assertEqual(result["driver"], "camoufox")
        self.assertEqual(result["account_flow"], "existing_login")
        self.assertNotIn("password", result)
        mailbox.close.assert_called_once_with()

    def test_runner_passes_configured_password_for_signup(self):
        mailbox = Mock()
        pool = Mock()
        pool.register.return_value = {
            "access_token": "access-token",
            "account_flow": "signup",
            "registration_password_used": True,
            "password": "Custom-Password-123",
        }
        task = {
            "task_id": "signup-task",
            "email": "user@example.test",
            "mailbox_url": "https://mail.example.test/code",
            "proxy": "",
        }
        config = {
            "driver": "camoufox",
            "account_password": "Custom-Password-123",
            "email_code_timeout": 90,
            "camoufox": self._config(),
        }
        with (
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=mailbox),
            patch.object(runtime, "_pool_for", return_value=pool),
        ):
            runtime.CamoufoxRegistrationRunner()(task, config, threading.Event(), Mock(), Mock())

        self.assertEqual(pool.register.call_args.kwargs["password"], "Custom-Password-123")
        mailbox.close.assert_called_once_with()

    def test_runner_passes_existing_login_mode_for_twofa_retry(self):
        mailbox = Mock()
        pool = Mock()
        pool.register.return_value = {"access_token": "access-token", "twofa_status": "enabled", "totp_secret": "JBSWY3DPEHPK3PXP"}
        task = {
            "task_id": "retry-task", "email": "user@example.test",
            "mailbox_url": "https://mail.example.test/code", "proxy": "",
            "result": {"password": "saved-account-password"},
        }
        config = {"driver": "camoufox", "email_code_timeout": 90, "camoufox": self._config()}
        with patch.object(runtime, "build_free_mailbox_otp_provider", return_value=mailbox), patch.object(runtime, "_pool_for", return_value=pool):
            runtime.CamoufoxRegistrationRunner()(task, config, threading.Event(), Mock(), Mock(), twofa_retry=True)
        self.assertTrue(pool.register.call_args.kwargs["force_existing_login"])
        self.assertEqual(pool.register.call_args.kwargs["existing_password"], "saved-account-password")
        self.assertEqual(pool.register.call_args.kwargs["password"], "")

    def test_password_retry_runner_passes_continuation_flag_without_login_mode(self):
        mailbox = Mock()
        pool = Mock()
        pool.register.return_value = {
            "access_token": "access-token",
            "password_status": "enabled",
            "password_set_after_registration": True,
            "password": "new-account-password",
        }
        task = {
            "task_id": "password-retry-task",
            "email": "user@example.test",
            "mailbox_url": "https://mail.example.test/code",
            "proxy": "",
            "result": {
                "access_token": "access-token",
                "password_status": "pending",
                "twofa_status": "enabled",
            },
        }
        config = {"driver": "camoufox", "email_code_timeout": 90, "camoufox": self._config()}
        with (
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=mailbox),
            patch.object(runtime, "_pool_for", return_value=pool),
        ):
            result = runtime.CamoufoxRegistrationRunner()(
                task,
                config,
                threading.Event(),
                Mock(),
                Mock(),
                password_retry=True,
            )

        kwargs = pool.register.call_args.kwargs
        self.assertTrue(kwargs["password_retry"])
        self.assertFalse(kwargs["force_existing_login"])
        self.assertEqual(kwargs["password"], "")
        self.assertEqual(result["password_status"], "enabled")
        self.assertEqual(result["access_token"], "access-token")
        mailbox.close.assert_called_once_with()

    def test_password_retry_runner_accepts_disabled_passwordless_signup(self):
        mailbox = Mock()
        pool = Mock()
        pool.register.return_value = {
            "access_token": "access-token",
            "account_flow": "signup",
            "password_status": "enabled",
            "password_set_after_registration": True,
            "password": "new-account-password",
        }
        task = {
            "task_id": "password-retry-disabled-task",
            "email": "user@example.test",
            "mailbox_url": "https://mail.example.test/code",
            "proxy": "",
            "result": {
                "access_token": "access-token",
                "account_flow": "signup",
                "password_status": "disabled",
                "registration_password_used": False,
            },
        }
        config = {"driver": "camoufox", "email_code_timeout": 90, "camoufox": self._config()}
        with (
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=mailbox),
            patch.object(runtime, "_pool_for", return_value=pool),
        ):
            result = runtime.CamoufoxRegistrationRunner()(
                task,
                config,
                threading.Event(),
                Mock(),
                Mock(),
                password_retry=True,
            )

        kwargs = pool.register.call_args.kwargs
        self.assertTrue(kwargs["password_retry"])
        self.assertFalse(kwargs["force_existing_login"])
        self.assertEqual(result["password_status"], "enabled")
        self.assertEqual(result["password"], "new-account-password")
        mailbox.close.assert_called_once_with()

    def test_password_retry_browser_flow_only_calls_password_helper(self):
        page = Mock()
        page.goto = AsyncMock()
        add_password = AsyncMock(return_value={
            "access_token": "access-token",
            "password_status": "enabled",
            "password_set_after_registration": True,
            "password": "new-account-password",
        })
        with (
            patch.object(runtime, "browser_add_password", new=add_password),
            patch.object(runtime, "browser_twofa", new=AsyncMock()) as twofa,
            patch.object(runtime, "browser_json_fetch", new=AsyncMock()) as json_fetch,
        ):
            result = asyncio.run(
                runtime._browser_flow(
                    page,
                    email="user@example.test",
                    password="new-account-password",
                    otp_callback=lambda: "123456",
                    config={"registration_timeout_seconds": 60},
                    log=lambda *_args: None,
                    password_retry=True,
                    password_retry_token="access-token",
                )
            )

        page.goto.assert_awaited_once()
        add_password.assert_awaited_once()
        self.assertEqual(add_password.call_args.args[1], "access-token")
        twofa.assert_not_awaited()
        json_fetch.assert_not_awaited()
        self.assertEqual(result["password_status"], "enabled")
        self.assertEqual(result["access_token"], "access-token")

    def test_runner_rejects_twofa_retry_without_saved_password(self):
        mailbox = Mock()
        pool = Mock()
        task = {
            "task_id": "retry-task", "email": "user@example.test",
            "mailbox_url": "https://mail.example.test/code", "proxy": "",
            "result": {"twofa_status": "pending"},
        }
        config = {"driver": "camoufox", "email_code_timeout": 90, "camoufox": self._config()}
        with (
            patch.object(runtime, "build_free_mailbox_otp_provider", return_value=mailbox),
            patch.object(runtime, "_pool_for", return_value=pool),
        ):
            with self.assertRaises(runtime.FreeRegisterError) as raised:
                runtime.CamoufoxRegistrationRunner()(task, config, threading.Event(), Mock(), Mock(), twofa_retry=True)
        self.assertEqual(raised.exception.error_code, "free_existing_login_password_missing")
        pool.register.assert_not_called()

    def test_shared_plan_parser_preserves_non_success_http_status(self):
        details = free_account_service.plan_details_from_payloads(
            {"status": 429, "payload": {"error": {"code": "rate_limited"}}},
            {"status": 200, "payload": {"eligible": False}},
        )

        self.assertEqual(details["plan_accounts_http_status"], 429)
        self.assertEqual(details["plan_check_status"], "failed")
        self.assertEqual(details["plan_failure"]["http_status"], 429)


if __name__ == "__main__":
    unittest.main()
