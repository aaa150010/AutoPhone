from __future__ import annotations

import asyncio
import inspect
import threading
import unittest
from unittest.mock import AsyncMock, Mock, patch

from mac_overrides import free_account_service
from mac_overrides import free_camoufox_runtime as runtime


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
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)) as submit,
            patch.object(
                runtime,
                "_wait_for_any_selector",
                new=AsyncMock(side_effect=["input[type='email']", "input[type='email']"]),
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
        self.assertEqual(submit.await_args_list[0].args[1], "#entry-email")
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
            patch.object(runtime, "_submit_visible_form", new=AsyncMock(return_value=True)),
            patch.object(
                runtime,
                "_wait_for_any_selector",
                new=AsyncMock(side_effect=["input[type='email']", "input[type='email']"]),
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

    def test_runner_passes_existing_login_mode_for_twofa_retry(self):
        mailbox = Mock()
        pool = Mock()
        pool.register.return_value = {"access_token": "access-token", "twofa_status": "enabled", "totp_secret": "JBSWY3DPEHPK3PXP"}
        task = {"task_id": "retry-task", "email": "user@example.test", "mailbox_url": "https://mail.example.test/code", "proxy": ""}
        config = {"driver": "camoufox", "email_code_timeout": 90, "camoufox": self._config()}
        with patch.object(runtime, "build_free_mailbox_otp_provider", return_value=mailbox), patch.object(runtime, "_pool_for", return_value=pool):
            runtime.CamoufoxRegistrationRunner()(task, config, threading.Event(), Mock(), Mock(), twofa_retry=True)
        self.assertTrue(pool.register.call_args.kwargs["force_existing_login"])

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
