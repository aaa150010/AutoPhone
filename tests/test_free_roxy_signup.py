from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.free_roxy_client import RoxyOpenResult
from mac_overrides.free_roxy_client import RoxyBrowserClient
from mac_overrides.free_roxy_page_flow import classify_page
from mac_overrides.free_roxy_runtime import RoxyRegistrationRunner
from mac_overrides import free_roxy_signup


class _NavigationDriver:
    def __init__(self, url: str = "about:blank") -> None:
        self.current_url = url
        self.visits: list[str] = []
        self.timeout = 0

    def set_page_load_timeout(self, timeout: int) -> None:
        self.timeout = timeout

    def get(self, url: str) -> None:
        self.visits.append(url)
        self.current_url = url


class _ScriptDriver:
    def __init__(self, result):
        self.result = result
        self.scripts: list[str] = []

    def execute_script(self, script: str, *_args):
        self.scripts.append(script)
        return self.result


class _LoginPageDriver:
    current_url = "https://auth.openai.com/log-in"

    def execute_script(self, script: str, *_args):
        if "return {title:" in script:
            return {"title": "Log in", "body": "", "inputs": []}
        return None


class _UntrustedChallengeDriver(_LoginPageDriver):
    current_url = "https://chatgpt.com.attacker.test/cdn-cgi/challenge-platform"

    def execute_script(self, script: str, *_args):
        if "return {title:" in script:
            return {"title": "Just a moment", "body": "Verify you are human", "inputs": []}
        return None


class FreeRoxySignupTests(unittest.TestCase):
    def test_bootstrap_starts_at_chatgpt_login_ui(self):
        driver = _NavigationDriver()
        free_roxy_signup.open_signup_page(driver, "account@example.test", 30)
        self.assertEqual(driver.visits, ["https://chatgpt.com/auth/login"])
        self.assertEqual(driver.timeout, 30)

    def test_email_form_script_uses_native_setter_and_async_enter_click(self):
        driver = _ScriptDriver({"ok": True, "mode": "async_enter_click"})
        result = free_roxy_signup._submit_email_form(driver, "account@example.test")
        self.assertTrue(result["ok"])
        script = driver.scripts[0]
        self.assertIn("HTMLInputElement.prototype, 'value'", script)
        self.assertIn("beforeinput", script)
        self.assertIn("KeyboardEvent('keydown'", script)
        self.assertIn("setTimeout", script)
        self.assertIn("submit.click()", script)
        self.assertIn("requestSubmit", script)
        self.assertIn("el.textContent", script)
        self.assertNotIn("!el.querySelector('img,svg,use')", script)

    def test_cookie_warmup_only_clicks_explicit_consent_selectors(self):
        class Driver:
            def __init__(self):
                self.scripts = []

            def execute_script(self, script, *_args):
                self.scripts.append(script)
                return None

            def execute_cdp_cmd(self, *_args):
                return None

        driver = Driver()
        free_roxy_signup.warmup_login_page(driver)
        self.assertTrue(driver.scripts)
        self.assertIn("onetrust-accept-btn-handler", driver.scripts[0])
        self.assertIn("cookie-accept", driver.scripts[0])
        self.assertNotIn("Continue", driver.scripts[0])

    def test_controlled_resubmit_is_explicitly_marked(self):
        driver = _ScriptDriver({"ok": True, "mode": "controlled_resubmit"})
        result = free_roxy_signup._submit_email_form(driver, "account@example.test", recovery=True)
        self.assertEqual(result["mode"], "controlled_resubmit")
        self.assertIn("recovery", driver.scripts[0])

    def test_email_submit_rejects_explicit_missing_controls_and_filters_fallback(self):
        driver = _ScriptDriver({
            "ok": True,
            "submit_candidate": False,
            "request_submit_available": False,
        })
        result = free_roxy_signup._submit_email_form(driver, "account@example.test")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "no_safe_submit_control")
        self.assertGreaterEqual(len(driver.scripts), 2)
        self.assertIn("google|apple|microsoft", driver.scripts[1])
        self.assertIn("cancel|back|skip", driver.scripts[1])

    def test_email_submit_fallback_scores_button_text_for_idp_exclusion(self):
        """The fallback must inspect rendered button text, not only attributes."""
        driver = _ScriptDriver({
            "ok": False,
            "reason": "driver_script_rejected",
        })
        result = free_roxy_signup._submit_email_form(driver, "account@example.test")
        self.assertFalse(result["ok"])
        self.assertGreaterEqual(len(driver.scripts), 2)
        fallback_script = driver.scripts[1]
        self.assertIn("el.textContent", fallback_script)
        self.assertIn("same_form_request_submit", fallback_script)

    def test_email_submit_primary_script_fails_closed_without_button_or_request_submit(self):
        driver = _ScriptDriver({
            "ok": False,
            "reason": "no_safe_submit_control",
        })
        result = free_roxy_signup._submit_email_form(driver, "account@example.test")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "no_safe_submit_control")

    def test_auth_log_in_without_email_input_remains_unclassified_until_dom_ready(self):
        self.assertEqual(classify_page(_LoginPageDriver()), "unknown")

    def test_page_classifier_rejects_lookalike_openai_hosts(self):
        for url in (
            "https://chatgpt.com.attacker.test/",
            "https://auth.openai.com.attacker.test/log-in/password",
            "https://attacker.test/chatgpt.com/email-verification",
            "https://attacker.test/about-you?next=auth.openai.com",
        ):
            with self.subTest(url=url):
                self.assertEqual(classify_page(_NavigationDriver(url)), "unknown")
        self.assertEqual(classify_page(_UntrustedChallengeDriver()), "unknown")

    def test_page_classifier_accepts_real_subdomains_only(self):
        self.assertEqual(classify_page(_NavigationDriver("https://www.chatgpt.com/")), "home")
        self.assertEqual(
            classify_page(_NavigationDriver("https://edge.auth.openai.com/authorize")),
            "oauth_callback",
        )

    def test_open_result_extracts_roxy_chromedriver_path(self):
        opened = RoxyOpenResult(
            "profile-1",
            {"data": {"driver": "/opt/roxy/chromedriver", "http": "127.0.0.1:9222"}},
        )
        self.assertEqual(opened.driver_path, "/opt/roxy/chromedriver")

    def test_open_defaults_to_headless_and_never_force_opens(self):
        class Response:
            status_code = 200
            text = ""

            @staticmethod
            def json():
                return {"code": 0, "data": {"dirId": "p1", "http": "127.0.0.1:9222", "driver": "/opt/roxy/chromedriver"}}

        class Session:
            def __init__(self):
                self.headers = {}
                self.calls = []

            def request(self, method, url, **kwargs):
                self.calls.append((method, url, kwargs.get("json")))
                if url.endswith("/browser/connection_info"):
                    return type("EmptyResponse", (), {
                        "status_code": 200, "text": "", "json": staticmethod(lambda: {"code": 0, "data": []}),
                    })()
                return Response()

        session = Session()
        client = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000", "api_retries": 1}, session=session)
        opened = client.open_profile("p1")
        body = next(item[2] for item in session.calls if item[1].endswith("/browser/open"))
        self.assertTrue(body["headless"])
        self.assertFalse(body["forceOpen"])
        self.assertEqual(opened.driver_path, "/opt/roxy/chromedriver")

    def test_existing_connection_is_reused_without_second_open(self):
        class Session:
            def __init__(self):
                self.headers = {}
                self.calls = []

            def request(self, method, url, **kwargs):
                self.calls.append((method, url, kwargs.get("json")))
                return type("Response", (), {
                    "status_code": 200,
                    "text": "",
                    "json": staticmethod(lambda: {"code": 0, "data": [{
                        "dirId": "p1", "http": "127.0.0.1:9222", "driver": "/opt/roxy/chromedriver",
                    }]}),
                })()

        session = Session()
        opened = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000"}, session=session).open_profile("p1")
        self.assertTrue(opened.connection_reused)
        self.assertEqual([url.rsplit("/", 1)[-1] for _method, url, _body in session.calls], ["connection_info"])

    def test_driver_refuses_system_chromedriver_fallback(self):
        opened = RoxyOpenResult("profile-1", {}, debugger_address="127.0.0.1:9222")
        with self.assertRaises(FreeRegisterError) as raised:
            RoxyRegistrationRunner._driver(opened)
        self.assertEqual(raised.exception.node_code, "free_roxy_connect")
        self.assertEqual(raised.exception.error_code, "free_roxy_driver_unavailable")

    def test_driver_uses_roxy_chromedriver_service(self):
        opened = RoxyOpenResult(
            "profile-1", {}, debugger_address="127.0.0.1:9222",
            driver_path="/opt/roxy/chromedriver",
        )
        fake_driver = MagicMock()
        service_type = type("FakeService", (), {
            "__init__": lambda self, executable_path: setattr(self, "path", executable_path),
        })
        with (
            patch("mac_overrides.free_roxy_driver.os.path.isfile", return_value=True),
            patch("selenium.webdriver.chrome.service.Service", service_type),
            patch("selenium.webdriver.Chrome", return_value=fake_driver) as chrome,
        ):
            result = RoxyRegistrationRunner._driver(opened)
        self.assertIs(result, fake_driver)
        self.assertEqual(chrome.call_args.kwargs["service"].path, "/opt/roxy/chromedriver")
        self.assertEqual(
            chrome.call_args.kwargs["options"].experimental_options["debuggerAddress"],
            "127.0.0.1:9222",
        )

    def test_driver_source_is_credential_free(self):
        opened = RoxyOpenResult(
            "profile-1", {}, debugger_address="127.0.0.1:9222",
            driver_path="/opt/roxy/chromedriver",
        )
        with patch("mac_overrides.free_roxy_driver.os.path.isfile", return_value=True):
            self.assertEqual(RoxyRegistrationRunner._driver_source(opened), "roxy_chromedriver")

    def test_login_email_recovery_runs_once_per_attempt(self):
        class Clock:
            now = 0.0

            @classmethod
            def monotonic(cls):
                return cls.now

            @classmethod
            def sleep(cls, seconds):
                cls.now += float(seconds)

        submissions: list[tuple[bool, float]] = []

        def submit(_driver, _email, *, recovery=False):
            submissions.append((bool(recovery), Clock.now))
            return {"ok": True}

        human = type("Human", (), {"delay": staticmethod(lambda _kind: None)})()
        with (
            patch("mac_overrides.free_roxy_signup.time.monotonic", side_effect=Clock.monotonic),
            patch("mac_overrides.free_roxy_signup.time.sleep", side_effect=Clock.sleep),
            patch("mac_overrides.free_roxy_signup.EMAIL_CLEAR_DEBOUNCE_SECONDS", 6.0),
            patch("mac_overrides.free_roxy_signup.EMAIL_CLEAR_RECOVERY_SECONDS", 2.0),
            patch("mac_overrides.free_roxy_signup.EMAIL_NON_LOGIN_CLEAR_DEBOUNCE_SECONDS", 4.0),
            patch("mac_overrides.free_roxy_signup.EMAIL_TRANSITION_TIMEOUT_SECONDS", 6.0),
            patch("mac_overrides.free_roxy_signup._email_target", return_value={"ok": True, "input": object()}),
            patch("mac_overrides.free_roxy_signup._stabilize_email", return_value={"ok": True, "has_form": True}),
            patch("mac_overrides.free_roxy_signup._submit_email_form", side_effect=submit),
            patch("mac_overrides.free_roxy_signup._email_form_state", return_value={
                "input_count": 1, "has_blank": True, "has_expected": False,
                "path": "/auth/login", "has_email_query": True,
            }),
        ):
            with self.assertRaises(FreeRegisterError):
                free_roxy_signup.submit_email_and_wait(
                    object(), "account@example.test", human, None, 30,
                    classify=lambda _driver: "unknown",
                    wait_security=lambda _driver, _timeout, _log: "unknown",
                    type_element=lambda *_args: None,
                    click_element=lambda *_args: None,
                )
        self.assertEqual([recovery for recovery, _at in submissions], [False, True, False, True, False, True])
        self.assertTrue(all(attempt_at >= 2.0 for recovery, attempt_at in submissions if recovery))

    def test_non_login_clear_uses_short_debounce_without_recovery(self):
        class Clock:
            now = 0.0

            @classmethod
            def monotonic(cls):
                return cls.now

            @classmethod
            def sleep(cls, seconds):
                cls.now += float(seconds)

        submissions: list[bool] = []

        def submit(_driver, _email, *, recovery=False):
            submissions.append(bool(recovery))
            return {"ok": True}

        human = type("Human", (), {"delay": staticmethod(lambda _kind: None)})()
        with (
            patch("mac_overrides.free_roxy_signup.time.monotonic", side_effect=Clock.monotonic),
            patch("mac_overrides.free_roxy_signup.time.sleep", side_effect=Clock.sleep),
            patch("mac_overrides.free_roxy_signup.EMAIL_NON_LOGIN_CLEAR_DEBOUNCE_SECONDS", 2.0),
            patch("mac_overrides.free_roxy_signup.EMAIL_TRANSITION_TIMEOUT_SECONDS", 3.0),
            patch("mac_overrides.free_roxy_signup._email_target", return_value={"ok": True, "input": object()}),
            patch("mac_overrides.free_roxy_signup._stabilize_email", return_value={"ok": True, "has_form": True}),
            patch("mac_overrides.free_roxy_signup._submit_email_form", side_effect=submit),
            patch("mac_overrides.free_roxy_signup._email_form_state", return_value={
                "input_count": 1, "has_blank": True, "has_expected": False,
                "path": "/log-in", "has_email_query": False,
            }),
        ):
            with self.assertRaises(FreeRegisterError):
                free_roxy_signup.submit_email_and_wait(
                    object(), "account@example.test", human, None, 90,
                    classify=lambda _driver: "unknown",
                    wait_security=lambda _driver, _timeout, _log: "unknown",
                    type_element=lambda *_args: None,
                    click_element=lambda *_args: None,
                )
        self.assertEqual(submissions, [False, False, False])

    def test_login_email_recovery_waits_for_debounce_and_observes_same_submission(self):
        class Clock:
            now = 0.0
            recovered = False
            observed_after_recovery = False

            @classmethod
            def monotonic(cls):
                return cls.now

            @classmethod
            def sleep(cls, seconds):
                cls.now += float(seconds)
                if cls.recovered:
                    cls.observed_after_recovery = True

        submissions: list[tuple[bool, float]] = []

        def submit(_driver, _email, *, recovery=False):
            submissions.append((bool(recovery), Clock.now))
            if recovery:
                Clock.recovered = True
            return {"ok": True}

        def classify(_driver):
            return "otp" if Clock.observed_after_recovery else "unknown"

        human = type("Human", (), {"delay": staticmethod(lambda _kind: None)})()
        with (
            patch("mac_overrides.free_roxy_signup.time.monotonic", side_effect=Clock.monotonic),
            patch("mac_overrides.free_roxy_signup.time.sleep", side_effect=Clock.sleep),
            patch("mac_overrides.free_roxy_signup.EMAIL_CLEAR_DEBOUNCE_SECONDS", 18.0),
            patch("mac_overrides.free_roxy_signup.EMAIL_CLEAR_RECOVERY_SECONDS", 2.0),
            patch("mac_overrides.free_roxy_signup._email_target", return_value={"ok": True, "input": object()}),
            patch("mac_overrides.free_roxy_signup._stabilize_email", return_value={"ok": True, "has_form": True}),
            patch("mac_overrides.free_roxy_signup._submit_email_form", side_effect=submit),
            patch("mac_overrides.free_roxy_signup._email_form_state", return_value={
                "input_count": 1, "has_blank": True, "has_expected": False,
                "path": "/auth/login", "has_email_query": True,
            }),
        ):
            result = free_roxy_signup.submit_email_and_wait(
                object(), "account@example.test", human, None, 30,
                classify=classify,
                wait_security=lambda _driver, _timeout, _log: "unknown",
                type_element=lambda *_args: None,
                click_element=lambda *_args: None,
            )

        self.assertEqual(result, "otp")
        self.assertEqual([recovery for recovery, _at in submissions], [False, True])
        self.assertGreaterEqual(submissions[1][1], 2.0)

    def test_timeout_argument_does_not_expand_email_transition_window(self):
        class Clock:
            now = 0.0

            @classmethod
            def monotonic(cls):
                return cls.now

            @classmethod
            def sleep(cls, seconds):
                cls.now += float(seconds)

        human = type("Human", (), {"delay": staticmethod(lambda _kind: None)})()
        with (
            patch("mac_overrides.free_roxy_signup.time.monotonic", side_effect=Clock.monotonic),
            patch("mac_overrides.free_roxy_signup.time.sleep", side_effect=Clock.sleep),
            patch("mac_overrides.free_roxy_signup.EMAIL_CLEAR_DEBOUNCE_SECONDS", 18.0),
            patch("mac_overrides.free_roxy_signup.EMAIL_CLEAR_RECOVERY_SECONDS", 2.0),
            patch("mac_overrides.free_roxy_signup.EMAIL_TRANSITION_TIMEOUT_SECONDS", 20.0),
            patch("mac_overrides.free_roxy_signup._email_target", return_value={"ok": True, "input": object()}),
            patch("mac_overrides.free_roxy_signup._stabilize_email", return_value={"ok": True, "has_form": True}),
            patch("mac_overrides.free_roxy_signup._submit_email_form", return_value={"ok": True}),
            patch("mac_overrides.free_roxy_signup._email_form_state", return_value={
                "input_count": 0, "has_blank": False, "has_expected": False,
                "path": "/auth/login", "has_email_query": True,
            }),
        ):
            with self.assertRaises(FreeRegisterError):
                free_roxy_signup.submit_email_and_wait(
                    object(), "account@example.test", human, None, 90,
                    classify=lambda _driver: "unknown",
                    wait_security=lambda _driver, _timeout, _log: "unknown",
                    type_element=lambda *_args: None,
                    click_element=lambda *_args: None,
                )
        self.assertGreaterEqual(Clock.now, 60.0)
        self.assertLess(Clock.now, 75.0)


if __name__ == "__main__":
    unittest.main()
