from __future__ import annotations

from pathlib import Path
import os
import json
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from mac_overrides.free_register_config import FreeConfigStore
from mac_overrides.free_roxy_runtime import RoxyBrowserClient, RoxyOpenResult, RoxyRegistrationRunner, proxy_to_roxy_info
from mac_overrides.free_roxy_page_flow import (
    classify_page,
    password_form_targets,
    switch_login_to_email_code,
    wait_after_otp_submit,
)
from mac_overrides import free_roxy_session
from mac_overrides.free_roxy_session import extract_session, session_token
from mac_overrides.free_register_common import FIXED_PASSWORD, FreeRegisterError
from mac_overrides.free_register_store import FreeProxyPool


class _Response:
    status_code = 200

    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value


class _FakeSession:
    def __init__(self):
        self.headers = {}
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if url.endswith("/browser/workspace"):
            return _Response({"data": {"rows": [{"id": "w", "workspaceName": "Workspace", "project_details": [{"projectId": "p", "projectName": "Project"}]}]}})
        if url.endswith("/browser/create"):
            return _Response({"code": 0, "data": {"dirId": "42"}})
        if url.endswith("/browser/open"):
            return _Response({"code": 0, "data": {"debuggerAddress": "127.0.0.1:9222"}})
        return _Response({"code": 0})


class _ConnectionInfoSession(_FakeSession):
    def __init__(self):
        super().__init__()
        self.connection_checks = 0

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if url.endswith("/browser/open"):
            return _Response({"code": 0, "data": {}})
        if url.endswith("/browser/connection_info"):
            self.connection_checks += 1
            if self.connection_checks == 1:
                return _Response({"code": 0, "data": []})
            return _Response({"code": 0, "data": [{
                "dirId": "42",
                "ws": "ws://127.0.0.1:9222/devtools/browser/42",
                "http": "127.0.0.1:9222",
            }]})
        return _Response({"code": 0})


class _AlreadyOpenSession(_FakeSession):
    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if url.endswith("/browser/connection_info"):
            return _Response({"code": 0, "data": [{
                "dirId": "42",
                "http": "127.0.0.1:9222",
                "ws": "ws://127.0.0.1:9222/devtools/browser/42",
            }]})
        return _Response({"code": 0})


class _CleanupFailureSession(_FakeSession):
    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if url.endswith("/browser/close"):
            raise RuntimeError("close unavailable")
        return _Response({"code": 0})


class _SignupDriver:
    def __init__(self, result=None):
        self.result = result or {"ok": True, "url": "https://auth.openai.com/log-in"}
        self.current_url = "about:blank"
        self.visits = []
        self.timeout = 0
        self.scripts = []

    def set_page_load_timeout(self, timeout):
        self.timeout = timeout

    def get(self, url):
        self.visits.append(url)
        self.current_url = url

    def execute_async_script(self, script, *args):
        self.scripts.append((script, args))
        return self.result


class _AuthNavigationErrorDriver(_SignupDriver):
    def get(self, url):
        self.visits.append(url)
        if str(url).startswith("https://auth.openai.com/"):
            self.current_url = "https://auth.openai.com/api/accounts/authorize"
            raise RuntimeError("navigation committed")
        self.current_url = url


class _SessionDriver:
    def __init__(self, payload):
        self.payload = payload
        self.current_url = "https://chatgpt.com/"
        self.visits = []

    def get(self, url):
        self.visits.append(url)
        self.current_url = url

    def find_element(self, _by, _value):
        return type("Element", (), {"text": json.dumps(self.payload)})()


class _BrowserSessionDriver:
    def __init__(self, response):
        self.response = response
        self.current_url = "https://chatgpt.com/"
        self.visits = []

    def execute_async_script(self, _script, *_args):
        return self.response

    def get(self, url):
        self.visits.append(url)
        self.current_url = url


class _PageDriver:
    def __init__(self, url="https://auth.openai.com/log-in/password", *, body="", click_result=True):
        self.current_url = url
        self.body = body
        self.click_result = click_result

    def find_element(self, _by, _value):
        return type("Element", (), {"text": self.body})()

    def execute_script(self, script, *_args):
        if "passwordless.*otp" in script:
            if self.click_result:
                self.current_url = "https://auth.openai.com/email-verification"
            return self.click_result
        return {"title": "Auth", "body": self.body, "inputs": []}


class _PasswordField:
    def __init__(self):
        self.value = ""

    def send_keys(self, *values):
        for value in values:
            text = str(value)
            if text in {"\ue009", "\ue003"}:
                if text == "\ue003":
                    self.value = ""
                continue
            if text.lower() == "a" and len(values) > 1:
                continue
            self.value += text

    def clear(self):
        self.value = ""

    def get_attribute(self, name):
        return self.value if name == "value" else ""


class _PasswordButton:
    def __init__(self, driver):
        self.driver = driver

    def click(self):
        self.driver.clicks += 1
        self.driver.current_url = "https://auth.openai.com/email-verification"


class _SignupPasswordDriver:
    def __init__(self):
        self.current_url = "https://auth.openai.com/create-account/password"
        self.field = _PasswordField()
        self.button = _PasswordButton(self)
        self.clicks = 0

    def find_element(self, _by, _value):
        return type("Element", (), {"text": ""})()

    def execute_script(self, script, *_args):
        if "missing_password_input" in script:
            return {"ok": True, "input": self.field, "button": self.button}
        if "const values =" in script:
            return ""
        if "return {title:" in script:
            return {
                "title": "Create account",
                "body": "Create your password",
                "inputs": [{"type": "password", "name": "password", "autocomplete": "new-password"}],
            }
        return None


class _StalledSignupPasswordDriver(_SignupPasswordDriver):
    def __init__(self):
        super().__init__()
        self.button = type("Button", (), {"click": lambda _self: None})()


class _ExistingLoginDriver(_PageDriver):
    def __init__(self):
        super().__init__("https://auth.openai.com/log-in")
        self.script_timeout = 0
        self.closed = False

    def set_script_timeout(self, timeout):
        self.script_timeout = timeout

    def quit(self):
        self.closed = True


class _ExistingLoginClient:
    cleaned = False

    def __init__(self, _config, **_kwargs):
        pass

    def create_profile(self, _proxy):
        return "existing-42"

    def open_profile(self, profile_id):
        return RoxyOpenResult(profile_id, {}, debugger_address="127.0.0.1:9222", created_by_run=True)

    def cleanup(self, _opened):
        self.cleaned = True


class _ExistingOtp:
    def __init__(self, *_args, **_kwargs):
        self.stages = []

    def prepare(self):
        pass

    def mark_sent(self, stage_code="free_email_otp_wait"):
        self.stages.append(stage_code)

    def wait_code(self, _email, stage_code="free_email_otp_wait"):
        self.stages.append(stage_code)
        return "123456"


class _ExistingLoginRunner(RoxyRegistrationRunner):
    def __init__(self, driver):
        self.driver = driver

    def _driver(self, _opened):
        return self.driver

    @staticmethod
    def _browser_ip(_driver, _probe_url, _timeout):
        return "203.0.113.10"

    @staticmethod
    def _open_signup_page(driver, _email, _timeout):
        driver.current_url = "https://auth.openai.com/log-in"

    @staticmethod
    def _find(_driver, selectors, _timeout):
        if any("signup" in selector for selector in selectors):
            raise RuntimeError("signup control absent")
        return object()

    @staticmethod
    def _click(_driver, _element, _human):
        pass

    @staticmethod
    def _type(_element, _value, _human):
        pass

    @staticmethod
    def _submit(driver, _human):
        driver.current_url = "https://auth.openai.com/log-in/password"

    @staticmethod
    def _fill_otp(driver, _code, _human):
        driver.current_url = "https://chatgpt.com/"

    @staticmethod
    def _session(_driver, _timeout, _log=None):
        return {"accessToken": "EXISTING_TOKEN"}

    @staticmethod
    def _plan_details(_driver, _token):
        return {"plan_check_status": "success", "plan_type": "free", "plus_trial_eligible": True}


class FreeRoxyRuntimeTests(unittest.TestCase):
    def test_migration_copies_sensitive_files_with_private_permissions(self):
        with TemporaryDirectory() as legacy_directory, TemporaryDirectory() as target_directory:
            legacy = Path(legacy_directory)
            (legacy / "free_mailbox_pool.txt").write_text("account@example.test----https://mail.test/inbox\n", encoding="utf-8")
            results = legacy / "free_register_results"
            results.mkdir()
            (results / "result.json").write_text("{}", encoding="utf-8")
            os.chmod(legacy / "free_mailbox_pool.txt", 0o644)
            os.chmod(results, 0o755)

            store = FreeConfigStore(target_directory)
            store.migrate_legacy({}, legacy)

            self.assertEqual(os.stat(Path(target_directory) / "free_mailbox_pool.txt").st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(Path(target_directory) / "free_register_results").st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(Path(target_directory) / "free_register_results" / "result.json").st_mode & 0o777, 0o600)

    def test_config_is_free_only_and_masks_roxy_key(self):
        with TemporaryDirectory() as directory:
            store = FreeConfigStore(directory)
            saved = store.save({
                "driver": "roxybrowser",
                "concurrency": 99,
                "mailbox_network_mode": "local_proxy",
                "mailbox_proxy_url": "http://mail-user:mail-pass@127.0.0.1:7897",
                "roxybrowser": {"api_key": "secret", "workspace_id": "w", "project_id": "p", "existing_account_login": False},
            })
            self.assertEqual(saved["concurrency"], 5)
            self.assertEqual(saved["mailbox_request_retries"], 3)
            self.assertEqual(saved["mailbox_retry_backoff_seconds"], 1.0)
            self.assertTrue(saved["roxybrowser"]["headless"])
            self.assertFalse(saved["roxybrowser"]["existing_account_login"])
            self.assertEqual(store.public()["roxybrowser"]["api_key"], "********")
            self.assertEqual(store.public()["mailbox_proxy_url"], "********")
            self.assertEqual(store.secret("mailbox_proxy_url"), "http://mail-user:mail-pass@127.0.0.1:7897")
            store.save(store.public())
            self.assertEqual(store.secret("mailbox_proxy_url"), "http://mail-user:mail-pass@127.0.0.1:7897")
            self.assertNotIn("free_proxy_pool_content", store.load())

    def test_legacy_visible_default_is_migrated_to_headless_once(self):
        with TemporaryDirectory() as directory:
            store = FreeConfigStore(directory)
            migrated = store.normalize({"version": 2, "roxybrowser": {"headless": False}})
            self.assertTrue(migrated["roxybrowser"]["headless"])
            explicit = store.normalize({"version": 3, "roxybrowser": {"headless": False}})
            self.assertFalse(explicit["roxybrowser"]["headless"])

    def test_roxy_profile_lifecycle_uses_bound_proxy_and_deletes_after_close(self):
        session = _FakeSession()
        client = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000", "workspace_id": "w", "project_id": "p", "api_retries": 1, "headless": True}, session=session)
        profile_id = client.create_profile("http://user:pass@proxy.test:8000")
        opened = client.open_profile(profile_id)
        self.assertTrue(client.cleanup(opened))
        self.assertEqual(profile_id, "42")
        self.assertEqual(opened.debugger_address, "127.0.0.1:9222")
        create = next(body for method, url, body in session.calls if url.endswith("/browser/create"))
        self.assertEqual(create["workspaceId"], "w")
        self.assertEqual(create["projectId"], "p")
        self.assertEqual(create["proxyInfo"]["host"], "proxy.test")
        self.assertNotIn("headless", create)
        self.assertNotIn("forceOpen", create)
        opened_body = next(body for method, url, body in session.calls if url.endswith("/browser/open"))
        self.assertTrue(opened_body["headless"])
        self.assertFalse(opened_body["forceOpen"])
        self.assertEqual([url.rsplit("/", 1)[-1] for _method, url, _body in session.calls], ["create", "connection_info", "open", "close", "delete"])

    def test_roxy_cleanup_reports_incomplete_without_skipping_delete(self):
        session = _CleanupFailureSession()
        client = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000", "workspace_id": "w", "project_id": "p", "api_retries": 1}, session=session)
        completed = client.cleanup(RoxyOpenResult("42", {}, created_by_run=True))
        self.assertFalse(completed)
        self.assertEqual([url.rsplit("/", 1)[-1] for _method, url, _body in session.calls], ["close", "delete"])

    def test_open_profile_reconciles_async_connection_info(self):
        session = _ConnectionInfoSession()
        client = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000", "workspace_id": "w", "project_id": "p", "api_retries": 1, "headless": True}, session=session)
        opened = client.open_profile("42")
        self.assertEqual(opened.debugger_address, "127.0.0.1:9222")
        self.assertEqual(opened.ws_endpoint, "ws://127.0.0.1:9222/devtools/browser/42")
        self.assertEqual([url.rsplit("/", 1)[-1] for _method, url, _body in session.calls], ["connection_info", "open", "connection_info"])

    def test_open_profile_adopts_existing_connection_without_opening_again(self):
        session = _AlreadyOpenSession()
        client = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000", "workspace_id": "w", "project_id": "p", "api_retries": 1, "headless": True}, session=session)
        opened = client.open_profile("42")
        self.assertEqual(opened.debugger_address, "127.0.0.1:9222")
        self.assertEqual([url.rsplit("/", 1)[-1] for _method, url, _body in session.calls], ["connection_info"])

    def test_signup_bootstrap_uses_chatgpt_context_and_selenium_callback_last(self):
        driver = _SignupDriver()
        RoxyRegistrationRunner._open_signup_page(driver, "account@example.test", 90)
        self.assertEqual(driver.timeout, 90)
        self.assertEqual(driver.visits, ["https://chatgpt.com/", "https://auth.openai.com/log-in"])
        script, args = driver.scripts[0]
        self.assertEqual(args, ("account@example.test",))
        self.assertIn("arguments[arguments.length - 1]", script)
        self.assertIn("screen_hint: 'signup'", script)

    def test_signup_bootstrap_rejects_untrusted_redirect(self):
        driver = _SignupDriver({"ok": True, "url": "https://example.test/collect"})
        with self.assertRaises(FreeRegisterError) as raised:
            RoxyRegistrationRunner._open_signup_page(driver, "account@example.test", 90)
        self.assertEqual(raised.exception.error_code, "free_roxy_signup_bootstrap_response_invalid")
        self.assertEqual(driver.visits, ["https://chatgpt.com/"])

    def test_signup_navigation_error_continues_after_trusted_auth_redirect(self):
        driver = _AuthNavigationErrorDriver()
        RoxyRegistrationRunner._open_signup_page(driver, "account@example.test", 90)
        self.assertEqual(driver.current_url, "https://auth.openai.com/api/accounts/authorize")

    def test_email_verification_redirect_is_treated_as_submitted_signup(self):
        driver = _SignupDriver()
        driver.current_url = "https://auth.openai.com/email-verification"
        self.assertTrue(RoxyRegistrationRunner._is_email_verification_page(driver))

    def test_session_extraction_navigates_to_endpoint_and_accepts_lowercase_token(self):
        driver = _SessionDriver({"WARNING_BANNER": "private warning", "access_token": "TEST_TOKEN"})
        result = extract_session(driver, 5)
        self.assertEqual(session_token(result), "TEST_TOKEN")
        self.assertEqual(driver.visits, ["https://chatgpt.com/api/auth/session", "https://chatgpt.com/"])

    def test_session_failure_does_not_include_response_body(self):
        driver = _SessionDriver({"WARNING_BANNER": "PRIVATE_RESPONSE_BODY"})
        with self.assertRaises(FreeRegisterError) as raised:
            extract_session(driver, 5)
        self.assertIn("WARNING_BANNER", str(raised.exception))
        self.assertNotIn("PRIVATE_RESPONSE_BODY", str(raised.exception))

    def test_same_origin_session_fetch_accepts_nested_token_and_restores_home(self):
        driver = _BrowserSessionDriver({
            "ok": True,
            "status": 200,
            "content_type": "application/json; charset=utf-8",
            "payload": {"data": {"access_token": "NESTED_TOKEN"}, "user": {"id": "safe-id"}},
            "body_length": 120,
        })
        logs = []
        result = extract_session(driver, 5, lambda message, level="info": logs.append((level, message)))
        self.assertEqual(session_token(result), "NESTED_TOKEN")
        self.assertEqual(driver.visits, ["https://chatgpt.com/"])
        self.assertTrue(any("HTTP 200" in message and "Token=存在" in message for _level, message in logs))
        self.assertFalse(any("NESTED_TOKEN" in message for _level, message in logs))

    def test_same_origin_session_summaries_reject_http_and_non_json(self):
        http_driver = _BrowserSessionDriver({
            "ok": True, "status": 503, "content_type": "application/json", "payload": {}, "body_length": 2,
        })
        payload, summary = free_roxy_session._browser_session(http_driver)
        self.assertEqual(payload, {})
        self.assertEqual(summary, "HTTP 503")
        html_driver = _BrowserSessionDriver({
            "ok": True, "status": 200, "content_type": "text/html", "payload": {}, "body_length": 20,
        })
        payload, summary = free_roxy_session._browser_session(html_driver)
        self.assertEqual(payload, {})
        self.assertEqual(summary, "响应类型 text/html")

    def test_password_page_switches_to_reference_passwordless_otp_action(self):
        driver = _PageDriver()
        self.assertEqual(classify_page(driver), "login_password")
        switch_login_to_email_code(driver)
        self.assertEqual(classify_page(driver), "otp")

    def test_passwordless_action_missing_has_stable_existing_login_error(self):
        driver = _PageDriver(click_result=False)
        with self.assertRaises(FreeRegisterError) as raised:
            switch_login_to_email_code(driver)
        self.assertEqual(raised.exception.node_code, "free_existing_login")
        self.assertEqual(raised.exception.error_code, "free_existing_passwordless_action_missing")
        self.assertNotIn("passwordless", str(raised.exception).casefold())

    def test_post_otp_classifies_signup_password_and_security(self):
        password_driver = _PageDriver("https://auth.openai.com/sign-up/password")
        self.assertEqual(wait_after_otp_submit(password_driver, 3), "signup_password")
        security_driver = _PageDriver("https://auth.openai.com/authorize", body="Verify you are human")
        self.assertEqual(wait_after_otp_submit(security_driver, 3), "security")

    def test_signup_password_uses_form_scoped_submit_once_and_verifies_value(self):
        driver = _SignupPasswordDriver()
        runner = RoxyRegistrationRunner()
        human = type("Human", (), {"actions": False, "delay": staticmethod(lambda _kind: None)})()
        logs = []
        state = runner._submit_signup_password(
            driver,
            human,
            lambda message, level="info": logs.append((level, message)),
        )
        self.assertEqual(state, "otp")
        self.assertEqual(driver.clicks, 1)
        self.assertEqual(driver.field.value, FIXED_PASSWORD)
        self.assertTrue(any("提交一次" in message for _level, message in logs))

    def test_signup_password_reports_submit_not_observed_without_repeating_click(self):
        driver = _StalledSignupPasswordDriver()
        runner = RoxyRegistrationRunner()
        human = type("Human", (), {"actions": False, "delay": staticmethod(lambda _kind: None)})()
        with self.assertRaises(FreeRegisterError) as raised:
            runner._submit_signup_password(driver, human, lambda *_args: None)
        self.assertEqual(raised.exception.error_code, "free_roxy_signup_password_submit_not_observed")

    def test_password_target_resolution_rejects_login_password_page(self):
        driver = _PageDriver("https://auth.openai.com/log-in/password")
        with self.assertRaises(FreeRegisterError) as raised:
            password_form_targets(driver)
        self.assertEqual(raised.exception.error_code, "free_roxy_signup_password_wrong_page")

    def test_existing_account_runner_uses_fixed_proxy_otp_and_never_saves_signup_password(self):
        driver = _ExistingLoginDriver()
        runner = _ExistingLoginRunner(driver)
        task = {
            "task_id": "free-existing-1",
            "email": "existing@example.test",
            "mailbox_url": "https://mail.example.test/inbox/private",
            "proxy": "http://user:pass@proxy.example.test:8000",
            "expected_exit_ip": "203.0.113.10",
        }
        config = {
            "proxy_probe_url": "https://api.ipify.org",
            "email_code_timeout": 30,
            "auto_set_2fa": False,
            "roxybrowser": {
                "existing_account_login": True,
                "humanize_delay": False,
                "humanize_browser_actions": False,
                "selenium_timeout": 30,
                "post_registration_dwell_min": 0,
                "post_registration_dwell_max": 0,
            },
        }
        stages = []
        logs = []
        stop = type("Stop", (), {"is_set": staticmethod(lambda: False)})()
        with (
            patch("mac_overrides.free_roxy_runtime.RoxyBrowserClient", _ExistingLoginClient),
            patch(
                "mac_overrides.free_roxy_runtime.build_free_mailbox_otp_provider",
                lambda *_args, **_kwargs: _ExistingOtp(),
            ),
            patch("mac_overrides.free_roxy_runtime.time.sleep", lambda _seconds: None),
        ):
            result = runner(
                task,
                config,
                stop,
                lambda task_id, code: stages.append((task_id, code)),
                lambda message, level="info": logs.append((level, message)),
            )
        self.assertEqual(result["account_flow"], "existing_login")
        self.assertEqual(result["access_token"], "EXISTING_TOKEN")
        self.assertNotIn("password", result)
        self.assertNotIn("credential_line", result)
        self.assertIn(("free-existing-1", "free_existing_login"), stages)
        self.assertIn(("free-existing-1", "free_existing_login_otp"), stages)
        self.assertTrue(any("已有账号邮箱验证码登录" in message for _level, message in logs))
        self.assertTrue(driver.closed)

    def test_proxy_import_appends_without_duplicate_credentials(self):
        with TemporaryDirectory() as directory:
            pool = FreeProxyPool(Path(directory))
            self.assertEqual(pool.import_text("proxy-a.test:8000:user:pass\n"), 1)
            self.assertEqual(pool.import_text("proxy-a.test:8000:user:pass\nproxy-b.test:8000\n"), 1)
            self.assertEqual(len(pool.values()), 2)

    def test_proxy_info_keeps_supported_protocol_and_masks_nothing_in_payload_contract(self):
        info = proxy_to_roxy_info("socks5h://u:p@proxy.test:8000")
        self.assertEqual(info["protocol"], "SOCKS5")
        self.assertEqual(info["proxyUserName"], "u")
        self.assertEqual(info["proxyPassword"], "p")


if __name__ == "__main__":
    unittest.main()
