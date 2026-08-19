from __future__ import annotations

from pathlib import Path
import os
import json
from tempfile import TemporaryDirectory
import unittest

from mac_overrides.free_register_config import FreeConfigStore
from mac_overrides.free_roxy_runtime import RoxyBrowserClient, RoxyRegistrationRunner, proxy_to_roxy_info
from mac_overrides.free_roxy_session import extract_session, session_token
from mac_overrides.free_register_common import FreeRegisterError
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
    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        if url.endswith("/browser/open"):
            return _Response({"code": 0, "data": {}})
        if url.endswith("/browser/connection_info"):
            return _Response({"code": 0, "data": [{
                "dirId": "42",
                "ws": "ws://127.0.0.1:9222/devtools/browser/42",
                "http": "127.0.0.1:9222",
            }]})
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
            saved = store.save({"driver": "roxybrowser", "concurrency": 99, "roxybrowser": {"api_key": "secret", "workspace_id": "w", "project_id": "p"}})
            self.assertEqual(saved["concurrency"], 5)
            self.assertTrue(saved["roxybrowser"]["headless"])
            self.assertEqual(store.public()["roxybrowser"]["api_key"], "********")
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
        client.cleanup(opened)
        self.assertEqual(profile_id, "42")
        self.assertEqual(opened.debugger_address, "127.0.0.1:9222")
        create = next(body for method, url, body in session.calls if url.endswith("/browser/create"))
        self.assertEqual(create["workspaceId"], "w")
        self.assertEqual(create["projectId"], "p")
        self.assertEqual(create["proxyInfo"]["host"], "proxy.test")
        opened_body = next(body for method, url, body in session.calls if url.endswith("/browser/open"))
        self.assertTrue(opened_body["headless"])
        self.assertFalse(opened_body["forceOpen"])
        self.assertEqual([url.rsplit("/", 1)[-1] for _method, url, _body in session.calls], ["create", "open", "close", "delete"])

    def test_open_profile_reconciles_async_connection_info(self):
        session = _ConnectionInfoSession()
        client = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000", "workspace_id": "w", "project_id": "p", "api_retries": 1, "headless": True}, session=session)
        opened = client.open_profile("42")
        self.assertEqual(opened.debugger_address, "127.0.0.1:9222")
        self.assertEqual(opened.ws_endpoint, "ws://127.0.0.1:9222/devtools/browser/42")
        self.assertEqual([url.rsplit("/", 1)[-1] for _method, url, _body in session.calls], ["open", "connection_info"])

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
