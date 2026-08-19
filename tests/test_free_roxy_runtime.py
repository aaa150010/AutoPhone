from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mac_overrides.free_register_config import FreeConfigStore
from mac_overrides.free_roxy_runtime import RoxyBrowserClient, proxy_to_roxy_info
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


class FreeRoxyRuntimeTests(unittest.TestCase):
    def test_config_is_free_only_and_masks_roxy_key(self):
        with TemporaryDirectory() as directory:
            store = FreeConfigStore(directory)
            saved = store.save({"driver": "roxybrowser", "concurrency": 99, "roxybrowser": {"api_key": "secret", "workspace_id": "w", "project_id": "p"}})
            self.assertEqual(saved["concurrency"], 5)
            self.assertEqual(store.public()["roxybrowser"]["api_key"], "********")
            self.assertNotIn("free_proxy_pool_content", store.load())

    def test_roxy_profile_lifecycle_uses_bound_proxy_and_deletes_after_close(self):
        session = _FakeSession()
        client = RoxyBrowserClient({"api_base": "http://127.0.0.1:50000", "workspace_id": "w", "project_id": "p", "api_retries": 1}, session=session)
        profile_id = client.create_profile("http://user:pass@proxy.test:8000")
        opened = client.open_profile(profile_id)
        client.cleanup(opened)
        self.assertEqual(profile_id, "42")
        self.assertEqual(opened.debugger_address, "127.0.0.1:9222")
        create = next(body for method, url, body in session.calls if url.endswith("/browser/create"))
        self.assertEqual(create["workspaceId"], "w")
        self.assertEqual(create["projectId"], "p")
        self.assertEqual(create["proxyInfo"]["host"], "proxy.test")
        self.assertEqual([url.rsplit("/", 1)[-1] for _method, url, _body in session.calls], ["create", "open", "close", "delete"])

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
