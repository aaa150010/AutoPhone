from __future__ import annotations

from pathlib import Path
import json
from types import SimpleNamespace
import tempfile
import unittest

from mac_overrides.free_config_routes import save_free_config_bundle
from mac_overrides.free_register_config import FreeConfigStore


class FreeConfigRouteTests(unittest.TestCase):
    def test_legacy_proxy_policy_is_normalized_to_shared_pool(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            store.path.write_text(json.dumps({
                "version": 5,
                "proxy_allocation_mode": "exclusive",
                "proxy_selection": {"protocol": {"country": "US", "group": "residential"}},
            }), encoding="utf-8")
            normalized = store.normalize({
                "version": 5,
                "proxy_allocation_mode": "exclusive",
                "proxy_selection": {"protocol": {"country": "US", "group": "residential"}},
            })
            self.assertEqual(normalized["version"], 6)
            self.assertEqual(normalized["proxy_allocation_mode"], "healthy_random")
            self.assertEqual(normalized["proxy_selection"]["protocol"], {"country": "", "group": ""})
            self.assertEqual(store.load()["version"], 6)
            self.assertEqual(json.loads(store.path.read_text(encoding="utf-8"))["proxy_allocation_mode"], "healthy_random")

    def test_single_pool_migration_clears_classification_without_touching_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = FreeConfigStore(root)
            (root / "free_proxy_pool.json").write_text(json.dumps({
                "version": 3,
                "proxies": [{"proxy": "http://proxy.test:8000", "proxy_country": "US", "proxy_group": "住宅", "password": "private"}],
            }), encoding="utf-8")
            (root / "tasks.json").write_text(json.dumps({
                "tasks": {"task-1": {"proxy_country": "US", "proxy_group": "住宅", "token": "private-token"}},
            }), encoding="utf-8")
            results = root / "free_register_results"
            results.mkdir()
            (results / "result.json").write_text(json.dumps({"proxy_country": "US", "proxy_group": "住宅", "access_token": "private-token"}), encoding="utf-8")

            first = store.migrate_single_pool_state()
            second = store.migrate_single_pool_state()

            self.assertTrue(first["migrated"])
            self.assertFalse(second["migrated"])
            self.assertEqual(json.loads((root / "tasks.json").read_text())["tasks"]["task-1"]["proxy_country"], "")
            self.assertEqual(json.loads((results / "result.json").read_text())["proxy_group"], "")
            self.assertIn("private-token", (root / "tasks.json").read_text())
    def test_proxy_importer_signature_compatibility_calls_legacy_once(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))

            class LegacyProxies:
                def __init__(self):
                    self.calls = []

                def import_text(self, content):
                    self.calls.append(content)
                    return 1

                def public(self):
                    return {"count": 1, "rows": []}

            proxies = LegacyProxies()
            result = save_free_config_bundle(
                store,
                SimpleNamespace(proxies=proxies),
                {
                    "target_count": 2,
                    "proxy_content": "proxy.test:8000",
                    "proxy_country": "US",
                    "proxy_group": "住宅代理",
                    "proxy_scheme": "socks5h",
                },
            )

            self.assertEqual(result["proxy_imported"], 1)
            self.assertEqual(proxies.calls, ["proxy.test:8000"])
            self.assertEqual(store.load()["target_count"], 2)

    def test_proxy_importer_internal_typeerror_is_not_retried_or_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            store.save({"target_count": 4, "concurrency": 2})

            class FailingProxies:
                def __init__(self):
                    self.calls = []

                def import_text(self, content, *, country=None, group=None, scheme=None):
                    self.calls.append((content, country, group, scheme))
                    raise TypeError("synthetic importer internal failure")

                def public(self):
                    return {"count": 0, "rows": []}

            proxies = FailingProxies()
            with self.assertRaisesRegex(TypeError, "internal failure"):
                save_free_config_bundle(
                    store,
                    SimpleNamespace(proxies=proxies),
                    {
                        "target_count": 8,
                        "proxy_content": "proxy.test:8000",
                        "proxy_country": "US",
                        "proxy_group": "住宅代理",
                        "proxy_scheme": "socks5h",
                    },
                )

            self.assertEqual(
                proxies.calls,
                [("proxy.test:8000", "US", "住宅代理", "socks5h")],
            )
            saved = store.load()
            self.assertEqual((saved["target_count"], saved["concurrency"]), (4, 2))


if __name__ == "__main__":
    unittest.main()
