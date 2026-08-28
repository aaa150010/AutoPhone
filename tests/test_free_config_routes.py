from __future__ import annotations

from pathlib import Path
import json
from types import SimpleNamespace
import tempfile
import unittest

from mac_overrides.free_config_routes import save_free_config_bundle
from mac_overrides.free_register_config import FreeConfigStore
from mac_overrides.free_camoufox_runtime import _effective_camoufox_headless


class FreeConfigRouteTests(unittest.TestCase):
    def test_new_config_defaults_to_socks5_remote_chatgpt(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            normalized = store.normalize({})
            self.assertEqual(normalized["version"], 9)
            self.assertEqual(normalized["proxy_default_scheme"], "socks5")
            self.assertEqual(normalized["proxy_socks5_dns_mode"], "remote")
            self.assertEqual(normalized["proxy_probe_url"], "https://chatgpt.com/")
            self.assertTrue(normalized["camoufox"]["debug_mode"])
            # ``headless`` remains the persisted preference.  The runtime
            # forces a headed browser while debug mode is enabled.
            self.assertTrue(normalized["camoufox"]["headless"])

    def test_v7_legacy_proxy_defaults_migrate_and_persist(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            store.path.write_text(json.dumps({
                "version": 7,
                "proxy_default_scheme": "http",
                "proxy_socks5_dns_mode": "auto",
                "proxy_probe_url": "https://chatgpt.com/",
            }), encoding="utf-8")
            normalized = store.load()
            self.assertEqual(normalized["version"], 8)
            self.assertEqual(normalized["proxy_default_scheme"], "socks5")
            self.assertEqual(normalized["proxy_socks5_dns_mode"], "remote")
            persisted = json.loads(store.path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["version"], 8)
            self.assertEqual(persisted["proxy_default_scheme"], "socks5")
            self.assertEqual(persisted["proxy_socks5_dns_mode"], "remote")
            self.assertTrue(persisted["camoufox"]["debug_mode"])
            self.assertTrue(persisted["camoufox"]["headless"])

            # A subsequent startup completes the new v8 -> v9 migration.
            normalized = store.load()
            self.assertEqual(normalized["version"], 9)
            self.assertEqual(json.loads(store.path.read_text(encoding="utf-8"))["version"], 9)

    def test_v8_config_adds_debug_mode_and_persists_as_v9(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            store.path.write_text(json.dumps({
                "version": 8,
                "proxy_default_scheme": "socks5",
                "proxy_socks5_dns_mode": "remote",
                "camoufox": {"headless": True},
            }), encoding="utf-8")

            normalized = store.load()

            self.assertEqual(normalized["version"], 9)
            self.assertTrue(normalized["camoufox"]["debug_mode"])
            # The old user's headless preference is preserved for when debug
            # mode is later disabled.
            self.assertTrue(normalized["camoufox"]["headless"])
            persisted = json.loads(store.path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["version"], 9)
            self.assertTrue(persisted["camoufox"]["debug_mode"])

    def test_v9_explicit_debug_mode_and_headless_choice_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            normalized = store.normalize({
                "version": 9,
                "camoufox": {"debug_mode": False, "headless": True},
            })

            self.assertEqual(normalized["version"], 9)
            self.assertFalse(normalized["camoufox"]["debug_mode"])
            self.assertTrue(normalized["camoufox"]["headless"])

    def test_debug_mode_forces_effective_headed_without_overwriting_preference(self):
        self.assertEqual(
            _effective_camoufox_headless({"debug_mode": True, "headless": True}),
            (True, False),
        )
        self.assertEqual(
            _effective_camoufox_headless({"camoufox": {"debug_mode": True, "headless": True}}),
            (True, False),
        )
        self.assertEqual(
            _effective_camoufox_headless({"debug_mode": False, "headless": True}),
            (False, True),
        )
        self.assertEqual(
            _effective_camoufox_headless({"debug_mode": False, "headless": False}),
            (False, False),
        )
        self.assertEqual(
            _effective_camoufox_headless({"debug_mode": "false", "headless": True}),
            (False, True),
        )

    def test_v8_explicit_debug_mode_off_is_not_overridden_by_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            store.path.write_text(json.dumps({
                "version": 8,
                "camoufox": {"debug_mode": False, "headless": True},
            }), encoding="utf-8")

            normalized = store.load()

            self.assertEqual(normalized["version"], 9)
            self.assertFalse(normalized["camoufox"]["debug_mode"])
            self.assertTrue(normalized["camoufox"]["headless"])

    def test_current_explicit_proxy_defaults_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            normalized = store.normalize({
                "version": 8,
                "proxy_default_scheme": "http",
                "proxy_socks5_dns_mode": "local",
            })
            self.assertEqual(normalized["version"], 9)
            self.assertEqual(normalized["proxy_default_scheme"], "http")
            self.assertEqual(normalized["proxy_socks5_dns_mode"], "local")

    def test_free_config_forces_twofa_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            normalized = store.normalize({"auto_set_2fa": False})
            self.assertTrue(normalized["auto_set_2fa"])
            saved = store.save({"auto_set_2fa": False})
            self.assertTrue(saved["auto_set_2fa"])
            self.assertTrue(store.public()["auto_set_2fa"])

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

    def test_v6_config_is_persisted_as_v7_on_load(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))
            store.path.write_text(json.dumps({"version": 6, "proxy_allocation_mode": "healthy_random"}), encoding="utf-8")
            self.assertEqual(store.load()["version"], 7)
            self.assertEqual(json.loads(store.path.read_text(encoding="utf-8"))["version"], 7)

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

    def test_proxy_source_label_is_forwarded_without_becoming_allocation_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FreeConfigStore(Path(directory))

            class Proxies:
                def __init__(self):
                    self.calls = []

                def import_text(self, content, **kwargs):
                    self.calls.append((content, kwargs))
                    return 1

                def public(self):
                    return {"count": 1, "rows": []}

            proxies = Proxies()
            save_free_config_bundle(
                store,
                SimpleNamespace(proxies=proxies),
                {
                    "proxy_content": "proxy.test:8000",
                    "proxy_scheme": "socks5",
                    "proxy_source_label": "cliproxy",
                    "proxy_country": "CN",
                    "proxy_group": "住宅",
                },
            )

            self.assertEqual(proxies.calls[0][1]["source_label"], "cliproxy")
            self.assertEqual(store.load()["proxy_allocation_mode"], "healthy_random")


if __name__ == "__main__":
    unittest.main()
