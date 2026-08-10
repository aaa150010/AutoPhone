from __future__ import annotations

from types import SimpleNamespace
import threading
import unittest

from flask import Flask, jsonify, request

from mac_overrides.connectivity_routes import patch_openai_connectivity_guard_route


class _Store:
    def __init__(self) -> None:
        self.current = {"concurrency": 8, "openai_connectivity_guard": True}

    def load(self):
        return dict(self.current)

    def save(self, value):
        self.current = dict(value)
        return dict(self.current)


class ConnectivityGuardRouteTests(unittest.TestCase):
    def setUp(self):
        self.store = _Store()
        self.local = {"proxy": "masked", "openai_connectivity_guard": True}
        self.runtime = {"runtime": {"running": True}}
        self.logs = []
        self.fail_disable_write = False
        self.app = Flask(__name__)
        module = SimpleNamespace(jsonify=jsonify, request=request)
        patch_openai_connectivity_guard_route(
            self.app,
            module=module,
            lifecycle_lock=threading.Lock(),
            store=self.store,
            logs=SimpleNamespace(add=lambda *row: self.logs.append(row)),
            state_getter=lambda: self.runtime,
            read_local_config=lambda: dict(self.local),
            write_local_config=self._write_local,
            masked_local_config=lambda value: dict(value),
            masked_state=lambda value: dict(value),
        )

    def _write_local(self, value):
        if self.fail_disable_write and value.get("openai_connectivity_guard") is False:
            raise RuntimeError("private-proxy-password")
        self.local = dict(value)
        return dict(value)

    def test_guard_can_be_disabled_while_runtime_is_active(self):
        response = self.app.test_client().post(
            "/api/openai-connectivity-guard",
            json={"enabled": False},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["enabled"])
        self.assertFalse(self.store.current["openai_connectivity_guard"])
        self.assertFalse(self.local["openai_connectivity_guard"])
        self.assertEqual(self.local["proxy"], "masked")

    def test_non_boolean_value_is_rejected_without_changes(self):
        response = self.app.test_client().post(
            "/api/openai-connectivity-guard",
            json={"enabled": "false"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.store.current["openai_connectivity_guard"])
        self.assertTrue(self.local["openai_connectivity_guard"])

    def test_failed_local_write_rolls_back_store_without_exposing_detail(self):
        self.fail_disable_write = True
        response = self.app.test_client().post(
            "/api/openai-connectivity-guard",
            json={"enabled": False},
        )

        self.assertEqual(response.status_code, 500)
        self.assertTrue(self.store.current["openai_connectivity_guard"])
        self.assertTrue(self.local["openai_connectivity_guard"])
        self.assertNotIn("private-proxy-password", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
