from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest

from flask import Flask, Response, jsonify, request

from mac_overrides.web_routes import WebRouteContext, patch_flask_app


class FakeStore:
    def __init__(self) -> None:
        self.saved: list[dict] = []
        self.current = {"sms_api_keys": ["initial"]}

    def load(self):
        return dict(self.current)

    def save(self, value):
        saved = dict(value)
        self.saved.append(saved)
        self.current = saved
        return saved

    def save_pool_text(self, content):
        return Path("/tmp/fake-pool.txt")


class FakePool:
    def __init__(self):
        self.validation = {"ok": True, "entries": 3}

    def validate(self):
        return dict(self.validation)

    def reset_for_pool_replacement(self):
        return 0


class FakeImporter:
    def __init__(self) -> None:
        self.running = False
        self.started_with = None
        self.pool = FakePool()

    def status(self, _settings):
        return {"running": self.running}

    def settings_validation(self, _config, *, remote=False):
        return {
            "pool": {"entries": 3},
            "sub2_group": "default",
            "sub2_group_id": 1,
            "remote": remote,
        }

    def _pool(self, _config):
        return self.pool

    def start(self, config):
        self.started_with = dict(config)
        self.running = True

    def stop(self):
        self.running = False


class FakeLogs:
    def __init__(self) -> None:
        self.rows = []

    def add(self, message, level="info"):
        self.rows.append((message, level))


class FakeMailboxAdmin:
    def list_mailboxes(self):
        return []

    def import_mailboxes(self, _content):
        return {"ok": True, "imported": 0, "skipped": 0}

    def delete_mailboxes(self, _payload):
        return {"ok": True, "deleted": 0}

    def restore_mailboxes(self, _payload):
        return {"ok": True, "restored": 0}

    def latest_code(self, _payload):
        return {"ok": False, "error": "没有验证码"}


class FakeRunComponent:
    def begin_run(self):
        return None

    def clear(self):
        return None

    def reset(self):
        return None

    def public_statuses(self):
        return []


class WebRouteTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = FakeStore()
        self.importer = FakeImporter()
        self.logs = FakeLogs()
        self.preflight_started = threading.Event()
        self.release_preflight = threading.Event()
        self.preflight_configs: list[dict] = []
        self.configure_configs: list[dict] = []
        self.active_sms_keys: list[str] = []
        self.fail_configure_keys: list[str] | None = None
        self.local_config = {}
        self.module = SimpleNamespace(
            jsonify=jsonify,
            request=request,
            Response=Response,
            _clean=lambda value: str(value or "").strip(),
            _safe=str,
        )
        component = FakeRunComponent()
        self.context = WebRouteContext(
            module=self.module,
            app_dir=Path(self.tempdir.name),
            send_from_directory=lambda *_args, **_kwargs: None,
            closure_values=lambda _fn: {
                "importer": self.importer,
                "logs": self.logs,
                "settings": lambda: {},
                "state": lambda: {"runtime": {"running": self.importer.running}},
                "store": self.store,
            },
            lifecycle_lock=threading.Lock(),
            read_local_config=lambda: dict(self.local_config),
            write_local_config=self._write_local_config,
            local_config_from_runtime=lambda data, _existing=None: dict(data),
            local_config_secret=lambda _name: "",
            masked_local_config=lambda data: dict(data),
            masked_state=lambda data: dict(data),
            apply_server_defaults=lambda data: dict(data),
            configure_sms_pool=self._configure_sms_pool,
            preflight_sms_pool=self._preflight_sms_pool,
            safe_runtime_error=str,
            sms_alerts=component,
            sms_cost_ledger=component,
            sms_route_policy=component,
            sms_key_pool=component,
            sms_phone_gate=component,
            mailbox_admin_factory=lambda _store, _importer, _logs: FakeMailboxAdmin(),
            mailbox_manager_html="fallback",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _write_local_config(self, value):
        self.local_config = dict(value)
        return dict(value)

    def _configure_sms_pool(self, config, **_kwargs):
        self.configure_configs.append(dict(config))
        self.active_sms_keys = list(config.get("sms_api_keys") or [])
        if self.active_sms_keys == self.fail_configure_keys:
            raise RuntimeError("synthetic configure failure")
        return ""

    def _preflight_sms_pool(self, config, **_kwargs):
        self._configure_sms_pool(config)
        self.preflight_configs.append(dict(config))
        self.preflight_started.set()
        self.release_preflight.wait(2)
        return []

    def _app(self):
        app = Flask(__name__)

        app.add_url_rule("/", "index", lambda: "legacy")
        app.add_url_rule("/api/state", "api_state", lambda: {})
        app.add_url_rule("/api/config", "save_config", lambda: {}, methods=["POST"])
        app.add_url_rule("/api/preflight", "preflight", lambda: {}, methods=["POST"])
        app.add_url_rule("/api/start", "start", lambda: {}, methods=["POST"])
        app.add_url_rule("/api/stop", "stop", lambda: {}, methods=["POST"])
        return patch_flask_app(app, self.context)

    def test_start_preflight_blocks_save_and_second_preflight(self):
        app = self._app()
        start_result = []

        def run_start():
            with app.test_client() as client:
                start_result.append(
                    client.post(
                        "/api/start",
                        json={"sms_api_keys": ["key-a"], "pool_content": ""},
                    )
                )

        worker = threading.Thread(target=run_start)
        worker.start()
        self.assertTrue(self.preflight_started.wait(1))

        with app.test_client() as client:
            save_response = client.post("/api/config", json={"sms_api_keys": ["key-b"]})
            preflight_response = client.post("/api/preflight", json={"sms_api_keys": ["key-b"]})
            import_response = client.post(
                "/api/local-config/import",
                json={"config": {"sms_api_keys": ["key-b"]}},
            )

        self.assertEqual(save_response.status_code, 409)
        self.assertEqual(preflight_response.status_code, 409)
        self.assertEqual(import_response.status_code, 409)
        self.assertEqual(self.store.saved, [{"sms_api_keys": ["key-a"]}])
        self.assertEqual(self.preflight_configs, [{"sms_api_keys": ["key-a"]}])
        self.assertEqual(self.active_sms_keys, ["key-a"])
        self.assertEqual(self.local_config, {"sms_api_keys": ["key-a"]})

        self.release_preflight.set()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(start_result[0].status_code, 200)
        self.assertEqual(self.importer.started_with, {"sms_api_keys": ["key-a"]})

    def test_failed_pool_validation_keeps_saved_config_and_key_pool_consistent(self):
        app = self._app()
        self.importer.pool.validation = {"ok": False, "entries": 0, "errors": ["邮箱池为空"]}

        with app.test_client() as client:
            response = client.post("/api/start", json={"sms_api_keys": ["key-new"]})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.store.current["sms_api_keys"], ["key-new"])
        self.assertEqual(self.active_sms_keys, ["key-new"])
        self.assertEqual(self.local_config["sms_api_keys"], ["key-new"])
        self.assertIsNone(self.importer.started_with)

    def test_save_config_failure_rolls_back_store_pool_and_local_config(self):
        app = self._app()
        self.fail_configure_keys = ["key-bad"]

        with app.test_client() as client:
            response = client.post("/api/config", json={"sms_api_keys": ["key-bad"]})

        self.assertEqual(response.status_code, 500)
        self.assertFalse(response.get_json()["ok"])
        self.assertEqual(self.store.current, {"sms_api_keys": ["initial"]})
        self.assertEqual(self.active_sms_keys, ["initial"])
        self.assertEqual(self.local_config, {"sms_api_keys": ["initial"]})

    def test_local_config_export_does_not_mutate_active_local_config(self):
        app = self._app()
        before = dict(self.local_config)

        with app.test_client() as client:
            response = client.post(
                "/api/local-config/export",
                json={"sms_api_keys": ["draft-key"], "download": True},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["config"]["sms_api_keys"], ["draft-key"])
        self.assertEqual(self.local_config, before)


if __name__ == "__main__":
    unittest.main()
