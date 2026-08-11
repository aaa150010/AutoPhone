from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import patch

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
    def __init__(self):
        self.sub2_result = {"ok": True, "tested": 0, "results": []}
        self.selected_result = {
            "ok": True,
            "items": [],
            "skipped": 0,
        }
        self.relogin_result = {
            "ok": True,
            "count": 1,
            "items": [
                {
                    "row_id": "a" * 64,
                    "line_no": 7,
                    "email": "relogin@example.test",
                    "sub2api_account_id": "sub2-account-501",
                    "status_code": 401,
                    "status_kind": "unauthorized",
                }
            ],
        }
        self.relogin_payloads: list[dict] = []
        self.delete_result = {"ok": True, "deleted": 0}
        self.totp_result = {
            "ok": True,
            "kind": "totp",
            "code": "123456",
            "remaining": 17,
        }

    def list_mailboxes(self):
        return {"ok": True, "counts": {}, "rows": []}

    def import_mailboxes(self, _content):
        return {"ok": True, "imported": 0, "skipped": 0}

    def delete_mailboxes(self, _payload):
        return dict(self.delete_result)

    def restore_mailboxes(self, _payload):
        return {"ok": True, "restored": 0}

    def latest_code(self, _payload):
        return {"ok": False, "error": "没有验证码"}

    def reveal_password(self, _row_id, _line_no):
        return {"ok": False, "code": "mailbox_row_stale", "error": "邮箱列表已变化"}

    def reveal_totp(self, _row_id, _line_no):
        return dict(self.totp_result)

    def reveal_mailbox_url(self, _row_id, _line_no):
        return {"ok": True, "mailbox_url": "https://mail.example.test/messages/token"}

    def online_mailbox_snapshot(self):
        return {
            "ok": True,
            "items": [{
                "email": "user@example.test",
                "mailbox_url": "https://mail.example.test/messages/private-token",
            }],
            "eligible": 1,
            "skipped": 2,
            "local_duplicates": 1,
        }

    def sub2_test(self, _payload):
        return dict(self.sub2_result)

    def selected_success_results(self, _payload):
        return dict(self.selected_result)

    def query_openai_quotas(self, _payload):
        return {"ok": True, "results": [], "queried": 0, "failed": 0, "skipped": 0}

    def resolve_relogin_rows(self, payload):
        self.relogin_payloads.append(dict(payload))
        return dict(self.relogin_result)


class FakePixelError(RuntimeError):
    def __init__(self, public_message="公开错误", status_code=502):
        self.public_message = public_message
        self.status_code = status_code
        super().__init__("private-token-must-not-leak")


class FakeOnlineMailboxClient:
    def __init__(self):
        self.calls = []
        self.error = None

    def upload(self, items, *, batch_id):
        self.calls.append((list(items), batch_id))
        if self.error is not None:
            raise self.error
        return {
            "ok": True,
            "batch_id": batch_id,
            "submitted": len(items),
            "created": 1,
            "updated": 0,
            "duplicates": 0,
            "rejected": 0,
            "manager_url": "https://lynote.xyz/token-tool/mailboxes/",
        }


class FakeOnlineMailboxError(RuntimeError):
    def __init__(self, message, *, code, status_code, provider_status=None):
        self.public_message = message
        self.code = code
        self.status_code = status_code
        self.provider_status = provider_status
        super().__init__("private-provider-detail-must-not-leak")


class FakePixelClient:
    def __init__(self):
        self.calls = []
        self.error = None

    def _result(self, name, *values):
        self.calls.append((name, *values))
        if self.error is not None:
            raise self.error
        return {"operation": name}

    def targets(self):
        self.calls.append(("targets",))
        if self.error is not None:
            raise self.error
        return {
            "targets": [
                {"id": "pixel-1", "email": "excluded@example.com"},
                {"id": "pixel-2", "email": "automatic@example.com", "accountCount": 12},
                {"id": "pixel-3", "email": "automatic-3@example.com", "accountCount": 13},
                {"id": "pixel-4", "email": "automatic-4@example.com", "accountCount": 14},
                {"id": "pixel-5", "email": "automatic-5@example.com", "accountCount": 15},
                {"id": "pixel-6", "email": "automatic-6@example.com", "accountCount": 16},
                {"targetId": "pixel-7", "email": "automatic-7@example.com", "accountCount": 17},
            ]
        }

    def accounts(self, target_id, **query):
        self.calls.append(("accounts", target_id, query))
        if self.error is not None:
            raise self.error
        return {"items": [], "page": int(query["page"]), "pageSize": int(query["page_size"])}

    def bulk_test(self, target_id, account_ids):
        return self._result("bulk_test", target_id, list(account_ids))

    def share_accounts(self, target_id, account_ids):
        return self._result("share_accounts", target_id, list(account_ids))

    def relogin(self, target_id):
        return self._result("relogin", target_id)

    def share_all(self, target_ids):
        return self._result("share_all", list(target_ids))


class FakePixelQueue:
    def __init__(self):
        self.calls = []
        self.error = None

    def records(self):
        if self.error is not None:
            raise self.error
        return [{"record_id": "record-a", "targets": []}]

    def overview(self):
        return {
            "revision": 7,
            "queue": {"configured_workers": 2, "active_workers": 1, "pending_records": 3},
            "current_batch": {
                "batch_id": "batch-a",
                "status": "processing",
                "source": {"total": 4, "completed": 1, "success": 1},
                "deliveries": {"total": 24, "success": 6},
            },
        }

    def batches(self, *, page, page_size):
        self.calls.append(("batches", page, page_size))
        return {"items": [self.overview()["current_batch"]], "total": 1, "page": 1, "page_size": 20}

    def batch_records(self, batch_id, *, page, page_size, status):
        self.calls.append(("batch_records", batch_id, page, page_size, status))
        return {
            "batch": self.overview()["current_batch"],
            "items": [{"record_id": "record-a", "targets": []}],
            "total": 1,
            "page": 1,
            "page_size": 50,
        }

    def retry(self, record_id, target_ids):
        self.calls.append((record_id, target_ids))
        if self.error is not None:
            raise self.error
        return {"record_id": record_id}

    def requeue(self, task_id, result_file):
        self.calls.append(("requeue", task_id, Path(result_file)))
        if self.error is not None:
            raise self.error
        return {"record_id": f"record-{task_id}", "targets": []}


class FakeNvClient:
    def __init__(self, configured=True):
        self.is_configured = configured

    def configured(self):
        return self.is_configured


class FakeNvQueue:
    def __init__(self, configured=True):
        self.client = FakeNvClient(configured)
        self.calls = []

    def overview(self):
        return {"revision": 1, "configured": self.client.configured(), "queue": {"active": 0, "pending": 0}, "current_batch": None, "batch_count": 1}

    def records(self):
        return [{"record_id": "nv-record", "status": "failed", "error": "safe"}]

    def batches(self):
        return [{"batch_id": "nv-batch", "status": "failed"}]

    def retry(self, record_id):
        self.calls.append(record_id)
        return {"record_id": record_id, "status": "queued"}


class FakeBatchUploadCoordinator:
    def __init__(self):
        self.calls = []
        self.retry_calls = []

    def begin(self, importer, settings):
        self.calls.append((importer, dict(settings)))
        return {"batch_id": settings["batch_id"]}

    def records(self):
        return [{
            "batch_id": "batch-a",
            "targets": {"pixel": True, "nv": True},
            "platforms": {
                "pixel": {"status": "queued", "error": ""},
                "nv": {"status": "queue_failed", "error": "safe failure"},
            },
        }]

    def retry(self, batch_id, platform):
        self.retry_calls.append((batch_id, platform))
        if batch_id == "missing":
            raise KeyError(batch_id)
        if platform == "pixel":
            raise ValueError("该平台当前不可重试")
        return {
            "batch_id": batch_id,
            "platforms": {platform: {"status": "queued", "error": ""}},
        }


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
        self.mailbox_admin = FakeMailboxAdmin()
        self.preflight_started = threading.Event()
        self.release_preflight = threading.Event()
        self.preflight_configs: list[dict] = []
        self.configure_configs: list[dict] = []
        self.active_sms_keys: list[str] = []
        self.fail_configure_keys: list[str] | None = None
        self.local_config = {}
        self.online_mailbox_client = FakeOnlineMailboxClient()
        self.online_mailbox_factory_calls = []
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
            test_email_notification=lambda _data: {
                "event": "test",
                "status": "sent",
                "timestamp": 123,
                "recipient_count": 1,
            },
            sms_alerts=component,
            sms_cost_ledger=component,
            sms_route_policy=component,
            sms_key_pool=component,
            sms_phone_gate=component,
            mailbox_admin_factory=lambda _store, _importer, _logs: self.mailbox_admin,
            mailbox_manager_html="fallback",
            online_mailbox_client_factory=self._online_mailbox_client_factory,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _write_local_config(self, value):
        self.local_config = dict(value)
        return dict(value)

    def _online_mailbox_client_factory(self, base_url, api_token):
        self.online_mailbox_factory_calls.append((base_url, api_token))
        return self.online_mailbox_client

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

    def _app(self, context=None):
        app = Flask(__name__)

        app.add_url_rule("/", "index", lambda: "legacy")
        app.add_url_rule("/api/state", "api_state", lambda: {})
        app.add_url_rule("/api/config", "save_config", lambda: {}, methods=["POST"])
        app.add_url_rule("/api/preflight", "preflight", lambda: {}, methods=["POST"])
        app.add_url_rule("/api/start", "start", lambda: {}, methods=["POST"])
        app.add_url_rule("/api/stop", "stop", lambda: {}, methods=["POST"])
        return patch_flask_app(app, context or self.context)

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
        self.assertEqual(self.importer.started_with["sms_api_keys"], ["key-a"])
        self.assertRegex(self.importer.started_with["batch_id"], r"^\d{8}-\d{4}(?:-\d{2,})?$")
        self.assertGreater(self.importer.started_with["batch_started_at"], 0)

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

    def test_start_existing_keeps_one_run_mailbox_selection_out_of_saved_config(self):
        self.store.current["target_count"] = 61
        app = self._app()
        response = app.test_client().post(
            "/api/start-existing",
            json={
                "target_count": 1,
                "run_mailbox_rows": [
                    {"row_id": "A" * 64, "line_no": 25},
                    {"row_id": "a" * 64, "line_no": "25"},
                    {"row_id": "B" * 64, "line_no": 83},
                ],
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.importer.started_with["_gptphone_run_mailbox_rows"],
            [
                {"row_id": "a" * 64, "line_no": 25},
                {"row_id": "b" * 64, "line_no": 83},
            ],
        )
        self.assertEqual(self.importer.started_with["target_count"], 2)
        self.assertEqual(self.store.current["target_count"], 61)
        self.assertNotIn("run_mailbox_rows", self.importer.started_with)
        self.assertNotIn("run_mailbox_rows", self.store.current)

    def test_start_existing_rejects_non_sha256_mailbox_row_ids(self):
        app = self._app()

        for row_id in ("a" * 63, "g" * 64, "邮箱" * 32):
            with self.subTest(row_id=row_id):
                response = app.test_client().post(
                    "/api/start-existing",
                    json={
                        "run_mailbox_rows": [{"row_id": row_id, "line_no": 1}],
                    },
                )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.get_json()["error"], "本次运行的邮箱行绑定参数无效")
                self.assertIsNone(self.importer.started_with)

    def test_start_existing_without_selected_rows_keeps_requested_target_behavior(self):
        self.store.current["target_count"] = 61
        app = self._app()

        response = app.test_client().post(
            "/api/start-existing",
            json={"target_count": 1},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.importer.started_with["target_count"], 1)
        self.assertEqual(self.store.current["target_count"], 1)
        self.assertNotIn("_gptphone_run_mailbox_rows", self.importer.started_with)

    def test_start_upload_targets_are_transient_and_coordinator_receives_selection(self):
        pixel = FakePixelQueue()
        nv = FakeNvQueue()
        coordinator = FakeBatchUploadCoordinator()
        app = self._app(replace(
            self.context,
            pixel_upload_queue=pixel,
            nv_upload_queue=nv,
            batch_upload_coordinator=coordinator,
        ))

        response = app.test_client().post(
            "/api/start-existing",
            json={"target_count": 1, "upload_targets": {"pixel": True, "nv": True}},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["upload_targets"], {"pixel": True, "nv": True})
        self.assertNotIn("upload_targets", self.store.current)
        self.assertNotIn("_gptphone_upload_targets", self.store.current)
        self.assertEqual(
            self.importer.started_with["_gptphone_upload_targets"],
            {"pixel": True, "nv": True},
        )
        self.assertEqual(
            coordinator.calls[0][1]["_gptphone_upload_targets"],
            {"pixel": True, "nv": True},
        )

    def test_start_defaults_both_upload_targets_off_and_rejects_unconfigured_nv(self):
        coordinator = FakeBatchUploadCoordinator()
        app = self._app(replace(
            self.context,
            pixel_upload_queue=FakePixelQueue(),
            nv_upload_queue=FakeNvQueue(configured=False),
            batch_upload_coordinator=coordinator,
        ))

        missing = app.test_client().post(
            "/api/start-existing",
            json={"upload_targets": {"nv": True}},
        )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.get_json()["code"], "nv_configuration_invalid")
        self.assertIsNone(self.importer.started_with)

        defaulted = app.test_client().post("/api/start-existing", json={})
        self.assertEqual(defaulted.status_code, 200)
        self.assertEqual(
            self.importer.started_with["_gptphone_upload_targets"],
            {"pixel": False, "nv": False},
        )
        self.assertEqual(coordinator.calls, [])

    def test_start_accepts_valid_nv_configuration_from_settings_draft(self):
        coordinator = FakeBatchUploadCoordinator()
        app = self._app(replace(
            self.context,
            nv_upload_queue=FakeNvQueue(configured=False),
            batch_upload_coordinator=coordinator,
        ))

        response = app.test_client().post(
            "/api/start-existing",
            json={
                "target_count": 1,
                "nv_import": {
                    "endpoint": "https://nv.example.test/api/import",
                    "api_key": "draft-nv-secret",
                },
                "upload_targets": {"nv": True},
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["upload_targets"], {"pixel": False, "nv": True})
        self.assertEqual(self.local_config["nv_import"]["api_key"], "draft-nv-secret")
        self.assertEqual(
            self.importer.started_with["_gptphone_upload_targets"],
            {"pixel": False, "nv": True},
        )

    def test_start_rejects_remote_http_nv_draft_before_saving_or_starting(self):
        app = self._app(replace(
            self.context,
            nv_upload_queue=FakeNvQueue(configured=False),
            batch_upload_coordinator=FakeBatchUploadCoordinator(),
        ))
        local_config_before = dict(self.local_config)

        response = app.test_client().post(
            "/api/start-existing",
            json={
                "nv_import": {
                    "endpoint": "http://nv.example.test/api/import",
                    "schema_url": "https://nv.example.test/api/schema",
                    "api_key": "draft-nv-secret",
                },
                "upload_targets": {"nv": True},
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "nv_configuration_invalid")
        self.assertIn("HTTPS", response.get_json()["error"])
        self.assertIsNone(self.importer.started_with)
        self.assertEqual(self.local_config, local_config_before)

    def test_relogin_starts_from_server_bound_rows_without_sms_preflight_or_config_save(self):
        app = self._app()
        payload = {
            "rows": [{
                "row_id": "a" * 64,
                "line_no": 7,
                "sub2api_account_id": "untrusted-client-account",
            }]
        }

        with app.test_client() as client:
            response = client.post("/api/mailboxes/relogin", json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["run_mode"], "relogin")
        self.assertEqual(response.get_json()["started"], 1)
        self.assertEqual(self.mailbox_admin.relogin_payloads, [payload])
        self.assertEqual(self.preflight_configs, [])
        self.assertEqual(self.store.saved, [])
        self.assertEqual(self.importer.started_with["run_mode"], "relogin")
        self.assertEqual(
            self.importer.started_with["_gptphone_upload_targets"],
            {"pixel": False, "nv": False},
        )
        self.assertEqual(self.importer.started_with["target_count"], 1)
        self.assertEqual(
            self.importer.started_with["_gptphone_relogin_rows"][0]["sub2api_account_id"],
            "sub2-account-501",
        )
        self.assertNotIn(
            "untrusted-client-account",
            str(self.importer.started_with["_gptphone_relogin_rows"]),
        )
        self.assertEqual(
            self.importer.started_with["_gptphone_run_mailbox_rows"],
            [{"row_id": "a" * 64, "line_no": 7}],
        )

    def test_relogin_rejects_stale_or_no_longer_failed_rows_before_start(self):
        app = self._app()
        with app.test_client() as client:
            for code in ("mailbox_rows_stale", "relogin_not_required"):
                with self.subTest(code=code):
                    self.mailbox_admin.relogin_result = {
                        "ok": False,
                        "code": code,
                        "error": "邮箱状态已变化",
                    }
                    response = client.post(
                        "/api/mailboxes/relogin",
                        json={"rows": [{"row_id": "a" * 64, "line_no": 7}]},
                    )
                    self.assertEqual(response.status_code, 409)
                    self.assertEqual(response.get_json()["code"], code)

        self.assertIsNone(self.importer.started_with)
        self.assertEqual(self.preflight_configs, [])
        self.assertEqual(self.store.saved, [])

    def test_save_config_failure_rolls_back_store_pool_and_local_config(self):
        app = self._app()
        self.fail_configure_keys = ["key-bad"]

        with app.test_client() as client:
            response = client.post("/api/config", json={"sms_api_keys": ["key-bad"]})

        self.assertEqual(response.status_code, 500)
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["node_code"], "config_save")
        self.assertEqual(payload["error_code"], "config_save_failed")
        self.assertEqual(payload["failure"]["node_label"], "保存运行配置")
        self.assertEqual(self.store.current, {"sms_api_keys": ["initial"]})
        self.assertEqual(self.active_sms_keys, ["initial"])
        self.assertEqual(self.local_config, {"sms_api_keys": ["initial"]})

    def test_config_and_preflight_failures_redact_submitted_credentials(self):
        secret = "submitted-private-key"

        def fail_config(config, **_kwargs):
            if secret in config.get("sms_api_keys", []):
                raise RuntimeError(f"provider rejected {secret}")
            return ""

        context = replace(
            self.context,
            configure_sms_pool=fail_config,
            failure_secrets=lambda config: tuple(config.get("sms_api_keys") or ()),
        )
        config_response = self._app(context).test_client().post(
            "/api/config", json={"sms_api_keys": [secret]},
        )
        self.assertEqual(config_response.status_code, 500)
        self.assertEqual(config_response.get_json()["node_code"], "config_save")
        self.assertNotIn(secret, config_response.get_data(as_text=True) + str(self.logs.rows))

        def fail_preflight(_config, **_kwargs):
            raise RuntimeError(f"upstream rejected {secret}")

        preflight_context = replace(
            self.context,
            preflight_sms_pool=fail_preflight,
            failure_secrets=lambda config: tuple(config.get("sms_api_keys") or ()),
        )
        preflight_response = self._app(preflight_context).test_client().post(
            "/api/preflight", json={"sms_api_keys": [secret]},
        )
        self.assertEqual(preflight_response.status_code, 502)
        self.assertEqual(preflight_response.get_json()["node_code"], "sms_preflight")
        self.assertNotIn(secret, preflight_response.get_data(as_text=True) + str(self.logs.rows))

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

    def test_local_config_export_never_contains_nv_api_key(self):
        secret = "nv-export-secret"
        app = self._app(replace(
            self.context,
            local_config_secret=lambda name: secret if name == "nv_import_api_key" else "",
        ))

        with app.test_client() as client:
            exported = client.post(
                "/api/local-config/export",
                json={
                    "download": True,
                    "nv_import": {
                        "endpoint": "https://nv.example.test/import",
                        "api_key": secret,
                    },
                },
            )
            revealed = client.post(
                "/api/local-config/secret",
                json={"id": "nv_import_api_key"},
            )

        self.assertEqual(exported.status_code, 200)
        self.assertNotIn("api_key", exported.get_json()["config"]["nv_import"])
        self.assertNotIn(secret, exported.get_data(as_text=True))
        self.assertEqual(revealed.get_json()["value"], secret)

    def test_sms_balance_query_uses_draft_config_without_exposing_or_saving_keys(self):
        secret = "draft-balance-secret"
        captured = []

        def query_balances(config):
            captured.append(dict(config))
            return [{
                "provider": "smsbower",
                "index": 1,
                "fingerprint": "abc123",
                "status": "usable",
                "balance_usd": 4.25,
                "last_checked_at": 123,
            }]

        app = self._app(replace(self.context, query_sms_balances=query_balances))
        before_local = dict(self.local_config)
        before_saved = list(self.store.saved)

        with app.test_client() as client:
            response = client.post(
                "/api/sms/balances",
                json={"sms_api_keys": [secret]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(captured, [{"sms_api_keys": [secret]}])
        self.assertEqual(response.get_json()["sms_key_statuses"][0]["balance_usd"], 4.25)
        self.assertNotIn(secret, response.get_data(as_text=True))
        self.assertEqual(self.local_config, before_local)
        self.assertEqual(self.store.saved, before_saved)

    def test_settings_route_and_notification_test_are_available(self):
        app = self._app()

        with app.test_client() as client:
            settings_response = client.get("/settings")
            accounts_response = client.get("/accounts")
            splitter_response = client.get("/splitter")
            notification_response = client.post(
                "/api/notifications/email/test",
                json={"email_notification": {"enabled": False}},
            )

        self.assertEqual(settings_response.status_code, 200)
        self.assertEqual(settings_response.get_data(as_text=True), "fallback")
        self.assertEqual(accounts_response.status_code, 200)
        self.assertEqual(accounts_response.get_data(as_text=True), "fallback")
        self.assertEqual(splitter_response.status_code, 200)
        self.assertEqual(splitter_response.get_data(as_text=True), "fallback")
        self.assertEqual(notification_response.status_code, 200)
        payload = notification_response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["notification"]["event"], "test")
        self.assertEqual(payload["notification"]["recipient_count"], 1)

    def test_mailbox_url_test_route_returns_safe_diagnostics_and_preserves_input(self):
        calls = []

        class FakeUrlTester:
            def test(self, value, **kwargs):
                calls.append((value, kwargs))
                return {
                    "ok": True,
                    "code_found": True,
                    "verification_code": "654321",
                    "reason": "code_found",
                    "attempts": 1,
                    "elapsed_seconds": 0.1,
                    "resend_attempted": False,
                    "resend_succeeded": False,
                    "diagnostics": {
                        "listing_messages": 1,
                        "detail_links": 1,
                        "detail_refreshed": 1,
                        "detail_cache_hits": 0,
                        "detail_refresh_pending": 0,
                        "detail_errors": 0,
                        "openai_messages": 1,
                        "code_messages": 1,
                    },
                }

        context = replace(
            self.context,
            mailbox_url_test_factory=FakeUrlTester,
            read_local_config=lambda: {
                "proxy": "http://127.0.0.1:7897",
                "proxy_scope": {"email": True},
            },
        )
        app = self._app(context)
        url = "https://mail.example.test/messages/sample-token/user%40example.test?all=1"
        with app.test_client() as client:
            response = client.post("/api/mailbox-url-test", json={"value": url})

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["verification_code"], "654321")
        self.assertEqual(calls[0][0], url)
        self.assertEqual(calls[0][1]["timeout_seconds"], 60)
        self.assertEqual(calls[0][1]["interval_seconds"], 5)
        self.assertEqual(calls[0][1]["resend_after_seconds"], 15)
        self.assertEqual(calls[0][1]["proxy"], "http://127.0.0.1:7897")

    def test_mailbox_url_test_redacts_isolated_url_and_proxy_credentials(self):
        class FailingUrlTester:
            def test(self, _value, **_kwargs):
                raise RuntimeError(
                    "request rejected auth_code=url-private-secret "
                    "by proxy-user with proxy-private-password"
                )

        context = replace(
            self.context,
            mailbox_url_test_factory=FailingUrlTester,
            read_local_config=lambda: {
                "proxy": "http://proxy-user:proxy-private-password@127.0.0.1:7897",
                "proxy_scope": {"email": True},
            },
        )
        app = self._app(context)
        submitted = "https://mail.example.test/inbox?auth_code=url-private-secret"

        response = app.test_client().post("/api/mailbox-url-test", json={"value": submitted})

        self.assertEqual(response.status_code, 500)
        payload = response.get_json()
        self.assertEqual(payload["node_code"], "mailbox_url_test")
        self.assertEqual(payload["error_code"], "mailbox_url_test_failed")
        serialized = response.get_data(as_text=True) + str(self.logs.rows)
        for secret in ("url-private-secret", "proxy-user", "proxy-private-password"):
            self.assertNotIn(secret, serialized)

    def test_start_and_relogin_exceptions_keep_exact_failure_nodes(self):
        def fail_start(_config):
            raise OSError("marker-free startup failure")

        self.importer.start = fail_start
        context = replace(self.context, preflight_sms_pool=lambda *_args, **_kwargs: [])
        app = self._app(context)

        start_response = app.test_client().post(
            "/api/start", json={"sms_api_keys": ["key-a"], "pool_content": ""},
        )
        start_payload = start_response.get_json()
        self.assertEqual(start_response.status_code, 500)
        self.assertEqual(start_payload["node_code"], "run_start")
        self.assertEqual(start_payload["node_label"], "启动注册任务")
        self.assertEqual(start_payload["error_code"], "run_start_failed")
        self.assertEqual(start_payload["failure"]["node_code"], "run_start")

        relogin_response = app.test_client().post(
            "/api/mailboxes/relogin",
            json={"rows": [{"row_id": "a" * 64, "line_no": 7}]},
        )
        relogin_payload = relogin_response.get_json()
        self.assertEqual(relogin_response.status_code, 500)
        self.assertEqual(relogin_payload["node_code"], "relogin_start")
        self.assertEqual(relogin_payload["node_label"], "启动重登任务")
        self.assertEqual(relogin_payload["error_code"], "relogin_start_failed")
        self.assertEqual(relogin_payload["failure"]["node_code"], "relogin_start")

    def test_mailbox_read_exceptions_return_exact_redacted_failures(self):
        secret = "mailbox-read-private-secret"

        def fail(*_args, **_kwargs):
            raise RuntimeError(secret)

        self.mailbox_admin.latest_code = fail
        self.mailbox_admin.reveal_password = fail
        self.mailbox_admin.reveal_totp = fail
        self.mailbox_admin.reveal_mailbox_url = fail
        app = self._app()
        requests = (
            ("/api/mailboxes/latest-code", {}, "email_code_lookup"),
            ("/api/mailboxes/password", {"row_id": "a" * 64, "line_no": 1}, "mailbox_password_reveal"),
            ("/api/mailboxes/totp", {"row_id": "a" * 64, "line_no": 1}, "mailbox_totp_reveal"),
            ("/api/mailboxes/url", {"row_id": "a" * 64, "line_no": 1}, "mailbox_url_reveal"),
        )
        with app.test_client() as client:
            for path, body, node_code in requests:
                with self.subTest(path=path):
                    response = client.post(path, json=body)
                    self.assertEqual(response.status_code, 500)
                    self.assertEqual(response.get_json()["node_code"], node_code)
                    self.assertEqual(response.get_json()["failure"]["node_code"], node_code)
                    self.assertNotIn(secret, response.get_data(as_text=True))

    def test_manifest_and_runtime_task_read_exceptions_are_structured(self):
        class FailingRunManifest:
            log_fn = None

            def records(self, **_kwargs):
                raise RuntimeError("run-manifest-private-detail")

            def get(self, *_args, **_kwargs):
                raise RuntimeError("run-detail-private-detail")

        class FailingUploadCoordinator:
            def records(self):
                raise RuntimeError("upload-manifest-private-detail")

        context = replace(
            self.context,
            run_batch_manifest=FailingRunManifest(),
            batch_upload_coordinator=FailingUploadCoordinator(),
        )
        app = self._app(context)
        with app.test_client() as client:
            responses = (
                (client.get("/api/run-batches"), "run_batch_manifest"),
                (client.get("/api/run-batches/batch-1"), "run_batch_manifest"),
                (client.get("/api/upload-manifests"), "batch_upload_manifest"),
            )
        for response, node_code in responses:
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.get_json()["node_code"], node_code)
            self.assertIn("failure", response.get_json())
            self.assertNotIn("private-detail", response.get_data(as_text=True))

        source_row = "user@example.test---password---refresh-token---client-id"
        self.importer.tasks = {"task-1": {"source_row": source_row}}
        self.importer.lock = threading.RLock()

        def fail_list():
            raise RuntimeError("runtime-task-private-detail")

        self.mailbox_admin.list_mailboxes = fail_list
        runtime_response = app.test_client().post(
            "/api/runtime/tasks/mailbox-url", json={"task_id": "task-1"},
        )
        self.assertEqual(runtime_response.status_code, 500)
        self.assertEqual(runtime_response.get_json()["error_code"], "runtime_task_mailbox_url_failed")
        self.assertNotIn("private-detail", runtime_response.get_data(as_text=True))

    def test_local_config_notification_and_balance_exceptions_are_structured(self):
        secret = "route-private-secret"

        failure_enabled = False

        def fail_config(data, *_args, **_kwargs):
            if failure_enabled:
                raise RuntimeError(secret)
            return dict(data)

        context = replace(
            self.context,
            local_config_from_runtime=fail_config,
            local_config_secret=lambda _name: (_ for _ in ()).throw(RuntimeError(secret)),
            test_email_notification=lambda _data: (_ for _ in ()).throw(RuntimeError(secret)),
            query_sms_balances=lambda _data: (_ for _ in ()).throw(RuntimeError(secret)),
            failure_secrets=lambda _config: (secret,),
        )
        app = self._app(context)
        failure_enabled = True
        requests = (
            ("/api/local-config/export", {"download": True}, "local_config_export"),
            ("/api/local-config/import", {"config": {}}, "local_config_import"),
            ("/api/local-config/secret", {"id": "sms_api_key"}, "local_config_secret"),
            ("/api/notifications/email/test", {"email_notification": {"password": secret}}, "notification_test"),
            ("/api/sms/balances", {"sms_api_keys": [secret]}, "sms_balance_query"),
        )
        with app.test_client() as client:
            for path, body, node_code in requests:
                with self.subTest(path=path):
                    response = client.post(path, json=body)
                    self.assertGreaterEqual(response.status_code, 500)
                    self.assertEqual(response.get_json()["node_code"], node_code)
                    self.assertIn("failure", response.get_json())
                    self.assertNotIn(secret, response.get_data(as_text=True) + str(self.logs.rows))

    def test_mailbox_totp_route_returns_temporary_code_without_base32_secret(self):
        app = self._app()

        with app.test_client() as client:
            response = client.post(
                "/api/mailboxes/totp",
                json={"row_id": "a" * 64, "line_no": 1},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(
            payload,
            {"ok": True, "kind": "totp", "code": "123456", "remaining": 17},
        )
        self.assertNotIn("totp_secret", payload)

        self.mailbox_admin.totp_result = {
            "ok": False,
            "code": "mailbox_row_stale",
            "error": "邮箱列表已变化，请刷新后重试",
        }
        with app.test_client() as client:
            stale = client.post(
                "/api/mailboxes/totp",
                json={"row_id": "b" * 64, "line_no": 1},
            )

        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.get_json()["code"], "mailbox_row_stale")
        self.assertNotIn("totp_secret", stale.get_json())

    def test_stale_mailbox_password_request_returns_conflict(self):
        app = self._app()

        with app.test_client() as client:
            response = client.post(
                "/api/mailboxes/password",
                json={"row_id": "stale", "line_no": 1},
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["code"], "mailbox_row_stale")

    def test_mailbox_url_request_returns_bound_url_without_listing_it(self):
        app = self._app()

        with app.test_client() as client:
            response = client.post(
                "/api/mailboxes/url",
                json={"row_id": "row-1", "line_no": 1},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["mailbox_url"],
            "https://mail.example.test/messages/token",
        )

    def test_runtime_task_mailbox_url_rebinds_private_task_to_current_pool_row(self):
        source_row = (
            "private@example.test----password----client----refresh----"
            "https://mail.example.test/messages/private-token"
        )
        row_id = hashlib.sha256(source_row.encode("utf-8")).hexdigest()
        self.importer.tasks = {
            "T001-bound": {
                "task_id": "T001-bound",
                "source_row": source_row,
                "status": "authorizing",
            }
        }
        self.importer.lock = threading.RLock()
        self.mailbox_admin.list_mailboxes = lambda: {
            "ok": True,
            "rows": [{"row_id": row_id, "line_no": 7, "has_mailbox_url": True}],
        }
        reveal_calls = []

        def reveal(bound_row_id, line_no):
            reveal_calls.append((bound_row_id, line_no))
            return {
                "ok": True,
                "mailbox_url": "https://mail.example.test/messages/private-token",
            }

        self.mailbox_admin.reveal_mailbox_url = reveal
        app = self._app()

        response = app.test_client().post(
            "/api/runtime/tasks/mailbox-url",
            json={"task_id": "T001-bound"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(reveal_calls, [(row_id, 7)])
        payload = response.get_json()
        self.assertEqual(
            payload["mailbox_url"],
            "https://mail.example.test/messages/private-token",
        )
        serialized = json.dumps(payload)
        self.assertNotIn("private@example.test", serialized)
        self.assertNotIn("password", serialized)
        self.assertNotIn("refresh", serialized)

    def test_runtime_task_mailbox_url_rejects_missing_and_stale_tasks(self):
        source_row = "stale@example.test----password----private-url"
        self.importer.tasks = {
            "T002-stale": {
                "task_id": "T002-stale",
                "source_row": source_row,
                "status": "authorizing",
            }
        }
        self.mailbox_admin.list_mailboxes = lambda: {"ok": True, "rows": []}
        app = self._app()

        with app.test_client() as client:
            missing = client.post(
                "/api/runtime/tasks/mailbox-url",
                json={"task_id": "T999-missing"},
            )
            stale = client.post(
                "/api/runtime/tasks/mailbox-url",
                json={"task_id": "T002-stale"},
            )
            rejected = client.post(
                "/api/runtime/tasks/mailbox-url",
                json={"task_id": "T002-stale", "source_row": source_row},
            )

        self.assertEqual(missing.status_code, 404)
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.get_json()["code"], "mailbox_row_stale")
        self.assertEqual(rejected.status_code, 400)
        self.assertNotIn("stale@example.test", stale.get_data(as_text=True))
        self.assertNotIn("private-url", stale.get_data(as_text=True))

    def test_start_existing_returns_bad_request_for_invalid_notification_config(self):
        def invalid_config(_data):
            raise ValueError("enabled email_notification has invalid fields: password")

        app = self._app(replace(self.context, apply_server_defaults=invalid_config))

        with app.test_client() as client:
            response = client.post("/api/start-existing", json={})

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertIn("password", payload["error"])
        self.assertIn("state", payload)

    def test_mailbox_delete_maps_stale_binding_to_conflict(self):
        self.mailbox_admin.delete_result = {
            "ok": False,
            "code": "mailbox_rows_stale",
            "error": "邮箱列表已变化，请刷新后重试",
        }
        app = self._app()

        response = app.test_client().post(
            "/api/mailboxes/delete",
            json={"line_nos": [2], "rows": [{"row_id": "a" * 64, "line_no": 2}]},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["code"], "mailbox_rows_stale")

    def test_mailbox_unavailable_route_passes_stable_bindings_and_refreshes_rows(self):
        selected = [{"row_id": "a" * 64, "line_no": 2}]
        with patch(
            "mac_overrides.web_routes.mark_mailboxes_unavailable",
            return_value={"ok": True, "unavailable": 1},
        ) as unavailable:
            app = self._app()
            response = app.test_client().post(
                "/api/mailboxes/unavailable",
                json={"line_nos": [2], "rows": selected},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["unavailable"], 1)
        self.assertIn("mailboxes", response.get_json())
        unavailable.assert_called_once_with(
            self.mailbox_admin,
            {"line_nos": [2], "rows": selected},
        )

        with patch(
            "mac_overrides.web_routes.mark_mailboxes_unavailable",
            return_value={
                "ok": False,
                "code": "mailbox_rows_running",
                "error": "选中的邮箱仍在运行中，请等待任务结束后重试",
            },
        ):
            conflict = app.test_client().post(
                "/api/mailboxes/unavailable",
                json={"line_nos": [2], "rows": selected},
            )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.get_json()["code"], "mailbox_rows_running")

    def test_website_mailbox_import_uploads_server_snapshot_and_returns_counts(self):
        api_token = "online-api-private-token"
        app = self._app()
        self.local_config = {
            "online_mailbox": {
                "base_url": "https://lynote.xyz/token-tool",
                "api_token": api_token,
            }
        }
        response = app.test_client().post("/api/mailboxes/website-import", json={})

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["created"], 1)
        self.assertEqual(payload["skipped"], 2)
        self.assertEqual(payload["local_duplicates"], 1)
        self.assertEqual(
            self.online_mailbox_factory_calls,
            [("https://lynote.xyz/token-tool", api_token)],
        )
        self.assertEqual(len(self.online_mailbox_client.calls), 1)
        log_text = str(self.logs.rows)
        self.assertNotIn(api_token, log_text)
        self.assertNotIn("private-token", log_text)
        self.assertNotIn("user@example.test", log_text)

    def test_website_mailbox_import_preserves_safe_failure_identity(self):
        api_token = "online-api-private-token"
        app = self._app()
        self.local_config = {
            "online_mailbox": {
                "base_url": "https://lynote.xyz/token-tool",
                "api_token": api_token,
            }
        }
        self.online_mailbox_client.error = FakeOnlineMailboxError(
            "网站邮箱上传鉴权失败，请检查 API 密钥",
            code="online_mailbox_provider_http_error",
            status_code=401,
            provider_status=401,
        )
        response = app.test_client().post("/api/mailboxes/website-import", json={})

        self.assertEqual(response.status_code, 401)
        payload = response.get_json()
        self.assertEqual(payload["node_code"], "online_mailbox_upload")
        self.assertEqual(payload["node_label"], "网站邮箱上传")
        self.assertEqual(payload["provider_status"], 401)
        self.assertIn("网站邮箱上传鉴权失败", payload["error"])
        serialized = str(payload) + str(self.logs.rows)
        self.assertNotIn(api_token, serialized)
        self.assertNotIn("private-provider-detail", serialized)

    def test_website_mailbox_import_requires_configured_token(self):
        app = self._app()

        response = app.test_client().post("/api/mailboxes/website-import", json={})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error_code"], "online_mailbox_token_missing")
        self.assertEqual(self.online_mailbox_client.calls, [])

    def test_sub2_test_maps_stale_and_admin_failures_and_refreshes_success(self):
        app = self._app()
        with app.test_client() as client:
            self.mailbox_admin.sub2_result = {
                "ok": False,
                "code": "mailbox_rows_stale",
                "error": "邮箱列表已变化，请刷新后重试",
            }
            stale = client.post("/api/mailboxes/sub2-test", json={"rows": []})
            self.mailbox_admin.sub2_result = {
                "ok": False,
                "code": "sub2_admin_auth_failed",
                "error": "SUB2 管理员鉴权失败",
            }
            admin = client.post("/api/mailboxes/sub2-test", json={"rows": []})
            self.mailbox_admin.sub2_result = {
                "ok": True,
                "tested": 1,
                "results": [{"row_id": "row-a", "sub2_status": {"status_code": 200}}],
            }
            success = client.post("/api/mailboxes/sub2-test", json={"rows": []})

        self.assertEqual(stale.status_code, 409)
        self.assertEqual(admin.status_code, 502)
        self.assertEqual(success.status_code, 200)
        self.assertIn("mailboxes", success.get_json())
        self.assertIn("state", success.get_json())

    def test_mailbox_quota_route_returns_public_batch_results(self):
        app = self._app()
        with app.test_client() as client:
            response = client.post(
                "/api/mailboxes/quota",
                json={"rows": [{"row_id": "row-a", "line_no": 1}]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["ok"], True)
        self.assertIn("results", response.get_json())

    def test_mailbox_api_exposes_first_completed_row_while_peer_is_blocked(self):
        app = self._app()
        first_completed = threading.Event()
        release_second = threading.Event()
        rows = [
            {"row_id": "row-one", "line_no": 1},
            {"row_id": "row-two", "line_no": 2},
        ]
        public_rows = [
            {**row, "quota_status": "", "quota_5h": None, "quota_7d": None}
            for row in rows
        ]

        def list_mailboxes():
            return {"ok": True, "counts": {}, "rows": [dict(row) for row in public_rows]}

        def query_quotas(payload):
            callback = payload["_on_row_completed"]
            public_rows[0].update(
                quota_status="ok",
                quota_5h={"remaining_percent": 81},
                quota_7d={"remaining_percent": 41},
            )
            callback(payload["rows"][0])
            first_completed.set()
            self.assertTrue(release_second.wait(2))
            public_rows[1].update(
                quota_status="ok",
                quota_5h={"remaining_percent": 82},
                quota_7d={"remaining_percent": 42},
            )
            callback(payload["rows"][1])
            return {"ok": True, "queried": 2, "failed": 0, "skipped": 0, "results": []}

        self.mailbox_admin.list_mailboxes = list_mailboxes
        self.mailbox_admin.query_openai_quotas = query_quotas
        accepted = app.test_client().post(
            "/api/mailboxes/quota",
            json={"background": True, "rows": rows},
        )
        operation = accepted.get_json()["operation"]
        try:
            self.assertTrue(first_completed.wait(1))
            refreshed = app.test_client().get("/api/mailboxes").get_json()
            self.assertEqual(refreshed["operation"]["completed"], 1)
            self.assertEqual(refreshed["rows"][0]["quota_5h"]["remaining_percent"], 81)
            self.assertIsNone(refreshed["rows"][1]["quota_5h"])
        finally:
            release_second.set()

        manager = app.extensions["gptphone_mailbox_batch_operations"]
        self.assertEqual(manager.wait(operation["job_id"], 2)["completed"], 2)

    def test_mailbox_background_operation_survives_refresh_and_rejects_overlap(self):
        app = self._app()
        started = threading.Event()
        release = threading.Event()
        calls = []
        rows = [
            {
                "row_id": f"row-{index}",
                "line_no": index + 1,
                "email": "private@example.test",
                "access_token": "access-secret",
            }
            for index in range(7)
        ]

        def openai_test(payload):
            calls.append(payload)
            if len(calls) == 1:
                started.set()
                release.wait(2)
            return {
                "ok": True,
                "tested": len(payload["rows"]),
                "healthy": len(payload["rows"]),
                "results": [{"refresh_token": "must-not-be-retained"}],
            }

        self.mailbox_admin.openai_test = openai_test
        try:
            with app.test_client() as client:
                accepted = client.post(
                    "/api/mailboxes/openai-test",
                    json={"background": True, "rows": rows},
                )
            self.assertEqual(accepted.status_code, 202)
            operation = accepted.get_json()["operation"]
            self.assertTrue(started.wait(1))

            with app.test_client() as refreshed_client:
                refreshed = refreshed_client.get("/api/mailboxes")
                duplicate = refreshed_client.post(
                    "/api/mailboxes/sub2-test",
                    json={"background": True, "rows": rows},
                )
                overlap = refreshed_client.post(
                    "/api/mailboxes/quota",
                    json={"background": True, "rows": rows},
                )
            refreshed_operation = refreshed.get_json()["operation"]
            self.assertEqual(refreshed_operation["job_id"], operation["job_id"])
            self.assertEqual(refreshed_operation["status"], "running")
            self.assertEqual(duplicate.status_code, 202)
            self.assertFalse(duplicate.get_json()["created"])
            self.assertEqual(overlap.status_code, 409)
            self.assertEqual(overlap.get_json()["operation"]["job_id"], operation["job_id"])
        finally:
            release.set()

        manager = app.extensions["gptphone_mailbox_batch_operations"]
        completed = manager.wait(operation["job_id"], 2)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["completed"], 7)
        self.assertEqual([len(call["rows"]) for call in calls], [5, 2])
        serialized = json.dumps({
            "accepted": accepted.get_json(),
            "refreshed": refreshed.get_json(),
            "completed": completed,
            "logs": self.logs.rows,
        })
        self.assertNotIn("private@example.test", serialized)
        self.assertNotIn("access-secret", serialized)
        self.assertNotIn("must-not-be-retained", serialized)

    def test_mailbox_quota_background_route_chunks_all_stable_bindings(self):
        app = self._app()
        calls = []

        def query_quotas(payload):
            calls.append(payload)
            return {
                "ok": True,
                "queried": len(payload["rows"]),
                "failed": 0,
                "skipped": 0,
                "results": [],
            }

        self.mailbox_admin.query_openai_quotas = query_quotas
        rows = [{"row_id": f"quota-{index}", "line_no": index + 1} for index in range(11)]
        response = app.test_client().post(
            "/api/mailboxes/quota",
            json={"background": True, "rows": rows},
        )

        self.assertEqual(response.status_code, 202)
        operation = response.get_json()["operation"]
        manager = app.extensions["gptphone_mailbox_batch_operations"]
        completed = manager.wait(operation["job_id"], 2)
        self.assertEqual(completed["kind"], "quota")
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["succeeded"], 11)
        self.assertEqual([len(call["rows"]) for call in calls], [5, 5, 1])

    def test_mailbox_pixel_requeue_and_sub2_export_use_server_side_success_result(self):
        queue = FakePixelQueue()
        result_file = Path(self.tempdir.name) / "result.json"
        document = {"status": "success", "result": {"private": "server-only"}}
        self.mailbox_admin.selected_result = {
            "ok": True,
            "skipped": 1,
            "items": [{
                "task_id": "task-a",
                "result_file": result_file,
                "document": document,
                "email": "account@example.test",
            }],
        }

        def payload_builder(received):
            self.assertIs(received, document)
            return {
                "accounts": [{
                    "credentials": {
                        "email": "account@example.test",
                        "access_token": "access-secret",
                        "refresh_token": "refresh-secret",
                        "chatgpt_account_id": "account-id",
                        "client_id": "client-id",
                        "expires_at": "not-a-number",
                        "expires_in": "also-not-a-number",
                    },
                }],
            }

        app = self._app(replace(
            self.context,
            pixel_upload_queue=queue,
            pixel_payload_builder=payload_builder,
        ))
        with app.test_client() as client:
            pixel = client.post("/api/mailboxes/pixel-retry", json={"rows": [{"row_id": "a", "line_no": 1}]})
            exported = client.post("/api/mailboxes/sub2-export", json={"rows": [{"row_id": "a", "line_no": 1}]})

        self.assertEqual(pixel.status_code, 200)
        self.assertEqual(pixel.get_json()["queued"], 1)
        self.assertEqual(queue.calls, [("requeue", "task-a", result_file)])
        self.assertEqual(exported.status_code, 200)
        bundle = exported.get_json()["export"]
        self.assertEqual(bundle["proxies"], [])
        self.assertEqual(bundle["accounts"][0]["credentials"]["access_token"], "access-secret")
        self.assertEqual(bundle["accounts"][0]["credentials"]["refresh_token"], "refresh-secret")
        self.assertIsInstance(bundle["accounts"][0]["credentials"]["expires_at"], int)
        self.assertIsInstance(bundle["accounts"][0]["credentials"]["expires_in"], int)
        self.assertTrue(bundle["exported_at"].endswith("Z"))
        self.assertNotIn("access-secret", str(self.logs.rows))

    def test_pixel_targets_accounts_and_random_share_routes(self):
        pixel = FakePixelClient()
        app = self._app(replace(self.context, pixel_client=pixel))

        with app.test_client() as client:
            targets = client.get("/api/pixel/targets")
            accounts = client.get(
                "/api/pixel/targets/pixel-2/accounts?page=3&page_size=20&search=name&status=active"
            )
            tested = client.post(
                "/api/pixel/targets/pixel-2/accounts/bulk-test",
                json={"account_ids": [11, 12]},
            )
            shared = client.post(
                "/api/pixel/targets/pixel-2/accounts/bulk-update",
                json={"accountIds": [11, 12], "shareMode": "public"},
            )
            relogin = client.post("/api/pixel/targets/pixel-2/relogin", json={})
            hidden_requests = (
                client.get("/api/pixel/targets/pixel-1/accounts"),
                client.post(
                    "/api/pixel/targets/pixel-1/accounts/bulk-test",
                    json={"account_ids": [11]},
                ),
                client.post(
                    "/api/pixel/targets/pixel-1/accounts/bulk-update",
                    json={"account_ids": [11]},
                ),
                client.post("/api/pixel/targets/pixel-1/relogin", json={}),
            )

        values = {item.get("id") or item.get("targetId"): item for item in targets.get_json()["targets"]}
        self.assertNotIn("pixel-1", values)
        self.assertEqual(set(values), {f"pixel-{index}" for index in range(2, 8)})
        self.assertTrue(values["pixel-2"]["autoUpload"])
        self.assertTrue(values["pixel-7"]["autoUpload"])
        self.assertEqual(accounts.get_json()["page"], 3)
        self.assertEqual(accounts.get_json()["pageSize"], 20)
        self.assertEqual(tested.status_code, 200)
        self.assertEqual(shared.status_code, 200)
        self.assertEqual(relogin.status_code, 200)
        self.assertTrue(all(response.status_code == 404 for response in hidden_requests))
        self.assertIn(("bulk_test", "pixel-2", [11, 12]), pixel.calls)
        self.assertIn(("share_accounts", "pixel-2", [11, 12]), pixel.calls)
        self.assertIn(("relogin", "pixel-2"), pixel.calls)
        self.assertFalse(any("pixel-1" in call for call in pixel.calls))
        self.assertNotIn("bulk_update", [call[0] for call in pixel.calls])

    def test_pixel_share_all_rejects_excluded_and_unknown_targets(self):
        pixel = FakePixelClient()
        app = self._app(replace(self.context, pixel_client=pixel))

        with app.test_client() as client:
            shared = client.post(
                "/api/pixel/share-all",
                json={"targetIds": ["pixel-2", "pixel-7"]},
            )
            hidden_mixed = client.post(
                "/api/pixel/share-all",
                json={"targetIds": ["pixel-1", "pixel-2", "pixel-7"]},
            )
            excluded_only = client.post(
                "/api/pixel/share-all",
                json={"target_id": "pixel-1"},
            )
            invalid = client.post(
                "/api/pixel/share-all",
                json={"target_ids": ["pixel-2", "pixel-8"]},
            )

        self.assertEqual(shared.status_code, 200)
        self.assertIn(("share_all", ["pixel-2", "pixel-7"]), pixel.calls)
        self.assertEqual(hidden_mixed.status_code, 400)
        self.assertEqual(excluded_only.status_code, 400)
        self.assertEqual(invalid.status_code, 400)

    def test_pixel_upload_records_retry_selectors_and_public_errors(self):
        pixel = FakePixelClient()
        queue = FakePixelQueue()
        app = self._app(
            replace(self.context, pixel_client=pixel, pixel_upload_queue=queue)
        )

        with app.test_client() as client:
            records = client.get("/api/pixel/upload-records")
            camel = client.post(
                "/api/pixel/upload-records/record-a/retry",
                json={"targetIds": ["pixel-2", "pixel-3"]},
            )
            snake = client.post(
                "/api/pixel/upload-records/record-a/retry",
                json={"target_id": "pixel-4"},
            )
            hidden = client.post(
                "/api/pixel/upload-records/record-a/retry",
                json={"target_id": "pixel-1"},
            )
            queue.error = FakePixelError("可以公开", 409)
            failed = client.post(
                "/api/pixel/upload-records/record-a/retry",
                json={},
            )

        self.assertEqual(records.get_json()["records"][0]["record_id"], "record-a")
        self.assertEqual(camel.status_code, 200)
        self.assertEqual(snake.status_code, 200)
        self.assertEqual(hidden.status_code, 400)
        self.assertEqual(queue.calls[:2], [
            ("record-a", ["pixel-2", "pixel-3"]),
            ("record-a", ["pixel-4"]),
        ])
        self.assertEqual(failed.status_code, 409)
        self.assertEqual(failed.get_json()["error"], "Pixel 管理操作失败：可以公开")
        self.assertEqual(failed.get_json()["failure"]["node_code"], "pixel_management")
        self.assertNotIn("private-token", failed.get_data(as_text=True))

    def test_nv_upload_records_batches_overview_and_retry_routes(self):
        nv = FakeNvQueue()
        coordinator = FakeBatchUploadCoordinator()
        app = self._app(replace(
            self.context,
            nv_upload_queue=nv,
            batch_upload_coordinator=coordinator,
        ))

        with app.test_client() as client:
            overview = client.get("/api/nv/overview")
            records = client.get("/api/nv/upload-records")
            batches = client.get("/api/nv/upload-batches")
            retried = client.post("/api/nv/upload-records/nv-record/retry", json={})
            manifests = client.get("/api/upload-manifests")

        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.get_json()["batch_count"], 1)
        self.assertEqual(records.get_json()["records"][0]["record_id"], "nv-record")
        self.assertEqual(batches.get_json()["items"][0]["batch_id"], "nv-batch")
        self.assertEqual(retried.status_code, 200)
        self.assertEqual(nv.calls, ["nv-record"])
        self.assertEqual(manifests.get_json()["records"][0]["batch_id"], "batch-a")

    def test_nv_upload_records_and_batches_are_paginated(self):
        nv = FakeNvQueue()
        nv.records = lambda: [
            {"record_id": f"record-{index}", "status": "success"}
            for index in range(7)
        ]
        nv.batches = lambda: [
            {"batch_id": f"batch-{index}", "status": "success"}
            for index in range(5)
        ]
        app = self._app(replace(self.context, nv_upload_queue=nv))

        with app.test_client() as client:
            records = client.get("/api/nv/upload-records?page=2&page_size=3")
            batches = client.get("/api/nv/upload-batches?page=2&page_size=2")

        self.assertEqual(records.status_code, 200)
        self.assertEqual([item["record_id"] for item in records.get_json()["records"]], [
            "record-3", "record-4", "record-5",
        ])
        self.assertEqual(records.get_json()["total"], 7)
        self.assertEqual(records.get_json()["pages"], 3)
        self.assertEqual([item["batch_id"] for item in batches.get_json()["items"]], [
            "batch-2", "batch-3",
        ])
        self.assertEqual(batches.get_json()["total"], 5)

    def test_batch_upload_manifest_retry_validates_platform_and_maps_errors(self):
        coordinator = FakeBatchUploadCoordinator()
        app = self._app(replace(self.context, batch_upload_coordinator=coordinator))

        with app.test_client() as client:
            invalid = client.post(
                "/api/upload-manifests/batch-a/retry",
                json={"platform": "other"},
            )
            extra = client.post(
                "/api/upload-manifests/batch-a/retry",
                json={"platform": "nv", "token": "must-not-be-accepted"},
            )
            missing = client.post(
                "/api/upload-manifests/missing/retry",
                json={"platform": "nv"},
            )
            unavailable = client.post(
                "/api/upload-manifests/batch-a/retry",
                json={"platform": "pixel"},
            )
            retried = client.post(
                "/api/upload-manifests/batch-a/retry",
                json={"platform": "nv"},
            )

        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(extra.status_code, 400)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(unavailable.status_code, 409)
        self.assertNotIn("secret", unavailable.get_data(as_text=True))
        self.assertEqual(retried.status_code, 200)
        self.assertEqual(retried.get_json()["manifest"]["platforms"]["nv"]["status"], "queued")
        self.assertEqual(coordinator.retry_calls, [
            ("missing", "nv"),
            ("batch-a", "pixel"),
            ("batch-a", "nv"),
        ])

    def test_pixel_overview_and_paginated_batch_routes_are_lightweight(self):
        pixel = FakePixelClient()
        queue = FakePixelQueue()
        app = self._app(replace(
            self.context,
            pixel_client=pixel,
            pixel_upload_queue=queue,
        ))

        with app.test_client() as client:
            overview = client.get("/api/pixel/overview")
            cached_overview = client.get("/api/pixel/overview")
            batches = client.get("/api/pixel/upload-batches?page=2&page_size=10")
            records = client.get(
                "/api/pixel/upload-batches/batch-a/records?page=3&page_size=25&status=failed"
            )

        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.get_json()["current_batch"]["source"]["total"], 4)
        self.assertEqual(overview.get_json()["current_batch"]["deliveries"]["total"], 24)
        self.assertEqual(
            [item["account_count"] for item in overview.get_json()["targets"]],
            [12, 13, 14, 15, 16, 17],
        )
        self.assertEqual(cached_overview.status_code, 200)
        self.assertEqual(pixel.calls.count(("targets",)), 1)
        self.assertEqual(batches.status_code, 200)
        self.assertEqual(records.status_code, 200)
        self.assertIn(("batches", "2", "10"), queue.calls)
        self.assertIn(("batch_records", "batch-a", "3", "25", "failed"), queue.calls)


if __name__ == "__main__":
    unittest.main()
