from __future__ import annotations

from dataclasses import replace
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
    def __init__(self):
        self.sub2_result = {"ok": True, "tested": 0, "results": []}
        self.selected_result = {
            "ok": True,
            "items": [],
            "skipped": 0,
        }

    def list_mailboxes(self):
        return {"ok": True, "counts": {}, "rows": []}

    def import_mailboxes(self, _content):
        return {"ok": True, "imported": 0, "skipped": 0}

    def delete_mailboxes(self, _payload):
        return {"ok": True, "deleted": 0}

    def restore_mailboxes(self, _payload):
        return {"ok": True, "restored": 0}

    def latest_code(self, _payload):
        return {"ok": False, "error": "没有验证码"}

    def reveal_password(self, _row_id, _line_no):
        return {"ok": False, "code": "mailbox_row_stale", "error": "邮箱列表已变化"}

    def sub2_test(self, _payload):
        return dict(self.sub2_result)

    def selected_success_results(self, _payload):
        return dict(self.selected_result)

    def query_openai_quotas(self, _payload):
        return {"ok": True, "results": [], "queried": 0, "failed": 0, "skipped": 0}


class FakePixelError(RuntimeError):
    def __init__(self, public_message="公开错误", status_code=502):
        self.public_message = public_message
        self.status_code = status_code
        super().__init__("private-token-must-not-leak")


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
                {"id": "pixel-2", "email": "automatic@example.com"},
                {"id": "pixel-3", "email": "automatic-3@example.com"},
                {"id": "pixel-4", "email": "automatic-4@example.com"},
                {"id": "pixel-5", "email": "automatic-5@example.com"},
                {"id": "pixel-6", "email": "automatic-6@example.com"},
                {"targetId": "pixel-7", "email": "automatic-7@example.com"},
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
        self.assertRegex(self.importer.started_with["batch_id"], r"^\d{8}-\d{6}-[0-9a-f]{6}$")
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
        app = self._app()
        response = app.test_client().post(
            "/api/start-existing",
            json={
                "target_count": 2,
                "run_mailbox_rows": [
                    {"row_id": "A" * 64, "line_no": 25},
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
        self.assertNotIn("run_mailbox_rows", self.importer.started_with)
        self.assertNotIn("run_mailbox_rows", self.store.current)

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

    def test_settings_route_and_notification_test_are_available(self):
        app = self._app()

        with app.test_client() as client:
            settings_response = client.get("/settings")
            accounts_response = client.get("/accounts")
            notification_response = client.post(
                "/api/notifications/email/test",
                json={"email_notification": {"enabled": False}},
            )

        self.assertEqual(settings_response.status_code, 200)
        self.assertEqual(settings_response.get_data(as_text=True), "fallback")
        self.assertEqual(accounts_response.status_code, 200)
        self.assertEqual(accounts_response.get_data(as_text=True), "fallback")
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
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(calls[0][0], url)
        self.assertEqual(calls[0][1]["timeout_seconds"], 60)
        self.assertEqual(calls[0][1]["interval_seconds"], 5)
        self.assertEqual(calls[0][1]["resend_after_seconds"], 15)
        self.assertEqual(calls[0][1]["proxy"], "http://127.0.0.1:7897")

    def test_stale_mailbox_password_request_returns_conflict(self):
        app = self._app()

        with app.test_client() as client:
            response = client.post(
                "/api/mailboxes/password",
                json={"row_id": "stale", "line_no": 1},
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["code"], "mailbox_row_stale")

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
        self.assertEqual(failed.get_json()["error"], "可以公开")
        self.assertNotIn("private-token", failed.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
