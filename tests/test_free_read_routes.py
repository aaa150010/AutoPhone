from __future__ import annotations

from dataclasses import replace
import unittest

from tests import test_web_routes as web_route_support


class FreeReadRouteFailureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = web_route_support.WebRouteTests(
            methodName="test_start_preflight_blocks_save_and_second_preflight"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def _app(self, *, manager=None, config_store=None):
        return self.fixture._app(replace(
            self.fixture.context,
            free_register_manager=manager,
            free_config_store=config_store,
        ))

    def assert_read_failure(self, response, *, node_code, node_label, secret):
        payload = response.get_json()
        self.assertEqual(response.status_code, 503)
        self.assertIsInstance(payload, dict)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["node_code"], node_code)
        self.assertEqual(payload["node_label"], node_label)
        self.assertEqual(payload["failure"]["node_code"], node_code)
        self.assertEqual(payload["failure"]["http_status"], 503)
        self.assertNotIn(secret, str(payload))

    def test_pool_and_log_read_failures_return_structured_503(self):
        secret = "free-read-route-secret"

        class FailingPool:
            def counts(self):
                raise RuntimeError(f"pool storage unavailable token={secret}")

            def public_rows(self):
                return []

        class FailingProxies:
            def public(self):
                raise RuntimeError(f"proxy storage unavailable token={secret}")

        class FailingManager:
            pool = FailingPool()
            proxies = FailingProxies()

            def public_state(self):
                return {"running": False, "tasks": [], "summary": {}}

            def public_logs(self, _task_id):
                raise RuntimeError(f"log storage unavailable token={secret}")

            def _log(self, _message, _level):
                raise RuntimeError(f"diagnostic logger unavailable token={secret}")

        app = self._app(manager=FailingManager())
        with app.test_client() as client:
            responses = (
                (
                    client.get("/api/free/mailboxes"),
                    "free_mailboxes_read",
                    "读取 Free 邮箱池",
                ),
                (
                    client.get("/api/free/proxies"),
                    "free_proxies_read",
                    "读取 Free 代理池",
                ),
                (
                    client.get("/api/free/logs?task_id=free-task"),
                    "free_logs_read",
                    "读取 Free 账号日志",
                ),
            )

        for response, node_code, node_label in responses:
            with self.subTest(node_code=node_code):
                self.assert_read_failure(
                    response,
                    node_code=node_code,
                    node_label=node_label,
                    secret=secret,
                )

    def test_state_read_failure_is_structured_on_state_and_config_routes(self):
        secret = "free-state-read-secret"

        class FailingStateManager:
            def public_state(self):
                raise RuntimeError(f"state storage unavailable token={secret}")

        class HealthyConfigStore:
            def public(self):
                return {}

        app = self._app(
            manager=FailingStateManager(),
            config_store=HealthyConfigStore(),
        )
        with app.test_client() as client:
            responses = (
                client.get("/api/free/state"),
                client.get("/api/free/config"),
            )

        for response in responses:
            with self.subTest(path=response.request.path):
                self.assert_read_failure(
                    response,
                    node_code="free_state_read",
                    node_label="读取 Free 运行状态",
                    secret=secret,
                )

    def test_config_read_failure_is_structured_on_state_and_config_routes(self):
        secret = "free-config-read-secret"

        class HealthyManager:
            def public_state(self):
                return {"running": False, "tasks": [], "summary": {}}

        class FailingConfigStore:
            def public(self):
                raise RuntimeError(f"config storage unavailable token={secret}")

        app = self._app(
            manager=HealthyManager(),
            config_store=FailingConfigStore(),
        )
        with app.test_client() as client:
            responses = (
                client.get("/api/free/state"),
                client.get("/api/free/config"),
            )

        for response in responses:
            with self.subTest(path=response.request.path):
                self.assert_read_failure(
                    response,
                    node_code="free_config_read",
                    node_label="读取 Free 配置",
                    secret=secret,
                )

    def test_other_free_get_routes_use_structured_503_for_read_failures(self):
        secret = "free-account-read-secret"

        class HealthyPool:
            def public_rows(self):
                return []

        class FailingLiveChecks:
            def public_state(self):
                raise RuntimeError(f"live state unavailable token={secret}")

        class Manager:
            pool = HealthyPool()
            live_checks = FailingLiveChecks()

            def public_state(self):
                return {"running": False, "tasks": [], "summary": {}}

        class FailingConfigStore:
            def load(self):
                raise RuntimeError(f"workspace config unavailable token={secret}")

        app = self._app(
            manager=Manager(),
            config_store=FailingConfigStore(),
        )
        with app.test_client() as client:
            responses = (
                (
                    client.get("/api/free/live-check/state"),
                    "free_live_state",
                    "读取 Free 账号测活状态",
                ),
            )

        for response, node_code, node_label in responses:
            with self.subTest(node_code=node_code):
                self.assert_read_failure(
                    response,
                    node_code=node_code,
                    node_label=node_label,
                    secret=secret,
                )

    def test_post_backed_free_reads_use_structured_503_for_store_failures(self):
        secret = "free-post-read-secret"

        class FailingPool:
            def reveal_mailbox_url(self, _row_id):
                raise OSError(f"mailbox store unavailable token={secret}")

            def export_success(self, _row_ids):
                raise OSError(f"export store unavailable token={secret}")

        class Manager:
            pool = FailingPool()

            def public_state(self):
                return {"running": False, "tasks": [], "summary": {}}

            def secret(self, _task_ids, _kind, *, row_ids=()):
                raise OSError(f"secret store unavailable token={secret}")

        class FailingConfigStore:
            def secret(self, _secret_id):
                raise OSError(f"config secret store unavailable token={secret}")

        app = self._app(
            manager=Manager(),
            config_store=FailingConfigStore(),
        )
        with app.test_client() as client:
            responses = (
                (
                    client.post("/api/free/mailboxes/url", json={"row_id": "row-a"}),
                    "free_mailbox_url",
                    "读取 Free 取件地址",
                ),
                (
                    client.post("/api/free/mailboxes/export", json={"row_ids": ["row-a"]}),
                    "free_export",
                    "导出 Free 注册结果",
                ),
                (
                    client.post("/api/free/secrets", json={"task_id": "task-a", "kind": "token"}),
                    "free_secret",
                    "读取 Free 敏感字段",
                ),
                (
                    client.post("/api/free/config/secret", json={"id": "removed_secret"}),
                    "free_config_secret",
                    "读取 Free 配置密钥",
                ),
            )

        for response, node_code, node_label in responses:
            with self.subTest(node_code=node_code):
                self.assert_read_failure(
                    response,
                    node_code=node_code,
                    node_label=node_label,
                    secret=secret,
                )


if __name__ == "__main__":
    unittest.main()
