from __future__ import annotations

import tempfile
import time
import unittest

from flask import Flask

from mac_overrides.payment_tools_routes import install_payment_routes
from mac_overrides.network_tools import NetworkToolsService
from mac_overrides.network_tools_routes import install_network_routes


class _Socket:
    def close(self):
        pass


class ToolRouteTests(unittest.TestCase):
    def test_network_proxy_test_success_with_fake_socket_returns_ok_json(self):
        with tempfile.TemporaryDirectory() as root:
            app = Flask(__name__)
            service = NetworkToolsService(root, socket_factory=lambda *args, **kwargs: _Socket())
            app._gptphone_network_tools = service
            install_network_routes(app, module=__import__("flask"), data_root=root)
            client = app.test_client()

            imported = client.post(
                "/api/tools/proxies/import",
                json={"proxy_content": "proxy.example:8080:user:secret", "scheme": "socks5"},
            )
            self.assertEqual(imported.status_code, 200)
            proxy_id = imported.get_json()["rows"][0]["proxy_id"]

            tested = client.post("/api/tools/proxies/test", json={"proxy_id": proxy_id, "mode": "quick"})
            self.assertEqual(tested.status_code, 200)
            payload = tested.get_json()
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["proxy_id"], proxy_id)

    def test_payment_and_network_routes_are_independent(self):
        with tempfile.TemporaryDirectory() as root:
            app = Flask(__name__)
            install_payment_routes(app, module=__import__("flask"), data_root=root)
            install_network_routes(app, module=__import__("flask"), data_root=root)
            client = app.test_client()
            payment = client.get("/api/tools/payment/config")
            network = client.get("/api/tools/proxies")
            self.assertEqual(payment.status_code, 200)
            self.assertEqual(network.status_code, 200)
            self.assertEqual(payment.get_json()["config"]["mode"], "local")
            self.assertEqual(network.get_json()["total"], 0)
            created = client.post("/api/tools/payment/tasks", json={"mode": "manual", "manual_link": "https://pay.example/cs_live_fake"})
            self.assertEqual(created.status_code, 200)
            task_id = created.get_json()["tasks"][0]["task_id"]
            for _ in range(30):
                current = client.get(f"/api/tools/payment/tasks/{task_id}").get_json()["task"]
                if current["status"] == "succeeded":
                    break
                time.sleep(0.01)
            secret = client.get(f"/api/tools/payment/tasks/{task_id}/secret")
            self.assertEqual(secret.get_json()["value"], "https://pay.example/cs_live_fake")
            self.assertFalse((__import__("pathlib").Path(root) / "network_tools" / "tasks.json").exists())


if __name__ == "__main__":
    unittest.main()
