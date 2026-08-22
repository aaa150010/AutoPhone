from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from mac_overrides.payment_tools import PaymentToolError, PaymentToolsService


class _Entry:
    email = "demo@example.com"


class _Pool:
    def entry(self, row_id):
        return _Entry() if row_id == "row-1" else None

    def result(self, row_id):
        return {"access_token": "eyJ.secret.token", "proxy": "http://user:password@example.test:3000"}


class _Free:
    pool = _Pool()


class PaymentToolsTests(unittest.TestCase):
    def wait_for(self, service: PaymentToolsService, task_id: str, status: str) -> dict:
        deadline = time.time() + 3
        while time.time() < deadline:
            task = service.task(task_id)
            if task.get("status") == status:
                return task
            time.sleep(0.02)
        self.fail(f"task did not reach {status}: {service.task(task_id)}")

    def test_local_task_isolated_and_result_requires_reveal(self):
        with tempfile.TemporaryDirectory() as root:
            def adapter(task, secret, config, stage, cancel):
                stage("fake_local")
                return {"value": "https://checkout.example/cs_live_fake"}

            service = PaymentToolsService(root, free_manager=_Free(), adapters={"local": adapter})
            created = service.create({"mode": "local", "row_ids": ["row-1"], "channel": "paypal"})
            task_id = created["tasks"][0]["task_id"]
            task = self.wait_for(service, task_id, "succeeded")
            self.assertEqual(task["result_summary"]["result_host"], "checkout.example")
            self.assertNotIn("eyJ", str(task))
            self.assertNotIn("password", str(service.logs(task_id)))
            self.assertEqual(service.reveal(task_id), "https://checkout.example/cs_live_fake")
            self.assertTrue((Path(root) / "payment_tools" / "secrets.json").exists())

    def test_external_mode_requires_exact_domain_confirmation(self):
        with tempfile.TemporaryDirectory() as root:
            service = PaymentToolsService(root, free_manager=_Free(), adapters={"http": lambda *args: {"value": "https://x"}})
            service.save_config({"mode": "http", "http_endpoint": "https://api.example.test/extract"})
            created = service.create({"mode": "http", "row_ids": ["row-1"]})
            task = created["tasks"][0]
            self.assertEqual(task["status"], "awaiting_confirmation")
            with self.assertRaises(PaymentToolError):
                service.confirm(task["task_id"], "evil.example")
            service.confirm(task["task_id"], "api.example.test")
            done = self.wait_for(service, task["task_id"], "succeeded")
            self.assertTrue(done["confirmed"])

    def test_manual_link_and_bad_config_are_structured(self):
        with tempfile.TemporaryDirectory() as root:
            service = PaymentToolsService(root)
            with self.assertRaises(PaymentToolError) as caught:
                service.save_config({"workers": "nope"})
            self.assertEqual(caught.exception.node_code, "payment_config")
            created = service.create({"mode": "manual", "manual_link": "https://pay.example/cs_live_manual"})
            task = self.wait_for(service, created["tasks"][0]["task_id"], "succeeded")
            self.assertEqual(service.reveal(task["task_id"]), "https://pay.example/cs_live_manual")

    def test_saving_idle_worker_count_replaces_executor(self):
        with tempfile.TemporaryDirectory() as root:
            service = PaymentToolsService(root)
            previous = service._executor
            config = service.save_config({"workers": 4})

            self.assertEqual(config["workers"], 4)
            self.assertIsNot(service._executor, previous)
            self.assertEqual(service._executor._max_workers, 4)


if __name__ == "__main__":
    unittest.main()
