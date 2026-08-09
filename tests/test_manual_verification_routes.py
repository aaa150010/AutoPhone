from __future__ import annotations

import unittest

from flask import Flask

from mac_overrides.manual_verification_routes import patch_flask_app
from mac_overrides.manual_verification_runtime import ManualVerificationBroker


class ManualVerificationRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.broker = ManualVerificationBroker()
        self.current_generation = 2
        patch_flask_app(
            self.app,
            broker=self.broker,
            task_exists=lambda task_id: task_id == "T001",
            task_generation=lambda task_id: self.current_generation,
        )
        self.client = self.app.test_client()
        self.broker.open("T001", "email_otp", 2)

    def test_submit_success(self):
        response = self.client.post(
            "/api/runtime/tasks/manual-verification",
            json={"task_id": "T001", "input_kind": "email_otp", "generation": 2, "code": "123456"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["ok"])
        self.assertNotIn("123456", repr(response.json))

    def test_stale_and_missing_are_stable(self):
        stale = self.client.post(
            "/api/runtime/tasks/manual-verification",
            json={"task_id": "T001", "input_kind": "email_otp", "generation": 1, "code": "123456"},
        )
        missing = self.client.post(
            "/api/runtime/tasks/manual-verification",
            json={"task_id": "T999", "input_kind": "email_otp", "generation": 2, "code": "123456"},
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(missing.status_code, 404)

    def test_expired_prompt_returns_410_after_public_cleanup(self):
        now = [100.0]
        app = Flask("expired-manual-verification")
        broker = ManualVerificationBroker(clock=lambda: now[0], default_window_seconds=1)
        patch_flask_app(
            app,
            broker=broker,
            task_exists=lambda task_id: task_id == "T001",
            task_generation=lambda _task_id: 3,
        )
        client = app.test_client()
        broker.open("T001", "email_otp", 2)
        now[0] = 102.0
        self.assertEqual(broker.public("T001"), {})

        response = client.post(
            "/api/runtime/tasks/manual-verification",
            json={"task_id": "T001", "input_kind": "email_otp", "generation": 2, "code": "123456"},
        )
        self.assertEqual(response.status_code, 410)

    def test_expired_prompt_keeps_410_when_task_was_removed(self):
        """A late UI request must retain the broker tombstone classification."""
        now = [100.0]
        app = Flask("removed-expired-manual-verification")
        broker = ManualVerificationBroker(clock=lambda: now[0], default_window_seconds=1)
        patch_flask_app(
            app,
            broker=broker,
            task_exists=lambda _task_id: False,
        )
        client = app.test_client()
        broker.open("T001", "email_otp", 2)
        now[0] = 102.0

        response = client.post(
            "/api/runtime/tasks/manual-verification",
            json={"task_id": "T001", "input_kind": "email_otp", "generation": 2, "code": "123456"},
        )
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json["error_code"], "expired")

    def test_stopped_prompt_keeps_410_when_task_was_removed(self):
        app = Flask("removed-stopped-manual-verification")
        broker = ManualVerificationBroker()
        patch_flask_app(app, broker=broker, task_exists=lambda _task_id: False)
        client = app.test_client()
        broker.open("T001", "sms_otp", 2)
        broker.cancel_task("T001")

        response = client.post(
            "/api/runtime/tasks/manual-verification",
            json={"task_id": "T001", "input_kind": "sms_otp", "generation": 2, "code": "123456"},
        )
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json["error_code"], "expired")

    def test_malformed_payload_is_400_before_task_lookup(self):
        looked_up = []
        app = Flask("invalid-manual-verification")
        broker = ManualVerificationBroker()
        patch_flask_app(
            app,
            broker=broker,
            task_exists=lambda task_id: looked_up.append(task_id) or False,
        )
        client = app.test_client()

        response = client.post(
            "/api/runtime/tasks/manual-verification",
            json={"task_id": "missing", "input_kind": "sms_otp", "generation": 2, "code": "bad"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error_code"], "invalid_code")
        self.assertEqual(looked_up, [])

    def test_current_task_generation_rejects_old_prompt(self):
        self.current_generation = 3
        response = self.client.post(
            "/api/runtime/tasks/manual-verification",
            json={"task_id": "T001", "input_kind": "email_otp", "generation": 2, "code": "123456"},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json["error_code"], "stale_generation")
        self.assertTrue(self.broker.public("T001").get("can_submit"))


if __name__ == "__main__":
    unittest.main()
