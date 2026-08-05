from __future__ import annotations

import unittest
from types import SimpleNamespace

from mac_overrides.auth_request_runtime import begin_request, finish_request
from mac_overrides.auth_session_runtime import AuthSessionRegistry, is_session_invalid


class AuthSessionRuntimeTests(unittest.TestCase):
    def test_session_invalid_marker_is_detected_without_needing_raw_response_shape(self):
        self.assertTrue(is_session_invalid("oauth_session_invalid: Your sign-in session is no longer valid"))
        self.assertTrue(is_session_invalid({"code": "oauth_session_invalid", "status": 401}))
        self.assertFalse(is_session_invalid({"code": "phone_send_rejected"}))

    def test_invalidation_keeps_count_across_fresh_generation_and_cancels_sms(self):
        cancellations = []
        registry = AuthSessionRegistry(
            cancel_sms=lambda task_id, reason: cancellations.append((task_id, reason)),
        )
        item = registry.start_generation(
            "task-1",
            email="user@example.test",
            node_instance_id="node-a",
            transport_instance_id="transport-a",
        )
        registry.observe(
            "task-1",
            "phone_submitting",
            continue_url="https://auth.example.test/add-phone?state=secret",
            success=True,
        )
        registry.invalidate("task-1", "oauth_session_invalid", stage="phone_submitting")
        self.assertEqual(item.invalidations, 1)
        self.assertTrue(item.fresh_oauth_required)
        self.assertEqual(item.latest_continue_path, "")
        self.assertEqual(cancellations, [("task-1", "oauth_session_invalid")])

        fresh = registry.start_generation(
            "task-1",
            email="user@example.test",
            node_instance_id="node-b",
            transport_instance_id="transport-b",
        )
        self.assertIs(fresh, item)
        self.assertEqual(fresh.generation, 2)
        self.assertEqual(fresh.invalidations, 1)
        self.assertFalse(fresh.invalid)
        self.assertFalse(fresh.fresh_oauth_required)
        self.assertNotEqual(fresh.node_instance_id, "")

        registry.invalidate("task-1", "oauth_session_invalid", stage="phone_submitting")
        self.assertEqual(fresh.invalidations, 2)
        self.assertEqual(len(cancellations), 2)

    def test_public_snapshot_contains_fingerprints_but_not_session_material(self):
        registry = AuthSessionRegistry()
        registry.start_generation(
            "task-safe",
            email="user@example.test",
            node_instance_id="node-secret",
            transport_instance_id="transport-secret",
        )
        registry.observe(
            "task-safe",
            "phone_submitting",
            continue_url="https://auth.example.test/add-phone?state=oauth-secret",
            success=True,
        )
        item = registry.get("task-safe")
        item.begin_request(
            endpoint="/api/accounts/add-phone/send",
            stage="phone_submitting",
            cookies_present=True,
            csrf_present=True,
        )
        snapshot = registry.public_snapshot("task-safe")
        serialized = repr(snapshot)
        self.assertNotIn("node-secret", serialized)
        self.assertNotIn("transport-secret", serialized)
        self.assertNotIn("oauth-secret", serialized)
        self.assertEqual(snapshot["current_stage"], "phone_submitting")
        self.assertEqual(snapshot["events"][-1]["continue_path"], "/add-phone")

    def test_request_completion_updates_the_same_registered_event(self):
        registry = AuthSessionRegistry()
        transport = SimpleNamespace(
            config={"sms_task_id": "task-request", "_auth_account_email": "user@example.test"},
            account_email="user@example.test",
            session=SimpleNamespace(cookies={"session": "present"}),
            proxy="",
            _gptphone_page_type="add_phone",
        )

        request = begin_request(
            transport,
            registry,
            endpoint="/api/accounts/add-phone/send",
            stage="phone_submitting",
        )
        finish_request(
            transport,
            registry,
            request,
            {"_status": 200, "page": {"type": "phone_otp"}},
        )

        snapshot = registry.public_snapshot("task-request")
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(snapshot["events"][0]["request_context_id"], request["request_context_id"])
        self.assertEqual(snapshot["events"][0]["response_status"], 200)
        self.assertEqual(snapshot["events"][0]["page_type"], "phone_otp")


if __name__ == "__main__":
    unittest.main()
