from __future__ import annotations

from types import SimpleNamespace
import threading
import unittest

from mac_overrides.phase1_checkpoint_hooks import (
    CheckpointCoordinator,
    _clean_response,
    import_phase1_session,
    should_delete_checkpoint,
)


class FakeStore:
    def __init__(self):
        self.saved = []
        self.loaded = None
        self.deleted = []
        self.released = []

    def save(self, **kwargs):
        self.saved.append(kwargs)
        return {"state": "saved", "resume_stage": "phone_acquiring"}

    def load(self, **kwargs):
        self.load_kwargs = kwargs
        return self.loaded

    def delete(self, row_id):
        self.deleted.append(row_id)

    def release(self, row_id, *, claim_id=""):
        self.released.append((row_id, claim_id))
        return True


class Cookie:
    def __init__(self, name, value, domain="auth.example.test", path="/", secure=True):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.secure = secure


class CheckpointCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.public_updates = []
        self.logs = []
        self.context = {
            "task_id": "task-1",
            "row_id": "row-1",
            "email": "user@example.test",
            "proxy": "http://proxy.example.test:8080",
            "batch_id": "batch-1",
        }
        self.coordinator = CheckpointCoordinator(
            self.store,
            context_getter=lambda: self.context,
            generation_getter=lambda _task_id: 7,
            public_update=lambda task_id, value: self.public_updates.append((task_id, value)),
            log_fn=lambda message, level: self.logs.append((message, level)),
        )
        self.transport = SimpleNamespace(
            config={},
            device_id="device-1",
            session=SimpleNamespace(cookies=[Cookie("session", "cookie-value")]),
            sentinel_provider=SimpleNamespace(_cache={"challenge": "sentinel-value"}),
        )

    def test_save_captures_cookie_and_sentinel_snapshot_without_otp_values(self):
        status = self.coordinator.save(
            self.transport,
            {
                "verification_code": "123456",
                "continue_url": "https://auth.example.test/add-phone?code=one-time&state=keep",
                "nested": {"otp": "654321", "value": "retained"},
            },
        )

        saved = self.store.saved[0]
        snapshot = saved["snapshot"]
        self.assertEqual(status["state"], "saved")
        self.assertEqual(snapshot["cookies"][0]["value"], "cookie-value")
        self.assertEqual(snapshot["sentinel_cache"], {"challenge": "sentinel-value"})
        self.assertNotIn("verification_code", snapshot["response"])
        self.assertNotIn("otp", snapshot["response"]["nested"])
        self.assertNotIn("code=one-time", snapshot["response"]["continue_url"])
        self.assertIn("state=keep", snapshot["response"]["continue_url"])
        self.assertEqual(
            snapshot["continue_url"],
            "https://auth.example.test/add-phone?state=keep",
        )

    def test_save_filters_camel_case_verification_fields_and_query_values(self):
        cleaned = _clean_response(
            {
                "verificationCode": "123456",
                "otpCode": "654321",
                "TOTPSecret": "seed",
                "continueUrl": "https://auth.example.test/continue?verificationCode=one&otpCode=two&state=keep",
                "nested": {"passCode": "secret", "safeValue": "retained"},
            }
        )

        self.assertNotIn("verificationCode", cleaned)
        self.assertNotIn("otpCode", cleaned)
        self.assertNotIn("TOTPSecret", cleaned)
        self.assertNotIn("passCode", cleaned["nested"])
        self.assertEqual(cleaned["nested"]["safeValue"], "retained")
        self.assertNotIn("verificationCode=one", cleaned["continueUrl"])
        self.assertNotIn("otpCode=two", cleaned["continueUrl"])
        self.assertIn("state=keep", cleaned["continueUrl"])

    def test_restore_injects_private_snapshot_and_claims_task(self):
        snapshot = {"ready": True, "cookies": [{"name": "session", "value": "cookie-value"}]}
        self.store.loaded = {
            "snapshot": snapshot,
            "public": {"state": "restored", "resume_stage": "phone_acquiring"},
        }

        restored = self.coordinator.restore(self.transport)

        self.assertIsNotNone(restored)
        self.assertEqual(self.store.load_kwargs["claim_id"], "task-1")
        self.assertEqual(self.store.load_kwargs["task_generation"], 7)
        self.assertEqual(self.transport.config["phase1_active_session"], snapshot)
        self.assertIsNot(self.transport.config["phase1_active_session"], snapshot)
        self.assertTrue(self.transport._gptphone_checkpoint_restored)
        self.assertEqual(self.public_updates[-1][1]["state"], "restored")

    def test_restore_passes_stop_signal_only_to_keychain_call(self):
        stop = threading.Event()
        self.transport.config["_stop_requested"] = stop
        self.store.loaded = {
            "snapshot": {"ready": True, "cookies": []},
            "public": {"state": "restored", "resume_stage": "phone_acquiring"},
        }

        self.assertIsNotNone(self.coordinator.restore(self.transport))
        self.assertIs(self.store.load_kwargs["stop_event"], stop)
        self.assertNotIn("_stop_requested", self.transport.config["phase1_active_session"])

    def test_restore_failure_clears_stale_private_snapshot(self):
        self.transport.config["phase1_active_session"] = {"ready": True, "cookies": ["old"]}

        self.assertIsNone(self.coordinator.restore(self.transport))

        self.assertNotIn("phase1_active_session", self.transport.config)

    def test_restore_load_exception_clears_stale_private_snapshot(self):
        self.transport.config["phase1_active_session"] = {"ready": True, "cookies": ["old"]}

        def fail_load(**_kwargs):
            raise RuntimeError("bad checkpoint")

        self.store.load = fail_load
        self.assertIsNone(self.coordinator.restore(self.transport))

        self.assertNotIn("phase1_active_session", self.transport.config)

    def test_keychain_disable_is_publicly_diagnosed_and_falls_back_fresh(self):
        class DisabledStore(FakeStore):
            enabled = True

            def load(self, **kwargs):
                self.load_kwargs = kwargs
                self.enabled = False
                return None

            def public_status(self, *, state="none"):
                return {"state": state, "resume_stage": ""}

        store = DisabledStore()
        coordinator = CheckpointCoordinator(
            store,
            context_getter=lambda: self.context,
            public_update=lambda task_id, value: self.public_updates.append((task_id, value)),
            log_fn=lambda message, level: self.logs.append((message, level)),
        )

        self.assertIsNone(coordinator.restore(self.transport))
        self.assertEqual(self.public_updates[-1][1]["state"], "disabled")
        self.assertIn("Keychain 不可用", self.logs[-1][0])

    def test_import_failure_discards_snapshot_and_restores_fresh_flow(self):
        self.transport.config["phase1_active_session"] = {"ready": True}

        self.coordinator.discard_import_failure(self.transport)

        self.assertEqual(self.store.deleted, ["row-1"])
        self.assertNotIn("phase1_active_session", self.transport.config)
        self.assertEqual(self.public_updates[-1], ("task-1", None))
        self.assertIn("回退 fresh OAuth", self.logs[-1][0])

    def test_import_exception_from_restored_checkpoint_falls_back_fresh(self):
        self.transport._gptphone_checkpoint_restored = True
        self.transport.config["phase1_active_session"] = {"ready": True}

        imported = import_phase1_session(
            self.transport,
            self.transport.config["phase1_active_session"],
            original=lambda *_args: (_ for _ in ()).throw(RuntimeError("bad import")),
            coordinator=self.coordinator,
        )

        self.assertFalse(imported)
        self.assertFalse(self.transport._gptphone_checkpoint_restored)
        self.assertEqual(self.store.deleted, ["row-1"])
        self.assertNotIn("phase1_active_session", self.transport.config)

    def test_terminal_cleanup_deletes_checkpoint_and_public_status(self):
        self.coordinator.cleanup_terminal(identity=self.context)

        self.assertEqual(self.store.deleted, ["row-1"])
        self.assertEqual(self.public_updates[-1], ("task-1", None))

    def test_release_retains_payload_and_uses_current_task_claim(self):
        self.assertTrue(self.coordinator.release(self.transport))

        self.assertEqual(self.store.released, [("row-1", "task-1")])
        self.assertEqual(self.store.deleted, [])

    def test_checkpoint_cleanup_policy_preserves_stops_and_resumable_failures(self):
        self.assertFalse(should_delete_checkpoint("stopped"))
        self.assertFalse(should_delete_checkpoint("stopped_before_start"))
        self.assertFalse(should_delete_checkpoint("retryable_infra"))
        self.assertFalse(should_delete_checkpoint("repair_pending"))

    def test_checkpoint_cleanup_policy_removes_non_reusable_sessions(self):
        self.assertTrue(should_delete_checkpoint("success"))
        self.assertTrue(should_delete_checkpoint("account_banned"))
        self.assertTrue(should_delete_checkpoint("failed", invalid_session=True))
        self.assertTrue(
            should_delete_checkpoint(
                "failed",
                values=("oauth_account_mismatch: expected account differs",),
            )
        )


if __name__ == "__main__":
    unittest.main()
