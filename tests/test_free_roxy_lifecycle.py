from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mac_overrides.free_roxy_lifecycle import (
    MANAGED_WINDOW_REMARK,
    RoxyCleanupStore,
    RoxyLifecycle,
)
from mac_overrides.free_roxy_runtime import RoxyBrowserClient
from mac_overrides.free_register_common import FreeRegisterError


class _LifecycleClient:
    def __init__(self, *, close_fails: bool = False, delete_fails: bool = False) -> None:
        self.closed: list[str] = []
        self.deleted: list[str] = []
        self.close_fails = close_fails
        self.delete_fails = delete_fails
        self.active = {"42"}
        self.profiles = {"42"}

    def close_profile(self, profile_id: str) -> None:
        if self.close_fails:
            raise RuntimeError("close failed")
        self.closed.append(profile_id)
        self.active.discard(profile_id)

    def delete_profile(self, profile_id: str) -> None:
        if self.delete_fails:
            raise RuntimeError("delete failed")
        self.deleted.append(profile_id)
        self.profiles.discard(profile_id)

    def connection_info(self, profile_id: str):
        return {"profile_id": profile_id} if profile_id in self.active else None

    def list_profiles(self, _workspace_id: str):
        return [{"profile_id": value} for value in sorted(self.profiles)]


class _WorkspaceLifecycleClient(_LifecycleClient):
    def __init__(self):
        super().__init__()
        self.workspace_calls = []

    def connection_info(self, profile_id, *, workspace_id=None):
        self.workspace_calls.append(("connection_info", profile_id, workspace_id))
        return {"profile_id": profile_id} if profile_id in self.active else None

    def close_profile(self, profile_id, *, workspace_id=None):
        self.workspace_calls.append(("close_profile", profile_id, workspace_id))
        super().close_profile(profile_id)

    def delete_profile(self, profile_id, *, workspace_id=None):
        self.workspace_calls.append(("delete_profile", profile_id, workspace_id))
        super().delete_profile(profile_id)


class _DeleteReleasesClient(_LifecycleClient):
    def close_profile(self, _profile_id):
        raise RuntimeError("close request timed out")

    def delete_profile(self, profile_id):
        self.deleted.append(profile_id)
        self.active.discard(profile_id)
        self.profiles.discard(profile_id)


class _Response:
    status_code = 200
    text = ""

    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value


class _QuotaSession:
    def __init__(self):
        self.headers = {}

    def request(self, method, url, **_kwargs):
        return _Response({"code": 1001, "message": "窗口额度不足"})


class _ProfileListSession:
    def __init__(self):
        self.headers = {}

    def request(self, method, url, **_kwargs):
        if url.endswith("/browser/list"):
            return _Response({"data": [{
                "dirId": "owned-1",
                "workspaceId": "workspace-1",
                "windowName": "FreeRegister task-1",
                "windowRemark": MANAGED_WINDOW_REMARK,
            }, {
                "dirId": "foreign-1",
                "workspaceId": "workspace-1",
                "windowName": "User profile",
                "windowRemark": "",
            }]})
        return _Response({})


class _GhostConnectionClient:
    def __init__(self):
        self.closed = []
        self.deleted = []
        self.active = {"ghost-1"}

    def list_connections(self, _workspace_id):
        return [{
            "profile_id": "ghost-1",
            "workspace_id": "workspace-1",
            "window_name": "FreeRegister task-ghost",
            "window_remark": MANAGED_WINDOW_REMARK,
        }]

    def list_profiles(self, _workspace_id):
        # The profile was already removed from /browser/list, but its
        # connection still occupies a window slot.
        return []

    def close_profile(self, profile_id):
        self.closed.append(profile_id)
        self.active.discard(profile_id)

    def delete_profile(self, profile_id):
        self.deleted.append(profile_id)

    def connection_info(self, profile_id):
        return {"profile_id": profile_id} if profile_id in self.active else None


class _Connection404Client(_LifecycleClient):
    def connection_info(self, _profile_id):
        raise FreeRegisterError(
            "free_roxy_api", "调用 RoxyBrowser API", "窗口不存在", provider_status=404,
        )


class FreeRoxyLifecycleTests(unittest.TestCase):
    def test_store_persists_owned_profile_and_pending_state(self):
        with TemporaryDirectory() as directory:
            store = RoxyCleanupStore(Path(directory) / "free_register" / "roxy_cleanup.json")
            record = store.upsert(
                "42", workspace_id="w", batch_id="batch-1", task_id="task-1",
                window_name="FreeRegister task-1", state="created",
            )
            self.assertEqual(record.window_remark, MANAGED_WINDOW_REMARK)
            self.assertEqual(store.pending()[0].profile_id, "42")
            store.mark_pending("42", "删除未确认")
            reloaded = RoxyCleanupStore(store.path)
            self.assertEqual(reloaded.pending()[0].state, "cleanup_pending")
            self.assertEqual(reloaded.pending()[0].attempts, 1)

    def test_cleanup_confirms_close_delete_and_removes_record(self):
        with TemporaryDirectory() as directory:
            store = RoxyCleanupStore(Path(directory) / "roxy_cleanup.json")
            record = store.upsert("42", workspace_id="w", state="opened")
            client = _LifecycleClient()
            lifecycle = RoxyLifecycle(client, store, verify_timeout=0.5, verify_interval=0.01)
            self.assertTrue(lifecycle.cleanup(record))
            self.assertEqual(client.closed, ["42"])
            self.assertEqual(client.deleted, ["42"])
            self.assertEqual(store.records(), [])

    def test_cleanup_failure_remains_pending_for_restart_recovery(self):
        with TemporaryDirectory() as directory:
            store = RoxyCleanupStore(Path(directory) / "roxy_cleanup.json")
            record = store.upsert("42", workspace_id="w", state="opened")
            client = _LifecycleClient(delete_fails=True)
            lifecycle = RoxyLifecycle(client, store, verify_timeout=0.1, verify_interval=0.01, retries=2)
            self.assertFalse(lifecycle.cleanup(record))
            self.assertEqual(store.pending()[0].state, "cleanup_pending")
            self.assertGreaterEqual(store.pending()[0].attempts, 1)

    def test_cleanup_uses_record_workspace_and_compatibility_clients(self):
        with TemporaryDirectory() as directory:
            store = RoxyCleanupStore(Path(directory) / "roxy_cleanup.json")
            record = store.upsert("42", workspace_id="record-workspace", state="opened")
            client = _WorkspaceLifecycleClient()
            lifecycle = RoxyLifecycle(client, store, verify_timeout=0.5, verify_interval=0.01)
            self.assertTrue(lifecycle.cleanup(record))
            self.assertTrue({call[2] for call in client.workspace_calls if call[0] != "connection_info"} == {"record-workspace"})
            self.assertIn(("connection_info", "42", "record-workspace"), client.workspace_calls)

    def test_successful_delete_clears_queue_after_close_timeout(self):
        with TemporaryDirectory() as directory:
            store = RoxyCleanupStore(Path(directory) / "roxy_cleanup.json")
            record = store.upsert("42", workspace_id="w", state="opened")
            lifecycle = RoxyLifecycle(
                _DeleteReleasesClient(), store, verify_timeout=0.1, verify_interval=0.01, retries=1,
            )
            self.assertTrue(lifecycle.cleanup(record))
            self.assertEqual(store.records(), [])

    def test_window_quota_is_a_distinct_non_retryable_node(self):
        client = RoxyBrowserClient(
            {"api_base": "http://127.0.0.1:50000", "api_retries": 1},
            session=_QuotaSession(),
        )
        with self.assertRaises(FreeRegisterError) as raised:
            client.request("POST", "/browser/create", body={})
        self.assertEqual(raised.exception.node_code, "free_roxy_window_quota_exhausted")
        self.assertEqual(raised.exception.error_code, "roxy_window_quota_exhausted")
        self.assertFalse(raised.exception.retryable)

    def test_profile_list_accepts_direct_data_array_for_owned_recovery(self):
        client = RoxyBrowserClient(
            {"api_base": "http://127.0.0.1:50000"},
            session=_ProfileListSession(),
        )
        rows = client.find_owned_profiles(task_id="task-1", batch_id="batch-1")
        self.assertEqual([row["profile_id"] for row in rows], ["owned-1"])

    def test_creation_intent_recovers_ghost_connection_missing_from_profile_list(self):
        with TemporaryDirectory() as directory:
            store = RoxyCleanupStore(Path(directory) / "roxy_cleanup.json")
            store.reserve_intent(
                "intent-ghost", workspace_id="workspace-1", batch_id="batch-1",
                task_id="task-ghost", window_name="FreeRegister task-ghost",
            )
            client = _GhostConnectionClient()
            lifecycle = RoxyLifecycle(client, store, verify_timeout=0.2, verify_interval=0.01)
            result = lifecycle.recover_creation_intents()
            self.assertEqual(result["recovered"], 1)
            self.assertEqual(client.closed, ["ghost-1"])
            self.assertEqual(store.intents(), [])
            self.assertEqual(store.records(), [])

    def test_connection_404_is_treated_as_already_gone(self):
        with TemporaryDirectory() as directory:
            store = RoxyCleanupStore(Path(directory) / "roxy_cleanup.json")
            record = store.upsert("42", workspace_id="w", state="opened")
            lifecycle = RoxyLifecycle(_Connection404Client(), store, verify_timeout=0.1, verify_interval=0.01)
            self.assertTrue(lifecycle.cleanup(record))
            self.assertEqual(store.records(), [])


if __name__ == "__main__":
    unittest.main()
