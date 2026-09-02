from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from mac_overrides.free_storage_adapters import (
    SQLiteFreeMailboxPool,
    SQLiteFreeProxyPool,
    SQLiteFreeTaskStore,
    build_free_storage_adapters,
)
from mac_overrides.free_register_common import FreeRegisterError


class SQLiteStorageAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="gptphone-free-adapter-")
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_mailbox_adapter_preserves_state_and_redacts_public_projection(self) -> None:
        adapters = build_free_storage_adapters(self.root)
        pool = adapters.mailboxes
        added, skipped = pool.import_text_with_stats(
            "first@example.com----https://api798.com/get_code?email=first@example.com&auth_code=SECRET\n"
            "second@example.com----https://api798.com/get_code?email=second@example.com&auth_code=SECRET2\n"
        )
        self.assertEqual((added, skipped), (2, 0))
        self.assertEqual(pool.import_text("first@example.com----https://api798.com/get_code?email=first@example.com&auth_code=SECRET"), 0)
        rows = pool.entries()
        self.assertEqual(len(rows), 2)
        self.assertEqual(pool.available(10)[0].email, "first@example.com")

        pool.reserve([rows[0]], "batch-1")
        pool.update(rows[0].row_id, status="queued", task_id="task-1", driver="protocol")
        pool.save_result(
            rows[0].row_id,
            {
                "status": "success",
                "password": "pw-secret",
                "access_token": "token-secret",
                "totp_secret": "totp-secret",
            },
        )
        public = pool.public_rows()
        first = next(row for row in public if row["row_id"] == rows[0].row_id)
        serialized = json.dumps(first, ensure_ascii=False)
        self.assertNotIn("api798.com/get_code", serialized)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("pw-secret", serialized)
        self.assertNotIn("token-secret", serialized)
        self.assertTrue(first["has_access_token"])
        self.assertTrue(first["has_password"])
        self.assertEqual(pool.result(rows[0].row_id)["access_token"], "token-secret")
        self.assertIn("first@example.com----pw-secret", pool.export_success([rows[0].row_id]))

    def test_mailbox_adapter_preserves_canonical_mask_for_short_local_part(self) -> None:
        pool = SQLiteFreeMailboxPool(self.root)
        pool.import_text("ab@example.com----https://mail.example/short")

        public = pool.public_rows()[0]

        self.assertEqual(public["email"], "a*@example.com")
        self.assertEqual(public["email_masked"], public["email"])

    def test_remail_mailbox_reveals_scoped_pickup_url_and_hides_token_from_public_rows(self) -> None:
        pool = SQLiteFreeMailboxPool(self.root)
        row = pool.import_remail_order({
            "orderNo": "ord-url",
            "status": "active",
            "deliveryEmail": "user@example.com",
            "serviceToken": "private-service-token",
        })
        url = pool.reveal_mailbox_url(row["row_id"])
        self.assertIn("email=user%40example.com", url)
        self.assertIn("token=private-service-token", url)
        public = json.dumps(pool.public_rows(), ensure_ascii=False)
        self.assertNotIn("private-service-token", public)

    def test_expired_remail_mailbox_is_quarantined_before_allocation(self) -> None:
        pool = SQLiteFreeMailboxPool(self.root)
        row = pool.import_remail_order({
            "orderNo": "ord-expired",
            "status": "active",
            "deliveryEmail": "expired@example.com",
            "serviceToken": "private-service-token",
            "expiresAt": time.time() - 60,
        })
        self.assertEqual(pool.available(10), [])
        state = pool._row_state(row["row_id"])
        self.assertEqual(state["status"], "unavailable")
        self.assertTrue(state["remail_expired"])

    def test_mailbox_adapter_keeps_new_imports_first(self) -> None:
        pool = SQLiteFreeMailboxPool(self.root)
        pool.import_text("first@example.com----https://mail.example/one")
        pool.import_text(
            "second@example.com----https://mail.example/two\n"
            "third@example.com----https://mail.example/three"
        )
        self.assertEqual(
            [row.email for row in pool.entries()],
            ["second@example.com", "third@example.com", "first@example.com"],
        )
        self.assertEqual([row.line_no for row in pool.entries()], [1, 2, 3])

    def test_manual_restore_rejects_durable_confirmed_rows_atomically(self) -> None:
        pool = SQLiteFreeMailboxPool(self.root)
        pool.import_text(
            "confirmed-restore@example.com----https://mail.example/confirmed-restore\n"
            "untouched-restore@example.com----https://mail.example/untouched-restore"
        )
        confirmed, untouched = pool.entries()
        claimed = pool.storage.claim_mailbox(owner="restore-owner", row_id=confirmed.row_id)
        self.assertIsNotNone(claimed)
        self.assertIsNotNone(
            pool.storage.confirm_mailbox_lease(
                confirmed.row_id,
                owner="restore-owner",
                task_id="restore-task",
                expected_revision=claimed["revision"],
            )
        )
        self.assertTrue(pool.release(confirmed.row_id, owner="restore-owner", reusable=True))
        self.assertEqual(pool._row_state(confirmed.row_id)["status"], "pending_rerun")

        with self.assertRaises(FreeRegisterError) as raised:
            pool.set_status([confirmed.row_id, untouched.row_id], "available")

        self.assertEqual(raised.exception.error_code, "free_pool_confirmed_requires_rerun")
        self.assertEqual(pool._row_state(confirmed.row_id)["status"], "pending_rerun")
        self.assertEqual(pool._row_state(untouched.row_id)["status"], "available")
        self.assertTrue(pool._row_state(confirmed.row_id)["lease_confirmed"])

    def test_mailbox_adapter_releases_unconfirmed_and_keeps_confirmed_consumed(self) -> None:
        pool = SQLiteFreeMailboxPool(self.root)
        pool.import_text("one@example.com----https://mail.example/one")
        row = pool.entries()[0]
        pool.reserve([row], "batch")
        pool.update(row.row_id, status="reserved", task_id="task", driver="protocol")
        self.assertTrue(pool.release(row.row_id, owner="batch", reusable=True))
        self.assertEqual(pool._row_state(row.row_id)["status"], "available")

        claimed = pool.storage.claim_mailbox(owner="worker", row_id=row.row_id)
        self.assertIsNotNone(
            pool.storage.confirm_mailbox_lease(
                row.row_id,
                owner="worker",
                task_id="task-2",
                expected_revision=claimed["revision"],
            )
        )
        self.assertTrue(pool.release(row.row_id, owner="worker", reusable=True))
        self.assertEqual(pool._row_state(row.row_id)["status"], "pending_rerun")

    def test_mailbox_adapter_rejects_stale_owner_release_without_clearing_live_lease(self) -> None:
        pool = SQLiteFreeMailboxPool(self.root)
        pool.import_text("race-owner@example.com----https://mail.example/race-owner")
        row = pool.entries()[0]
        lease = pool.storage.claim_mailbox(owner="owner-a", row_id=row.row_id, lease_seconds=60)
        self.assertIsNotNone(lease)

        self.assertFalse(pool.release(row.row_id, owner="owner-b", reusable=True))
        current = pool.storage.get_mailbox(row.row_id)
        self.assertEqual(current["lease_owner"], "owner-a")
        self.assertEqual(current["status"], "reserved")

    def test_mailbox_batch_reservation_rolls_back_when_a_later_row_is_taken(self) -> None:
        pool = SQLiteFreeMailboxPool(self.root)
        pool.import_text(
            "first-race@example.com----https://mail.example/first\n"
            "second-race@example.com----https://mail.example/second"
        )
        rows = pool.entries()
        # Simulate another worker winning the second row after selection but
        # before this batch reaches the reservation transaction.
        other = pool.storage.claim_mailbox(owner="other-worker", row_id=rows[1].row_id)
        self.assertIsNotNone(other)

        with self.assertRaises(FreeRegisterError) as raised:
            pool.reserve(rows, "batch-race")
        self.assertEqual(raised.exception.node_code, "free_pool_reserve")
        self.assertEqual(pool._row_state(rows[0].row_id)["status"], "available")
        self.assertEqual(pool._row_state(rows[1].row_id)["status"], "reserved")

    def test_task_adapter_merges_partial_snapshots_and_skips_stale_timing(self) -> None:
        tasks = SQLiteFreeTaskStore(self.root)
        tasks.save({"task-1": {"task_id": "task-1", "status": "running", "result": {"token": "keep"}}})
        tasks.save({"task-1": {"task_id": "task-1", "status": "running", "stage": "otp"}})
        loaded = tasks.load()["task-1"]
        self.assertEqual(loaded["result"], {"token": "keep"})
        self.assertEqual(loaded["stage"], "otp")
        self.assertTrue(tasks.save_timing("task-1", {"elapsed_ms": 42, "stages": []}))
        loaded = tasks.load()["task-1"]
        self.assertEqual(loaded["timing"]["elapsed_ms"], 42)

        tasks.save({"task-1": {"task_id": "task-1", "status": "success", "result": {"ok": True}}})
        self.assertFalse(tasks.save_timing("task-1", {"elapsed_ms": 100}))
        self.assertEqual(tasks.load()["task-1"]["timing"]["elapsed_ms"], 42)

    def test_task_adapter_retries_stale_revision_and_updates_snapshot(self) -> None:
        tasks = SQLiteFreeTaskStore(self.root)
        snapshot = {"task_id": "cas-task", "status": "queued", "stage": "one"}
        tasks.save({"cas-task": snapshot})
        self.assertEqual(snapshot["revision"], 0)

        # Simulate a timing writer advancing the durable row while a manager
        # still holds the previous full snapshot.
        current = tasks.storage.get_task("cas-task")
        self.assertIsNotNone(current)
        tasks.storage.save_task(
            "cas-task",
            {**current["payload"], "timing": {"elapsed_ms": 10}},
            expected_revision=current["revision"],
            status="queued",
        )
        snapshot["status"] = "running"
        snapshot["stage"] = "two"
        tasks.save({"cas-task": snapshot})
        self.assertEqual(snapshot["revision"], 2)
        self.assertEqual(tasks.load()["cas-task"]["stage"], "two")
        self.assertEqual(tasks.load()["cas-task"]["timing"], {"elapsed_ms": 10})

    def test_task_adapter_does_not_prune_rows_created_after_snapshot(self) -> None:
        """A stale full snapshot must not delete another process' history."""
        first = SQLiteFreeTaskStore(self.root)
        first.save({
            "original": {
                "task_id": "original",
                "status": "success",
            }
        })
        snapshot = first.load()

        second = SQLiteFreeTaskStore(self.root)
        second.save({
            "new-after-load": {
                "task_id": "new-after-load",
                "status": "success",
            }
        })

        # ``first`` still holds the old complete map and does not know about
        # the task created by ``second``.  Saving it must retain that row.
        first.save(snapshot)
        self.assertIsNotNone(first.storage.get_task("new-after-load"))

    def test_task_adapter_does_not_prune_known_row_after_concurrent_revision(self) -> None:
        """An advanced known row is retained until deletion is retried fresh."""
        first = SQLiteFreeTaskStore(self.root)
        first.save({
            "advanced": {
                "task_id": "advanced",
                "status": "success",
            }
        })
        snapshot = first.load()
        second = SQLiteFreeTaskStore(self.root)
        current = second.storage.get_task("advanced")
        self.assertIsNotNone(current)
        second.storage.save_task(
            "advanced",
            {**current["payload"], "external_note": "kept"},
            expected_revision=current["revision"],
            status="success",
        )
        snapshot.pop("advanced")

        first.save(snapshot)
        durable = first.storage.get_task("advanced")
        self.assertIsNotNone(durable)
        self.assertEqual(durable["payload"]["external_note"], "kept")

    def test_proxy_adapter_uses_shared_leases_and_public_credentials_are_hidden(self) -> None:
        pool = SQLiteFreeProxyPool(self.root)
        self.assertEqual(pool.import_text("socks5://user:password@proxy.example:1080"), 1)
        self.assertIsNotNone(pool.bind(1, perform_probe=False)[0])
        binding = pool.bind(1, perform_probe=False)[0]
        pool.lease(binding, owner="task-a", batch_id="batch", task_id="task-a")
        pool.lease(binding, owner="task-b", batch_id="batch", task_id="task-b")
        # Keep the historical FreeProxyPool projection shape: callers read
        # the redacted records from ``public()["rows"]``.
        public = pool.public()["rows"]
        serialized = json.dumps(public, ensure_ascii=False)
        self.assertNotIn("password", serialized)
        self.assertNotIn("user@", serialized)
        self.assertEqual(public[0]["proxy"], "socks5://proxy.example:1080")

    def test_free_proxy_public_contract_does_not_expose_group_dimensions(self) -> None:
        pool = SQLiteFreeProxyPool(self.root)
        self.assertEqual(pool.import_text("http://proxy.example:8080"), 1)
        before = pool.public()
        # Keep the legacy projection shape for existing UI callers, while
        # exposing only one aggregate shared-pool bucket.  Country/group are
        # no longer allocation dimensions and must remain empty.
        self.assertEqual(len(before["groups"]), 1)
        self.assertEqual(before["groups"][0]["country"], "")
        self.assertEqual(before["groups"][0]["group"], "")
        self.assertEqual(len(before["countries"]), 1)
        self.assertEqual(before["countries"][0]["country"], "")
        self.assertEqual(pool.update_group("US", "residential", enabled=False)["modified"], 0)
        self.assertEqual(pool.delete_group("US", "residential"), 0)
        self.assertEqual(pool.update_group("", "", enabled=False)["modified"], 1)
        after = pool.public()
        self.assertEqual(after["rows"][0]["country"], "")
        self.assertEqual(after["rows"][0]["group"], "")
        self.assertFalse(after["rows"][0]["enabled"])

    def test_proxy_adapter_preserves_concurrent_leases_and_does_not_resurrect_release(self) -> None:
        """A stale full snapshot must not clobber or recreate durable leases."""
        first = SQLiteFreeProxyPool(self.root)
        second = SQLiteFreeProxyPool(self.root)
        self.assertEqual(first.import_text("socks5://proxy.example:1080"), 1)
        binding = first.bind(1, perform_probe=False)[0]
        self.assertIsNotNone(binding)

        # Capture a snapshot before any owner is present, then acquire one in
        # another instance.  A subsequent stale health write must retain it.
        stale_without_owner = second._load()
        first.lease(binding, owner="owner-a", batch_id="batch", task_id="task-a")
        stale_without_owner[0]["last_probe_ok"] = True
        second._save(stale_without_owner)
        owners = {item["owner"] for item in second._load()[0]["leases"]}
        self.assertEqual(owners, {"owner-a"})

        # Capture a snapshot that knows owner-a.  If owner-a is released and a
        # different owner is acquired before this stale writer saves, the
        # release must stick while the unknown concurrent owner survives.
        stale_with_owner = second._load()
        first.release(binding, owner="owner-a")
        first.lease(binding, owner="owner-b", batch_id="batch", task_id="task-b")
        stale_with_owner[0]["leases"] = []
        second._save(stale_with_owner)
        owners = {item["owner"] for item in second._load()[0]["leases"]}
        self.assertEqual(owners, {"owner-b"})

        # A stale snapshot still containing a concurrently released owner must
        # not resurrect it from the in-memory payload.
        stale_for_release = second._load()
        first.release(binding, owner="owner-b")
        second._save(stale_for_release)
        self.assertEqual(second._load()[0]["leases"], [])


if __name__ == "__main__":
    unittest.main()
