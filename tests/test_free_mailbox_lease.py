from __future__ import annotations

from contextlib import closing
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from mac_overrides.free_register.mailbox_lease import MailboxLeaseCoordinator
from mac_overrides.free_storage import FreeSQLiteStore


class MailboxLeaseCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="free-lease-")
        self.root = Path(self.tmp.name)
        self.store = FreeSQLiteStore(self.root)
        self.row = self.store.upsert_mailbox(
            email="lease@example.com",
            mailbox_url="https://mail.example/code",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_claim_is_deferred_until_confirm_and_release_returns_unused_row(self) -> None:
        coordinator = MailboxLeaseCoordinator(self.store, lease_seconds=30)
        lease = coordinator.acquire(
            self.row["row_id"], task_id="task-a", batch_id="batch-a", driver="protocol"
        )
        self.assertIsNotNone(lease)
        current = self.store.get_mailbox(self.row["row_id"])
        self.assertEqual(current["status"], "reserved")
        self.assertFalse(lease.confirmed)

        self.assertTrue(coordinator.release(task_id="task-a", reusable=True))
        self.assertEqual(self.store.get_mailbox(self.row["row_id"])["status"], "available")

    def test_confirm_is_idempotent_and_consumes_row(self) -> None:
        coordinator = MailboxLeaseCoordinator(self.store)
        coordinator.acquire(self.row["row_id"], task_id="task-a", batch_id="batch-a", driver="camoufox")
        self.assertTrue(coordinator.confirm(task_id="task-a"))
        self.assertTrue(coordinator.confirm(task_id="task-a"))
        row = self.store.get_mailbox(self.row["row_id"])
        self.assertEqual(row["status"], "running")
        self.assertTrue(row["payload"]["lease_confirmed"])
        self.assertEqual(row["payload"]["task_id"], "task-a")
        self.assertTrue(coordinator.release(task_id="task-a", reusable=True))
        self.assertEqual(self.store.get_mailbox(self.row["row_id"])["status"], "pending_rerun")

    def test_confirm_can_be_aborted_only_with_definite_not_started_proof(self) -> None:
        coordinator = MailboxLeaseCoordinator(self.store)
        coordinator.acquire(
            self.row["row_id"], task_id="task-abort", batch_id="batch-a",
            driver="camoufox",
        )
        self.assertTrue(coordinator.confirm(task_id="task-abort"))

        self.assertFalse(coordinator.abort_confirmation(task_id="task-abort"))
        still_confirmed = self.store.get_mailbox(self.row["row_id"])
        self.assertEqual(still_confirmed["status"], "running")
        self.assertTrue(still_confirmed["payload"]["lease_confirmed"])

        self.assertTrue(
            coordinator.abort_confirmation(
                task_id="task-abort",
                submission_definitely_not_started=True,
            )
        )
        aborted = self.store.get_mailbox(self.row["row_id"])
        self.assertEqual(aborted["status"], "reserved")
        self.assertEqual(aborted["lease_owner"], "task-abort")
        self.assertFalse(aborted["payload"].get("lease_confirmed", False))
        self.assertNotIn("task_id", aborted["payload"])
        self.assertTrue(coordinator.release(task_id="task-abort", reusable=True))
        self.assertEqual(self.store.get_mailbox(self.row["row_id"])["status"], "available")

    def test_aborted_confirmation_can_be_confirmed_again(self) -> None:
        coordinator = MailboxLeaseCoordinator(self.store)
        coordinator.acquire(self.row["row_id"], task_id="task-reconfirm")
        self.assertTrue(coordinator.confirm(task_id="task-reconfirm"))
        self.assertTrue(
            coordinator.abort_confirmation(
                task_id="task-reconfirm",
                submission_definitely_not_started=True,
            )
        )
        self.assertTrue(coordinator.confirm(task_id="task-reconfirm"))
        self.assertTrue(coordinator.release(task_id="task-reconfirm", reusable=True))
        self.assertEqual(
            self.store.get_mailbox(self.row["row_id"])["status"], "pending_rerun"
        )

    def test_renew_refreshes_cached_revision_before_confirmation(self) -> None:
        """A heartbeat renewal must not make the later CAS confirmation stale."""
        coordinator = MailboxLeaseCoordinator(self.store, lease_seconds=10)
        lease = coordinator.acquire(
            self.row["row_id"], task_id="task-renew", batch_id="batch", driver="protocol",
            lease_seconds=10,
        )
        self.assertIsNotNone(lease)
        before = self.store.get_mailbox(self.row["row_id"])
        self.assertTrue(coordinator.renew(task_id="task-renew", lease_seconds=10))
        after = self.store.get_mailbox(self.row["row_id"])
        self.assertGreater(after["revision"], before["revision"])
        self.assertGreater(float(after["lease_until"]), float(before["lease_until"]))
        # The coordinator must have replaced its cached revision; otherwise
        # this call would fail with a stale expected_revision.
        self.assertTrue(coordinator.confirm(task_id="task-renew"))
        self.assertTrue(coordinator.is_confirmed(task_id="task-renew"))

    def test_durable_confirmation_survives_expiry_and_missing_sidecar(self) -> None:
        """Confirmation remains attributable after ephemeral lease cleanup."""
        coordinator = MailboxLeaseCoordinator(self.store, lease_seconds=30)
        lease = coordinator.acquire(self.row["row_id"], task_id="task-durable")
        self.assertIsNotNone(lease)
        self.assertTrue(coordinator.confirm(task_id="task-durable"))

        # A process restart/recovery can remove the resource-leases sidecar
        # independently of the mailbox payload.  The durable query must still
        # identify the exact task/mailbox pair.
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute(
                "DELETE FROM resource_leases WHERE resource_type='mailbox' AND resource_id=?",
                (self.row["row_id"],),
            )
            db.execute(
                "UPDATE mailboxes SET status='reserved',lease_until=0 WHERE row_id=?",
                (self.row["row_id"],),
            )
            db.commit()

        self.assertTrue(
            self.store.is_mailbox_confirmed_for_task(
                self.row["row_id"], "task-durable"
            )
        )
        self.assertTrue(
            coordinator.is_confirmed(
                task_id="task-durable", row_id=self.row["row_id"]
            )
        )
        self.assertFalse(
            coordinator.is_confirmed(
                task_id="other-task", row_id=self.row["row_id"]
            )
        )

    def test_only_one_concurrent_owner_can_claim(self) -> None:
        coordinators = [MailboxLeaseCoordinator(self.store), MailboxLeaseCoordinator(self.store)]
        results: list[object] = []
        barrier = threading.Barrier(2)

        def claim(index: int) -> None:
            barrier.wait()
            results.append(
                coordinators[index].acquire(
                    self.row["row_id"], task_id=f"task-{index}", batch_id="batch", driver="protocol"
                )
            )

        threads = [threading.Thread(target=claim, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(value is not None for value in results), 1)

    def test_cached_lease_is_invalidated_after_external_release(self) -> None:
        coordinator = MailboxLeaseCoordinator(self.store, lease_seconds=30)
        lease = coordinator.acquire(
            self.row["row_id"], task_id="task-external-release", batch_id="batch", driver="protocol"
        )
        self.assertIsNotNone(lease)

        # Simulate a second process completing cleanup without sharing the
        # coordinator's in-memory map.
        self.assertTrue(
            self.store.release_mailbox_lease(
                self.row["row_id"], owner="task-external-release", reusable=True
            )
        )
        self.assertFalse(
            coordinator.confirm(task_id="task-external-release", row_id=self.row["row_id"])
        )
        self.assertFalse(coordinator.renew(task_id="task-external-release"))

    def test_cached_revision_refreshes_after_external_same_owner_renewal(self) -> None:
        first = MailboxLeaseCoordinator(self.store, lease_seconds=30)
        lease = first.acquire(
            self.row["row_id"], task_id="task-external-renew", batch_id="batch", driver="protocol"
        )
        self.assertIsNotNone(lease)
        # Advance the durable revision from another process without touching
        # the first coordinator's in-memory snapshot.
        self.assertTrue(
            self.store.renew_lease(
                "mailbox",
                self.row["row_id"],
                owner="task-external-renew",
                lease_seconds=60,
                expected_revision=lease.revision,
            )
        )
        # The first coordinator must use the refreshed durable revision.
        self.assertTrue(first.confirm(task_id="task-external-renew"))

    def test_recover_reconciles_cache_after_external_owner_change(self) -> None:
        coordinator = MailboxLeaseCoordinator(self.store, lease_seconds=30)
        lease = coordinator.acquire(
            self.row["row_id"], task_id="task-old-owner", batch_id="batch", driver="protocol"
        )
        self.assertIsNotNone(lease)
        # Model a recovery process assigning the row to another owner while
        # keeping the lease alive.  The coordinator cache must be discarded.
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute(
                "UPDATE mailboxes SET lease_owner=?,lease_until=?,revision=revision+1 WHERE row_id=?",
                ("task-new-owner", 4_000_000_000, self.row["row_id"]),
            )
            db.execute(
                "DELETE FROM resource_leases WHERE resource_type='mailbox' AND resource_id=?",
                (self.row["row_id"],),
            )
            db.execute(
                "INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                "VALUES('mailbox',?,?,?,'now','now')",
                (self.row["row_id"], "task-new-owner", 4_000_000_000),
            )
            db.commit()
        coordinator.recover()
        self.assertFalse(coordinator.confirm(task_id="task-old-owner"))


if __name__ == "__main__":
    unittest.main()
