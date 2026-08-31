# -*- coding: utf-8 -*-
"""Focused contract tests for the optional Free SQLite repository."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from mac_overrides.free_storage import (
    MIGRATION_KEY,
    PROXY_REPAIR_KEY,
    SECRET_MASK,
    FreeSQLiteStore,
    FreeStorageError,
    RevisionConflict,
    _valid_migration_marker,
)


class FreeSQLiteStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_schema_uses_free_database_wal_and_busy_timeout(self) -> None:
        store = FreeSQLiteStore(self.root)

        self.assertEqual(store.path.name, "free_register.sqlite3")
        self.assertTrue(store.path.exists())
        health = store.health()
        self.assertTrue(health["ok"])
        self.assertEqual(health["journal_mode"], "wal")
        self.assertGreaterEqual(health["busy_timeout_ms"], 30_000)
        self.assertEqual(health["schema_version"], 1)
        self.assertIsNotNone(health["migration"])

        with closing(sqlite3.connect(store.path)) as db:
            tables = {
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            views = {
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='view'"
                )
            }
            db.commit()
        self.assertTrue(
            {"storage_meta", "mailboxes", "proxies", "tasks", "results", "resource_leases"}
            <= tables
        )
        self.assertTrue(
            {"free_storage_meta", "free_mailboxes", "free_proxies", "free_tasks", "free_results", "free_resource_leases"}
            <= views
        )

    def test_newer_schema_is_rejected_without_overwriting_metadata(self) -> None:
        """A downgraded runtime must never rewrite a newer database schema."""
        db_path = self.root / "free_register.sqlite3"
        with closing(sqlite3.connect(db_path)) as db:
            db.execute("CREATE TABLE storage_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute(
                "INSERT INTO storage_meta(key, value) VALUES('schema_version', '999')"
            )
            db.commit()

        with self.assertRaises(FreeStorageError):
            FreeSQLiteStore(self.root)

        with closing(sqlite3.connect(db_path)) as db:
            row = db.execute(
                "SELECT value FROM storage_meta WHERE key='schema_version'"
            ).fetchone()
        self.assertEqual(row[0], "999")

    def test_migration_is_read_only_and_idempotent(self) -> None:
        mailbox_text = (
            "first@example.com----https://api798.com/get_code?email=first@example.com&auth_code=SECRET\n"
            "invalid row\n"
        )
        state = {
            "version": 2,
            "rows": {
                # The ID is derived from the normalized email and URL.
                "placeholder": {"status": "used"},
            },
        }
        mailbox_path = self.root / "free_mailbox_pool.txt"
        state_path = self.root / "free_mailbox_state.json"
        proxy_path = self.root / "free_proxy_pool.json"
        task_path = self.root / "tasks.json"
        result_dir = self.root / "free_register_results"
        result_dir.mkdir()
        mailbox_path.write_text(mailbox_text, encoding="utf-8")
        state_path.write_text(json.dumps(state), encoding="utf-8")
        proxy_path.write_text(
            json.dumps(
                {
                    "version": 4,
                    "proxies": [
                        {
                            "proxy": "socks5://user:password@proxy.example:1080",
                            "status": "healthy",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        task_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "tasks": {"task-1": {"status": "queued", "email": "first@example.com"}},
                }
            ),
            encoding="utf-8",
        )
        (result_dir / "row-1.json").write_text(
            json.dumps({"row_id": "row-1", "access_token": "token-secret", "password": "pw-secret"}),
            encoding="utf-8",
        )
        before = {
            path: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (mailbox_path, state_path, proxy_path, task_path, result_dir / "row-1.json")
        }

        store = FreeSQLiteStore(self.root, auto_migrate=False)
        first = store.migrate_legacy()
        second = store.migrate_legacy()
        self.assertTrue(first["migrated"])
        self.assertEqual(second["reason"], "already_migrated")
        self.assertEqual(first["mailboxes"], 1)
        self.assertEqual(first["proxies"], 1)
        self.assertEqual(first["tasks"], 1)
        self.assertEqual(first["results"], 1)
        self.assertEqual(store._meta(MIGRATION_KEY) is not None, True)
        self.assertEqual(
            before,
            {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in before
            },
        )
        self.assertEqual(len(store.list_mailboxes()), 1)
        self.assertEqual(len(store.list_proxies()), 1)
        self.assertEqual(len(store.list_tasks()), 1)
        self.assertEqual(store.get_result("row-1")["payload"]["access_token"], "token-secret")

    def test_malformed_migration_marker_is_retried(self) -> None:
        """A truncated marker must not suppress a legacy mailbox import."""
        (self.root / "free_mailbox_pool.txt").write_text(
            "retry@example.com----https://mail.example/retry\n",
            encoding="utf-8",
        )
        store = FreeSQLiteStore(self.root, auto_migrate=False)
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "INSERT INTO storage_meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (MIGRATION_KEY, "{malformed"),
            )
            db.commit()

        result = store.migrate_legacy()
        self.assertTrue(result["migrated"])
        self.assertEqual(result["mailboxes"], 1)
        self.assertEqual(len(store.list_mailboxes()), 1)

    def test_malformed_or_old_migration_marker_is_retried(self) -> None:
        """Only a current JSON marker may suppress the legacy import."""
        for marker in ("{malformed", json.dumps({"version": 0}), "1"):
            with self.subTest(marker=marker):
                root = Path(tempfile.mkdtemp(prefix="free-marker-"))
                try:
                    store = FreeSQLiteStore(root, auto_migrate=False)
                    with closing(sqlite3.connect(store.path)) as db:
                        db.execute(
                            "INSERT INTO storage_meta(key,value) VALUES(?,?) "
                            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (MIGRATION_KEY, marker),
                        )
                        db.commit()
                    (root / "free_mailbox_pool.txt").write_text(
                        "retry@example.test----https://mail.example/retry\n",
                        encoding="utf-8",
                    )
                    restarted = FreeSQLiteStore(root)
                    self.assertTrue(restarted.migration_status()["completed"])
                    self.assertEqual(len(restarted.list_mailboxes()), 1)
                    self.assertTrue(_valid_migration_marker(restarted._meta(MIGRATION_KEY)))
                finally:
                    import shutil
                    shutil.rmtree(root, ignore_errors=True)

    def test_malformed_task_key_is_not_written_to_migration_marker(self) -> None:
        """Malformed legacy task keys must never leak mailbox-like identifiers."""
        (self.root / "tasks.json").write_text(
            json.dumps({
                "tasks": {
                    "private@example.com": "malformed-task-row",
                }
            }),
            encoding="utf-8",
        )

        store = FreeSQLiteStore(self.root, auto_migrate=False)
        result = store.migrate_legacy()
        self.assertTrue(result["migrated"])
        self.assertIn("task_row_invalid", result["errors"])
        serialized = json.dumps(store.migration_status(), ensure_ascii=False)
        self.assertIn("task_row_invalid", serialized)
        self.assertNotIn("private@example.com", serialized)
        self.assertNotIn("malformed-task-row", serialized)

    def test_legacy_result_read_error_never_exposes_filename(self) -> None:
        result_dir = self.root / "free_register_results"
        result_dir.mkdir()
        sensitive_name = "user-at-example.test-private-token.json"
        path = result_dir / sensitive_name
        path.write_text("{}", encoding="utf-8")
        store = FreeSQLiteStore(self.root, auto_migrate=False)

        original_read_text = Path.read_text
        resolved_path = path.resolve()

        def fail_result(candidate: Path, *args, **kwargs):
            if candidate == resolved_path:
                raise PermissionError("denied")
            return original_read_text(candidate, *args, **kwargs)

        with patch.object(Path, "read_text", autospec=True, side_effect=fail_result):
            result = store.migrate_legacy()

        self.assertTrue(result["recovery_required"])
        serialized = json.dumps(store.migration_status(), ensure_ascii=False)
        self.assertIn("legacy_read_result", serialized)
        self.assertNotIn(sensitive_name, serialized)
        self.assertNotIn("private-token", serialized)

    def test_concurrent_migration_reads_do_not_share_error_buffers(self) -> None:
        store = FreeSQLiteStore(self.root, auto_migrate=False)
        entered = threading.Event()
        release = threading.Event()
        original = store._legacy_mailboxes
        calls = 0
        calls_lock = threading.Lock()

        def controlled_mailboxes():
            nonlocal calls
            with calls_lock:
                calls += 1
                ordinal = calls
            if ordinal == 1:
                store._record_legacy_read_error(
                    self.root / "free_mailbox_pool.txt", "read"
                )
                entered.set()
                self.assertTrue(release.wait(2))
            return original()

        outcomes: list[dict[str, Any]] = []
        with patch.object(store, "_legacy_mailboxes", side_effect=controlled_mailboxes):
            first = threading.Thread(
                target=lambda: outcomes.append(store.migrate_legacy(force=True))
            )
            second = threading.Thread(
                target=lambda: outcomes.append(store.migrate_legacy(force=True))
            )
            first.start()
            self.assertTrue(entered.wait(2))
            second.start()
            # The second call cannot enter source reads until the first call
            # has captured and persisted its own error buffer.
            time.sleep(0.05)
            self.assertEqual(calls, 1)
            release.set()
            first.join(2)
            second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(calls, 2)
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(
            sum(bool(item.get("recovery_required")) for item in outcomes),
            1,
        )

    def test_migration_accepts_legacy_host_port_proxy_rows(self) -> None:
        """Pre-v4 proxy snapshots used scalar host/port/auth fields."""
        path = self.root / "free_proxy_pool.json"
        path.write_text(
            json.dumps({
                "version": 3,
                "proxies": [{
                    "proxy_id": "legacy-host-port",
                    "host": "proxy.example.test",
                    "port": 1080,
                    "username": "user",
                    "password": "p@ss",
                    "scheme": "socks5",
                    "status": "available",
                    "enabled": True,
                }],
            }),
            encoding="utf-8",
        )

        store = FreeSQLiteStore(self.root)
        row = store.get_proxy("legacy-host-port")
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["proxy"], "socks5://user:p%40ss@proxy.example.test:1080")
        self.assertEqual(store.health()["counts"]["proxies"], 1)
        self.assertIsNotNone(store._meta(PROXY_REPAIR_KEY))

    def test_legacy_pool_dimensions_are_cleared_from_mailbox_payload(self) -> None:
        """Retired country/group selectors must not reappear after migration."""
        email = "legacy@example.test"
        mailbox_url = "https://mail.example.test/code"
        row_id = hashlib.sha256(f"{email}|{mailbox_url}".encode()).hexdigest()[:16]
        (self.root / "free_mailbox_pool.txt").write_text(
            f"{email}----{mailbox_url}\n", encoding="utf-8"
        )
        (self.root / "free_mailbox_state.json").write_text(
            json.dumps({
                "rows": {
                    row_id: {
                        "status": "available",
                        "proxy_country": "US",
                        "proxy_group": "legacy-residential",
                    }
                }
            }),
            encoding="utf-8",
        )

        store = FreeSQLiteStore(self.root)
        mailbox = store.get_mailbox(row_id)
        self.assertIsNotNone(mailbox)
        assert mailbox is not None
        self.assertEqual(mailbox["payload"].get("proxy_country"), "")
        self.assertEqual(mailbox["payload"].get("proxy_group"), "")
        public = store.public_mailboxes()[0]["payload"]
        self.assertEqual(public.get("proxy_country"), "")
        self.assertEqual(public.get("proxy_group"), "")

    def test_task_progress_group_is_not_treated_as_proxy_dimension(self) -> None:
        """The generic progress ``group`` metadata remains intact."""
        store = FreeSQLiteStore(self.root)
        store.create_task(
            "progress-group",
            {"progress": {"group": "free", "stage": "entry"}, "group": "free"},
        )
        payload = store.get_task("progress-group")["payload"]
        self.assertEqual(payload["progress"]["group"], "free")
        # A top-level plain group is retained for compatibility in task rows;
        # only explicit proxy_* aliases are normalized outside proxy tables.
        self.assertEqual(payload["group"], "free")

    def test_proxy_repair_backfills_database_with_existing_main_marker(self) -> None:
        """An already-completed old migration gets the narrow proxy repair."""
        store = FreeSQLiteStore(self.root)
        with closing(sqlite3.connect(store.path)) as db:
            db.execute("DELETE FROM proxies")
            db.execute("DELETE FROM storage_meta WHERE key=?", (PROXY_REPAIR_KEY,))
            db.commit()
        (self.root / "free_proxy_pool.json").write_text(
            json.dumps({
                "version": 3,
                "proxies": [{
                    "proxy_id": "repair-proxy",
                    "host": "repair.example.test",
                    "port": 8000,
                    "scheme": "http",
                }],
            }),
            encoding="utf-8",
        )

        restarted = FreeSQLiteStore(self.root)
        self.assertEqual(restarted.migrate_legacy()["reason"], "already_migrated")
        self.assertIsNotNone(restarted.get_proxy("repair-proxy"))
        self.assertIsNotNone(restarted._meta(PROXY_REPAIR_KEY))

    def test_mailbox_claim_requires_available_and_release_is_owner_bound(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="claim@example.com",
            mailbox_url="https://mail.example/code",
        )
        claimed = store.claim_mailbox(owner="worker-a", lease_seconds=60)
        self.assertEqual(claimed["row_id"], mailbox["row_id"])
        self.assertIsNone(store.claim_mailbox(owner="worker-b", lease_seconds=60))
        self.assertFalse(
            store.release_lease("mailbox", mailbox["row_id"], owner="worker-b")
        )
        self.assertTrue(
            store.release_lease(
                "mailbox", mailbox["row_id"], owner="worker-a", status="available"
            )
        )
        self.assertIsNotNone(store.claim_mailbox(owner="worker-b", lease_seconds=60))

        # An explicitly selected non-available row cannot be stolen by claim.
        self.assertIsNone(
            store.claim_mailbox(
                owner="worker-c", row_id=mailbox["row_id"], lease_seconds=60
            )
        )

    def test_mailbox_confirmation_is_idempotent_and_release_is_atomic(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="confirm@example.com",
            mailbox_url="https://mail.example/code",
            payload={"source": "pool"},
        )
        lease = store.claim_mailbox(owner="worker-a", lease_seconds=60)
        confirmed = store.confirm_mailbox_lease(
            mailbox["row_id"],
            owner="worker-a",
            task_id="task-a",
            expected_revision=lease["revision"],
        )
        self.assertEqual(confirmed["status"], "running")
        revision = confirmed["revision"]
        # A retry for the same task is a no-op, while another task cannot
        # consume an already submitted mailbox.
        retried = store.confirm_mailbox_lease(
            mailbox["row_id"],
            owner="worker-a",
            task_id="task-a",
            expected_revision=lease["revision"],
        )
        self.assertEqual(retried["revision"], revision)
        self.assertIsNone(
            store.confirm_mailbox_lease(
                mailbox["row_id"], owner="worker-a", task_id="task-b"
            )
        )
        self.assertFalse(
            store.release_mailbox_lease(
                mailbox["row_id"], owner="worker-b"
            )
        )
        self.assertTrue(
            store.release_mailbox_lease(
                mailbox["row_id"], owner="worker-a", reusable=True
            )
        )
        released = store.get_mailbox(mailbox["row_id"])
        self.assertEqual(released["status"], "pending_rerun")
        self.assertTrue(released["payload"]["lease_confirmed"])

        reusable = store.upsert_mailbox(
            email="reusable@example.com",
            mailbox_url="https://mail.example/reusable",
            payload={"source": "pool"},
        )
        store.claim_mailbox(owner="worker-a", row_id=reusable["row_id"], lease_seconds=60)
        store.update_mailbox(
            reusable["row_id"],
            payload_patch={"lease_confirmed": False, "task_id": "stale"},
        )
        self.assertTrue(
            store.release_mailbox_lease(reusable["row_id"], owner="worker-a")
        )
        reusable_row = store.get_mailbox(reusable["row_id"])
        self.assertEqual(reusable_row["status"], "available")
        self.assertNotIn("task_id", reusable_row["payload"])

    def test_durable_confirmed_marker_blocks_stale_new_claim(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="durable-claim@example.com",
            mailbox_url="https://mail.example/durable-claim",
        )
        lease = store.claim_mailbox(owner="original-owner", row_id=mailbox["row_id"], lease_seconds=60)
        self.assertIsNotNone(lease)
        confirmed = store.confirm_mailbox_lease(
            mailbox["row_id"],
            owner="original-owner",
            task_id="original-task",
            expected_revision=lease["revision"],
        )
        self.assertIsNotNone(confirmed)

        # Simulate a stale/manual status reset after the lease sidecar was
        # removed.  The durable task-bound marker must still block a fresh
        # claim; explicit reserve_mailboxes is the only reset boundary.
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE mailboxes SET status='available',lease_owner='',lease_until=NULL WHERE row_id=?",
                (mailbox["row_id"],),
            )
            db.execute(
                "DELETE FROM resource_leases WHERE resource_type='mailbox' AND resource_id=?",
                (mailbox["row_id"],),
            )
            db.commit()

        self.assertTrue(
            store.is_mailbox_confirmed_for_task(
                mailbox["row_id"], "original-task"
            )
        )
        self.assertIsNone(
            store.claim_mailbox(owner="new-owner", row_id=mailbox["row_id"], lease_seconds=60)
        )

    def test_mailbox_confirmation_abort_is_owner_task_and_proof_bound(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="abort-confirm@example.com",
            mailbox_url="https://mail.example/abort-confirm",
            payload={"kept": "metadata"},
        )
        lease = store.claim_mailbox(owner="task-abort", lease_seconds=60)
        confirmed = store.confirm_mailbox_lease(
            mailbox["row_id"],
            owner="task-abort",
            task_id="task-abort",
            batch_id="batch-abort",
            driver="protocol",
            expected_revision=lease["revision"],
        )
        self.assertIsNotNone(confirmed)
        self.assertIsNone(
            store.abort_mailbox_confirmation(
                mailbox["row_id"], owner="task-abort", task_id="task-abort"
            )
        )
        self.assertIsNone(
            store.abort_mailbox_confirmation(
                mailbox["row_id"],
                owner="task-abort",
                task_id="other-task",
                submission_definitely_not_started=True,
            )
        )

        aborted = store.abort_mailbox_confirmation(
            mailbox["row_id"],
            owner="task-abort",
            task_id="task-abort",
            submission_definitely_not_started=True,
            expected_revision=confirmed["revision"],
        )
        self.assertIsNotNone(aborted)
        self.assertEqual(aborted["status"], "reserved")
        self.assertEqual(aborted["payload"]["kept"], "metadata")
        for key in (
            "lease_confirmed", "lease_confirmed_at", "task_id", "batch_id", "driver",
        ):
            self.assertNotIn(key, aborted["payload"])
        self.assertTrue(
            store.release_mailbox_lease(
                mailbox["row_id"], owner="task-abort", reusable=True
            )
        )
        self.assertEqual(store.get_mailbox(mailbox["row_id"])["status"], "available")

    def test_active_mailbox_upsert_and_stale_release_cannot_steal_new_owner(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="race@example.com",
            mailbox_url="https://mail.example/race",
            payload={"original": True},
        )
        first = store.claim_mailbox(owner="worker-a", lease_seconds=60)
        refreshed = store.upsert_mailbox(
            row_id=mailbox["row_id"],
            email="race@example.com",
            mailbox_url="https://mail.example/race",
            status="available",
            payload={"refresh": True, "lease_confirmed": False, "task_id": "stale"},
        )
        self.assertEqual(refreshed["status"], "reserved")
        self.assertEqual(refreshed["lease_owner"], "worker-a")
        self.assertTrue(refreshed["payload"]["original"])
        self.assertTrue(refreshed["payload"]["refresh"])
        self.assertNotIn("lease_confirmed", refreshed["payload"])
        self.assertEqual(refreshed["revision"], first["revision"])
        confirmed = store.confirm_mailbox_lease(
            mailbox["row_id"],
            owner="worker-a",
            task_id="task-a",
            expected_revision=first["revision"],
        )
        self.assertIsNotNone(confirmed)
        self.assertIsNone(store.claim_mailbox(owner="worker-b", lease_seconds=60))

        # Simulate lease expiry followed by a replacement claim.  Releasing
        # the stale owner must leave the replacement owner's status intact.
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE mailboxes SET status='available',lease_until=0 WHERE row_id=?",
                (mailbox["row_id"],),
            )
            # Model an unconfirmed stale owner for the replacement-race
            # assertion below.  A durable confirmed marker is intentionally
            # non-reusable and is covered by the dedicated recovery tests.
            db.execute(
                "UPDATE mailboxes SET payload='{}',private_payload='{}' WHERE row_id=?",
                (mailbox["row_id"],),
            )
            db.execute(
                "UPDATE resource_leases SET lease_until=0 "
                "WHERE resource_type='mailbox' AND resource_id=? AND owner=?",
                (mailbox["row_id"], "worker-a"),
            )
            db.commit()
        replacement = store.claim_mailbox(owner="worker-b", lease_seconds=60)
        self.assertEqual(replacement["lease_owner"], "worker-b")
        self.assertTrue(
            store.release_lease(
                "mailbox", mailbox["row_id"], owner="worker-a", status="available"
            )
        )
        current = store.get_mailbox(mailbox["row_id"])
        self.assertEqual(current["status"], "reserved")
        self.assertEqual(current["lease_owner"], "worker-b")

    def test_proxy_claims_are_shareable_by_default_but_can_be_exclusive(self) -> None:
        store = FreeSQLiteStore(self.root)
        proxy = store.upsert_proxy(
            proxy="socks5://user:password@proxy.example:1080",
            status="healthy",
        )
        self.assertIsNotNone(store.claim_proxy(owner="worker-a", lease_seconds=60))
        # Free's healthy_random policy allows concurrent owners on one exit.
        self.assertIsNotNone(store.claim_proxy(owner="worker-b", lease_seconds=60))

        other = store.upsert_proxy(proxy="http://proxy2.example:8080", status="healthy")
        self.assertTrue(
            store.lease_proxy(other["proxy_id"], owner="worker-a", shared=False, lease_seconds=60)
        )
        self.assertFalse(
            store.lease_proxy(other["proxy_id"], owner="worker-b", shared=False, lease_seconds=60)
        )

    def test_proxy_upsert_preserves_active_shared_lease(self) -> None:
        store = FreeSQLiteStore(self.root)
        proxy = store.upsert_proxy(
            proxy="socks5://user:secret@proxy.example.test:1080",
            status="healthy",
        )
        claimed = store.claim_proxy(
            owner="worker-a", proxy_id=proxy["proxy_id"], lease_seconds=60
        )
        self.assertIsNotNone(claimed)
        before = store.get_proxy(proxy["proxy_id"])
        assert before is not None

        store.upsert_proxy(
            proxy="socks5://user:secret@proxy.example.test:1080",
            proxy_id=proxy["proxy_id"],
            status="available",
            payload={"last_probe_ok": True},
        )
        after = store.get_proxy(proxy["proxy_id"])
        assert after is not None
        self.assertEqual(after["lease_owner"], before["lease_owner"])
        self.assertGreater(float(after["lease_until"] or 0), time.time())
        self.assertTrue(after["payload"].get("last_probe_ok"))

    def test_task_revision_compare_and_set_and_claim(self) -> None:
        store = FreeSQLiteStore(self.root)
        created = store.create_task("task-1", {"email": "task@example.com", "password": "secret"})
        self.assertEqual(created["revision"], 0)
        updated = store.save_task(
            "task-1", {"status": "running", "step": "otp"}, expected_revision=0
        )
        self.assertEqual(updated["revision"], 1)
        with self.assertRaises(RevisionConflict):
            store.save_task("task-1", {"step": "stale"}, expected_revision=0)
        claimed = store.claim_task("task-1", owner="worker-a", statuses=("running",))
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["revision"], 2)
        self.assertIsNone(store.claim_task("task-1", owner="worker-b", statuses=("running",)))

    def test_save_task_cannot_resurrect_terminal_state_and_delete_skips_live_lease(self) -> None:
        store = FreeSQLiteStore(self.root)
        terminal = store.create_task("terminal-task", {"status": "success", "result": {"ok": True}}, status="success")
        with self.assertRaises(RevisionConflict):
            store.save_task(
                "terminal-task",
                {"status": "running", "result": {"ok": False}},
                expected_revision=terminal["revision"],
            )
        self.assertEqual(store.get_task("terminal-task")["status"], "success")

        leased = store.create_task("leased-terminal", {"status": "failed"}, status="failed")
        # A terminal row can still be leased by a recovery worker; deletion
        # must wait until that lease is released.
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                "VALUES('task',?,?,?,?,?)",
                (leased["task_id"], "worker-a", time.time() + 60, "now", "now"),
            )
            db.commit()
        self.assertEqual(store.delete_tasks(["leased-terminal"]), 0)
        self.assertIsNotNone(store.get_task("leased-terminal"))
        self.assertTrue(store.release_lease("task", "leased-terminal", owner="worker-a"))
        self.assertEqual(store.delete_tasks(["leased-terminal"]), 1)

    def test_generic_release_marks_confirmed_mailbox_pending_rerun(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="generic-release@example.com",
            mailbox_url="https://mail.example/generic-release",
        )
        claimed = store.claim_mailbox(owner="worker-a", lease_seconds=60)
        confirmed = store.confirm_mailbox_lease(
            mailbox["row_id"],
            owner="worker-a",
            task_id="task-generic",
            expected_revision=claimed["revision"],
        )
        self.assertIsNotNone(confirmed)
        self.assertTrue(
            store.release_lease("mailbox", mailbox["row_id"], owner="worker-a")
        )
        self.assertEqual(
            store.get_mailbox(mailbox["row_id"])["status"], "pending_rerun"
        )

    def test_generic_release_clears_unconfirmed_mailbox_transient_payload(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="generic-unconfirmed@example.com",
            mailbox_url="https://mail.example/generic-unconfirmed",
            payload={
                "lease_confirmed": False,
                "lease_confirmed_at": 123.0,
                "task_id": "stale-task",
                "batch_id": "stale-batch",
                "driver": "camoufox",
                "kept": "metadata",
            },
        )
        claimed = store.claim_mailbox(owner="worker-a", row_id=mailbox["row_id"], lease_seconds=60)
        self.assertIsNotNone(claimed)

        self.assertTrue(
            store.release_lease(
                "mailbox",
                mailbox["row_id"],
                owner="worker-a",
                status="available",
            )
        )
        released = store.get_mailbox(mailbox["row_id"])
        self.assertEqual(released["status"], "available")
        for key in (
            "lease_confirmed",
            "lease_confirmed_at",
            "task_id",
            "batch_id",
            "driver",
        ):
            self.assertNotIn(key, released["payload"])
        self.assertEqual(released["payload"]["kept"], "metadata")

    def test_active_mailbox_update_preserves_lifecycle_and_revision(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="update-race@example.com",
            mailbox_url="https://mail.example/update-race",
        )
        claimed = store.claim_mailbox(owner="worker-a", lease_seconds=60)
        updated = store.update_mailbox(
            mailbox["row_id"],
            status="available",
            batch_id="stale-batch",
            payload_patch={
                "exit_ip": "203.0.113.4",
                "lease_confirmed": False,
                "task_id": "stale-task",
                "status": "available",
            },
        )
        self.assertEqual(updated["status"], "reserved")
        self.assertEqual(updated["batch_id"], "")
        self.assertEqual(updated["revision"], claimed["revision"])
        self.assertEqual(updated["payload"]["exit_ip"], "203.0.113.4")
        self.assertNotIn("task_id", updated["payload"])
        self.assertTrue(
            store.confirm_mailbox_lease(
                mailbox["row_id"],
                owner="worker-a",
                task_id="real-task",
                expected_revision=claimed["revision"],
            )
        )

    def test_transition_pagination_renew_and_expired_recovery(self) -> None:
        store = FreeSQLiteStore(self.root)
        for index in range(3):
            store.upsert_mailbox(
                email=f"page{index}@example.com",
                mailbox_url=f"https://mail.example/{index}",
            )
        page = store.list_mailboxes_page(limit=2, offset=1, public=True)
        self.assertEqual(page["total"], 3)
        self.assertEqual(page["offset"], 1)
        self.assertEqual(page["limit"], 2)
        self.assertEqual(len(page["items"]), 2)
        self.assertTrue(page["revision"])

        mailbox = store.claim_mailbox(owner="worker-a", lease_seconds=60)
        self.assertTrue(
            store.renew_lease(
                "mailbox",
                mailbox["row_id"],
                owner="worker-a",
                lease_seconds=120,
                expected_revision=mailbox["revision"],
            )
        )
        renewed = store.get_mailbox(mailbox["row_id"])
        self.assertGreater(renewed["lease_until"], mailbox["lease_until"])

        task = store.create_task("transition-task", {"stage": "entry"})
        transitioned = store.transition_task(
            "transition-task",
            "queued",
            "running",
            payload_patch={"stage": "otp"},
            expected_revision=task["revision"],
        )
        self.assertEqual(transitioned["status"], "running")
        self.assertEqual(transitioned["payload"]["stage"], "otp")
        self.assertIsNone(store.transition_task("transition-task", "queued", "failed"))
        task_lease = store.claim_task("transition-task", owner="old", statuses=("running",))
        self.assertIsNotNone(task_lease)

        # Force an expired lease in the isolated test database and let the
        # recovery routine return both resources to dispatchable states.
        with closing(sqlite3.connect(store.path)) as db:
            db.execute("UPDATE mailboxes SET lease_until=? WHERE row_id=?", (0, mailbox["row_id"]))
            db.execute("UPDATE tasks SET status='running',lease_owner='old',lease_until=? WHERE task_id=?", (0, "transition-task"))
            db.execute("UPDATE resource_leases SET lease_until=? WHERE resource_id IN (?,?)", (0, mailbox["row_id"], "transition-task"))
            db.commit()
        recovered = store.recover_expired_leases(now=1_000_000_000)
        self.assertGreaterEqual(recovered["mailbox"], 1)
        self.assertGreaterEqual(recovered["task"], 1)
        self.assertEqual(store.get_mailbox(mailbox["row_id"])["status"], "available")
        self.assertEqual(store.get_task("transition-task")["status"], "queued")

    def test_expired_unconfirmed_mailbox_clears_transient_dispatch_markers(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="expired-unconfirmed@example.test",
            mailbox_url="https://mail.example/expired-unconfirmed",
            payload={
                "task_id": "stale-task",
                "batch_id": "stale-batch",
                "driver": "protocol",
                "stage": "free_oauth_session",
                "lease_confirmed": "false",
                "lease_confirmed_at": 123,
                "kept": "metadata",
            },
        )
        claimed = store.claim_mailbox(
            owner="stale-task", row_id=mailbox["row_id"], lease_seconds=60
        )
        self.assertIsNotNone(claimed)
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE mailboxes SET status='running',batch_id='stale-batch',lease_until=0 WHERE row_id=?",
                (mailbox["row_id"],),
            )
            db.execute(
                "UPDATE resource_leases SET lease_until=0 WHERE resource_type='mailbox' AND resource_id=?",
                (mailbox["row_id"],),
            )
            db.commit()

        recovered = store.recover_expired_leases(now=time.time() + 1)
        self.assertGreaterEqual(recovered["mailbox"], 1)
        row = store.get_mailbox(mailbox["row_id"])
        self.assertEqual(row["status"], "available")
        self.assertEqual(row["batch_id"], "")
        self.assertEqual(row["lease_owner"], "")
        for key in (
            "lease_confirmed",
            "lease_confirmed_at",
            "task_id",
            "batch_id",
            "driver",
            "stage",
        ):
            self.assertNotIn(key, row["payload"])
        self.assertEqual(row["payload"]["kept"], "metadata")

    def test_public_projection_masks_credentials_and_private_urls(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="public@example.com",
            mailbox_url="https://api798.com/get_code?email=public@example.com&auth_code=SECRET",
            payload={"password": "pw-secret", "access_token": "at-secret", "label": "safe"},
        )
        store.upsert_proxy(
            proxy="socks5://user:password@proxy.example:1080",
            payload={"refresh_token": "refresh-secret"},
        )
        store.create_task("public-task", {"email": "public@example.com", "token": "secret-token"})
        store.save_result("row-1", {"access_token": "at-secret", "totp_secret": "totp-secret", "ok": True})

        public_mailbox = store.public_mailboxes()[0]
        public_proxy = store.public_proxies()[0]
        public_task = store.public_tasks()[0]
        public_result = store.get_result("row-1", public=True)
        serialized = json.dumps(
            [public_mailbox, public_proxy, public_task, public_result],
            ensure_ascii=False,
        )

        self.assertNotIn("api798.com/get_code", serialized)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("pw-secret", serialized)
        self.assertNotIn("at-secret", serialized)
        self.assertNotIn("totp-secret", serialized)
        self.assertIn(SECRET_MASK, serialized)
        self.assertEqual(public_mailbox["email"], "p***c@example.com")
        self.assertEqual(public_proxy["proxy"], "socks5://proxy.example:1080")
        self.assertEqual(mailbox["email"], "public@example.com")

    def test_public_projection_keeps_capability_state_but_masks_camel_case_api_key(self) -> None:
        store = FreeSQLiteStore(self.root)
        store.create_task(
            "state-task",
            {
                "passwordStatus": "enabled",
                "password_status": "enabled",
                "twofa_status": "enabled",
                "has_password": True,
                "has_access_token": True,
                "apiKey": "api-key-secret",
            },
        )
        public = store.public_tasks()[0]["payload"]
        self.assertEqual(public["password_status"], "enabled")
        self.assertEqual(public["twofa_status"], "enabled")
        self.assertTrue(public["has_password"])
        self.assertTrue(public["has_access_token"])
        self.assertEqual(public["passwordStatus"], "enabled")
        self.assertNotIn("apiKey", public)

    def test_public_projection_masks_email_aliases_in_nested_payload(self) -> None:
        store = FreeSQLiteStore(self.root)
        store.create_task(
            "email-alias-task",
            {
                "email": "private@example.test",
                "source_email": "source@example.test",
                "target_email": "target@example.test",
            },
        )
        public = store.public_tasks()[0]
        rendered = str(public)
        for value in ("private@example.test", "source@example.test", "target@example.test"):
            self.assertNotIn(value, rendered)
        self.assertEqual(public["payload"]["email"], "p***e@example.test")
        self.assertEqual(public["payload"]["source_email"], "s***e@example.test")

    def test_sensitive_values_are_kept_out_of_generic_payload_column(self) -> None:
        store = FreeSQLiteStore(self.root)
        task = store.create_task(
            "sidecar-task",
            {
                "step": "result",
                "password": "pw-secret",
                "result": {
                    "access_token": "access-secret",
                    "totp_secret": "totp-secret",
                    "safe": "kept",
                },
            },
        )
        store.save_result(
            "sidecar-row",
            {
                "credential_line": "user@example.test----pw-secret",
                "refresh_token": "refresh-secret",
                "safe": "kept",
            },
        )
        with closing(sqlite3.connect(store.path)) as db:
            raw_task = db.execute(
                "SELECT payload,private_payload FROM tasks WHERE task_id=?",
                (task["task_id"],),
            ).fetchone()
            raw_result = db.execute(
                "SELECT payload,private_payload FROM results WHERE row_id=?",
                ("sidecar-row",),
            ).fetchone()
        self.assertNotIn("pw-secret", str(raw_task[0]))
        self.assertNotIn("access-secret", str(raw_task[0]))
        self.assertNotIn("totp-secret", str(raw_task[0]))
        self.assertIn("kept", str(raw_task[0]))
        self.assertIn("pw-secret", str(raw_task[1]))
        self.assertIn("access-secret", str(raw_task[1]))
        self.assertNotIn("pw-secret", str(raw_result[0]))
        self.assertNotIn("refresh-secret", str(raw_result[0]))
        self.assertIn("pw-secret", str(raw_result[1]))
        self.assertEqual(store.get_task("sidecar-task")["payload"]["password"], "pw-secret")
        self.assertEqual(store.get_result("sidecar-row")["payload"]["refresh_token"], "refresh-secret")

    def test_confirmed_expired_mailbox_never_returns_to_available(self) -> None:
        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="expired-confirmed@example.test",
            mailbox_url="https://mail.example/expired-confirmed",
        )
        claimed = store.claim_mailbox(owner="worker", row_id=mailbox["row_id"], lease_seconds=60)
        self.assertIsNotNone(
            store.confirm_mailbox_lease(
                mailbox["row_id"],
                owner="worker",
                task_id="task-expired-confirmed",
                expected_revision=claimed["revision"],
            )
        )
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE mailboxes SET status='reserved',lease_until=0 WHERE row_id=?",
                (mailbox["row_id"],),
            )
            db.execute(
                "UPDATE resource_leases SET lease_until=0 WHERE resource_type='mailbox' AND resource_id=?",
                (mailbox["row_id"],),
            )
            db.commit()
        store.recover_expired_leases(now=time.time() + 1)
        self.assertEqual(
            store.get_mailbox(mailbox["row_id"])["status"], "pending_rerun"
        )

    def test_orphaned_reserved_mailbox_is_recovered_without_touching_confirmed_or_live_rows(self) -> None:
        """Startup recovery handles the crash window before lease insertion."""
        store = FreeSQLiteStore(self.root)
        orphan = store.upsert_mailbox(
            email="orphan@example.test",
            mailbox_url="https://mail.example/orphan",
            payload={
                "status": "reserved",
                "stage": "free_oauth_session",
                "task_id": "crashed-task",
                "batch_id": "crashed-batch",
                "driver": "protocol",
            },
        )
        # ``upsert_mailbox`` intentionally creates an available row; model the
        # crash window by setting only the scalar/payload reservation fields.
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE mailboxes SET status='reserved',batch_id=?,lease_owner=?,lease_until=? WHERE row_id=?",
                ("crashed-batch", "crashed-task", None, orphan["row_id"]),
            )
            db.commit()

        confirmed = store.upsert_mailbox(
            email="confirmed@example.test",
            mailbox_url="https://mail.example/confirmed",
        )
        claimed = store.claim_mailbox(owner="confirmed-owner", row_id=confirmed["row_id"], lease_seconds=60)
        self.assertIsNotNone(claimed)
        self.assertIsNotNone(
            store.confirm_mailbox_lease(
                confirmed["row_id"],
                owner="confirmed-owner",
                task_id="confirmed-task",
                expected_revision=claimed["revision"],
            )
        )
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE mailboxes SET status='reserved',lease_until=NULL WHERE row_id=?",
                (confirmed["row_id"],),
            )
            db.execute(
                "DELETE FROM resource_leases WHERE resource_type='mailbox' AND resource_id=?",
                (confirmed["row_id"],),
            )
            db.commit()

        live = store.upsert_mailbox(
            email="live@example.test",
            mailbox_url="https://mail.example/live",
        )
        live_claim = store.claim_mailbox(owner="live-owner", row_id=live["row_id"], lease_seconds=60)
        self.assertIsNotNone(live_claim)

        recovered = store.recover_orphaned_mailboxes()
        self.assertEqual(recovered, 1)
        orphan_row = store.get_mailbox(orphan["row_id"])
        self.assertEqual(orphan_row["status"], "available")
        self.assertEqual(orphan_row["batch_id"], "")
        self.assertEqual(orphan_row["payload"].get("stage"), None)
        self.assertNotIn("task_id", orphan_row["payload"])
        self.assertEqual(store.get_mailbox(confirmed["row_id"])["status"], "reserved")
        self.assertEqual(store.get_mailbox(live["row_id"])["status"], "reserved")

    def test_mailbox_coordinator_recover_includes_orphan_count(self) -> None:
        from mac_overrides.free_register.mailbox_lease import MailboxLeaseCoordinator

        store = FreeSQLiteStore(self.root)
        mailbox = store.upsert_mailbox(
            email="coordinator-orphan@example.test",
            mailbox_url="https://mail.example/coordinator-orphan",
        )
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE mailboxes SET status='reserved',batch_id='batch-orphan' WHERE row_id=?",
                (mailbox["row_id"],),
            )
            db.commit()
        result = MailboxLeaseCoordinator(store).recover()
        self.assertEqual(result["orphaned"], 1)
        self.assertGreaterEqual(result["mailbox"], 1)
        self.assertEqual(store.get_mailbox(mailbox["row_id"])["status"], "available")

    def test_concurrent_instances_claim_each_mailbox_once(self) -> None:
        seed = FreeSQLiteStore(self.root)
        for index in range(8):
            seed.upsert_mailbox(
                email=f"worker{index}@example.com",
                mailbox_url=f"https://mail.example/{index}",
            )

        claimed: list[str] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker(index: int) -> None:
            try:
                local = FreeSQLiteStore(self.root)
                row = local.claim_mailbox(owner=f"worker-{index}", lease_seconds=60)
                if row is not None:
                    with lock:
                        claimed.append(row["row_id"])
            except BaseException as exc:  # pragma: no cover - diagnostic aid
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(len(claimed), 8)
        self.assertEqual(len(set(claimed)), 8)


if __name__ == "__main__":
    unittest.main()
