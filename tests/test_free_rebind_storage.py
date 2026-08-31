from __future__ import annotations

import json
import hashlib
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.free_log_runtime import FreeLogStore
from mac_overrides.free_register_store import FreeMailboxPool
from mac_overrides.free_rebind_runtime import FreeRebindService, _invoke_otp_factory
from mac_overrides.free_rebind_storage import (
    REBIND_MIGRATION_KEY,
    RebindRevisionConflict,
    RebindSQLiteStore,
    RebindStorageError,
)
from mac_overrides.free_rebind_store import RebindMailboxPool


class FreeRebindStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-rebind-storage-")
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_rebind_database_is_independent_wal_and_schema_indexed(self) -> None:
        store = RebindSQLiteStore(self.root)
        self.assertEqual(store.path, (self.root / "rebind" / "free_rebind.sqlite3").resolve())
        self.assertTrue(store.health()["ok"])
        self.assertEqual(store.health()["journal_mode"], "wal")
        with closing(sqlite3.connect(store.path)) as db:
            tables = {
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            indexes = {
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )
            }
        self.assertTrue({"storage_meta", "mailboxes", "tasks"} <= tables)
        self.assertTrue({"idx_rebind_mailboxes_status", "idx_rebind_tasks_status"} <= indexes)
        self.assertFalse((self.root / "free_register.sqlite3").exists())

    def test_legacy_rebind_files_are_imported_once_without_being_rewritten(self) -> None:
        legacy_root = self.root / "rebind"
        legacy_root.mkdir()
        mailbox_path = legacy_root / "mailbox_pool.txt"
        state_path = legacy_root / "mailbox_state.json"
        tasks_path = legacy_root / "tasks.json"
        mailbox_path.write_text(
            "target@example.com----https://api798.com/get_code?email=target%40example.com&auth_code=private\n",
            encoding="utf-8",
        )
        state_path.write_text(
            json.dumps({"rows": {"unknown": {"status": "available"}}}),
            encoding="utf-8",
        )
        tasks_path.write_text(
            json.dumps({"tasks": {"rebind-old": {"status": "failed", "stage": "free_rebind_result"}}}),
            encoding="utf-8",
        )
        before = {path: path.read_bytes() for path in (mailbox_path, state_path, tasks_path)}

        store = RebindSQLiteStore(self.root)
        first = store.migration_status()
        second = store.migrate_legacy()
        self.assertEqual(first["key"], REBIND_MIGRATION_KEY)
        self.assertTrue(first["completed"])
        self.assertEqual(second["reason"], "already_migrated")
        self.assertEqual(len(store.list_mailboxes()), 1)
        self.assertEqual(len(store.list_tasks()), 1)
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_malformed_migration_marker_is_retried(self) -> None:
        store = RebindSQLiteStore(self.root)
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE storage_meta SET value=? WHERE key=?",
                ("{malformed", REBIND_MIGRATION_KEY),
            )
            db.commit()
        legacy_root = self.root / "rebind"
        legacy_root.mkdir(exist_ok=True)
        (legacy_root / "mailbox_pool.txt").write_text(
            "retry@example.com----https://mail.example/retry\n",
            encoding="utf-8",
        )

        restarted = RebindSQLiteStore(self.root)
        self.assertTrue(restarted.migration_status()["completed"])
        self.assertEqual(len(restarted.list_mailboxes()), 1)

    def test_incomplete_migration_marker_is_retried(self) -> None:
        """A marker written before the import commits must not suppress retry."""
        store = RebindSQLiteStore(self.root)
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(
                "UPDATE storage_meta SET value=? WHERE key=?",
                (json.dumps({"version": 1, "complete": False}), REBIND_MIGRATION_KEY),
            )
            db.commit()
        legacy_root = self.root / "rebind"
        (legacy_root / "mailbox_pool.txt").write_text(
            "retry-incomplete@example.com----https://mail.example/retry\n",
            encoding="utf-8",
        )

        restarted = RebindSQLiteStore(self.root)
        self.assertTrue(restarted.migration_status()["completed"])
        self.assertEqual(len(restarted.list_mailboxes()), 1)

    def test_higher_schema_version_is_rejected_without_overwriting_metadata(self) -> None:
        """An older runtime must never downgrade a newer rebind database."""
        rebind_root = self.root / "rebind"
        rebind_root.mkdir(parents=True, exist_ok=True)
        db_path = rebind_root / "free_rebind.sqlite3"
        with closing(sqlite3.connect(db_path)) as db:
            db.execute("CREATE TABLE storage_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute(
                "INSERT INTO storage_meta(key, value) VALUES(?, ?)",
                ("schema_version", "999"),
            )
            db.commit()

        with self.assertRaises(RebindStorageError):
            RebindSQLiteStore(self.root, auto_migrate=False)

        with closing(sqlite3.connect(db_path)) as db:
            self.assertEqual(
                db.execute(
                    "SELECT value FROM storage_meta WHERE key='schema_version'"
                ).fetchone()[0],
                "999",
            )

    def test_legacy_iso_timestamps_are_normalized_for_mailboxes_and_tasks(self) -> None:
        legacy_root = self.root / "rebind"
        legacy_root.mkdir(exist_ok=True)
        (legacy_root / "mailbox_pool.txt").write_text(
            "target@example.com----https://mail.example/target\n",
            encoding="utf-8",
        )
        row_id = hashlib.sha256(
            b"target@example.com|https://mail.example/target"
        ).hexdigest()
        (legacy_root / "mailbox_state.json").write_text(
            json.dumps({"rows": {row_id: {
                "created_at": "2024-01-02T03:04:05Z",
                "updated_at": "1704164645",
            }}}),
            encoding="utf-8",
        )
        (legacy_root / "tasks.json").write_text(
            json.dumps({"tasks": {
                "iso-task": {
                    "created_at": "2024-01-02T03:04:05+00:00",
                    "updated_at": 1704164645,
                },
            }}),
            encoding="utf-8",
        )
        store = RebindSQLiteStore(self.root)
        mailbox = store.list_mailboxes()[0]
        task = store.get_task("iso-task")
        self.assertEqual(mailbox["created_at"], 1704164645)
        self.assertEqual(mailbox["updated_at"], 1704164645)
        self.assertIsNotNone(task)
        assert task is not None
        self.assertEqual(task["created_at"], 1704164645)
        self.assertEqual(task["updated_at"], 1704164645)

    def test_public_rebind_rows_mask_email_fields(self) -> None:
        store = RebindSQLiteStore(self.root)
        row = store.upsert_mailbox(
            email="private@example.com",
            mailbox_url="https://mail.example/private",
        )
        public = store.public_mailboxes()[0]
        self.assertEqual(public["email"], "p***e@example.com")
        self.assertEqual(public["email_masked"], public["email"])
        self.assertNotIn("private@example.com", str(public))

        manager = SimpleNamespace(pool=FreeMailboxPool(self.root / "free_register"))
        service = FreeRebindService(self.root, free_manager=manager)
        service._tasks = {
            "rebind-public": {
                "task_id": "rebind-public",
                "source_email": "source@example.com",
                "target_email": "target@example.com",
                "new_bound_email": "bound@example.com",
                "status": "failed",
            },
        }
        task = service.public_tasks()[0]
        rendered = str(task)
        for value in ("source@example.com", "target@example.com", "bound@example.com"):
            self.assertNotIn(value, rendered)
        self.assertEqual(task["source_email"], "s***e@example.com")
        self.assertEqual(task["target_email"], "t***t@example.com")
        self.assertEqual(task["new_bound_email"], "b***d@example.com")

    def test_iso_legacy_timestamps_are_normalized_during_migration(self) -> None:
        """Older snapshots may store ISO timestamps despite INTEGER schema."""
        legacy_root = self.root / "rebind"
        legacy_root.mkdir(exist_ok=True)
        (legacy_root / "mailbox_pool.txt").write_text(
            "iso@example.com----https://mail.example/iso\n",
            encoding="utf-8",
        )
        # The row id is deterministic and derived from the normalized pair.
        import hashlib
        row_id = hashlib.sha256(
            "iso@example.com|https://mail.example/iso".encode("utf-8")
        ).hexdigest()
        (legacy_root / "mailbox_state.json").write_text(
            json.dumps({
                "rows": {
                    row_id: {
                        "status": "available",
                        "created_at": "2026-08-31T00:00:00Z",
                        "updated_at": "2026-08-31T00:00:01+00:00",
                    }
                }
            }),
            encoding="utf-8",
        )

        store = RebindSQLiteStore(self.root)
        row = store.list_mailboxes()[0]
        self.assertIsInstance(row["created_at"], int)
        self.assertIsInstance(row["updated_at"], int)
        self.assertGreater(row["updated_at"], row["created_at"])

    def test_mailbox_reservation_is_owner_bound_and_concurrent(self) -> None:
        store = RebindSQLiteStore(self.root)
        row = store.upsert_mailbox(
            email="target@example.com",
            mailbox_url="https://mail.example/target",
        )
        outcomes: list[str] = []
        lock = threading.Lock()

        def reserve(owner: str) -> None:
            try:
                claimed = store.reserve_mailbox(row["row_id"], owner)
                value = "ok" if claimed else "none"
            except Exception as exc:  # one contender should lose deterministically
                value = type(exc).__name__
            with lock:
                outcomes.append(value)

        threads = [threading.Thread(target=reserve, args=(f"task-{i}",)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(sum(value == "ok" for value in outcomes), 1)
        current = store.get_mailbox(row["row_id"])
        self.assertEqual(current["status"], "reserved")
        owner = current["task_id"]
        self.assertFalse(store.release_mailbox(row["row_id"], "other-task"))
        self.assertTrue(store.release_mailbox(row["row_id"], owner))
        self.assertEqual(store.get_mailbox(row["row_id"])["status"], "available")

    def test_task_revision_and_terminal_state_are_compare_and_set(self) -> None:
        store = RebindSQLiteStore(self.root)
        created = store.create_task(
            "rebind-task",
            {"status": "queued", "source_row_id": "source", "target_row_id": "target"},
        )
        updated = store.save_task(
            "rebind-task",
            {"status": "running", "stage": "free_rebind_login_old"},
            expected_revision=created["revision"],
        )
        self.assertEqual(updated["revision"], 1)
        with self.assertRaises(RebindRevisionConflict):
            store.save_task("rebind-task", {"status": "failed"}, expected_revision=0)
        terminal = store.save_task(
            "rebind-task",
            {"status": "success"},
            expected_revision=updated["revision"],
        )
        self.assertEqual(terminal["status"], "success")
        with self.assertRaises(RebindRevisionConflict):
            store.save_task("rebind-task", {"status": "running"}, expected_revision=terminal["revision"])

    def test_pool_and_service_use_sqlite_without_tasks_json_projection(self) -> None:
        pool = RebindMailboxPool(self.root)
        pool.import_text("target@example.com----https://mail.example/target")
        self.assertTrue(pool.storage.path.exists())
        self.assertFalse(pool.pool_path.exists())
        self.assertFalse(pool.state_path.exists())

        registration_pool = FreeMailboxPool(self.root)
        registration_pool.import_text("source@example.com----https://mail.example/source")
        manager = SimpleNamespace(pool=registration_pool)
        service = FreeRebindService(self.root, free_manager=manager)
        service._tasks["rebind-task"] = {
            "task_id": "rebind-task",
            "status": "failed",
            "stage": "free_rebind_result",
            "created_at": 1,
            "updated_at": 1,
        }
        service._save_tasks()
        self.assertTrue(service.storage.path.exists())
        self.assertFalse(service.tasks_path.exists())

        restarted = FreeRebindService(self.root, free_manager=manager)
        self.assertEqual(restarted._tasks["rebind-task"]["status"], "failed")

    def test_removed_in_memory_task_is_purged_from_sqlite_before_restart(self) -> None:
        manager = SimpleNamespace(pool=FreeMailboxPool(self.root))
        service = FreeRebindService(self.root, free_manager=manager)
        service._tasks["rollback-task"] = {
            "task_id": "rollback-task",
            "status": "queued",
            "created_at": 1,
            "updated_at": 1,
        }
        service._save_tasks()
        self.assertIsNotNone(service.storage.get_task("rollback-task"))

        service._tasks.pop("rollback-task")
        service._save_tasks()

        self.assertIsNone(service.storage.get_task("rollback-task"))
        restarted = FreeRebindService(self.root, free_manager=manager)
        self.assertNotIn("rollback-task", restarted._tasks)

    def test_rebind_logs_use_structured_workflow_and_redact_subject(self) -> None:
        diagnostics = DiagnosticStore(self.root / "diagnostics")
        free_root = self.root / "free_register"
        log_store = FreeLogStore(
            free_root,
            diagnostic_store=diagnostics,
            legacy_projection=False,
        )
        manager = SimpleNamespace(
            pool=FreeMailboxPool(free_root),
            log_store=log_store,
        )
        service = FreeRebindService(self.root, free_manager=manager)
        service._tasks["rebind-task"] = {
            "task_id": "rebind-task",
            "source_email": "source@example.com",
            "target_email": "target@example.com",
        }

        incident_id = service._log(
            "[rebind-task/换绑邮箱/free_rebind_otp] token=private-code",
            "error",
            task_id="rebind-task",
            node_code="free_rebind_otp",
            node_label="等待新邮箱验证码",
            failure={"error_code": "otp_timeout", "raw_body": "private-body"},
        )

        self.assertTrue(incident_id.startswith("LOG-"))
        detail = diagnostics.incident(incident_id)
        self.assertIsNotNone(detail)
        assert detail is not None
        self.assertEqual(detail["workflow"], "rebind")
        self.assertEqual(detail["driver"], "protocol")
        rendered = str(detail)
        for secret in ("source@example.com", "target@example.com", "private-code", "private-body"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(detail["subject_display"], "t***@example.com")
        self.assertEqual(service._tasks["rebind-task"]["incident_id"], incident_id)
        self.assertEqual(service.storage.get_task("rebind-task")["incident_id"], incident_id)

    def test_otp_factory_gets_rebind_strategy_context_with_legacy_compatibility(self) -> None:
        calls: list[dict[str, object]] = []

        def modern(mailbox_url, proxy, *, config, task_id, stage_fn, workflow, driver):
            calls.append({
                "mailbox_url": mailbox_url,
                "proxy": proxy,
                "config": config,
                "task_id": task_id,
                "workflow": workflow,
                "driver": driver,
                "stage_fn": stage_fn,
            })
            return "modern"

        self.assertEqual(
            _invoke_otp_factory(
                modern,
                "https://mail.example/target",
                "http://proxy.invalid:8080",
                {"mailbox_network_mode": "local_proxy"},
                task_id="rebind-task",
                stage_fn=lambda *_args: None,
            ),
            "modern",
        )
        self.assertEqual(calls[0]["workflow"], "free_rebind")
        self.assertEqual(calls[0]["driver"], "protocol")

        legacy_calls: list[dict[str, object]] = []

        def legacy(mailbox_url, proxy, *, config, task_id, stage_fn):
            legacy_calls.append({"mailbox_url": mailbox_url, "proxy": proxy, "task_id": task_id})
            return "legacy"

        self.assertEqual(
            _invoke_otp_factory(
                legacy,
                "https://mail.example/target",
                "http://proxy.invalid:8080",
                {},
                task_id="rebind-task",
                stage_fn=lambda *_args: None,
            ),
            "legacy",
        )
        self.assertEqual(legacy_calls[0]["task_id"], "rebind-task")

    def test_successful_rebind_persists_refreshed_session_token_privately(self) -> None:
        source_pool = FreeMailboxPool(self.root / "free_register")
        source_pool.import_text("source@example.com----https://mail.example/source")
        source_row = source_pool.entries()[0]
        source_pool.update(source_row.row_id, status="success", driver="protocol")
        source_pool.save_result(
            source_row.row_id,
            {
                "password": "pw-secret",
                "totp_secret": "totp-secret",
                "access_token": "old-token",
            },
        )
        manager = SimpleNamespace(pool=source_pool)
        service = FreeRebindService(self.root, free_manager=manager)
        service.pool.import_text("target@example.com----https://mail.example/target")
        target_row = service.pool.entries()[0]
        task_id = "rebind-token-refresh"
        service._tasks[task_id] = {
            "task_id": task_id,
            "source_row_id": source_row.row_id,
            "source_email": "source@example.com",
            "target_row_id": target_row.row_id,
            "target_email": "target@example.com",
            "status": "queued",
            "stage": "free_rebind_proxy",
            "created_at": 1,
            "updated_at": 1,
        }
        service.pool.reserve(target_row.row_id, task_id)
        service._save_tasks()
        source_context = {
            "row_id": source_row.row_id,
            "login_email": "source@example.com",
            "password": "pw-secret",
            "totp_secret": "totp-secret",
            "proxy": "http://proxy.example:8080",
            "saved": {
                "password": "pw-secret",
                "totp_secret": "totp-secret",
                "access_token": "old-token",
            },
        }
        with patch.object(service, "_source_context", return_value=source_context), \
             patch.object(service, "_choose_proxy", return_value=("http://proxy.example:8080", None)), \
             patch.object(
                 service,
                 "_run_protocol_rebind",
                 return_value={
                     "new_bound_email": "target@example.com",
                     "access_token": "new-token",
                     "refresh_token": "new-refresh-token",
                     "plan_type": "free",
                     "subscription_plan": "free",
                     "plus_trial_eligible": False,
                     "plan_check_status": "success",
                     "rebind_completed_at": 2,
                 },
             ):
            service._worker(task_id)

        saved = source_pool.result(source_row.row_id)
        self.assertEqual(saved["access_token"], "new-token")
        self.assertEqual(saved["refresh_token"], "new-refresh-token")
        self.assertNotIn("access_token", service._tasks[task_id].get("result", {}))
        self.assertEqual(service._tasks[task_id]["status"], "success")

    def test_rebind_prefers_current_shared_healthy_random_proxy_over_source_snapshot(self) -> None:
        calls: list[dict[str, object]] = []
        binding = SimpleNamespace(
            proxy="socks5://current.example:1080",
            proxy_id="proxy-current",
            scheme="socks5",
        )

        class Proxies:
            def bind(self, count, **kwargs):
                calls.append({"count": count, **kwargs})
                return [binding]

            def lease(self, value, **kwargs):
                calls.append({"lease": value.proxy_id, **kwargs})

        manager = SimpleNamespace(
            pool=FreeMailboxPool(self.root / "free_register"),
            proxies=Proxies(),
            proxy_probe=None,
        )
        service = FreeRebindService(self.root, free_manager=manager)
        proxy, selected = service._choose_proxy(
            {"proxy": "http://stale-source.example:8080"},
            {"proxy_probe_url": "https://chatgpt.com/"},
            "rebind-proxy-task",
        )
        self.assertEqual(proxy, binding.proxy)
        self.assertIs(selected, binding)
        self.assertEqual(calls[0]["count"], 1)
        self.assertEqual(calls[0]["driver"], "protocol")
        self.assertEqual(calls[1]["lease"], "proxy-current")

    def test_callback_only_rebind_logging_drops_private_keyword_fields(self) -> None:
        calls: list[tuple[object, object, dict[str, object]]] = []

        def callback(message, level, **fields):
            calls.append((message, level, dict(fields)))

        manager = SimpleNamespace(pool=FreeMailboxPool(self.root / "free_register"))
        service = FreeRebindService(
            self.root,
            free_manager=manager,
            log_fn=callback,
        )
        service._log(
            "换绑失败 email=private@example.com token=private-token",
            "error",
            task_id="rebind-callback",
            subject_ref="private@example.com",
            target_email="private@example.com",
            mailbox_url="https://mail.example/code?auth_code=private",
            proxy="socks5://user:password@proxy.example:1080",
            failure={"error_code": "otp_timeout", "raw_body": "private-body"},
        )
        self.assertEqual(len(calls), 1)
        rendered = str(calls[0])
        for secret in (
            "private@example.com",
            "private-token",
            "https://mail.example/code",
            "proxy.example",
            "private-body",
        ):
            self.assertNotIn(secret, rendered)
        self.assertEqual(calls[0][2]["task_id"], "rebind-callback")
        self.assertEqual(calls[0][2]["failure"]["error_code"], "otp_timeout")

    def test_rebind_snapshot_purge_supports_legacy_storage_delete_signature(self) -> None:
        class LegacyStorage:
            def __init__(self) -> None:
                self.deleted: list[str] = []

            def save_task(self, task_id, payload, *, expected_revision=None):
                return {"task_id": task_id, **dict(payload), "revision": expected_revision or 0}

            def delete_tasks(self, task_ids):
                self.deleted.extend(task_ids)
                return len(task_ids)

        service = object.__new__(FreeRebindService)
        service.storage = LegacyStorage()
        service._task_persisted = {"rollback-task": {"status": "queued"}}
        service._task_revisions = {"rollback-task": 0}
        service._tasks = {}

        service._save_tasks()

        self.assertEqual(service.storage.deleted, ["rollback-task"])

    def test_sqlite_task_read_failure_does_not_fall_back_to_legacy_json(self) -> None:
        manager = SimpleNamespace(pool=FreeMailboxPool(self.root / "free_register"))
        service = FreeRebindService(self.root, free_manager=manager)
        service.tasks_path.write_text(
            json.dumps({"tasks": {"legacy-task": {"status": "success"}}}),
            encoding="utf-8",
        )

        class BrokenStorage:
            def list_tasks(self, **_kwargs):
                raise sqlite3.DatabaseError("database is unavailable")

        service.storage = BrokenStorage()
        with self.assertRaises(sqlite3.DatabaseError):
            service._load_tasks()

    def test_startup_recovery_releases_proxy_lease_for_interrupted_task(self) -> None:
        class Proxies:
            def __init__(self) -> None:
                self.released: list[str] = []

            def release_owner(self, owner: str) -> int:
                self.released.append(str(owner))
                return 1

        target_pool = RebindMailboxPool(self.root)
        target_pool.import_text("target-recovery@example.com----https://mail.example/recovery")
        target = target_pool.entries()[0]
        proxies = Proxies()
        manager = SimpleNamespace(pool=FreeMailboxPool(self.root / "free_register"), proxies=proxies)
        service = FreeRebindService(self.root, free_manager=manager)
        service._tasks = {
            "rebind-recovery": {
                "task_id": "rebind-recovery",
                "source_row_id": "source-row",
                "target_row_id": target.row_id,
                "status": "running",
            },
        }

        service._recover_interrupted_tasks()

        self.assertEqual(proxies.released, ["rebind-recovery"])
        self.assertEqual(service._tasks["rebind-recovery"]["status"], "failed")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
