from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import mac_overrides.mailbox_source_lock as source_lock
from mac_overrides.mailbox_admin import MailboxAdminService, row_id_from_source
from mac_overrides.mailbox_state_runtime import mark_mailboxes_unavailable


class FakeStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.config = {
            "pool_path": "pool.txt",
            "state_path": "state.json",
            "results_dir": "results",
        }

    def load(self):
        return dict(self.config)


class NonReentrantFileLockFactory:
    """Model the recovered lock's separate-FD flock behavior without hanging tests."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def __call__(self, name: str):
        path = self.root / name

        @contextmanager
        def acquire():
            handle = path.open("a+b")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                handle.close()
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise AssertionError("source flock was acquired twice") from exc
                raise
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()

        return acquire()


class MailboxSourceLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = FakeStore(self.root)
        self.validations: list[dict] = []
        self.lock_factory = NonReentrantFileLockFactory(self.root / "locks")
        self.service = MailboxAdminService(
            self.store,
            validate_pool=self._validate_pool,
            imap_poller_factory=lambda *_args, **_kwargs: None,
            runtime_status=lambda _config: {"tasks": []},
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_pool(self, rows: list[str]) -> None:
        (self.root / "pool.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")

    def _write_state(self, items: dict) -> None:
        (self.root / "state.json").write_text(
            json.dumps({"items": items}, ensure_ascii=False),
            encoding="utf-8",
        )

    def _validate_pool(self, config):
        self.validations.append(dict(config))
        pool_path = Path(config["pool_path"])
        if not pool_path.is_absolute():
            pool_path = self.root / pool_path
        digest = hashlib.sha256(str(pool_path.resolve()).encode("utf-8")).hexdigest()[:16]
        with self.lock_factory(f"self_mailbox_source_{digest}.lock"):
            return {"ok": True}

    def test_all_source_mutations_avoid_nested_flock(self):
        rows = [
            "one@example.com----pass-one",
            "two@example.com----pass-two",
        ]
        self._write_pool(rows)
        self._write_state({
            "one": {"email": "one@example.com", "line_no": 1, "status": "damaged"},
            "two": {"email": "two@example.com", "line_no": 2, "status": "damaged"},
        })
        one_binding = {"row_id": row_id_from_source(rows[0]), "line_no": 1}

        with patch("mac_overrides.mailbox_source_lock._named_file_lock", self.lock_factory):
            restored = self.service.restore({"line_nos": [1]})
            unavailable = mark_mailboxes_unavailable(self.service, {
                "line_nos": [1],
                "rows": [one_binding],
            })
            imported = self.service.import_mailboxes("three@example.com----pass-three")
            third = "three@example.com----pass-three"
            deleted = self.service.delete({
                "line_nos": [3],
                "rows": [{"row_id": row_id_from_source(third), "line_no": 3}],
            })

        self.assertEqual(restored, {"ok": True, "restored": 1})
        self.assertEqual(unavailable, {"ok": True, "unavailable": 1})
        self.assertTrue(imported["ok"])
        self.assertEqual(deleted, {"ok": True, "deleted": 1})
        self.assertEqual(len(self.validations), 4)

    def _direct_lock_factory_marker(self):
        """Make the source module select its bounded recovered-lock path."""
        def marker(_name):
            raise AssertionError("the direct timed path should be used")

        marker.__module__ = "file_safety"
        marker.__name__ = "named_file_lock"
        marker.__wrapped__ = marker
        return marker

    def test_source_lock_timeout_releases_process_lock_and_file_handle(self):
        lock_name = "self_mailbox_source_timeout-test.lock"
        lock_path = self.root / "locks" / lock_name
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        holder = lock_path.open("a+b")
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        marker = self._direct_lock_factory_marker()

        with patch.object(source_lock, "_named_file_lock", marker), patch.object(
            source_lock, "_runtime_path", lambda *_parts: self.root / "locks"
        ), patch.object(source_lock, "SOURCE_LOCK_POLL_SECONDS", 0.005):
            started = time.monotonic()
            with self.assertRaises(source_lock.MailboxSourceLockTimeout) as raised:
                with source_lock._timed_source_file_lock(lock_name, 0.06):
                    pass
            elapsed = time.monotonic() - started

            self.assertEqual(raised.exception.code, "mailbox_source_lock_timeout")
            self.assertLess(elapsed, 0.5)

            # The timeout path must release the in-process RLock and close its
            # descriptor; after the external holder releases, acquisition works.
            fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
            with source_lock._timed_source_file_lock(lock_name, 0.5):
                pass
        holder.close()

    def test_source_lock_waits_for_external_release_before_deadline(self):
        lock_name = "self_mailbox_source_release-test.lock"
        lock_path = self.root / "locks" / lock_name
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        holder = lock_path.open("a+b")
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        marker = self._direct_lock_factory_marker()
        acquired = threading.Event()
        errors: list[Exception] = []

        def worker():
            try:
                with source_lock._timed_source_file_lock(lock_name, 0.8):
                    acquired.set()
            except Exception as exc:  # pragma: no cover - assertion below reports it.
                errors.append(exc)

        with patch.object(source_lock, "_named_file_lock", marker), patch.object(
            source_lock, "_runtime_path", lambda *_parts: self.root / "locks"
        ), patch.object(source_lock, "SOURCE_LOCK_POLL_SECONDS", 0.005):
            thread = threading.Thread(target=worker)
            thread.start()
            time.sleep(0.08)
            self.assertFalse(acquired.is_set())
            fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
            thread.join(1.0)

        holder.close()
        self.assertFalse(errors, errors)
        self.assertTrue(acquired.is_set())

    def test_source_lock_cleans_up_after_body_exception(self):
        lock_name = "self_mailbox_source_exception-test.lock"
        marker = self._direct_lock_factory_marker()
        with patch.object(source_lock, "_named_file_lock", marker), patch.object(
            source_lock, "_runtime_path", lambda *_parts: self.root / "locks"
        ):
            with self.assertRaisesRegex(RuntimeError, "body failure"):
                with source_lock._timed_source_file_lock(lock_name, 0.5):
                    raise RuntimeError("body failure")
            with source_lock._timed_source_file_lock(lock_name, 0.5):
                pass

    def test_import_queries_runtime_before_taking_source_flock(self):
        """Importer status may read the same pool lock without a lock cycle."""
        self._write_pool(["existing@example.com----existing-password"])

        def runtime_status(config):
            pool_path = Path(config["pool_path"])
            if not pool_path.is_absolute():
                pool_path = self.root / pool_path
            digest = hashlib.sha256(str(pool_path.resolve()).encode("utf-8")).hexdigest()[:16]
            with self.lock_factory(f"self_mailbox_source_{digest}.lock"):
                return {"running": False, "tasks": []}

        self.service.runtime_status = runtime_status
        with patch("mac_overrides.mailbox_source_lock._named_file_lock", self.lock_factory):
            result = self.service.import_mailboxes(
                "trilby.buskins_8l@example.test---https://mail.example.test/m/fake-token-one\n"
                "fugues.17.brut@example.test---https://mail.example.test/pickup?key=fake-token-two"
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["imported"], 2)


if __name__ == "__main__":
    unittest.main()
