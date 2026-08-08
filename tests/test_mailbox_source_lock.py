from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
