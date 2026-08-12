from __future__ import annotations

import threading
from types import SimpleNamespace
import unittest

from mac_overrides.current_run_append import append_imported_mailboxes


class _Priority:
    def __init__(self):
        self.consumed = []

    def consume(self, row):
        self.consumed.append(row)


class CurrentRunAppendTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            "one@example.test----password-one",
            "two@example.test----password-two",
        ]
        self.entries = [
            SimpleNamespace(source_row=row, line_no=index)
            for index, row in enumerate(self.rows, start=1)
        ]
        self.priority = _Priority()
        self.context = {"target": 3}
        self.released = []
        self.importer = SimpleNamespace(
            lock=threading.RLock(),
            running=True,
            _gptphone_append_accepting=True,
            _gptphone_append_entries=lambda entries: {
                "joined_current_batch": len(entries),
                "queued_current_batch": len(entries),
            },
            _gptphone_run_settings={"batch_id": "batch-current"},
            tasks={"existing": {}},
            _pool=lambda _settings: object(),
        )

    def _append(self, reserve=None):
        return append_imported_mailboxes(
            self.rows,
            importer=self.importer,
            row_id_from_source=lambda row: f"id:{row}",
            reserve_specific_available=reserve or (lambda _pool, _ids, **_kwargs: self.entries),
            release_owned_batch_leases=lambda *args, **kwargs: self.released.append((args, kwargs)),
            mailbox_error_type=RuntimeError,
            next_batch_priority=self.priority,
            notification_context_for=lambda _importer: self.context,
        )

    def test_active_batch_accepts_every_imported_row_and_updates_target(self):
        result = self._append()

        self.assertEqual(result["joined_current_batch"], 2)
        self.assertEqual(result["queued_current_batch"], 2)
        self.assertEqual(result["next_batch"], 0)
        self.assertEqual(self.priority.consumed, self.rows)
        self.assertEqual(self.context["target"], 5)

    def test_closed_batch_uses_next_batch_fallback_without_reserving(self):
        self.importer._gptphone_append_accepting = False
        reserve_calls = []

        result = self._append(lambda *_args, **_kwargs: reserve_calls.append(True))

        self.assertEqual(result["joined_current_batch"], 0)
        self.assertEqual(result["next_batch"], 2)
        self.assertEqual(result["append_node_code"], "current_batch_closed")
        self.assertEqual(result["append_node_label"], "追加当前运行批次")
        self.assertIn("已关闭", result["append_reason"])
        self.assertEqual(reserve_calls, [])
        self.assertEqual(self.priority.consumed, [])

    def test_idle_import_has_no_batch_assignment(self):
        self.importer.running = False
        reserve_calls = []

        result = self._append(lambda *_args, **_kwargs: reserve_calls.append(True))

        self.assertEqual(result, {
            "joined_current_batch": 0,
            "queued_current_batch": 0,
            "next_batch": 0,
        })
        self.assertEqual(reserve_calls, [])

    def test_relogin_batch_never_accepts_new_registration_mailboxes(self):
        self.importer._gptphone_run_settings["run_mode"] = "relogin"
        reserve_calls = []

        result = self._append(lambda *_args, **_kwargs: reserve_calls.append(True))

        self.assertEqual(result["joined_current_batch"], 0)
        self.assertEqual(result["next_batch"], 2)
        self.assertIn("重登批次", result["append_reason"])
        self.assertEqual(reserve_calls, [])

    def test_append_race_releases_exact_leases_and_keeps_next_batch_priority(self):
        self.importer._gptphone_append_entries = lambda _entries: (_ for _ in ()).throw(
            RuntimeError("current_batch_closed")
        )

        result = self._append()

        self.assertEqual(result["next_batch"], 2)
        self.assertEqual(self.priority.consumed, [])
        self.assertEqual(len(self.released), 1)
        args, kwargs = self.released[0]
        self.assertEqual(kwargs["reason"], "current_batch_append_failed")
        self.assertEqual(
            args[2],
            [
                {"row_id": f"id:{row}", "line_no": index}
                for index, row in enumerate(self.rows, start=1)
            ],
        )


if __name__ == "__main__":
    unittest.main()
