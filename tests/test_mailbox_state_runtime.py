from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest

from mac_overrides.mailbox_state_runtime import (
    MANUAL_UNAVAILABLE_REASON,
    human_mailbox_status,
    indexed_mailbox_state,
    index_mailbox_states,
    mark_mailboxes_unavailable,
    pool_count_status,
    public_mailbox_reason,
)


def row_id(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


class FakeMailboxAdmin:
    def __init__(self, root: Path, lines: list[str]) -> None:
        self.root = root
        self.lines = list(lines)
        self._lock = threading.RLock()
        self.logs = []
        self.validations = 0
        self.writes = 0
        self.now_fn = lambda: 1_234

    def _config(self):
        return {"state_path": "state.json"}

    def _read_pool_lines(self, _config):
        return list(self.lines)

    def _validate_pool(self):
        self.validations += 1
        return {"ok": True}

    def _path(self, _config, _name):
        return self.root / "state.json"

    @staticmethod
    def _read_json_file(path):
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_json_file(self, path, value):
        self.writes += 1
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def _log(self, message, level):
        self.logs.append((message, level))


class MailboxStateRuntimeTests(unittest.TestCase):
    def test_legacy_same_email_states_are_indexed_by_their_own_line(self):
        items = {
            "legacy-one": {
                "email": "shared@example.test",
                "line_no": 1,
                "status": "consumed",
            },
            "legacy-two": {
                "email": "shared@example.test",
                "line_no": 2,
                "status": "damaged",
            },
        }

        by_line, by_email_line, by_row_id = index_mailbox_states(items)

        first = indexed_mailbox_state(
            by_line,
            by_email_line,
            by_row_id,
            row_id=row_id("shared@example.test----password-one"),
            email="shared@example.test",
            line_no=1,
        )
        second = indexed_mailbox_state(
            by_line,
            by_email_line,
            by_row_id,
            row_id=row_id("shared@example.test----password-two"),
            email="shared@example.test",
            line_no=2,
        )

        self.assertEqual(first["status"], "consumed")
        self.assertEqual(second["status"], "damaged")

    def test_unavailable_updates_existing_and_creates_missing_state_without_touching_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = [
                "one@example.test----password-one",
                "two@example.test----password-two",
            ]
            pool_path = root / "pool.txt"
            pool_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            results_path = root / "result.json"
            results_path.write_text('{"status":"success"}', encoding="utf-8")
            (root / "state.json").write_text(
                json.dumps({
                    "items": {
                        "existing": {
                            "email": "one@example.test",
                            "line_no": 1,
                            "status": "available",
                            "history": [{"event": "restored", "at": 100}],
                        }
                    }
                }),
                encoding="utf-8",
            )
            admin = FakeMailboxAdmin(root, lines)

            result = mark_mailboxes_unavailable(admin, {
                "line_nos": [1, 2],
                "rows": [
                    {"row_id": row_id(source), "line_no": index}
                    for index, source in enumerate(lines, start=1)
                ],
            })

            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            first = state["items"]["existing"]
            second = state["items"][row_id(lines[1])]
            self.assertEqual(result, {"ok": True, "unavailable": 2})
            for item in (first, second):
                self.assertEqual(item["status"], "damaged")
                self.assertEqual(item["lease_until"], 0)
                self.assertEqual(item["reason"], MANUAL_UNAVAILABLE_REASON)
                self.assertEqual(item["updated_at"], 1234)
                self.assertEqual(item["history"][-1], {
                    "event": "damaged",
                    "reason": MANUAL_UNAVAILABLE_REASON,
                    "at": 1234,
                })
                self.assertEqual(pool_count_status(item, 1234), "damaged")
                self.assertEqual(human_mailbox_status(item, 1234), ("failed", "不可用"))
                self.assertEqual(public_mailbox_reason(item["reason"]), "")
            self.assertEqual(pool_path.read_text(encoding="utf-8"), "\n".join(lines) + "\n")
            self.assertEqual(results_path.read_text(encoding="utf-8"), '{"status":"success"}')
            self.assertEqual(admin.validations, 1)
            self.assertEqual(admin.logs, [("邮箱管理设置不可用: 2 条", "warn")])
            self.assertNotIn("example.test", str(admin.logs))
            self.assertNotIn("password", str(admin.logs))

    def test_duplicate_row_id_rejects_the_entire_selection_without_state_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["one@example.test----one", "two@example.test----two"]
            original_state = '{"items":{"one":{"status":"available"}}}'
            (root / "state.json").write_text(original_state, encoding="utf-8")
            admin = FakeMailboxAdmin(root, lines)

            result = mark_mailboxes_unavailable(admin, {
                "rows": [
                    {"row_id": row_id(lines[0]), "line_no": 1},
                    {"row_id": row_id(lines[0]), "line_no": 2},
                ]
            })

            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "mailbox_rows_invalid")
            self.assertEqual((root / "state.json").read_text(encoding="utf-8"), original_state)
            self.assertEqual(admin.writes, 0)
            self.assertEqual(admin.validations, 0)
            self.assertEqual(admin.logs, [])

    def test_stale_source_binding_rejects_the_entire_selection_without_state_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["one@example.test----one", "two@example.test----two"]
            original_state = '{"items":{"one":{"status":"available"}}}'
            (root / "state.json").write_text(original_state, encoding="utf-8")
            admin = FakeMailboxAdmin(root, lines)

            result = mark_mailboxes_unavailable(admin, {
                "rows": [
                    {"row_id": row_id(lines[0]), "line_no": 1},
                    {"row_id": row_id("old@example.test----old"), "line_no": 2},
                ]
            })

            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "mailbox_rows_stale")
            self.assertEqual((root / "state.json").read_text(encoding="utf-8"), original_state)
            self.assertEqual(admin.writes, 0)

    def test_stale_state_line_number_never_overwrites_another_mailbox(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["selected@example.test----selected-password"]
            (root / "state.json").write_text(
                json.dumps({
                    "items": {
                        "other": {
                            "email": "other@example.test",
                            "line_no": 1,
                            "status": "consumed",
                            "history": [{"event": "completed", "at": 10}],
                        }
                    }
                }),
                encoding="utf-8",
            )
            admin = FakeMailboxAdmin(root, lines)

            result = mark_mailboxes_unavailable(admin, {
                "rows": [{"row_id": row_id(lines[0]), "line_no": 1}],
            })

            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertTrue(result["ok"])
            self.assertEqual(state["items"]["other"]["email"], "other@example.test")
            self.assertEqual(state["items"]["other"]["status"], "consumed")
            self.assertEqual(state["items"]["other"]["history"], [{"event": "completed", "at": 10}])
            self.assertEqual(state["items"][row_id(lines[0])]["email"], "selected@example.test")

    def test_stale_same_email_lease_on_another_line_does_not_block_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["running@example.test----running", "idle@example.test----idle"]
            original_state = json.dumps({
                "items": {
                    row_id(lines[0]): {
                        "email": "running@example.test",
                        "line_no": 1,
                        "status": "available",
                    },
                    "running-history": {
                        "email": "running@example.test",
                        "line_no": 99,
                        "status": "leased",
                        "lease_until": 2000,
                    },
                    "idle": {
                        "email": "idle@example.test",
                        "line_no": 2,
                        "status": "available",
                    },
                }
            })
            (root / "state.json").write_text(original_state, encoding="utf-8")
            admin = FakeMailboxAdmin(root, lines)

            result = mark_mailboxes_unavailable(admin, {
                "rows": [
                    {"row_id": row_id(source), "line_no": index}
                    for index, source in enumerate(lines, start=1)
                ],
            })

            self.assertTrue(result["ok"])
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["items"][row_id(lines[0])]["status"], "damaged")
            self.assertEqual(state["items"]["idle"]["status"], "damaged")
            self.assertEqual(state["items"]["running-history"]["status"], "leased")
            self.assertEqual(state["items"]["running-history"]["line_no"], 99)

    def test_unavailable_only_changes_selected_credential_when_email_is_shared(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = [
                "shared@example.test----password-one",
                "shared@example.test----password-two",
            ]
            (root / "state.json").write_text(
                json.dumps({
                    "items": {
                        row_id(lines[0]): {
                            "email": "shared@example.test",
                            "line_no": 1,
                            "status": "available",
                        },
                        row_id(lines[1]): {
                            "email": "shared@example.test",
                            "line_no": 1,
                            "status": "consumed",
                        },
                    }
                }),
                encoding="utf-8",
            )
            admin = FakeMailboxAdmin(root, lines)

            result = mark_mailboxes_unavailable(admin, {
                "rows": [{"row_id": row_id(lines[0]), "line_no": 1}],
            })

            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(result, {"ok": True, "unavailable": 1})
            self.assertEqual(state["items"][row_id(lines[0])]["status"], "damaged")
            self.assertEqual(state["items"][row_id(lines[1])]["status"], "consumed")

    def test_active_exact_row_key_lease_rejects_even_with_stale_email_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["running@example.test----running"]
            original_state = json.dumps({
                "items": {
                    row_id(lines[0]): {
                        "email": "stale@example.test",
                        "line_no": 99,
                        "status": "leased",
                        "lease_until": 2000,
                    }
                }
            })
            (root / "state.json").write_text(original_state, encoding="utf-8")
            admin = FakeMailboxAdmin(root, lines)

            result = mark_mailboxes_unavailable(admin, {
                "rows": [{"row_id": row_id(lines[0]), "line_no": 1}],
            })

            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "mailbox_rows_running")
            self.assertEqual((root / "state.json").read_text(encoding="utf-8"), original_state)
            self.assertEqual(admin.writes, 0)

    def test_active_legacy_line_only_lease_rejects_the_entire_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["running@example.test----running"]
            original_state = json.dumps({
                "items": {
                    "legacy-line": {
                        "line_no": 1,
                        "status": "leased",
                        "lease_until": 2000,
                    }
                }
            })
            (root / "state.json").write_text(original_state, encoding="utf-8")
            admin = FakeMailboxAdmin(root, lines)

            result = mark_mailboxes_unavailable(admin, {
                "rows": [{"row_id": row_id(lines[0]), "line_no": 1}],
            })

            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "mailbox_rows_running")
            self.assertEqual((root / "state.json").read_text(encoding="utf-8"), original_state)
            self.assertEqual(admin.writes, 0)


if __name__ == "__main__":
    unittest.main()
