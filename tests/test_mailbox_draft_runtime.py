from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest

from mac_overrides.mailbox_admin import MailboxAdminService
from mac_overrides.mailbox_state_runtime import (
    MANUAL_DRAFT_REASON,
    MANUAL_SMS_CONSUMED_REASON,
    MANUAL_UNAVAILABLE_REASON,
    human_mailbox_status,
    mark_mailboxes_draft,
    mark_mailboxes_manual_used,
    pool_count_status,
    public_mailbox_reason,
    restore_draft_mailboxes,
    restore_manual_used_mailboxes,
)


def row_id(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


class FakeStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir

    def load(self):
        return {
            "pool_path": "pool.txt",
            "state_path": "state.json",
            "results_dir": "results",
        }


class FakeMailboxAdmin:
    def __init__(self, root: Path, lines: list[str]) -> None:
        self.root = root
        self.lines = list(lines)
        self._lock = threading.RLock()
        self.logs: list[tuple[str, str]] = []
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


class MailboxDraftRuntimeTests(unittest.TestCase):
    def test_manual_draft_has_distinct_public_status_and_hidden_reason(self):
        item = {"status": "damaged", "reason": MANUAL_DRAFT_REASON}

        self.assertEqual(pool_count_status(item, 1234), "draft")
        self.assertEqual(human_mailbox_status(item, 1234), ("draft", "草稿"))
        self.assertEqual(public_mailbox_reason(MANUAL_DRAFT_REASON), "")

    def test_list_mailboxes_exposes_draft_without_counting_it_available_or_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = [
                "draft@example.test----draft-password",
                "ready@example.test----ready-password",
            ]
            (root / "pool.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            (root / "state.json").write_text(
                json.dumps({
                    "items": {
                        row_id(lines[0]): {
                            "email": "draft@example.test",
                            "line_no": 1,
                            "status": "damaged",
                            "reason": MANUAL_DRAFT_REASON,
                        }
                    }
                }),
                encoding="utf-8",
            )
            service = MailboxAdminService(
                FakeStore(root),
                validate_pool=lambda _config: {"ok": True},
                imap_poller_factory=lambda *_args, **_kwargs: None,
                now_fn=lambda: 1234,
            )

            result = service.list_mailboxes()

            self.assertEqual(result["counts"], {
                "total": 2,
                "available": 1,
                "running": 0,
                "success": 0,
                "failed": 0,
                "draft": 1,
            })
            self.assertEqual(
                [(row["status"], row["status_label"]) for row in result["rows"]],
                [("draft", "草稿"), ("available", "可用")],
            )
            self.assertEqual(result["rows"][0]["reason"], "")
            self.assertNotIn("draft-password", json.dumps(result, ensure_ascii=False))

    def test_draft_and_restore_preserve_sources_and_use_stable_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = [
                "one@example.test----password-one",
                "two@example.test----password-two",
            ]
            pool_path = root / "pool.txt"
            pool_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result_path = root / "result.json"
            result_path.write_text('{"status":"success"}', encoding="utf-8")
            (root / "state.json").write_text(
                json.dumps({
                    "items": {
                        "existing": {
                            "email": "one@example.test",
                            "line_no": 1,
                            "status": "available",
                            "history": [],
                        }
                    }
                }),
                encoding="utf-8",
            )
            admin = FakeMailboxAdmin(root, lines)
            bindings = [
                {"row_id": row_id(source), "line_no": index}
                for index, source in enumerate(lines, start=1)
            ]

            drafted = mark_mailboxes_draft(admin, {"rows": bindings})
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))

            self.assertEqual(drafted, {"ok": True, "drafted": 2})
            for item in (state["items"]["existing"], state["items"][row_id(lines[1])]):
                self.assertEqual(item["status"], "damaged")
                self.assertEqual(item["reason"], MANUAL_DRAFT_REASON)
                self.assertEqual(item["history"][-1]["event"], "drafted")

            restored = restore_draft_mailboxes(admin, {"rows": [bindings[0]]})
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))

            self.assertEqual(restored, {"ok": True, "restored": 1})
            self.assertEqual(state["items"]["existing"]["status"], "available")
            self.assertEqual(state["items"]["existing"]["reason"], "manual_restore")
            self.assertEqual(pool_count_status(state["items"][row_id(lines[1])], 1234), "draft")
            self.assertEqual(pool_path.read_text(encoding="utf-8"), "\n".join(lines) + "\n")
            self.assertEqual(result_path.read_text(encoding="utf-8"), '{"status":"success"}')
            self.assertEqual(admin.logs, [
                ("邮箱管理放入草稿箱: 2 条", "info"),
                ("邮箱管理草稿放回可用: 1 条", "success"),
            ])
            self.assertNotIn("example.test", str(admin.logs))
            self.assertNotIn("password", str(admin.logs))

    def test_draft_rejects_non_available_rows_without_partial_write(self):
        cases = (
            ({"status": "consumed"}, "mailbox_rows_not_available"),
            ({"status": "damaged", "reason": MANUAL_UNAVAILABLE_REASON}, "mailbox_rows_not_available"),
            ({"status": "leased", "lease_until": 2000}, "mailbox_rows_running"),
        )
        for state_item, expected_code in cases:
            with self.subTest(expected_code=expected_code), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                lines = ["one@example.test----one", "two@example.test----two"]
                state = {
                    "items": {
                        row_id(lines[0]): {
                            "email": "one@example.test",
                            "line_no": 1,
                            "status": "available",
                        },
                        row_id(lines[1]): {
                            "email": "two@example.test",
                            "line_no": 2,
                            **state_item,
                        },
                    }
                }
                original_state = json.dumps(state)
                (root / "state.json").write_text(original_state, encoding="utf-8")
                admin = FakeMailboxAdmin(root, lines)

                result = mark_mailboxes_draft(admin, {
                    "rows": [
                        {"row_id": row_id(source), "line_no": index}
                        for index, source in enumerate(lines, start=1)
                    ]
                })

                self.assertFalse(result["ok"])
                self.assertEqual(result["code"], expected_code)
                self.assertEqual((root / "state.json").read_text(encoding="utf-8"), original_state)
                self.assertEqual(admin.writes, 0)

    def test_restore_rejects_rows_that_are_no_longer_drafts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["one@example.test----one", "two@example.test----two"]
            original_state = json.dumps({
                "items": {
                    row_id(lines[0]): {
                        "email": "one@example.test",
                        "line_no": 1,
                        "status": "damaged",
                        "reason": MANUAL_DRAFT_REASON,
                    },
                    row_id(lines[1]): {
                        "email": "two@example.test",
                        "line_no": 2,
                        "status": "consumed",
                    },
                }
            })
            (root / "state.json").write_text(original_state, encoding="utf-8")
            admin = FakeMailboxAdmin(root, lines)

            result = restore_draft_mailboxes(admin, {
                "rows": [
                    {"row_id": row_id(source), "line_no": index}
                    for index, source in enumerate(lines, start=1)
                ]
            })

            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "mailbox_rows_not_draft")
            self.assertEqual((root / "state.json").read_text(encoding="utf-8"), original_state)
            self.assertEqual(admin.writes, 0)

    def test_restore_ignores_stale_alias_when_exact_row_is_still_a_draft(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["one@example.test----one"]
            exact = row_id(lines[0])
            original = {
                "items": {
                    exact: {
                        "email": "one@example.test",
                        "line_no": 1,
                        "status": "damaged",
                        "reason": MANUAL_DRAFT_REASON,
                    },
                    "stale-identity": {
                        "email": "one@example.test",
                        "line_no": 1,
                        "status": "available",
                        "reason": "stopped",
                    },
                }
            }
            (root / "state.json").write_text(json.dumps(original), encoding="utf-8")
            admin = FakeMailboxAdmin(root, lines)

            result = restore_draft_mailboxes(admin, {
                "rows": [{"row_id": exact, "line_no": 1}],
            })

            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(result, {"ok": True, "restored": 1})
            self.assertEqual(state["items"][exact]["status"], "available")
            self.assertEqual(state["items"][exact]["reason"], "manual_restore")
            self.assertEqual(state["items"]["stale-identity"]["status"], "available")

    def test_manual_sms_marker_can_be_toggled_without_changing_source_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["one@example.test----one"]
            (root / "pool.txt").write_text(lines[0] + "\n", encoding="utf-8")
            (root / "state.json").write_text(
                json.dumps({"items": {}}),
                encoding="utf-8",
            )
            admin = FakeMailboxAdmin(root, lines)
            binding = {"row_id": row_id(lines[0]), "line_no": 1}

            used = mark_mailboxes_manual_used(admin, {"rows": [binding]})
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            item = state["items"][row_id(lines[0])]
            self.assertEqual(used, {"ok": True, "used": 1})
            self.assertEqual(item["status"], "consumed")
            self.assertEqual(item["reason"], MANUAL_SMS_CONSUMED_REASON)
            self.assertEqual(item["history"][-1]["event"], "manual_sms_received")

            unused = restore_manual_used_mailboxes(admin, {"rows": [binding]})
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            item = state["items"][row_id(lines[0])]
            self.assertEqual(unused, {"ok": True, "restored": 1})
            self.assertEqual(item["status"], "available")
            self.assertEqual(item["reason"], "manual_restore")
            self.assertEqual(item["history"][-1]["event"], "manual_unused")
            self.assertEqual((root / "pool.txt").read_text(encoding="utf-8"), lines[0] + "\n")

    def test_manual_unused_does_not_undo_a_real_consumed_account(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = ["one@example.test----one"]
            (root / "state.json").write_text(
                json.dumps({"items": {row_id(lines[0]): {
                    "email": "one@example.test",
                    "line_no": 1,
                    "status": "consumed",
                    "reason": "sub2_uploaded",
                }}}),
                encoding="utf-8",
            )
            admin = FakeMailboxAdmin(root, lines)

            result = restore_manual_used_mailboxes(admin, {
                "rows": [{"row_id": row_id(lines[0]), "line_no": 1}],
            })

            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "mailbox_rows_not_manual_used")
            self.assertEqual(admin.writes, 0)


if __name__ == "__main__":
    unittest.main()
