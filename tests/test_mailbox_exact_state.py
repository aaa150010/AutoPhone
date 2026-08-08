from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mac_overrides.mailbox_admin import MailboxAdminService, row_id_from_source


class _Store:
    def __init__(self, root: Path) -> None:
        self.data_dir = root

    def load(self):
        return {
            "pool_path": "pool.txt",
            "state_path": "state.json",
            "results_dir": "results",
        }


class MailboxExactStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.service = MailboxAdminService(
            _Store(self.root),
            validate_pool=lambda _config: {"ok": True},
            imap_poller_factory=lambda *_args, **_kwargs: None,
            now_fn=lambda: 1_000,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_pool(self, rows: list[str]) -> None:
        (self.root / "pool.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")

    def _write_state(self, items: dict) -> None:
        (self.root / "state.json").write_text(
            json.dumps({"items": items}, ensure_ascii=False),
            encoding="utf-8",
        )

    def _state_items(self) -> dict:
        return json.loads((self.root / "state.json").read_text(encoding="utf-8"))["items"]

    def test_restore_validates_binding_and_only_restores_selected_shared_email_row(self):
        rows = [
            "shared@example.com----password-one",
            "shared@example.com----password-two",
        ]
        first_id, second_id = (row_id_from_source(row) for row in rows)
        self._write_pool(rows)
        self._write_state({
            first_id: {"email": "shared@example.com", "line_no": 99, "status": "damaged"},
            "first-legacy": {"email": "shared@example.com", "line_no": 1, "status": "damaged"},
            second_id: {"email": "shared@example.com", "line_no": 1, "status": "damaged"},
            "second-legacy": {"email": "shared@example.com", "line_no": 2, "status": "damaged"},
        })

        stale = self.service.restore({
            "line_nos": [1],
            "rows": [{"row_id": row_id_from_source(rows[1]), "line_no": 1}],
        })
        self.assertEqual(stale["code"], "mailbox_rows_stale")
        self.assertEqual(self._state_items()[first_id]["status"], "damaged")

        result = self.service.restore({
            "line_nos": [1],
            "rows": [{"row_id": first_id, "line_no": 1}],
        })

        state = self._state_items()
        self.assertEqual(result, {"ok": True, "restored": 2})
        self.assertEqual(state[first_id]["status"], "available")
        self.assertEqual(state["first-legacy"]["reason"], "manual_restore")
        self.assertEqual(state[second_id]["status"], "damaged")
        self.assertEqual(state["second-legacy"]["status"], "damaged")

    def test_delete_removes_selected_exact_and_legacy_state_but_keeps_shared_email_row(self):
        rows = [
            "shared@example.com----password-one",
            "shared@example.com----password-two",
        ]
        first_id, second_id = (row_id_from_source(row) for row in rows)
        self._write_pool(rows)
        self._write_state({
            first_id: {"email": "shared@example.com", "line_no": 99, "status": "damaged"},
            "first-legacy": {"email": "shared@example.com", "line_no": 1, "status": "damaged"},
            second_id: {"email": "shared@example.com", "line_no": 1, "status": "consumed"},
            "second-legacy": {"email": "shared@example.com", "line_no": 2, "status": "consumed"},
        })

        result = self.service.delete({
            "line_nos": [1],
            "rows": [{"row_id": first_id, "line_no": 1}],
        })

        state = self._state_items()
        self.assertEqual(result, {"ok": True, "deleted": 1})
        self.assertEqual(
            (self.root / "pool.txt").read_text(encoding="utf-8").splitlines(),
            [rows[1]],
        )
        self.assertNotIn(first_id, state)
        self.assertNotIn("first-legacy", state)
        self.assertEqual(state[second_id]["line_no"], 1)
        self.assertEqual(state[second_id]["status"], "consumed")
        self.assertEqual(state["second-legacy"]["line_no"], 1)

    def test_list_does_not_display_another_shared_email_rows_state(self):
        rows = [
            "shared@example.com----password-one",
            "shared@example.com----password-two",
        ]
        self._write_pool(rows)
        self._write_state({
            "second": {"email": "shared@example.com", "line_no": 2, "status": "damaged"},
        })

        listed = self.service.list_mailboxes()["rows"]

        self.assertEqual([row["status"] for row in listed], ["available", "failed"])

    def test_openai_test_only_applies_manual_restore_to_matching_shared_email_line(self):
        rows = [
            "shared@example.com----password-one----client-one----refresh-one",
            "shared@example.com----password-two----client-two----refresh-two",
        ]
        self._write_pool(rows)
        self._write_state({
            "second": {
                "email": "shared@example.com",
                "line_no": 2,
                "status": "available",
                "reason": "manual_restore",
            },
        })
        results_dir = self.root / "results"
        results_dir.mkdir()
        (results_dir / "success.json").write_text(
            json.dumps({
                "email": "shared@example.com",
                "status": "success",
                "created_at": 1,
                "result": {
                    "access_token": "private-access-token",
                    "chatgpt_account_id": "account-id",
                },
            }),
            encoding="utf-8",
        )
        captured = []
        self.service.openai_direct_batch_tester = lambda selected, _proxy: (
            captured.extend(selected)
            or {"ok": True, "tested": 2, "results": []}
        )

        result = self.service.openai_test({
            "rows": [
                {"row_id": row_id_from_source(row), "line_no": line_no}
                for line_no, row in enumerate(rows, start=1)
            ],
        })

        self.assertTrue(result["ok"])
        self.assertTrue(captured[0]["document"])
        self.assertEqual(captured[0]["openai_status_id"], "account-id")
        self.assertEqual(captured[1]["document"], {})
        self.assertEqual(captured[1]["openai_status_id"], "")


if __name__ == "__main__":
    unittest.main()
