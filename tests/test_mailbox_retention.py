from __future__ import annotations

from dataclasses import dataclass
import unittest
from unittest.mock import patch

from mac_overrides.mailbox_retention import preserve_consumed_entry


@dataclass
class FakeEntry:
    key: str
    email: str
    line_no: int


class FakePool:
    def __init__(self) -> None:
        self.entries = [
            FakeEntry("row-one", "same@example.com", 1),
            FakeEntry("row-two", "same@example.com", 2),
        ]
        self.state = {"items": {}}
        self.pool_lines = ["first-secret-row", "second-secret-row"]

    def _update(self, callback):
        return callback(self.state, self.entries)

    @staticmethod
    def _item(state, entry):
        return state["items"].setdefault(
            entry.key,
            {"email": entry.email, "line_no": entry.line_no, "history": []},
        )

    @staticmethod
    def _history(item, event, reason=""):
        item["history"].append({"event": event, "reason": reason, "at": 1234})


class MailboxRetentionTests(unittest.TestCase):
    def test_success_marks_exact_row_consumed_without_removing_pool_line(self):
        pool = FakePool()

        with patch("mac_overrides.mailbox_retention.time.time", return_value=1234):
            changed = preserve_consumed_entry(
                pool,
                pool.entries[1],
                reason="sub2_uploaded",
            )

        self.assertTrue(changed)
        self.assertEqual(pool.pool_lines, ["first-secret-row", "second-secret-row"])
        self.assertNotIn("row-one", pool.state["items"])
        item = pool.state["items"]["row-two"]
        self.assertEqual(
            {key: item[key] for key in ("status", "lease_until", "reason", "updated_at")},
            {
                "status": "consumed",
                "lease_until": 0,
                "reason": "sub2_uploaded",
                "updated_at": 1234,
            },
        )
        self.assertEqual(
            item["history"][-1],
            {"event": "consumed", "reason": "sub2_uploaded", "at": 1234},
        )

    def test_missing_entry_is_left_unchanged(self):
        pool = FakePool()

        changed = preserve_consumed_entry(pool, FakeEntry("missing", "none@example.com", 3))

        self.assertFalse(changed)
        self.assertEqual(pool.state, {"items": {}})


if __name__ == "__main__":
    unittest.main()
