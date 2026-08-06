from __future__ import annotations

import threading
from types import SimpleNamespace
import unittest

from mac_overrides.log_retention import GuiLogRetention


class GuiLogRetentionTests(unittest.TestCase):
    def test_logs_older_than_two_days_are_pruned_on_periodic_check(self):
        clock = [1_000_000.0]
        retention = GuiLogRetention(now_fn=lambda: clock[0])
        target = SimpleNamespace(lock=threading.Lock(), items=[])

        retention.add(target, "first", "info", max_items=240)
        clock[0] += 2 * 24 * 60 * 60 - 1
        self.assertEqual([row["message"] for row in retention.snapshot(target)], ["first"])

        clock[0] += 2
        self.assertEqual(retention.snapshot(target), [])

    def test_count_limit_and_legacy_rows_are_preserved(self):
        clock = [2_000_000.0]
        retention = GuiLogRetention(now_fn=lambda: clock[0])
        target = SimpleNamespace(
            lock=threading.Lock(),
            items=[{"time": "10:00:00", "level": "info", "message": "legacy"}],
        )

        for index in range(4):
            retention.add(target, f"row-{index}", max_items=3)

        rows = retention.snapshot(target)
        self.assertEqual([row["message"] for row in rows], ["row-1", "row-2", "row-3"])
        self.assertTrue(all(row.get("created_at") for row in rows))


if __name__ == "__main__":
    unittest.main()
