from __future__ import annotations

import unittest

from mac_overrides.batch_identity import allocate_batch_id, batch_minute_key


class BatchIdentityTests(unittest.TestCase):
    def test_first_run_uses_local_minute(self):
        started_at = 1_755_000_123
        self.assertEqual(allocate_batch_id(started_at), batch_minute_key(started_at))

    def test_same_minute_runs_get_numeric_suffixes(self):
        started_at = 1_755_000_123
        base = batch_minute_key(started_at)
        existing = [base, f"{base}-02", f"{base}-04", "20200101-120000-abcdef"]

        self.assertEqual(allocate_batch_id(started_at, existing), f"{base}-03")

    def test_other_minutes_do_not_force_a_suffix(self):
        started_at = 1_755_000_123
        base = batch_minute_key(started_at)
        self.assertEqual(allocate_batch_id(started_at, [f"{base}-02", "20200101-1200"]), base)


if __name__ == "__main__":
    unittest.main()
