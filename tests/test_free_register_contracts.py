from __future__ import annotations

import unittest

from mac_overrides.free_register.contracts import FreeTaskSnapshot


class FreeTaskSnapshotContractTests(unittest.TestCase):
    def test_malformed_numeric_fields_degrade_to_zero(self) -> None:
        snapshot = FreeTaskSnapshot.from_mapping(
            {
                "task_id": "malformed-snapshot",
                "revision": "not-a-number",
                "retry_attempt": float("nan"),
            }
        )

        self.assertEqual(snapshot.revision, 0)
        self.assertEqual(snapshot.attempt, 0)

    def test_negative_numeric_fields_are_clamped(self) -> None:
        snapshot = FreeTaskSnapshot.from_mapping(
            {
                "task_id": "negative-snapshot",
                "revision": -4,
                "attempt": "-2",
            }
        )

        self.assertEqual(snapshot.revision, 0)
        self.assertEqual(snapshot.attempt, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
