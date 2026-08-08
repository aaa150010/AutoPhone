from __future__ import annotations

import unittest

from mac_overrides.pixel_batch_summary import build_pixel_batch_summary


class PixelBatchSummaryTests(unittest.TestCase):
    def test_weights_sources_and_preserves_confirmation_accounting(self) -> None:
        summary = build_pixel_batch_summary(
            "batch-1",
            [
                {
                    "source_count": 2,
                    "batch_started_at": 10,
                    "updated_at": 20,
                    "targets": {
                        "pixel-2": {"state": "success"},
                        "pixel-3": {"state": "success"},
                    },
                },
                {
                    "source_count": 3,
                    "created_at": 11,
                    "updated_at": 30,
                    "targets": {
                        "pixel-2": {"state": "success"},
                        "pixel-3": {"state": "needs_confirmation"},
                    },
                },
            ],
            ("pixel-2", "pixel-3"),
        )

        self.assertEqual(summary["status"], "partial")
        self.assertEqual(
            summary["source"],
            {
                "total": 5,
                "completed": 5,
                "success": 2,
                "pending": 0,
                "processing": 0,
                "failed": 3,
                "needs_confirmation": 3,
            },
        )
        self.assertEqual(summary["deliveries"]["success"], 7)
        self.assertEqual(summary["deliveries"]["needs_confirmation"], 3)
        self.assertEqual(summary["deliveries"]["completed"], 10)
        self.assertEqual(summary["batch_started_at"], 11)
        self.assertEqual(summary["updated_at"], 30)

    def test_missing_or_retry_requested_target_remains_pending(self) -> None:
        summary = build_pixel_batch_summary(
            "batch-2",
            [
                {
                    "targets": {
                        "pixel-2": {"state": "share_failed", "retry_requested": True},
                    }
                }
            ],
            ("pixel-2", "pixel-3"),
        )

        self.assertEqual(summary["status"], "processing")
        self.assertEqual(summary["source"]["pending"], 1)
        self.assertEqual(summary["deliveries"]["pending"], 2)

    def test_empty_batch_has_empty_status(self) -> None:
        summary = build_pixel_batch_summary("batch-empty", [], ("pixel-2",))

        self.assertEqual(summary["status"], "empty")
        self.assertEqual(summary["source"]["total"], 0)
        self.assertEqual(summary["deliveries"]["total"], 0)


if __name__ == "__main__":
    unittest.main()
