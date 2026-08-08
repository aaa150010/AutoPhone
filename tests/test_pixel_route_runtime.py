import unittest
from dataclasses import replace

from mac_overrides.pixel_route_runtime import (
    PixelBatchRetryError,
    batch_retry_failure,
    retry_batch_targets,
    target_ids_from,
)


class FakeQueue:
    def __init__(self):
        self.retries = []

    def batch_records(self, batch_id, *, page, page_size, status):
        records = {
            1: [
                {
                    "record_id": "record-a",
                    "targets": [
                        {"target_id": "pixel-2", "retryable": True},
                        {"target_id": "pixel-3", "retryable": False},
                    ],
                }
            ],
            2: [
                {
                    "record_id": "record-b",
                    "targets": {
                        "pixel-2": {"retryable": True},
                        "pixel-3": {"retryable": True},
                    },
                }
            ],
        }
        return {"items": records[page], "page": page, "pages": 2}

    def retry(self, record_id, target_ids):
        self.retries.append((record_id, list(target_ids)))


class AttemptQueue(FakeQueue):
    def __init__(self, outcomes=None):
        super().__init__()
        self.outcomes = list(outcomes or [])
        self.attempts = []

    def retry(self, record_id, target_ids, *, upload_attempt_id):
        self.retries.append((record_id, list(target_ids)))
        self.attempts.append(upload_attempt_id)
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome


class PixelRouteRuntimeTests(unittest.TestCase):
    def test_target_ids_accepts_camel_and_snake_case_without_duplicates(self):
        self.assertEqual(target_ids_from({"targetId": "pixel-2"}), ["pixel-2"])
        self.assertEqual(
            target_ids_from({"target_ids": ["pixel-2", "pixel-2", "pixel-3"]}),
            ["pixel-2", "pixel-3"],
        )

    def test_batch_retry_covers_all_pages_and_only_retryable_selected_target(self):
        queue = FakeQueue()
        logs = []
        result = retry_batch_targets(
            queue,
            "batch-a",
            ["pixel-2"],
            allowed_targets=["pixel-2", "pixel-3"],
            log_fn=lambda message, level: logs.append((message, level)),
        )
        self.assertEqual(
            queue.retries,
            [("record-a", ["pixel-2"]), ("record-b", ["pixel-2"])],
        )
        self.assertEqual(result["queued_records"], 2)
        self.assertEqual(result["queued_deliveries"], 2)
        self.assertEqual((result["accepted"], result["skipped"], result["failed"]), (2, 0, 0))
        self.assertEqual(result["batch_id"], "batch-a")
        self.assertTrue(result["upload_attempt_id"].startswith("upload-"))
        self.assertEqual(logs[0][1], "info")
        self.assertIn("Pixel 批量重传入队", logs[0][0])
        self.assertIn("仅表示已入队，远端结果尚未确认", logs[0][0])
        self.assertNotIn("上传确认", logs[0][0])

    def test_batch_retry_uses_one_attempt_id_and_reports_partial_failures(self):
        queue = AttemptQueue([
            None,
            RuntimeError(
                "access_token=private-value password=hunter2 "
                "user@example.test +8613800138000 https://oauth.test/callback?code=private"
            ),
        ])
        logs = []

        result = retry_batch_targets(
            queue,
            "batch-original",
            ["pixel-2"],
            allowed_targets=["pixel-2", "pixel-3"],
            log_fn=lambda message, level: logs.append((message, level)),
        )

        self.assertEqual(result["batch_id"], "batch-original")
        self.assertEqual(len(set(queue.attempts)), 1)
        self.assertEqual(queue.attempts[0], result["upload_attempt_id"])
        self.assertEqual((result["accepted"], result["skipped"], result["failed"]), (1, 0, 1))
        self.assertEqual((result["queued_records"], result["queued_deliveries"]), (1, 1))
        self.assertEqual(result["failed_records"], 1)
        self.assertNotIn("private-value", str(result))
        self.assertNotIn("hunter2", str(result))
        self.assertNotIn("user@example.test", str(result))
        self.assertNotIn("13800138000", str(result))
        self.assertNotIn("code=private", str(result))
        self.assertIn("accepted=1", logs[0][0])
        self.assertEqual(logs[0][1], "error")

    def test_batch_retry_finishes_preflight_before_any_queue_mutation(self):
        class BrokenPreflightQueue(AttemptQueue):
            def batch_records(self, batch_id, *, page, page_size, status):
                if page == 2:
                    raise RuntimeError("preflight failed")
                return super().batch_records(batch_id, page=page, page_size=page_size, status=status)

        queue = BrokenPreflightQueue()
        with self.assertRaisesRegex(RuntimeError, "preflight failed"):
            retry_batch_targets(
                queue,
                "batch-a",
                ["pixel-2"],
                allowed_targets=["pixel-2"],
            )
        self.assertEqual(queue.retries, [])

    def test_all_failed_retry_returns_attempt_and_structured_counts(self):
        queue = AttemptQueue([RuntimeError("first failed"), RuntimeError("second failed")])
        with self.assertRaises(PixelBatchRetryError) as raised:
            retry_batch_targets(
                queue,
                "batch-failed",
                ["pixel-2"],
                allowed_targets=["pixel-2"],
            )

        payload, status = batch_retry_failure(raised.exception)
        self.assertEqual(status, 502)
        self.assertEqual(payload["batch_id"], "batch-failed")
        self.assertTrue(payload["upload_attempt_id"].startswith("upload-"))
        self.assertEqual((payload["accepted"], payload["skipped"], payload["failed"]), (0, 0, 2))
        self.assertEqual(payload["failed_records"], 2)
        self.assertEqual(len(payload["failures"]), 2)

    def test_invalid_target_and_empty_retry_use_stable_redacted_failure(self):
        queue = FakeQueue()
        with self.assertRaises(PixelBatchRetryError) as raised:
            retry_batch_targets(queue, "batch-a", ["pixel-8"], allowed_targets=["pixel-2"])
        payload, status = batch_retry_failure(raised.exception)
        self.assertEqual(status, 400)
        self.assertEqual(payload["node_code"], "pixel_enqueue")
        self.assertEqual(payload["code"], "pixel_target_invalid")
        self.assertNotIn("token", str(payload).lower())

    def test_flask_route_batches_the_selected_target(self):
        from tests import test_web_routes as fixtures

        class RouteQueue(fixtures.FakePixelQueue):
            def batch_records(self, batch_id, *, page, page_size, status):
                return {
                    "items": [{
                        "record_id": "record-route",
                        "targets": [{"target_id": "pixel-2", "retryable": True}],
                    }],
                    "pages": 1,
                }

        case = fixtures.WebRouteTests()
        case.setUp()
        try:
            queue = RouteQueue()
            app = case._app(replace(case.context, pixel_upload_queue=queue))
            with app.test_client() as client:
                response = client.post(
                    "/api/pixel/upload-batches/batch-a/retry",
                    json={"target_id": "pixel-2"},
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["queued_records"], 1)
            self.assertIn(("record-route", ["pixel-2"]), queue.calls)
        finally:
            case.tearDown()


if __name__ == "__main__":
    unittest.main()
