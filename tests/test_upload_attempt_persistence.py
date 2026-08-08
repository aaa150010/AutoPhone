from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mac_overrides.nv_runtime import NvUploadQueue
from mac_overrides.pixel_runtime import PixelUploadQueue
from tests.test_pixel_runtime import FakePixelClient


def _success_document(task_id: str = "T001") -> dict:
    return {
        "task_id": task_id,
        "batch_id": "batch-upload-attempt",
        "batch_started_at": 1_786_000_000,
        "status": "success",
        "result": {
            "email": "attempt@example.test",
            "access_token": "private-access-token",
            "refresh_token": "private-refresh-token",
            "id_token": "private.id.token",
        },
    }


def _write_result(root: Path) -> Path:
    path = root / "results" / "result.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_success_document()), encoding="utf-8")
    return path


class _ConfirmingNvClient:
    def upload(self, cards):
        return {"accepted": len(cards)}


class UploadAttemptPersistenceTests(unittest.TestCase):
    def test_pixel_attempt_is_persisted_and_retry_updates_same_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result_file = _write_result(root)
            queue = PixelUploadQueue(
                root,
                client=FakePixelClient(),
                target_ids=("pixel-2",),
                auto_start=False,
            )

            queued = queue.enqueue_batch(
                "batch-upload-attempt",
                [("T001", result_file)],
                upload_attempt_id="upload-pixel-initial",
            )[0]
            self.assertEqual(queued["upload_attempt_id"], "upload-pixel-initial")
            stored = json.loads(queue.outbox_path.read_text(encoding="utf-8"))["records"][0]
            self.assertEqual(stored["upload_attempt_id"], "upload-pixel-initial")

            with queue._lock:
                record = queue._store["records"][0]
                record["status"] = "failed"
                record["targets"]["pixel-2"].update(
                    state="import_failed",
                    stage="import",
                    retry_requested=False,
                )
                queue._save_locked()
            retried = queue.retry(
                queued["record_id"],
                ["pixel-2"],
                upload_attempt_id="upload-pixel-retry",
            )

            self.assertEqual(retried["record_id"], queued["record_id"])
            self.assertEqual(retried["upload_attempt_id"], "upload-pixel-retry")
            stored = json.loads(queue.outbox_path.read_text(encoding="utf-8"))["records"][0]
            self.assertEqual(stored["upload_attempt_id"], "upload-pixel-retry")

    def test_pixel_confirmed_log_is_emitted_only_after_remote_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result_file = _write_result(root)
            logs = []
            queue = PixelUploadQueue(
                root,
                client=FakePixelClient(),
                target_ids=("pixel-2",),
                auto_start=False,
                log_fn=lambda message, level: logs.append((message, level)),
            )
            queue.enqueue_batch(
                "batch-upload-attempt",
                [("T001", result_file)],
                upload_attempt_id="upload-pixel-confirmed",
            )

            self.assertEqual(logs, [])
            self.assertTrue(queue.process_next())
            self.assertEqual(logs[-1][1], "success")
            self.assertIn("pixel_upload_confirmed", logs[-1][0])
            self.assertIn("upload-pixel-confirmed", logs[-1][0])

    def test_nv_attempt_is_persisted_inherited_and_logged_after_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result_file = _write_result(root)
            logs = []
            queue = NvUploadQueue(
                root,
                _ConfirmingNvClient(),
                auto_start=False,
                log_fn=lambda message, level: logs.append((message, level)),
            )
            queued = queue.enqueue_batch(
                "batch-upload-attempt",
                [("T001", result_file)],
                upload_attempt_id="upload-nv-initial",
            )[0]

            self.assertEqual(queued["upload_attempt_id"], "upload-nv-initial")
            self.assertEqual(logs, [])
            self.assertTrue(queue.process_next())
            self.assertEqual(logs[-1][1], "success")
            self.assertIn("nv_upload_confirmed", logs[-1][0])
            self.assertIn("upload-nv-initial", logs[-1][0])

            with queue._lock:
                record = queue._store["records"][0]
                record.update(status="failed", accepted=0, needs_confirmation=False)
                queue._save_locked()
            retried = queue.retry(queued["record_id"])
            self.assertEqual(retried["upload_attempt_id"], "upload-nv-initial")
            stored = json.loads(queue.outbox_path.read_text(encoding="utf-8"))["records"][0]
            self.assertEqual(stored["upload_attempt_id"], "upload-nv-initial")


if __name__ == "__main__":
    unittest.main()
