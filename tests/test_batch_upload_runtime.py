from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from mac_overrides.batch_upload_runtime import BatchUploadCoordinator


class FakeQueue:
    def __init__(self, failures=0):
        self.calls = []
        self.failures = failures

    def enqueue_batch(self, batch_id, sources, **kwargs):
        rows = [dict(item) for item in sources]
        self.calls.append((batch_id, rows, dict(kwargs)))
        if self.failures:
            self.failures -= 1
            raise RuntimeError("safe queue failure")
        return [{"record_id": f"record-{len(self.calls)}"}]


class PartialQueue(FakeQueue):
    def enqueue_batch(self, batch_id, sources, **kwargs):
        rows = [dict(item) for item in sources]
        self.calls.append((batch_id, rows, dict(kwargs)))
        return {"accepted": 1, "skipped": 1, "failed": 1}


class RecordListQueue(FakeQueue):
    def __init__(self, records):
        super().__init__()
        self.records = records

    def enqueue_batch(self, batch_id, sources, **kwargs):
        rows = [dict(item) for item in sources]
        self.calls.append((batch_id, rows, dict(kwargs)))
        return [dict(item) for item in self.records]


class LegacyPixelQueue:
    def __init__(self):
        self.calls = []

    def enqueue_batch(self, batch_id, sources):
        self.calls.append((batch_id, [dict(item) for item in sources]))
        return [{"record_id": "legacy-record"}]


class FakeImporter:
    def status(self, _settings):
        return {"running": False}


class SequencedImporter:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)

    def status(self, _settings):
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def result_document(task_id: str, batch_id: str, status: str) -> dict:
    return {
        "task_id": task_id,
        "batch_id": batch_id,
        "batch_started_at": 100,
        "status": status,
        "result": {
            "email": f"{task_id.lower()}@example.test",
            "access_token": f"private-access-{task_id}",
            "refresh_token": f"private-refresh-{task_id}",
            "id_token": f"private-id-{task_id}",
        },
    }


class BatchUploadCoordinatorTests(unittest.TestCase):
    def test_waits_for_batch_terminal_then_queues_only_successful_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-1"
            for task_id, status in (("T001", "success"), ("T002", "failed"), ("T003", "success")):
                (results / f"{task_id}.json").write_text(
                    json.dumps(result_document(task_id, batch_id, status)),
                    encoding="utf-8",
                )
            pixel = FakeQueue()
            nv = FakeQueue()
            logs = []
            coordinator = BatchUploadCoordinator(
                root,
                pixel_queue=pixel,
                nv_queue=nv,
                recover_pending=False,
                log_fn=lambda message, level: logs.append((message, level)),
            )

            coordinator.begin(FakeImporter(), {
                "batch_id": batch_id,
                "batch_started_at": 100,
                "results_dir": results,
                "_gptphone_upload_targets": {"pixel": True, "nv": True},
            })
            deadline = time.time() + 2
            while time.time() < deadline and coordinator.records()[0]["status"] != "complete":
                time.sleep(0.01)

            manifest = coordinator.records()[0]
            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(manifest["source_count"], 2)
            self.assertEqual([item["task_id"] for item in pixel.calls[0][1]], ["T001", "T003"])
            self.assertEqual([item["task_id"] for item in nv.calls[0][1]], ["T001", "T003"])
            pixel_attempt = manifest["platforms"]["pixel"]["upload_attempt_id"]
            nv_attempt = manifest["platforms"]["nv"]["upload_attempt_id"]
            self.assertTrue(pixel_attempt.startswith("upload-"))
            self.assertTrue(nv_attempt.startswith("upload-"))
            self.assertEqual(pixel.calls[0][2]["upload_attempt_id"], pixel_attempt)
            self.assertEqual(nv.calls[0][2]["upload_attempt_id"], nv_attempt)
            self.assertEqual(manifest["platforms"]["pixel"]["accepted"], 2)
            self.assertEqual(len(manifest["platforms"]["pixel"]["attempt_history"]), 1)
            self.assertEqual([level for _message, level in logs], ["info", "info"])
            self.assertTrue(all("仅表示已入队，远端结果尚未确认" in message for message, _level in logs))
            self.assertTrue(all("上传确认" not in message for message, _level in logs))
            persisted = coordinator.manifest_path.read_text(encoding="utf-8")
            self.assertNotIn("private-access", persisted)
            self.assertNotIn("private-refresh", persisted)

    def test_zero_success_completes_without_calling_uploaders(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-empty"
            (results / "failed.json").write_text(
                json.dumps(result_document("T001", batch_id, "failed")),
                encoding="utf-8",
            )
            pixel = FakeQueue()
            nv = FakeQueue()
            coordinator = BatchUploadCoordinator(
                root,
                pixel_queue=pixel,
                nv_queue=nv,
                recover_pending=False,
            )
            coordinator.begin(FakeImporter(), {
                "batch_id": batch_id,
                "results_dir": results,
                "_gptphone_upload_targets": {"pixel": True, "nv": True},
            })
            deadline = time.time() + 2
            while time.time() < deadline and coordinator.records()[0]["status"] != "complete":
                time.sleep(0.01)
            self.assertEqual(coordinator.records()[0]["source_count"], 0)
            self.assertEqual(pixel.calls, [])
            self.assertEqual(nv.calls, [])

    def test_pixel_queue_without_upload_attempt_keyword_remains_compatible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-legacy-signature"
            (results / "success.json").write_text(
                json.dumps(result_document("T001", batch_id, "success")),
                encoding="utf-8",
            )
            pixel = LegacyPixelQueue()
            coordinator = BatchUploadCoordinator(
                root,
                pixel_queue=pixel,
                recover_pending=False,
            )

            coordinator.begin(FakeImporter(), {
                "batch_id": batch_id,
                "results_dir": results,
                "_gptphone_upload_targets": {"pixel": True, "nv": False},
            })
            deadline = time.time() + 2
            while time.time() < deadline and coordinator.records()[0]["status"] != "complete":
                time.sleep(0.01)

            manifest = coordinator.records()[0]
            self.assertEqual(pixel.calls[0][0], batch_id)
            self.assertEqual(manifest["platforms"]["pixel"]["accepted"], 1)
            self.assertTrue(manifest["platforms"]["pixel"]["upload_attempt_id"].startswith("upload-"))

    def test_status_error_or_unknown_state_never_finalizes_early(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-status-retry"
            (results / "success.json").write_text(
                json.dumps(result_document("T001", batch_id, "success")),
                encoding="utf-8",
            )
            pixel = FakeQueue()
            observations = []
            coordinator = BatchUploadCoordinator(
                root,
                pixel_queue=pixel,
                recover_pending=False,
                sleeper=lambda _seconds: observations.append(len(pixel.calls)),
            )

            coordinator.begin(
                SequencedImporter([
                    RuntimeError("transient status failure"),
                    {},
                    {"running": True},
                    {"running": False},
                ]),
                {
                    "batch_id": batch_id,
                    "results_dir": results,
                    "_gptphone_upload_targets": {"pixel": True, "nv": False},
                },
            )
            deadline = time.time() + 2
            while time.time() < deadline and coordinator.records()[0]["status"] != "complete":
                time.sleep(0.01)

            self.assertEqual(observations, [0, 0, 0])
            self.assertEqual(len(pixel.calls), 1)

    def test_queue_failed_platform_retry_reuses_manifest_sources_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-retry"
            (results / "success.json").write_text(
                json.dumps(result_document("T001", batch_id, "success")),
                encoding="utf-8",
            )
            pixel = FakeQueue(failures=1)
            coordinator = BatchUploadCoordinator(
                root,
                pixel_queue=pixel,
                recover_pending=False,
            )
            coordinator.begin(FakeImporter(), {
                "batch_id": batch_id,
                "results_dir": results,
                "_gptphone_upload_targets": {"pixel": True, "nv": False},
            })
            deadline = time.time() + 2
            while time.time() < deadline and coordinator.records()[0]["status"] != "queue_failed":
                time.sleep(0.01)

            retried = coordinator.retry(batch_id, "pixel")

            self.assertEqual(retried["status"], "complete")
            self.assertEqual(len(pixel.calls), 2)
            self.assertEqual(pixel.calls[0][1], pixel.calls[1][1])
            self.assertEqual(pixel.calls[0][0], pixel.calls[1][0])
            first_attempt = pixel.calls[0][2]["upload_attempt_id"]
            second_attempt = pixel.calls[1][2]["upload_attempt_id"]
            self.assertNotEqual(first_attempt, second_attempt)
            history = retried["platforms"]["pixel"]["attempt_history"]
            self.assertEqual([item["upload_attempt_id"] for item in history], [first_attempt, second_attempt])
            self.assertEqual([item["kind"] for item in history], ["initial", "retry"])
            self.assertEqual([item["status"] for item in history], ["queue_failed", "queued"])
            with self.assertRaises(ValueError):
                coordinator.retry(batch_id, "pixel")
            self.assertEqual(len(pixel.calls), 2)

    def test_partial_queue_result_is_persisted_and_logged_with_structured_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-partial"
            for index in range(3):
                task_id = f"T{index + 1:03d}"
                (results / f"{task_id}.json").write_text(
                    json.dumps(result_document(task_id, batch_id, "success")),
                    encoding="utf-8",
                )
            logs = []
            pixel = PartialQueue()
            coordinator = BatchUploadCoordinator(
                root,
                pixel_queue=pixel,
                recover_pending=False,
                log_fn=lambda message, level: logs.append((message, level)),
            )

            coordinator.begin(FakeImporter(), {
                "batch_id": batch_id,
                "results_dir": results,
                "_gptphone_upload_targets": {"pixel": True, "nv": False},
            })
            deadline = time.time() + 2
            while time.time() < deadline and coordinator.records()[0]["status"] != "queue_failed":
                time.sleep(0.01)

            manifest = coordinator.records()[0]
            state = manifest["platforms"]["pixel"]
            self.assertEqual(manifest["batch_id"], batch_id)
            self.assertEqual(manifest["status"], "queue_failed")
            self.assertEqual((state["accepted"], state["skipped"], state["failed"]), (1, 1, 1))
            self.assertEqual(state["attempt_history"][0]["status"], "queue_failed")
            self.assertEqual(pixel.calls[0][0], batch_id)
            self.assertEqual(pixel.calls[0][2]["upload_attempt_id"], state["upload_attempt_id"])
            self.assertIn("accepted=1", logs[-1][0])
            self.assertIn("skipped=1", logs[-1][0])
            self.assertIn("failed=1", logs[-1][0])
            self.assertEqual(logs[-1][1], "error")

    def test_failed_record_list_never_reports_sources_as_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-record-failure"
            for index in range(2):
                task_id = f"T{index + 1:03d}"
                (results / f"{task_id}.json").write_text(
                    json.dumps(result_document(task_id, batch_id, "success")),
                    encoding="utf-8",
                )
            pixel = RecordListQueue(
                [
                    {
                        "record_id": "failed-source",
                        "status": "source_unavailable",
                        "source_count": 2,
                    },
                ]
            )
            coordinator = BatchUploadCoordinator(
                root,
                pixel_queue=pixel,
                recover_pending=False,
            )

            coordinator.begin(FakeImporter(), {
                "batch_id": batch_id,
                "results_dir": results,
                "_gptphone_upload_targets": {"pixel": True, "nv": False},
            })
            deadline = time.time() + 2
            while time.time() < deadline and coordinator.records()[0]["status"] != "queue_failed":
                time.sleep(0.01)

            manifest = coordinator.records()[0]
            state = manifest["platforms"]["pixel"]
            self.assertEqual(manifest["status"], "queue_failed")
            self.assertEqual((state["accepted"], state["skipped"], state["failed"]), (0, 0, 2))

    def test_mixed_record_list_aggregates_each_status_by_source_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-record-mixed"
            for index in range(6):
                task_id = f"T{index + 1:03d}"
                (results / f"{task_id}.json").write_text(
                    json.dumps(result_document(task_id, batch_id, "success")),
                    encoding="utf-8",
                )
            nv = RecordListQueue(
                [
                    {"record_id": "queued", "status": "queued", "source_count": 2},
                    {"record_id": "skipped", "status": "skipped", "source_count": 1},
                    {
                        "record_id": "unavailable",
                        "status": "source_unavailable",
                        "source_count": 1,
                    },
                    {"record_id": "failed", "status": "failed", "source_count": 2},
                ]
            )
            coordinator = BatchUploadCoordinator(
                root,
                nv_queue=nv,
                recover_pending=False,
            )

            coordinator.begin(FakeImporter(), {
                "batch_id": batch_id,
                "results_dir": results,
                "_gptphone_upload_targets": {"pixel": False, "nv": True},
            })
            deadline = time.time() + 2
            while time.time() < deadline and coordinator.records()[0]["status"] != "queue_failed":
                time.sleep(0.01)

            state = coordinator.records()[0]["platforms"]["nv"]
            self.assertEqual((state["accepted"], state["skipped"], state["failed"]), (2, 1, 3))
            self.assertEqual(state["attempt_history"][0]["status"], "queue_failed")

    def test_restart_recovers_selected_platforms_from_relative_result_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            batch_id = "batch-restart"
            (results / "success.json").write_text(
                json.dumps(result_document("T001", batch_id, "success")),
                encoding="utf-8",
            )
            manifest_path = root / "batch_upload_manifests.json"
            manifest_path.write_text(json.dumps({
                "version": 1,
                "batches": [{
                    "batch_id": batch_id,
                    "batch_started_at": 100,
                    "results_dir": "results",
                    "targets": {"pixel": False, "nv": True},
                    "platforms": {
                        "pixel": {"status": "disabled", "error": ""},
                        "nv": {"status": "waiting", "error": ""},
                    },
                    "status": "waiting",
                    "source_count": 0,
                    "task_ids": [],
                    "result_files": [],
                    "created_at": 100,
                    "updated_at": 100,
                }],
            }), encoding="utf-8")
            pixel = FakeQueue()
            nv = FakeQueue()

            coordinator = BatchUploadCoordinator(
                root,
                pixel_queue=pixel,
                nv_queue=nv,
                recover_pending=True,
            )

            self.assertEqual(coordinator.records()[0]["status"], "complete")
            self.assertEqual(pixel.calls, [])
            self.assertEqual(len(nv.calls), 1)
            self.assertEqual(nv.calls[0][1][0]["result_file"], "results/success.json")

    def test_relogin_never_creates_an_upload_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = BatchUploadCoordinator(temporary, recover_pending=False)
            result = coordinator.begin(FakeImporter(), {
                "run_mode": "relogin",
                "batch_id": "relogin-1",
                "_gptphone_upload_targets": {"pixel": True, "nv": True},
            })
            self.assertIsNone(result)
            self.assertEqual(coordinator.records(), [])


if __name__ == "__main__":
    unittest.main()
