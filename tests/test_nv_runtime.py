from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from mac_overrides.nv_runtime import (
    NvConfigurationError,
    NvImportClient,
    NvNetworkError,
    NvRuntimeError,
    NvUploadQueue,
    build_nv_card,
)


ACCESS = "nv-access-token-must-stay-private"
REFRESH = "nv-refresh-token-must-stay-private"
API_KEY = "nv-api-key-must-stay-private"


def result_document(index: int = 1) -> dict:
    return {
        "task_id": f"T{index:03d}",
        "batch_id": "batch-nv",
        "batch_started_at": 1234,
        "status": "success",
        "result": {
            "email": f"account-{index}@example.test",
            "access_token": f"{ACCESS}-{index}",
            "refresh_token": f"{REFRESH}-{index}",
        },
    }


class FakeTransport:
    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or [(200, {"accepted": 1})])
        self.calls = []

    def request(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class NvRuntimeTests(unittest.TestCase):
    def config(self, *, upload_proxy=True):
        return {
            "nv_import": {
                "endpoint": "https://nv.example.test/import",
                "schema_url": "https://nv.example.test/schema",
                "api_key": API_KEY,
            },
            "proxy": "http://127.0.0.1:7897",
            "proxy_scope": {"upload": upload_proxy},
        }

    def test_minimal_card_and_authenticated_request_shape(self):
        transport = FakeTransport([(201, {"accepted": 1, "token": ACCESS})])
        client = NvImportClient(lambda: self.config(), transport=transport, sleeper=lambda _value: None)

        result = client.upload([build_nv_card(result_document())])

        self.assertEqual(result["status"], 201)
        endpoint, call = transport.calls[0]
        self.assertEqual(endpoint, "https://nv.example.test/import")
        self.assertEqual(call["headers"]["user-agent"], "curl/8.7.1")
        self.assertEqual(call["headers"]["x-api-key"], API_KEY)
        self.assertEqual(call["proxy"], "http://127.0.0.1:7897")
        self.assertEqual(
            call["payload"],
            {
                "data": [{
                    "access_token": f"{ACCESS}-1",
                    "refresh_token": f"{REFRESH}-1",
                    "email": "account-1@example.test",
                    "type": "codex",
                }],
            },
        )
        self.assertNotIn(ACCESS, json.dumps(result))

    def test_remote_http_endpoint_and_schema_are_rejected(self):
        for field, value in (
            ("endpoint", "http://nv.example.test/import"),
            ("schema_url", "http://nv.example.test/schema"),
        ):
            with self.subTest(field=field):
                config = self.config()
                config["nv_import"][field] = value
                client = NvImportClient(lambda config=config: config, transport=FakeTransport())

                with self.assertRaises(NvConfigurationError) as raised:
                    client.upload([build_nv_card(result_document())])

                self.assertIn("必须使用 HTTPS", raised.exception.public_message)
                self.assertFalse(client.configured())

    def test_loopback_http_endpoint_and_schema_are_allowed(self):
        config = self.config()
        config["nv_import"].update({
            "endpoint": "http://127.0.0.1:18080/import",
            "schema_url": "http://localhost:18080/schema",
        })
        transport = FakeTransport([(200, {"accepted": 1})])
        client = NvImportClient(lambda: config, transport=transport)

        result = client.upload([build_nv_card(result_document())])

        self.assertTrue(client.configured())
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(transport.calls[0][0], "http://127.0.0.1:18080/import")

    def test_build_card_accepts_complete_sub2_account_export(self):
        source = {
            "name": "mojos-account",
            "credentials": {
                "email": "mojos@example.test",
                "access_token": ACCESS,
                "refresh_token": REFRESH,
            },
        }
        self.assertEqual(build_nv_card(source), {
            "email": "mojos@example.test",
            "access_token": ACCESS,
            "refresh_token": REFRESH,
            "type": "codex",
        })

    def test_network_429_and_5xx_retry_three_times(self):
        for outcomes in (
            [NvNetworkError("private"), NvNetworkError("private"), (200, {})],
            [(429, {"message": "busy"}), (500, {"message": "busy"}), (200, {})],
        ):
            with self.subTest(outcomes=outcomes):
                transport = FakeTransport(outcomes)
                sleeps = []
                client = NvImportClient(
                    lambda: self.config(),
                    transport=transport,
                    sleeper=sleeps.append,
                )
                client.upload([build_nv_card(result_document())])
                self.assertEqual(len(transport.calls), 3)
                self.assertEqual(sleeps, [1.0, 2.0])

    def test_other_4xx_stops_and_exposes_safe_failure_identity(self):
        transport = FakeTransport([(422, {
            "code": "invalid_card",
            "message": f"bad access_token={ACCESS}-1 api_key={API_KEY}",
        })])
        client = NvImportClient(lambda: self.config(), transport=transport, sleeper=lambda _value: None)

        with self.assertRaises(NvRuntimeError) as raised:
            client.upload([build_nv_card(result_document())])

        error = raised.exception
        self.assertEqual(error.error_code, "nv_request_rejected")
        self.assertEqual(error.status_code, 422)
        self.assertFalse(error.retryable)
        self.assertEqual(error.provider_code, "invalid_card")
        self.assertNotIn(ACCESS, error.public_message)
        self.assertNotIn(API_KEY, error.public_message)
        self.assertEqual(len(transport.calls), 1)

    def test_explicit_partial_2xx_requires_confirmation_without_automatic_replay(self):
        transport = FakeTransport([(201, {"accepted": 1})])
        client = NvImportClient(
            lambda: self.config(),
            transport=transport,
            sleeper=lambda _value: None,
        )

        with self.assertRaises(NvRuntimeError) as raised:
            client.upload([
                build_nv_card(result_document(1)),
                build_nv_card(result_document(2)),
            ])

        self.assertEqual(raised.exception.error_code, "nv_partial_import")
        self.assertEqual(raised.exception.accepted, 1)
        self.assertFalse(raised.exception.retryable)
        self.assertTrue(raised.exception.needs_confirmation)
        self.assertEqual(len(transport.calls), 1)

    def test_explicit_2xx_failure_signals_and_excess_count_are_rejected(self):
        cards = [build_nv_card(result_document(1)), build_nv_card(result_document(2))]
        cases = (
            ({"ok": False, "accepted": 2}, "nv_provider_reported_failure", 2),
            ({"success": False}, "nv_provider_reported_failure", None),
            ({"failed": 1}, "nv_provider_reported_failure", None),
            ({"accepted": 3}, "nv_response_count_mismatch", 3),
        )
        for response, error_code, accepted in cases:
            with self.subTest(response=response):
                transport = FakeTransport([(200, response)])
                client = NvImportClient(lambda: self.config(), transport=transport)
                with self.assertRaises(NvRuntimeError) as raised:
                    client.upload(cards)
                self.assertEqual(raised.exception.error_code, error_code)
                self.assertEqual(raised.exception.accepted, accepted)
                self.assertEqual(len(transport.calls), 1)

    def test_queue_chunks_to_100_and_never_persists_tokens(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = []
            for index in range(1, 102):
                path = root / "results" / f"{index}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(result_document(index)), encoding="utf-8")
                sources.append({"task_id": f"T{index:03d}", "result_file": path})
            transport = FakeTransport([(200, {"accepted": 100}), (200, {"accepted": 1})])
            queue = NvUploadQueue(
                root,
                NvImportClient(lambda: self.config(), transport=transport, sleeper=lambda _value: None),
                auto_start=False,
            )

            records = queue.enqueue_batch("batch-nv", sources, batch_started_at=1234)
            self.assertEqual([item["source_count"] for item in records], [100, 1])
            self.assertTrue(queue.process_next())
            self.assertTrue(queue.process_next())
            self.assertEqual([len(call[1]["payload"]["data"]) for call in transport.calls], [100, 1])
            persisted = queue.outbox_path.read_text(encoding="utf-8")
            self.assertNotIn(ACCESS, persisted)
            self.assertNotIn(REFRESH, persisted)
            self.assertNotIn(API_KEY, persisted)
            self.assertTrue(all(item["status"] == "success" for item in queue.records()))

    def test_failed_record_recovers_after_restart_and_manual_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "results" / "one.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result_document()), encoding="utf-8")
            first_transport = FakeTransport([(400, {"message": "invalid"})])
            first = NvUploadQueue(
                root,
                NvImportClient(lambda: self.config(), transport=first_transport, sleeper=lambda _value: None),
                auto_start=False,
            )
            record = first.enqueue_batch("batch-nv", [("T001", path)])[0]
            first.process_next()
            failed = first.records()[0]
            self.assertEqual(failed["failure"]["node_code"], "nv_import")
            self.assertTrue(failed["can_retry"])

            second_transport = FakeTransport([(200, {"accepted": 1})])
            second = NvUploadQueue(
                root,
                NvImportClient(lambda: self.config(), transport=second_transport, sleeper=lambda _value: None),
                auto_start=False,
            )
            second.retry(record["record_id"])
            second.process_next()
            self.assertEqual(second.records()[0]["status"], "success")

    def test_existing_inflight_and_success_record_are_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "results" / "one.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result_document()), encoding="utf-8")
            transport = FakeTransport([(200, {"accepted": 1})])
            queue = NvUploadQueue(
                root,
                NvImportClient(lambda: self.config(), transport=transport),
                auto_start=False,
            )

            first = queue.enqueue_batch("batch-nv", [("T001", path)])[0]
            duplicate_inflight = queue.enqueue_batch("batch-nv", [("T001", path)])[0]
            self.assertEqual(duplicate_inflight["record_id"], first["record_id"])
            self.assertTrue(queue.process_next())
            self.assertFalse(queue.process_next())

            duplicate_success = queue.enqueue_batch("batch-nv", [("T001", path)])[0]
            self.assertEqual(duplicate_success["status"], "success")
            self.assertFalse(queue.process_next())
            self.assertEqual(len(transport.calls), 1)

    def test_invalid_source_isolated_without_blocking_valid_nv_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            valid_path = results / "valid.json"
            valid_path.write_text(json.dumps(result_document(1)), encoding="utf-8")
            invalid = result_document(2)
            invalid["result"].pop("refresh_token")
            invalid_path = results / "invalid.json"
            invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
            transport = FakeTransport([(200, {"accepted": 1})])
            queue = NvUploadQueue(
                root,
                NvImportClient(lambda: self.config(), transport=transport),
                auto_start=False,
            )

            queued = queue.enqueue_batch(
                "batch-source-isolation",
                [("T001", valid_path), ("T002", invalid_path)],
            )

            self.assertEqual(sorted(item["status"] for item in queued), ["queued", "source_unavailable"])
            self.assertTrue(queue.process_next())
            self.assertFalse(queue.process_next())
            records = {item["task_ids"][0]: item for item in queue.records()}
            self.assertEqual(records["T001"]["status"], "success")
            self.assertEqual(records["T002"]["status"], "source_unavailable")
            self.assertEqual(len(transport.calls), 1)
            self.assertEqual(len(transport.calls[0][1]["payload"]["data"]), 1)
            self.assertEqual(json.loads(valid_path.read_text(encoding="utf-8"))["status"], "success")
            self.assertEqual(json.loads(invalid_path.read_text(encoding="utf-8"))["status"], "success")
            persisted = queue.outbox_path.read_text(encoding="utf-8")
            self.assertNotIn(ACCESS, persisted)
            self.assertNotIn(REFRESH, persisted)

    def test_partial_2xx_persists_actual_accepted_count_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = []
            for index in (1, 2):
                path = root / "results" / f"{index}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(result_document(index)), encoding="utf-8")
                sources.append((f"T{index:03d}", path))
            transport = FakeTransport([(201, {"accepted": 1})])
            queue = NvUploadQueue(
                root,
                NvImportClient(lambda: self.config(), transport=transport),
                auto_start=False,
            )

            record = queue.enqueue_batch("batch-partial", sources)[0]
            self.assertTrue(queue.process_next())
            failed = queue.records()[0]

            self.assertEqual(failed["record_id"], record["record_id"])
            self.assertEqual(failed["status"], "partial")
            self.assertEqual(failed["accepted"], 1)
            self.assertTrue(failed["needs_confirmation"])
            self.assertFalse(failed["can_retry"])
            self.assertEqual(failed["failure"]["error_code"], "nv_partial_import")
            self.assertEqual(failed["failure"]["http_status"], 201)
            self.assertEqual(len(transport.calls), 1)
            with self.assertRaises(NvRuntimeError) as raised:
                queue.retry(record["record_id"])
            self.assertEqual(raised.exception.error_code, "nv_retry_unavailable")
            self.assertTrue(all(json.loads(path.read_text(encoding="utf-8"))["status"] == "success" for _task, path in sources))

    def test_zero_accepted_count_can_be_retried_without_automatic_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "results" / "one.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result_document()), encoding="utf-8")
            transport = FakeTransport([(200, {"accepted": 0}), (200, {"accepted": 1})])
            queue = NvUploadQueue(
                root,
                NvImportClient(lambda: self.config(), transport=transport),
                auto_start=False,
            )

            record = queue.enqueue_batch("batch-zero", [("T001", path)])[0]
            self.assertTrue(queue.process_next())
            failed = queue.records()[0]
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["accepted"], 0)
            self.assertFalse(failed["needs_confirmation"])
            self.assertTrue(failed["can_retry"])
            self.assertEqual(len(transport.calls), 1)

            queue.retry(record["record_id"])
            self.assertTrue(queue.process_next())
            self.assertEqual(queue.records()[0]["status"], "success")
            self.assertEqual(len(transport.calls), 2)

    def test_excess_accepted_count_is_clamped_and_cannot_be_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "results" / "one.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result_document()), encoding="utf-8")
            queue = NvUploadQueue(
                root,
                NvImportClient(
                    lambda: self.config(),
                    transport=FakeTransport([(200, {"accepted": 2})]),
                ),
                auto_start=False,
            )

            queue.enqueue_batch("batch-excess", [("T001", path)])
            self.assertTrue(queue.process_next())
            record = queue.records()[0]
            persisted = json.loads(queue.outbox_path.read_text(encoding="utf-8"))["records"][0]
            self.assertEqual(record["status"], "partial")
            self.assertEqual(record["accepted"], 1)
            self.assertEqual(persisted["accepted"], 1)
            self.assertFalse(record["can_retry"])

    def test_worker_exception_isolated_and_overview_reports_liveness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = []
            for index in (1, 2):
                path = root / "results" / f"{index}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(result_document(index)), encoding="utf-8")
                paths.append(path)
            transport = FakeTransport([(200, {"accepted": 1})])
            logs = []
            queue = NvUploadQueue(
                root,
                NvImportClient(lambda: self.config(), transport=transport),
                log_fn=lambda message, level: logs.append((message, level)),
                auto_start=False,
            )
            first = queue.enqueue_batch("batch-worker-1", [("T001", paths[0])])[0]
            second = queue.enqueue_batch("batch-worker-2", [("T002", paths[1])])[0]
            original_process = queue._process

            def flaky_process(record_id):
                if record_id == first["record_id"]:
                    raise OSError(ACCESS)
                original_process(record_id)

            queue._process = flaky_process
            queue.start()
            deadline = time.monotonic() + 2
            while queue.overview()["queue"]["pending"] and time.monotonic() < deadline:
                time.sleep(0.01)
            deadline = time.monotonic() + 1
            while queue.overview()["queue"]["active"] and time.monotonic() < deadline:
                time.sleep(0.01)
            overview = queue.overview()
            records = {record["record_id"]: record for record in queue.records()}
            queue.stop()

            self.assertTrue(overview["queue"]["alive"])
            self.assertEqual(overview["queue"]["alive_workers"], 1)
            self.assertEqual(records[first["record_id"]]["failure"]["error_code"], "nv_worker_unexpected")
            self.assertEqual(records[second["record_id"]]["status"], "success")
            self.assertNotIn(ACCESS, json.dumps(logs))
            self.assertFalse(queue.overview()["queue"]["alive"])


if __name__ == "__main__":
    unittest.main()
