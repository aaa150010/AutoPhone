from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import unittest

from mac_overrides.pixel_runtime import (
    PIXEL_AUTO_TARGET_IDS,
    PIXEL_EXCLUDED_TARGET_IDS,
    PixelProxyClient,
    PixelProxyError,
    PixelSourceError,
    PixelStateError,
    PixelUploadQueue,
    build_pixel_import_payload,
    credential_fingerprint,
    sanitize_error,
)


ACCESS_TOKEN = "access-token-that-must-not-enter-outbox"
REFRESH_TOKEN = "refresh-token-that-must-not-enter-outbox"
ID_TOKEN = "header.payload.signature-that-must-not-enter-outbox"
SOURCE_EMAIL = "registered@example.test"


def success_document(*, task_id: str = "T0001") -> dict:
    return {
        "task_id": task_id,
        "email": SOURCE_EMAIL,
        "status": "success",
        "source_row": "credential-bearing-source-row",
        "result": {
            "email": SOURCE_EMAIL,
            "access_token": ACCESS_TOKEN,
            "refresh_token": REFRESH_TOKEN,
            "id_token": ID_TOKEN,
            "expires_at": 1_900_000_000,
            "account_id": "chatgpt-account-1",
            "chatgpt_account_id": "chatgpt-account-1",
            "chatgpt_user_id": "user-1",
            "chatgpt_plan_type": "plus",
            "password": "must-not-be-copied",
            "chatgpt_field_source": "must-not-be-copied",
        },
    }


def target_result(
    target_id: str,
    *,
    status: str = "success",
    created: int = 1,
    updated: int = 0,
    failed: int = 0,
    shared: int = 1,
    share_failed: int = 0,
    failed_share_ids: list[int] | None = None,
    concurrency_by_id: dict[str, int] | None = None,
    message: str = "ok",
) -> dict:
    if concurrency_by_id is None and status == "success" and shared > 0:
        suffix = int(target_id.rsplit("-", 1)[-1])
        concurrency_by_id = {str(100 + suffix): 3 + (suffix % 8)}
    target_number = int(target_id.rsplit("-", 1)[-1])
    return {
        "targetId": target_id,
        "generatedFileName": f"{target_id}.json",
        "sourceCount": 1,
        "created": created,
        "updated": updated,
        "failed": failed,
        "shared": shared,
        "shareFailed": share_failed,
        "failedShareIds": failed_share_ids or [],
        "concurrencyById": concurrency_by_id or {},
        "importErrors": [],
        "generatedNames": [f"acct-{target_number:012x}@example.test"],
        "status": status,
        "message": message,
    }


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.job_polls = 0

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if url.endswith("/pixel-manager/targets"):
            return {
                "targets": [
                    {
                        "id": "pixel-1",
                        "email": "manager@example.test",
                        "access_token": "remote-secret",
                        "refreshToken": "remote-camel-secret",
                    }
                ]
            }
        if "/accounts/bulk-test" in url:
            return {"ok": True, "successIds": [1, 2], "failedIds": []}
        if url.endswith("/share"):
            return {"ok": True, "successIds": [7], "failedIds": []}
        if url.endswith("/pixel-manager/import"):
            return {"job": {"jobId": "job-1", "status": "queued"}}
        if url.endswith("/pixel-manager/import-jobs/job-1"):
            self.job_polls += 1
            if self.job_polls == 1:
                return {"job": {"jobId": "job-1", "status": "running", "results": []}}
            return {
                "job": {
                    "jobId": "job-1",
                    "status": "completed",
                    "results": [target_result("pixel-2")],
                }
            }
        raise AssertionError(f"unexpected request: {method} {url}")


class FakePixelClient:
    def __init__(self) -> None:
        self.created: list[dict] = []
        self.share_calls: list[tuple[str, list[int]]] = []
        self.import_record_calls = 0
        self.remote_records: list[dict] = []
        self.identity_matches: dict[str, list[int]] = {}
        self.jobs: list[dict] = []
        self.share_results: list[dict] = []
        self.wait_error: PixelProxyError | None = None
        self.active = 0
        self.max_active = 0
        self.delay = 0.0

    def create_import(self, payload, target_ids, *, file_name):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        targets = list(target_ids)
        self.created.append(
            {
                "payload": payload,
                "target_ids": targets,
                "file_name": file_name,
                "job_id": f"job-{len(self.created) + 1}",
            }
        )
        return {"job": {"jobId": self.created[-1]["job_id"], "status": "queued"}}

    def wait_import_job(self, job_id):
        try:
            if self.wait_error is not None:
                error, self.wait_error = self.wait_error, None
                raise error
            if self.delay:
                time.sleep(self.delay)
            if self.jobs:
                return self.jobs.pop(0)
            call = next(item for item in self.created if item["job_id"] == job_id)
            return {
                "jobId": job_id,
                "status": "completed",
                "results": [target_result(target_id) for target_id in call["target_ids"]],
            }
        finally:
            self.active = max(self.active - 1, 0)

    def import_records(self):
        self.import_record_calls += 1
        return {"records": self.remote_records}

    def find_accounts_by_identity(self, target_id, identity_values):
        return list(self.identity_matches.get(target_id, []))

    def share_accounts(self, target_id, account_ids):
        ids = list(account_ids)
        self.share_calls.append((target_id, ids))
        if self.share_results:
            return self.share_results.pop(0)
        return {"ok": True, "success": len(ids), "failed": 0, "successIds": ids, "failedIds": []}


class PixelPayloadTests(unittest.TestCase):
    def test_builds_one_account_cost_calculator_payload_from_wrapped_result(self):
        payload = build_pixel_import_payload(success_document())

        self.assertEqual(payload["proxies"], [])
        self.assertEqual(len(payload["accounts"]), 1)
        account = payload["accounts"][0]
        self.assertEqual(account["name"], SOURCE_EMAIL)
        self.assertEqual(account["platform"], "openai")
        self.assertEqual(account["type"], "oauth")
        self.assertEqual(account["account_level"], "plus")
        self.assertEqual(account["credentials"]["plan_type"], "plus")
        self.assertEqual(account["credentials"]["access_token"], ACCESS_TOKEN)
        self.assertEqual(account["credentials"]["refresh_token"], REFRESH_TOKEN)
        self.assertEqual(account["credentials"]["id_token"], ID_TOKEN)
        self.assertEqual(account["extra"]["chatgpt_account_id"], "chatgpt-account-1")
        encoded = json.dumps(payload)
        self.assertNotIn("must-not-be-copied", encoded)
        self.assertNotIn("chatgpt_field_source", encoded)
        self.assertRegex(credential_fingerprint(payload), r"^[0-9a-f]{12}$")

    def test_accepts_nested_local_oauth_tokens(self):
        payload = build_pixel_import_payload(
            {
                "email": SOURCE_EMAIL,
                "local_oauth": {
                    "tokens": {
                        "access_token": ACCESS_TOKEN,
                        "refresh_token": REFRESH_TOKEN,
                        "id_token": ID_TOKEN,
                    }
                },
            }
        )
        self.assertEqual(payload["accounts"][0]["credentials"]["access_token"], ACCESS_TOKEN)

    def test_rejects_failed_or_incomplete_success_files_without_echoing_secrets(self):
        with self.assertRaises(PixelSourceError):
            build_pixel_import_payload({"status": "failed", "result": success_document()["result"]})
        with self.assertRaises(PixelSourceError) as raised:
            build_pixel_import_payload({"email": SOURCE_EMAIL, "access_token": ACCESS_TOKEN})
        self.assertNotIn(ACCESS_TOKEN, str(raised.exception))

    def test_error_sanitizer_removes_exact_encoded_bearer_and_jwt_values(self):
        jwt = "abcdefghijkl.mnopqrstuvwxyz.abcdefghijklmnop"
        text = sanitize_error(
            f"access_token={ACCESS_TOKEN} Authorization: Bearer {REFRESH_TOKEN} value={jwt}",
            [ACCESS_TOKEN],
        )
        self.assertNotIn(ACCESS_TOKEN, text)
        self.assertNotIn(REFRESH_TOKEN, text)
        self.assertNotIn(jwt, text)


class PixelProxyClientTests(unittest.TestCase):
    def test_management_and_import_calls_use_proxy_contract_and_sanitize_responses(self):
        transport = FakeTransport()
        sleeps: list[float] = []
        clock = iter([0.0, 0.0, 0.1, 0.2])
        client = PixelProxyClient(
            transport=transport,
            poll_interval=0.1,
            sleeper=sleeps.append,
            monotonic=lambda: next(clock),
        )

        targets = client.targets()
        self.assertNotIn("access_token", targets["targets"][0])
        self.assertNotIn("refreshToken", targets["targets"][0])
        tested = client.bulk_test("pixel-2", [1, "2", 2, 0])
        self.assertTrue(tested["ok"])
        shared = client.share_accounts("pixel-2", [7])
        self.assertTrue(shared["ok"])
        created = client.create_import(
            build_pixel_import_payload(success_document()),
            ["pixel-2"],
            file_name="../unsafe-name.json",
        )
        completed = client.wait_import_job(created["job"]["jobId"])

        self.assertEqual(completed["status"], "completed")
        self.assertEqual(sleeps, [0.1])
        import_call = next(call for call in transport.calls if call["url"].endswith("/pixel-manager/import"))
        self.assertEqual(import_call["params"]["targetIds"], '["pixel-2"]')
        self.assertEqual(import_call["params"]["fileName"], "unsafe-name.json")
        self.assertIn(ACCESS_TOKEN.encode(), import_call["body"])
        share_call = next(call for call in transport.calls if call["url"].endswith("/share"))
        self.assertEqual(share_call["json_body"], {"accountIds": [7]})

    def test_automatic_import_rejects_excluded_target(self):
        client = PixelProxyClient(transport=FakeTransport())
        with self.assertRaises(PixelStateError):
            client.create_import(
                build_pixel_import_payload(success_document()),
                [PIXEL_EXCLUDED_TARGET_IDS[0]],
                file_name="accounts.json",
            )


class PixelUploadQueueTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        self.results.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def write_result(self, name: str = "result.json", *, task_id: str = "T0001") -> Path:
        path = self.results / name
        path.write_text(json.dumps(success_document(task_id=task_id)), encoding="utf-8")
        return path

    @staticmethod
    def states(record: dict) -> dict[str, str]:
        return {item["target_id"]: item["state"] for item in record["targets"]}

    @staticmethod
    def stages(record: dict) -> dict[str, str]:
        return {item["target_id"]: item["stage"] for item in record["targets"]}

    def test_success_uploads_exactly_six_targets_and_persists_no_credentials(self):
        client = FakePixelClient()
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        queued = service.enqueue("T0001", self.write_result())

        self.assertEqual(queued["status"], "queued")
        self.assertTrue(service.process_next())
        completed = service.get(queued["record_id"])

        self.assertEqual(completed["status"], "success")
        self.assertEqual(tuple(client.created[0]["target_ids"]), PIXEL_AUTO_TARGET_IDS)
        self.assertNotIn("pixel-1", client.created[0]["target_ids"])
        self.assertEqual(set(self.states(completed).values()), {"success"})
        self.assertEqual(set(self.stages(completed).values()), {"verification"})
        generated_names = [item["generated_name"] for item in completed["targets"]]
        self.assertEqual(len(set(generated_names)), len(PIXEL_AUTO_TARGET_IDS))
        self.assertTrue(
            all(re.fullmatch(r"acct-[0-9a-f]{12}@example\.test", name) for name in generated_names)
        )
        persisted = service.outbox_path.read_text(encoding="utf-8")
        self.assertNotIn(ACCESS_TOKEN, persisted)
        self.assertNotIn(REFRESH_TOKEN, persisted)
        self.assertNotIn(ID_TOKEN, persisted)
        self.assertNotIn(SOURCE_EMAIL, persisted)
        self.assertNotIn("result_file", json.dumps(completed))
        stored = json.loads(persisted)["records"][0]
        self.assertEqual(stored["result_file"], "results/result.json")
        self.assertEqual(os.stat(service.outbox_path).st_mode & 0o777, 0o600)

    def test_success_requires_proxy_random_names_to_match_domain_and_be_unique(self):
        invalid = target_result("pixel-2")
        invalid["generatedNames"] = [SOURCE_EMAIL]
        duplicate = "acct-00000000abcd@example.test"
        first_duplicate = target_result("pixel-3")
        first_duplicate["generatedNames"] = [duplicate]
        second_duplicate = target_result("pixel-4")
        second_duplicate["generatedNames"] = [duplicate]
        client = FakePixelClient()
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    invalid,
                    first_duplicate,
                    second_duplicate,
                    *(target_result(target_id) for target_id in PIXEL_AUTO_TARGET_IDS[3:]),
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())

        service.process_next()

        completed = service.get(record["record_id"])
        by_target = {item["target_id"]: item for item in completed["targets"]}
        self.assertEqual(completed["status"], "partial")
        self.assertEqual(by_target["pixel-2"]["state"], "needs_confirmation")
        self.assertEqual(by_target["pixel-2"]["generated_names"], [])
        self.assertIn("12位十六进制", by_target["pixel-2"]["error"])
        self.assertEqual(by_target["pixel-3"]["state"], "needs_confirmation")
        self.assertEqual(by_target["pixel-4"]["state"], "needs_confirmation")
        self.assertIn("重复", by_target["pixel-3"]["error"])
        self.assertFalse(by_target["pixel-2"]["retryable"])
        self.assertNotIn(SOURCE_EMAIL, service.outbox_path.read_text(encoding="utf-8"))

    def test_duplicate_identity_with_existing_id_reuses_account_and_shares_without_reimport(self):
        client = FakePixelClient()
        client.share_results.append(
            {
                "ok": True,
                "success": 1,
                "failed": 0,
                "successIds": [501],
                "failedIds": [],
                "concurrencyById": {"501": 6},
            }
        )
        duplicate = target_result(
            "pixel-2",
            status="failed",
            created=0,
            shared=0,
            failed=1,
            concurrency_by_id={},
            message="导入失败；平台明细：account already exists",
        )
        duplicate["generatedNames"] = []
        duplicate["importErrors"] = [
            {
                "name": "acct-000000000501@example.test",
                "message": "account already exists (existing_account_id=501)",
                "existing_account_id": 501,
            }
        ]
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    duplicate if target_id == "pixel-2" else target_result(target_id)
                    for target_id in PIXEL_AUTO_TARGET_IDS
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())

        service.process_next()

        completed = service.get(record["record_id"])
        pixel_two = next(item for item in completed["targets"] if item["target_id"] == "pixel-2")
        self.assertEqual(completed["status"], "success")
        self.assertEqual(pixel_two["state"], "success")
        self.assertEqual(pixel_two["account_ids"], [501])
        self.assertEqual(pixel_two["concurrency_by_id"], {"501": 6})
        self.assertEqual(client.share_calls, [("pixel-2", [501])])
        self.assertEqual(len(client.created), 1)

    def test_duplicate_identity_without_existing_id_requires_confirmation(self):
        client = FakePixelClient()
        duplicate = target_result(
            "pixel-2",
            status="failed",
            created=0,
            shared=0,
            failed=1,
            concurrency_by_id={},
            message="导入失败；平台明细：account already exists",
        )
        duplicate["generatedNames"] = []
        duplicate["importErrors"] = [{"message": "account already exists"}]
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    duplicate if target_id == "pixel-2" else target_result(target_id)
                    for target_id in PIXEL_AUTO_TARGET_IDS
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())

        service.process_next()

        current = service.get(record["record_id"])
        pixel_two = next(item for item in current["targets"] if item["target_id"] == "pixel-2")
        self.assertEqual(current["status"], "partial")
        self.assertEqual(pixel_two["state"], "needs_confirmation")
        self.assertEqual(pixel_two["stage"], "verification")
        self.assertFalse(pixel_two["retryable"])
        self.assertIn("账号 ID", pixel_two["error"])
        self.assertEqual(client.share_calls, [])

    def test_duplicate_identity_can_be_mapped_by_remote_identity_scan(self):
        client = FakePixelClient()
        client.identity_matches["pixel-2"] = [777]
        client.share_results.append(
            {
                "ok": True,
                "success": 1,
                "failed": 0,
                "successIds": [777],
                "failedIds": [],
                "concurrencyById": {"777": 4},
            }
        )
        duplicate = target_result(
            "pixel-2",
            status="failed",
            created=0,
            shared=0,
            failed=1,
            concurrency_by_id={},
            message="导入失败；平台明细：account already exists",
        )
        duplicate["generatedNames"] = []
        duplicate["importErrors"] = [{"message": "account already exists"}]
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    duplicate if target_id == "pixel-2" else target_result(target_id)
                    for target_id in PIXEL_AUTO_TARGET_IDS
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())

        service.process_next()

        current = service.get(record["record_id"])
        pixel_two = next(item for item in current["targets"] if item["target_id"] == "pixel-2")
        self.assertEqual(current["status"], "success")
        self.assertEqual(pixel_two["account_ids"], [777])
        self.assertEqual(pixel_two["concurrency_by_id"], {"777": 4})
        self.assertEqual(client.share_calls, [("pixel-2", [777])])

    def test_recover_existing_accounts_persists_share_only_targets(self):
        client = FakePixelClient()
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())

        recovered = service.recover_existing_accounts(
            record["record_id"],
            {
                "pixel-2": [501],
                "pixel-3": [502, "502"],
            },
        )

        by_target = {item["target_id"]: item for item in recovered["targets"]}
        self.assertEqual(by_target["pixel-2"]["state"], "share_failed")
        self.assertEqual(by_target["pixel-2"]["failed_share_ids"], [501])
        self.assertEqual(by_target["pixel-3"]["account_ids"], [502])
        persisted = json.loads(service.outbox_path.read_text(encoding="utf-8"))["records"][0]
        self.assertEqual(persisted["targets"]["pixel-2"]["stage"], "share")
        self.assertTrue(persisted["targets"]["pixel-2"]["retry_requested"])
        with self.assertRaises(PixelStateError):
            service.recover_existing_accounts(record["record_id"], {"pixel-1": [1]})

    def test_share_failure_retries_only_failed_ids_without_reimport(self):
        client = FakePixelClient()
        client.share_results.append(
            {
                "ok": True,
                "success": 1,
                "failed": 0,
                "successIds": [202],
                "failedIds": [],
                "concurrencyById": {"202": 8},
            }
        )
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    target_result(
                        target_id,
                        status="partial" if target_id == "pixel-2" else "success",
                        shared=0 if target_id == "pixel-2" else 1,
                        share_failed=1 if target_id == "pixel-2" else 0,
                        failed_share_ids=[202] if target_id == "pixel-2" else [],
                    )
                    for target_id in PIXEL_AUTO_TARGET_IDS
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())
        service.process_next()
        partial = service.get(record["record_id"])
        self.assertEqual(self.states(partial)["pixel-2"], "share_failed")
        self.assertEqual(self.stages(partial)["pixel-2"], "share")
        self.assertTrue(partial["can_retry"])
        pixel_two = next(item for item in partial["targets"] if item["target_id"] == "pixel-2")
        self.assertTrue(pixel_two["retryable"])
        self.assertEqual(pixel_two["failed_ids"], [202])

        service.retry(record["record_id"], ["pixel-2"])
        service.process_next()
        completed = service.get(record["record_id"])

        self.assertEqual(completed["status"], "success")
        self.assertEqual(client.share_calls, [("pixel-2", [202])])
        self.assertEqual(len(client.created), 1)
        pixel_two = next(item for item in completed["targets"] if item["target_id"] == "pixel-2")
        self.assertEqual(pixel_two["concurrency"], 8)
        self.assertEqual(pixel_two["concurrency_by_id"], {"202": 8})
        self.assertEqual(pixel_two["stage"], "verification")

    def test_share_retry_without_verified_concurrency_stays_at_verification(self):
        client = FakePixelClient()
        client.share_results.append(
            {
                "ok": True,
                "success": 1,
                "failed": 0,
                "successIds": [202],
                "failedIds": [],
                "concurrencyById": {},
            }
        )
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    target_result(
                        target_id,
                        status="partial" if target_id == "pixel-2" else "success",
                        shared=0 if target_id == "pixel-2" else 1,
                        share_failed=1 if target_id == "pixel-2" else 0,
                        failed_share_ids=[202] if target_id == "pixel-2" else [],
                    )
                    for target_id in PIXEL_AUTO_TARGET_IDS
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())
        service.process_next()

        service.retry(record["record_id"], ["pixel-2"])
        service.process_next()
        pixel_two = next(
            item for item in service.get(record["record_id"])["targets"] if item["target_id"] == "pixel-2"
        )

        self.assertEqual(pixel_two["state"], "share_failed")
        self.assertEqual(pixel_two["stage"], "verification")
        self.assertIn("3-10", pixel_two["error"])
        self.assertEqual(len(client.created), 1)

    def test_initial_import_persists_verified_concurrency_mapping(self):
        client = FakePixelClient()
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    target_result(
                        target_id,
                        concurrency_by_id={str(index + 200): index + 3},
                    )
                    for index, target_id in enumerate(PIXEL_AUTO_TARGET_IDS)
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())
        service.process_next()

        completed = service.get(record["record_id"])
        by_target = {item["target_id"]: item for item in completed["targets"]}
        for index, target_id in enumerate(PIXEL_AUTO_TARGET_IDS):
            account_id = str(index + 200)
            self.assertEqual(by_target[target_id]["concurrency_by_id"], {account_id: index + 3})
            self.assertEqual(by_target[target_id]["concurrency"], index + 3)
        persisted = json.loads(service.outbox_path.read_text(encoding="utf-8"))["records"][0]
        self.assertEqual(persisted["targets"]["pixel-2"]["concurrency_by_id"], {"200": 3})

    def test_surface_success_without_verified_concurrency_needs_confirmation(self):
        client = FakePixelClient()
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    target_result(
                        target_id,
                        concurrency_by_id={} if target_id == "pixel-2" else None,
                    )
                    for target_id in PIXEL_AUTO_TARGET_IDS
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())
        service.process_next()

        completed = service.get(record["record_id"])
        pixel_two = next(item for item in completed["targets"] if item["target_id"] == "pixel-2")
        self.assertEqual(completed["status"], "partial")
        self.assertEqual(pixel_two["state"], "needs_confirmation")
        self.assertEqual(pixel_two["stage"], "verification")
        self.assertIsNone(pixel_two["concurrency"])
        self.assertIn("3-10", pixel_two["error"])

    def test_import_failure_recovers_then_reimports_only_failed_target(self):
        client = FakePixelClient()
        client.jobs.extend(
            [
                {
                    "jobId": "job-1",
                    "status": "completed",
                    "results": [
                        target_result(
                            target_id,
                            status="failed" if target_id == "pixel-3" else "success",
                            created=0 if target_id == "pixel-3" else 1,
                            failed=1 if target_id == "pixel-3" else 0,
                            shared=0 if target_id == "pixel-3" else 1,
                            message="import rejected" if target_id == "pixel-3" else "ok",
                        )
                        for target_id in PIXEL_AUTO_TARGET_IDS
                    ],
                },
                {
                    "jobId": "job-2",
                    "status": "completed",
                    "results": [target_result("pixel-3")],
                },
            ]
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())
        service.process_next()
        failed = service.get(record["record_id"])
        self.assertEqual(self.states(failed)["pixel-3"], "import_failed")
        self.assertEqual(self.stages(failed)["pixel-3"], "import")

        service.retry(record["record_id"], ["pixel-3"])
        service.process_next()
        completed = service.get(record["record_id"])

        self.assertEqual(completed["status"], "success")
        self.assertEqual(client.import_record_calls, 1)
        self.assertEqual(client.created[0]["target_ids"], list(PIXEL_AUTO_TARGET_IDS))
        self.assertEqual(client.created[1]["target_ids"], ["pixel-3"])
        attempts = {item["target_id"]: item["attempts"] for item in completed["targets"]}
        self.assertEqual(attempts["pixel-3"], 2)
        self.assertTrue(all(value == 1 for key, value in attempts.items() if key != "pixel-3"))

    def test_confirmed_failed_remote_record_does_not_suppress_reimport(self):
        client = FakePixelClient()
        failed_result = target_result(
            "pixel-4",
            status="failed",
            created=0,
            failed=1,
            shared=0,
            message="confirmed import failure",
        )
        client.jobs.extend(
            [
                {
                    "jobId": "job-1",
                    "status": "completed",
                    "results": [
                        failed_result if target_id == "pixel-4" else target_result(target_id)
                        for target_id in PIXEL_AUTO_TARGET_IDS
                    ],
                },
                {
                    "jobId": "job-2",
                    "status": "completed",
                    "results": [target_result("pixel-4")],
                },
            ]
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())
        service.process_next()
        current = service.get(record["record_id"])
        client.remote_records = [
            {
                "sourceFileName": current["upload_file_name"],
                "targets": [failed_result],
            },
            {
                "sourceFileName": current["upload_file_name"],
                "targets": [target_result("pixel-4")],
            },
        ]

        service.retry(record["record_id"], ["pixel-4"])
        service.process_next()

        self.assertEqual(service.get(record["record_id"])["status"], "success")
        self.assertEqual(client.created[1]["target_ids"], ["pixel-4"])

    def test_missing_result_is_retained_as_source_unavailable(self):
        client = FakePixelClient()
        path = self.write_result()
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", path)
        path.unlink()

        service.process_next()
        unavailable = service.get(record["record_id"])

        self.assertEqual(unavailable["status"], "source_unavailable")
        self.assertFalse(unavailable["source_available"])
        self.assertEqual(set(self.states(unavailable).values()), {"source_unavailable"})
        self.assertEqual(set(self.stages(unavailable).values()), {"source"})
        self.assertEqual(client.created, [])

    def test_unexpected_worker_exception_keeps_sanitized_reason_and_success_source(self):
        class UnexpectedClient(FakePixelClient):
            def create_import(self, payload, target_ids, *, file_name):
                raise RuntimeError(f"proxy worker crashed access_token={ACCESS_TOKEN}")

        path = self.write_result()
        original = path.read_bytes()
        service = PixelUploadQueue(self.root, client=UnexpectedClient(), auto_start=False)
        record = service.enqueue("T0001", path)

        self.assertTrue(service.process_next())
        failed = service.get(record["record_id"])

        self.assertEqual(failed["status"], "failed")
        self.assertIn("proxy worker crashed", failed["error"])
        self.assertNotIn(ACCESS_TOKEN, json.dumps(failed))
        self.assertEqual(set(self.states(failed).values()), {"import_failed"})
        self.assertEqual(set(self.stages(failed).values()), {"import"})
        self.assertTrue(all("proxy worker crashed" in item["error"] for item in failed["targets"]))
        persisted = service.outbox_path.read_text(encoding="utf-8")
        self.assertIn("proxy worker crashed", persisted)
        self.assertNotIn(ACCESS_TOKEN, persisted)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["status"], "success")

    def test_legacy_outbox_without_stage_derives_public_stage_from_state(self):
        service = PixelUploadQueue(self.root, client=FakePixelClient(), auto_start=False)
        record = service.enqueue("T0001", self.write_result())
        service.process_next()
        stored = json.loads(service.outbox_path.read_text(encoding="utf-8"))
        for target in stored["records"][0]["targets"].values():
            target.pop("stage", None)
        service.outbox_path.write_text(json.dumps(stored), encoding="utf-8")

        restored = PixelUploadQueue(
            self.root,
            client=FakePixelClient(),
            auto_start=False,
            resume_pending=False,
        )

        self.assertEqual(set(self.stages(restored.get(record["record_id"])).values()), {"verification"})

    def test_restart_resumes_known_remote_job_without_duplicate_import(self):
        path = self.write_result()
        first_client = FakePixelClient()
        first_client.wait_error = PixelProxyError("poll timeout", 504)
        first = PixelUploadQueue(self.root, client=first_client, auto_start=False)
        record = first.enqueue("T0001", path)
        first.process_next()
        waiting = first.get(record["record_id"])
        self.assertEqual(set(self.states(waiting).values()), {"importing"})

        second_client = FakePixelClient()
        second_client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [target_result(target_id) for target_id in PIXEL_AUTO_TARGET_IDS],
            }
        )
        resumed = PixelUploadQueue(self.root, client=second_client, auto_start=False)
        self.assertTrue(resumed.process_next())
        completed = resumed.get(record["record_id"])

        self.assertEqual(completed["status"], "success")
        self.assertEqual(second_client.created, [])

    def test_remote_error_is_redacted_in_public_and_persisted_records(self):
        client = FakePixelClient()
        client.jobs.append(
            {
                "jobId": "job-1",
                "status": "completed",
                "results": [
                    target_result(
                        target_id,
                        status="failed",
                        created=0,
                        failed=1,
                        shared=0,
                        message=f"access_token={ACCESS_TOKEN}",
                    )
                    for target_id in PIXEL_AUTO_TARGET_IDS
                ],
            }
        )
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        record = service.enqueue("T0001", self.write_result())
        service.process_next()

        self.assertNotIn(ACCESS_TOKEN, json.dumps(service.get(record["record_id"])))
        self.assertNotIn(ACCESS_TOKEN, service.outbox_path.read_text(encoding="utf-8"))

    def test_background_worker_processes_records_serially(self):
        client = FakePixelClient()
        client.delay = 0.02
        service = PixelUploadQueue(self.root, client=client, auto_start=False)
        first = service.enqueue("T0001", self.write_result("one.json", task_id="T0001"))
        second = service.enqueue("T0002", self.write_result("two.json", task_id="T0002"))
        service.start()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if service.get(first["record_id"])["status"] == "success" and service.get(second["record_id"])["status"] == "success":
                break
            time.sleep(0.01)
        service.stop()

        self.assertEqual(service.get(first["record_id"])["status"], "success")
        self.assertEqual(service.get(second["record_id"])["status"], "success")
        self.assertEqual(client.max_active, 1)


if __name__ == "__main__":
    unittest.main()
