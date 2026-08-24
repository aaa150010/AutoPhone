import json
import tempfile
import unittest
from pathlib import Path

from mac_overrides.result_persistence_runtime import (
    apply_result_json_metadata,
    resolve_results_dir,
    result_json_path,
    settings_with_absolute_results_dir,
)


class ResultPersistenceRuntimeTests(unittest.TestCase):
    def test_relative_results_dir_is_resolved_against_data_dir_without_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / "runtime-data"
            settings = {"results_dir": "custom/results", "batch_id": "batch-1"}
            original = dict(settings)

            resolved = resolve_results_dir(settings, data_dir)
            copied = settings_with_absolute_results_dir(settings, data_dir)

            self.assertEqual(resolved, (data_dir / "custom/results").resolve())
            self.assertTrue(Path(copied["results_dir"]).is_absolute())
            self.assertEqual(Path(copied["results_dir"]), resolved)
            self.assertEqual(copied["batch_id"], "batch-1")
            self.assertEqual(settings, original)

    def test_empty_results_dir_defaults_to_data_results_and_path_matches_recovered_name(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / "data"
            self.assertEqual(
                resolve_results_dir({"results_dir": "  "}, data_dir),
                (data_dir / "results").resolve(),
            )
            self.assertEqual(
                result_json_path({}, data_dir, "T001", "person@example.test"),
                (data_dir / "results" / "T001_person_at_example.test.json").resolve(),
            )

    def test_relative_data_dir_is_not_joined_twice(self):
        expected = (Path.cwd() / "relative-data" / "results").resolve()
        self.assertEqual(resolve_results_dir({}, "relative-data"), expected)

    def test_all_metadata_is_merged_with_one_atomic_write(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / "data"
            target = result_json_path({}, data_dir, "T002", "batch@example.test")
            target.parent.mkdir(parents=True)
            target.write_text(
                json.dumps(
                    {
                        "task_id": "T002",
                        "status": "failed",
                        "untouched": {"value": 1},
                        "result": {"access_token": "already-persisted", "other": True},
                    }
                ),
                encoding="utf-8",
            )
            writes = []

            def atomic_write(path, payload):
                writes.append((path, payload))
                path.write_text(json.dumps(payload), encoding="utf-8")

            failure = {
                "node_code": "oauth_token_exchange",
                "public_message": "OAuth Token 交换失败：HTTP 401",
                "technical_summary": "status=401",
            }
            timing = {"elapsed_seconds": 12.5, "segments": [{"code": "email_otp"}]}
            updated = apply_result_json_metadata(
                {},
                data_dir,
                "T002",
                "batch@example.test",
                timing=timing,
                batch_id=" batch-shared ",
                batch_started_at="123",
                failure=failure,
                status="failed",
                atomic_write_json=atomic_write,
                sanitize_failure_detail=lambda value, **_kwargs: str(value),
            )

            self.assertTrue(updated)
            self.assertEqual(len(writes), 1)
            self.assertEqual(writes[0][0], target)
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(payload["untouched"], {"value": 1})
            self.assertEqual(payload["timing"], timing)
            self.assertEqual(payload["result"]["timing"], timing)
            self.assertEqual(payload["batch_id"], "batch-shared")
            self.assertEqual(payload["batch_started_at"], 123)
            self.assertEqual(payload["result"]["batch_id"], "batch-shared")
            self.assertEqual(payload["failure"], failure)
            self.assertEqual(payload["result"]["failure"], failure)
            self.assertEqual(payload["error"], failure["public_message"])
            self.assertEqual(payload["technical_error"], failure["technical_summary"])
            self.assertEqual(payload["result"]["access_token"], "already-persisted")
            self.assertEqual(payload["result"]["other"], True)
            self.assertEqual(timing, {"elapsed_seconds": 12.5, "segments": [{"code": "email_otp"}]})
            self.assertEqual(failure["node_code"], "oauth_token_exchange")

    def test_account_banned_diagnostic_is_sanitized_and_keeps_public_message(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp)
            target = result_json_path({}, data_dir, "T003", "banned@example.test")
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({"result": {}}), encoding="utf-8")
            secret = "private-token"
            sanitizer_calls = []

            def sanitizer(value, *, secrets=(), limit=500):
                sanitizer_calls.append((str(value), tuple(secrets), limit))
                text = str(value)
                for item in secrets:
                    text = text.replace(str(item), "***")
                return text

            def atomic_write(path, payload):
                path.write_text(json.dumps(payload), encoding="utf-8")

            message = "OpenAI 账号已被停用"
            self.assertTrue(
                apply_result_json_metadata(
                    {},
                    data_dir,
                    "T003",
                    "banned@example.test",
                    status="account_banned",
                    account_banned_detail=f"status=403 token={secret}",
                    account_banned_message=message,
                    secrets=(secret,),
                    atomic_write_json=atomic_write,
                    sanitize_failure_detail=sanitizer,
                )
            )
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(payload["error"], message)
            self.assertEqual(payload["technical_error"], message)
            self.assertEqual(
                payload["account_banned_local_diagnostic"],
                "status=403 token=***",
            )
            self.assertNotIn(secret, json.dumps(payload))
            self.assertEqual(sanitizer_calls, [(f"status=403 token={secret}", (secret,), 1000)])

    def test_account_banned_scrubs_nested_provider_details_but_keeps_safe_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp)
            target = result_json_path({}, data_dir, "T003-nested", "banned@example.test")
            target.parent.mkdir(parents=True)
            target.write_text(
                json.dumps(
                    {
                        "phase2_error": "password_verify_failed: deleted or deactivated",
                        "local_oauth_exchange_error": "password_verify_failed: deleted or deactivated",
                        "result": {
                            "error": "password_verify_failed: deleted or deactivated",
                            "technical_error": "password_verify_failed: deleted or deactivated",
                            "phase2_error": "password_verify_failed: deleted or deactivated",
                            "local_oauth_exchange_error": "password_verify_failed: deleted or deactivated",
                            "untouched": "keep",
                            "failure": {
                                "node_code": "account_banned",
                                "public_message": "raw provider detail",
                                "technical_summary": "password_verify_failed: deleted or deactivated",
                                "provider_code": "password_verify_failed",
                                "http_status": 403,
                                "retryable": True,
                            },
                            "codex_chain_events": [
                                {"state": "START", "detail": "real chain"},
                                {
                                    "state": "FAILED",
                                    "detail": "password_verify_failed: deleted or deactivated",
                                    "message": "password_verify_failed: deleted or deactivated",
                                },
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )

            message = "OpenAI 账号已被停用"
            failure = {
                "node_code": "account_banned",
                "public_message": message,
                "technical_summary": "password_verify_failed: deleted or deactivated",
                "provider_code": "password_verify_failed",
                "http_status": 403,
                "retryable": True,
            }

            self.assertTrue(
                apply_result_json_metadata(
                    {},
                    data_dir,
                    "T003-nested",
                    "banned@example.test",
                    failure=failure,
                    status="account_banned",
                    account_banned_detail="HTTP 403 provider=deleted or deactivated",
                    account_banned_message=message,
                    atomic_write_json=lambda path, payload: path.write_text(
                        json.dumps(payload), encoding="utf-8"
                    ),
                    sanitize_failure_detail=lambda value, **_kwargs: str(value),
                )
            )

            payload = json.loads(target.read_text(encoding="utf-8"))
            nested = payload["result"]
            self.assertEqual(payload["error"], message)
            self.assertEqual(payload["technical_error"], message)
            self.assertEqual(payload["phase2_error"], message)
            self.assertEqual(payload["local_oauth_exchange_error"], message)
            self.assertEqual(payload["failure"]["public_message"], message)
            self.assertEqual(payload["failure"]["technical_summary"], "")
            self.assertEqual(payload["failure"]["provider_code"], "password_verify_failed")
            self.assertEqual(payload["failure"]["http_status"], 403)
            self.assertFalse(payload["failure"]["retryable"])
            for key in (
                "error",
                "technical_error",
                "phase2_error",
                "local_oauth_exchange_error",
            ):
                self.assertEqual(nested[key], message)
            self.assertEqual(nested["untouched"], "keep")
            self.assertEqual(nested["failure"]["public_message"], message)
            self.assertEqual(nested["failure"]["technical_summary"], "")
            self.assertEqual(nested["failure"]["provider_code"], "password_verify_failed")
            self.assertEqual(nested["failure"]["http_status"], 403)
            self.assertFalse(nested["failure"]["retryable"])
            self.assertEqual(nested["codex_chain_events"][0]["detail"], "real chain")
            self.assertEqual(nested["codex_chain_events"][1]["detail"], message)
            self.assertEqual(nested["codex_chain_events"][1]["message"], message)
            self.assertEqual(
                payload["account_banned_local_diagnostic"],
                "HTTP 403 provider=deleted or deactivated",
            )
            public_payload = dict(payload)
            public_payload.pop("account_banned_local_diagnostic", None)
            self.assertNotIn("deleted or deactivated", json.dumps(public_payload))

    def test_structured_failure_write_error_is_logged_only_after_sanitizing(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp)
            target = result_json_path({}, data_dir, "T004", "failure@example.test")
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({"result": {}}), encoding="utf-8")
            secret = "mail-password"
            logs = []

            def fail_write(_path, _payload):
                raise OSError(f"permission denied password={secret}")

            def sanitizer(value, *, secrets=(), limit=500):
                self.assertEqual(limit, 500)
                text = str(value)
                for item in secrets:
                    text = text.replace(str(item), "***")
                return text

            updated = apply_result_json_metadata(
                {},
                data_dir,
                "T004",
                "failure@example.test",
                failure={
                    "public_message": "保存失败",
                    "technical_summary": "permission denied",
                },
                secrets=(secret,),
                atomic_write_json=fail_write,
                sanitize_failure_detail=sanitizer,
                logger=lambda message, level: logs.append((message, level)),
            )

            self.assertFalse(updated)
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0][1], "error")
            self.assertIn("password=***", logs[0][0])
            self.assertNotIn(secret, logs[0][0])

    def test_batch_metadata_write_error_is_logged_for_success_result(self):
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp)
            target = result_json_path({}, data_dir, "T005", "success@example.test")
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({"result": {}}), encoding="utf-8")
            logs = []

            updated = apply_result_json_metadata(
                {},
                data_dir,
                "T005",
                "success@example.test",
                batch_id="batch-write-failed",
                atomic_write_json=lambda *_args: (_ for _ in ()).throw(
                    OSError("read-only result directory")
                ),
                sanitize_failure_detail=lambda value, **_kwargs: str(value),
                logger=lambda message, level: logs.append((message, level)),
            )

            self.assertFalse(updated)
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0][1], "error")
            self.assertIn("read-only result directory", logs[0][0])

    def test_no_metadata_does_not_read_or_write_result_file(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            self.assertFalse(
                apply_result_json_metadata(
                    {},
                    temp,
                    "missing",
                    "missing@example.test",
                    atomic_write_json=lambda *_args: calls.append("write"),
                    sanitize_failure_detail=lambda value, **_kwargs: str(value),
                )
            )
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
