from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mac_overrides.mailbox_admin import (
    MailboxAdminService,
    email_from_row,
    generate_totp_code,
    is_importable_mailbox_row,
    mailbox_url_from_row,
    masked_source_row,
    parse_chatgpt_totp_row,
    parse_mailbox_url_totp_row,
    parse_mailbox_url_row,
    parse_oauth_mailbox_row,
    parse_plain_password_mailbox_row,
    password_from_row,
    public_sub2_status,
    public_task_account,
    redact_mailbox_credentials,
    row_id_from_source,
    selected_line_numbers,
    totp_secret_from_row,
    url_credential_secrets,
)
from mac_overrides.mailbox_batch_operations import MailboxBatchOperationManager
from mac_overrides.mailbox_priority_runtime import MailboxNextBatchPriorityStore
from mac_overrides.openai_quota_runtime import OpenAIQuotaSnapshotStore


class FakeStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.config = {
            "pool_path": "pool.txt",
            "state_path": "state.json",
            "results_dir": "results",
        }

    def load(self):
        return dict(self.config)


class FakePoller:
    def __init__(self, code="123456", error: Exception | None = None) -> None:
        self.code = code
        self.error = error
        self.poll_kwargs = None
        self.closed = False

    def poll_code(self, **kwargs):
        self.poll_kwargs = kwargs
        if self.error is not None:
            raise self.error
        return self.code

    def close(self):
        self.closed = True


class MailboxAdminTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = FakeStore(self.root)
        self.logs: list[tuple[str, str]] = []
        self.validations: list[dict] = []
        self.pollers: list[FakePoller] = []
        self.poller_args: list[tuple[tuple, dict]] = []
        self.runtime = {"tasks": []}
        self.progress: dict[str, dict] = {}
        self.clock = 1_000.0

        def validate(config):
            self.validations.append(dict(config))
            return {"ok": True, "entries": len(self._pool_lines())}

        def create_poller(*args, **kwargs):
            self.poller_args.append((args, kwargs))
            poller = FakePoller()
            self.pollers.append(poller)
            return poller

        self.create_poller = create_poller
        self.service = MailboxAdminService(
            self.store,
            validate_pool=validate,
            imap_poller_factory=create_poller,
            runtime_status=lambda _config: self.runtime,
            progress_lookup=self.progress.get,
            is_active_progress=lambda value, status: (
                isinstance(value, dict)
                and value.get("finished_at") is None
                and status not in {"failed", "success", "stopped"}
            ),
            log_fn=lambda message, level: self.logs.append((message, level)),
            now_fn=lambda: self.clock,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_pool(self, text: str) -> None:
        (self.root / "pool.txt").write_text(text, encoding="utf-8")

    def _pool_lines(self) -> list[str]:
        path = self.root / "pool.txt"
        if not path.exists():
            return []
        return [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]

    def _write_state(self, items: dict) -> None:
        (self.root / "state.json").write_text(
            json.dumps({"items": items}, ensure_ascii=False),
            encoding="utf-8",
        )

    def test_row_parsers_preserve_supported_formats(self):
        oauth = "User@Example.COM----mail-pass----client-id----refresh-token"
        totp = "Mfa@Example.com|login-pass|JBSW Y3DP EHPK3PXP"
        dashed_totp = "Mfa2@Example.com--login-pass-2--JBSW Y3DP EHPK3PXP"
        url_row = "Url@Example.com｜https://mail.example.test/messages/private-token"
        url_totp = (
            "UrlMfa@Example.com----"
            "https://mail.example.test/latest?email=urlmfa%40example.com&auth_code=private----"
            "JBSWY3DPEHPK3PXP"
        )

        self.assertEqual(email_from_row(oauth), "user@example.com")
        self.assertEqual(
            parse_oauth_mailbox_row(oauth),
            ("user@example.com", "mail-pass", "client-id", "refresh-token"),
        )
        self.assertEqual(
            parse_chatgpt_totp_row(totp),
            ("mfa@example.com", "login-pass", "JBSWY3DPEHPK3PXP"),
        )
        self.assertEqual(
            parse_chatgpt_totp_row(dashed_totp),
            ("mfa2@example.com", "login-pass-2", "JBSWY3DPEHPK3PXP"),
        )
        self.assertEqual(password_from_row(totp), "login-pass")
        self.assertEqual(password_from_row(dashed_totp), "login-pass-2")
        plain = "Plain@Example.com--plain-pass"
        four_dash_plain = "Four@Example.com----four-pass"
        pipe_plain = "PipePlain@Example.com|pipe-pass"
        self.assertEqual(
            parse_plain_password_mailbox_row(plain),
            ("plain@example.com", "plain-pass", "--"),
        )
        self.assertEqual(
            parse_plain_password_mailbox_row(four_dash_plain),
            ("four@example.com", "four-pass", "----"),
        )
        self.assertEqual(
            parse_plain_password_mailbox_row(pipe_plain),
            ("pipeplain@example.com", "pipe-pass", "|"),
        )
        self.assertEqual(password_from_row(plain), "plain-pass")
        self.assertEqual(masked_source_row(plain), "plain@example.com--********")
        self.assertTrue(is_importable_mailbox_row(oauth))
        self.assertTrue(is_importable_mailbox_row(totp))
        self.assertTrue(is_importable_mailbox_row(dashed_totp))
        self.assertTrue(is_importable_mailbox_row(plain))
        self.assertTrue(is_importable_mailbox_row(four_dash_plain))
        self.assertTrue(is_importable_mailbox_row(pipe_plain))
        self.assertEqual(
            parse_mailbox_url_row(url_row).mailbox_url,
            "https://mail.example.test/messages/private-token",
        )
        self.assertTrue(is_importable_mailbox_row(url_row))
        self.assertEqual(password_from_row(url_row), "")
        self.assertEqual(masked_source_row(url_row), "url@example.com｜********")
        self.assertEqual(
            parse_mailbox_url_totp_row(url_totp),
            (
                "urlmfa@example.com",
                "https://mail.example.test/latest?email=urlmfa%40example.com&auth_code=private",
                "JBSWY3DPEHPK3PXP",
            ),
        )
        self.assertTrue(is_importable_mailbox_row(url_totp))
        self.assertEqual(password_from_row(url_totp), "")
        self.assertEqual(
            mailbox_url_from_row(url_totp),
            "https://mail.example.test/latest?email=urlmfa%40example.com&auth_code=private",
        )
        self.assertEqual(totp_secret_from_row(url_totp), "JBSWY3DPEHPK3PXP")
        self.assertEqual(
            masked_source_row(url_totp),
            "urlmfa@example.com----********----********",
        )
        self.assertEqual(
            masked_source_row(dashed_totp),
            "mfa2@example.com--********--********",
        )
        self.assertFalse(is_importable_mailbox_row("# user@example.com----secret"))
        self.assertTrue(is_importable_mailbox_row("user@example.com----password"))
        self.assertFalse(is_importable_mailbox_row("user@example.com|password|INVALID018"))
        self.assertIsNone(parse_plain_password_mailbox_row(url_row))
        self.assertIsNone(parse_plain_password_mailbox_row(totp))
        self.assertIsNone(parse_plain_password_mailbox_row(oauth))
        self.assertIsNone(
            parse_oauth_mailbox_row(
                "prefix user@example.com----password----client-id----refresh-token"
            )
        )
        self.assertIsNone(
            parse_oauth_mailbox_row(
                "user@example.com----password----client-id----refresh-token----extra"
            )
        )
        self.assertEqual(selected_line_numbers({"line_nos": ["3", 1, 3, 0, "bad"]}), [1, 3])

    def test_online_mailbox_snapshot_uses_latest_url_and_excludes_other_secrets(self):
        old_url = "https://mail.example.test/inbox/old-private"
        new_url = "https://mail.example.test/inbox/new-private"
        self._write_pool("\n".join((
            f"User@Example.com---{old_url}",
            "oauth@example.com----mail-pass----client-id----refresh-token",
            "totp@example.com|login-pass|JBSWY3DPEHPK3PXP",
            f"user@example.com----{new_url}----JBSWY3DPEHPK3PXP",
            "other@example.com|https://mail.example.test/inbox/other-private",
        )))

        snapshot = self.service.online_mailbox_snapshot()

        self.assertEqual(snapshot["eligible"], 2)
        self.assertEqual(snapshot["skipped"], 2)
        self.assertEqual(snapshot["local_duplicates"], 1)
        by_email = {item["email"]: item for item in snapshot["items"]}
        self.assertEqual(by_email["user@example.com"]["mailbox_url"], new_url)
        serialized = json.dumps(snapshot)
        for secret in ("mail-pass", "client-id", "refresh-token", "login-pass", "JBSWY3DPEHPK3PXP"):
            self.assertNotIn(secret, serialized)

    def test_public_sub2_status_recomputes_legacy_classification_flags(self):
        fixtures = (
            (
                {"kind": "unauthorized", "status_code": 401, "is_error": False},
                {"is_error": True, "is_abnormal": True, "is_test_failure": False, "needs_rerun": True},
            ),
            (
                {"kind": "rate_limited", "status_code": 429, "is_error": True, "needs_rerun": True},
                {"is_error": False, "is_abnormal": False, "is_test_failure": False, "needs_rerun": False},
            ),
            (
                {"kind": "not_found", "status_code": 404, "is_error": False},
                {"is_error": True, "is_abnormal": False, "is_test_failure": True, "needs_rerun": True},
            ),
        )
        for value, expected in fixtures:
            with self.subTest(value=value):
                status = public_sub2_status(value, linked=True)
                self.assertEqual(
                    {key: status[key] for key in expected},
                    expected,
                )

    def test_list_mailboxes_enriches_latest_successful_sub2_account_snapshot(self):
        row = "linked@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        fixtures = (
            ("old-success.json", "success", 100, "101"),
            ("new-success.json", "success", 200, "202"),
            ("newer-failure.json", "failed", 300, "303"),
        )
        for name, status, created_at, account_id in fixtures:
            (results / name).write_text(
                json.dumps(
                    {
                        "email": "linked@example.com",
                        "status": status,
                        "created_at": created_at,
                        "result": {"sub2api_account_id": account_id},
                    }
                ),
                encoding="utf-8",
            )
        looked_up = []
        self.service.sub2_status_lookup = lambda account_id: looked_up.append(account_id) or {
            "kind": "unauthorized",
            "status_code": 401,
            "label": "401 Token失效",
            "summary": "expired",
            "tested_at": 999,
            "is_error": True,
            "needs_rerun": True,
            "private": "must-not-leak",
        }

        public = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(looked_up, ["202"])
        self.assertEqual(
            public["sub2_status"],
            {
                "kind": "unauthorized",
                "status_code": 401,
                "label": "401 Token失效",
                "summary": "expired",
                "tested_at": 999,
                "is_error": True,
                "is_abnormal": True,
                "is_test_failure": False,
                "needs_rerun": True,
            },
        )
        self.assertNotIn("private", json.dumps(public, ensure_ascii=False))

    def test_relogin_resolver_accepts_totp_url_and_outlook_oauth_rows(self):
        rows = [
            "totp@example.com|login-pass|JBSWY3DPEHPK3PXP",
            "url@example.com|https://mail.example.test/messages/private-token",
            "oauth@example.com----mail-pass----12345678-1234-1234-1234-123456789abc----refresh-token",
        ]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        for index, row in enumerate(rows, start=1):
            email = email_from_row(row)
            (results / f"success-{index}.json").write_text(
                json.dumps({
                    "email": email,
                    "status": "success",
                    "created_at": 100 + index,
                    "result": {"sub2api_account_id": str(500 + index)},
                }),
                encoding="utf-8",
            )
        self.service.openai_status_lookup = lambda account_id: {
            "kind": "unauthorized" if account_id != "502" else "not_found",
            "status_code": 401 if account_id != "502" else 404,
        }

        result = self.service.resolve_relogin_rows({
            "rows": [
                {"row_id": row_id_from_source(row), "line_no": index}
                for index, row in enumerate(rows, start=1)
            ]
        })

        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 3)
        self.assertEqual(
            [item["sub2api_account_id"] for item in result["items"]],
            ["501", "502", "503"],
        )
        serialized = json.dumps(result, ensure_ascii=False)
        for secret in ("login-pass", "JBSWY3DPEHPK3PXP", "private-token", "mail-pass", "refresh-token"):
            self.assertNotIn(secret, serialized)

    def test_relogin_resolver_rejects_stale_or_no_longer_failed_binding(self):
        row = "rerun@example.com|login-pass|JBSWY3DPEHPK3PXP"
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "success.json").write_text(
            json.dumps({
                "email": "rerun@example.com",
                "status": "success",
                "created_at": 100,
                "result": {"sub2api_account_id": "501"},
            }),
            encoding="utf-8",
        )

        stale = self.service.resolve_relogin_rows({
            "rows": [{"row_id": "0" * 64, "line_no": 1}],
        })
        self.service.openai_status_lookup = lambda _account_id: {
            "kind": "healthy",
            "status_code": 200,
        }
        healthy = self.service.resolve_relogin_rows({
            "rows": [{"row_id": row_id_from_source(row), "line_no": 1}],
        })

        self.assertEqual(stale["code"], "mailbox_rows_stale")
        self.assertEqual(healthy["code"], "relogin_not_required")

    def test_relogin_resolver_uses_openai_account_id_for_direct_status(self):
        row = "rerun@example.com|login-pass|JBSWY3DPEHPK3PXP"
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "success.json").write_text(
            json.dumps({
                "email": "rerun@example.com",
                "status": "success",
                "created_at": 100,
                "result": {
                    "sub2api_account_id": "sub2-row-501",
                    "local_oauth": {
                        "tokens": {
                            "access_token": "private-access-token",
                            "chatgpt_account_id": "openai-account-501",
                        }
                    },
                },
            }),
            encoding="utf-8",
        )
        lookups = []
        self.service.openai_status_lookup = lambda account_id: lookups.append(account_id) or {
            "kind": "unauthorized" if account_id == "openai-account-501" else "untested",
            "status_code": 401 if account_id == "openai-account-501" else None,
        }

        result = self.service.resolve_relogin_rows({
            "rows": [{"row_id": row_id_from_source(row), "line_no": 1}],
        })

        self.assertTrue(result["ok"])
        self.assertEqual(lookups, ["openai-account-501"])
        self.assertEqual(result["items"][0]["sub2api_account_id"], "sub2-row-501")
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("private-access-token", serialized)
        self.assertNotIn("openai-account-501", serialized)

    def test_list_mailboxes_marks_imported_without_remote_upload_as_not_ready(self):
        row = "imported@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(row + "\n")
        self._write_state({})
        looked_up = []
        self.service.openai_status_lookup = lambda account_id: looked_up.append(account_id)

        public = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(public["sub2_status"]["kind"], "not_ready")
        self.assertEqual(public["sub2_status"]["label"], "未上传")
        self.assertFalse(public["sub2_status"]["is_error"])
        self.assertEqual(looked_up, [])

    def test_list_mailboxes_restores_persisted_openai_quota_snapshot(self):
        row = "quota@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "success.json").write_text(
            json.dumps(
                {
                    "email": "quota@example.com",
                    "status": "success",
                    "task_id": "task-quota",
                    "created_at": 100,
                    "result": {
                        "sub2api_account_id": "legacy-sub2-id",
                        "local_oauth": {
                            "tokens": {
                                "access_token": "private-access-token",
                                "chatgpt_account_id": "private-account-id",
                            }
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        looked_up = []
        openai_lookups = []
        self.service.openai_status_lookup = lambda account_id: openai_lookups.append(account_id) or (
            {
                "kind": "healthy",
                "status_code": 200,
                "label": "200 健康",
                "tested_at": 100,
            }
            if account_id == "legacy-sub2-id"
            else {"kind": "untested", "label": "未测试"}
        )
        self.service.openai_quota_status_lookup = lambda account_id: looked_up.append(account_id) or {
            "status": "error",
            "error": "查询 OpenAI 额度失败：网络不可用",
            "queried_at": 200,
            "quota_5h": {"remaining_percent": 80, "queried_at": 100},
            "quota_7d": {"remaining_percent": 40, "queried_at": 100},
        }

        public = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(looked_up, ["private-account-id"])
        self.assertEqual(openai_lookups, ["private-account-id", "legacy-sub2-id"])
        self.assertEqual(public["sub2_status"]["kind"], "healthy")
        self.assertEqual(public["quota_status"], "error")
        self.assertEqual(public["quota_5h"]["remaining_percent"], 80)
        self.assertEqual(public["quota_7d"]["remaining_percent"], 40)
        serialized = json.dumps(public, ensure_ascii=False)
        self.assertNotIn("private-access-token", serialized)
        self.assertNotIn("private-account-id", serialized)

    def test_consumed_internal_reason_is_hidden_but_history_is_preserved(self):
        row = "done@example.com|login-pass|JBSWY3DPEHPK3PXP"
        self._write_pool(row + "\n")
        self._write_state(
            {
                "done": {
                    "email": "done@example.com",
                    "line_no": 1,
                    "status": "consumed",
                    "reason": "sub2_uploaded",
                    "history": [
                        {"event": "consumed", "reason": "sub2_uploaded", "at": 900},
                    ],
                }
            }
        )

        public = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(public["status"], "consumed")
        self.assertEqual(public["reason"], "")
        self.assertEqual(public["error"], "")
        self.assertEqual(public["technical_error"], "")
        saved = json.loads((self.root / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["items"]["done"]["reason"], "sub2_uploaded")
        self.assertEqual(saved["items"]["done"]["history"][0]["reason"], "sub2_uploaded")

    def test_internal_reason_from_legacy_result_is_not_returned(self):
        row = "done@example.com|login-pass|JBSWY3DPEHPK3PXP"
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "done.json").write_text(
            json.dumps(
                {
                    "email": "done@example.com",
                    "status": "success",
                    "technical_error": "sub2_uploaded",
                }
            ),
            encoding="utf-8",
        )

        public = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(public["error"], "")
        self.assertEqual(public["technical_error"], "")

    def test_sub2_batch_validates_all_stable_bindings_before_calling_tester(self):
        rows = [
            "one@example.com----pass-one----client-one----refresh-one",
            "two@example.com|pass|JBSWY3DPEHPK3PXP",
        ]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "one.json").write_text(
            json.dumps(
                {
                    "email": "one@example.com",
                    "status": "success",
                    "created_at": 100,
                    "result": {"sub2api_account_id": "501"},
                }
            ),
            encoding="utf-8",
        )
        captured = []
        self.service.sub2_batch_tester = lambda selected: captured.extend(selected) or {
            "ok": True,
            "tested": 1,
            "unlinked": 1,
            "results": [],
        }
        payload = {
            "rows": [
                {"row_id": row_id_from_source(rows[0]), "line_no": 1},
                {"row_id": row_id_from_source(rows[1]), "line_no": 2},
            ]
        }

        result = self.service.sub2_test(payload)

        self.assertTrue(result["ok"])
        self.assertEqual(
            captured,
            [
                {
                    "row_id": row_id_from_source(rows[0]),
                    "line_no": 1,
                    "email": "one@example.com",
                    "sub2api_account_id": "501",
                },
                {
                    "row_id": row_id_from_source(rows[1]),
                    "line_no": 2,
                    "email": "two@example.com",
                    "sub2api_account_id": "",
                },
            ],
        )
        stale = self.service.sub2_test(
            {
                "rows": [
                    {"row_id": row_id_from_source(rows[0]), "line_no": 1},
                    {"row_id": "0" * 64, "line_no": 2},
                ]
            }
        )
        self.assertEqual(stale["code"], "mailbox_rows_stale")
        self.assertEqual(len(captured), 2)

    def test_query_openai_quotas_uses_stable_bindings_and_returns_only_public_fields(self):
        rows = [
            "one@example.com----pass-one----client-one----refresh-one",
            "two@example.com----pass-two----client-two----refresh-two",
        ]
        self._write_pool("\n".join(rows) + "\n")
        results = self.root / "results"
        results.mkdir()
        for index, row in enumerate(rows, start=1):
            email = email_from_row(row)
            (results / f"{index}.json").write_text(
                json.dumps({
                    "email": email,
                    "status": "success",
                    "task_id": f"task-{index}",
                    "created_at": index,
                    "result": {
                        "access_token": f"private-access-{index}",
                        "chatgpt_account_id": f"private-account-{index}",
                    },
                }),
                encoding="utf-8",
            )
        captured = []

        def query(document, proxy):
            captured.append((document["task_id"], proxy))
            return {
                "status": "ok",
                "node_code": "openai_quota",
                "node_label": "查询 OpenAI 额度",
                "quota_5h": {"remaining_percent": 80},
                "quota_7d": {"remaining_percent": 40},
                "queried_at": 1000,
            }

        self.service.openai_quota_query = query
        stored = []

        def store_quota(account_id, value):
            stored.append((account_id, dict(value)))
            return value

        self.service.openai_quota_status_store = store_quota
        payload = {
            "rows": [
                {"row_id": row_id_from_source(row), "line_no": index}
                for index, row in enumerate(rows, start=1)
            ]
        }

        result = self.service.query_openai_quotas(payload)

        self.assertTrue(result["ok"])
        self.assertEqual(result["queried"], 2)
        self.assertEqual(sorted(captured), [("task-1", ""), ("task-2", "")])
        self.assertEqual(sorted(item[0] for item in stored), ["private-account-1", "private-account-2"])
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("private-access", serialized)
        self.assertNotIn("private-account", serialized)
        self.assertEqual(
            [
                (
                    item["line_no"],
                    item["status"],
                    item["quota_5h"]["remaining_percent"],
                    item["quota_7d"]["remaining_percent"],
                )
                for item in result["results"]
            ],
            [
                (1, "ok", 80, 40),
                (2, "ok", 80, 40),
            ],
        )

    def test_quota_without_account_id_persists_by_row_and_survives_reload(self):
        row = "missing-id@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "missing-id.json").write_text(
            json.dumps({
                "email": "missing-id@example.com",
                "status": "success",
                "task_id": "task-missing-id",
                "created_at": 1,
                "result": {"access_token": "private-access-without-account-id"},
            }),
            encoding="utf-8",
        )
        snapshot_path = self.root / "quota-snapshots.json"
        snapshot_store = OpenAIQuotaSnapshotStore(snapshot_path)
        self.service.openai_quota_query = lambda *_args: self.fail("query must not run")
        self.service.openai_quota_status_store = snapshot_store.put
        self.service.openai_quota_status_lookup = OpenAIQuotaSnapshotStore(
            snapshot_path
        ).status_for

        result = self.service.query_openai_quotas({
            "rows": [{"row_id": row_id_from_source(row), "line_no": 1}],
        })
        public = self.service.list_mailboxes()["rows"][0]

        self.assertTrue(result["ok"])
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["results"][0]["code"], "openai_quota_account_id_missing")
        self.assertEqual(public["quota_status"], "error")
        self.assertEqual(public["quota_error"], result["results"][0]["error"])
        self.assertIsNone(public["quota_5h"])
        self.assertIsNone(public["quota_7d"])
        serialized = snapshot_path.read_text(encoding="utf-8")
        self.assertNotIn("private-access-without-account-id", serialized)
        self.assertNotIn("missing-id@example.com", serialized)

    def test_quota_missing_result_is_saved_as_a_row_failure(self):
        row = "missing-result@example.com----mail-pass----client-id----refresh-token"
        row_id = row_id_from_source(row)
        self._write_pool(row + "\n")
        self._write_state({
            row_id: {
                "email": "missing-result@example.com",
                "line_no": 1,
                "status": "consumed",
            },
        })
        snapshot_path = self.root / "quota-snapshots.json"
        snapshot_store = OpenAIQuotaSnapshotStore(snapshot_path)
        self.service.openai_quota_query = lambda *_args: self.fail("query must not run")
        self.service.openai_quota_status_store = snapshot_store.put
        self.service.openai_quota_status_lookup = OpenAIQuotaSnapshotStore(
            snapshot_path
        ).status_for

        result = self.service.query_openai_quotas({
            "rows": [{"row_id": row_id, "line_no": 1}],
        })
        public = self.service.list_mailboxes()["rows"][0]

        self.assertTrue(result["ok"])
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["results"][0]["code"], "openai_quota_result_missing")
        self.assertEqual(public["quota_status"], "error")
        self.assertIn("本地成功结果缺失", public["quota_error"])

    def test_background_quota_row_is_visible_before_slow_peer_finishes(self):
        rows = [
            "one@example.com----pass-one----client-one----refresh-one",
            "two@example.com----pass-two----client-two----refresh-two",
        ]
        self._write_pool("\n".join(rows) + "\n")
        results = self.root / "results"
        results.mkdir()
        for index, row in enumerate(rows, start=1):
            (results / f"{index}.json").write_text(
                json.dumps({
                    "email": email_from_row(row),
                    "status": "success",
                    "task_id": f"task-{index}",
                    "created_at": index,
                    "result": {
                        "access_token": f"private-access-{index}",
                        "chatgpt_account_id": f"private-account-{index}",
                    },
                }),
                encoding="utf-8",
            )

        second_started = threading.Event()
        release_second = threading.Event()
        first_persisted = threading.Event()
        snapshot_path = self.root / "quota-snapshots.json"
        snapshot_store = OpenAIQuotaSnapshotStore(snapshot_path)

        def query(document, _proxy):
            if document["task_id"] == "task-2":
                second_started.set()
                release_second.wait(2)
            suffix = int(document["task_id"].rsplit("-", 1)[1])
            return {
                "status": "ok",
                "quota_5h": {"remaining_percent": 80 + suffix},
                "quota_7d": {"remaining_percent": 40 + suffix},
            }

        def store(account_id, value):
            stored = snapshot_store.put(account_id, value)
            if account_id == "private-account-1":
                first_persisted.set()
            return stored

        self.service.openai_quota_query = query
        self.service.openai_quota_status_store = store
        self.service.openai_quota_status_lookup = OpenAIQuotaSnapshotStore(
            snapshot_path
        ).status_for
        bindings = [
            {"row_id": row_id_from_source(row), "line_no": index}
            for index, row in enumerate(rows, start=1)
        ]
        manager = MailboxBatchOperationManager(chunk_size=5)
        operation, _created = manager.start("quota", bindings, self.service.query_openai_quotas)
        try:
            self.assertTrue(second_started.wait(1))
            self.assertTrue(first_persisted.wait(1))
            for _attempt in range(100):
                if manager.snapshot()["completed"] == 1:
                    break
                threading.Event().wait(0.01)
            self.assertEqual(manager.snapshot()["status"], "running")
            self.assertEqual(manager.snapshot()["completed"], 1)
            listed = self.service.list_mailboxes()["rows"]
            self.assertEqual(listed[0]["quota_5h"]["remaining_percent"], 81)
            self.assertEqual(listed[0]["quota_7d"]["remaining_percent"], 41)
            self.assertIsNone(listed[1]["quota_5h"])
            self.assertIsNone(listed[1]["quota_7d"])
        finally:
            release_second.set()

        completed = manager.wait(operation["job_id"], 2)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["succeeded"], 2)

    def test_sub2_batch_accepts_more_than_twenty_rows_for_queued_chunk_processing(self):
        rows = [f"user{index}@example.com|pass-{index}|JBSWY3DPEHPK3PXP" for index in range(1, 22)]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state({})
        called = []

        def tester(selected):
            called.append(list(selected))
            return {
                "ok": True,
                "tested": len(selected),
                "results": [],
            }

        self.service.sub2_batch_tester = tester
        result = self.service.sub2_test(
            {
                "rows": [
                    {"row_id": row_id_from_source(row), "line_no": index}
                    for index, row in enumerate(rows, start=1)
                ]
            }
        )

        self.assertTrue(result["ok"])
        self.assertEqual(len(called), 1)
        self.assertEqual(len(called[0]), 21)

    def test_openai_test_uses_only_success_result_and_marks_unuploaded_row(self):
        rows = [
            "ready@example.com----mail-pass----client-id----refresh-token",
            "new@example.com----mail-pass-2----client-id-2----refresh-token-2",
        ]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "ready.json").write_text(
            json.dumps(
                {
                    "email": "ready@example.com",
                    "status": "success",
                    "created_at": 100,
                    "result": {
                        "sub2api_account_id": "remote-1",
                        "local_oauth": {
                            "tokens": {
                                "access_token": "private-access",
                                "chatgpt_account_id": "chatgpt-account-1",
                            }
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        captured = []

        def tester(selected, proxy):
            captured.extend(selected)
            self.assertEqual(proxy, "")
            return {
                "ok": True,
                "tested": 1,
                "unlinked": 1,
                "not_ready": 1,
                "results": [],
            }

        self.service.openai_direct_batch_tester = tester
        result = self.service.openai_test(
            {
                "rows": [
                    {"row_id": row_id_from_source(row), "line_no": index}
                    for index, row in enumerate(rows, start=1)
                ]
            }
        )

        self.assertTrue(result["ok"])
        self.assertEqual(len(captured), 2)
        self.assertEqual(captured[0]["sub2api_account_id"], "remote-1")
        self.assertEqual(captured[0]["openai_status_id"], "chatgpt-account-1")
        self.assertIn("private-access", json.dumps(captured[0]))
        self.assertEqual(captured[1]["sub2api_account_id"], "")
        self.assertEqual(captured[1]["openai_status_id"], "")
        self.assertEqual(captured[1]["document"], {})

    def test_openai_test_resolves_sha_and_legacy_line_state_keys(self):
        rows = [
            "sha@example.com----mail-pass----client-id----refresh-token",
            "legacy@example.com----mail-pass-2----client-id-2----refresh-token-2",
        ]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state({
            row_id_from_source(rows[0]): {
                "email": "sha@example.com",
                "line_no": 99,
                "status": "available",
                "reason": "manual_restore",
            },
            "legacy-state": {
                "line_no": 2,
                "status": "available",
                "reason": "manual_restore",
            },
        })
        results = self.root / "results"
        results.mkdir()
        for index, row in enumerate(rows, start=1):
            (results / f"ready-{index}.json").write_text(
                json.dumps({
                    "email": email_from_row(row),
                    "status": "success",
                    "created_at": index,
                    "result": {
                        "access_token": f"private-access-{index}",
                        "chatgpt_account_id": f"private-account-{index}",
                    },
                }),
                encoding="utf-8",
            )
        captured = []
        self.service.openai_direct_batch_tester = lambda selected, _proxy: captured.extend(selected) or {
            "ok": True,
            "tested": 0,
            "not_ready": 2,
            "results": [],
        }

        result = self.service.openai_test({
            "rows": [
                {"row_id": row_id_from_source(row), "line_no": index}
                for index, row in enumerate(rows, start=1)
            ]
        })

        self.assertTrue(result["ok"])
        self.assertEqual([item["document"] for item in captured], [{}, {}])
        self.assertEqual([item["openai_status_id"] for item in captured], ["", ""])


    def test_list_mailboxes_combines_state_results_and_latest_live_progress(self):
        rows = [
            "running@example.com----run-pass----client-a----refresh-a",
            "done@example.com----done-pass----client-b----refresh-b",
            "restored@example.com|login-pass|JBSWY3DPEHPK3PXP",
        ]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state(
            {
                "running": {
                    "email": "running@example.com",
                    "line_no": 1,
                    "status": "available",
                    "updated_at": 900,
                },
                "done": {
                    "email": "done@example.com",
                    "line_no": 2,
                    "status": "consumed",
                    "updated_at": 910,
                },
                "restored": {
                    "email": "restored@example.com",
                    "line_no": 3,
                    "status": "available",
                    "reason": "manual_restore",
                    "updated_at": 920,
                },
            }
        )
        results = self.root / "results"
        results.mkdir()
        (results / "done.json").write_text(
            json.dumps(
                {
                    "email": "done@example.com",
                    "status": "success",
                    "task_id": "T-done",
                    "created_at": 950,
                    "result": {
                        "sms_cost_usd": 0.05,
                        "sms_cost_cny": 0.36,
                        "timing": {
                            "started_at": 900,
                            "finished_at": 950,
                            "elapsed_seconds": 50,
                            "stages": [],
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        (results / "restored.json").write_text(
            json.dumps(
                {
                    "email": "restored@example.com",
                    "status": "failed",
                    "task_id": "T-old",
                    "error": "old failure login-pass JBSWY3DPEHPK3PXP",
                    "created_at": 940,
                }
            ),
            encoding="utf-8",
        )
        self.runtime = {
            "tasks": [
                {
                    "task_id": "T-old-running",
                    "email": "running@example.com",
                    "status": "authorizing",
                    "updated_at": 930,
                },
                {
                    "task_id": "T-current",
                    "email": "running@example.com",
                    "status": "authorizing",
                    "updated_at": 960,
                    "batch_id": "batch-live",
                    "batch_started_at": 925,
                },
            ]
        }
        self.progress["T-old-running"] = {
            "code": "queue_waiting",
            "label": "排队等待",
            "group": "queue",
            "entered_at": 900,
            "finished_at": None,
        }
        self.progress["T-current"] = {
            "code": "sms_waiting",
            "label": "等待短信验证码",
            "group": "sms",
            "entered_at": 955,
            "finished_at": None,
            "timing": {
                "started_at": 940,
                "finished_at": None,
                "elapsed_seconds": 20,
                "stages": [],
                "segments": [
                    {
                        "code": "phone_slot_waiting",
                        "label": "等待手机号提交槽",
                        "elapsed_seconds": 0.75,
                        "visits": 1,
                    }
                ],
            },
            "mailbox_password": "must-not-leak",
        }

        result = self.service.rows()

        self.assertEqual(
            result["counts"],
            {"total": 3, "available": 1, "running": 1, "success": 1, "failed": 0},
        )
        self.assertEqual([row["line_no"] for row in result["rows"]], [1, 2, 3])
        running, done, restored = result["rows"]
        self.assertEqual((running["status"], running["task_id"]), ("running", "T-current"))
        self.assertEqual((running["batch_id"], running["batch_started_at"]), ("batch-live", 925))
        self.assertEqual(running["progress"]["code"], "sms_waiting")
        self.assertEqual(running["timing"], running["progress"]["timing"])
        self.assertEqual(
            running["timing"]["segments"][0]["code"],
            "phone_slot_waiting",
        )
        self.assertNotIn("mailbox_password", running["progress"])
        self.assertEqual((done["status"], done["sms_cost_usd"], done["sms_cost_cny"]), ("consumed", 0.05, 0.36))
        self.assertEqual(done["timing"]["elapsed_seconds"], 50)
        self.assertEqual(restored["task_id"], "")
        self.assertEqual(restored["error"], "")
        self.assertEqual(restored["password"], "********")
        self.assertEqual(restored["source_row"], "restored@example.com|********|********")
        public_payload = json.dumps(result, ensure_ascii=False)
        for secret in ("run-pass", "done-pass", "login-pass", "refresh-a", "JBSWY3DPEHPK3PXP"):
            self.assertNotIn(secret, public_payload)

    def test_legacy_mailboxes_keep_pool_order_and_resolve_only_success_results(self):
        older = "older@example.com----pass-a----client-a----refresh-a"
        newer = "newer@example.com----pass-b----client-b----refresh-b"
        failed = "failed@example.com----pass-c----client-c----refresh-c"
        rows = [older, newer, failed]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        fixtures = (
            ("older.json", "older@example.com", "success", "task-old", 100, "batch-old"),
            ("newer.json", "newer@example.com", "success", "task-new", 300, "batch-new"),
            ("failed.json", "failed@example.com", "failed", "task-failed", 400, "batch-failed"),
        )
        for name, email, status, task_id, batch_started_at, batch_id in fixtures:
            (results / name).write_text(
                json.dumps({
                    "email": email,
                    "status": status,
                    "task_id": task_id,
                    "created_at": batch_started_at + 10,
                    "batch_id": batch_id,
                    "batch_started_at": batch_started_at,
                    "result": {
                        "email": email,
                        "access_token": f"access-{task_id}",
                        "refresh_token": f"refresh-{task_id}",
                        "id_token": f"id-{task_id}",
                    },
                }),
                encoding="utf-8",
            )

        listed = self.service.list_mailboxes()["rows"]

        self.assertEqual([row["email"] for row in listed], [
            "older@example.com",
            "newer@example.com",
            "failed@example.com",
        ])
        self.assertEqual(listed[1]["batch_id"], "batch-new")
        self.assertEqual(listed[1]["batch_started_at"], 300)
        self.assertNotIn("_result_file", json.dumps(listed))

        selected = self.service.selected_success_results({
            "rows": [
                {"row_id": row_id_from_source(newer), "line_no": 2},
                {"row_id": row_id_from_source(failed), "line_no": 3},
            ],
        })

        self.assertTrue(selected["ok"])
        self.assertEqual(selected["skipped"], 1)
        self.assertEqual(selected["items"][0]["task_id"], "task-new")
        self.assertEqual(selected["items"][0]["result_file"], (results / "newer.json").resolve())

    def test_new_import_batches_sort_first_and_preserve_pasted_order(self):
        legacy = [
            "legacy-one@example.com----legacy-pass-one----legacy-client-one----legacy-refresh-one",
            "legacy-two@example.com----legacy-pass-two----legacy-client-two----legacy-refresh-two",
        ]
        first_batch = [
            "first-one@example.com----first-pass-one----first-client-one----first-refresh-one",
            "first-two@example.com----first-pass-two----first-client-two----first-refresh-two",
        ]
        second_batch = [
            "second-one@example.com----second-pass-one----second-client-one----second-refresh-one",
            "second-two@example.com----second-pass-two----second-client-two----second-refresh-two",
        ]
        self._write_pool("\n".join(legacy) + "\n")
        self._write_state({})
        self.assertEqual(
            [row["email"] for row in self.service.list_mailboxes()["rows"]],
            ["legacy-one@example.com", "legacy-two@example.com"],
        )

        self.service.append("\n".join(first_batch))
        self.service.append("\n".join(second_batch))
        listed = self.service.list_mailboxes()["rows"]

        self.assertEqual(
            [row["email"] for row in listed],
            [
                "second-one@example.com",
                "second-two@example.com",
                "first-one@example.com",
                "first-two@example.com",
                "legacy-one@example.com",
                "legacy-two@example.com",
            ],
        )
        sidecar_text = (self.root / "mailbox_import_order.json").read_text(encoding="utf-8")
        for secret in (*legacy, *first_batch, *second_batch, "example.com", "pass"):
            self.assertNotIn(secret, sidecar_text)
        sidecar = json.loads(sidecar_text)
        self.assertEqual(sidecar["version"], 1)
        self.assertEqual(sidecar["next_batch"], 2)
        self.assertEqual(len(sidecar["entries"]), 6)
        self.assertEqual(os.stat(self.root / "mailbox_import_order.json").st_mode & 0o777, 0o600)

    def test_task_updates_do_not_reorder_import_batches_and_external_append_is_newest(self):
        old = "old@example.com----old-pass----old-client----old-refresh"
        imported = "imported@example.com----imported-pass----imported-client----imported-refresh"
        external = "external@example.com----external-pass----external-client----external-refresh"
        self._write_pool(old + "\n")
        self._write_state({})
        self.service.list_mailboxes()
        self.service.append(imported)

        results = self.root / "results"
        results.mkdir()
        (results / "old-new-task.json").write_text(
            json.dumps({
                "email": "old@example.com",
                "status": "failed",
                "created_at": 9_999_999,
                "batch_started_at": 9_999_000,
                "task_id": "old-late-task",
            }),
            encoding="utf-8",
        )
        self.assertEqual(
            [row["email"] for row in self.service.list_mailboxes()["rows"]],
            ["imported@example.com", "old@example.com"],
        )

        self._write_pool("\n".join([old, imported, external]) + "\n")
        self.assertEqual(
            [row["email"] for row in self.service.list_mailboxes()["rows"]],
            ["external@example.com", "imported@example.com", "old@example.com"],
        )

        stale = self.service.selected_success_results({
            "rows": [{"row_id": row_id_from_source(old), "line_no": 2}],
        })
        self.assertFalse(stale["ok"])
        self.assertEqual(stale["code"], "mailbox_rows_stale")

    def test_public_rows_use_stable_full_source_row_sha256_ids(self):
        rows = [
            "one@example.com----pass-one",
            "one@example.com----pass-two",
        ]
        self._write_pool("\n".join(rows) + "\n")

        first = self.service.list_mailboxes()["rows"]
        second = self.service.list_mailboxes()["rows"]

        expected = [hashlib.sha256(row.encode("utf-8")).hexdigest() for row in rows]
        self.assertEqual([row["row_id"] for row in first], expected)
        self.assertEqual([row["row_id"] for row in second], expected)
        self.assertNotEqual(first[0]["row_id"], first[1]["row_id"])
        self.assertTrue(all(len(row["row_id"]) == 64 for row in first))
        self.assertEqual(row_id_from_source(rows[0]), expected[0])

    def test_public_task_account_drops_recovered_composite_credentials(self):
        source_row = "user@example.test----mail-pass----client-id----refresh-token"
        account = public_task_account(
            {
                "email": "",
                "account": "user@example.test---mail-pass---client-id---refresh-token",
            },
            source_row,
        )

        self.assertEqual(account, "user@example.test")
        self.assertNotIn("mail-pass", account)
        self.assertNotIn("client-id", account)
        self.assertNotIn("refresh-token", account)

    def test_proxy_credential_fragments_cover_encoded_and_decoded_forms(self):
        proxy = "http://user%40example.test:p%40ss-word@127.0.0.1:7890"
        secrets = url_credential_secrets(proxy)

        self.assertIn(proxy, secrets)
        self.assertIn("user%40example.test", secrets)
        self.assertIn("user@example.test", secrets)
        self.assertIn("p%40ss-word", secrets)
        self.assertIn("p@ss-word", secrets)

    def test_credential_redaction_covers_plus_encoded_query_fragments(self):
        redacted = redact_mailbox_credentials(
            "provider echoed auth_code=private+value",
            ("private value",),
        )

        self.assertNotIn("private+value", redacted)
        self.assertIn("********", redacted)

    def test_credential_redaction_uses_bounded_literal_matching(self):
        raw = "prefix SeCrEt-ToKeN suffix " + ("x" * 5000)
        with patch(
            "mac_overrides.mailbox_redaction.re.sub",
            side_effect=AssertionError("regex redaction is forbidden"),
        ):
            redacted = redact_mailbox_credentials(raw, ["secret-token"])

        self.assertNotIn("SeCrEt-ToKeN", redacted)
        self.assertIn("********", redacted)
        self.assertLessEqual(len(redacted), 4096)

    def test_credential_redaction_does_not_rescan_or_expand_mask_placeholders(self):
        redacted = redact_mailbox_credentials(
            "masked=*** existing=******** first=SeCrEt-ToKeN second=secret-token",
            ["***", "********", "secret-token"],
        )

        self.assertEqual(
            redacted,
            "masked=*** existing=******** first=******** second=********",
        )

    def test_reveal_password_returns_only_current_row_password(self):
        row = "mail@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(row + "\n")
        public_row = self.service.list_mailboxes()["rows"][0]

        result = self.service.reveal_password(public_row["row_id"], public_row["line_no"])

        self.assertEqual(result, {"ok": True, "password": "mail-pass"})

    def test_plain_password_row_imports_and_exposes_only_masked_public_state(self):
        row = "plain@example.com--plain-pass"
        result = self.service.append(f"{row}\nPLAIN@example.com----plain-pass\n")

        self.assertEqual(result["imported"], 1)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(self._pool_lines(), [row])
        public_row = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(public_row["email"], "plain@example.com")
        self.assertEqual(public_row["password"], "********")
        self.assertEqual(public_row["source_row"], "plain@example.com--********")
        self.assertNotIn("plain-pass", json.dumps(public_row))
        self.assertEqual(
            self.service.reveal_password(public_row["row_id"], public_row["line_no"]),
            {"ok": True, "password": "plain-pass"},
        )

    def test_plain_password_import_deduplicates_formats_but_preserves_password_case(self):
        result = self.service.append(
            "CaseUser@Example.com----CasePass\n"
            "caseuser@example.com--CasePass\n"
            "CASEUSER@EXAMPLE.COM|CasePass\n"
            "caseuser@example.com|casepass\n"
        )

        self.assertEqual(result["imported"], 2)
        self.assertEqual(result["skipped"], 2)
        self.assertEqual(
            self._pool_lines(),
            [
                "CaseUser@Example.com----CasePass",
                "caseuser@example.com|casepass",
            ],
        )
        self.assertEqual(result["validate"], {"ok": True, "entries": 2})

    def test_reveal_totp_returns_only_current_temporary_code_from_one_clock_snapshot(self):
        row = "mfa@example.com|login-pass|JBSWY3DPEHPK3PXP"
        self._write_pool(row + "\n")
        self.clock = 59.0
        public_row = self.service.list_mailboxes()["rows"][0]

        result = self.service.reveal_totp(public_row["row_id"], public_row["line_no"])

        self.assertEqual(result["kind"], "totp")
        self.assertEqual(result["code"], generate_totp_code("JBSWY3DPEHPK3PXP", now=59))
        self.assertRegex(result["code"], r"^\d{6}$")
        self.assertEqual(result["remaining"], 1)
        self.assertNotIn("totp_secret", result)
        self.assertNotIn("JBSWY3DPEHPK3PXP", json.dumps(result))

    def test_reveal_totp_rejects_stale_row_without_returning_code_or_secret(self):
        original = "mfa@example.com|login-pass|JBSWY3DPEHPK3PXP"
        replacement = "other@example.com|other-pass|KRUGS4ZANFZSAYJA"
        self._write_pool(original + "\n")
        captured = self.service.list_mailboxes()["rows"][0]
        self._write_pool(replacement + "\n" + original + "\n")

        result = self.service.reveal_totp(captured["row_id"], captured["line_no"])

        self.assertEqual(result["code"], "mailbox_row_stale")
        self.assertNotIn("totp_secret", result)
        self.assertNotIn("JBSWY3DPEHPK3PXP", json.dumps(result))
        self.assertNotIn("KRUGS4ZANFZSAYJA", json.dumps(result))

    def test_mailbox_row_exposes_safe_phone_risk_retry_label(self):
        self._write_pool("risk@example.com----mail-pass\n")
        self.service.phone_risk_lookup = lambda email: {
            "active": email == "risk@example.com",
            "reason_code": "oauth_session_invalid",
            "count": 2,
        }

        row = self.service.list_mailboxes()["rows"][0]

        self.assertTrue(row["phone_risk_retry"])
        self.assertEqual(row["phone_risk_label"], "手机号风控重试：已启用成熟线路优先")
        self.assertIn(row["phone_risk_label"], row["error"])
        serialized = json.dumps(row, ensure_ascii=False)
        self.assertNotIn("mail-pass", serialized)
        self.assertNotIn("oauth_session_invalid", serialized)

    def test_mailbox_url_is_publicly_flagged_and_revealed_by_current_row_binding(self):
        row = "url@example.com----https://mail.example.test/messages/private-token"
        self._write_pool(row + "\n")

        public_row = self.service.list_mailboxes()["rows"][0]
        self.assertTrue(public_row["has_mailbox_url"])
        result = self.service.reveal_mailbox_url(public_row["row_id"], public_row["line_no"])

        self.assertEqual(
            result,
            {"ok": True, "mailbox_url": "https://mail.example.test/messages/private-token"},
        )

    def test_mailbox_url_reveal_rejects_stale_binding_and_missing_url(self):
        row = "mail@example.com----mail-pass"
        self._write_pool(row + "\n")
        public_row = self.service.list_mailboxes()["rows"][0]
        stale = self.service.reveal_mailbox_url(public_row["row_id"], 2)
        missing = self.service.reveal_mailbox_url(public_row["row_id"], 1)

        self.assertEqual(stale["code"], "mailbox_row_stale")
        self.assertEqual(missing["code"], "mailbox_url_missing")
        self.assertNotIn("mail-pass", json.dumps(stale, ensure_ascii=False))

    def test_reveal_password_reports_missing_password_without_leak(self):
        row = "mail@example.com----"
        self._write_pool(row + "\n")

        result = self.service.reveal_password(row_id_from_source(row), 1)

        self.assertEqual(
            result,
            {
                "ok": False,
                "code": "mailbox_password_missing",
                "error": "这一行没有可复制的密码",
            },
        )
        self.assertNotIn("password", result)

    def test_reveal_password_rejects_stale_line_binding_without_leak(self):
        original = "one@example.com----pass-one"
        replacement = "two@example.com----pass-two"
        self._write_pool(original + "\n")
        captured = self.service.list_mailboxes()["rows"][0]
        self._write_pool(replacement + "\n" + original + "\n")

        result = self.service.reveal_password(captured["row_id"], captured["line_no"])

        self.assertEqual(
            result,
            {
                "ok": False,
                "code": "mailbox_row_stale",
                "error": "邮箱列表已变化，请刷新后重试",
            },
        )
        self.assertNotIn("password", result)
        self.assertNotIn("pass-one", json.dumps(result, ensure_ascii=False))
        self.assertNotIn("pass-two", json.dumps(result, ensure_ascii=False))

    def test_list_mailboxes_redacts_credentials_from_errors(self):
        row = "secret@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(row + "\n")
        self._write_state(
            {
                "secret": {
                    "email": "secret@example.com",
                    "line_no": 1,
                    "status": "damaged",
                    "reason": "refresh-token rejected",
                }
            }
        )
        results = self.root / "results"
        results.mkdir()
        (results / "failed.json").write_text(
            json.dumps(
                {
                    "email": "secret@example.com",
                    "status": "failed",
                    "technical_error": "failure for mail-pass client-id refresh-token",
                }
            ),
            encoding="utf-8",
        )

        item = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(item["technical_error"], "failure for ******** ******** ********")
        self.assertNotIn("mail-pass", item["error"])
        self.assertNotIn("refresh-token", item["error"])
        self.assertEqual(item["reason"], "******** rejected")

    def test_mailbox_row_uses_the_persisted_structured_failure_message(self):
        row = "oauth@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        failure = {
            "node_code": "finalizing_token",
            "node_label": "交换 OAuth Token",
            "error_code": "sub2_exchange_failed",
            "provider_code": "invalid_grant",
            "public_message": "交换 OAuth Token失败：SUB2 OAuth 会话已过期",
            "technical_summary": "HTTP 401 refresh_token=refresh-token",
            "retryable": True,
            "http_status": 401,
        }
        (results / "failed.json").write_text(
            json.dumps({
                "email": "oauth@example.com",
                "status": "repair_pending",
                "error": "legacy generic error",
                "failure": failure,
            }),
            encoding="utf-8",
        )

        item = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(item["error"], failure["public_message"])
        self.assertEqual(item["failure"]["node_code"], "finalizing_token")
        self.assertEqual(item["failure"]["provider_code"], "invalid_grant")
        self.assertNotIn("refresh-token", item["technical_error"])
        self.assertNotIn("mail-pass", json.dumps(item["failure"], ensure_ascii=False))

    def test_totp_error_redaction_covers_spaced_secret(self):
        row = "mfa@example.com|login-pass|JBSW Y3DP EHPK 3PXP"
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "failed.json").write_text(
            json.dumps(
                {
                    "email": "mfa@example.com",
                    "status": "failed",
                    "error": "TOTP JBSW Y3DP EHPK 3PXP rejected",
                }
            ),
            encoding="utf-8",
        )

        item = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(item["technical_error"], "TOTP ******** rejected")

    def test_import_filters_invalid_rows_deduplicates_and_logs_counts_only(self):
        existing = "one@example.com----pass-one----client-one----refresh-one"
        existing_email_case = "ONE@EXAMPLE.COM----pass-one----client-one----refresh-one"
        added = "two@example.com----pass-two----client-two----refresh-two"
        self._write_pool(existing + "\n")

        result = self.service.append(
            f"{existing_email_case}\nnot-a-mailbox\n{added}\n{added}\n"
        )

        self.assertEqual(result, {"ok": True, "imported": 1, "skipped": 2, "validate": {"ok": True, "entries": 2}})
        self.assertEqual(self._pool_lines(), [existing, added])
        self.assertEqual(len(self.validations), 1)
        self.assertEqual(self.logs, [("邮箱管理追加导入: 新增 1 条，跳过重复 2 条", "success")])
        self.assertNotIn("pass-two", self.logs[0][0])

    def test_import_during_active_run_marks_only_actual_new_rows_for_next_batch(self):
        existing = "existing@example.com----pass-existing"
        active_new = [
            "active-one@example.com----pass-one",
            "active-two@example.com----pass-two",
        ]
        idle_new = "idle@example.com----pass-idle"
        self._write_pool(existing + "\n")
        priority = MailboxNextBatchPriorityStore(self.root, now=lambda: self.clock)
        self.service.next_batch_priority = priority
        self.runtime["running"] = True

        active_result = self.service.import_mailboxes("\n".join(active_new + [active_new[0]]))
        self.runtime["running"] = False
        idle_result = self.service.import_mailboxes(idle_new)

        self.assertEqual(active_result["imported"], 2)
        self.assertEqual(active_result["skipped"], 1)
        self.assertEqual(idle_result["imported"], 1)
        snapshot = priority.snapshot()
        self.assertEqual(snapshot["pending"], 2)
        self.assertEqual(
            snapshot["row_ids"],
            [row_id_from_source(row) for row in active_new],
        )
        persisted = priority.path.read_text(encoding="utf-8")
        self.assertNotIn("@example.com", persisted)
        self.assertNotIn("pass-one", persisted)

    def test_latest_batch_membership_overrides_older_result_for_batch_filters(self):
        row = "member@example.com----pass-member"
        row_id = row_id_from_source(row)
        self._write_pool(row + "\n")
        self._write_state({})
        results = self.root / "results"
        results.mkdir()
        (results / "older.json").write_text(
            json.dumps(
                {
                    "task_id": "T-old",
                    "email": "member@example.com",
                    "status": "success",
                    "batch_id": "batch-old",
                    "batch_started_at": 100,
                    "created_at": 101,
                    "result": {"batch_id": "batch-old"},
                }
            ),
            encoding="utf-8",
        )
        self.service.run_batch_membership = lambda **_kwargs: [
            {
                "row_id": row_id,
                "line_no": 1,
                "task_id": "T-new",
                "status": "retryable_infra",
                "batch_id": "batch-new",
                "batch_started_at": 200,
            }
        ]

        public = self.service.list_mailboxes()["rows"][0]

        self.assertEqual(public["batch_id"], "batch-new")
        self.assertEqual(public["batch_started_at"], 200)
        self.assertEqual(public["task_id"], "T-new")
        self.assertEqual(public["task_status"], "retryable_infra")

    def test_delete_rewrites_state_line_numbers_and_drops_selected_entry(self):
        rows = [
            "one@example.com----pass-one",
            "two@example.com----pass-two",
            "three@example.com----pass-three",
        ]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state(
            {
                "one": {"email": "one@example.com", "line_no": 1, "status": "available"},
                "two": {"email": "two@example.com", "line_no": 2, "status": "leased"},
                "three": {"email": "three@example.com", "line_no": 3, "status": "available"},
            }
        )

        result = self.service.delete({"line_nos": [2]})

        self.assertEqual(result, {"ok": True, "deleted": 1})
        self.assertEqual(self._pool_lines(), [rows[0], rows[2]])
        state = json.loads((self.root / "state.json").read_text(encoding="utf-8"))
        self.assertNotIn("two", state["items"])
        self.assertEqual(state["items"]["one"]["line_no"], 1)
        self.assertEqual(state["items"]["three"]["line_no"], 2)
        self.assertEqual(state["updated_at"], 1000)
        self.assertEqual(self.logs[-1], ("邮箱管理删除: 1 条", "warn"))
        sidecar = json.loads((self.root / "mailbox_import_order.json").read_text(encoding="utf-8"))
        self.assertNotIn(row_id_from_source(rows[1]), sidecar["entries"])
        self.assertEqual(set(sidecar["entries"]), {row_id_from_source(rows[0]), row_id_from_source(rows[2])})

    def test_delete_rejects_stale_stable_row_binding_without_mutating_pool(self):
        rows = [
            "one@example.com----pass-one",
            "two@example.com----pass-two",
        ]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state({})

        result = self.service.delete({
            "line_nos": [2],
            "rows": [{"row_id": row_id_from_source(rows[0]), "line_no": 2}],
        })

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "mailbox_rows_stale")
        self.assertEqual(self._pool_lines(), rows)
        self.assertEqual(self.logs, [])

    def test_restore_updates_selected_state_and_history(self):
        self._write_pool("one@example.com----pass-one\ntwo@example.com----pass-two\n")
        self._write_state(
            {
                "one": {"email": "one@example.com", "line_no": 1, "status": "damaged"},
                "two": {"email": "two@example.com", "line_no": 2, "status": "damaged"},
            }
        )

        result = self.service.restore({"line_nos": [2]})

        self.assertEqual(result, {"ok": True, "restored": 1})
        state = json.loads((self.root / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["items"]["one"]["status"], "damaged")
        restored = state["items"]["two"]
        self.assertEqual(
            {key: restored[key] for key in ("status", "lease_until", "reason", "updated_at")},
            {"status": "available", "lease_until": 0, "reason": "manual_restore", "updated_at": 1000},
        )
        self.assertEqual(restored["history"][-1], {"event": "restored", "reason": "manual_restore", "at": 1000})
        self.assertEqual(self.logs[-1], ("邮箱管理放回可领取: 1 条", "success"))

    def test_list_state_requires_email_fallback_to_match_the_current_line(self):
        rows = [
            "exact@example.com----exact-password",
            "email@example.com----email-password",
            "legacy@example.com----legacy-password",
            "new@example.com----new-password",
        ]
        self._write_pool("\n".join(rows) + "\n")
        self._write_state({
            "stale-line": {
                "email": "other@example.com",
                "line_no": 1,
                "status": "damaged",
            },
            row_id_from_source(rows[0]): {
                "email": "exact@example.com",
                "line_no": 99,
                "status": "consumed",
            },
            "email-match": {
                "email": "email@example.com",
                "line_no": 1,
                "status": "damaged",
            },
            "legacy-line": {
                "line_no": 3,
                "status": "damaged",
            },
            "stale-new-line": {
                "email": "moved@example.com",
                "line_no": 4,
                "status": "damaged",
            },
        })

        listed = self.service.list_mailboxes()

        self.assertEqual(
            [(item["status"], item["status_label"]) for item in listed["rows"]],
            [("consumed", "已使用"), ("available", "可用"), ("failed", "失败"), ("available", "可用")],
        )
        self.assertEqual(
            listed["counts"],
            {"total": 4, "available": 2, "running": 0, "success": 1, "failed": 1},
        )

    def test_totp_latest_code_uses_one_clock_snapshot_and_skips_imap(self):
        self.clock = 59.0
        self._write_pool("mfa@example.com|login-pass|JBSWY3DPEHPK3PXP\n")

        result = self.service.latest_code({"line_no": 1})

        self.assertEqual(result["kind"], "totp")
        self.assertEqual(result["code"], generate_totp_code("JBSWY3DPEHPK3PXP", now=59))
        self.assertEqual(result["remaining"], 1)
        self.assertEqual(self.pollers, [])

    def test_imap_latest_code_uses_oauth_fields_and_closes_poller(self):
        row = "mail@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(f"\n{row}\n\nsecond@example.com----other-pass\n")

        result = self.service.latest_code({"line_no": 1})

        self.assertEqual(result["code"], "123456")
        args, kwargs = self.poller_args[0]
        self.assertEqual(args, ("mail@example.com", "mail-pass"))
        self.assertEqual(
            kwargs,
            {
                "verbose": False,
                "oauth_client_id": "client-id",
                "oauth_refresh_token": "refresh-token",
                "proxy": "",
            },
        )
        self.assertEqual(
            self.pollers[0].poll_kwargs,
            {
                "timeout": 5,
                "interval": 1,
                "since_ts": -800.0,
                "recent_scan_limit": 40,
                "include_existing": True,
            },
        )
        self.assertTrue(self.pollers[0].closed)
        self.assertEqual(self.service.pool_row_by_line(2)[1], "second@example.com")

    def test_url_latest_code_uses_generic_reader_and_skips_imap(self):
        row = "url@example.com---https://mail.example.test/messages/private-token"
        self._write_pool(row + "\n")
        reader_calls = []

        class FakeReader:
            def latest_code(self, *, include_existing):
                self.include_existing = include_existing
                return SimpleNamespace(code="654321")

        reader = FakeReader()

        def reader_factory(*args, **kwargs):
            reader_calls.append((args, kwargs))
            return reader

        service = MailboxAdminService(
            self.store,
            validate_pool=lambda _config: {"ok": True},
            imap_poller_factory=self.create_poller,
            mailbox_url_reader_factory=reader_factory,
        )

        result = service.latest_code({"line_no": 1})

        self.assertEqual(result["code"], "654321")
        self.assertEqual(result["kind"], "email")
        self.assertEqual(self.pollers, [])
        self.assertEqual(reader_calls[0][0], ("https://mail.example.test/messages/private-token",))
        self.assertEqual(reader_calls[0][1], {"timeout_seconds": 5, "proxy": ""})
        self.assertTrue(reader.include_existing)

    def test_url_totp_latest_code_sends_only_url_and_skips_imap(self):
        mailbox_url = (
            "https://mail.example.test/latest?"
            "email=urlmfa%40example.com&auth_code=private"
        )
        self._write_pool(
            f"urlmfa@example.com----{mailbox_url}----JBSWY3DPEHPK3PXP\n"
        )
        reader_calls = []

        class FakeReader:
            def latest_code(self, *, include_existing):
                self.include_existing = include_existing
                return SimpleNamespace(code="012345")

        reader = FakeReader()

        def reader_factory(*args, **kwargs):
            reader_calls.append((args, kwargs))
            return reader

        service = MailboxAdminService(
            self.store,
            validate_pool=lambda _config: {"ok": True},
            imap_poller_factory=self.create_poller,
            mailbox_url_reader_factory=reader_factory,
        )

        result = service.latest_code({"line_no": 1})

        self.assertEqual(result["code"], "012345")
        self.assertEqual(result["kind"], "email")
        self.assertEqual(reader_calls[0][0], (mailbox_url,))
        self.assertEqual(reader_calls[0][1], {"timeout_seconds": 5, "proxy": ""})
        self.assertNotIn("JBSWY3DPEHPK3PXP", reader_calls[0][0][0])
        self.assertTrue(reader.include_existing)
        self.assertEqual(self.pollers, [])

    def test_url_latest_code_failure_redacts_url_and_email(self):
        row = "url@example.com|https://mail.example.test/messages/private-token"
        self._write_pool(row + "\n")

        def failing_reader(*_args, **_kwargs):
            raise RuntimeError(f"failed {row}")

        service = MailboxAdminService(
            self.store,
            validate_pool=lambda _config: {"ok": True},
            imap_poller_factory=self.create_poller,
            mailbox_url_reader_factory=failing_reader,
        )

        result = service.latest_code({"line_no": 1})

        self.assertFalse(result["ok"])
        self.assertNotIn("url@example.com", result["error"])
        self.assertNotIn("private-token", result["error"])
        self.assertNotIn("mail.example.test", result["error"])
        self.assertIn("********", result["error"])

    def test_imap_failure_closes_poller_and_redacts_all_row_credentials(self):
        row = "mail@example.com----mail-pass----client-id----refresh-token"
        self._write_pool(row + "\n")

        def failing_poller(*args, **kwargs):
            self.poller_args.append((args, kwargs))
            poller = FakePoller(
                error=RuntimeError(
                    "mail@example.com mail-pass client-id refresh-token rejected"
                )
            )
            self.pollers.append(poller)
            return poller

        service = MailboxAdminService(
            self.store,
            validate_pool=lambda _config: {"ok": True},
            imap_poller_factory=failing_poller,
            now_fn=lambda: self.clock,
        )

        result = service.latest_code({"line_no": 1})

        self.assertFalse(result["ok"])
        self.assertTrue(self.pollers[0].closed)
        self.assertNotIn("mail@example.com", result["error"])
        self.assertNotIn("mail-pass", result["error"])
        self.assertNotIn("client-id", result["error"])
        self.assertNotIn("refresh-token", result["error"])
        self.assertIn("********", result["error"])


if __name__ == "__main__":
    unittest.main()
