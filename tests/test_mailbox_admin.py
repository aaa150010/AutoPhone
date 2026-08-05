from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mac_overrides.mailbox_admin import (
    MailboxAdminService,
    email_from_row,
    generate_totp_code,
    is_importable_mailbox_row,
    masked_source_row,
    parse_chatgpt_totp_row,
    parse_mailbox_url_row,
    parse_oauth_mailbox_row,
    password_from_row,
    public_sub2_status,
    public_task_account,
    redact_mailbox_credentials,
    row_id_from_source,
    selected_line_numbers,
    url_credential_secrets,
)


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
        self.assertTrue(is_importable_mailbox_row(oauth))
        self.assertTrue(is_importable_mailbox_row(totp))
        self.assertTrue(is_importable_mailbox_row(dashed_totp))
        self.assertEqual(
            parse_mailbox_url_row(url_row).mailbox_url,
            "https://mail.example.test/messages/private-token",
        )
        self.assertTrue(is_importable_mailbox_row(url_row))
        self.assertEqual(password_from_row(url_row), "")
        self.assertEqual(masked_source_row(url_row), "url@example.com｜********")
        self.assertEqual(
            masked_source_row(dashed_totp),
            "mfa2@example.com--********--********",
        )
        self.assertFalse(is_importable_mailbox_row("# user@example.com----secret"))
        self.assertFalse(is_importable_mailbox_row("user@example.com----password"))
        self.assertFalse(is_importable_mailbox_row("user@example.com|password|INVALID018"))
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
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("private-access", serialized)
        self.assertNotIn("private-account", serialized)
        self.assertEqual(
            [{key: item[key] for key in ("line_no", "status", "quota_5h", "quota_7d")} for item in result["results"]],
            [
                {"line_no": 1, "status": "ok", "quota_5h": {"remaining_percent": 80}, "quota_7d": {"remaining_percent": 40}},
                {"line_no": 2, "status": "ok", "quota_5h": {"remaining_percent": 80}, "quota_7d": {"remaining_percent": 40}},
            ],
        )

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
                    "result": {"sms_cost_usd": 0.05, "sms_cost_cny": 0.36},
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
        self.assertEqual(running["progress"]["code"], "sms_waiting")
        self.assertNotIn("mailbox_password", running["progress"])
        self.assertEqual((done["status"], done["sms_cost_usd"], done["sms_cost_cny"]), ("consumed", 0.05, 0.36))
        self.assertEqual(restored["task_id"], "")
        self.assertEqual(restored["error"], "")
        self.assertEqual(restored["password"], "********")
        self.assertEqual(restored["source_row"], "restored@example.com|********|********")
        public_payload = json.dumps(result, ensure_ascii=False)
        for secret in ("run-pass", "done-pass", "login-pass", "refresh-a", "JBSWY3DPEHPK3PXP"):
            self.assertNotIn(secret, public_payload)

    def test_mailboxes_sort_newest_batch_first_and_resolve_only_success_results(self):
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
            "failed@example.com",
            "newer@example.com",
            "older@example.com",
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

        stale = self.service.selected_success_results({
            "rows": [{"row_id": row_id_from_source(older), "line_no": 2}],
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

    def test_credential_redaction_uses_bounded_literal_matching(self):
        raw = "prefix SeCrEt-ToKeN suffix " + ("x" * 5000)
        with patch(
            "mac_overrides.mailbox_admin.re.sub",
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
        added = "two@example.com----pass-two----client-two----refresh-two"
        self._write_pool(existing + "\n")

        result = self.service.append(
            f"{existing.upper()}\nnot-a-mailbox\n{added}\n{added}\n"
        )

        self.assertEqual(result, {"ok": True, "imported": 1, "skipped": 2, "validate": {"ok": True, "entries": 2}})
        self.assertEqual(self._pool_lines(), [existing, added])
        self.assertEqual(len(self.validations), 1)
        self.assertEqual(self.logs, [("邮箱管理追加导入: 新增 1 条，跳过重复 2 条", "success")])
        self.assertNotIn("pass-two", self.logs[0][0])

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
