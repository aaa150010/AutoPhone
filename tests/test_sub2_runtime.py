from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.parse

from mac_overrides.sub2_runtime import (
    AdminTokenCache,
    Sub2AdminError,
    Sub2BatchService,
    Sub2Client,
    Sub2ConfigurationError,
    Sub2RequestNetworkError,
    Sub2RequestTimeout,
    Sub2Runtime,
    Sub2SnapshotStore,
    _status_from_code,
    normalize_sub2_base_url,
    service_fingerprint,
)


class FakeResponse:
    def __init__(self, status_code=200, *, payload=None, chunks=(), stream_error=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {}
        self.chunks = list(chunks)
        self.stream_error = stream_error
        self.text = json.dumps(self.payload)
        self.closed = False

    def json(self):
        return self.payload

    def iter_content(self, chunk_size=1024):
        del chunk_size
        yield from self.chunks
        if self.stream_error is not None:
            raise self.stream_error

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self._lock = threading.Lock()

    def request(self, method, url, **kwargs):
        call = {"method": method, "url": url, **kwargs}
        with self._lock:
            self.calls.append(call)
        return self.handler(call)


def login_response(token="admin-token"):
    return FakeResponse(200, payload={"code": 0, "data": {"access_token": token, "expires_in": 600}})


def sse_response(*events, chunks=None):
    body = "".join(f"data: {json.dumps(event, ensure_ascii=False)}\n\n" for event in events).encode("utf-8")
    return FakeResponse(200, chunks=list(chunks) if chunks is not None else [body])


class Sub2RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.clock = 1_700_000_000.0

    def tearDown(self):
        self.temp_dir.cleanup()

    def _client(self, transport, *, timeout=30):
        return Sub2Client(
            "https://Sub2.Example.test/login",
            "admin@example.test",
            "admin-password",
            snapshot_store=Sub2SnapshotStore(self.root / "snapshots.json", now_fn=lambda: self.clock),
            transport=transport,
            token_cache=AdminTokenCache(now_fn=lambda: self.clock),
            timeout=timeout,
            now_fn=lambda: self.clock,
        )

    def test_normalizes_service_root_ui_login_and_login_api_urls(self):
        expected = "https://sub2.example.test/prefix"
        for value in (
            "https://SUB2.example.test:443/prefix/",
            "https://sub2.example.test/prefix/login?next=/admin",
            "https://sub2.example.test/prefix/api/v1/auth/login#ignored",
            "sub2.example.test/prefix/auth/login",
        ):
            with self.subTest(value=value):
                self.assertEqual(normalize_sub2_base_url(value), expected)
        self.assertEqual(
            normalize_sub2_base_url("http://SUB2.example.test:80/api/v1/auth/login"),
            "http://sub2.example.test",
        )
        self.assertEqual(service_fingerprint(expected), service_fingerprint(f"{expected}/login"))
        for invalid in ("", "ftp://example.test", "https://user:pass@example.test"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(Sub2ConfigurationError):
                    normalize_sub2_base_url(invalid)

    def test_success_uses_expected_contract_reuses_token_and_redacts_snapshot(self):
        def handler(call):
            if call["url"].endswith("/api/v1/auth/login"):
                return login_response("sensitive-admin-token")
            body = (
                'data: {"type":"content","text":"hello admin-password sensitive-admin-token 世界"}\n\n'
                'data: {"type":"test_complete","success":true}\n\n'
            ).encode("utf-8")
            marker = body.index("世".encode("utf-8")) + 1
            return FakeResponse(200, chunks=[body[:marker], body[marker : marker + 1], body[marker + 1 :]])

        transport = FakeTransport(handler)
        client = self._client(transport)

        first = client.test_account("41")
        second = client.test_account("42")

        self.assertEqual((first.kind, first.status_code, first.label), ("healthy", 200, "200 健康"))
        self.assertIn("世界", first.summary)
        self.assertNotIn("admin-password", first.summary)
        self.assertNotIn("sensitive-admin-token", first.summary)
        self.assertEqual(second.kind, "healthy")
        login_calls = [call for call in transport.calls if call["url"].endswith("/auth/login")]
        self.assertEqual(len(login_calls), 1)
        test_call = next(call for call in transport.calls if "/accounts/41/test" in call["url"])
        self.assertEqual(test_call["json_body"], {"model_id": "gpt-5.4", "prompt": "", "mode": "default"})
        self.assertEqual(test_call["headers"]["X-Admin-UI-Request"], "1")
        self.assertEqual(test_call["headers"]["Authorization"], "Bearer sensitive-admin-token")
        saved = (self.root / "snapshots.json").read_text(encoding="utf-8")
        self.assertNotIn("admin-password", saved)
        self.assertNotIn("sensitive-admin-token", saved)
        self.assertNotIn("sub2.example.test", saved)
        self.assertEqual(client.stored_status("41").kind, "healthy")

    def test_account_level_sse_errors_are_classified_without_confusing_admin_auth(self):
        errors = {
            "401": "API returned 401: invalid access token",
            "429": "API returned 429: rate limit reached",
            "404": "Account not found",
            "500": "API returned 500: upstream failed",
        }

        def handler(call):
            if call["url"].endswith("/auth/login"):
                return login_response()
            account_id = call["url"].split("/accounts/", 1)[1].split("/", 1)[0]
            return sse_response({"type": "error", "error": errors[account_id]})

        client = self._client(FakeTransport(handler))
        statuses = {account_id: client.test_account(account_id) for account_id in errors}

        self.assertEqual(
            (
                statuses["401"].kind,
                statuses["401"].is_error,
                statuses["401"].is_abnormal,
                statuses["401"].is_test_failure,
                statuses["401"].needs_rerun,
            ),
            ("unauthorized", True, True, False, True),
        )
        self.assertEqual(
            (
                statuses["429"].kind,
                statuses["429"].is_error,
                statuses["429"].is_abnormal,
                statuses["429"].is_test_failure,
                statuses["429"].needs_rerun,
            ),
            ("rate_limited", False, False, False, False),
        )
        self.assertEqual(
            (
                statuses["404"].kind,
                statuses["404"].is_abnormal,
                statuses["404"].is_test_failure,
                statuses["404"].needs_rerun,
            ),
            ("not_found", False, True, True),
        )
        self.assertEqual(
            (statuses["500"].kind, statuses["500"].status_code, statuses["500"].is_test_failure),
            ("http_error", 500, True),
        )

    def test_old_snapshot_flags_are_recomputed_from_kind_and_status_code(self):
        fingerprint = "f" * 16
        path = self.root / "snapshots.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "items": {
                        f"{fingerprint}:limited": {
                            "kind": "rate_limited",
                            "status_code": 429,
                            "label": "429 额度受限",
                            "summary": "old",
                            "tested_at": int(self.clock),
                            "is_error": True,
                            "needs_rerun": True,
                        },
                        f"{fingerprint}:missing": {
                            "kind": "not_found",
                            "status_code": 404,
                            "label": "404 账号不存在",
                            "summary": "old",
                            "tested_at": int(self.clock),
                            "is_error": False,
                            "needs_rerun": True,
                        },
                        f"{fingerprint}:legacy-unlinked": {
                            "kind": "not_linked",
                            "status_code": None,
                            "label": "未关联",
                            "summary": "",
                            "tested_at": int(self.clock),
                            "is_error": True,
                            "needs_rerun": True,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        store = Sub2SnapshotStore(path, now_fn=lambda: self.clock)
        limited = store.get(fingerprint, "limited")
        missing = store.get(fingerprint, "missing")
        legacy_unlinked = store.get(fingerprint, "legacy-unlinked")

        self.assertIsNotNone(limited)
        self.assertEqual(
            (limited.is_error, limited.is_abnormal, limited.is_test_failure, limited.needs_rerun),
            (False, False, False, False),
        )
        self.assertIsNotNone(missing)
        self.assertEqual(
            (missing.is_error, missing.is_abnormal, missing.is_test_failure, missing.needs_rerun),
            (True, False, True, True),
        )
        self.assertIsNotNone(legacy_unlinked)
        self.assertEqual(
            (
                legacy_unlinked.is_error,
                legacy_unlinked.is_abnormal,
                legacy_unlinked.is_test_failure,
                legacy_unlinked.needs_rerun,
            ),
            (False, False, False, False),
        )

    def test_sse_status_code_fields_override_generic_failure_text(self):
        events = {
            "401": {"type": "error", "status_code": 401, "error": "request failed"},
            "429": {"type": "test_complete", "success": False, "statusCode": 429},
            "404": {"type": "error", "error": {"code": 404, "message": "request failed"}},
        }

        def handler(call):
            if call["url"].endswith("/auth/login"):
                return login_response()
            account_id = call["url"].split("/accounts/", 1)[1].split("/", 1)[0]
            return sse_response(events[account_id])

        client = self._client(FakeTransport(handler))
        statuses = {account_id: client.test_account(account_id) for account_id in events}

        self.assertEqual((statuses["401"].kind, statuses["401"].needs_rerun), ("unauthorized", True))
        self.assertEqual((statuses["429"].kind, statuses["429"].is_error), ("rate_limited", False))
        self.assertEqual((statuses["404"].kind, statuses["404"].is_test_failure), ("not_found", True))

    def test_http_timeout_network_and_protocol_failures_are_distinct(self):
        def handler(call):
            if call["url"].endswith("/auth/login"):
                return login_response()
            account_id = call["url"].split("/accounts/", 1)[1].split("/", 1)[0]
            if account_id == "404":
                return FakeResponse(404)
            if account_id == "timeout":
                raise Sub2RequestTimeout("private timeout detail")
            if account_id == "network":
                raise Sub2RequestNetworkError("private network detail")
            if account_id == "stream-timeout":
                return FakeResponse(200, chunks=[b'data: {"type":"content","text":"partial"}\n'], stream_error=Sub2RequestTimeout())
            return FakeResponse(200, chunks=[b'data: {not-json}\n\n'])

        client = self._client(FakeTransport(handler))
        expected = {
            "404": "not_found",
            "timeout": "timeout",
            "network": "network_error",
            "stream-timeout": "timeout",
            "protocol": "protocol_error",
        }
        for account_id, kind in expected.items():
            with self.subTest(account_id=account_id):
                status = client.test_account(account_id)
                self.assertEqual(status.kind, kind)
                self.assertTrue(status.is_error)
                self.assertFalse(status.is_abnormal)
                self.assertTrue(status.is_test_failure)
                self.assertEqual(status.needs_rerun, account_id == "404")

    def test_management_401_forces_one_token_refresh_then_retries(self):
        login_count = 0
        test_count = 0

        def handler(call):
            nonlocal login_count, test_count
            if call["url"].endswith("/auth/login"):
                login_count += 1
                return login_response(f"token-{login_count}")
            test_count += 1
            if test_count == 1:
                return FakeResponse(401)
            return sse_response({"type": "test_complete", "success": True})

        transport = FakeTransport(handler)
        status = self._client(transport).test_account("77")

        self.assertEqual(status.kind, "healthy")
        self.assertEqual((login_count, test_count), (2, 2))
        test_calls = [call for call in transport.calls if "/accounts/77/test" in call["url"]]
        self.assertEqual([call["headers"]["Authorization"] for call in test_calls], ["Bearer token-1", "Bearer token-2"])

    def test_repeated_management_401_is_batch_wide_and_does_not_write_snapshot(self):
        def handler(call):
            if call["url"].endswith("/auth/login"):
                return login_response(f"token-{len([c for c in transport.calls if c['url'].endswith('/auth/login')])}")
            return FakeResponse(401)

        transport = FakeTransport(handler)
        client = self._client(transport)
        with self.assertRaises(Sub2AdminError) as captured:
            client.test_account("88")

        self.assertEqual(captured.exception.code, "sub2_admin_auth_failed")
        self.assertFalse((self.root / "snapshots.json").exists())

    def test_batch_limits_workers_keeps_unlinked_and_persists_completed_rows(self):
        barrier = threading.Barrier(3)
        active = 0
        max_active = 0
        lock = threading.Lock()

        def handler(call):
            nonlocal active, max_active
            if call["url"].endswith("/auth/login"):
                return login_response()
            with lock:
                active += 1
                max_active = max(max_active, active)
            barrier.wait(timeout=2)
            with lock:
                active -= 1
            return sse_response({"type": "test_complete", "success": True})

        client = self._client(FakeTransport(handler))
        rows = [
            {"row_id": f"row-{index}", "line_no": index, "sub2api_account_id": str(index)}
            for index in range(1, 4)
        ] + [{"row_id": "unlinked", "line_no": 4, "sub2api_account_id": ""}]

        result = Sub2BatchService(client).test_rows(rows)

        self.assertTrue(result["ok"])
        self.assertEqual(
            (result["tested"], result["unlinked"], result["healthy"], result["failed"], max_active),
            (3, 1, 3, 0, 3),
        )
        self.assertEqual(result["results"][-1]["sub2_status"]["kind"], "unlinked")
        self.assertEqual(client.stored_status("1").kind, "healthy")
        queued = Sub2BatchService(client).test_rows(rows * 6)
        self.assertTrue(queued["ok"])
        self.assertEqual(queued["batch_count"], 2)
        self.assertEqual(queued["queued_batches"], 1)
        self.assertEqual(queued["completed_batches"], 2)
        self.assertEqual(queued["tested"], 18)
        self.assertEqual(queued["unlinked"], 6)

    def test_queued_batch_keeps_completed_snapshot_when_later_admin_auth_fails(self):
        attempts = []

        def handler(call):
            if call["url"].endswith("/auth/login"):
                return login_response()
            account_id = urllib.parse.unquote(call["url"].split("/accounts/", 1)[1].split("/", 1)[0])
            attempts.append(account_id)
            if account_id == "bad-admin":
                return FakeResponse(401)
            return sse_response({"type": "test_complete", "success": True})

        client = self._client(FakeTransport(handler))
        rows = [
            {"row_id": f"row-{index}", "line_no": index, "sub2api_account_id": str(index)}
            for index in range(1, 21)
        ]
        rows.append({"row_id": "bad", "line_no": 21, "sub2api_account_id": "bad-admin"})

        result = Sub2BatchService(client).test_rows(rows)

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "sub2_admin_auth_failed")
        self.assertEqual(result["completed_batches"], 1)
        self.assertEqual(client.stored_status("1").kind, "healthy")
        self.assertTrue((self.root / "snapshots.json").exists())

    def test_batch_counts_rate_limited_separately_from_failures(self):
        def handler(call):
            if call["url"].endswith("/auth/login"):
                return login_response()
            account_id = call["url"].split("/accounts/", 1)[1].split("/", 1)[0]
            if account_id == "healthy":
                return sse_response({"type": "test_complete", "success": True})
            if account_id == "limited":
                return sse_response({"type": "error", "error": "API returned 429: rate limit"})
            if account_id == "expired":
                return sse_response({"type": "error", "error": "API returned 401: token expired"})
            return sse_response({"type": "error", "error": "API returned 404: account not found"})

        client = self._client(FakeTransport(handler))
        result = Sub2BatchService(client).test_rows(
            [
                {"row_id": account_id, "line_no": index, "sub2api_account_id": account_id}
                for index, account_id in enumerate(
                    ("healthy", "limited", "expired", "missing"),
                    start=1,
                )
            ]
        )

        self.assertEqual(
            {
                key: result[key]
                for key in ("tested", "healthy", "rate_limited", "failed", "test_failures")
            },
            {"tested": 4, "healthy": 1, "rate_limited": 1, "failed": 2, "test_failures": 1},
        )
        limited = next(
            item["sub2_status"]
            for item in result["results"]
            if item["row_id"] == "limited"
        )
        self.assertFalse(limited["is_error"])
        self.assertFalse(limited["is_test_failure"])

    def test_not_found_status_explains_remote_account_lifecycle_and_is_retryable_only_manually(self):
        status = _status_from_code(
            404,
            "API returned 404: account not found",
            int(self.clock),
            (),
        )

        public = status.public()
        self.assertEqual(public["kind"], "not_found")
        self.assertEqual(public["label"], "404 账号不存在")
        self.assertIn("远端账号不存在", public["summary"])
        self.assertIn("重新上传或重新关联", public["summary"])
        self.assertTrue(public["is_test_failure"])
        self.assertTrue(public["needs_rerun"])

    def test_admin_failure_does_not_discard_an_already_completed_row(self):
        test_attempts = {}
        lock = threading.Lock()
        good_persisted = threading.Event()

        def handler(call):
            if call["url"].endswith("/auth/login"):
                return login_response(f"token-{len([c for c in transport.calls if c['url'].endswith('/auth/login')])}")
            account_id = urllib.parse.unquote(call["url"].split("/accounts/", 1)[1].split("/", 1)[0])
            with lock:
                test_attempts[account_id] = test_attempts.get(account_id, 0) + 1
            if account_id == "bad-admin":
                self.assertTrue(good_persisted.wait(2))
                return FakeResponse(401)
            return sse_response({"type": "test_complete", "success": True})

        transport = FakeTransport(handler)
        client = self._client(transport)
        original_persist = client.persist_statuses

        def persist_statuses(values):
            original_persist(values)
            if "good" in values:
                good_persisted.set()

        client.persist_statuses = persist_statuses
        result = Sub2BatchService(client).test_rows(
            [
                {"row_id": "one", "line_no": 1, "sub2api_account_id": "good"},
                {"row_id": "two", "line_no": 2, "sub2api_account_id": "bad-admin"},
            ]
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "sub2_admin_auth_failed")
        self.assertEqual(client.stored_status("good").kind, "healthy")
        self.assertTrue((self.root / "snapshots.json").exists())

    def test_runtime_uses_service_fingerprint_when_enriching_status(self):
        config = {
            "sub2api": {
                "url": "https://one.example.test",
                "email": "admin@example.test",
                "password": "secret",
            }
        }
        runtime = Sub2Runtime(lambda: config, self.root / "snapshots.json", now_fn=lambda: self.clock)
        first_fingerprint = service_fingerprint(config["sub2api"]["url"])
        from mac_overrides.sub2_runtime import Sub2TestStatus

        runtime.snapshot_store.put_many(
            first_fingerprint,
            {"9": Sub2TestStatus("healthy", 200, "200 健康", "ok", int(self.clock), False, False)},
        )
        self.assertEqual(runtime.status_for("9")["kind"], "healthy")
        config["sub2api"]["url"] = "https://two.example.test/login"
        self.assertEqual(runtime.status_for("9")["kind"], "untested")
        self.assertEqual(runtime.status_for("")["kind"], "unlinked")

    def test_runtime_clears_stale_status_after_existing_account_update(self):
        config = {
            "sub2api": {
                "url": "https://one.example.test",
                "email": "admin@example.test",
                "password": "secret",
            }
        }
        runtime = Sub2Runtime(lambda: config, self.root / "snapshots.json", now_fn=lambda: self.clock)
        fingerprint = service_fingerprint(config["sub2api"]["url"])
        from mac_overrides.sub2_runtime import Sub2TestStatus

        runtime.snapshot_store.put_many(
            fingerprint,
            {
                "9": Sub2TestStatus(
                    "unauthorized",
                    401,
                    "401 Token失效",
                    "token expired",
                    int(self.clock),
                    True,
                    True,
                )
            },
        )
        self.assertTrue(runtime.status_for("9")["needs_rerun"])

        runtime.clear_status("9")

        self.assertEqual(runtime.status_for("9")["kind"], "untested")


if __name__ == "__main__":
    unittest.main()
