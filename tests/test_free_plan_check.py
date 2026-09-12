from __future__ import annotations

import time
import tempfile
import unittest
from unittest.mock import patch

from mac_overrides import free_account_service
from mac_overrides.free_account_service import plan_details_with_fallbacks
from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.free_log_runtime import FreeLogStore
from mac_overrides.free_plan_check import FreePlanCheckError, FreePlanCheckService
from mac_overrides.free_register_store import FreeMailboxPool


class FreePlanCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gptphone-free-plan-")
        self.pool = FreeMailboxPool(self.temp.name)
        self.pool.import_text("user@example.test----https://mailbox.test/inbox")
        self.row = self.pool.entries()[0]

    def tearDown(self):
        self.temp.cleanup()

    def test_public_plan_job_masks_email_and_exposes_only_fingerprint(self):
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1, recover=False)
        try:
            public = service._public({
                "task_id": "plan-task-1",
                "row_id": self.row.row_id,
                "email": "private@example.test",
                "status": "queued",
                "created_at": 1,
                "updated_at": 1,
            })
            self.assertEqual(public["email"], "private@example.test")
            self.assertEqual(public["email_masked"], "private@example.test")

            self.assertRegex(public["subject_ref_fingerprint"], r"^[0-9a-f]{16}$")
        finally:
            service.shutdown()

    def test_public_plan_job_uses_diagnostic_hmac_when_available(self):
        diagnostics = DiagnosticStore(self.temp.name + "/diagnostics")
        logs = FreeLogStore(self.temp.name, diagnostic_store=diagnostics, legacy_projection=False)
        service = FreePlanCheckService(self.temp.name, pool=self.pool, log_store=logs, workers=1, recover=False)
        try:
            public = service._public({"email": "private@example.test", "status": "queued"})
            self.assertEqual(public["subject_ref_fingerprint"], diagnostics.fingerprint("private@example.test"))
        finally:
            service.shutdown()

    def test_plan_check_logs_declare_their_diagnostic_workflow(self):
        class CaptureLog:
            def __init__(self):
                self.calls = []

            def add(self, *args, **kwargs):
                self.calls.append((args, kwargs))

        capture = CaptureLog()
        service = FreePlanCheckService(
            self.temp.name,
            pool=self.pool,
            log_store=capture,
            workers=1,
            recover=False,
        )
        try:
            service._log("free-plan-1", "queued")
            self.assertEqual(capture.calls[-1][1]["workflow"], "plan_check")
            self.assertEqual(capture.calls[-1][1]["driver"], "free")
            self.assertEqual(capture.calls[-1][1]["task_id"], "free-plan-1")
        finally:
            service.shutdown()

    def test_plan_check_log_falls_back_to_legacy_sink_signature(self):
        calls = []

        class LegacyLog:
            def add(self, message, level):
                calls.append((message, level))

        service = FreePlanCheckService(
            self.temp.name,
            pool=self.pool,
            log_store=LegacyLog(),
            workers=1,
            recover=False,
        )
        try:
            service._log("free-plan-legacy", "queued")
        finally:
            service.shutdown()
        self.assertEqual(len(calls), 1)
        self.assertIn("free-plan-legacy", calls[0][0])

    def test_invalid_accounts_response_falls_back_to_me_then_usage(self):
        accounts = {"ok": True, "status": 200, "payload": {}}
        eligibility = {"ok": True, "status": 200, "payload": {"eligible": False}}
        me = {"ok": True, "status": 200, "payload": {}}
        usage = {"ok": True, "status": 200, "payload": {"plan_type": "plus"}}
        details = plan_details_with_fallbacks(accounts, eligibility, [("backend-api/me", me), ("backend-api/wham/usage", usage)])
        self.assertEqual(details["plan_check_status"], "success")
        self.assertEqual(details["subscription_plan"], "plus")
        self.assertEqual(details["plan_source"], "backend-api/wham/usage")

    def test_browser_plan_query_uses_same_origin_me_and_usage_fallback(self):
        responses = {
            "accounts/check": {"ok": True, "status": 200, "payload": {}},
            "/aip/first-party/eligibility": {"ok": True, "status": 200, "payload": {"eligible": False}},
            "/backend-api/me": {"ok": True, "status": 200, "payload": {}},
            "/backend-api/wham/usage": {"ok": True, "status": 200, "payload": {"plan_type": "free"}},
        }

        async def fake_fetch(_page, url, **_kwargs):
            return next(value for key, value in responses.items() if key in url)

        with patch.object(free_account_service, "browser_json_fetch", side_effect=fake_fetch):
            details = __import__("asyncio").run(free_account_service.browser_plan_details(object(), "token"))
        self.assertEqual(details["plan_check_status"], "success")
        self.assertEqual(details["plan_source"], "backend-api/wham/usage")

    def test_browser_plan_queries_run_concurrently(self):
        import asyncio as _asyncio

        started: list[str] = []
        finished: list[str] = []

        class _Gate:
            def __init__(self):
                self._event = _asyncio.Event()

            async def arrive(self, name: str):
                started.append(name)
                if len(started) >= 2:
                    self._event.set()
                else:
                    await _asyncio.wait_for(self._event.wait(), timeout=1)

        gate = _Gate()

        async def fake_fetch(_page, url, **_kwargs):
            name = "accounts" if "accounts/check" in url else "eligibility"
            await gate.arrive(name)
            finished.append(name)
            return {"ok": True, "status": 200, "payload": {"eligible": True}}

        with patch.object(free_account_service, "browser_json_fetch", side_effect=fake_fetch):
            details = _asyncio.run(free_account_service.browser_plan_details(object(), "token"))

        # Both queries must be in flight before either returns.
        self.assertEqual(sorted(started), ["accounts", "eligibility"])
        self.assertEqual(sorted(finished), ["accounts", "eligibility"])
        self.assertEqual(details["plan_check_status"], "success")

    def test_queue_transport_falls_back_without_relogging(self):
        self.pool.save_result(self.row.row_id, {"access_token": "token"})
        calls = []

        class Response:
            def __init__(self, status, payload):
                self.status_code = status
                self._payload = payload
                self.headers = {}

            def json(self):
                return self._payload

        class Session:
            def __init__(self, **_kwargs):
                self.trust_env = True
                self.proxies = {}

            def get(self, url, **_kwargs):
                calls.append(url)
                if "/accounts/check/" in url:
                    return Response(200, {})
                if url.endswith("/aip/first-party/eligibility"):
                    return Response(200, {"eligible": False})
                if url.endswith("/backend-api/me"):
                    return Response(200, {})
                return Response(200, {"plan_type": "plus"})

            def close(self):
                pass

        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1)
        try:
            with patch("curl_cffi.requests.Session", Session):
                details = service._query(self.row.row_id)
            self.assertEqual(details["plan_source"], "backend-api/wham/usage")
            self.assertEqual(details["plan_type"], "plus")
            self.assertEqual(len(calls), 4)
        finally:
            service.shutdown()

    def test_queue_transport_honors_configured_socks5_dns_mode(self):
        self.pool.save_result(self.row.row_id, {"access_token": "token"})
        service = FreePlanCheckService(
            self.temp.name,
            pool=self.pool,
            workers=1,
            config_provider=lambda: {"proxy_socks5_dns_mode": "local"},
        )
        captured = []
        try:
            with patch("mac_overrides.free_plan_check.proxy_transport_value", side_effect=lambda value, **kwargs: captured.append(kwargs) or "socks5://proxy.test:8000"):
                with patch("curl_cffi.requests.Session") as session_factory:
                    session = session_factory.return_value
                    session.get.side_effect = [
                        type("Response", (), {"status_code": 200, "headers": {}, "json": lambda self: {}})(),
                        type("Response", (), {"status_code": 200, "headers": {}, "json": lambda self: {"eligible": False}})(),
                        type("Response", (), {"status_code": 200, "headers": {}, "json": lambda self: {"plan_type": "free"}})(),
                    ]
                    service._query(self.row.row_id)
            self.assertEqual(captured[0]["socks5_dns_mode"], "local")
        finally:
            service.shutdown()

    def test_success_syncs_result_and_promotes_plan_only_partial(self):
        self.pool.save_result(self.row.row_id, {
            "task_id": "free-task-1",
            "status": "partial_success",
            "access_token": "token",
            "plan_check_status": "failed",
            "plan_error_code": "free_plan_accounts_response_invalid",
            "failure": {"node_code": "free_plan_check", "node_label": "查询 Free 套餐资格", "error_code": "free_plan_accounts_response_invalid", "public_message": "套餐查询失败", "retryable": True},
        })
        updates = []
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1, task_updater=lambda row_id, result, promoted: updates.append((row_id, promoted, result.get("plan_type", ""))))
        try:
            service._query = lambda _row_id: {"plan_check_status": "success", "plan_type": "free", "subscription_plan": "free", "has_active_subscription": False, "plus_trial_eligible": False, "plan_http_status": 200}
            result = service.enqueue([self.row.row_id])
            self.assertEqual(result["accepted_count"], 1)
            deadline = time.time() + 2
            while service.public_state()["active"] and time.time() < deadline:
                time.sleep(0.01)
            saved = self.pool.result(self.row.row_id)
            self.assertEqual(saved["plan_check_status"], "success")
            self.assertEqual(saved["status"], "success")
            self.assertTrue(any(promoted for _row_id, promoted, _plan in updates))
        finally:
            service.shutdown()

    def test_429_saves_cooldown_and_deduplicates_requeue(self):
        self.pool.save_result(self.row.row_id, {"access_token": "token", "status": "success"})
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1)
        try:
            service._query = lambda _row_id: (_ for _ in ()).throw(FreePlanCheckError(
                "free_plan_check", "查询 Free 套餐资格", "限流", provider_status=429,
                error_code="free_plan_rate_limited", retry_after_seconds=60,
            ))
            accepted = service.enqueue([self.row.row_id])
            self.assertEqual(accepted["accepted_count"], 1)
            deadline = time.time() + 2
            while service.public_state()["active"] and time.time() < deadline:
                time.sleep(0.01)
            saved = self.pool.result(self.row.row_id)
            self.assertGreater(int(saved.get("plan_retry_after_until") or 0), int(time.time()))
            skipped = service.enqueue([self.row.row_id])
            self.assertEqual(skipped["accepted_count"], 0)
            self.assertIn("冷却", skipped["skipped"][0]["reason"])
        finally:
            service.shutdown()

    def test_recheck_rejects_unknown_mode(self):
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1, recover=False)
        try:
            with self.assertRaises(FreePlanCheckError):
                service.enqueue([self.row.row_id], "browser")
        finally:
            service.shutdown()

    def test_token_mode_still_skips_rows_without_token(self):
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1, recover=False)
        try:
            result = service.enqueue([self.row.row_id])
            self.assertEqual(result["accepted_count"], 0)
            self.assertIn("Token", result["skipped"][0]["reason"])
        finally:
            service.shutdown()

    def test_recheck_without_token_relogins_and_refreshes_plan(self):
        # The row deliberately has no access_token: only the recheck mode may
        # pick it up, and it must re-establish the account first.
        relogin_rows: list[str] = []
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1)

        def fake_relogin(row_id, _result, _task_id):
            relogin_rows.append(row_id)
            self.pool.save_result(row_id, {"access_token": "fresh-token", "has_access_token": True})
            return {"plan_check_status": "success", "plan_type": "plus", "subscription_plan": "plus", "has_active_subscription": True, "plan_http_status": 200}

        service._protocol_relogin_query = fake_relogin
        try:
            result = service.enqueue([self.row.row_id], "recheck")
            self.assertEqual(result["accepted_count"], 1)
            deadline = time.time() + 2
            while service.public_state()["active"] and time.time() < deadline:
                time.sleep(0.01)
            self.assertEqual(relogin_rows, [self.row.row_id])
            saved = self.pool.result(self.row.row_id)
            self.assertEqual(saved["plan_check_status"], "success")
            self.assertEqual(saved["plan_type"], "plus")
            self.assertEqual(saved["access_token"], "fresh-token")
        finally:
            service.shutdown()

    def test_recheck_401_falls_back_to_protocol_relogin(self):
        self.pool.save_result(self.row.row_id, {"access_token": "stale-token", "driver": "protocol"})
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1)
        attempts: list[str] = []
        relogin_rows: list[str] = []

        def fake_query(row_id, **_kwargs):
            attempts.append(row_id)
            raise FreePlanCheckError(
                "free_plan_check", "查询 Free 套餐资格", "Token 已失效",
                provider_status=401, error_code="free_plan_accounts_response_invalid",
            )

        def fake_relogin(row_id, _result, _task_id):
            relogin_rows.append(row_id)
            return {"plan_check_status": "success", "plan_type": "free", "plan_http_status": 200}

        service._query = fake_query
        service._protocol_relogin_query = fake_relogin
        try:
            result = service.enqueue([self.row.row_id], "recheck")
            self.assertEqual(result["accepted_count"], 1)
            deadline = time.time() + 2
            while service.public_state()["active"] and time.time() < deadline:
                time.sleep(0.01)
            self.assertEqual(attempts, [self.row.row_id])
            self.assertEqual(relogin_rows, [self.row.row_id])
            self.assertEqual(self.pool.result(self.row.row_id)["plan_check_status"], "success")
        finally:
            service.shutdown()

    def test_recheck_camoufox_row_uses_browser_callback_and_saves_account_fields(self):
        self.pool.save_result(self.row.row_id, {"access_token": "stale-token", "driver": "camoufox", "password": "saved-pass"})
        browser_calls: list[tuple[str, dict]] = []

        def browser_recheck(row_id, context, _log_fn):
            browser_calls.append((row_id, dict(context)))
            return {
                "plan_check_status": "success", "plan_type": "plus",
                "has_active_subscription": True, "plan_http_status": 200,
                "access_token": "browser-token", "has_access_token": True,
                "twofa_status": "enabled",
            }

        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1, browser_recheck=browser_recheck)

        def fake_query(_row_id, **_kwargs):
            raise FreePlanCheckError(
                "free_plan_check", "查询 Free 套餐资格", "Token 已失效",
                provider_status=401, error_code="free_plan_accounts_response_invalid",
            )

        service._query = fake_query
        try:
            result = service.enqueue([self.row.row_id], "recheck")
            self.assertEqual(result["accepted_count"], 1)
            deadline = time.time() + 2
            while service.public_state()["active"] and time.time() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(browser_calls), 1)
            row_id, context = browser_calls[0]
            self.assertEqual(row_id, self.row.row_id)
            self.assertEqual(context["email"], self.row.email)
            self.assertTrue(context["mailbox_url"])
            self.assertEqual(context["password"], "saved-pass")
            saved = self.pool.result(self.row.row_id)
            self.assertEqual(saved["plan_check_status"], "success")
            self.assertEqual(saved["access_token"], "browser-token")
            self.assertEqual(saved["twofa_status"], "enabled")
        finally:
            service.shutdown()

    def test_recheck_camoufox_row_with_valid_token_never_opens_browser(self):
        self.pool.save_result(self.row.row_id, {"access_token": "valid-token", "driver": "camoufox"})

        def browser_recheck(_row_id, _context, _log_fn):
            raise AssertionError("a valid token must answer without the browser")

        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1, browser_recheck=browser_recheck)
        service._query = lambda _row_id, **_kwargs: {"plan_check_status": "success", "plan_type": "free", "plan_http_status": 200}
        try:
            result = service.enqueue([self.row.row_id], "recheck")
            self.assertEqual(result["accepted_count"], 1)
            deadline = time.time() + 2
            while service.public_state()["active"] and time.time() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.pool.result(self.row.row_id)["plan_check_status"], "success")
        finally:
            service.shutdown()

    def test_recheck_skips_rows_with_active_registration(self):
        self.pool.update(self.row.row_id, status="running")
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1, recover=False)
        try:
            result = service.enqueue([self.row.row_id], "recheck")
            self.assertEqual(result["accepted_count"], 0)
            self.assertIn("注册", result["skipped"][0]["reason"])
        finally:
            service.shutdown()

    def test_recheck_confirmed_deactivation_deletes_pool_row(self):
        self.pool.save_result(self.row.row_id, {"access_token": "stale-token", "driver": "protocol"})
        service = FreePlanCheckService(self.temp.name, pool=self.pool, workers=1)
        service._recheck_query = lambda _row_id, _task_id: (_ for _ in ()).throw(FreePlanCheckError(
            "free_plan_relogin", "重查套餐重新登录", "重新登录明确返回账号已停用",
            retryable=False, error_code="account_deactivated",
        ))
        try:
            result = service.enqueue([self.row.row_id], "recheck")
            self.assertEqual(result["accepted_count"], 1)
            deadline = time.time() + 2
            while service.public_state()["active"] and time.time() < deadline:
                time.sleep(0.01)
            self.assertIsNone(self.pool.entry(self.row.row_id))
        finally:
            service.shutdown()


if __name__ == "__main__":
    unittest.main()
