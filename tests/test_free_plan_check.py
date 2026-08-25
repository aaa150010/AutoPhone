from __future__ import annotations

import time
import tempfile
import unittest
from unittest.mock import patch

from mac_overrides import free_account_service
from mac_overrides.free_account_service import plan_details_with_fallbacks
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


if __name__ == "__main__":
    unittest.main()
