from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from mac_overrides.free_live_check import FreeLiveCheckService
from mac_overrides.free_log_runtime import FreeLogStore
from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore


class FreeLiveCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp.name)
        self.services: list[FreeLiveCheckService] = []

    def tearDown(self) -> None:
        for service in self.services:
            service.shutdown(wait=True)
        self.temp.cleanup()

    @staticmethod
    def _probe(proxy: str, _target: str) -> str:
        port = int(urlsplit(proxy).port or 9001)
        return f"10.0.0.{port - 9000}"

    def _resources(self, count: int = 1):
        pool = FreeMailboxPool(self.data_dir)
        proxies = FreeProxyPool(self.data_dir)
        logs = FreeLogStore(self.data_dir)
        mailboxes = "\n".join(
            f"account{index}@example.test----https://mail.example.test/{index}"
            for index in range(1, count + 1)
        )
        proxy_values = [
            f"http://user{index}:secret{index}@proxy{index}.example.test:{9000 + index}"
            for index in range(1, count + 1)
        ]
        pool.import_text(mailboxes)
        proxies.import_text("\n".join(proxy_values), country="US", group="live-test", scheme="http")
        bindings = proxies.bind(count, probe=self._probe)
        for entry, binding in zip(pool.entries(), bindings):
            result = {
                "status": "success",
                "task_id": f"free-register-{entry.line_no}",
                "driver": "protocol",
                "access_token": f"old-token-{entry.line_no}",
                "password": f"password-{entry.line_no}",
                "totp_secret": "JBSWY3DPEHPK3PXP",
                "proxy": binding.proxy,
                "proxy_id": binding.proxy_id,
                "proxy_scheme": binding.scheme,
                "proxy_country": binding.country,
                "proxy_group": binding.group,
                "expected_exit_ip": binding.exit_ip,
                "registration_ip": binding.exit_ip,
                "plan_type": "free",
            }
            pool.save_result(entry.row_id, result)
            pool.update(
                entry.row_id,
                status="success",
                proxy=binding.proxy,
                proxy_id=binding.proxy_id,
                proxy_scheme=binding.scheme,
                proxy_country=binding.country,
                proxy_group=binding.group,
                proxy_masked=binding.masked,
                registration_ip=binding.exit_ip,
                expected_exit_ip=binding.exit_ip,
            )
        return pool, proxies, logs

    def _service(self, pool, proxies, logs, **kwargs):
        service = FreeLiveCheckService(
            self.data_dir,
            pool=pool,
            proxies=proxies,
            log_store=logs,
            config_provider=lambda: {"proxy_probe_url": "https://probe.example.test", "email_code_timeout": 10},
            proxy_probe=self._probe,
            recover=False,
            **kwargs,
        )
        self.services.append(service)
        return service

    def _wait(self, service: FreeLiveCheckService, timeout: float = 3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = service.public_state()
            if not state["running"]:
                return state
            time.sleep(0.01)
        self.fail("Free 测活任务未在测试时限内结束")

    def test_fast_check_uses_registration_proxy_and_preserves_registration_status(self):
        pool, proxies, logs = self._resources()
        observed = []

        def runner(context, _config):
            observed.append(dict(context))
            return {
                "status": "live",
                "plan_check_status": "success",
                "plan_type": "free",
                "subscription_plan": "free",
                "plus_trial_eligible": True,
            }

        service = self._service(pool, proxies, logs, fast_runner=runner)
        row = pool.entries()[0]
        started = service.enqueue([row.row_id], "fast")
        state = self._wait(service)

        self.assertEqual(started["accepted_count"], 1)
        self.assertEqual(state["jobs"][0]["status"], "live")
        self.assertEqual(observed[0]["proxy"], pool.result(row.row_id)["proxy"])
        self.assertEqual(observed[0]["registration_ip"], "10.0.0.1")
        self.assertEqual(pool._row_state(row.row_id)["status"], "success")
        saved = pool.result(row.row_id)
        self.assertEqual(saved["live_check_status"], "live")
        self.assertEqual(saved["live_check_ip"], "10.0.0.1")
        self.assertTrue(saved["plus_trial_eligible"])
        self.assertTrue(logs.snapshot(started["accepted"][0]["task_id"]))

    def test_live_check_clears_stale_plan_only_partial_status(self):
        pool, proxies, logs = self._resources()
        row = pool.entries()[0]
        saved = pool.result(row.row_id)
        saved.update({
            "status": "partial_success",
            "plan_check_status": "failed",
            "plan_error_code": "free_plan_accounts_response_invalid",
            "failure": {
                "error_code": "free_plan_accounts_response_invalid",
                "node_code": "free_plan_check",
            },
        })
        pool.save_result(row.row_id, saved)
        pool.update(row.row_id, status="partial_success")
        task_store = FreeTaskStore(self.data_dir)
        task_store.save({
            saved["task_id"]: {
                "task_id": saved["task_id"],
                "status": "partial_success",
                "failure": saved["failure"],
                "result": dict(saved),
            },
        })

        service = self._service(
            pool,
            proxies,
            logs,
            task_store=task_store,
            fast_runner=lambda _context, _config: {
                "status": "live",
                "plan_check_status": "success",
                "plan_type": "free",
            },
        )
        service.enqueue([row.row_id], "fast")
        self._wait(service)

        result = pool.result(row.row_id)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["plan_check_status"], "success")
        self.assertNotIn("failure", result)
        self.assertEqual(pool._row_state(row.row_id)["status"], "success")
        task = task_store.load()[saved["task_id"]]
        self.assertEqual(task["status"], "success")
        self.assertNotIn("failure", task)

    def test_failed_followup_live_check_does_not_restore_plan_only_partial_status(self):
        pool, proxies, logs = self._resources()
        row = pool.entries()[0]
        saved = pool.result(row.row_id)
        saved.update({
            "status": "partial_success",
            "plan_check_status": "success",
            "plan_type": "free",
            "plan_error_code": "free_plan_accounts_response_invalid",
            "failure": {
                "error_code": "free_plan_accounts_response_invalid",
                "node_code": "free_plan_check",
            },
        })
        pool.save_result(row.row_id, saved)
        pool.update(row.row_id, status="partial_success")

        service = self._service(pool, proxies, logs)
        service._save_live_result(row.row_id, {
            "live_check_status": "failed",
            "live_check_failure": {
                "error_code": "free_live_account_http_failed",
                "node_code": "free_live_fast",
            },
        })

        result = pool.result(row.row_id)
        self.assertEqual(result["status"], "success")
        self.assertNotIn("failure", result)
        self.assertEqual(pool._row_state(row.row_id)["status"], "success")

    def test_fast_unauthorized_does_not_mark_account_deactivated(self):
        pool, proxies, logs = self._resources()
        service = self._service(
            pool,
            proxies,
            logs,
            fast_runner=lambda _context, _config: {"status": "token_expired", "http_status": 401},
        )
        row = pool.entries()[0]
        original_token = pool.result(row.row_id)["access_token"]
        service.enqueue([row.row_id], "fast")
        self._wait(service)

        saved = pool.result(row.row_id)
        self.assertEqual(saved["live_check_status"], "token_expired")
        self.assertEqual(saved["access_token"], original_token)
        self.assertIsNone(saved.get("live_check_failure"))

    def test_fast_account_query_classifies_401_explicit_deactivation_and_live_plan(self):
        pool, proxies, logs = self._resources()
        service = self._service(pool, proxies, logs)

        class Response:
            def __init__(self, status, payload):
                self.status_code = status
                self.payload = payload

            def json(self):
                return self.payload

        class Session:
            def __init__(self, responses):
                self.responses = list(responses)

            def get(self, *_args, **_kwargs):
                return self.responses.pop(0)

        unauthorized = service._query_account(Session([Response(401, {})]), "expired-token")
        deactivated = service._query_account(
            Session([Response(403, {"error": {"code": "account_deactivated"}})]),
            "disabled-token",
        )
        live = service._query_account(
            Session(
                [
                    Response(200, {"accounts": {"account-a": {"plan_type": "free"}}}),
                    Response(200, {"eligible_promo_campaigns": {"plus": {"campaign_id": "plus-trial-a"}}}),
                ]
            ),
            "live-token",
        )

        self.assertEqual(unauthorized["status"], "token_expired")
        self.assertEqual(deactivated["status"], "deactivated")
        self.assertEqual(deactivated["failure"]["error_code"], "account_deactivated")
        self.assertEqual(live["status"], "live")
        self.assertTrue(live["plus_trial_eligible"])
        self.assertEqual(live["eligible_campaign_id"], "plus-trial-a")

    def test_account_query_sends_task_device_context_and_target_routes(self):
        pool, proxies, logs = self._resources()
        service = self._service(pool, proxies, logs)

        class Cookies:
            def __init__(self):
                self.values = []

            def set(self, name, value, **kwargs):
                self.values.append((name, value, kwargs))

        class Response:
            status_code = 200
            headers = {"content-type": "application/json"}
            text = ""

            def __init__(self, payload):
                self.payload = payload

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.calls = []
                self.cookies = Cookies()
                self.headers = {}
                self.trust_env = True

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                if len(self.calls) == 1:
                    return Response({"accounts": {"account-a": {"plan_type": "free"}}})
                return Response({})

        session = Session()
        result = service._query_account(session, "private-token", device_id="device-task-a")

        self.assertEqual(result["status"], "live")
        self.assertFalse(session.trust_env)
        self.assertTrue(any(item[0:2] == ("oai-did", "device-task-a") for item in session.cookies.values))
        account_headers = session.calls[0][1]["headers"]
        self.assertEqual(account_headers["oai-device-id"], "device-task-a")
        self.assertEqual(account_headers["x-openai-target-path"], "/backend-api/accounts/check/v4-2023-04-27")
        self.assertEqual(account_headers["x-openai-target-route"], "/backend-api/accounts/check/v4-2023-04-27")
        self.assertEqual(account_headers["referer"], "https://chatgpt.com/")
        self.assertEqual(account_headers["sec-fetch-site"], "same-origin")
        self.assertEqual(account_headers["sec-fetch-mode"], "cors")
        self.assertEqual(account_headers["sec-fetch-dest"], "empty")
        self.assertEqual(account_headers["authorization"], "Bearer private-token")
        eligibility_headers = session.calls[1][1]["headers"]
        self.assertEqual(eligibility_headers["x-openai-target-route"], "/backend-api/aip/first-party/eligibility")

    def test_account_query_classifies_security_rate_limit_upstream_and_network_failures(self):
        pool, proxies, logs = self._resources()
        service = self._service(pool, proxies, logs)

        class Response:
            def __init__(self, status, payload=None, *, headers=None, text=""):
                self.status_code = status
                self.payload = payload or {}
                self.headers = headers or {}
                self.text = text

            def json(self):
                return self.payload

        class Session:
            def __init__(self, response=None, error=None):
                self.response = response
                self.error = error

            def get(self, *_args, **_kwargs):
                if self.error is not None:
                    raise self.error
                return self.response

        cases = (
            (
                Response(403, {"error": {"code": "access_denied"}}),
                "free_live_proxy_blocked",
                0,
            ),
            (
                Response(403, headers={"content-type": "text/html"}, text="Checking your browser - Cloudflare"),
                "free_live_proxy_blocked",
                0,
            ),
            (
                Response(429, {"error": {"code": "rate_limit"}}, headers={"retry-after": "17"}),
                "free_live_rate_limited",
                17,
            ),
            (
                Response(503, {"error": {"code": "upstream_unavailable"}}),
                "free_live_upstream_error",
                0,
            ),
        )
        for response, node_code, retry_after in cases:
            with self.subTest(node_code=node_code, status=response.status_code):
                with self.assertRaises(FreeRegisterError) as caught:
                    service._query_account(Session(response), "private-token", device_id="device-task-b")
                self.assertEqual(caught.exception.node_code, node_code)
                self.assertTrue(caught.exception.retryable)
                self.assertEqual(caught.exception.retry_after_seconds, retry_after)

        with self.assertRaises(FreeRegisterError) as caught:
            service._query_account(Session(error=TimeoutError("private network detail")), "private-token")
        self.assertEqual(caught.exception.node_code, "free_live_network_error")
        self.assertTrue(caught.exception.retryable)
        self.assertNotIn("private network detail", str(caught.exception))

    def test_retryable_failure_nodes_remain_visible_in_mailbox_live_status(self):
        pool, proxies, logs = self._resources(4)
        node_by_email = {
            "account1@example.test": "free_live_rate_limited",
            "account2@example.test": "free_live_upstream_error",
            "account3@example.test": "free_live_network_error",
            "account4@example.test": "free_live_password_required",
        }

        def runner(context, _config):
            node = node_by_email[context["email"]]
            raise FreeRegisterError(node, "Free 测活分类", "可重试分类", retryable=node != "free_live_password_required")

        service = self._service(pool, proxies, logs, fast_runner=runner)
        service.enqueue([row.row_id for row in pool.entries()], "fast")
        self._wait(service)

        for row in pool.entries():
            with self.subTest(email=row.email):
                saved = pool.result(row.row_id)
                self.assertEqual(saved["live_check_status"], node_by_email[row.email])
                self.assertEqual(saved["status"], "success")

    def test_deep_check_refreshes_token_on_the_same_proxy(self):
        pool, proxies, logs = self._resources()
        observed = []

        def deep_runner(context, _config):
            observed.append((context["proxy"], context["registration_ip"]))
            return {
                "status": "live",
                "access_token": "new-access-token",
                "plan_check_status": "success",
                "plan_type": "free",
            }

        service = self._service(pool, proxies, logs, deep_runner=deep_runner)
        row = pool.entries()[0]
        service.enqueue([row.row_id], "deep")
        self._wait(service)

        saved = pool.result(row.row_id)
        self.assertEqual(observed, [(saved["proxy"], "10.0.0.1")])
        self.assertEqual(saved["access_token"], "new-access-token")
        self.assertTrue(saved["live_check_token_refreshed"])
        self.assertEqual(saved["live_check_mode"], "deep")

    def test_proxy_drift_updates_live_ip_and_continues_runner(self):
        pool, proxies, logs = self._resources()
        called = []
        service = FreeLiveCheckService(
            self.data_dir,
            pool=pool,
            proxies=proxies,
            log_store=logs,
            config_provider=lambda: {},
            proxy_probe=lambda _proxy, _target: "10.0.0.99",
            fast_runner=lambda *_args: called.append(True) or {"status": "live"},
            recover=False,
        )
        self.services.append(service)
        row = pool.entries()[0]
        service.enqueue([row.row_id], "fast")
        self._wait(service)

        saved = pool.result(row.row_id)
        self.assertTrue(called)
        self.assertEqual(saved["live_check_status"], "live")
        self.assertEqual(saved["live_check_ip"], "10.0.0.99")
        self.assertEqual(saved["expected_exit_ip"], "10.0.0.1")
        self.assertEqual(saved["exit_ip"], "10.0.0.99")
        self.assertEqual(pool._row_state(row.row_id)["status"], "success")
        self.assertEqual(saved["access_token"], "old-token-1")

    def test_proxy_drift_failure_persists_current_exit_ip(self):
        pool, proxies, logs = self._resources()
        service = FreeLiveCheckService(
            self.data_dir,
            pool=pool,
            proxies=proxies,
            log_store=logs,
            config_provider=lambda: {},
            proxy_probe=lambda _proxy, _target: "10.0.0.99",
            fast_runner=lambda *_args: (_ for _ in ()).throw(
                FreeRegisterError(
                    "free_live_proxy_blocked",
                    "出口拒绝",
                    "安全策略拒绝",
                    retryable=True,
                )
            ),
            recover=False,
        )
        self.services.append(service)
        row = pool.entries()[0]
        service.enqueue([row.row_id], "fast")
        self._wait(service)

        saved = pool.result(row.row_id)
        self.assertEqual(saved["registration_ip"], "10.0.0.1")
        self.assertEqual(saved["live_check_ip"], "10.0.0.99")
        self.assertEqual(saved["expected_exit_ip"], "10.0.0.1")
        self.assertEqual(saved["exit_ip"], "10.0.0.99")
        self.assertEqual(saved["live_check_status"], "free_live_proxy_blocked")

    def test_live_failure_identity_is_canonical_and_redacted_in_job_result_and_api(self):
        pool, proxies, logs = self._resources()
        secret = "private-live-path"

        def runner(_context, _config):
            raise FreeRegisterError(
                "free_live_fast",
                "快速测活",
                f"请求失败 https://user:pass@example.test/{secret}?token=private-token otp_code=123456",
                provider_status=503,
                provider_code="upstream_unavailable",
                action_hint="稍后重试",
            )

        service = self._service(pool, proxies, logs, fast_runner=runner)
        row = pool.entries()[0]
        service.enqueue([row.row_id], "fast")
        state = self._wait(service)

        public_failure = state["jobs"][0]["failure"]
        saved_failure = pool.result(row.row_id)["live_check_failure"]
        persisted = json.loads(service.path.read_text(encoding="utf-8"))
        persisted_failure = next(iter(persisted["jobs"].values()))["failure"]
        self.assertEqual(public_failure, saved_failure)
        self.assertEqual(public_failure, persisted_failure)
        self.assertEqual(public_failure["node_code"], "free_live_fast")
        self.assertEqual(public_failure["http_status"], 503)
        self.assertEqual(public_failure["provider_code"], "upstream_unavailable")
        for value in ("user:pass", secret, "private-token", "123456"):
            self.assertNotIn(value, str(public_failure))
            self.assertNotIn(value, service.path.read_text(encoding="utf-8"))

    def test_queue_limits_active_workers_to_three_and_allows_shared_proxies(self):
        pool, proxies, logs = self._resources(5)
        release = threading.Event()
        three_started = threading.Event()
        lock = threading.Lock()
        active = peak = 0
        seen: list[str] = []

        def runner(context, _config):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                seen.append(context["proxy"])
                if active == 3:
                    three_started.set()
            release.wait(2)
            with lock:
                active -= 1
            return {"status": "live"}

        service = self._service(pool, proxies, logs, fast_runner=runner, workers=3)
        result = service.enqueue([row.row_id for row in pool.entries()], "fast")
        self.assertEqual(result["accepted_count"], 5)
        self.assertTrue(three_started.wait(1))
        self.assertEqual(peak, 3)
        release.set()
        self._wait(service)
        self.assertEqual(len(seen), 5)
        self.assertGreaterEqual(len(set(seen)), 1)
        self.assertLessEqual(len(set(seen)), 5)

    def test_failure_logs_redact_token_password_and_proxy_credentials(self):
        pool, proxies, logs = self._resources()

        def runner(context, _config):
            raise RuntimeError(
                f"access_token={context['access_token']} password={context['password']} proxy={context['proxy']}"
            )

        service = self._service(pool, proxies, logs, fast_runner=runner)
        row = pool.entries()[0]
        started = service.enqueue([row.row_id], "fast")
        self._wait(service)
        text = "\n".join(item["message"] for item in logs.snapshot(started["accepted"][0]["task_id"]))
        self.assertNotIn("old-token-1", text)
        self.assertNotIn("password-1", text)
        self.assertNotIn("secret1", text)

    def test_deep_default_runner_handles_email_otp_and_refreshes_session_token(self):
        pool, proxies, logs = self._resources()
        service = self._service(pool, proxies, logs)
        calls: list[str] = []

        class FakeOtp:
            def __init__(self, *_args, **_kwargs):
                pass

            def mark_sent(self):
                calls.append("mark_sent")

            def wait_code(self, _email):
                calls.append("wait_code")
                return "123456"

        class FakeSession:
            def close(self):
                calls.append("session_close")

        class FakeTransport:
            def __init__(self, *_args, **_kwargs):
                self.session = FakeSession()
                self._gptphone_initial_email_otp_send_confirmed = True
                self.ready = False

            def start_chatgpt_signup_authorize(self, _email):
                calls.append("start")
                return {"page_type": "email_identifier"}

            def submit_email_identifier(self, _email):
                calls.append("submit")
                return {"page_type": "email_otp_verification", "continue_url": "https://auth.example/otp"}

            def verify_email_otp(self, code):
                calls.append(f"verify:{code}")
                return {"page_type": "continue", "continue_url": "https://chatgpt.example/callback"}

            def complete_chatgpt_callback(self, _url):
                calls.append("callback")
                self.ready = True
                return {"page_type": "done"}

            def chatgpt_access_token(self):
                return "deep-session-token" if self.ready else ""

            def close(self):
                calls.append("transport_close")

        runner_module = types.ModuleType("codex_chain_runner")
        runner_module.build_oauth_url = lambda **_kwargs: ("https://oauth.example/start", "verifier", "state")
        oauth_module = types.ModuleType("codex_oauth_chain")
        oauth_module.parse_oauth_url = lambda _url: {"client_id": "client", "redirect_uri": "http://localhost"}
        oauth_module.RealNodeSentinelProvider = lambda **_kwargs: object()
        oauth_module.RealCodexTransport = FakeTransport
        oauth_module._page_type = lambda response: response.get("page_type", "")
        oauth_module._continue_url = lambda response: response.get("continue_url", "")
        oauth_module._is_success_response = lambda response: response.get("ok", True)
        context = service._context({"task_id": "free-live-deep-test", "row_id": pool.entries()[0].row_id})

        with patch.dict(sys.modules, {"codex_chain_runner": runner_module, "codex_oauth_chain": oauth_module}), patch(
            "mac_overrides.free_live_check.MailboxUrlOtpProvider", FakeOtp
        ), patch.object(
            service,
            "_query_account",
            return_value={"status": "live", "plan_type": "free"},
        ):
            result = service._run_deep(context, {"email_code_timeout": 10, "protocol": {}})

        self.assertEqual(result["status"], "live")
        self.assertEqual(result["access_token"], "deep-session-token")
        self.assertEqual(calls[:6], ["start", "mark_sent", "submit", "wait_code", "verify:123456", "callback"])
        self.assertIn("session_close", calls)
        self.assertIn("transport_close", calls)


if __name__ == "__main__":
    unittest.main()
