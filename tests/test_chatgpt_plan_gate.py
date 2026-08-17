from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from mac_overrides.chatgpt_plan_gate import (
    ChatGptPlanGate,
    normalize_plan_type,
    plan_from_accounts_check,
)
from tests.web_gui_test_runtime import RecoveredWebGuiImport


class FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self.payload = payload


class FakeSession:
    def __init__(self, *responses):
        self.cookies = {"session": "present"}
        self.responses = list(responses)
        self.calls: list[dict] = []

    def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if not self.responses:
            raise AssertionError("unexpected session request")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class FakeChainError(RuntimeError):
    pass


class FakeAuthContextError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def jwt_token(*, account_id: str = "account-1", plan: str = "") -> str:
    auth = {"chatgpt_account_id": account_id}
    if plan:
        auth["chatgpt_plan_type"] = plan
    payload = {"https://api.openai.com/auth": auth}
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"header.{encoded}.signature"


def make_gate(transport, *, stages=None, prepared=None):
    stages = stages if stages is not None else []
    prepared = prepared if prepared is not None else []
    return ChatGptPlanGate(
        chatgpt_origin="https://chatgpt.example.test",
        json_response=lambda response: {
            **response.payload,
            "_status": response.status_code,
        },
        clean=lambda value: str(value or "").strip(),
        with_protocol_lease=lambda _transport, callback: callback(),
        request_headers=lambda _transport, headers, **_kwargs: dict(headers),
        active_transport=lambda: transport,
        transport_for_task=lambda _task_id: transport,
        transport_task_id=lambda value: str(value.config.get("sms_task_id") or ""),
        prepare_phone_entry=lambda value, **kwargs: prepared.append(
            (value, kwargs["expected_task_id"])
        ) or {"ok": True},
        set_stage=stages.append,
        auth_context_error=FakeAuthContextError,
        invalidate_auth_session=lambda *_args: None,
        chain_error=FakeChainError,
    )


class ChatGptPlanGateUnitTests(unittest.TestCase):
    def test_plan_normalization_blocks_unknown_markers_and_recognizes_known_plans(self):
        for plan in (
            "unknown_plan",
            "chatgpt_unknown_plan",
            "n/a",
            "not available",
            "unavailable",
        ):
            with self.subTest(plan=plan):
                self.assertEqual(normalize_plan_type(plan), "")

        self.assertEqual(normalize_plan_type("ChatGPTFreeWorkspacePlan"), "free")
        self.assertEqual(normalize_plan_type("ChatGPTGoPlan"), "go")
        self.assertEqual(normalize_plan_type("ChatGPTProLite"), "prolite")

    def test_accounts_check_selects_token_account_and_non_free_plans(self):
        token = jwt_token(account_id="wanted")
        for plan in ("plus", "team", "k12", "pro"):
            with self.subTest(plan=plan):
                detected, source = plan_from_accounts_check(
                    {
                        "accounts": {
                            "other": {"account": {"plan_type": "free"}},
                            "wanted": {"account": {"plan_type": plan}},
                        }
                    },
                    token=token,
                )
                self.assertEqual(detected, plan)
                self.assertEqual(source, "accounts_check.account.plan_type")

    def test_inactive_non_free_entitlement_is_not_a_current_paid_plan(self):
        detected, source = plan_from_accounts_check(
            {
                "accounts": {
                    "default": {
                        "account": {},
                        "entitlement": {
                            "subscription_plan": "ChatGPTPlusPlan",
                            "has_active_subscription": False,
                        },
                    }
                }
            }
        )

        self.assertEqual(detected, "")
        self.assertEqual(source, "")

    def test_explicit_session_plan_applies_free_only_policy(self):
        session = FakeSession()
        transport = SimpleNamespace(config={}, session=session)
        gate = make_gate(transport)

        for plan in (
            "plus",
            "team",
            "k12",
            "pro",
            "go",
            "prolite",
            "business",
            "enterprise",
            "edu",
        ):
            with self.subTest(plan=plan):
                transport._gptphone_chatgpt_session = {
                    "account": {"planType": plan}
                }
                decision = gate.evaluate_sms_binding(transport)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.plan_type, plan)

        transport._gptphone_chatgpt_session = {"account": {"planType": "free"}}
        decision = gate.evaluate_sms_binding(transport)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, "phone_plan_free_skipped")
        self.assertEqual(session.calls, [])

    def test_enabled_switch_bypasses_all_plan_queries(self):
        transport = SimpleNamespace(
            config={"allow_free_plan_sms_binding": True},
            session=FakeSession(),
            _gptphone_chatgpt_session={"account": {"planType": "free"}},
        )

        decision = make_gate(transport).evaluate_sms_binding(transport)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "config_bypass")
        self.assertEqual(transport.session.calls, [])

    def test_missing_cache_fetches_session_before_deciding(self):
        token = jwt_token(plan="plus")
        session = FakeSession(
            FakeResponse(
                200,
                {"accessToken": token, "account": {"planType": "plus"}},
            )
        )
        transport = SimpleNamespace(config={}, session=session)

        decision = make_gate(transport).evaluate_sms_binding(transport)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.plan_type, "plus")
        self.assertEqual(len(session.calls), 1)
        self.assertTrue(session.calls[0]["url"].endswith("/api/auth/session"))

    def test_session_http_failure_preserves_status_in_unknown_decision(self):
        session = FakeSession(
            FakeResponse(503, {"error": "temporarily unavailable"})
        )
        transport = SimpleNamespace(config={}, session=session)

        decision = make_gate(transport).evaluate_sms_binding(transport)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, "phone_plan_unknown_skipped")
        self.assertEqual(decision.http_status, 503)
        self.assertIn("ChatGPT session 查询返回 HTTP 503", decision.reason)

    def test_accounts_check_failure_blocks_without_exposing_credentials(self):
        secret = "access-token-secret-value"
        session = FakeSession(
            FakeResponse(503, {"error": {"access_token": secret}})
        )
        transport = SimpleNamespace(
            config={},
            session=session,
            _gptphone_chatgpt_session={"accessToken": secret},
            _gptphone_chatgpt_access_token=secret,
        )

        decision = make_gate(transport).evaluate_sms_binding(transport)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error_code, "phone_plan_unknown_skipped")
        self.assertEqual(decision.http_status, 503)
        self.assertIn("HTTP 503", decision.reason)
        self.assertNotIn(secret, decision.error_message())
        self.assertTrue(
            session.calls[0]["url"].endswith(
                "/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min=-"
            )
        )

    def test_accounts_check_result_controls_sms_binding_when_session_has_no_plan(self):
        token = jwt_token(account_id="wanted")
        for plan, allowed in (("free", False), ("team", True)):
            with self.subTest(plan=plan):
                session = FakeSession(
                    FakeResponse(
                        200,
                        {
                            "accounts": {
                                "wanted": {"account": {"plan_type": plan}}
                            }
                        },
                    )
                )
                transport = SimpleNamespace(
                    config={},
                    session=session,
                    _gptphone_chatgpt_session={"accessToken": token},
                    _gptphone_chatgpt_access_token=token,
                )

                decision = make_gate(transport).evaluate_sms_binding(transport)

                self.assertEqual(decision.allowed, allowed)
                self.assertEqual(decision.plan_type, plan)
                self.assertEqual(len(session.calls), 1)

    def test_capture_access_token_does_not_enforce_phone_plan_gate(self):
        token = jwt_token(plan="free")
        session = FakeSession(
            FakeResponse(
                200,
                {"accessToken": token, "account": {"planType": "free"}},
            )
        )
        transport = SimpleNamespace(config={}, session=session)

        captured = make_gate(transport).capture_access_token(transport)

        self.assertEqual(captured, token)
        self.assertEqual(transport._gptphone_chatgpt_plan_type, "free")


class PaidAllocationReached(RuntimeError):
    pass


class ChatGptPlanGateIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.previous_data_dir = os.environ.get("GPTPHONE_DATA_DIR")
        os.environ["GPTPHONE_DATA_DIR"] = cls.tempdir.name
        cls.web_gui_import = RecoveredWebGuiImport(Path(__file__).resolve().parents[1])
        cls.module = cls.web_gui_import.load()

    @classmethod
    def tearDownClass(cls):
        if cls.previous_data_dir is None:
            os.environ.pop("GPTPHONE_DATA_DIR", None)
        else:
            os.environ["GPTPHONE_DATA_DIR"] = cls.previous_data_dir
        cls.web_gui_import.cleanup()
        cls.tempdir.cleanup()

    def _run_until_allocation(self, *, task_id: str, plan: str, allow_free: bool):
        module = self.module
        calls = []
        session = FakeSession()
        transport = SimpleNamespace(
            config={
                "sms_task_id": task_id,
                "_auth_account_email": f"{task_id}@example.test",
                "allow_free_plan_sms_binding": allow_free,
            },
            account_email=f"{task_id}@example.test",
            session=session,
            sentinel_provider=SimpleNamespace(reset=lambda *_args: None),
            proxy="",
            device_id="device-test",
            _gptphone_page_type="add_phone",
            _gptphone_chatgpt_session={"account": {"planType": plan}},
        )
        adapter = SimpleNamespace(
            config=transport.config,
            provider=SimpleNamespace(),
            selector=None,
        )
        original_preflight = module._SMS_WEB.phone_context_preflight
        original_allocate = module._SMS_WEB.original_adapter_get_number
        active_token = module._ACTIVE_SMS_TRANSPORT.set(None)
        module._register_sms_transport(task_id, transport)

        def paid_allocation(*_args, **_kwargs):
            calls.append("paid_allocation")
            raise PaidAllocationReached(task_id)

        try:
            module._SMS_WEB.phone_context_preflight = module._preflight_sms_phone_context
            module._SMS_WEB.original_adapter_get_number = paid_allocation
            error = None
            try:
                module._SMS_WEB.adapter_get_number(adapter)
            except Exception as exc:
                error = exc
            return calls, error, session.calls
        finally:
            module._SMS_WEB.phone_context_preflight = original_preflight
            module._SMS_WEB.original_adapter_get_number = original_allocate
            module._ACTIVE_SMS_TRANSPORT.reset(active_token)
            module._unregister_sms_transport(task_id, transport)
            module._AUTH_SESSIONS.clear(task_id)

    def test_free_plan_stops_before_paid_number_allocation(self):
        calls, error, session_calls = self._run_until_allocation(
            task_id="task-free-plan",
            plan="free",
            allow_free=False,
        )

        self.assertEqual(calls, [])
        self.assertIn("phone_plan_free_skipped", str(error))
        self.assertEqual(session_calls, [])

    def test_non_free_plans_continue_to_paid_number_allocation(self):
        for plan in (
            "plus",
            "team",
            "k12",
            "pro",
            "go",
            "prolite",
            "business",
            "enterprise",
            "edu",
        ):
            with self.subTest(plan=plan):
                calls, error, session_calls = self._run_until_allocation(
                    task_id=f"task-{plan}-plan",
                    plan=plan,
                    allow_free=False,
                )
                self.assertEqual(calls, ["paid_allocation"])
                self.assertIsInstance(error, PaidAllocationReached)
                self.assertEqual(session_calls, [])

    def test_unknown_plan_stops_before_paid_number_allocation(self):
        for plan in ("", "unknown_plan", "chatgpt_unknown_plan", "n/a"):
            with self.subTest(plan=plan):
                calls, error, session_calls = self._run_until_allocation(
                    task_id=f"task-unknown-plan-{plan or 'empty'}",
                    plan=plan,
                    allow_free=False,
                )

                self.assertEqual(calls, [])
                self.assertIn("phone_plan_unknown_skipped", str(error))
                self.assertEqual(len(session_calls), 1)

    def test_enabled_switch_allows_free_without_plan_query(self):
        calls, error, session_calls = self._run_until_allocation(
            task_id="task-free-bypass",
            plan="free",
            allow_free=True,
        )

        self.assertEqual(calls, ["paid_allocation"])
        self.assertIsInstance(error, PaidAllocationReached)
        self.assertEqual(session_calls, [])

    def test_configuration_defaults_disabled_and_preserves_explicit_true(self):
        disabled = self.module._local_config_from_runtime({}, {})
        enabled = self.module._local_config_from_runtime(
            {"allow_free_plan_sms_binding": True},
            disabled,
        )
        preserved = self.module._local_config_from_runtime({}, enabled)

        self.assertFalse(disabled["allow_free_plan_sms_binding"])
        self.assertTrue(enabled["allow_free_plan_sms_binding"])
        self.assertTrue(preserved["allow_free_plan_sms_binding"])
        self.assertFalse(
            self.module._apply_server_defaults({})["allow_free_plan_sms_binding"]
        )

    def test_plan_gate_failures_do_not_retry_the_whole_auth_session(self):
        for code in ("phone_plan_free_skipped", "phone_plan_unknown_skipped"):
            with self.subTest(code=code):
                self.assertFalse(
                    self.module._patched_pre_auth_session_retryable(
                        {"phase2_error": f"{code}: stopped before SMS allocation"}
                    )
                )


if __name__ == "__main__":
    unittest.main()
