"""Focused tests for the composable Free Camoufox boundaries."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock

from mac_overrides.free_camoufox.contracts import (
    CamoufoxFlowContext,
    CamoufoxFlowState,
    CamoufoxRegistrationRequest,
    CamoufoxRegistrationResult,
    normalize_flow_state,
)
from mac_overrides.free_camoufox.debug_artifacts import (
    DebugEventBuffer,
    sanitize_debug_text,
    write_json_atomic,
)
from mac_overrides.free_camoufox.browser_pool import BrowserPoolGateway
from mac_overrides.free_camoufox.errors import (
    browser_process_lost,
    is_transient_navigation_error,
    navigation_failure_category,
    navigation_failure_reason,
)
from mac_overrides.free_camoufox.state_machine import (
    CamoufoxFlowCoordinator,
    CamoufoxStateMachine,
    InvalidTransitionError,
)
from mac_overrides.free_camoufox.transport import CamoufoxTransport, PageTransportContract


class _Locator:
    def __init__(self, visible: bool = True, enabled: bool = True) -> None:
        self.first = self
        self.visible = visible
        self.enabled = enabled
        self.values: list[str] = []
        self.clicks = 0

    async def is_visible(self, **_kwargs):
        return self.visible

    async def is_enabled(self, **_kwargs):
        return self.enabled

    async def click(self, **_kwargs):
        self.clicks += 1

    async def fill(self, value, **_kwargs):
        self.values.append(str(value))

    async def press(self, _key):
        self.clicks += 1

    async def inner_text(self, **_kwargs):
        return "body text"


class _Page:
    def __init__(self) -> None:
        self.locators: dict[str, _Locator] = {}
        self.title = AsyncMock(return_value="ChatGPT")

    def locator(self, selector: str):
        return self.locators.setdefault(selector, _Locator())

    async def evaluate(self, script, arg=None):
        return {"script": script, "arg": arg}

    async def goto(self, url, **_kwargs):
        self.url = url
        return {"url": url}


class _Pool:
    def __init__(self):
        self.calls = []

    def register(self, **kwargs):
        self.calls.append(kwargs)
        return {"ok": True}

    def shutdown(self):
        self.calls.append({"shutdown": True})
        return True


class _StateTransport:
    def __init__(self, *states):
        self.states = list(states)

    async def page_state(self):
        return self.states.pop(0) if self.states else "unknown"


class ContractTests(unittest.TestCase):
    def test_request_mapping_does_not_require_manager_shape(self):
        request = CamoufoxRegistrationRequest.from_mapping({
            "email": " user@example.test ",
            "proxy": "socks5://127.0.0.1:1080",
            "task_id": "task-1",
            "saved_password": "secret",
            "expected_exit_ip": "203.0.113.10",
            "force_existing_login": True,
        })
        self.assertEqual(request.email, "user@example.test")
        self.assertEqual(request.existing_password, "secret")
        self.assertTrue(request.force_existing_login)
        self.assertNotIn("secret", repr(request))
        public = request.public_dict()
        self.assertEqual(public["email"], "u***@example.test")
        self.assertNotIn("proxy", public)

    def test_result_public_projection_masks_email_and_omits_private_fields(self):
        result = CamoufoxRegistrationResult(
            email="user@example.test",
            success=True,
            state=CamoufoxFlowState.HOME,
            fields={"access_token": "private"},
        )
        public = result.public_dict()
        self.assertEqual(public["email"], "u***@example.test")
        self.assertNotIn("access_token", public)

    def test_pool_snapshot_whitelists_and_redacts_session_metadata(self):
        from mac_overrides.free_camoufox.contracts import CamoufoxPoolSnapshot

        snapshot = CamoufoxPoolSnapshot(sessions=({
            "session_id": "session-1",
            "task_id": "task-private@example.test",
            "safe_page": "https://chatgpt.com/auth/login?code=private",
            "token": "must-not-project",
            "password": "must-not-project",
            "created_at": 100.0,
        },))
        public = snapshot.as_dict()
        self.assertEqual(public["sessions"][0]["session_id"], "session-1")
        self.assertEqual(public["sessions"][0]["safe_page"], "https://chatgpt.com/auth/login")
        self.assertNotIn("private@example.test", str(public))
        self.assertNotIn("must-not-project", str(public))

    def test_pool_snapshot_redacts_sensitive_trusted_path_segments(self):
        from mac_overrides.free_camoufox.contracts import CamoufoxPoolSnapshot

        public = CamoufoxPoolSnapshot(sessions=({
            "safe_page": "https://auth.openai.com/u/user@example.test/phone/13800138000",
        },)).as_dict()
        page = public["sessions"][0]["safe_page"]
        self.assertNotIn("user@example.test", page)
        self.assertNotIn("13800138000", page)

    def test_context_records_normalized_checkpoints_and_deadline(self):
        context = CamoufoxFlowContext(
            CamoufoxRegistrationRequest(email="user@example.test"),
            deadline_monotonic=10.0,
        )
        checkpoint = context.observe("login-password", observed_at=1.0)
        self.assertEqual(checkpoint.state, CamoufoxFlowState.LOGIN_PASSWORD)
        self.assertEqual(context.state, CamoufoxFlowState.LOGIN_PASSWORD)
        self.assertFalse(context.expired(now=9.9))
        self.assertTrue(context.expired(now=10.0))

    def test_state_machine_rejects_impossible_terminal_transition(self):
        machine = CamoufoxStateMachine("entry")
        machine.transition("otp")
        machine.transition("home")
        self.assertTrue(machine.terminal)
        with self.assertRaises(InvalidTransitionError):
            machine.transition("entry")

    def test_profile_consent_is_a_first_class_step_before_completion(self):
        machine = CamoufoxStateMachine("profile")
        transition = machine.transition("profile_consent", reason="terms_required")
        self.assertEqual(transition.current, CamoufoxFlowState.CONSENT)
        self.assertFalse(machine.terminal)
        machine.transition("home", reason="consent_accepted")
        self.assertEqual(machine.state, CamoufoxFlowState.HOME)
        self.assertEqual(
            [item.current for item in machine.history],
            [CamoufoxFlowState.CONSENT, CamoufoxFlowState.HOME],
        )

    def test_security_challenge_is_terminal_until_a_new_attempt(self):
        machine = CamoufoxStateMachine("entry")
        machine.transition("security", reason="challenge")
        self.assertTrue(machine.terminal)
        self.assertFalse(machine.can_transition("home"))
        with self.assertRaises(InvalidTransitionError):
            machine.transition("home")

    def test_terminal_observation_cannot_be_replaced_by_unknown_cleanup_state(self):
        machine = CamoufoxStateMachine("entry")
        machine.transition("otp", reason="otp_submitted")
        machine.transition("home", reason="oauth_complete")
        with self.assertRaises(InvalidTransitionError):
            machine.observe("unknown", reason="page_closed_during_cleanup")
        self.assertEqual(machine.state, CamoufoxFlowState.HOME)
        self.assertTrue(machine.terminal)

    def test_flow_coordinator_records_transport_observations(self):
        async def exercise():
            coordinator = CamoufoxFlowCoordinator(
                _StateTransport("entry", "otp", "home"),
                machine=CamoufoxStateMachine("unknown"),
            )
            result = await coordinator.wait_for({"home"}, timeout=0.2, poll_interval=0.01)
            self.assertTrue(result.matched)
            self.assertEqual(result.state, CamoufoxFlowState.HOME)
            self.assertEqual([item.current for item in coordinator.machine.history], [
                CamoufoxFlowState.ENTRY,
                CamoufoxFlowState.OTP,
                CamoufoxFlowState.HOME,
            ])

        asyncio.run(exercise())

    def test_state_machine_can_run_unknown_observation_without_poisoning_history(self):
        machine = CamoufoxStateMachine("entry")
        transition = machine.observe("unrecognized-page", reason="hydrating")
        self.assertEqual(transition.current, CamoufoxFlowState.UNKNOWN)
        self.assertEqual(machine.state, CamoufoxFlowState.UNKNOWN)
        machine.transition("entry")
        self.assertEqual(machine.state, CamoufoxFlowState.ENTRY)

    def test_transport_contract_and_common_operations(self):
        page = _Page()
        transport = CamoufoxTransport(page)
        valid, missing = PageTransportContract.check(transport)
        self.assertTrue(valid)
        self.assertEqual(missing, ())

        async def exercise():
            found = await transport.wait_for_any(("#missing", "#email"), timeout=0.05, poll_interval=0.01)
            self.assertEqual(found, "#missing")
            self.assertTrue(await transport.fill("#email", "user@example.test"))
            self.assertEqual(await transport.click("#email"), "#email")
            self.assertTrue(await transport.submit("#email"))
            self.assertEqual(await transport.body_text(), "body text")
            self.assertEqual(await transport.title(), "ChatGPT")
            value = await transport.evaluate("x => x", {"ok": True})
            self.assertEqual(value["arg"], {"ok": True})
            await transport.goto("https://chatgpt.com/")
            snapshot = await transport.snapshot()
            self.assertEqual(snapshot["state"], "home")
            self.assertEqual(snapshot["url"], "https://chatgpt.com/")

        asyncio.run(exercise())
        self.assertEqual(page.locators["#email"].values, ["", "user@example.test"])

    def test_error_classification_is_transport_only(self):
        error = RuntimeError("page.goto: navigation timeout while connecting to proxy")
        self.assertTrue(is_transient_navigation_error(error))
        self.assertFalse(browser_process_lost(error))
        self.assertEqual(navigation_failure_category(error), "navigation_timeout")
        self.assertEqual(navigation_failure_reason(error), "timeout")
        self.assertTrue(browser_process_lost(RuntimeError("browser disconnected")))

    def test_debug_event_buffer_is_bounded_and_redacts_common_values(self):
        events = DebugEventBuffer(limit=10)
        events.add("response", text="code=123456 email=user@example.test")
        events.add("response", token="raw-secret", proxy="socks5://user:pass@proxy.test:1080")
        events.add("response", secret_value="another-secret")
        snapshot = events.snapshot()
        self.assertEqual(len(snapshot), 3)
        self.assertNotIn("123456", str(snapshot))
        self.assertNotIn("user@example.test", str(snapshot))
        self.assertNotIn("raw-secret", str(snapshot))
        self.assertNotIn("user:pass@proxy.test", str(snapshot))
        self.assertNotIn("another-secret", str(snapshot))

    def test_debug_event_buffer_honors_small_limit_exactly(self):
        events = DebugEventBuffer(limit=1)
        events.add("first", message="one")
        events.add("second", message="two")
        snapshot = events.snapshot()
        self.assertEqual(len(snapshot), 1)
        self.assertEqual(snapshot[0]["kind"], "second")

    def test_debug_event_snapshot_is_detached(self):
        events = DebugEventBuffer(limit=2)
        events.add("response", details={"state": "entry"})
        snapshot = events.snapshot()
        snapshot[0]["details"] = {"state": "mutated"}
        self.assertNotEqual(events.snapshot()[0].get("details"), {"state": "mutated"})

    def test_debug_fallback_redaction_removes_urls_and_authorization(self):
        safe = sanitize_debug_text(
            "Authorization: Bearer abc.def https://evil.test/callback?code=secret code=654321"
        )
        self.assertNotIn("abc.def", safe)
        self.assertNotIn("evil.test", safe)
        self.assertNotIn("654321", safe)

    def test_atomic_artifact_writer_projects_unknown_fields(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            write_json_atomic(path, {
                "artifact_id": "artifact-1",
                "safe_page": "https://chatgpt.com/auth/login?token=secret",
                "password": "must-not-persist",
                "events": [{"kind": "response", "text": "code=123456"}],
            })
            raw = path.read_text(encoding="utf-8")
            self.assertIn("artifact-1", raw)
            self.assertNotIn("must-not-persist", raw)
            self.assertNotIn("token=secret", raw)
            self.assertNotIn("123456", raw)

    def test_debug_capture_projects_legacy_response_and_constrains_path(self):
        import tempfile
        from pathlib import Path
        import mac_overrides.free_camoufox.debug_artifacts as module

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            async def fake_capture(**_kwargs):
                return {
                    "artifact_id": "wrong-id",
                    "artifact_path": "/tmp/outside-secret",
                    "token": "must-not-cross",
                    "screenshot": "saved",
                }

            runtime = module._legacy_runtime()
            original = getattr(runtime, "_capture_debug_artifact", None)
            setattr(runtime, "_capture_debug_artifact", fake_capture)
            try:
                result = asyncio.run(module.DebugArtifactService(root).capture(
                    page=object(), session_id="session-1", artifact_id="safe-id",
                    summary={}, trace=None,
                ))
            finally:
                setattr(runtime, "_capture_debug_artifact", original)
            self.assertEqual(result["artifact_id"], "safe-id")
            self.assertEqual(result["artifact_path"], "")
            self.assertNotIn("must-not-cross", str(result))

    def test_state_normalization_has_safe_unknown_fallback(self):
        self.assertIs(normalize_flow_state("oauth"), CamoufoxFlowState.OAUTH_CALLBACK)
        self.assertIs(
            normalize_flow_state("sign_in_with_chatgpt_codex_consent"),
            CamoufoxFlowState.CONSENT,
        )
        self.assertIs(normalize_flow_state("not-a-real-state"), CamoufoxFlowState.UNKNOWN)

    def test_package_keeps_legacy_class_identity_without_browser_import(self):
        from mac_overrides.free_camoufox import (
            CamoufoxBrowserError,
            CamoufoxBrowserPool,
            CamoufoxRegistrationRunner,
        )
        from mac_overrides import free_camoufox_runtime

        self.assertIs(CamoufoxBrowserError, free_camoufox_runtime.CamoufoxBrowserError)
        self.assertIs(CamoufoxBrowserPool, free_camoufox_runtime.CamoufoxBrowserPool)
        self.assertIs(CamoufoxRegistrationRunner, free_camoufox_runtime.CamoufoxRegistrationRunner)

    def test_legacy_entrypoint_lazily_exports_new_boundaries(self):
        from mac_overrides import free_camoufox_runtime
        from mac_overrides.free_camoufox import (
            BrowserPoolGateway,
            CamoufoxTransport,
            CamoufoxStateMachine,
            DebugArtifactService,
            DebugEventBuffer,
        )

        self.assertIs(free_camoufox_runtime.CamoufoxTransport, CamoufoxTransport)
        self.assertIs(free_camoufox_runtime.CamoufoxStateMachine, CamoufoxStateMachine)
        self.assertIs(free_camoufox_runtime.BrowserPoolGateway, BrowserPoolGateway)
        self.assertIs(free_camoufox_runtime.DebugArtifactService, DebugArtifactService)
        self.assertIs(free_camoufox_runtime.DebugEventBuffer, DebugEventBuffer)

    def test_pool_gateway_supports_injected_pool_and_legacy_shutdown_signature(self):
        pool = _Pool()
        gateway = BrowserPoolGateway({"pool_size": 1}, pool=pool)
        self.assertEqual(gateway.register(email="user@example.test"), {"ok": True})
        self.assertTrue(gateway.shutdown(force=True))
        self.assertEqual(pool.calls[0]["email"], "user@example.test")

    def test_runner_facade_preserves_delegate_signature(self):
        from mac_overrides.free_camoufox.runner import CamoufoxRunner

        runner = CamoufoxRunner()
        self.assertEqual(runner.lifecycle_store_path, "")
        self.assertEqual(runner.debug_artifact_dir, "")
        self.assertTrue(callable(runner.delegate))

    def test_typed_request_preserves_private_result_for_password_retry(self):
        from mac_overrides.free_camoufox.runner import runner_from_request

        captured = {}

        class _Runner:
            def __call__(self, task, config, stop_event, stage, log, **kwargs):
                captured["task"] = task
                captured["kwargs"] = kwargs
                return {"success": True}

        request = CamoufoxRegistrationRequest(
            email="user@example.test",
            task_id="task-1",
            password_retry=True,
            password_retry_token="token-private",
            prior_result={"password_status": "pending", "account_flow": "signup"},
        )
        # Patch the facade's constructor target without importing browser code
        # or invoking a real pool.
        import mac_overrides.free_camoufox.runner as module
        original = module.CamoufoxRunner
        try:
            module.CamoufoxRunner = lambda: _Runner()
            runner_from_request(request, {}, object(), lambda *_: None, lambda *_: None)
        finally:
            module.CamoufoxRunner = original

        self.assertEqual(captured["task"]["result"]["password_status"], "pending")
        self.assertEqual(captured["task"]["result"]["access_token"], "token-private")
        self.assertTrue(captured["kwargs"]["password_retry"])
        self.assertNotIn("token-private", repr(request))

    def test_runner_bridge_does_not_inject_retry_token_for_normal_signup(self):
        from mac_overrides.free_camoufox.runner import runner_from_request

        captured = {}

        class _Runner:
            def __call__(self, task, config, stop_event, stage, log, **kwargs):
                captured["task"] = task
                return {"success": True}

        request = CamoufoxRegistrationRequest(
            email="user@example.test", password_retry_token="should-stay-private"
        )
        import mac_overrides.free_camoufox.runner as module
        original = module.CamoufoxRunner
        try:
            module.CamoufoxRunner = lambda: _Runner()
            runner_from_request(request, {}, object(), lambda *_: None, lambda *_: None)
        finally:
            module.CamoufoxRunner = original
        self.assertNotIn("access_token", captured["task"]["result"])

    def test_runner_bridge_keeps_existing_token_alias(self):
        from mac_overrides.free_camoufox.runner import runner_from_request

        captured = {}

        class _Runner:
            def __call__(self, task, config, stop_event, stage, log, **kwargs):
                captured["task"] = task
                return {"success": True}

        request = CamoufoxRegistrationRequest(
            email="user@example.test", password_retry=True,
            password_retry_token="new-token", prior_result={"token": "old-token"},
        )
        import mac_overrides.free_camoufox.runner as module
        original = module.CamoufoxRunner
        try:
            module.CamoufoxRunner = lambda: _Runner()
            runner_from_request(request, {}, object(), lambda *_: None, lambda *_: None)
        finally:
            module.CamoufoxRunner = original
        self.assertEqual(captured["task"]["result"]["token"], "old-token")
        self.assertNotIn("access_token", captured["task"]["result"])

    def test_private_result_snapshot_is_detached_for_nested_retry_state(self):
        nested = {"failure": {"error_code": "old"}}
        request = CamoufoxRegistrationRequest(
            email="user@example.test", prior_result=nested,
        )
        snapshot = request.private_result_snapshot()
        snapshot["failure"]["error_code"] = "mutated"
        self.assertEqual(nested["failure"]["error_code"], "old")

    def test_request_mapping_reads_result_as_prior_result_without_public_projection(self):
        request = CamoufoxRegistrationRequest.from_mapping({
            "email": "user@example.test",
            "password_retry": True,
            "result": {"access_token": "secret-token", "password_status": "pending"},
        })
        self.assertEqual(request.prior_result["password_status"], "pending")
        self.assertNotIn("secret-token", repr(request))
        self.assertNotIn("secret-token", str(request.public_dict()))

    def test_request_mapping_drops_incidental_result_for_new_signup(self):
        request = CamoufoxRegistrationRequest.from_mapping({
            "email": "user@example.test",
            "result": {"access_token": "must-not-retain"},
        })
        self.assertEqual(request.prior_result, {})

    def test_request_mapping_preserves_prior_result_for_existing_login_retry(self):
        request = CamoufoxRegistrationRequest.from_mapping({
            "email": "user@example.test",
            "force_existing_login": True,
            "result": {"access_token": "private", "account_flow": "signup"},
        })
        self.assertEqual(request.prior_result["account_flow"], "signup")
        self.assertNotIn("private", str(request.public_dict()))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
