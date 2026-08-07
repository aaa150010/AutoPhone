from __future__ import annotations

import unittest
from types import SimpleNamespace

from mac_overrides.auth_request_runtime import (
    AuthRequestContextError,
    begin_request,
    finish_request,
    invalidate_auth_session,
    mark_phone_ready,
    recover_phone_entry_context,
    validate_phone_context,
)
from mac_overrides.auth_session_runtime import (
    AuthSessionRegistry,
    invalidation_reason_code,
    is_session_invalid,
)


class AuthSessionRuntimeTests(unittest.TestCase):
    def test_session_invalid_marker_is_detected_without_needing_raw_response_shape(self):
        self.assertTrue(is_session_invalid("oauth_session_invalid: Your sign-in session is no longer valid"))
        self.assertTrue(is_session_invalid({"code": "oauth_session_invalid", "status": 401}))
        self.assertTrue(is_session_invalid("mfa_otp_failed: Invalid authorization step."))
        self.assertFalse(is_session_invalid({"code": "phone_send_rejected"}))
        self.assertEqual(
            invalidation_reason_code("mfa_otp_failed: Invalid authorization step."),
            "mfa_authorization_step_expired",
        )
        self.assertEqual(
            invalidation_reason_code({"code": "mfa_authorization_step_expired"}),
            "mfa_authorization_step_expired",
        )
        self.assertEqual(
            invalidation_reason_code("private_mailbox_token: unexpected failure"),
            "auth_session_invalid",
        )

    def test_phone_context_accepts_only_number_entry_pages(self):
        for page_type in (
            "add_phone",
            "contact_verification",
            "phone_number_collection",
        ):
            with self.subTest(page_type=page_type):
                transport = SimpleNamespace(
                    config={"sms_task_id": f"task-{page_type}"},
                    session=SimpleNamespace(cookies={"session": "present"}),
                    _gptphone_page_type=page_type,
                )
                context = validate_phone_context(transport, AuthSessionRegistry())
                self.assertEqual(context.task_id, f"task-{page_type}")

    def test_phone_context_still_rejects_unrelated_auth_page(self):
        transport = SimpleNamespace(
            config={"sms_task_id": "task-consent"},
            session=SimpleNamespace(cookies={"session": "present"}),
            _gptphone_page_type="consent",
        )

        with self.assertRaisesRegex(AuthRequestContextError, "不是手机号录入页面") as raised:
            validate_phone_context(transport, AuthSessionRegistry())

        self.assertEqual(raised.exception.code, "auth_context_page_mismatch")
        self.assertIn("page_type=consent", str(raised.exception))

    def test_phone_otp_page_is_restored_with_private_task_entry_url(self):
        visits = []
        registry = AuthSessionRegistry()
        transport = SimpleNamespace(
            config={"sms_task_id": "task-recover"},
            session=SimpleNamespace(cookies={"session": "present"}),
            _gptphone_page_type="add_phone",
        )
        mark_phone_ready(
            transport,
            registry,
            {"_status": 200, "page": {"type": "add_phone"}},
            continue_url="https://auth.openai.com/add-phone?state=private-oauth-state",
        )
        transport._gptphone_page_type = "phone_otp_verification"
        transport._gptphone_request_context.page_type = "phone_otp_verification"

        context = recover_phone_entry_context(
            transport,
            registry,
            expected_task_id="task-recover",
            visit_fn=lambda url, **_kwargs: visits.append(url) or {
                "_status": 200,
                "page": {"type": "add_phone"},
            },
        )

        self.assertEqual(context.page_type, "add_phone")
        self.assertEqual(visits, ["https://auth.openai.com/add-phone?state=private-oauth-state"])
        self.assertNotIn("private-oauth-state", repr(registry.public_snapshot("task-recover")))

    def test_phone_otp_page_is_restored_from_real_add_phone_html(self):
        registry = AuthSessionRegistry()
        transport = SimpleNamespace(
            config={"sms_task_id": "task-html-recover"},
            session=SimpleNamespace(cookies={"session": "present"}),
            _gptphone_page_type="add_phone",
        )
        mark_phone_ready(
            transport,
            registry,
            {"_status": 200, "page": {"type": "add_phone"}},
            continue_url="https://auth.openai.com/add-phone",
        )
        transport._gptphone_page_type = "phone_otp_verification"
        transport._gptphone_request_context.page_type = "phone_otp_verification"

        context = recover_phone_entry_context(
            transport,
            registry,
            expected_task_id="task-html-recover",
            visit_fn=lambda _url, **_kwargs: {
                "_status": 200,
                "_content_type": "text/html; charset=utf-8",
                "_url": "https://auth.openai.com/add-phone",
                "_html_title": "Phone number required - OpenAI",
            },
        )

        self.assertEqual(context.page_type, "add_phone")
        self.assertEqual(transport._gptphone_page_type, "add_phone")

    def test_phone_otp_html_recovery_rejects_unrelated_final_url(self):
        registry = AuthSessionRegistry()
        transport = SimpleNamespace(
            config={"sms_task_id": "task-html-login"},
            session=SimpleNamespace(cookies={"session": "present"}),
            _gptphone_page_type="add_phone",
        )
        mark_phone_ready(
            transport,
            registry,
            {"_status": 200, "page": {"type": "add_phone"}},
            continue_url="https://auth.openai.com/add-phone",
        )
        transport._gptphone_page_type = "phone_otp_verification"
        transport._gptphone_request_context.page_type = "phone_otp_verification"

        with self.assertRaises(AuthRequestContextError) as raised:
            recover_phone_entry_context(
                transport,
                registry,
                expected_task_id="task-html-login",
                visit_fn=lambda _url, **_kwargs: {
                    "_status": 200,
                    "_content_type": "text/html; charset=utf-8",
                    "_url": "https://auth.openai.com/log-in",
                    "_html_title": "Log in - OpenAI",
                },
            )

        self.assertEqual(raised.exception.code, "phone_flow_login_regressed")
        self.assertIn("回退到登录验证页面", str(raised.exception))

    def test_phone_otp_html_recovery_rejects_non_phone_html_on_entry_url(self):
        for title, body, expected_code in (
            (
                "Log in - OpenAI",
                "<main><h1>Welcome back</h1></main>",
                "phone_flow_login_regressed",
            ),
            (
                "Just a moment...",
                "<main>Checking your browser</main>",
                "auth_context_page_mismatch",
            ),
        ):
            with self.subTest(title=title):
                registry = AuthSessionRegistry()
                transport = SimpleNamespace(
                    config={"sms_task_id": f"task-html-{title}"},
                    session=SimpleNamespace(cookies={"session": "present"}),
                    _gptphone_page_type="add_phone",
                )
                mark_phone_ready(
                    transport,
                    registry,
                    {"_status": 200, "page": {"type": "add_phone"}},
                    continue_url="https://auth.openai.com/add-phone",
                )
                transport._gptphone_page_type = "phone_otp_verification"
                transport._gptphone_request_context.page_type = "phone_otp_verification"

                with self.assertRaises(AuthRequestContextError) as raised:
                    recover_phone_entry_context(
                        transport,
                        registry,
                        expected_task_id=f"task-html-{title}",
                        visit_fn=lambda _url, **_kwargs: {
                            "_status": 200,
                            "_content_type": "text/html; charset=utf-8",
                            "_url": "https://auth.openai.com/add-phone",
                            "_html_title": title,
                            "_body": body,
                        },
                    )
                self.assertEqual(raised.exception.code, expected_code)

    def test_phone_context_distinguishes_mfa_and_login_regressions(self):
        for page_type, expected_code in (
            ("mfa_otp_verification", "phone_flow_mfa_regressed"),
            ("password_verification", "phone_flow_login_regressed"),
            ("login_password", "phone_flow_login_regressed"),
            ("password_required", "phone_flow_login_regressed"),
        ):
            with self.subTest(page_type=page_type):
                transport = SimpleNamespace(
                    config={"sms_task_id": f"task-{page_type}"},
                    session=SimpleNamespace(cookies={"session": "present"}),
                    _gptphone_page_type=page_type,
                )
                with self.assertRaises(AuthRequestContextError) as raised:
                    validate_phone_context(transport, AuthSessionRegistry())
                self.assertEqual(raised.exception.code, expected_code)

    def test_phone_otp_recovery_without_saved_entry_fails(self):
        transport = SimpleNamespace(
            config={"sms_task_id": "task-no-entry"},
            session=SimpleNamespace(cookies={"session": "present"}),
            _gptphone_page_type="phone_otp",
        )
        with self.assertRaisesRegex(AuthRequestContextError, "缺少可恢复"):
            recover_phone_entry_context(
                transport,
                AuthSessionRegistry(),
                expected_task_id="task-no-entry",
            )

    def test_invalidation_keeps_count_across_fresh_generation_and_cancels_sms(self):
        cancellations = []
        registry = AuthSessionRegistry(
            cancel_sms=lambda task_id, reason: cancellations.append((task_id, reason)),
        )
        item = registry.start_generation(
            "task-1",
            email="user@example.test",
            node_instance_id="node-a",
            transport_instance_id="transport-a",
        )
        registry.observe(
            "task-1",
            "phone_submitting",
            continue_url="https://auth.example.test/add-phone?state=secret",
            success=True,
        )
        registry.invalidate("task-1", "oauth_session_invalid", stage="phone_submitting")
        self.assertEqual(item.invalidations, 1)
        self.assertTrue(item.fresh_oauth_required)
        self.assertEqual(item.latest_continue_path, "")
        self.assertEqual(cancellations, [("task-1", "oauth_session_invalid")])

        fresh = registry.start_generation(
            "task-1",
            email="user@example.test",
            node_instance_id="node-b",
            transport_instance_id="transport-b",
        )
        self.assertIs(fresh, item)
        self.assertEqual(fresh.generation, 2)
        self.assertEqual(fresh.invalidations, 1)
        self.assertFalse(fresh.invalid)
        self.assertFalse(fresh.fresh_oauth_required)
        self.assertNotEqual(fresh.node_instance_id, "")

        registry.invalidate("task-1", "oauth_session_invalid", stage="phone_submitting")
        self.assertEqual(fresh.invalidations, 2)
        self.assertEqual(len(cancellations), 2)

    def test_transport_invalidation_clears_private_auth_state_and_reports_exact_reason(self):
        callbacks = []
        cancellations = []
        sentinel_resets = []
        registry = AuthSessionRegistry(
            cancel_sms=lambda task_id, reason: cancellations.append((task_id, reason)),
            on_invalidate=lambda *args: callbacks.append(args),
        )
        cookies = {"session": "present", "other": "private"}
        transport = SimpleNamespace(
            config={
                "sms_task_id": "task-clean",
                "_auth_account_email": "risk@example.test",
                "phase1_active_session": "must-be-discarded",
            },
            account_email="risk@example.test",
            session=SimpleNamespace(cookies=cookies),
            sentinel_provider=SimpleNamespace(
                reset=lambda: sentinel_resets.append(True),
            ),
            _gptphone_page_type="add_phone",
        )
        mark_phone_ready(
            transport,
            registry,
            {"_status": 200, "page": {"type": "add_phone"}},
            continue_url="https://auth.openai.com/add-phone?state=private-state",
        )
        context = transport._gptphone_request_context

        invalidate_auth_session(
            transport,
            registry,
            "phone_flow_mfa_regressed: stale MFA page",
            stage="phone_submitting",
        )

        self.assertEqual(cookies, {})
        self.assertEqual(sentinel_resets, [True])
        self.assertNotIn("phase1_active_session", transport.config)
        self.assertTrue(transport.config["_phone_risk_retry"])
        self.assertEqual(
            transport.config["_phone_risk_reason_code"],
            "phone_flow_mfa_regressed",
        )
        self.assertEqual(context.phone_entry_url, "")
        self.assertEqual(context.continue_path, "")
        self.assertEqual(context.last_sentinel, {})
        self.assertEqual(
            callbacks,
            [(
                "task-clean",
                "risk@example.test",
                "phone_flow_mfa_regressed",
                "phone_submitting",
            )],
        )
        self.assertEqual(
            cancellations,
            [("task-clean", "phone_flow_mfa_regressed")],
        )

    def test_public_snapshot_contains_fingerprints_but_not_session_material(self):
        registry = AuthSessionRegistry()
        registry.start_generation(
            "task-safe",
            email="user@example.test",
            node_instance_id="node-secret",
            transport_instance_id="transport-secret",
        )
        registry.observe(
            "task-safe",
            "phone_submitting",
            continue_url="https://auth.example.test/add-phone?state=oauth-secret",
            success=True,
        )
        item = registry.get("task-safe")
        item.begin_request(
            endpoint="/api/accounts/add-phone/send",
            stage="phone_submitting",
            cookies_present=True,
            csrf_present=True,
        )
        snapshot = registry.public_snapshot("task-safe")
        serialized = repr(snapshot)
        self.assertNotIn("node-secret", serialized)
        self.assertNotIn("transport-secret", serialized)
        self.assertNotIn("oauth-secret", serialized)
        self.assertEqual(snapshot["current_stage"], "phone_submitting")
        self.assertEqual(snapshot["events"][-1]["continue_path"], "/add-phone")

    def test_request_completion_updates_the_same_registered_event(self):
        registry = AuthSessionRegistry()
        transport = SimpleNamespace(
            config={"sms_task_id": "task-request", "_auth_account_email": "user@example.test"},
            account_email="user@example.test",
            session=SimpleNamespace(cookies={"session": "present"}),
            proxy="",
            _gptphone_page_type="add_phone",
        )

        request = begin_request(
            transport,
            registry,
            endpoint="/api/accounts/add-phone/send",
            stage="phone_submitting",
        )
        finish_request(
            transport,
            registry,
            request,
            {"_status": 200, "page": {"type": "phone_otp"}},
        )

        snapshot = registry.public_snapshot("task-request")
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(snapshot["events"][0]["request_context_id"], request["request_context_id"])
        self.assertEqual(snapshot["events"][0]["response_status"], 200)
        self.assertEqual(snapshot["events"][0]["page_type"], "phone_otp")


if __name__ == "__main__":
    unittest.main()
