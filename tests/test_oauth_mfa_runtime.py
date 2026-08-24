from __future__ import annotations

import threading
import unittest
from types import SimpleNamespace

from mac_overrides.oauth_mfa_runtime import (
    bind_provider_totp_secret,
    clear_task_secrets,
    EmailOtpMfaRuntime,
    provider_stop_event,
    runtime_task_id,
    TaskSecretRegistry,
    normalize_totp_secret,
    remember_provider_totp_secret,
)


class EmailOtpMfaRuntimeTests(unittest.TestCase):
    def test_task_secret_registry_is_thread_safe_and_task_scoped(self):
        registry = TaskSecretRegistry()
        worker = threading.Thread(
            target=registry.remember,
            args=("task-a", "JBSWY3DPEHPK3PXP"),
        )
        worker.start()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        registry.remember("task-b", "MFRGGZDFMZTWQ2LK")
        self.assertEqual(registry.get("task-a"), "JBSWY3DPEHPK3PXP")
        self.assertEqual(registry.get("task-b"), "MFRGGZDFMZTWQ2LK")
        registry.clear("task-a")
        self.assertEqual(registry.get("task-a"), "")
        self.assertEqual(registry.get("task-b"), "MFRGGZDFMZTWQ2LK")

    def test_totp_secret_normalization_rejects_non_base32_values(self):
        self.assertEqual(
            normalize_totp_secret(" totp: jbsw y3d pehp k3pxp "),
            "JBSWY3DPEHPK3PXP",
        )
        self.assertEqual(normalize_totp_secret("not-a-secret!"), "")
        registry = TaskSecretRegistry()
        registry.remember("task-invalid", "not-a-secret!")
        self.assertEqual(registry.get("task-invalid"), "")

    def test_explicit_task_id_wins_over_stale_provider_task_id(self):
        registry = TaskSecretRegistry()
        provider = SimpleNamespace(
            task_id="task-stale",
            config={"sms_task_id": "task-also-stale"},
            entry=SimpleNamespace(
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token="JBSWY3DPEHPK3PXP",
            ),
        )

        remember_provider_totp_secret(
            provider,
            registry,
            task_id="task-current",
            current_task_get=lambda: "task-context",
        )

        self.assertEqual(registry.get("task-current"), "JBSWY3DPEHPK3PXP")
        self.assertEqual(registry.get("task-stale"), "")
        self.assertEqual(registry.get("task-also-stale"), "")

    def test_runtime_task_helpers_keep_one_canonical_key(self):
        provider = SimpleNamespace(
            task_id="task-provider-stale",
            config={"sms_task_id": "task-provider-config"},
            entry=SimpleNamespace(
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token="JBSWY3DPEHPK3PXP",
            ),
        )
        transport = SimpleNamespace(config={"sms_task_id": "task-transport"})
        registry = TaskSecretRegistry()
        task_id = runtime_task_id(
            {},
            context_task_get=lambda: "",
            transport=transport,
            transport_task_id_get=lambda current: current.config.get("sms_task_id"),
        )
        bound = bind_provider_totp_secret(
            provider,
            registry,
            task_id=task_id,
            current_task_get=lambda: "",
        )

        self.assertEqual(task_id, "task-transport")
        self.assertEqual(bound, "task-transport")
        self.assertEqual(registry.get("task-transport"), "JBSWY3DPEHPK3PXP")
        self.assertIsNone(provider_stop_event(SimpleNamespace(config={})))
        clear_task_secrets(registry, task_id, bound)
        self.assertEqual(registry.get("task-transport"), "")

    def test_signup_email_otp_completes_mfa_before_continuation(self):
        secret = ["JBSWY3DPEHPK3PXP"]
        original_calls = []
        totp_calls = []
        observed = []
        checkpoints = []
        continued = []

        def original_verify(transport, code):
            original_calls.append((transport, code))
            return {
                "_status": 200,
                "page": {"type": "mfa_challenge"},
                "continue_url": "/mfa-challenge/factor-safe",
            }

        def verify_totp(transport, **kwargs):
            totp_calls.append((transport, kwargs))
            return {"_status": 200, "page": {"type": "consent"}}

        def continue_if_needed(transport, response, *, origin):
            continued.append((transport, response, origin))
            return {**response, "continued": True}

        runtime = EmailOtpMfaRuntime(
            secret_get=lambda: secret[0],
            secret_clear=lambda: secret.__setitem__(0, ""),
            checkpoint_save=lambda transport, response: checkpoints.append(
                (transport, response)
            ),
            response_error_code=lambda response: str(
                (response.get("error") or {}).get("code") or ""
            ),
            page_type=lambda response: str(response["page"]["type"]),
            observe_auth_step=lambda transport, response, stage: observed.append(stage),
            continue_if_needed=continue_if_needed,
            factor_id=lambda _response: "factor-safe",
            verify_totp=verify_totp,
            verify_mfa=lambda *_args, **_kwargs: None,
            manual_fallback=lambda *_args: None,
            session_invalid=lambda _response: False,
            stop_event=lambda _transport: None,
        )
        transport = SimpleNamespace(log_fn=lambda *_args: None)

        result = runtime.verify(transport, "email-code", original_verify)

        self.assertEqual(original_calls, [(transport, "email-code")])
        self.assertEqual(secret, [""])
        self.assertEqual(len(totp_calls), 1)
        self.assertEqual(totp_calls[0][1]["factor_id"], "factor-safe")
        self.assertEqual(totp_calls[0][1]["secret"], "JBSWY3DPEHPK3PXP")
        self.assertTrue(callable(totp_calls[0][1]["verify_fn"]))
        self.assertEqual(observed, ["mfa_otp_verifying"])
        self.assertEqual(len(checkpoints), 2)
        self.assertEqual(continued[0][2], "email_otp")
        self.assertTrue(result["continued"])

    def test_signup_email_otp_supports_transport_bound_secret(self):
        original_calls = []
        totp_calls = []

        def original_verify(transport, code):
            original_calls.append((transport, code))
            return {
                "_status": 200,
                "page": {"type": "mfa_challenge"},
                "continue_url": "/mfa-challenge/factor-safe",
            }

        def verify_totp(transport, **kwargs):
            totp_calls.append((transport, kwargs))
            return {"_status": 200, "page": {"type": "consent"}}

        class Provider:
            entry = type(
                "Entry",
                (),
                {
                    "oauth_client_id": "chatgpt_totp",
                    "oauth_refresh_token": "JBSWY3DPEHPK3PXP",
                },
            )()

        transport = SimpleNamespace(
            _gptphone_auth_challenge_context=SimpleNamespace(
                email_otp_provider=Provider()
            )
        )
        runtime = EmailOtpMfaRuntime(
            secret_get=lambda current: getattr(
                getattr(
                    getattr(current, "_gptphone_auth_challenge_context", None),
                    "email_otp_provider",
                    None,
                ).entry,
                "oauth_refresh_token",
                "",
            ),
            secret_clear=lambda: None,
            checkpoint_save=lambda *_args: None,
            response_error_code=lambda response: str(
                (response.get("error") or {}).get("code") or ""
            ),
            page_type=lambda response: response["page"]["type"],
            observe_auth_step=lambda *_args: None,
            continue_if_needed=lambda *_args, **_kwargs: None,
            factor_id=lambda _response: "factor-safe",
            verify_totp=verify_totp,
            verify_mfa=lambda *_args, **_kwargs: None,
            manual_fallback=lambda *_args: None,
            session_invalid=lambda _response: False,
            stop_event=lambda _transport: None,
        )

        runtime.verify(transport, "email-code", original_verify)

        self.assertEqual(original_calls, [(transport, "email-code")])
        self.assertEqual(totp_calls[0][1]["secret"], "JBSWY3DPEHPK3PXP")

    def test_expected_totp_without_secret_stops_before_callback_continuation(self):
        continued = []
        observed = []

        runtime = EmailOtpMfaRuntime(
            secret_get=lambda _transport: "",
            secret_clear=lambda *_args: None,
            checkpoint_save=lambda *_args: None,
            response_error_code=lambda response: str(
                (response.get("error") or {}).get("code") or ""
            ),
            page_type=lambda response: response["page"]["type"],
            observe_auth_step=lambda _transport, _response, stage: observed.append(stage),
            continue_if_needed=lambda *_args, **_kwargs: continued.append(True),
            factor_id=lambda _response: "factor-safe",
            verify_totp=lambda *_args, **_kwargs: None,
            verify_mfa=lambda *_args, **_kwargs: None,
            manual_fallback=lambda *_args: None,
            session_invalid=lambda _response: False,
            stop_event=lambda _transport: None,
            requires_secret=lambda _transport: True,
        )
        response = runtime.verify(
            SimpleNamespace(log_fn=lambda *_args: None),
            "email-code",
            lambda *_args: {"_status": 200, "page": {"type": "mfa_challenge"}},
        )

        self.assertEqual(response["error"]["code"], "mfa_totp_secret_missing")
        # recovered codex_oauth_chain._error_text only exposes error.message;
        # the stable code must therefore survive in that field too.
        self.assertIn(
            "mfa_totp_secret_missing",
            response["error"]["message"],
        )
        self.assertEqual(observed, ["mfa_otp_verifying"])
        self.assertEqual(continued, [])

    def test_url_only_mfa_without_totp_marker_stops_before_callback(self):
        continued = []
        response = {
            "_status": 200,
            "page": {"type": "mfa_challenge"},
            "continue_url": "/mfa-challenge/factor-private",
        }
        runtime = EmailOtpMfaRuntime(
            secret_get=lambda _transport: "",
            secret_clear=lambda *_args: None,
            checkpoint_save=lambda *_args: None,
            response_error_code=lambda value: str(
                (value.get("error") or {}).get("code") or ""
            ),
            page_type=lambda value: value["page"]["type"],
            observe_auth_step=lambda *_args: None,
            continue_if_needed=lambda *_args, **_kwargs: continued.append(True),
            factor_id=lambda _value: "factor-private",
            verify_totp=lambda *_args, **_kwargs: self.fail(
                "URL-only MFA must not attempt TOTP without a secret"
            ),
            verify_mfa=lambda *_args, **_kwargs: None,
            manual_fallback=lambda *_args: None,
            session_invalid=lambda _value: False,
            stop_event=lambda _transport: None,
            # This mirrors an ordinary `email----URL` provider: no TOTP
            # client marker and no task registry entry.
            requires_secret=lambda _transport: False,
        )

        result = runtime.verify(
            SimpleNamespace(log_fn=lambda *_args: None),
            "email-code",
            lambda *_args: response,
        )

        self.assertEqual(result["error"]["code"], "mfa_totp_secret_missing")
        self.assertEqual(continued, [])

    def test_mfa_challenge_url_is_fail_closed_when_page_type_is_missing(self):
        continued = []
        runtime = EmailOtpMfaRuntime(
            secret_get=lambda _transport: "",
            secret_clear=lambda *_args: None,
            checkpoint_save=lambda *_args: None,
            response_error_code=lambda _value: "",
            page_type=lambda _value: "",
            observe_auth_step=lambda *_args: None,
            continue_if_needed=lambda *_args, **_kwargs: continued.append(True),
            factor_id=lambda _value: "factor-private",
            verify_totp=lambda *_args, **_kwargs: self.fail(
                "MFA challenge URL must stop before TOTP verification"
            ),
            verify_mfa=lambda *_args, **_kwargs: None,
            manual_fallback=lambda *_args: None,
            session_invalid=lambda _value: False,
            stop_event=lambda _transport: None,
        )

        result = runtime.verify(
            SimpleNamespace(log_fn=lambda *_args: None),
            "email-code",
            lambda *_args: {
                "_status": 200,
                "continue_url": "/mfa-challenge/factor-private",
            },
        )

        self.assertEqual(result["error"]["code"], "mfa_totp_secret_missing")
        self.assertEqual(continued, [])

    def test_mfa_page_alias_is_normalized_before_fail_closed_routing(self):
        continued = []
        runtime = EmailOtpMfaRuntime(
            secret_get=lambda _transport: "",
            secret_clear=lambda *_args: None,
            checkpoint_save=lambda *_args: None,
            response_error_code=lambda _response: "",
            page_type=lambda response: response["page"]["type"],
            observe_auth_step=lambda *_args: None,
            continue_if_needed=lambda *_args, **_kwargs: continued.append(True),
            factor_id=lambda _response: "factor-private",
            verify_totp=lambda *_args, **_kwargs: self.fail(
                "an MFA alias without a secret must stop before TOTP"
            ),
            verify_mfa=lambda *_args, **_kwargs: None,
            manual_fallback=lambda *_args: None,
            session_invalid=lambda _response: False,
            stop_event=lambda _transport: None,
            requires_secret=lambda _transport: False,
        )

        result = runtime.verify(
            SimpleNamespace(log_fn=lambda *_args: None),
            "email-code",
            lambda *_args: {
                "_status": 200,
                "page": {"type": "MFA-CHALLENGE"},
                "continue_url": "/mfa-challenge/factor-private",
            },
        )

        self.assertEqual(result["error"]["code"], "mfa_totp_secret_missing")
        self.assertEqual(continued, [])

    def test_expected_totp_without_factor_id_exposes_stable_code_in_message(self):
        runtime = EmailOtpMfaRuntime(
            secret_get=lambda _transport: "JBSWY3DPEHPK3PXP",
            secret_clear=lambda *_args: None,
            checkpoint_save=lambda *_args: None,
            response_error_code=lambda response: str(
                (response.get("error") or {}).get("code") or ""
            ),
            page_type=lambda response: response["page"]["type"],
            observe_auth_step=lambda *_args: None,
            continue_if_needed=lambda *_args, **_kwargs: self.fail(
                "missing factor id must stop before continuation"
            ),
            factor_id=lambda _response: "",
            verify_totp=lambda *_args, **_kwargs: self.fail(
                "missing factor id must stop before TOTP verification"
            ),
            verify_mfa=lambda *_args, **_kwargs: None,
            manual_fallback=lambda *_args: None,
            session_invalid=lambda _response: False,
            stop_event=lambda _transport: None,
            requires_secret=lambda _transport: True,
        )

        response = runtime.verify(
            SimpleNamespace(log_fn=lambda *_args: None),
            "email-code",
            lambda *_args: {"_status": 200, "page": {"type": "mfa_challenge"}},
        )

        self.assertEqual(response["error"]["code"], "mfa_factor_id_missing")
        self.assertIn("mfa_factor_id_missing", response["error"]["message"])


if __name__ == "__main__":
    unittest.main()
