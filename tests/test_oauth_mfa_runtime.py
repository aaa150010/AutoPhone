from __future__ import annotations

import unittest
from types import SimpleNamespace

from mac_overrides.oauth_mfa_runtime import EmailOtpMfaRuntime


class EmailOtpMfaRuntimeTests(unittest.TestCase):
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
                    "oauth_refresh_token": "BOUND-SEED",
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
        self.assertEqual(totp_calls[0][1]["secret"], "BOUND-SEED")


if __name__ == "__main__":
    unittest.main()
