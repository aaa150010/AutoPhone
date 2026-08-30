from __future__ import annotations

import json
from types import SimpleNamespace
import unittest

from mac_overrides import free_protocol_runtime as runtime
from mac_overrides.diagnostic_store import DiagnosticStore
from mac_overrides.free_protocol_diagnostics import (
    is_known_state_response,
    response_detail,
    response_metadata,
)


class FreeProtocolDiagnosticsTests(unittest.TestCase):
    def test_reauth_observation_keeps_status_and_redacts_url_query_and_path_secret(self):
        observations = []
        transport = SimpleNamespace(
            log_fn=lambda message, level="info", **fields: observations.append(
                (message, level, fields)
            )
        )
        response = SimpleNamespace(
            status_code=302,
            headers={"Content-Type": "text/html; charset=utf-8"},
            url=(
                "https://auth.openai.com/callback/private-token-abc123456789"
                "?code=otp-secret&state=state-secret"
            ),
        )

        runtime._emit_twofa_reauth_observation(
            transport,
            "twofa-diagnostic-task",
            "OAuth callback 最终响应",
            response=response,
            request_stage="reauth_callback",
            include_location=True,
        )

        self.assertEqual(len(observations), 1)
        message, level, fields = observations[0]
        self.assertEqual(level, "info")
        self.assertIn("HTTP 302", message)
        self.assertIn("Content-Type text/html", message)
        self.assertNotIn("otp-secret", message)
        self.assertNotIn("state-secret", message)
        self.assertEqual(fields["request_stage"], "reauth_callback")
        self.assertEqual(fields["transport"]["http_status"], 302)
        self.assertEqual(fields["transport"]["content_type"], "text/html")
        self.assertEqual(fields["transport"]["final_host"], "auth.openai.com")
        self.assertEqual(fields["transport"]["final_path"], "/callback/[值已隐藏]")
        self.assertNotIn("private-token-abc123456789", json.dumps(fields, ensure_ascii=False))

    def test_reauth_observation_hides_assigned_path_secret_before_logging(self):
        observations = []
        transport = SimpleNamespace(
            log_fn=lambda message, level="info", **fields: observations.append(
                (message, fields)
            )
        )
        response = {
            "_status": 302,
            "_url": (
                "https://auth.openai.com/callback/code%3Dsecret-value/"
                "token%3Ahidden/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
            ),
        }

        runtime._emit_twofa_reauth_observation(
            transport,
            "twofa-path-redaction-task",
            "OAuth callback 最终响应",
            response=response,
            include_location=True,
        )

        self.assertEqual(len(observations), 1)
        message, fields = observations[0]
        serialized = json.dumps(fields, ensure_ascii=False)
        self.assertEqual(
            fields["transport"]["final_path"],
            "/callback/[值已隐藏]/[值已隐藏]/[值已隐藏]",
        )
        for secret in (
            "secret-value", "hidden", "code_secret", "token_hidden",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
        ):
            self.assertNotIn(secret, message)
            self.assertNotIn(secret, serialized)

    def test_reauth_observation_transport_fields_are_redacted_by_diagnostic_store(self):
        observations = []
        transport = SimpleNamespace(
            log_fn=lambda message, level="info", **fields: observations.append(fields)
        )
        response = {
            "_status": 200,
            "_content_type": "application/json; charset=utf-8",
            "_url": "https://auth.openai.com/authorize?code=do-not-store&token=also-do-not-store",
        }
        runtime._emit_twofa_reauth_observation(
            transport,
            "twofa-store-task",
            "authorize 页面最终响应",
            response=response,
            request_stage="reauth_authorize",
            include_location=True,
            transport_fields={
                "proxy_fingerprints": "socks5://user:password@proxy.example.test:1080",
                "raw_url": "https://user:password@proxy.example.test:1080/?token=secret",
            },
        )
        self.assertEqual(len(observations), 1)
        self.assertNotIn("proxy_fingerprints", observations[0]["transport"])
        self.assertNotIn("raw_url", observations[0]["transport"])

        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="gptphone-reauth-diagnostic-") as directory:
            store = DiagnosticStore(directory)
            incident_id = store.record({
                "task_id": "twofa-store-task",
                "chain": "free",
                "workflow": "twofa",
                "driver": "protocol",
                "node_code": observations[0]["node_code"],
                "node_label": observations[0]["node_label"],
                "outcome": observations[0]["outcome"],
                "request_stage": observations[0]["request_stage"],
                "transport": observations[0]["transport"],
                "message": "safe observation",
            })
            detail = store.incident(incident_id)
            self.assertIsNotNone(detail)
            serialized = json.dumps(detail, ensure_ascii=False)
            for secret in (
                "do-not-store", "also-do-not-store", "user:password",
                "raw_url", "proxy.example.test:1080",
            ):
                self.assertNotIn(secret, serialized)
            assert detail is not None
            self.assertEqual(detail["events"][0]["transport"]["final_host"], "auth.openai.com")
            self.assertEqual(detail["events"][0]["transport"]["final_path"], "/authorize")
            self.assertEqual(
                detail["events"][0]["transport"]["request_stage"],
                "reauth_authorize",
            )

    def test_response_detail_exposes_metadata_without_html_body(self):
        secret = "private-user-marker"
        response = {
            "_status": 200,
            "_content_type": "text/html; charset=utf-8",
            "_body_summary": f"<!doctype html><title>Login</title>{secret}",
            "_body": f"<html><script>token={secret}</script></html>",
            "_location": "https://auth.openai.com/log-in/password?state=private",
            "error": f"<!DOCTYPE html>{secret}",
            "error_code": "oauth_session_invalid",
        }

        detail = response_detail(response, response["error"])
        metadata = response_metadata(response, diagnostic_error=response["error"])

        self.assertIn("HTTP 200", detail)
        self.assertIn("Content-Type text/html", detail)
        self.assertIn("Provider code oauth_session_invalid", detail)
        self.assertNotIn(secret, detail)
        self.assertNotIn("DOCTYPE", detail)
        self.assertNotIn(secret, metadata["diagnostic"])
        self.assertEqual(metadata["safe_page"], "https://auth.openai.com/log-in/password")

    def test_response_detail_reports_missing_provider_detail_explicitly(self):
        detail = response_detail({"_status": 502, "_content_type": "text/html"}, "upstream HTML")
        self.assertEqual(detail, "HTTP 502，Content-Type text/html")

    def test_known_http_state_can_override_a_stale_success_classifier(self):
        known = {"login_password"}
        self.assertTrue(is_known_state_response(
            {"_status": 200, "page": {"type": "login_password"}},
            lambda _response: False,
            frozenset(known),
        ))
        self.assertFalse(is_known_state_response(
            {"_status": 200, "error": "unexpected"},
            lambda _response: False,
            frozenset(known),
        ))


if __name__ == "__main__":
    unittest.main()
