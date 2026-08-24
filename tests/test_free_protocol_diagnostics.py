from __future__ import annotations

import unittest

from mac_overrides.free_protocol_diagnostics import (
    is_known_state_response,
    response_detail,
    response_metadata,
)


class FreeProtocolDiagnosticsTests(unittest.TestCase):
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
