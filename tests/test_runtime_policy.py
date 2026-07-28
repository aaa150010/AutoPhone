from __future__ import annotations

import unittest

from mac_overrides.runtime_policy import should_retry_expired_sub2_session


class RuntimePolicyTests(unittest.TestCase):
    def test_retries_expired_sub2_session_after_phone_verification(self):
        result = {
            "error": "sub2_exchange_failed: session not found or expired",
            "codex_chain_events": [{"state": "PHONE_OTP_VERIFIED"}],
        }
        self.assertTrue(should_retry_expired_sub2_session(result))

    def test_retries_expired_sub2_session_after_callback(self):
        result = {
            "phase2_error": "sub2_exchange_failed: sub2_session_expired",
            "codex_chain_events": [{"state": "CALLBACK_RECEIVED"}],
        }
        self.assertTrue(should_retry_expired_sub2_session(result))

    def test_retries_expired_sub2_session_from_structured_reason(self):
        result = {
            "error": "sub2_exchange_failed: OPENAI_OAUTH_SESSION_NOT_FOUND",
            "codex_chain_events": [{"state": "PHONE_OTP_VERIFIED"}],
        }
        self.assertTrue(should_retry_expired_sub2_session(result))

    def test_matches_failure_and_expiry_across_result_fields(self):
        result = {
            "error": "sub2_exchange_failed",
            "local_oauth_exchange_error": "OPENAI_OAUTH_SESSION_NOT_FOUND",
            "codex_chain_events": [{"state": "CALLBACK_RECEIVED"}],
        }
        self.assertTrue(should_retry_expired_sub2_session(result))

    def test_does_not_retry_before_phone_is_verified(self):
        result = {
            "error": "sub2_exchange_failed: session not found or expired",
            "codex_chain_events": [{"state": "PHONE_OTP_SENT"}],
        }
        self.assertFalse(should_retry_expired_sub2_session(result))

    def test_does_not_retry_other_sub2_failures(self):
        result = {
            "error": "sub2_exchange_failed: invalid response",
            "codex_chain_events": [{"state": "PHONE_OTP_VERIFIED"}],
        }
        self.assertFalse(should_retry_expired_sub2_session(result))

    def test_rejects_unstructured_results(self):
        self.assertFalse(should_retry_expired_sub2_session(None))
        self.assertFalse(should_retry_expired_sub2_session("expired"))


if __name__ == "__main__":
    unittest.main()
