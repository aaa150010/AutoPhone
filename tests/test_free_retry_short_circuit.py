"""Focused tests for the Free same-error retry short circuit."""

from __future__ import annotations
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from mac_overrides.free_register.retry_policy import (
        FreeRetryPolicy,
        consecutive_same_failures,
    )
except ImportError:  # pragma: no cover - direct mac_overrides execution
    from free_register.retry_policy import (  # type: ignore[no-redef]
        FreeRetryPolicy,
        consecutive_same_failures,
    )


def _failure(node_code="free_oauth_session", error_code="oauth_bootstrap_html", **overrides):
    value = {"node_code": node_code, "error_code": error_code, "retryable": True}
    value.update(overrides)
    return value


def _attempt(node_code="free_oauth_session", error_code="oauth_bootstrap_html", **overrides):
    value = {"proxy_id": "p1", "stage": node_code, "error_code": error_code, "retryable": True}
    value.update(overrides)
    return value


class ConsecutiveSameFailuresTests(unittest.TestCase):
    def test_counts_trailing_matches(self):
        history = [
            _attempt("free_protocol_preflight", "proxy_connect_timeout"),
            _attempt(),
            _attempt(),
        ]
        self.assertEqual(
            consecutive_same_failures(history, {"node_code": "free_oauth_session", "error_code": "oauth_bootstrap_html"}),
            2,
        )

    def test_stops_at_first_mismatch(self):
        history = [_attempt(), _attempt("free_email_identifier", "other_code"), _attempt()]
        self.assertEqual(
            consecutive_same_failures(history, {"node_code": "free_oauth_session", "error_code": "oauth_bootstrap_html"}),
            1,
        )

    def test_alternating_errors_reset_count(self):
        history = [_attempt(), _attempt(error_code="different"), _attempt()]
        self.assertEqual(
            consecutive_same_failures(history, {"node_code": "free_oauth_session", "error_code": "oauth_bootstrap_html"}),
            1,
        )

    def test_empty_history_and_non_mapping_entries(self):
        self.assertEqual(consecutive_same_failures([], {"node_code": "x", "error_code": "y"}), 0)
        self.assertEqual(consecutive_same_failures([None, "junk"], {"node_code": "x", "error_code": "y"}), 0)

    def test_identity_without_fields_never_matches(self):
        self.assertEqual(consecutive_same_failures([_attempt()], {}), 0)


class DecideShortCircuitTests(unittest.TestCase):
    def setUp(self):
        self.policy = FreeRetryPolicy(max_attempts=3)

    def test_default_parameter_keeps_legacy_behavior(self):
        # Regression anchor: without recent_same_failures the decision is
        # identical to the historical retryable_transient path.
        decision = self.policy.decide(_failure(), attempt=0)
        self.assertTrue(decision.retry)
        self.assertEqual(decision.reason, "retryable_transient")

    def test_short_circuits_on_third_consecutive_failure(self):
        decision = self.policy.decide(_failure(), attempt=0, recent_same_failures=2)
        self.assertFalse(decision.retry)
        self.assertEqual(decision.reason, "same_error_short_circuit")

    def test_two_consecutive_failures_still_retry(self):
        decision = self.policy.decide(_failure(), attempt=0, recent_same_failures=1)
        self.assertTrue(decision.retry)
        self.assertEqual(decision.reason, "retryable_transient")

    def test_business_blocks_keep_priority_over_short_circuit(self):
        decision = self.policy.decide(_failure(http_status=429), attempt=0, recent_same_failures=5)
        self.assertFalse(decision.retry)
        self.assertEqual(decision.reason, "business_or_security_stop")

    def test_captcha_markers_keep_priority_over_short_circuit(self):
        decision = self.policy.decide(_failure(error_code="captcha_required"), attempt=0, recent_same_failures=5)
        self.assertFalse(decision.retry)
        self.assertEqual(decision.reason, "business_or_security_stop")

    def test_attempt_limit_keeps_priority_over_short_circuit(self):
        decision = self.policy.decide(_failure(), attempt=2, recent_same_failures=5)
        self.assertFalse(decision.retry)
        self.assertEqual(decision.reason, "attempt_limit")

    def test_explicit_non_retryable_keeps_priority(self):
        decision = self.policy.decide(_failure(retryable=False), attempt=0, recent_same_failures=5)
        self.assertFalse(decision.retry)
        self.assertEqual(decision.reason, "explicit_non_retryable")


if __name__ == "__main__":
    unittest.main()
