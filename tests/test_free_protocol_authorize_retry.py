"""Focused contract tests for the same-session authorize 403 retry."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from mac_overrides.free_protocol_authorize_retry import (
    _RETRY_DELAY_SECONDS,
    authorize_403_same_session_retry,
)


def _envelope(status: int, *, challenge: bool = False) -> dict:
    if challenge:
        return {
            "_status": status,
            "_html_title": "Just a moment...",
            "_body_summary": "challenge-platform cf-chl verify you are human",
        }
    return {"_status": status, "_body_summary": ""}


class _ScriptedNavigate:
    """Authorize navigation stub recording the session used per attempt."""

    def __init__(self, responses: list, *, session: object = None, error: Exception | None = None) -> None:
        self._responses = list(responses)
        self._error = error
        self._session = session
        self.calls = 0
        self.sessions: list[object] = []

    def __call__(self) -> object:
        self.calls += 1
        self.sessions.append(self._session)
        if self._error is not None:
            raise self._error
        return self._responses[min(self.calls, len(self._responses)) - 1]


class Authorize403SameSessionRetryTests(unittest.TestCase):
    def test_plain_403_retries_once_on_same_session_and_returns_second_response(self):
        session = object()
        first, second = _envelope(403), _envelope(200)
        navigate = _ScriptedNavigate([first, second], session=session)

        result = authorize_403_same_session_retry(navigate)

        self.assertIs(result, second)
        self.assertEqual(navigate.calls, 2)
        self.assertIs(navigate.sessions[0], navigate.sessions[1])

    def test_repeated_403_returns_second_response_for_existing_classification(self):
        second = _envelope(403)
        navigate = _ScriptedNavigate([_envelope(403), second])

        result = authorize_403_same_session_retry(navigate)

        self.assertIs(result, second)
        self.assertEqual(navigate.calls, 2)

    def test_security_challenge_403_keeps_existing_node_and_is_not_retried(self):
        challenge = _envelope(403, challenge=True)
        navigate = _ScriptedNavigate([challenge])

        result = authorize_403_same_session_retry(navigate)

        self.assertIs(result, challenge)
        self.assertEqual(navigate.calls, 1)

    def test_other_status_envelopes_are_not_retried(self):
        for status in (200, 401, 429, 502):
            with self.subTest(status=status):
                response = _envelope(status)
                navigate = _ScriptedNavigate([response])
                result = authorize_403_same_session_retry(navigate)
                self.assertIs(result, response)
                self.assertEqual(navigate.calls, 1)

    def test_non_mapping_response_is_returned_untouched(self):
        sentinel = object()
        navigate = _ScriptedNavigate([sentinel])

        result = authorize_403_same_session_retry(navigate)

        self.assertIs(result, sentinel)
        self.assertEqual(navigate.calls, 1)

    def test_stop_request_skips_the_in_place_retry(self):
        first, second = _envelope(403), _envelope(200)
        navigate = _ScriptedNavigate([first, second])

        result = authorize_403_same_session_retry(navigate, stop_requested=lambda: True)

        self.assertIs(result, first)
        self.assertEqual(navigate.calls, 1)

    def test_first_navigate_exception_propagates_without_retry(self):
        navigate = _ScriptedNavigate([], error=RuntimeError("connection reset"))

        with self.assertRaises(RuntimeError):
            authorize_403_same_session_retry(navigate)
        self.assertEqual(navigate.calls, 1)

    def test_retry_waits_before_second_attempt_and_logs_a_warning(self):
        navigate = _ScriptedNavigate([_envelope(403), _envelope(200)])
        logs: list[tuple[str, str]] = []

        with patch(
            "mac_overrides.free_protocol_authorize_retry.time.sleep"
        ) as sleep:
            authorize_403_same_session_retry(
                navigate,
                log=lambda message, level="info": logs.append((message, level)),
                node_code="free_live_deep",
                node_label="深度测活",
            )

        sleep.assert_called_once_with(_RETRY_DELAY_SECONDS)
        self.assertTrue(any(level == "warn" and "403" in message for message, level in logs))


if __name__ == "__main__":
    unittest.main()
