from __future__ import annotations

import unittest

from mac_overrides.free_autoregister_protocol import run_autoregister_prelude
from mac_overrides.free_register_common import FreeRegisterError


class _Transport:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else {"_status": 200, "url": "https://auth.openai.com/log-in"}
        self.error = error
        self.calls = []

    def start_chatgpt_signup_authorize(self, email):
        self.calls.append(email)
        if self.error is not None:
            raise self.error
        return self.response


class AutoRegisterPreludeTests(unittest.TestCase):
    def test_runs_reference_prelude_and_marks_transport(self):
        transport = _Transport()
        stages = []
        logs = []
        result = run_autoregister_prelude(
            transport,
            "user@example.test",
            task_id="task-1",
            stage=lambda task_id, code: stages.append((task_id, code)),
            log=lambda message, level="info": logs.append((message, level)),
        )
        self.assertEqual(transport.calls, ["user@example.test"])
        self.assertEqual(result["_status"], 200)
        self.assertTrue(transport._gptphone_autoregister_prelude)
        self.assertEqual(stages, [("task-1", "free_oauth_session")])
        self.assertTrue(any("AutoRegister" in message for message, _level in logs))

    def test_does_not_call_register_user_or_fail_for_legacy_transport(self):
        class Legacy:
            def register_user(self, *_args):
                raise AssertionError("legacy user/register must not be called")

        self.assertIsNone(run_autoregister_prelude(Legacy(), "user@example.test"))

    def test_provider_failure_keeps_oauth_node_and_redacts_detail(self):
        transport = _Transport({"_status": 429, "error": {"code": "rate_limit_exceeded"}})
        with self.assertRaises(FreeRegisterError) as raised:
            run_autoregister_prelude(transport, "user@example.test")
        self.assertEqual(raised.exception.node_code, "free_oauth_session")
        self.assertEqual(raised.exception.provider_status, 429)
        self.assertEqual(raised.exception.provider_code, "rate_limit_exceeded")
        self.assertEqual(raised.exception.error_code, "free_autoregister_prelude_failed")


if __name__ == "__main__":
    unittest.main()
