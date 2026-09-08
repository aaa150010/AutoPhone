"""Focused tests for the consecutive mailbox-source failure degradation."""

from __future__ import annotations
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from mac_overrides.free_register_runtime import FreeRegisterManager
except ImportError:  # pragma: no cover - direct mac_overrides execution
    from free_register_runtime import FreeRegisterManager  # type: ignore[no-redef]


class _Host:
    """Expose only the classmethods/methods the degradation logic touches."""

    _MAILBOX_DEGRADE_ERRORS = FreeRegisterManager._MAILBOX_DEGRADE_ERRORS
    _MAILBOX_DEGRADE_THRESHOLD = FreeRegisterManager._MAILBOX_DEGRADE_THRESHOLD
    _is_mailbox_source_failure = FreeRegisterManager._is_mailbox_source_failure.__func__
    _maybe_degrade_mailbox_source = FreeRegisterManager._maybe_degrade_mailbox_source

    def __init__(self, row_states, updates, logs):
        self._row_states = row_states
        self.updates = updates
        self.logs = logs
        self.pool = _Host._Pool(self)

    class _Pool:
        def __init__(self, host):
            self._host = host

        def _row_state(self, row_id):
            return self._host._row_states.get(row_id, {})

        def update(self, row_id, **values):
            self._host.updates.append((row_id, values))
            self._host._row_states.setdefault(row_id, {}).update(values)

    def _log(self, message, level="info", **fields):
        self.logs.append((message, level))

def _mailbox_timeout_failure():
    return {
        "node_code": "free_email_otp_wait",
        "error_code": "mailbox_code_timeout",
        "public_message": "邮箱验证码等待已达到调用方时间预算 [邮箱验证码等待/mailbox_code_timeout]：mailbox 超时",
    }


class MailboxSourceFailureClassifierTests(unittest.TestCase):
    def test_timeout_failures_classify_as_source_failure(self):
        host = _Host({}, [], [])
        self.assertTrue(host._is_mailbox_source_failure(_mailbox_timeout_failure()))
        self.assertTrue(host._is_mailbox_source_failure({
            "node_code": "free_email_otp_wait", "error_code": "mailbox_timeout",
        }))

    def test_parse_failures_classify_as_source_failure(self):
        host = _Host({}, [], [])
        self.assertTrue(host._is_mailbox_source_failure({
            "node_code": "free_email_otp_wait", "error_code": "mailbox_parse_failed",
        }))

    def test_network_or_business_failures_do_not_classify(self):
        host = _Host({}, [], [])
        self.assertFalse(host._is_mailbox_source_failure({
            "node_code": "free_oauth_session", "error_code": "oauth_bootstrap_html",
        }))
        self.assertFalse(host._is_mailbox_source_failure({
            "node_code": "free_plan_check", "error_code": "free_plan_accounts_http_failed",
        }))
        self.assertFalse(host._is_mailbox_source_failure({
            "node_code": "free_protocol_preflight", "error_code": "proxy_connect_timeout",
        }))


class MaybeDegradeMailboxTests(unittest.TestCase):
    def _snapshot(self):
        return {"row_id": "row-1", "task_id": "task-1"}

    def test_first_two_failures_only_count(self):
        row_states = {}
        updates = []
        logs = []
        host = _Host(row_states, updates, logs)
        host._maybe_degrade_mailbox_source(self._snapshot(), _mailbox_timeout_failure())
        host._maybe_degrade_mailbox_source(self._snapshot(), _mailbox_timeout_failure())
        self.assertEqual(len(updates), 2)
        for _, values in updates:
            self.assertNotEqual(values.get("status"), "unavailable")
        self.assertEqual(row_states["row-1"]["mailbox_otp_failures"], 2)
        self.assertEqual(logs, [])

    def test_third_failure_degrades_row(self):
        row_states = {"row-1": {"mailbox_otp_failures": 2}}
        updates = []
        logs = []
        host = _Host(row_states, updates, logs)
        host._maybe_degrade_mailbox_source(self._snapshot(), _mailbox_timeout_failure())
        self.assertEqual(len(updates), 1)
        row_id, values = updates[0]
        self.assertEqual(row_id, "row-1")
        self.assertEqual(values["status"], "unavailable")
        self.assertEqual(values["degraded_reason"], "free_mailbox_degraded")
        self.assertIn("手动恢复", values["error"])
        self.assertEqual(row_states["row-1"]["mailbox_otp_failures"], 0)
        self.assertEqual(logs[0][1], "error")

    def test_success_resets_counter_before_threshold(self):
        row_states = {"row-1": {"mailbox_otp_failures": 2}}
        updates = []
        host = _Host(row_states, updates, [])
        # A success path resets via pool.update(mailbox_otp_failures=0).
        row_states["row-1"].update({"mailbox_otp_failures": 0})
        host._maybe_degrade_mailbox_source(self._snapshot(), _mailbox_timeout_failure())
        self.assertEqual(row_states["row-1"]["mailbox_otp_failures"], 1)
        self.assertEqual(len(updates), 1)

    def test_non_mailbox_failure_never_counts_or_degrades(self):
        row_states = {"row-1": {"mailbox_otp_failures": 2}}
        updates = []
        host = _Host(row_states, updates, [])
        host._maybe_degrade_mailbox_source(self._snapshot(), {
            "node_code": "free_oauth_session", "error_code": "oauth_bootstrap_html",
        })
        self.assertEqual(updates, [])
        self.assertEqual(row_states["row-1"]["mailbox_otp_failures"], 2)

    def test_missing_row_id_is_noop(self):
        updates = []
        host = _Host({}, updates, [])
        host._maybe_degrade_mailbox_source({"row_id": ""}, _mailbox_timeout_failure())
        self.assertEqual(updates, [])


class ManualRestoreClearsDegradeMarkerTests(unittest.TestCase):
    def test_set_status_available_clears_degrade_state(self):
        import tempfile
        from pathlib import Path

        try:
            from mac_overrides.free_register_store import FreeMailboxPool
        except ImportError:  # pragma: no cover
            from free_register_store import FreeMailboxPool  # type: ignore[no-redef]

        with tempfile.TemporaryDirectory(prefix="gptphone-degrade-") as temp:
            pool = FreeMailboxPool(Path(temp))
            pool.import_text("a@example.test----https://mail.example.test/pickup\n")
            row_id = pool.entries()[0].row_id
            pool.update(
                row_id,
                status="unavailable",
                mailbox_otp_failures=0,
                degraded_reason="free_mailbox_degraded",
                error="邮箱取件连续失败，已自动降级；请在邮箱中心手动恢复",
            )
            self.assertEqual(pool._row_state(row_id).get("degraded_reason"), "free_mailbox_degraded")
            pool.set_status([row_id], "available")
            state = pool._row_state(row_id)
            self.assertEqual(state.get("status"), "available")
            self.assertNotIn("degraded_reason", state)
            self.assertNotIn("mailbox_otp_failures", state)


if __name__ == "__main__":
    unittest.main()
