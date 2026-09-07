"""Focused tests for mid-flight durable persistence of 2FA secret and password."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from mac_overrides.free_register_runtime import FreeRegisterManager
except ImportError:  # pragma: no cover - direct mac_overrides execution
    from free_register_runtime import FreeRegisterManager  # type: ignore[no-redef]

try:
    from mac_overrides.free_protocol_runtime import FreeProtocolMixin
except ImportError:  # pragma: no cover - direct mac_overrides execution
    from free_protocol_runtime import FreeProtocolMixin  # type: ignore[no-redef]


class PersistPartialHelperTest(unittest.TestCase):
    """The protocol-side helper must be a safe, swappable no-op without the hook."""

    def test_missing_hook_is_noop(self):
        ok = FreeProtocolMixin._persist_partial({}, {"row_id": "r1"}, {"a": 1}, stage_code="x")
        self.assertFalse(ok)

    def test_hook_receives_values_and_stage(self):
        calls = []

        def hook(values, *, stage_code=""):
            calls.append((values, stage_code))
            return True

        ok = FreeProtocolMixin._persist_partial(
            {"_persist_partial_result": hook}, {"row_id": "r1"}, {"a": 1}, stage_code="free_twofa_enroll",
        )
        self.assertTrue(ok)
        self.assertEqual(calls, [({"a": 1}, "free_twofa_enroll")])

    def test_raising_hook_is_swallowed(self):
        def hook(values, *, stage_code=""):
            raise RuntimeError("disk full")

        ok = FreeProtocolMixin._persist_partial(
            {"_persist_partial_result": hook}, {"row_id": "r1"}, {"a": 1}, stage_code="x",
        )
        self.assertFalse(ok)


class _Host:
    """Minimal stand-in exposing only what _persist_partial_result touches."""

    def _persist_partial_result(self, task, values, *, stage_code=""):
        return FreeRegisterManager._persist_partial_result(self, task, values, stage_code=stage_code)


class ManagerPersistPartialTest(unittest.TestCase):
    def test_merges_into_saved_result(self):
        pool_save = []

        class _Pool:
            def result(self, row_id):
                return {"access_token": "tok"}

            def save_result(self, row_id, values):
                pool_save.append((row_id, values))

        host = _Host()
        host.pool = _Pool()
        host._log = lambda *a, **k: None
        ok = host._persist_partial_result(
            {"row_id": "r1", "task_id": "t1"},
            {"totp_secret": "SECRET", "twofa_status": "pending"},
            stage_code="free_twofa_enroll",
        )
        self.assertTrue(ok)
        self.assertEqual(pool_save[0][0], "r1")
        self.assertEqual(pool_save[0][1]["access_token"], "tok")
        self.assertEqual(pool_save[0][1]["totp_secret"], "SECRET")

    def test_pool_failure_returns_false(self):
        pool_save = []

        class _Pool:
            def result(self, row_id):
                raise RuntimeError("locked")

            def save_result(self, row_id, values):
                pool_save.append((row_id, values))

        host = _Host()
        host.pool = _Pool()
        host._log = lambda *a, **k: None
        ok = host._persist_partial_result({"row_id": "r1", "task_id": "t1"}, {"a": 1}, stage_code="x")
        self.assertFalse(ok)
        self.assertEqual(pool_save, [])

    def test_missing_row_is_noop(self):
        pool_save = []

        class _Pool:
            def result(self, row_id):
                raise AssertionError("must not be called")

            def save_result(self, row_id, values):
                pool_save.append((row_id, values))

        host = _Host()
        host.pool = _Pool()
        host._log = lambda *a, **k: None
        ok = host._persist_partial_result({"row_id": ""}, {"a": 1}, stage_code="x")
        self.assertFalse(ok)
        self.assertEqual(pool_save, [])


if __name__ == "__main__":
    unittest.main()
