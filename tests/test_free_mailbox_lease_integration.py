from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from mac_overrides.free_register_runtime import FreeRegisterError, FreeRegisterManager
from mac_overrides.free_storage_adapters import build_free_storage_adapters


class FreeMailboxLeaseIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="free-lease-manager-")
        self.root = Path(self.tempdir.name) / "free_register"
        self.root.mkdir()
        self.adapters = build_free_storage_adapters(self.root)
        self.managers: list[FreeRegisterManager] = []

    def tearDown(self) -> None:
        for manager in self.managers:
            manager.stop()
            deadline = time.time() + 2
            while manager.public_state().get("running") and time.time() < deadline:
                time.sleep(0.01)
        self.tempdir.cleanup()

    def _manager(self, runner):
        manager = FreeRegisterManager(
            self.root,
            storage_adapters=self.adapters,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.10",
        )
        self.managers.append(manager)
        return manager

    def _start_and_wait(self, manager: FreeRegisterManager) -> dict:
        manager.start(
            {"target_count": 1, "concurrency": 1},
            pool_content="lease@example.test----https://mail.example.test/code",
            proxy_content="http://proxy.example.test:8080",
        )
        deadline = time.time() + 3
        while manager.public_state().get("running") and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(manager.public_state().get("running"))
        return manager.public_tasks()[0]

    def test_confirm_callback_is_injected_once_and_terminal_status_is_preserved(self) -> None:
        callbacks: list[tuple[str, str]] = []

        def runner(task, config, _stop, _stage, _log, **_kwargs):
            callback = config.get("_confirm_mailbox_lease")
            self.assertTrue(callable(callback))
            self.assertTrue(callback(task_id=task["task_id"], email=task["email"]))
            callbacks.append((task["task_id"], task["row_id"]))
            return {
                "access_token": "token-private",
                "password": "password-private",
                "twofa_status": "enabled",
                "totp_secret": "totp-private",
                "registration_completed": True,
            }

        manager = self._manager(runner)
        task = self._start_and_wait(manager)
        self.assertEqual(len(callbacks), 1)
        row = self.adapters.storage.get_mailbox(task["row_id"])
        self.assertEqual(row["status"], "success")
        self.assertFalse(row["lease_owner"])

    def test_unconfirmed_entry_failure_releases_mailbox(self) -> None:
        def runner(_task, _config, _stop, _stage, _log, **_kwargs):
            raise FreeRegisterError(
                "free_protocol_preflight",
                "Free 协议预检",
                "预检失败",
                retryable=False,
            )

        manager = self._manager(runner)
        task = self._start_and_wait(manager)
        self.assertEqual(task["status"], "failed")
        row = self.adapters.storage.get_mailbox(task["row_id"])
        self.assertEqual(row["status"], "available")
        self.assertFalse(row["payload"].get("lease_confirmed", False))

    def test_confirmed_failure_never_returns_mailbox_to_available(self) -> None:
        def runner(task, config, _stop, _stage, _log, **_kwargs):
            callback = config.get("_confirm_mailbox_lease")
            self.assertTrue(callback(task_id=task["task_id"], email=task["email"]))
            raise FreeRegisterError(
                "free_email_otp_wait",
                "获取 Free 邮箱验证码",
                "验证码等待失败",
                retryable=True,
            )

        manager = self._manager(runner)
        task = self._start_and_wait(manager)
        row = self.adapters.storage.get_mailbox(task["row_id"])
        self.assertEqual(row["status"], "pending_rerun")
        self.assertNotEqual(row["status"], "available")
        self.assertTrue(row["payload"].get("lease_confirmed"))

    def test_definitely_unstarted_submit_can_abort_confirmation(self) -> None:
        callbacks: list[str] = []

        def runner(task, config, _stop, _stage, _log, **_kwargs):
            confirm = config.get("_confirm_mailbox_lease")
            abort = config.get("_abort_mailbox_lease_confirmation")
            self.assertTrue(callable(confirm))
            self.assertTrue(callable(abort))
            self.assertTrue(confirm(task_id=task["task_id"], email=task["email"]))
            callbacks.append("confirm")
            self.assertFalse(abort(task_id=task["task_id"]))
            self.assertTrue(
                abort(
                    task_id=task["task_id"],
                    submission_definitely_not_started=True,
                )
            )
            callbacks.append("abort")
            raise FreeRegisterError(
                "free_camoufox_signup_email",
                "填写 Camoufox 注册邮箱",
                "邮箱表单未能提交",
                retryable=True,
                error_code="camoufox_email_submit_failed",
            )

        manager = self._manager(runner)
        task = self._start_and_wait(manager)
        self.assertEqual(task["status"], "failed")
        self.assertEqual(callbacks, ["confirm", "abort"])
        row = self.adapters.storage.get_mailbox(task["row_id"])
        self.assertEqual(row["status"], "available")
        self.assertFalse(row["payload"].get("lease_confirmed", False))

    def test_reused_confirmation_cannot_be_aborted_by_later_attempt(self) -> None:
        def runner(task, config, _stop, _stage, _log, **_kwargs):
            confirm = config["_confirm_mailbox_lease"]
            abort = config["_abort_mailbox_lease_confirmation"]
            self.assertTrue(confirm(task_id=task["task_id"]))
            # Calling confirm again models a rebuilt/retried transport after
            # the first submit may have reached the provider.
            self.assertTrue(confirm(task_id=task["task_id"]))
            self.assertFalse(
                abort(
                    task_id=task["task_id"],
                    submission_definitely_not_started=True,
                )
            )
            raise FreeRegisterError(
                "free_email_identifier",
                "识别 Free 注册邮箱",
                "请求结果不确定",
                retryable=True,
            )

        manager = self._manager(runner)
        task = self._start_and_wait(manager)
        row = self.adapters.storage.get_mailbox(task["row_id"])
        self.assertEqual(row["status"], "pending_rerun")
        self.assertTrue(row["payload"].get("lease_confirmed"))

    def test_durable_confirmation_disables_proxy_retry(self) -> None:
        attempts: list[str] = []

        def runner(task, config, _stop, _stage, _log, **_kwargs):
            attempts.append(str(task.get("proxy_id") or ""))
            self.assertTrue(
                config["_confirm_mailbox_lease"](
                    task_id=task["task_id"], email=task["email"]
                )
            )
            error = FreeRegisterError(
                "free_email_identifier",
                "识别 Free 注册邮箱",
                "请求结果不确定",
                retryable=True,
                provider_status=403,
                error_code="free_email_identifier_proxy_denied",
            )
            # Model a route-level adapter error that would normally permit a
            # proxy switch.  Durable mailbox confirmation must override it.
            error.proxy_retryable = True
            raise error

        manager = self._manager(runner)
        manager.start(
            {"target_count": 1, "concurrency": 1, "proxy_retry_count": 3},
            pool_content="confirmed-retry@example.test----https://mail.example.test/code",
            proxy_content=(
                "http://proxy-a.example.test:8080\n"
                "http://proxy-b.example.test:8080"
            ),
        )
        deadline = time.time() + 3
        while manager.public_state().get("running") and time.time() < deadline:
            time.sleep(0.01)
        self.assertFalse(manager.public_state().get("running"))
        self.assertEqual(len(attempts), 1)
        task = manager.public_tasks()[0]
        self.assertEqual(task["status"], "failed")
        row = self.adapters.storage.get_mailbox(task["row_id"])
        self.assertEqual(row["status"], "pending_rerun")
        self.assertTrue(row["payload"].get("lease_confirmed"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
