from __future__ import annotations

from pathlib import Path
import tempfile
import time
import unittest

from mac_overrides.free_register_common import FreeRegisterError
from mac_overrides.free_register_runtime import FreeRegisterManager


class FreeMailboxFailureBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="gptphone-free-mailbox-boundary-")
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_protocol_preflight_failure_releases_unsubmitted_mailbox(self) -> None:
        def runner(_task, _config, _stop, stage, _log, *, twofa_retry=False):
            self.assertFalse(twofa_retry)
            stage(_task["task_id"], "free_protocol_preflight")
            raise FreeRegisterError(
                "free_protocol_preflight",
                "协议网络预检",
                "auth-login 预检返回 HTTP 403",
                retryable=False,
                provider_status=403,
                error_code="free_protocol_preflight_http",
                content_type="text/html",
                page_type="access_denied",
                action_hint="当前出口被 Auth 拒绝，请更换代理后重试",
            )

        manager = FreeRegisterManager(
            self.data_dir,
            runner=runner,
            proxy_probe=lambda _proxy, _url: "203.0.113.90",
        )
        manager.pool.import_text("user@example.test----https://mail.example.test/pickup\n")
        manager.proxies.import_text("socks5://user:private@proxy.example.test:3000\n")

        manager.start({"driver": "protocol", "target_count": 1, "concurrency": 1})
        deadline = time.time() + 3
        while manager.public_state()["running"] and time.time() < deadline:
            time.sleep(0.01)

        task = manager.public_tasks()[0]
        mailbox = manager.pool.public_rows()[0]
        self.assertEqual(task["status"], "failed")
        self.assertEqual(task["failure"]["node_code"], "free_protocol_preflight")
        self.assertEqual(task["failure"]["http_status"], 403)
        self.assertEqual(mailbox["status"], "available")
        self.assertNotIn("private", str(manager.public_logs(task["task_id"])))


if __name__ == "__main__":
    unittest.main()
