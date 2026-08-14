from __future__ import annotations

from pathlib import Path
import unittest

from tests.web_gui_test_runtime import RecoveredWebGuiImport


ROOT = Path(__file__).resolve().parents[1]


class SentinelLogClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._runtime = RecoveredWebGuiImport(ROOT)
        cls.module = cls._runtime.load()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._runtime.cleanup()

    def test_sentinel_lifecycle_emit_remains_informational(self):
        module = self.module
        original_emit = module._ORIGINAL_CHAIN_EMIT
        captured = []
        messages = (
            (
                "  [SentinelRunner] 调用 Node 生成 token, "
                "flow=chat-requirements, attempt=1/2, timeout=45s"
            ),
            (
                "  [SentinelRunner] token 生成成功, "
                "flow=chat-requirements, 包含 so=True"
            ),
        )
        try:
            module._ORIGINAL_CHAIN_EMIT = lambda *args: captured.append(args)
            for message in messages:
                module._patched_chain_emit(lambda *_args: None, message, "info")
        finally:
            module._ORIGINAL_CHAIN_EMIT = original_emit

        self.assertEqual([args[1] for args in captured], list(messages))
        self.assertEqual([args[2] for args in captured], ["info", "info"])

    def test_public_logs_keep_sentinel_lifecycle_lines_informational(self):
        messages = (
            (
                "T001-safe [SentinelRunner] 调用 Node 生成 token, "
                "flow=password_verify, attempt=1/2, timeout=45s"
            ),
            (
                "T001-safe [SentinelRunner] token 生成成功, "
                "flow=password_verify, 包含 so=True"
            ),
        )

        public = self.module._public_logs(
            [{"level": "info", "message": message} for message in messages],
            [{"task_id": "T001-safe", "status": "authorizing"}],
        )

        self.assertEqual([row["message"] for row in public], list(messages))
        self.assertEqual([row["level"] for row in public], ["info", "info"])
        self.assertTrue(
            all("Node/Sentinel 重试" not in row["message"] for row in public)
        )


if __name__ == "__main__":
    unittest.main()
