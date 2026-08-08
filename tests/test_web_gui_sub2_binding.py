from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from tests.web_gui_test_runtime import RecoveredWebGuiImport


class WebGuiSub2BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls._web_gui_import = RecoveredWebGuiImport(root)
        cls._owns_import = cls._web_gui_import.owns_import
        cls._runtime_tempdir = None
        cls._previous_data_dir = os.environ.get("GPTPHONE_DATA_DIR")
        if cls._owns_import:
            cls._runtime_tempdir = tempfile.TemporaryDirectory()
            os.environ["GPTPHONE_DATA_DIR"] = cls._runtime_tempdir.name
        cls.module = cls._web_gui_import.load()

    @classmethod
    def tearDownClass(cls):
        if not cls._owns_import:
            return
        if cls._previous_data_dir is None:
            os.environ.pop("GPTPHONE_DATA_DIR", None)
        else:
            os.environ["GPTPHONE_DATA_DIR"] = cls._previous_data_dir
        cls._web_gui_import.cleanup()
        cls._runtime_tempdir.cleanup()

    def test_direct_401_forces_update_and_never_calls_create(self):
        module = self.module
        original_task_config = module._ORIGINAL_TASK_CONFIG
        original_sub2_runtime = module._SUB2_RUNTIME
        original_direct_runtime = module._OPENAI_DIRECT_RUNTIME
        original_upload = module._ORIGINAL_REAL_SUB2_UPLOAD
        original_update = module._sub2_update_runtime_ext.update_existing_sub2_account
        create_calls = []
        update_calls = []
        sub2_cleared = []
        direct_cleared = []
        direct_refreshed = []

        with tempfile.TemporaryDirectory() as tempdir:
            results_dir = Path(tempdir) / "results"
            results_dir.mkdir()
            (results_dir / "success.json").write_text(
                json.dumps(
                    {
                        "email": "rerun@example.test",
                        "status": "success",
                        "created_at": 100,
                        "result": {
                            "sub2api_account_id": "remote-501",
                            "access_token": "private-access-token",
                            "chatgpt_account_id": "openai-501",
                        },
                    }
                ),
                encoding="utf-8",
            )
            sub2_runtime = SimpleNamespace(
                status_for=lambda _account_id: {"status_code": 200, "kind": "healthy"},
                clear_status=sub2_cleared.append,
            )
            direct_runtime = SimpleNamespace(
                status_for=lambda account_id: {
                    "status_code": 401 if account_id == "openai-501" else 200,
                    "kind": "unauthorized" if account_id == "openai-501" else "healthy",
                },
                clear_status=direct_cleared.append,
                mark_credentials_refreshed=direct_refreshed.append,
            )

            def update_existing(**kwargs):
                update_calls.append(kwargs)
                return {
                    "ok": True,
                    "sub2api_account_id": kwargs["account_id"],
                    "chatgpt_account_id": "openai-501",
                    "sub2_update_existing": True,
                    "sub2_upload_created": False,
                }

            try:
                module._ORIGINAL_TASK_CONFIG = lambda *_args, **_kwargs: {"code_timeout": 30}
                module._SUB2_RUNTIME = sub2_runtime
                module._OPENAI_DIRECT_RUNTIME = direct_runtime
                config = module._patched_task_config(
                    SimpleNamespace(data_dir=tempdir),
                    {"results_dir": str(results_dir)},
                    "rerun@example.test",
                    "task-direct-401",
                )
                module._ORIGINAL_REAL_SUB2_UPLOAD = (
                    lambda *_args, **kwargs: create_calls.append(kwargs) or {"ok": True}
                )
                module._sub2_update_runtime_ext.update_existing_sub2_account = update_existing
                result = module._real_sub2_upload(
                    SimpleNamespace(config=config, upload_proxy="", log_fn=None),
                    credentials={"access_token": "new-access-token"},
                    email="rerun@example.test",
                )
            finally:
                module._ORIGINAL_TASK_CONFIG = original_task_config
                module._SUB2_RUNTIME = original_sub2_runtime
                module._OPENAI_DIRECT_RUNTIME = original_direct_runtime
                module._ORIGINAL_REAL_SUB2_UPLOAD = original_upload
                module._sub2_update_runtime_ext.update_existing_sub2_account = original_update

        self.assertTrue(result["ok"])
        self.assertEqual(config["_sub2_update_existing"]["account_id"], "remote-501")
        self.assertEqual(config["_sub2_update_existing"]["openai_account_id"], "openai-501")
        self.assertEqual(config["_sub2_update_existing"]["status_source"], "openai_direct")
        self.assertEqual(len(update_calls), 1)
        self.assertEqual(update_calls[0]["account_id"], "remote-501")
        self.assertEqual(create_calls, [])
        self.assertEqual(sub2_cleared, ["remote-501"])
        self.assertEqual(direct_cleared, ["openai-501", "remote-501"])
        self.assertEqual(direct_refreshed, ["openai-501"])

    def test_verified_create_emits_redacted_confirmation(self):
        module = self.module
        original_upload = module._ORIGINAL_REAL_SUB2_UPLOAD
        logs = []
        try:
            module._ORIGINAL_REAL_SUB2_UPLOAD = lambda *_args, **_kwargs: {
                "ok": True,
                "sub2api_account_id": "remote-private-501",
                "sub2_remote_verified": True,
                "sub2_group_verified": True,
                "sub2_chatgpt_account_id_verified": True,
            }
            result = module._real_sub2_upload(
                SimpleNamespace(
                    config={},
                    upload_proxy="",
                    log_fn=lambda message, level: logs.append((message, level)),
                ),
                credentials={"access_token": "private-access-token"},
                email="private@example.test",
            )
        finally:
            module._ORIGINAL_REAL_SUB2_UPLOAD = original_upload

        self.assertTrue(result["ok"])
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0][1], "success")
        self.assertIn("sub2_upload_confirmed", logs[0][0])
        self.assertNotIn("remote-private-501", logs[0][0])
        self.assertNotIn("private@example.test", logs[0][0])
        self.assertNotIn("private-access-token", logs[0][0])

    def test_unverified_success_does_not_emit_confirmation(self):
        module = self.module
        original_upload = module._ORIGINAL_REAL_SUB2_UPLOAD
        logs = []
        try:
            module._ORIGINAL_REAL_SUB2_UPLOAD = lambda *_args, **_kwargs: {
                "ok": True,
                "sub2api_account_id": "remote-private-501",
                "sub2_remote_verified": True,
                "sub2_group_verified": False,
                "sub2_chatgpt_account_id_verified": True,
            }
            module._real_sub2_upload(
                SimpleNamespace(
                    config={},
                    upload_proxy="",
                    log_fn=lambda message, level: logs.append((message, level)),
                ),
                credentials={"access_token": "private-access-token"},
                email="private@example.test",
            )
        finally:
            module._ORIGINAL_REAL_SUB2_UPLOAD = original_upload

        self.assertEqual(logs, [])


if __name__ == "__main__":
    unittest.main()
