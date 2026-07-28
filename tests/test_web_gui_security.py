from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


class WebGuiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.previous_data_dir = os.environ.get("GPTPHONE_DATA_DIR")
        os.environ["GPTPHONE_DATA_DIR"] = cls.tempdir.name
        root = Path(__file__).resolve().parents[1]
        cls.import_paths = [str(root / "mac_overrides"), str(root / "business_pyc")]
        for path in reversed(cls.import_paths):
            sys.path.insert(0, path)
        cls.module = importlib.import_module("web_gui")

    @classmethod
    def tearDownClass(cls):
        if cls.previous_data_dir is None:
            os.environ.pop("GPTPHONE_DATA_DIR", None)
        else:
            os.environ["GPTPHONE_DATA_DIR"] = cls.previous_data_dir
        for path in cls.import_paths:
            try:
                sys.path.remove(path)
            except ValueError:
                pass
        cls.tempdir.cleanup()

    def test_masked_draft_preserves_existing_sms_and_smtp_secrets(self):
        existing = {
            "performance_policy_version": 5,
            "sms_api_keys": ["sms-secret-a", "sms-secret-b"],
            "proxy": "http://proxy-user:proxy-pass@127.0.0.1:7890",
            "email_notification": {
                "enabled": False,
                "provider": "qq",
                "password": "smtp-secret",
            },
        }
        draft = {
            "performance_policy_version": 5,
            "sms_api_keys": ["********", "********"],
            "proxy": "********",
            "email_notification": {"password": "********"},
        }

        resolved = self.module._local_config_from_runtime(draft, existing)

        self.assertEqual(resolved["sms_api_keys"], ["sms-secret-a", "sms-secret-b"])
        self.assertEqual(resolved["proxy"], existing["proxy"])
        self.assertEqual(resolved["email_notification"]["password"], "smtp-secret")

    def test_public_config_masks_all_supported_secrets(self):
        config = {
            "sms_api_keys": ["sms-secret"],
            "proxy": "http://proxy-user:proxy-pass@127.0.0.1:7890",
            "sub2api": {"password": "sub2-secret"},
            "nvtoken": {"api_key": "nv-secret"},
            "email_notification": {"password": "smtp-secret"},
        }

        masked = self.module._masked_local_config(config)
        serialized = json.dumps(masked)

        for secret in ("sms-secret", "proxy-pass", "sub2-secret", "nv-secret", "smtp-secret"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(masked["email_notification"]["password"], "********")

    def test_public_task_drops_composite_account_tokens_and_source_row(self):
        task = {
            "task_id": "task-1",
            "account": "user@example.test---mail-pass",
            "email": "user@example.test",
            "source_row": "user@example.test----mail-pass----client-id----refresh-token",
            "status": "failed",
            "error": "mail-pass client-id refresh-token",
            "result": {"access_token": "access-secret", "sms_cost_cny": 1.23},
        }

        public = self.module._public_task(task)
        serialized = json.dumps(public)

        self.assertEqual(public["account"], "user@example.test")
        self.assertNotIn("source_row", public)
        self.assertNotIn("access_token", serialized)
        for secret in ("mail-pass", "client-id", "refresh-token", "access-secret"):
            self.assertNotIn(secret, serialized)

    def test_public_logs_redact_proxy_username_and_password_fragments(self):
        self.module._write_local_config({
            "proxy": "http://proxy%40user:p%40ss-word@127.0.0.1:7890",
        })
        logs = [{"message": "proxy%40user p%40ss-word proxy@user p@ss-word"}]

        public = self.module._public_logs(logs, [])
        serialized = json.dumps(public)

        for secret in ("proxy%40user", "p%40ss-word", "proxy@user", "p@ss-word"):
            self.assertNotIn(secret, serialized)
        self.assertIn("********", serialized)


if __name__ == "__main__":
    unittest.main()
