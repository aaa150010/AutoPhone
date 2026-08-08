from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mac_overrides.mailbox_admin import latest_sub2_accounts_by_email


class Sub2LineageRuntimeTests(unittest.TestCase):
    def test_duplicate_identity_uses_latest_successful_remote_binding_and_result(self):
        with tempfile.TemporaryDirectory() as temp:
            results_dir = Path(temp)
            fixtures = (
                (
                    "older.json",
                    100,
                    "remote-old",
                    "old-access-token",
                    "success",
                ),
                (
                    "newer.json",
                    200,
                    "remote-active",
                    "new-access-token",
                    "success",
                ),
                (
                    "failed.json",
                    300,
                    "remote-failed",
                    "failed-access-token",
                    "failed",
                ),
            )
            for filename, created_at, remote_id, access_token, status in fixtures:
                (results_dir / filename).write_text(
                    json.dumps(
                        {
                            "email": "duplicate@example.test",
                            "status": status,
                            "created_at": created_at,
                            "result": {
                                "sub2api_account_id": remote_id,
                                "access_token": access_token,
                                "chatgpt_account_id": "openai-stable-identity",
                            },
                        }
                    ),
                    encoding="utf-8",
                )

            binding = latest_sub2_accounts_by_email(results_dir)[
                "duplicate@example.test"
            ]

            self.assertEqual(binding["account_id"], "remote-active")
            self.assertEqual(binding["openai_account_id"], "openai-stable-identity")
            self.assertEqual(binding["created_at"], 200)
            self.assertEqual(Path(binding["result_file"]).name, "newer.json")


if __name__ == "__main__":
    unittest.main()
