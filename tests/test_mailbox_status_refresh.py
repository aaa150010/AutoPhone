from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mac_overrides.mailbox_admin import MailboxAdminService
from mac_overrides.sub2_binding_runtime import clear_successful_update_statuses


class _Store:
    def __init__(self, root: Path) -> None:
        self.data_dir = root

    @staticmethod
    def load():
        return {
            "pool_path": "pool.txt",
            "state_path": "state.json",
            "results_dir": "results",
        }


class MailboxStatusRefreshTests(unittest.TestCase):
    def test_successful_update_clears_legacy_remote_401_before_list_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pool.txt").write_text(
                "rerun@example.com|login-pass|JBSWY3DPEHPK3PXP\n",
                encoding="utf-8",
            )
            (root / "state.json").write_text('{"items": {}}', encoding="utf-8")
            (root / "results").mkdir()
            (root / "results" / "success.json").write_text(
                json.dumps(
                    {
                        "email": "rerun@example.com",
                        "status": "success",
                        "task_id": "task-rerun",
                        "created_at": 100,
                        "result": {
                            "sub2api_account_id": "remote-501",
                            "local_oauth": {
                                "tokens": {
                                    "access_token": "private-access-token",
                                    "chatgpt_account_id": "openai-501",
                                }
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            statuses = {
                "remote-501": {"kind": "unauthorized", "status_code": 401},
                "openai-501": {"kind": "unauthorized", "status_code": 401},
            }

            class DirectStatuses:
                @staticmethod
                def clear_status(account_id):
                    statuses.pop(account_id, None)

                @staticmethod
                def mark_credentials_refreshed(account_id):
                    statuses[account_id] = {
                        "kind": "untested",
                        "status_code": None,
                        "label": "凭据已更新，待复测",
                        "summary": "重登已成功并更新远端凭据",
                    }

            clear_successful_update_statuses(
                {"account_id": "remote-501", "openai_account_id": "openai-501"},
                {"ok": True, "sub2api_account_id": "remote-501"},
                direct_runtime=DirectStatuses(),
            )
            lookups = []
            service = MailboxAdminService(
                _Store(root),
                validate_pool=lambda _config: None,
                imap_poller_factory=lambda **_kwargs: None,
                openai_status_lookup=lambda account_id: lookups.append(account_id)
                or statuses.get(
                    account_id,
                    {"kind": "untested", "status_code": None, "label": "未测试"},
                ),
            )
            public = service.list_mailboxes()["rows"][0]

        self.assertEqual(lookups, ["openai-501", "remote-501"])
        self.assertEqual(public["sub2_status"]["label"], "凭据已更新，待复测")
        self.assertFalse(public["sub2_status"]["needs_rerun"])
        self.assertNotEqual(public["sub2_status"]["status_code"], 401)


if __name__ == "__main__":
    unittest.main()
