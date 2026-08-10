from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
import sys
import unittest

from mac_overrides.sub2_upload_override import upload_sub2_with_relogin_policy


class Sub2UploadOverrideTests(unittest.TestCase):
    @staticmethod
    def modules():
        return {
            "chatgpt_fields": SimpleNamespace(
                fetch_sub2_account_detail=lambda *_args, **_kwargs: {},
                extract_chatgpt_auth_fields=lambda *_args, **_kwargs: {},
                sub2_extra_from_item=lambda *_args, **_kwargs: {},
            ),
            "proxy_scope": SimpleNamespace(requests_kwargs=lambda _proxy: {}),
            "requests": SimpleNamespace(put=lambda *_args, **_kwargs: None),
            "sub2_groups": SimpleNamespace(
                resolve_sub2_group_id=lambda *_args, **_kwargs: (7, "CHATGPT"),
                assert_sub2_account_group=lambda *_args, **_kwargs: ([7], ["CHATGPT"]),
            ),
            "sub2_session": SimpleNamespace(get_admin_token=lambda *_args, **_kwargs: "token"),
        }

    @staticmethod
    def owner():
        return SimpleNamespace(
            config={
                "run_mode": "relogin",
                "_sub2_update_existing": {
                    "account_id": "old-501",
                    "openai_account_id": "openai-501",
                    "email": "rerun@example.test",
                },
            },
            upload_proxy="",
            log_fn=None,
        )

    def test_confirmed_missing_target_uses_original_verified_create_path(self):
        created = []
        cleared = []
        logs = []
        update_runtime = SimpleNamespace(
            Sub2UpdateDependencies=lambda **kwargs: kwargs,
            update_existing_sub2_account=lambda **_kwargs: {
                "ok": False,
                "error_code": "sub2_update_target_missing",
                "error": "sub2_update_target_missing: target missing",
            },
        )
        binding_runtime = SimpleNamespace(
            clear_successful_update_statuses=lambda binding, result, **kwargs: cleared.append(
                (binding, result, kwargs)
            ),
            confirmed_upload_log=lambda result: "confirmed" if result.get("ok") else "",
        )

        def original_upload(_owner, **kwargs):
            created.append(kwargs)
            return {
                "ok": True,
                "sub2api_account_id": "new-901",
                "sub2_upload_created": True,
                "sub2_remote_verified": True,
                "sub2_group_verified": True,
                "sub2_chatgpt_account_id_verified": True,
            }

        with patch.dict(sys.modules, self.modules()):
            result = upload_sub2_with_relogin_policy(
                self.owner(),
                credentials={"access_token": "private-access", "refresh_token": "private-refresh"},
                email="rerun@example.test",
                original_upload=original_upload,
                identity_locations=lambda _detail: ("", ""),
                update_runtime=update_runtime,
                binding_runtime=binding_runtime,
                call_log=lambda _logger, message, level: logs.append((message, level)),
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["sub2_upload_created"])
        self.assertTrue(result["sub2_recreated_missing_target"])
        self.assertEqual(len(created), 1)
        self.assertEqual(len(cleared), 1)
        self.assertEqual(logs[-1], ("confirmed", "success"))
        self.assertTrue(any("原账号已确认不存在" in message for message, _level in logs))
        self.assertNotIn("private-access", str(logs))
        self.assertNotIn("private-refresh", str(logs))

    def test_non_missing_update_failure_never_creates(self):
        created = []
        update_runtime = SimpleNamespace(
            Sub2UpdateDependencies=lambda **kwargs: kwargs,
            update_existing_sub2_account=lambda **_kwargs: {
                "ok": False,
                "error_code": "sub2_update_existing_failed",
                "error": "sub2_update_existing_failed: HTTP 500",
            },
        )
        binding_runtime = SimpleNamespace(
            clear_successful_update_statuses=lambda *_args, **_kwargs: None,
            confirmed_upload_log=lambda _result: "",
        )

        with patch.dict(sys.modules, self.modules()):
            result = upload_sub2_with_relogin_policy(
                self.owner(),
                credentials={"access_token": "private-access"},
                email="rerun@example.test",
                original_upload=lambda *_args, **kwargs: created.append(kwargs),
                identity_locations=lambda _detail: ("", ""),
                update_runtime=update_runtime,
                binding_runtime=binding_runtime,
                call_log=lambda *_args: None,
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "sub2_update_existing_failed")
        self.assertEqual(created, [])


if __name__ == "__main__":
    unittest.main()
