from __future__ import annotations

from types import SimpleNamespace
import unittest

from mac_overrides.sub2_binding_runtime import (
    clear_successful_update_statuses,
    confirmed_upload_log,
    historical_openai_account_id,
    resolve_existing_update_binding,
    status_requires_existing_update,
)


class Sub2BindingRuntimeTests(unittest.TestCase):
    def test_status_requires_existing_update_for_codes_and_kinds(self):
        for status in (
            {"status_code": 401},
            {"status_code": "404"},
            {"kind": "unauthorized"},
            {"kind": "not_found"},
        ):
            with self.subTest(status=status):
                self.assertTrue(status_requires_existing_update(status))
        self.assertFalse(status_requires_existing_update({"status_code": 200, "kind": "healthy"}))

    def test_direct_401_binds_historical_remote_row(self):
        direct_lookups = []
        sub2_lookups = []
        binding = resolve_existing_update_binding(
            {"account_id": "remote-501", "openai_account_id": "openai-501"},
            direct_status_lookup=lambda account_id: direct_lookups.append(account_id) or {
                "status_code": 401,
                "kind": "unauthorized",
            },
            sub2_status_lookup=lambda account_id: sub2_lookups.append(account_id) or {
                "status_code": 200,
                "kind": "healthy",
            },
        )

        self.assertEqual(binding["account_id"], "remote-501")
        self.assertEqual(binding["openai_account_id"], "openai-501")
        self.assertEqual(binding["status_source"], "openai_direct")
        self.assertEqual(direct_lookups, ["openai-501"])
        self.assertEqual(sub2_lookups, [])

    def test_sub2_404_binds_when_direct_status_is_healthy(self):
        binding = resolve_existing_update_binding(
            {"account_id": "remote-501", "openai_account_id": "openai-501"},
            direct_status_lookup=lambda _account_id: {"status_code": 200, "kind": "healthy"},
            sub2_status_lookup=lambda _account_id: {"status_code": 404, "kind": "not_found"},
        )

        self.assertEqual(binding["account_id"], "remote-501")
        self.assertEqual(binding["status_source"], "sub2")

    def test_lookup_failure_falls_through_to_the_other_status(self):
        def failed_direct(_account_id):
            raise RuntimeError("local snapshot unavailable")

        binding = resolve_existing_update_binding(
            {"account_id": "remote-501", "openai_account_id": "openai-501"},
            direct_status_lookup=failed_direct,
            sub2_status_lookup=lambda _account_id: {"status_code": 401},
        )

        self.assertEqual(binding["status_source"], "sub2")
        self.assertIsNone(
            resolve_existing_update_binding(
                {"account_id": "remote-501", "openai_account_id": "openai-501"},
                direct_status_lookup=failed_direct,
                sub2_status_lookup=lambda _account_id: {"status_code": 200},
            )
        )

    def test_historical_openai_id_requires_matching_remote_binding(self):
        historical = {"account_id": "remote-501", "openai_account_id": "openai-501"}
        self.assertEqual(historical_openai_account_id(historical, "remote-501"), "openai-501")
        self.assertEqual(historical_openai_account_id(historical, "remote-older"), "")

    def test_missing_openai_id_never_uses_remote_id_for_direct_lookup(self):
        direct_lookups = []
        binding = resolve_existing_update_binding(
            {"account_id": "remote-501"},
            direct_status_lookup=lambda account_id: direct_lookups.append(account_id) or {
                "status_code": 401,
            },
            sub2_status_lookup=lambda _account_id: {"status_code": 200},
        )
        self.assertIsNone(binding)
        self.assertEqual(direct_lookups, [])

    def test_success_clears_remote_and_openai_caches_with_separate_ids(self):
        sub2_cleared = []
        direct_cleared = []
        direct_refreshed = []
        targets = clear_successful_update_statuses(
            {"account_id": "remote-501", "openai_account_id": "openai-501"},
            {"ok": True, "sub2api_account_id": "remote-501"},
            sub2_runtime=SimpleNamespace(clear_status=sub2_cleared.append),
            direct_runtime=SimpleNamespace(
                clear_status=direct_cleared.append,
                mark_credentials_refreshed=direct_refreshed.append,
            ),
        )

        self.assertEqual(targets, ("remote-501", "openai-501"))
        self.assertEqual(sub2_cleared, ["remote-501"])
        self.assertEqual(direct_cleared, ["openai-501", "remote-501"])
        self.assertEqual(direct_refreshed, ["openai-501"])

    def test_failed_update_keeps_existing_statuses(self):
        sub2_cleared = []
        direct_cleared = []
        direct_refreshed = []

        targets = clear_successful_update_statuses(
            {"account_id": "remote-501", "openai_account_id": "openai-501"},
            {"ok": False, "error_code": "sub2_update_failed"},
            sub2_runtime=SimpleNamespace(clear_status=sub2_cleared.append),
            direct_runtime=SimpleNamespace(
                clear_status=direct_cleared.append,
                mark_credentials_refreshed=direct_refreshed.append,
            ),
        )

        self.assertEqual(targets, ("", ""))
        self.assertEqual(sub2_cleared, [])
        self.assertEqual(direct_cleared, [])
        self.assertEqual(direct_refreshed, [])

    def test_confirmed_upload_log_requires_every_remote_check(self):
        result = {
            "ok": True,
            "sub2api_account_id": "remote-private-501",
            "sub2_remote_verified": True,
            "sub2_group_verified": True,
            "sub2_chatgpt_account_id_verified": True,
            "access_token": "private-access-token",
        }

        message = confirmed_upload_log(result)

        self.assertIn("[SUB2 上传确认/sub2_upload_confirmed]", message)
        self.assertIn("sha256:", message)
        self.assertIn("保留远端当前分组", message)
        self.assertNotIn("remote-private-501", message)
        self.assertNotIn("private-access-token", message)
        for key in (
            "ok",
            "sub2_remote_verified",
            "sub2_group_verified",
            "sub2_chatgpt_account_id_verified",
        ):
            with self.subTest(missing=key):
                incomplete = dict(result)
                incomplete.pop(key)
                self.assertEqual(confirmed_upload_log(incomplete), "")

    def test_confirmed_upload_log_requires_remote_id(self):
        self.assertEqual(
            confirmed_upload_log(
                {
                    "ok": True,
                    "sub2_remote_verified": True,
                    "sub2_group_verified": True,
                    "sub2_chatgpt_account_id_verified": True,
                }
            ),
            "",
        )


if __name__ == "__main__":
    unittest.main()
