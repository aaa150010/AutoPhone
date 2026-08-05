from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
import unittest

from mac_overrides.sub2_update_runtime import (
    Sub2UpdateDependencies,
    update_existing_sub2_account,
)


EMAIL = "rerun@example.test"
ACCOUNT_ID = "42"
CHATGPT_ACCOUNT_ID = "chatgpt-account-42"


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {"code": 0}

    def json(self):
        return self.payload


class Sub2ExistingAccountUpdateTests(unittest.TestCase):
    def dependencies(self, *, response=None, bound_email=EMAIL):
        calls = SimpleNamespace(puts=[], fetches=[], posts=[])
        before = {
            "data": {
                "id": ACCOUNT_ID,
                "name": bound_email,
                "group_ids": [7],
                "credentials": {
                    "email": bound_email,
                    "access_token": "old-access",
                    "chatgpt_account_id": CHATGPT_ACCOUNT_ID,
                    "account_id": CHATGPT_ACCOUNT_ID,
                },
                "extra": {
                    "email": bound_email,
                    "chatgpt_account_id": CHATGPT_ACCOUNT_ID,
                    "account_id": CHATGPT_ACCOUNT_ID,
                },
            }
        }
        after = {
            "data": {
                "id": ACCOUNT_ID,
                "name": bound_email,
                "group_ids": [7],
                "credentials": {
                    "email": bound_email,
                    "access_token": "new-access",
                    "chatgpt_account_id": CHATGPT_ACCOUNT_ID,
                    "account_id": CHATGPT_ACCOUNT_ID,
                },
                "extra": {
                    "email": bound_email,
                    "chatgpt_account_id": CHATGPT_ACCOUNT_ID,
                    "account_id": CHATGPT_ACCOUNT_ID,
                },
            }
        }
        details = [before, after]

        def fetch_detail(_base, _token, account_id, **_kwargs):
            calls.fetches.append(account_id)
            return details.pop(0) if details else after

        def extract_fields(_credentials, *, exchange_data=None):
            value = exchange_data or {}
            data = value.get("data") if isinstance(value.get("data"), dict) else value
            credentials = data.get("credentials") if isinstance(data.get("credentials"), dict) else data
            return {
                "chatgpt_account_id": credentials.get("chatgpt_account_id") or CHATGPT_ACCOUNT_ID,
                "account_id": credentials.get("account_id") or CHATGPT_ACCOUNT_ID,
            }

        def identity_locations(detail):
            data = detail.get("data") or detail
            return (
                str((data.get("credentials") or {}).get("chatgpt_account_id") or ""),
                str((data.get("extra") or {}).get("chatgpt_account_id") or ""),
            )

        def put(url, **kwargs):
            calls.puts.append((url, kwargs))
            return response or FakeResponse()

        dependencies = Sub2UpdateDependencies(
            get_admin_token=lambda *_args, **_kwargs: "admin-token",
            resolve_group=lambda *_args, **_kwargs: (7, "CHATGPT"),
            fetch_detail=fetch_detail,
            assert_group=lambda *_args, **_kwargs: ([7], ["CHATGPT"]),
            extract_fields=extract_fields,
            extra_from_item=lambda item: {
                "email": item.get("email") or EMAIL,
                "chatgpt_account_id": item.get("chatgpt_account_id") or CHATGPT_ACCOUNT_ID,
                "account_id": item.get("account_id") or CHATGPT_ACCOUNT_ID,
            },
            identity_locations=identity_locations,
            put=put,
            requests_kwargs=lambda _proxy: {},
        )
        return dependencies, calls

    @staticmethod
    def config():
        return {
            "sub2api": {
                "url": "https://sub2.example.test",
                "email": "admin@example.test",
                "pwd": "admin-password",
                "group": "CHATGPT",
            }
        }

    @staticmethod
    def credentials():
        return {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "id_token": "new-id",
            "chatgpt_account_id": CHATGPT_ACCOUNT_ID,
        }

    def test_401_rerun_updates_bound_id_without_create_request(self):
        dependencies, calls = self.dependencies()

        result = update_existing_sub2_account(
            config=self.config(),
            credentials=self.credentials(),
            email=EMAIL,
            account_id=ACCOUNT_ID,
            upload_proxy="",
            log_fn=None,
            dependencies=dependencies,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["sub2api_account_id"], ACCOUNT_ID)
        self.assertTrue(result["sub2_update_existing"])
        self.assertFalse(result["sub2_upload_created"])
        self.assertEqual(calls.fetches, [ACCOUNT_ID, ACCOUNT_ID])
        self.assertEqual(len(calls.puts), 1)
        self.assertEqual(calls.posts, [])
        url, kwargs = calls.puts[0]
        self.assertTrue(url.endswith(f"/api/v1/admin/accounts/{ACCOUNT_ID}"))
        self.assertEqual(kwargs["json"]["credentials"]["access_token"], "new-access")
        self.assertEqual(kwargs["json"]["credentials"]["refresh_token"], "new-refresh")

    def test_update_http_failure_does_not_fall_back_to_create(self):
        dependencies, calls = self.dependencies(response=FakeResponse(500, {"code": 500}))

        result = update_existing_sub2_account(
            config=self.config(),
            credentials=self.credentials(),
            email=EMAIL,
            account_id=ACCOUNT_ID,
            upload_proxy="",
            log_fn=None,
            dependencies=dependencies,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "sub2_update_existing_failed")
        self.assertEqual(result["http_status"], 500)
        self.assertEqual(len(calls.puts), 1)
        self.assertEqual(calls.posts, [])

    def test_binding_mismatch_stops_before_put(self):
        dependencies, calls = self.dependencies(bound_email="different@example.test")

        result = update_existing_sub2_account(
            config=self.config(),
            credentials=self.credentials(),
            email=EMAIL,
            account_id=ACCOUNT_ID,
            upload_proxy="",
            log_fn=None,
            dependencies=dependencies,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "sub2_update_binding_mismatch")
        self.assertEqual(calls.puts, [])
        self.assertEqual(calls.posts, [])

    def test_pre_update_failures_preserve_exact_branch_and_skip_put(self):
        base_dependencies, calls = self.dependencies()
        cases = (
            (
                "sub2_update_binding_missing",
                self.config(),
                self.credentials(),
                "",
                base_dependencies,
            ),
            (
                "sub2_update_config_missing",
                {},
                self.credentials(),
                ACCOUNT_ID,
                base_dependencies,
            ),
            (
                "sub2_update_token_incomplete",
                self.config(),
                {"access_token": "new-access"},
                ACCOUNT_ID,
                base_dependencies,
            ),
            (
                "sub2_update_prepare_failed",
                self.config(),
                self.credentials(),
                ACCOUNT_ID,
                replace(
                    base_dependencies,
                    get_admin_token=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        RuntimeError("network failure")
                    ),
                ),
            ),
            (
                "sub2_update_target_missing",
                self.config(),
                self.credentials(),
                ACCOUNT_ID,
                replace(base_dependencies, fetch_detail=lambda *_args, **_kwargs: {}),
            ),
        )

        for code, config, credentials, account_id, dependencies in cases:
            with self.subTest(code=code):
                result = update_existing_sub2_account(
                    config=config,
                    credentials=credentials,
                    email=EMAIL,
                    account_id=account_id,
                    upload_proxy="",
                    log_fn=None,
                    dependencies=dependencies,
                )
                self.assertFalse(result["ok"])
                self.assertEqual(result["error_code"], code)

        self.assertEqual(calls.puts, [])
        self.assertEqual(calls.posts, [])

    def test_post_update_verification_failures_never_create_an_account(self):
        before = {
            "data": {
                "id": ACCOUNT_ID,
                "name": EMAIL,
                "credentials": {
                    "email": EMAIL,
                    "chatgpt_account_id": CHATGPT_ACCOUNT_ID,
                },
                "extra": {
                    "email": EMAIL,
                    "chatgpt_account_id": CHATGPT_ACCOUNT_ID,
                },
            }
        }

        dependencies, calls = self.dependencies()
        details = [before, {}]
        verification_dependencies = replace(
            dependencies,
            fetch_detail=lambda *_args, **_kwargs: details.pop(0),
        )
        verification = update_existing_sub2_account(
            config=self.config(),
            credentials=self.credentials(),
            email=EMAIL,
            account_id=ACCOUNT_ID,
            upload_proxy="",
            log_fn=None,
            dependencies=verification_dependencies,
        )

        group_dependencies, group_calls = self.dependencies()
        group = update_existing_sub2_account(
            config=self.config(),
            credentials=self.credentials(),
            email=EMAIL,
            account_id=ACCOUNT_ID,
            upload_proxy="",
            log_fn=None,
            dependencies=replace(
                group_dependencies,
                assert_group=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("group mismatch")
                ),
            ),
        )

        identity_dependencies, identity_calls = self.dependencies()
        identity = update_existing_sub2_account(
            config=self.config(),
            credentials=self.credentials(),
            email=EMAIL,
            account_id=ACCOUNT_ID,
            upload_proxy="",
            log_fn=None,
            dependencies=replace(
                identity_dependencies,
                identity_locations=lambda _detail: ("wrong", "wrong"),
            ),
        )

        self.assertEqual(verification["error_code"], "sub2_update_verification_failed")
        self.assertEqual(group["error_code"], "sub2_update_group_verification_failed")
        self.assertEqual(identity["error_code"], "sub2_update_identity_verification_failed")
        for branch_calls in (calls, group_calls, identity_calls):
            self.assertEqual(len(branch_calls.puts), 1)
            self.assertEqual(branch_calls.posts, [])


if __name__ == "__main__":
    unittest.main()
