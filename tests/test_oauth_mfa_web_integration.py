from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from tests.web_gui_test_runtime import RecoveredWebGuiImport


class OAuthMfaWebIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.previous_data_dir = os.environ.get("GPTPHONE_DATA_DIR")
        os.environ["GPTPHONE_DATA_DIR"] = cls.tempdir.name
        cls.web_gui_import = RecoveredWebGuiImport(Path(__file__).resolve().parents[1])
        cls.module = cls.web_gui_import.load()

    @classmethod
    def tearDownClass(cls):
        if cls.previous_data_dir is None:
            os.environ.pop("GPTPHONE_DATA_DIR", None)
        else:
            os.environ["GPTPHONE_DATA_DIR"] = cls.previous_data_dir
        cls.web_gui_import.cleanup()
        cls.tempdir.cleanup()

    def test_missing_mfa_secret_code_survives_recovered_error_text(self):
        response = {
            "_status": 200,
            "error": {
                "code": "mfa_totp_secret_missing",
                "message": "mfa_totp_secret_missing: 当前任务未绑定有效 2FA 密钥",
            },
        }
        error_text = self.module._codex_oauth_chain._error_text(response)
        self.assertIn("mfa_totp_secret_missing", error_text)
        failure = self.module._error_observability_ext.classify_failure(
            error=error_text
        )
        self.assertEqual(failure["node_code"], "mfa_otp_verifying")
        self.assertEqual(failure["error_code"], "mfa_totp_secret_missing")

    def test_url_mailbox_wait_binds_totp_secret_to_task_before_worker(self):
        module = self.module
        original_wait = module._manual_email_wait
        task_token = module._TASK_CONTEXT.set("T-url-secret")
        provider = SimpleNamespace(
            task_id="T-url-secret",
            config={},
            entry=SimpleNamespace(
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token="JBSWY3DPEHPK3PXP",
            ),
        )
        try:
            module._manual_email_wait = lambda current, _email, _automatic: current
            self.assertIs(module._url_mailbox_wait_code(provider, "user@example.com"), provider)
            transport = SimpleNamespace(config={"sms_task_id": "T-url-secret"})
            self.assertEqual(
                module._oauth_mfa_runtime_ext.resolve_totp_secret(
                    transport,
                    context_secret_get=lambda: "",
                    task_secret_get=module._TASK_TOTP_SECRETS.get,
                    task_id_get=lambda current: module._transport_task_id(current),
                ),
                "JBSWY3DPEHPK3PXP",
            )
        finally:
            module._manual_email_wait = original_wait
            module._TASK_TOTP_SECRETS.clear("T-url-secret")
            module._TASK_CONTEXT.reset(task_token)

    def test_totp_provider_binding_is_shared_before_oauth_worker_starts(self):
        module = self.module
        provider = SimpleNamespace(
            task_id="T-provider-secret",
            config={},
            entry=SimpleNamespace(
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token="JBSWY3DPEHPK3PXP",
            ),
        )
        try:
            self.assertTrue(
                module._oauth_mfa_runtime_ext.remember_provider_totp_secret(
                    provider,
                    module._TASK_TOTP_SECRETS,
                    task_id="T-provider-secret",
                    current_task_get=module._TASK_CONTEXT.get,
                )
            )
            self.assertTrue(getattr(provider, "_gptphone_totp_expected", False))
            self.assertEqual(
                module._TASK_TOTP_SECRETS.get("T-provider-secret"),
                "JBSWY3DPEHPK3PXP",
            )
            transport = SimpleNamespace(config={"sms_task_id": "T-provider-secret"})
            self.assertTrue(
                module._oauth_mfa_runtime_ext.transport_expects_totp(
                    transport,
                    module._TASK_TOTP_SECRETS,
                    transport_task_id_get=module._transport_task_id,
                    current_task_get=module._TASK_CONTEXT.get,
                )
            )
            module._oauth_mfa_runtime_ext.clear_task_totp_secret(
                transport,
                module._TASK_TOTP_SECRETS,
                context_clear=module._MAILBOX_TOTP_SECRET_CONTEXT.set,
                transport_task_id_get=module._transport_task_id,
                current_task_get=module._TASK_CONTEXT.get,
            )
            self.assertEqual(module._TASK_TOTP_SECRETS.get("T-provider-secret"), "")
        finally:
            module._TASK_TOTP_SECRETS.clear("T-provider-secret")

    def test_run_codex_clears_provider_only_totp_task_after_chain_exit(self):
        module = self.module
        original_run = module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION
        provider = SimpleNamespace(
            task_id="T-provider-only",
            config={},
            entry=SimpleNamespace(
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token="JBSWY3DPEHPK3PXP",
            ),
        )
        observed = []

        def run(**_kwargs):
            observed.append(module._TASK_TOTP_SECRETS.get("T-provider-only"))
            return {"ok": False, "error": "test_failure"}

        try:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = run
            result = module._run_codex_after_registration(
                oauth_url="https://auth.example.test/authorize",
                account_email="masked@example.test",
                email_otp_provider=provider,
                config={},
            )
        finally:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = original_run
            module._TASK_TOTP_SECRETS.clear("T-provider-only")

        self.assertFalse(result["ok"])
        self.assertEqual(observed, ["JBSWY3DPEHPK3PXP"])
        self.assertEqual(module._TASK_TOTP_SECRETS.get("T-provider-only"), "")

    def test_run_codex_uses_context_task_id_for_transport_registration(self):
        module = self.module
        originals = {
            "run": module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION,
            "bind": module._auth_challenge_runtime_ext.bind_transport_context,
            "ensure": module._auth_request_runtime_ext.ensure_transport_context,
            "register": module._register_sms_transport,
        }
        token = module._TASK_CONTEXT.set("T-context-task")
        ensured = []
        registered = []
        transport = SimpleNamespace(config={})
        try:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = lambda **_kwargs: {
                "ok": False,
                "error": "test_failure",
            }
            module._auth_challenge_runtime_ext.bind_transport_context = (
                lambda *_args, **_kwargs: None
            )
            module._auth_request_runtime_ext.ensure_transport_context = (
                lambda _transport, _sessions, **kwargs: ensured.append(kwargs)
            )
            module._register_sms_transport = lambda task_id, _transport: registered.append(
                task_id
            )
            module._run_codex_after_registration(
                oauth_url="https://auth.example.test/authorize",
                account_email="masked@example.test",
                config={},
                transport=transport,
            )
        finally:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = originals["run"]
            module._auth_challenge_runtime_ext.bind_transport_context = originals["bind"]
            module._auth_request_runtime_ext.ensure_transport_context = originals["ensure"]
            module._register_sms_transport = originals["register"]
            module._TASK_CONTEXT.reset(token)

        self.assertEqual(registered, ["T-context-task"])
        self.assertEqual(len(ensured), 1)

    def test_run_codex_preserves_existing_transport_task_id_when_config_is_empty(self):
        module = self.module
        originals = {
            "run": module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION,
            "bind": module._auth_challenge_runtime_ext.bind_transport_context,
            "ensure": module._auth_request_runtime_ext.ensure_transport_context,
            "register": module._register_sms_transport,
        }
        registered = []
        transport = SimpleNamespace(config={"sms_task_id": "T-transport-only"})
        task_token = module._TASK_CONTEXT.set("")
        try:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = lambda **_kwargs: {
                "ok": False,
                "error": "test_failure",
            }
            module._auth_challenge_runtime_ext.bind_transport_context = (
                lambda *_args, **_kwargs: None
            )
            module._auth_request_runtime_ext.ensure_transport_context = (
                lambda *_args, **_kwargs: None
            )
            module._register_sms_transport = lambda task_id, _transport: registered.append(
                task_id
            )
            module._run_codex_after_registration(
                oauth_url="https://auth.example.test/authorize",
                account_email="masked@example.test",
                config={},
                transport=transport,
            )
        finally:
            module._ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = originals["run"]
            module._auth_challenge_runtime_ext.bind_transport_context = originals["bind"]
            module._auth_request_runtime_ext.ensure_transport_context = originals["ensure"]
            module._register_sms_transport = originals["register"]
            module._TASK_CONTEXT.reset(task_token)

        self.assertEqual(registered, ["T-transport-only"])


if __name__ == "__main__":
    unittest.main()
