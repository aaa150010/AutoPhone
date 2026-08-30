from __future__ import annotations

import asyncio
import sys
import threading
from types import ModuleType
import unittest
from unittest.mock import AsyncMock, patch

from mac_overrides import free_camoufox_runtime as camoufox
from mac_overrides import free_protocol_runtime as protocol


class _Session:
    def close(self) -> None:
        pass


class _Sentinel:
    def __init__(self, **_kwargs):
        self.fingerprint = {}


class _Transport:
    def __init__(self, config, *, oauth_params, proxy, sentinel_provider, device_id, log_fn):
        self.config = config
        self.oauth_params = dict(oauth_params)
        self.proxy = proxy
        self.sentinel_provider = sentinel_provider
        self.device_id = device_id
        self.log_fn = log_fn
        self.session = _Session()

    def close(self) -> None:
        self.session.close()


class _Otp:
    def close(self) -> None:
        pass


class _ProtocolManager(protocol.FreeProtocolMixin):
    def __init__(self) -> None:
        self.calls: list[str] = []

    @classmethod
    def resolve_node_runner(cls, _config=None):
        return "/private/tmp/fake-sentinel-runner.js"

    @staticmethod
    def _instrument_transport(_transport, _task_id, _stage):
        return None

    def _plan_check(self, _transport, _token):
        return "free", False

    def _set_password(self, *_args):
        self.calls.append("password")
        return {
            "password_status": "enabled",
            "password_set_after_registration": True,
            "password": protocol.FIXED_PASSWORD,
            "access_token": "password-token",
        }

    def _enroll_twofa(self, *_args):
        self.calls.append("twofa")
        return {
            "twofa_status": "enabled",
            "totp_secret": "TESTTOTPSECRET",
        }


def _protocol_modules() -> dict[str, ModuleType]:
    chain_runner = ModuleType("codex_chain_runner")
    chain_runner.build_oauth_url = lambda **_kwargs: (
        "https://auth.example.test/authorize?client_id=client&state=state",
        "state",
        "verifier",
    )
    oauth_chain = ModuleType("codex_oauth_chain")
    oauth_chain.parse_oauth_url = lambda _url: {
        "client_id": "client",
        "state": "state",
        "redirect_uri": "http://localhost:1455/auth/callback",
    }
    oauth_chain.RealNodeSentinelProvider = _Sentinel
    oauth_chain.RealCodexTransport = _Transport
    return {"codex_chain_runner": chain_runner, "codex_oauth_chain": oauth_chain}


def _protocol_task() -> dict[str, str]:
    return {
        "task_id": "combo-task",
        "row_id": "combo-row",
        "email": "user@example.test",
        "mailbox_url": "https://mail.example.test/inbox",
        "proxy": "socks5h://proxy.example.test:1080",
        "proxy_fingerprint": "proxy-fingerprint",
        "device_id": "device-id",
    }


class FreeSecurityCombinationTests(unittest.TestCase):
    def test_protocol_runs_each_security_operation_only_when_enabled(self):
        for set_password, set_twofa in (
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ):
            with self.subTest(set_password=set_password, set_twofa=set_twofa):
                manager = _ProtocolManager()

                def run_flow(transport, **_kwargs):
                    return {
                        "ok": True,
                        "registration_completed": True,
                        "oauth_callback_completed": True,
                        "access_token": "registration-token",
                        "account_flow": "signup",
                        "registration_password_used": False,
                    }, transport

                with (
                    patch.dict(sys.modules, _protocol_modules()),
                    patch.object(protocol, "build_free_mailbox_otp_provider", return_value=_Otp()),
                    patch.object(protocol, "run_free_protocol_flow", side_effect=run_flow),
                ):
                    result = manager._run_protocol(
                        _protocol_task(),
                        {
                            "flow_profile": "legacy",
                            "auto_set_password": set_password,
                            "auto_set_2fa": set_twofa,
                        },
                        threading.Event(),
                        lambda *_args: None,
                        lambda *_args: None,
                    )

                expected_calls = (["password"] if set_password else []) + (
                    ["twofa"] if set_twofa else []
                )
                self.assertEqual(manager.calls, expected_calls)
                self.assertEqual(result["password_status"], "enabled" if set_password else "disabled")
                self.assertEqual(result["twofa_status"], "enabled" if set_twofa else "disabled")
                self.assertEqual(bool(result.get("password")), set_password)
                self.assertEqual(bool(result.get("totp_secret")), set_twofa)
                if set_password and set_twofa:
                    self.assertEqual(
                        result["credential_line"],
                        f"user@example.test----{protocol.FIXED_PASSWORD}----TESTTOTPSECRET",
                    )
                elif set_password:
                    self.assertEqual(
                        result["credential_line"],
                        f"user@example.test----{protocol.FIXED_PASSWORD}",
                    )
                else:
                    self.assertNotIn("credential_line", result)

    def test_camoufox_finish_home_keeps_operations_independent(self):
        class Page:
            url = "https://chatgpt.com/"

        async def no_navigation(*_args, **_kwargs):
            return None

        async def entry_selector(*_args, **_kwargs):
            return "input[type='email']"

        async def prepared_form(*_args, **_kwargs):
            return {
                "ok": True,
                "form_present": True,
                "input_selector": "input[type='email']",
                "submit_selector": "button",
            }

        async def clicked(*_args, **_kwargs):
            return True

        async def home(*_args, **_kwargs):
            return "home"

        async def session(*_args, **_kwargs):
            return {"accessToken": "browser-token"}

        async def plan(*_args, **_kwargs):
            return {"plan_type": "free"}

        for set_password, set_twofa in (
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ):
            with self.subTest(set_password=set_password, set_twofa=set_twofa):
                calls: list[str] = []

                async def add_password(*_args, **_kwargs):
                    calls.append("password")
                    return {
                        "password_status": "enabled",
                        "password_set_after_registration": True,
                        "password": "TESTPASSWORD",
                        "access_token": "password-token",
                    }

                async def enroll_twofa(*_args, **_kwargs):
                    calls.append("twofa")
                    return {
                        "twofa_status": "enabled",
                        "totp_secret": "TESTTOTPSECRET",
                        "access_token": "twofa-token",
                    }

                with (
                    patch.object(camoufox, "_goto_with_retry", new=no_navigation),
                    patch.object(camoufox, "_wait_for_any_selector", new=entry_selector),
                    patch.object(camoufox, "_submit_email_form_stable", new=prepared_form),
                    patch.object(camoufox, "_click_visible_submit", new=clicked),
                    patch.object(camoufox, "_page_state", new=home),
                    patch.object(camoufox, "browser_session", new=session),
                    patch.object(camoufox, "browser_plan_details", new=plan),
                    patch.object(camoufox, "browser_add_password", new=add_password),
                    patch.object(camoufox, "browser_twofa", new=enroll_twofa),
                    patch.object(camoufox.asyncio, "sleep", new=AsyncMock()),
                ):
                    result = asyncio.run(
                        camoufox._browser_flow(
                            Page(),
                            email="user@example.test",
                            password="TESTPASSWORD",
                            otp_callback=lambda *_args, **_kwargs: "000000",
                            config={
                                "registration_timeout_seconds": 60,
                                "auto_set_password": set_password,
                                "auto_set_2fa": set_twofa,
                            },
                            log=lambda *_args: None,
                        )
                    )

                expected_calls = (["password"] if set_password else []) + (
                    ["twofa"] if set_twofa else []
                )
                self.assertEqual(calls, expected_calls)
                self.assertEqual(result["password_status"], "enabled" if set_password else "disabled")
                self.assertEqual(result["twofa_status"], "enabled" if set_twofa else "disabled")
                self.assertEqual(bool(result.get("password")), set_password)
                self.assertEqual(bool(result.get("totp_secret")), set_twofa)


if __name__ == "__main__":
    unittest.main()
