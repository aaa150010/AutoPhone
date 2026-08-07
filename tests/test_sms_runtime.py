from __future__ import annotations

from dataclasses import dataclass
import json
import tempfile
import threading
import time
from pathlib import Path
import unittest
import urllib.parse

from mac_overrides.sms_runtime import (
    _candidate_route,
    ExchangeRateCache,
    HeroSmsCancellationDeferred,
    PhoneSubmissionGate,
    PERFORMANCE_POLICY_VERSION,
    PooledSmsProvider,
    PooledSmsBowerProvider,
    RuntimeAlertBuffer,
    ProxyProtocolGate,
    SingleFlightTtlCache,
    SmsCostLedger,
    SmsCleanupQueue,
    SmsKeyPool,
    SmsProviderRegistry,
    SmsRoutePolicy,
    confirm_herosms_cancellation,
    isolated_sms_get,
    is_protocol_pressure_error,
    is_sms_route_infrastructure_error,
    is_transient_openai_error,
    migrate_performance_config,
    normalize_sms_keys,
    normalize_sms_provider_pools,
    rank_sms_candidates,
    redact_sms_secrets,
)


class FakeSmsProvider:
    def __init__(self, key: str, scenario: dict, calls: list[tuple]) -> None:
        self.key = key
        self.scenario = scenario
        self.calls = calls
        self.activation_id = ""

    def balance(self):
        value = self.scenario.get("balance", 1.0)
        if isinstance(value, Exception):
            raise value
        return f"ACCESS_BALANCE:{value}"

    def get_price_candidates(self, service="dr", countries=None):
        value = self.scenario.get("prices", [{"price": 0.04, "count": 10}])
        if isinstance(value, Exception):
            raise value
        return value

    def get_number_from_candidate(self, **kwargs):
        outcomes = self.scenario.setdefault("activations", [])
        outcome = outcomes.pop(0) if outcomes else (f"activation-{self.key}", f"+1000{self.key[-1:]}")
        self.calls.append(("activate", self.key, kwargs.get("candidate_price")))
        if isinstance(outcome, Exception):
            raise outcome
        self.activation_id = str(outcome[0])
        return outcome

    def wait_code(self, timeout=300, interval=3):
        self.calls.append(("wait", self.key, self.activation_id))
        value = self.scenario.get("code", "123456")
        if isinstance(value, Exception):
            raise value
        return value

    def set_ready(self):
        self.calls.append(("ready", self.key, self.activation_id))
        value = self.scenario.get("ready")
        if isinstance(value, Exception):
            raise value

    def complete(self):
        self.calls.append(("complete", self.key, self.activation_id))

    def cancel(self):
        self.calls.append(("cancel", self.key, self.activation_id))


class FakeFactory:
    def __init__(self, scenarios: dict[str, dict]) -> None:
        self.scenarios = scenarios
        self.calls: list[tuple] = []

    def __call__(self, key: str, proxy: str = "") -> FakeSmsProvider:
        scenario = self.scenarios[key]
        error = scenario.get("factory_error")
        if isinstance(error, Exception):
            raise error
        return FakeSmsProvider(key, scenario, self.calls)


class FakeMultiPlatformProvider:
    def __init__(self, platform: str, key: str, scenario: dict, calls: list[tuple]) -> None:
        self.platform = platform
        self.key = key
        self.scenario = scenario
        self.calls = calls
        self.activation_id = ""

    def balance(self):
        value = self.scenario.get("balance", 1.0)
        if isinstance(value, Exception):
            raise value
        return value

    def get_price_candidates(self, service="dr", countries=None):
        self.calls.append(("prices", self.platform, self.key, service))
        value = self.scenario.get(
            "prices",
            [{"country": "151", "provider_id": "any", "price": 0.04, "count": 10}],
        )
        if isinstance(value, Exception):
            raise value
        return value

    def get_number_from_candidate(self, **kwargs):
        self.calls.append(("activate", self.platform, self.key, kwargs.get("service")))
        outcomes = self.scenario.setdefault("activations", [])
        value = outcomes.pop(0) if outcomes else (
            f"{self.platform}-{self.key}-order",
            "+15550001111",
        )
        if isinstance(value, Exception):
            raise value
        self.activation_id = str(value[0])
        return value

    def get_number(self, **kwargs):
        return self.get_number_from_candidate(**kwargs)

    def set_ready(self):
        self.calls.append(("ready", self.platform, self.key, self.activation_id))

    def wait_code(self, timeout=300, interval=3):
        self.calls.append(
            ("wait", self.platform, self.key, self.activation_id, timeout, interval)
        )
        values = self.scenario.setdefault("codes", ["123456"])
        value = values.pop(0) if values else None
        if isinstance(value, Exception):
            raise value
        return value

    def complete(self):
        self.calls.append(("complete", self.platform, self.key, self.activation_id))

    def cancel(self):
        self.calls.append(("cancel", self.platform, self.key, self.activation_id))
        value = self.scenario.get("cancel")
        if isinstance(value, Exception):
            raise value

    def _api(self, params):
        action = str(params.get("action") or "")
        self.calls.append(("api", self.platform, self.key, action))
        if action == "setStatus":
            value = self.scenario.get("cancel_response", "ACCESS_CANCEL")
        else:
            value = self.scenario.get("cancel_status", "STATUS_CANCEL")
        if isinstance(value, Exception):
            raise value
        return value

    def _rest_get(self, path, timeout=15):
        self.calls.append(("rest_get", self.platform, self.key, path))
        value = self.scenario.get("rest_get")
        if isinstance(value, Exception):
            raise value
        return value if value is not None else {"status": "BANNED"}


class FakeMultiPlatformFactory:
    def __init__(self, scenarios: dict[tuple[str, str], dict]) -> None:
        self.scenarios = scenarios
        self.calls: list[tuple] = []

    def __call__(self, platform: str, key: str, proxy: str = "") -> FakeMultiPlatformProvider:
        return FakeMultiPlatformProvider(
            platform,
            key,
            self.scenarios[(platform, key)],
            self.calls,
        )


@dataclass
class FakeLease:
    activation_id: str
    meta: dict


class FakeExchange:
    def get_rate(self):
        return {"rate": 7.25, "date": "2026-07-26", "source": "test"}


class SmsRuntimeTests(unittest.TestCase):
    def test_normalizes_legacy_key_without_hyphen_splitting(self):
        self.assertEqual(normalize_sms_keys(None, "  abc-def  "), ["abc-def"])
        self.assertEqual(normalize_sms_keys([" a ", "", "a", "b"]), ["a", "b"])

    def test_policy_migrates_once_and_preserves_later_zero(self):
        migrated, changed = migrate_performance_config({"sms_api_key": "legacy", "phone_max_attempts": 0})
        self.assertTrue(changed)
        self.assertEqual(migrated["sms_api_keys"], ["legacy"])
        self.assertEqual(migrated["phone_max_attempts"], 45)
        self.assertEqual(migrated["phone_attempts_per_provider"], 15)
        self.assertEqual(migrated["phone_session_cycle_seconds"], 1800)
        self.assertEqual(migrated["auth_session_retries"], 1)
        self.assertEqual(migrated["auto_email_login_concurrency"], 5)
        self.assertEqual(migrated["phone_submission_concurrency"], 2)
        self.assertEqual(migrated["pixel_upload_concurrency"], 2)

        upgraded, changed = migrate_performance_config({
            "performance_policy_version": 4,
            "phone_max_attempts": 0,
            "auth_session_retries": 0,
        })
        self.assertTrue(changed)
        self.assertEqual(upgraded["phone_max_attempts"], 45)
        self.assertEqual(upgraded["auth_session_retries"], 1)
        self.assertEqual(upgraded["performance_policy_version"], PERFORMANCE_POLICY_VERSION)

        saved, changed = migrate_performance_config({
            "performance_policy_version": PERFORMANCE_POLICY_VERSION,
            "phone_max_attempts": 0,
            "auth_session_retries": 0,
        })
        self.assertFalse(changed)
        self.assertEqual(saved["phone_max_attempts"], 0)
        self.assertEqual(saved["auth_session_retries"], 0)
        self.assertEqual(saved["auto_email_login_concurrency"], 5)
        self.assertEqual(saved["phone_session_cycle_seconds"], 1800)

        saved_one, changed = migrate_performance_config({
            "performance_policy_version": PERFORMANCE_POLICY_VERSION,
            "auto_email_login_concurrency": 1,
        })
        self.assertFalse(changed)
        self.assertEqual(saved_one["auto_email_login_concurrency"], 1)

        clamped_email, changed = migrate_performance_config({
            "performance_policy_version": PERFORMANCE_POLICY_VERSION,
            "concurrency": 3,
            "auto_email_login_concurrency": 5,
        })
        self.assertFalse(changed)
        self.assertEqual(clamped_email["auto_email_login_concurrency"], 3)

        over_limit, changed = migrate_performance_config({
            "performance_policy_version": PERFORMANCE_POLICY_VERSION,
            "phone_max_attempts": 47,
        })
        self.assertFalse(changed)
        self.assertEqual(over_limit["phone_max_attempts"], 45)

        bounded, _changed = migrate_performance_config({
            "performance_policy_version": PERFORMANCE_POLICY_VERSION,
            "concurrency": 99,
            "phone_submission_concurrency": 9,
            "pixel_upload_concurrency": 0,
        })
        self.assertEqual(bounded["concurrency"], 8)
        self.assertEqual(bounded["phone_submission_concurrency"], 3)
        self.assertEqual(bounded["pixel_upload_concurrency"], 2)

    def test_provider_pool_config_migrates_legacy_and_preserves_platform_defaults(self):
        legacy, _changed = migrate_performance_config({
            "sms_provider": "herosms",
            "sms_api_keys": ["hero-a", "hero-b"],
        })
        self.assertEqual(legacy["sms_provider_pools"], [{
            "provider": "herosms",
            "enabled": True,
            "api_keys": ["hero-a", "hero-b"],
            "service": "dr",
        }])

        pools = normalize_sms_provider_pools([
            {"provider": "smsbower", "api_keys": ["bower-a"], "enabled": True},
            {"provider": "hero-sms", "api_keys": ["hero-a"], "enabled": False},
            {"provider": "fivesim", "api_keys": ["five-a"], "enabled": True},
        ])
        self.assertEqual([pool["provider"] for pool in pools], ["smsbower", "herosms", "5sim"])
        self.assertEqual(pools[2]["service"], "openai")

    def test_duplicate_provider_pool_rows_merge_keys_instead_of_dropping_one(self):
        pools = normalize_sms_provider_pools([
            {"provider": "smsbower", "api_keys": ["key-a"], "enabled": True},
            {"provider": "SMSBower", "api_keys": ["key-b"], "enabled": False},
        ])

        self.assertEqual(len(pools), 1)
        self.assertEqual(pools[0]["provider"], "smsbower")
        self.assertEqual(pools[0]["api_keys"], ["key-a", "key-b"])
        self.assertTrue(pools[0]["enabled"])

    def test_multi_platform_registry_preflight_isolated_status_and_secret_redaction(self):
        secret = "hero-secret/key"
        factory = FakeMultiPlatformFactory({
            ("smsbower", "bower-a"): {"balance": RuntimeError("NO_BALANCE")},
            ("herosms", secret): {"balance": 2.5},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-a"], "service": "dr"},
                {"provider": "herosms", "enabled": True, "api_keys": [secret], "service": "dr"},
            ]
        })

        statuses = registry.preflight()

        self.assertEqual(
            [(row["provider"], row["status"]) for row in statuses],
            [("smsbower", "insufficient_balance"), ("herosms", "usable")],
        )
        self.assertFalse(registry.is_exhausted())
        self.assertNotIn(secret, str(statuses))
        self.assertNotIn(secret, registry.safe_error(f"provider rejected api_key={secret}"))

    def test_multi_platform_balance_query_skips_inventory_and_includes_disabled_keys(self):
        secret = "disabled-secret/key"
        factory = FakeMultiPlatformFactory({
            ("smsbower", "bower-a"): {"balance": 2.5},
            ("herosms", secret): {"balance": 0.005},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure(
            {
                "sms_provider_pools": [
                    {"provider": "smsbower", "enabled": True, "api_keys": ["bower-a"]},
                    {"provider": "herosms", "enabled": False, "api_keys": [secret]},
                ]
            },
            min_price=0.01,
        )

        statuses = registry.query_balances(proxy="http://127.0.0.1:7897")

        self.assertEqual(
            [(row["provider"], row["status"], row["balance_usd"], row["enabled"]) for row in statuses],
            [
                ("smsbower", "usable", 2.5, True),
                ("herosms", "insufficient_balance", 0.005, False),
            ],
        )
        self.assertFalse(any(call[0] == "prices" for call in factory.calls))
        self.assertNotIn(secret, str(statuses))

    def test_multi_platform_activation_failover_binds_order_to_platform_and_key(self):
        factory = FakeMultiPlatformFactory({
            ("smsbower", "bower-a"): {
                "balance": 1.0,
                "activations": [RuntimeError("NO_NUMBERS")],
            },
            ("herosms", "hero-a"): {
                "balance": 1.0,
                "activations": [("hero-order", "+15550002222")],
            },
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-a"]},
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-a"]},
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.get_price_candidates()

        activation_id, _phone = provider.get_number_from_candidate(
            "dr", "151", "any", "0.1", 0.04
        )

        self.assertEqual(activation_id, "hero-order")
        self.assertEqual(provider.current_order_meta["platform"], "herosms")
        self.assertEqual(provider.current_order_meta["key_index"], 1)
        self.assertTrue(provider.current_order_meta["key_fingerprint"])
        provider.cancel()
        self.assertEqual(
            [row["in_flight"] for row in registry.public_statuses()],
            [0, 0],
        )

    def test_multi_platform_balancing_and_same_order_resend(self):
        factory = FakeMultiPlatformFactory({
            ("smsbower", "bower-a"): {"balance": 1.0, "codes": [None, "654321"]},
            ("herosms", "hero-a"): {"balance": 1.0},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-a"]},
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-a"]},
            ]
        })
        first = PooledSmsProvider(registry)
        first.get_price_candidates()
        first.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
        first.set_ready()
        self.assertEqual(first.wait_code(timeout=1, interval=0), "654321")
        self.assertEqual(first.current_order_meta["platform"], "smsbower")
        self.assertEqual(
            len([call for call in factory.calls if call[0] == "wait"]),
            2,
        )
        self.assertEqual(
            len([call for call in factory.calls if call[0] == "ready" and call[1] == "smsbower"]),
            2,
        )
        first.complete()

        second = PooledSmsProvider(registry)
        second.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
        self.assertEqual(second.current_order_meta["platform"], "herosms")
        second.cancel()

    def test_sms_wait_uses_two_fixed_thirty_second_rounds_at_three_second_intervals(self):
        factory = FakeMultiPlatformFactory({
            ("smsbower", "bower-a"): {"balance": 1.0, "codes": [None, None]},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-a"]},
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        with self.assertRaisesRegex(RuntimeError, "sms_timeout"):
            provider.wait_code(timeout=30, interval=99)

        waits = [call for call in factory.calls if call[0] == "wait"]
        self.assertEqual([call[4:] for call in waits], [(30, 3), (30, 3)])
        self.assertEqual(len({call[3] for call in waits}), 1)

    def test_herosms_cancel_uses_documented_access_cancel_refund_ack(self):
        factory = FakeMultiPlatformFactory({
            ("herosms", "hero-a"): {
                "balance": 1.0,
                "cancel_response": "ACCESS_CANCEL",
                "cancel_status": "STATUS_CANCEL",
            },
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-a"]},
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        receipt = provider.cancel()

        self.assertEqual(receipt["cancel_state"], "confirmed")
        self.assertEqual(receipt["provider_response"], "ACCESS_CANCEL")
        self.assertEqual(receipt["provider_status"], "STATUS_CANCEL")
        self.assertEqual(receipt["refund_status"], "provider_refund_accepted")
        self.assertEqual(
            [call[3] for call in factory.calls if call[0] == "api"],
            ["setStatus", "getStatus"],
        )
        self.assertEqual(registry.public_statuses()[0]["in_flight"], 0)

    def test_herosms_early_cancel_is_retried_after_documented_minimum(self):
        responses = [
            {"title": "EARLY_CANCEL_DENIED", "info": {"minActivationTime": 120}},
            "ACCESS_CANCEL",
            "STATUS_CANCEL",
        ]
        calls = []
        clock = [0.0]
        sleeps = []

        def api(params):
            calls.append(dict(params))
            return responses.pop(0)

        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds

        receipt = confirm_herosms_cancellation(
            type("Provider", (), {"_api": staticmethod(api)})(),
            "hero-order-early",
            now_fn=lambda: clock[0],
            sleep_fn=sleep,
        )

        self.assertEqual(receipt["cancel_state"], "confirmed")
        self.assertEqual(receipt["refund_status"], "provider_refund_accepted")
        self.assertEqual(sleeps, [121.0])
        self.assertEqual(
            [call["action"] for call in calls],
            ["setStatus", "setStatus", "getStatus"],
        )

    def test_herosms_early_cancel_json_error_body_is_detected(self):
        responses = [
            '{"title":"EARLY_CANCEL_DENIED","info":{"minActivationTime":120}}',
            "ACCESS_CANCEL",
            "STATUS_CANCEL",
        ]
        clock = [0.0]

        def api(_params):
            return responses.pop(0)

        receipt = confirm_herosms_cancellation(
            type("Provider", (), {"_api": staticmethod(api)})(),
            "hero-order-json-error",
            now_fn=lambda: clock[0],
            sleep_fn=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )

        self.assertEqual(receipt["cancel_state"], "confirmed")
        self.assertEqual(receipt["refund_status"], "provider_refund_accepted")

    def test_herosms_early_cancel_defers_only_remaining_order_age(self):
        clock = [1060.0]

        with self.assertRaises(HeroSmsCancellationDeferred) as raised:
            confirm_herosms_cancellation(
                type(
                    "Provider",
                    (),
                    {
                        "_api": staticmethod(
                            lambda _params: {
                                "title": "EARLY_CANCEL_DENIED",
                                "info": {"minActivationTime": 120},
                            }
                        )
                    },
                )(),
                "hero-order-deferred",
                leased_at=1000.0,
                now_fn=lambda: clock[0],
                defer_early=True,
            )

        self.assertEqual(raised.exception.retry_after_seconds, 61.0)

    def test_herosms_cancel_remains_confirmed_when_status_reconciliation_races_cleanup(self):
        for cancel_status in ("NO_ACTIVATION", "STATUS_WAIT_CODE", RuntimeError("timeout")):
            with self.subTest(cancel_status=cancel_status):
                factory = FakeMultiPlatformFactory({
                    ("herosms", "hero-a"): {
                        "balance": 1.0,
                        "cancel_response": "ACCESS_CANCEL",
                        "cancel_status": cancel_status,
                    },
                })
                registry = SmsProviderRegistry(factory)
                registry.configure({
                    "sms_provider_pools": [
                        {"provider": "herosms", "enabled": True, "api_keys": ["hero-a"]},
                    ]
                })
                provider = PooledSmsProvider(registry)
                provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

                receipt = provider.cancel()

                self.assertEqual(receipt["cancel_state"], "confirmed")
                self.assertEqual(receipt["provider_response"], "ACCESS_CANCEL")
                self.assertEqual(receipt["refund_status"], "provider_refund_accepted")
                self.assertEqual(registry.public_statuses()[0]["in_flight"], 0)

    def test_herosms_cancel_rejection_is_not_reported_as_confirmed(self):
        factory = FakeMultiPlatformFactory({
            ("herosms", "hero-a"): {
                "balance": 1.0,
                "cancel_response": "BAD_STATUS",
            },
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-a"]},
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        with self.assertRaisesRegex(RuntimeError, "herosms_cancel_rejected:BAD_STATUS"):
            provider.cancel()

        self.assertEqual(provider.last_finish_receipt["cancel_state"], "error")
        self.assertEqual(registry.public_statuses()[0]["in_flight"], 0)
        with self.assertRaisesRegex(RuntimeError, "单平台尝试上限"):
            provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
        self.assertEqual(
            len([call for call in factory.calls if call[0] == "activate"]),
            1,
        )

    def test_herosms_cancel_error_disables_only_hero_for_the_current_task(self):
        factory = FakeMultiPlatformFactory({
            ("herosms", "hero-a"): {
                "balance": 1.0,
                "cancel_response": "BAD_STATUS",
            },
            ("smsbower", "bower-a"): {"balance": 1.0},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-a"]},
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-a"]},
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
        self.assertEqual(provider.current_order_meta["platform"], "herosms")
        with self.assertRaisesRegex(RuntimeError, "BAD_STATUS"):
            provider.cancel()

        provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        self.assertEqual(provider.current_order_meta["platform"], "smsbower")
        provider.cancel()
        provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
        self.assertEqual(provider.current_order_meta["platform"], "smsbower")
        provider.cancel()
        self.assertEqual(
            sum(
                call[0] == "activate" and call[1] == "herosms"
                for call in factory.calls
            ),
            1,
        )

    def test_multi_platform_attempt_limit_allows_fifteen_per_platform(self):
        platforms = ("smsbower", "herosms", "5sim")
        factory = FakeMultiPlatformFactory({
            (platform, f"{platform}-key"): {"balance": 1.0}
            for platform in platforms
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {
                    "provider": platform,
                    "enabled": True,
                    "api_keys": [f"{platform}-key"],
                }
                for platform in platforms
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.max_attempts_per_platform = 15

        for _index in range(45):
            provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
            provider.cancel()

        with self.assertRaisesRegex(RuntimeError, "单平台尝试上限"):
            provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        activation_calls = [call for call in factory.calls if call[0] == "activate"]
        self.assertEqual(len(activation_calls), 45)
        self.assertEqual(
            {platform: sum(call[1] == platform for call in activation_calls) for platform in platforms},
            {platform: 15 for platform in platforms},
        )

    def test_single_platform_multiple_keys_share_one_fifteen_attempt_budget(self):
        factory = FakeMultiPlatformFactory({
            ("herosms", "hero-a"): {"balance": 1.0},
            ("herosms", "hero-b"): {"balance": 1.0},
            ("5sim", "disabled-key"): {"balance": 1.0},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {
                    "provider": "herosms",
                    "enabled": True,
                    "api_keys": ["hero-a", "hero-b"],
                },
                {
                    "provider": "5sim",
                    "enabled": False,
                    "api_keys": ["disabled-key"],
                },
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.max_attempts_per_platform = 15

        for _index in range(15):
            provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
            provider.cancel()

        with self.assertRaisesRegex(RuntimeError, "单平台尝试上限"):
            provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        activation_calls = [call for call in factory.calls if call[0] == "activate"]
        self.assertEqual(len(activation_calls), 15)
        self.assertEqual(
            {key: sum(call[2] == key for call in activation_calls) for key in ("hero-a", "hero-b")},
            {"hero-a": 8, "hero-b": 7},
        )
        self.assertFalse(any(call[1] == "5sim" for call in activation_calls))
        self.assertEqual([row["in_flight"] for row in registry.public_statuses()], [0, 0, 0])

    def test_candidate_starting_platform_rotates_when_other_inventory_is_empty(self):
        factory = FakeMultiPlatformFactory({
            ("smsbower", "bower-a"): {"balance": 1.0},
            ("herosms", "hero-a"): {"balance": 1.0},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "smsbower", "enabled": True, "api_keys": ["bower-a"]},
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-a"]},
            ]
        })
        registry.candidates = [
            {
                "platform": "smsbower",
                "country": "151",
                "provider_id": "any",
                "price": 0.04,
                "count": 10,
            }
        ]

        orders = [
            [row["provider"] for row in registry._candidate_specs(
                country="151",
                provider_ids="any",
                price=0.04,
                platform="smsbower",
            )]
            for _attempt in range(4)
        ]

        self.assertEqual(
            orders,
            [
                ["smsbower", "herosms"],
                ["herosms", "smsbower"],
                ["smsbower", "herosms"],
                ["herosms", "smsbower"],
            ],
        )

    def test_task_attempt_budget_survives_provider_recreation(self):
        factory = FakeMultiPlatformFactory({
            ("herosms", "hero-a"): {"balance": 1.0},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "herosms", "enabled": True, "api_keys": ["hero-a"]},
            ]
        })

        for _session in range(3):
            provider = PooledSmsProvider(registry)
            provider.bind_task("T001-shared-budget")
            for _attempt in range(5):
                provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
                provider.cancel()

        recreated = PooledSmsProvider(registry)
        recreated.bind_task("T001-shared-budget")
        with self.assertRaisesRegex(RuntimeError, "单平台尝试上限"):
            recreated.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        other_task = PooledSmsProvider(registry)
        other_task.bind_task("T002-independent-budget")
        other_task.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
        other_task.cancel()

        activation_calls = [call for call in factory.calls if call[0] == "activate"]
        self.assertEqual(len(activation_calls), 16)

    def test_fivesim_reject_uses_official_ban_endpoint_and_releases_lease(self):
        factory = FakeMultiPlatformFactory({
            ("5sim", "five-key"): {"balance": 1.0},
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "5sim", "enabled": True, "api_keys": ["five-key"]},
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        provider.reject()

        self.assertIn(
            ("rest_get", "5sim", "five-key", "/user/ban/5sim-five-key-order"),
            factory.calls,
        )
        self.assertFalse(any(call[0] == "cancel" for call in factory.calls))
        self.assertEqual(registry.public_statuses()[0]["in_flight"], 0)

    def test_fivesim_ban_failure_falls_back_to_cancel_without_leaking_lease(self):
        factory = FakeMultiPlatformFactory({
            ("5sim", "five-key"): {
                "balance": 1.0,
                "rest_get": RuntimeError("network timeout"),
            },
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "5sim", "enabled": True, "api_keys": ["five-key"]},
            ]
        })
        provider = PooledSmsProvider(registry)
        provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)

        provider.reject()

        self.assertEqual(
            [call[0] for call in factory.calls if call[0] in {"rest_get", "cancel"}],
            ["rest_get", "cancel"],
        )
        self.assertEqual(registry.public_statuses()[0]["in_flight"], 0)

    def test_quality_pools_share_the_persisted_route_identity(self):
        @dataclass
        class Candidate:
            pool: str
            country: str = "151"
            provider_id: str = "any"

        quality_candidates = [
            Candidate("main"),
            Candidate("semi"),
            Candidate("preferred"),
            Candidate("explore"),
        ]
        cold = Candidate("main", country="37", provider_id="cold")
        ranked = rank_sms_candidates(
            [cold, *quality_candidates],
            {
                ("151", "any"): {"success": 8, "fail": 1},
            },
        )

        self.assertEqual(ranked[:4], quality_candidates)
        for candidate in quality_candidates:
            with self.subTest(pool=candidate.pool):
                self.assertEqual(_candidate_route(candidate), ("151", "any"))

        platform_candidate = {
            "platform": "smsbower",
            "pool": "main",
            "country": "151",
            "provider_id": "any",
        }
        self.assertEqual(
            _candidate_route(platform_candidate),
            ("151", "any"),
        )

    def test_preflight_reports_mixed_balances(self):
        factory = FakeFactory({
            "key-a": {"balance": 0.03, "prices": [{"price": 0.04, "count": 3}]},
            "key-b": {"balance": 1.25, "prices": [{"price": 0.04, "count": 3}]},
            "key-c": {"balance": RuntimeError("BAD_KEY")},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a", "key-b", "key-c"], min_price=0.01, max_price=0.10)
        statuses = pool.preflight()
        self.assertEqual([row["status"] for row in statuses], ["insufficient_balance", "usable", "invalid"])
        self.assertEqual(statuses[1]["balance_usd"], 1.25)
        self.assertNotIn("key-b", str(statuses))

    def test_preflight_detects_all_insufficient(self):
        factory = FakeFactory({
            "key-a": {"balance": 0.00, "prices": [{"price": 0.04, "count": 1}]},
            "key-b": {"balance": 0.01, "prices": [{"price": 0.04, "count": 1}]},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a", "key-b"], min_price=0.01, max_price=0.10)
        pool.preflight()
        self.assertTrue(pool.all_balance_insufficient())
        self.assertTrue(pool.is_exhausted())

    def test_preflight_checks_balances_in_parallel_and_prices_once(self):
        all_balances_started = threading.Event()
        prices_started = 0
        balances_started = 0
        lock = threading.Lock()

        class ParallelProvider(FakeSmsProvider):
            def get_price_candidates(inner_self, service="dr", countries=None):
                nonlocal prices_started
                with lock:
                    prices_started += 1
                return super().get_price_candidates(service=service, countries=countries)

            def balance(inner_self):
                nonlocal balances_started
                with lock:
                    balances_started += 1
                    if balances_started == 4:
                        all_balances_started.set()
                if not all_balances_started.wait(1):
                    raise RuntimeError("balance checks ran sequentially")
                return super().balance()

        class ParallelFactory(FakeFactory):
            def __call__(inner_self, key: str, proxy: str = "") -> ParallelProvider:
                return ParallelProvider(key, inner_self.scenarios[key], inner_self.calls)

        factory = ParallelFactory({
            "key-a": {"balance": 1.0},
            "key-b": {"balance": 1.0},
            "key-c": {"balance": 1.0},
            "key-d": {"balance": 1.0},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a", "key-b", "key-c", "key-d"])

        statuses = pool.preflight()

        self.assertTrue(all_balances_started.is_set())
        self.assertEqual(prices_started, 1)
        self.assertEqual([row["status"] for row in statuses], ["usable"] * 4)

    def test_preflight_price_failure_never_tries_a_third_healthy_key(self):
        price_keys: list[str] = []

        class PriceFallbackProvider(FakeSmsProvider):
            def get_price_candidates(inner_self, service="dr", countries=None):
                price_keys.append(inner_self.key)
                if inner_self.key in {"key-a", "key-b"}:
                    raise RuntimeError("temporary price failure")
                return super().get_price_candidates(service=service, countries=countries)

        class PriceFallbackFactory(FakeFactory):
            def __call__(inner_self, key: str, proxy: str = "") -> PriceFallbackProvider:
                return PriceFallbackProvider(key, inner_self.scenarios[key], inner_self.calls)

        keys = ["key-a", "key-b", "key-c"]
        pool = SmsKeyPool(PriceFallbackFactory({key: {"balance": 1.0} for key in keys}))
        pool.configure(keys)

        statuses = pool.preflight()

        self.assertEqual(price_keys, ["key-a", "key-b"])
        self.assertEqual([row["status"] for row in statuses], ["usable"] * 3)

    def test_reconfigured_preflight_does_not_price_removed_key(self):
        old_balance_started = threading.Event()
        release_old_balance = threading.Event()
        price_keys: list[str] = []

        class ReconfiguredProvider(FakeSmsProvider):
            def balance(inner_self):
                if inner_self.key == "old-key":
                    old_balance_started.set()
                    release_old_balance.wait(1)
                return super().balance()

            def get_price_candidates(inner_self, service="dr", countries=None):
                price_keys.append(inner_self.key)
                return super().get_price_candidates(service=service, countries=countries)

        class ReconfiguredFactory(FakeFactory):
            def __call__(inner_self, key: str, proxy: str = "") -> ReconfiguredProvider:
                return ReconfiguredProvider(key, inner_self.scenarios[key], inner_self.calls)

        factory = ReconfiguredFactory({"old-key": {"balance": 1.0}, "new-key": {"balance": 1.0}})
        pool = SmsKeyPool(factory)
        pool.configure(["old-key"])
        result: list[list[dict]] = []
        worker = threading.Thread(target=lambda: result.append(pool.preflight()))
        worker.start()
        self.assertTrue(old_balance_started.wait(1))

        pool.configure(["new-key"])
        release_old_balance.set()
        worker.join(1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(price_keys, [])
        self.assertEqual(result[0], pool.public_statuses())
        self.assertEqual(result[0][0]["status"], "unchecked")

    def test_preflight_caps_balance_concurrency_at_eight(self):
        eight_started = threading.Event()
        release_balances = threading.Event()
        lock = threading.Lock()
        started = 0
        active = 0
        peak_active = 0

        class BoundedProvider(FakeSmsProvider):
            def balance(inner_self):
                nonlocal started, active, peak_active
                with lock:
                    started += 1
                    active += 1
                    peak_active = max(peak_active, active)
                    if started == 8:
                        eight_started.set()
                release_balances.wait(1)
                try:
                    return super().balance()
                finally:
                    with lock:
                        active -= 1

        class BoundedFactory(FakeFactory):
            def __call__(inner_self, key: str, proxy: str = "") -> BoundedProvider:
                return BoundedProvider(key, inner_self.scenarios[key], inner_self.calls)

        keys = [f"key-{index}" for index in range(12)]
        pool = SmsKeyPool(BoundedFactory({key: {"balance": 1.0} for key in keys}))
        pool.configure(keys)
        worker = threading.Thread(target=pool.preflight)
        worker.start()
        self.assertTrue(eight_started.wait(1))

        with lock:
            self.assertEqual(started, 8)
            self.assertEqual(peak_active, 8)
        release_balances.set()
        worker.join(1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(started, 12)

    def test_stale_preflight_success_does_not_clear_newer_key_error(self):
        balance_started = threading.Event()
        release_balance = threading.Event()

        class DelayedBalanceProvider(FakeSmsProvider):
            def balance(inner_self):
                balance_started.set()
                release_balance.wait(1)
                return super().balance()

        class DelayedBalanceFactory(FakeFactory):
            def __call__(inner_self, key: str, proxy: str = "") -> DelayedBalanceProvider:
                return DelayedBalanceProvider(key, inner_self.scenarios[key], inner_self.calls)

        pool = SmsKeyPool(DelayedBalanceFactory({"key-a": {"balance": 1.0}}))
        pool.configure(["key-a"])
        worker = threading.Thread(target=pool.preflight)
        worker.start()
        self.assertTrue(balance_started.wait(1))

        pool.report_error(pool.states[0], RuntimeError("status=429 too many requests"))
        release_balance.set()
        worker.join(1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(pool.public_statuses()[0]["status"], "rate_limited")

    def test_older_preflight_cannot_write_after_newer_one_starts_during_pricing(self):
        price_started = threading.Event()
        release_price = threading.Event()
        balance_lock = threading.Lock()
        balance_calls = 0

        class InterleavedProvider(FakeSmsProvider):
            def balance(inner_self):
                nonlocal balance_calls
                with balance_lock:
                    balance_calls += 1
                    current = balance_calls
                if current == 2:
                    raise RuntimeError("BAD_KEY")
                return super().balance()

            def get_price_candidates(inner_self, service="dr", countries=None):
                price_started.set()
                release_price.wait(1)
                return super().get_price_candidates(service=service, countries=countries)

        class InterleavedFactory(FakeFactory):
            def __call__(inner_self, key: str, proxy: str = "") -> InterleavedProvider:
                return InterleavedProvider(key, inner_self.scenarios[key], inner_self.calls)

        pool = SmsKeyPool(InterleavedFactory({"key-a": {"balance": 1.0}}))
        pool.configure(["key-a"])
        older = threading.Thread(target=pool.preflight)
        older.start()
        self.assertTrue(price_started.wait(1))

        newer = threading.Thread(target=pool.preflight)
        newer.start()
        newer.join(1)
        self.assertFalse(newer.is_alive())
        release_price.set()
        older.join(1)

        self.assertFalse(older.is_alive())
        self.assertEqual(pool.public_statuses()[0]["status"], "invalid")

    def test_activation_stays_bound_to_its_key(self):
        factory = FakeFactory({
            "key-a": {"balance": 1.0},
            "key-b": {"balance": 1.0},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a", "key-b"])
        pool.preflight()
        first = PooledSmsBowerProvider(pool)
        second = PooledSmsBowerProvider(pool)

        first.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)
        second.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)
        first.wait_code()
        second.wait_code()
        first.complete()
        second.complete()

        activated_keys = [call[1] for call in factory.calls if call[0] == "activate"]
        self.assertEqual(activated_keys, ["key-a", "key-b"])
        for operation, key, activation in [call for call in factory.calls if call[0] in {"wait", "complete"}]:
            self.assertTrue(str(activation).endswith(key))
        self.assertEqual([row["in_flight"] for row in pool.public_statuses()], [0, 0])

    def test_five_active_orders_balance_across_two_keys(self):
        factory = FakeFactory({
            "key-a": {"balance": 1.0},
            "key-b": {"balance": 1.0},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a", "key-b"])
        providers = [PooledSmsBowerProvider(pool) for _ in range(5)]

        for provider in providers:
            provider.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)

        self.assertEqual(
            [provider.current_order_meta["key_index"] for provider in providers],
            [1, 2, 1, 2, 1],
        )
        self.assertEqual([row["in_flight"] for row in pool.public_statuses()], [3, 2])
        for provider in providers:
            provider.complete()
        self.assertEqual([row["in_flight"] for row in pool.public_statuses()], [0, 0])

    def test_older_success_does_not_clear_newer_key_cooldown(self):
        success_started = threading.Event()
        release_success = threading.Event()
        call_lock = threading.Lock()
        call_count = 0

        class RaceProvider:
            def get_available_countries(inner_self, service="dr"):
                nonlocal call_count
                with call_lock:
                    call_count += 1
                    current = call_count
                if current == 1:
                    success_started.set()
                    release_success.wait(1)
                    return {"151": "ok"}
                raise RuntimeError("status=429 too many requests")

        pool = SmsKeyPool(lambda key, proxy="": RaceProvider())
        pool.configure(["key-a"])
        results: list[object] = []
        errors: list[Exception] = []

        def query():
            try:
                results.append(pool.query("get_available_countries"))
            except Exception as exc:
                errors.append(exc)

        older = threading.Thread(target=query)
        newer = threading.Thread(target=query)
        older.start()
        self.assertTrue(success_started.wait(1))
        newer.start()
        newer.join(1)
        release_success.set()
        older.join(1)

        self.assertEqual(results, [{"151": "ok"}])
        self.assertEqual(len(errors), 1)
        status = pool.public_statuses()[0]
        self.assertEqual(status["status"], "rate_limited")
        self.assertGreater(status["retry_after_seconds"], 0)

    def test_activation_load_balances_across_all_healthy_keys(self):
        factory = FakeFactory({
            "key-a": {"balance": 1.0},
            "key-b": {"balance": 1.0},
            "key-c": {"balance": 1.0},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a", "key-b", "key-c"])
        pool.preflight()
        providers = [PooledSmsBowerProvider(pool) for _ in range(7)]

        for provider in providers:
            provider.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)

        self.assertEqual([row["in_flight"] for row in pool.public_statuses()], [3, 2, 2])
        self.assertEqual(
            [call[1] for call in factory.calls if call[0] == "activate"],
            ["key-a", "key-b", "key-c", "key-a", "key-b", "key-c", "key-a"],
        )
        for provider in providers:
            provider.complete()
        self.assertEqual([row["in_flight"] for row in pool.public_statuses()], [0, 0, 0])

    def test_runtime_balance_exhaustion_switches_key_and_alerts_once(self):
        factory = FakeFactory({
            "key-a": {"balance": 1.0, "activations": [RuntimeError("NO_BALANCE")]},
            "key-b": {
                "balance": 1.0,
                "activations": [("activation-key-b", "+1222"), RuntimeError("NO_BALANCE")],
            },
        })
        alerts: list[dict] = []
        exhausted: list[bool] = []
        pool = SmsKeyPool(factory)
        pool.configure(
            ["key-a", "key-b"],
            alert_fn=alerts.append,
            exhausted_fn=lambda: exhausted.append(True),
        )
        pool.preflight()

        provider = PooledSmsBowerProvider(pool)
        provider.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)
        self.assertEqual(provider.current_order_meta["key_index"], 2)
        provider.complete()

        with self.assertRaisesRegex(RuntimeError, "sms_balance_insufficient"):
            PooledSmsBowerProvider(pool).get_number_from_candidate("dr", "151", "1", "0.1", 0.04)
        self.assertEqual([alert["kind"] for alert in alerts], ["insufficient_balance", "insufficient_balance"])
        self.assertEqual(exhausted, [True])
        self.assertTrue(pool.is_exhausted())

    def test_factory_failure_releases_reservation(self):
        factory = FakeFactory({"key-a": {"factory_error": RuntimeError("network connection failed")}})
        pool = SmsKeyPool(factory)
        pool.configure(["key-a"])
        with self.assertRaisesRegex(RuntimeError, "temporarily_unavailable"):
            PooledSmsBowerProvider(pool).get_number_from_candidate("dr", "151", "1", "0.1", 0.04)
        self.assertEqual(pool.public_statuses()[0]["in_flight"], 0)

    def test_malformed_activation_releases_key_reservation(self):
        factory = FakeFactory({
            "key-a": {"balance": 1.0, "activations": [("only-one-field",)]},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a"])

        with self.assertRaisesRegex(RuntimeError, "sms_activation_invalid_response"):
            PooledSmsBowerProvider(pool).get_number_from_candidate("dr", "151", "1", "0.1", 0.04)

        self.assertEqual(pool.public_statuses()[0]["in_flight"], 0)
        self.assertEqual([call[0] for call in factory.calls], ["activate", "cancel"])

    def test_malformed_activation_cancel_failure_still_releases_reservation(self):
        class CancelFailureProvider(FakeSmsProvider):
            def cancel(inner_self):
                inner_self.calls.append(("cancel", inner_self.key, inner_self.activation_id))
                raise RuntimeError("network timeout")

        class CancelFailureFactory(FakeFactory):
            def __call__(inner_self, key: str, proxy: str = "") -> CancelFailureProvider:
                return CancelFailureProvider(key, inner_self.scenarios[key], inner_self.calls)

        factory = CancelFailureFactory({
            "key-a": {"balance": 1.0, "activations": [("only-one-field",)]},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a"])

        with self.assertRaisesRegex(RuntimeError, "sms_activation_invalid_response"):
            PooledSmsBowerProvider(pool).get_number_from_candidate("dr", "151", "1", "0.1", 0.04)

        self.assertEqual(pool.public_statuses()[0]["in_flight"], 0)
        self.assertEqual([call[0] for call in factory.calls], ["activate", "cancel"])

    def test_monitoring_callback_failures_do_not_leak_or_mask_key_failover(self):
        factory = FakeFactory({
            "key-a": {"balance": 1.0, "activations": [RuntimeError("NO_BALANCE")]},
            "key-b": {"balance": 1.0},
        })

        def fail_callback(*_args, **_kwargs):
            raise RuntimeError("monitor unavailable")

        pool = SmsKeyPool(factory)
        pool.configure(
            ["key-a", "key-b"],
            logger=fail_callback,
            alert_fn=fail_callback,
            exhausted_fn=fail_callback,
        )
        provider = PooledSmsBowerProvider(pool)

        provider.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)

        self.assertEqual(provider.current_order_meta["key_index"], 2)
        provider.complete()
        self.assertEqual([row["in_flight"] for row in pool.public_statuses()], [0, 0])

    def test_wait_error_releases_key_reservation_before_cancel_cleanup(self):
        factory = FakeFactory({
            "key-a": {"balance": 1.0, "code": RuntimeError("network timeout")},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a"])
        provider = PooledSmsBowerProvider(pool)
        peer = PooledSmsBowerProvider(pool)
        provider.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)
        peer.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)

        with self.assertRaisesRegex(RuntimeError, "network timeout"):
            provider.wait_code()

        self.assertEqual(pool.public_statuses()[0]["in_flight"], 1)
        provider.cancel()
        self.assertEqual(pool.public_statuses()[0]["in_flight"], 1)
        peer.cancel()
        self.assertEqual(pool.public_statuses()[0]["in_flight"], 0)
        self.assertEqual(
            [call[0] for call in factory.calls],
            ["activate", "activate", "wait", "cancel", "cancel"],
        )

    def test_set_ready_error_releases_key_reservation(self):
        factory = FakeFactory({
            "key-a": {"balance": 1.0, "ready": RuntimeError("network timeout")},
        })
        pool = SmsKeyPool(factory)
        pool.configure(["key-a"])
        provider = PooledSmsBowerProvider(pool)
        peer = PooledSmsBowerProvider(pool)
        provider.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)
        peer.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)

        with self.assertRaisesRegex(RuntimeError, "network timeout"):
            provider.set_ready()

        self.assertEqual(pool.public_statuses()[0]["in_flight"], 1)
        provider.cancel()
        self.assertEqual(pool.public_statuses()[0]["in_flight"], 1)
        peer.cancel()
        self.assertEqual(pool.public_statuses()[0]["in_flight"], 0)
        self.assertEqual(
            [call[0] for call in factory.calls],
            ["activate", "activate", "ready", "cancel", "cancel"],
        )

    def test_cost_ledger_counts_only_orders_that_received_codes(self):
        ledger = SmsCostLedger()
        ledger.record_lease("T001", FakeLease("paid", {"price_usd": 0.04, "key_index": 1}))
        ledger.record_lease("T001", FakeLease("unused", {"price_usd": 0.05, "key_index": 2}))
        ledger.mark_code_received("T001", "paid")
        summary = ledger.summary("T001", FakeExchange())
        self.assertEqual(summary["sms_cost_usd"], 0.04)
        self.assertEqual(summary["sms_cost_cny"], 0.29)
        self.assertEqual(summary["sms_exchange_rate"], 7.25)
        self.assertEqual(len(summary["sms_order_outcomes"]), 2)
        self.assertNotIn("paid", str(summary["sms_order_outcomes"]))

    def test_cost_ledger_persists_only_safe_cancel_receipt_fields(self):
        ledger = SmsCostLedger()
        ledger.record_lease("T001", FakeLease("hero-order", {"price_usd": 0.04}))
        ledger.mark_finished(
            "T001",
            "hero-order",
            "cancel_confirmed",
            "phone rejected",
            details={
                "cancel_state": "confirmed",
                "provider_response": "ACCESS_CANCEL",
                "provider_status": "STATUS_CANCEL",
                "refund_status": "provider_cancel_confirmed",
                "raw_response": "must-not-persist",
            },
        )

        outcome = ledger.summary("T001", FakeExchange())["sms_order_outcomes"][0]

        self.assertEqual(outcome["status"], "cancel_confirmed")
        self.assertEqual(outcome["cancel_receipt"]["provider_status"], "STATUS_CANCEL")
        self.assertNotIn("raw_response", str(outcome))
        self.assertNotIn("hero-order", str(outcome))

    def test_exchange_rate_uses_ecb_then_cache_and_fallback(self):
        xml = b"""<?xml version='1.0'?><Envelope><Cube><Cube time='2026-07-26'><Cube currency='USD' rate='1.2'/><Cube currency='CNY' rate='8.4'/></Cube></Cube></Envelope>"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rate.json"
            cache = ExchangeRateCache(path, fetcher=lambda: xml, now_fn=lambda: 1000)
            self.assertEqual(cache.get_rate()["rate"], 7.0)
            cached = ExchangeRateCache(path, fetcher=lambda: (_ for _ in ()).throw(RuntimeError()), now_fn=lambda: 1001)
            self.assertEqual(cached.get_rate()["source"], "cache")

            fallback = ExchangeRateCache(
                Path(directory) / "missing.json",
                fetcher=lambda: (_ for _ in ()).throw(RuntimeError()),
                now_fn=lambda: 1000,
            )
            self.assertEqual(fallback.get_rate()["rate"], 7.20)
            self.assertEqual(fallback.get_rate()["source"], "fallback")

    def test_route_policy_limits_and_cooldowns(self):
        @dataclass
        class Candidate:
            country: str = "151"
            provider_id: str = "3109"

        candidate = Candidate()
        clock = [1000.0]
        policy = SmsRoutePolicy(now_fn=lambda: clock[0])
        self.assertEqual(policy.route_limit({}), 1)
        self.assertEqual(policy.route_limit({"otp_sent": 1}), 1)
        self.assertEqual(policy.route_limit({"otp_received": 1}), 2)
        self.assertEqual(policy.route_limit({"success": 1}), 2)
        self.assertEqual(
            policy.cooldown_for(
                candidate,
                ok=False,
                kind="timeout",
                stat={"success": 0, "fail": 1, "timeout": 1},
            ),
            180,
        )
        policy.cooldown_for(candidate, ok=True, kind="success")
        self.assertEqual(
            policy.cooldown_for(
                candidate,
                ok=False,
                kind="timeout",
                stat={"success": 8, "fail": 3, "timeout": 3},
            ),
            180,
        )
        policy.cooldown_for(candidate, ok=True, kind="success")
        self.assertEqual(
            policy.cooldown_for(candidate, ok=False, kind="no_numbers"),
            60,
        )
        policy.cooldown_for(candidate, ok=True, kind="success")
        self.assertEqual(
            policy.cooldown_for(
                candidate,
                ok=False,
                kind="no_numbers",
                stat={"fail": 6, "no_numbers": 6, "no_numbers_streak": 3},
            ),
            180,
        )
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="phone_rejected", error="already been used"), 180)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="fail", error="suspicious similar number"), 180)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="transient_server"), 0)

    def test_no_number_streak_is_time_bounded_and_success_clears_it(self):
        @dataclass
        class Candidate:
            country: str = "151"
            provider_id: str = "3109"

        clock = [1000.0]
        policy = SmsRoutePolicy(now_fn=lambda: clock[0])
        candidate = Candidate()
        stat = {}

        stat = policy.update_stat_for_outcome(stat, ok=False, kind="no_numbers")
        self.assertEqual(stat["no_numbers_streak"], 1)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="no_numbers", stat=stat), 60)

        clock[0] = 1100.0
        stat = policy.update_stat_for_outcome(stat, ok=False, kind="no_numbers")
        self.assertEqual(stat["no_numbers_streak"], 2)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="no_numbers", stat=stat), 60)

        clock[0] = 3001.0
        stat = policy.update_stat_for_outcome(stat, ok=False, kind="no_numbers")
        self.assertEqual(stat["no_numbers_streak"], 1)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="no_numbers", stat=stat), 60)

        stat = policy.update_stat_for_outcome(stat, ok=True, kind="success")
        self.assertNotIn("no_numbers_streak", stat)
        self.assertNotIn("last_no_numbers_at", stat)

    def test_no_number_streak_accepts_epoch_zero_as_a_valid_timestamp(self):
        policy = SmsRoutePolicy(now_fn=lambda: 100.0)
        stat = policy.update_stat_for_outcome({}, ok=False, kind="no_numbers", now=0.0)
        stat = policy.update_stat_for_outcome(stat, ok=False, kind="no_numbers", now=100.0)
        self.assertEqual(stat["no_numbers_streak"], 2)

    def test_route_streaks_handle_out_of_order_failures_and_successes(self):
        policy = SmsRoutePolicy()
        cases = (
            ("no_numbers", "no_numbers_streak", "last_no_numbers_at"),
            ("no_code", "no_code_streak", "last_no_code_at"),
            ("other", "generic_failure_streak", "last_generic_failure_at"),
        )

        for kind, streak_name, timestamp_name in cases:
            with self.subTest(kind=kind):
                stat = policy.update_stat_for_outcome(
                    {}, ok=False, kind=kind, now=1000.0
                )
                stat = policy.update_stat_for_outcome(
                    stat, ok=False, kind=kind, now=1100.0
                )
                stale_failure = policy.update_stat_for_outcome(
                    stat, ok=False, kind=kind, now=1050.0
                )
                self.assertEqual(stale_failure[streak_name], 3)
                self.assertEqual(stale_failure[timestamp_name], 1100.0)

                far_older_failure = policy.update_stat_for_outcome(
                    stale_failure, ok=False, kind=kind, now=-1000.0
                )
                self.assertEqual(far_older_failure[streak_name], 3)
                self.assertEqual(far_older_failure[timestamp_name], 1100.0)

                stale_success = policy.update_stat_for_outcome(
                    far_older_failure, ok=True, kind="success", now=1050.0
                )
                self.assertEqual(stale_success[streak_name], 3)
                self.assertEqual(stale_success[timestamp_name], 1100.0)

                current_success = policy.update_stat_for_outcome(
                    stale_success, ok=True, kind="success", now=1200.0
                )
                current_success["last_success_at"] = 1200.0
                self.assertNotIn(streak_name, current_success)
                self.assertNotIn(timestamp_name, current_success)

                stale_after_success = policy.update_stat_for_outcome(
                    current_success, ok=False, kind=kind, now=1150.0
                )
                self.assertNotIn(streak_name, stale_after_success)
                self.assertNotIn(timestamp_name, stale_after_success)

    def test_concurrent_route_failures_keep_every_in_window_event(self):
        policy = SmsRoutePolicy(streak_window_seconds=1800.0)
        timestamps = [
            1000.0 + offset
            for offset in (90, 10, 80, 20, 70, 30, 60, 40, 50)
        ]
        barrier = threading.Barrier(len(timestamps))
        update_lock = threading.Lock()
        stat: dict[str, float | int] = {}

        def worker(observed_at: float) -> None:
            nonlocal stat
            barrier.wait()
            with update_lock:
                stat = policy.update_stat_for_outcome(
                    stat,
                    ok=False,
                    kind="no_numbers",
                    now=observed_at,
                )

        threads = [
            threading.Thread(target=worker, args=(observed_at,))
            for observed_at in timestamps
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(stat["no_numbers_streak"], len(timestamps))
        self.assertEqual(stat["last_no_numbers_at"], max(timestamps))

    def test_record_delivery_clears_failure_state_and_records_timestamp(self):
        clock = [1000.0]
        policy = SmsRoutePolicy(now_fn=lambda: clock[0])
        stat = {
            "otp_received": 2,
            "no_numbers_streak": 3,
            "no_code_streak": 2,
            "cooldown_until": 2000,
        }
        first = policy.record_delivery(stat)
        self.assertEqual(first["otp_received"], 3)
        self.assertEqual(first["last_delivery_at"], 1000.0)
        self.assertNotIn("no_numbers_streak", first)
        self.assertNotIn("no_code_streak", first)
        self.assertNotIn("cooldown_until", first)

    def test_record_delivery_preserves_newer_failure_and_monotonic_timestamp(self):
        policy = SmsRoutePolicy()
        stat = {
            "otp_received": 2,
            "last_delivery_at": 1000.0,
            "no_code_streak": 2,
            "last_no_code_at": 1200.0,
        }

        stale = policy.record_delivery(stat, now=1100.0)
        self.assertEqual(stale["last_delivery_at"], 1100.0)
        self.assertEqual(stale["no_code_streak"], 2)
        self.assertEqual(stale["last_no_code_at"], 1200.0)

        current = policy.record_delivery(stale, now=1300.0)
        stale_again = policy.record_delivery(current, now=1250.0)
        self.assertEqual(stale_again["last_delivery_at"], 1300.0)

    def test_candidate_ranking_prefers_proven_acceptance_over_static_priority(self):
        @dataclass
        class Candidate:
            country: str
            provider_id: str
            score: float = 1.0
            price: float = 0.04
            count: int = 10

        weak_priority = Candidate("151", "3109")
        proven = Candidate("37", "9999")
        cold_priority = Candidate("151", "3419")
        stats = {
            ("151", "3109"): {"success": 0, "fail": 8},
            ("37", "9999"): {"success": 4, "fail": 1},
        }

        ranked = rank_sms_candidates(
            [weak_priority, cold_priority, proven],
            stats,
            priority_routes=(("151", "3109"), ("151", "3419")),
            priority_countries=("151", "37"),
        )

        self.assertEqual(ranked, [proven, cold_priority, weak_priority])

    def test_candidate_ranking_accepts_serialized_route_keys(self):
        @dataclass
        class Candidate:
            country: str
            provider_id: str

        proven = Candidate("37", "3237")
        cold = Candidate("151", "3109")
        ranked = rank_sms_candidates(
            [cold, proven],
            {"37::3237": {"otp_received": 2, "fail": 0}},
            priority_routes=(("151", "3109"),),
        )
        self.assertEqual(ranked, [proven, cold])

    def test_candidate_ranking_does_not_treat_repeated_no_number_route_as_cold(self):
        @dataclass
        class Candidate:
            country: str
            provider_id: str

        unavailable = Candidate("37", "3309")
        cold = Candidate("151", "3109")
        ranked = rank_sms_candidates(
            [unavailable, cold],
            {("37", "3309"): {"fail": 24, "no_numbers": 24}},
        )
        self.assertEqual(ranked, [cold, unavailable])

    def test_candidate_ranking_prefers_recent_success_within_proven_tier(self):
        @dataclass
        class Candidate:
            country: str
            provider_id: str

        historical = Candidate("37", "3237")
        recent = Candidate("172", "3237")
        ranked = rank_sms_candidates(
            [historical, recent],
            {
                ("37", "3237"): {"success": 10, "fail": 5, "last_success_at": 100},
                ("172", "3237"): {"success": 4, "fail": 3, "last_success_at": 990},
            },
            now=1000,
            recent_success_window_seconds=300,
        )
        self.assertEqual(ranked, [recent, historical])

    def test_risk_retry_ranking_prefers_real_receipt_then_legacy_mature_routes(self):
        @dataclass
        class Candidate:
            country: str
            provider_id: str
            price: float = 0.04
            count: int = 10

        real_receipt = Candidate("1", "real")
        legacy_success = Candidate("2", "legacy")
        ordinary = Candidate("3", "ordinary")

        ranked = rank_sms_candidates(
            [ordinary, legacy_success, real_receipt],
            {
                ("1", "real"): {
                    "success": 2,
                    "fail": 1,
                    "otp_received": 1,
                    "last_delivery_at": 990,
                },
                ("2", "legacy"): {"success": 20, "fail": 0},
            },
            reliability_mode=True,
            now=1000,
        )

        self.assertEqual(ranked, [real_receipt, legacy_success, ordinary])

    def test_risk_retry_ranking_uses_recent_delivery_and_quality_within_tier(self):
        @dataclass
        class Candidate:
            country: str
            provider_id: str
            price: float = 0.04
            count: int = 10

        recent = Candidate("1", "recent")
        historical = Candidate("2", "historical")
        high_delivery = Candidate("3", "high-delivery")
        low_delivery = Candidate("4", "low-delivery")
        stats = {
            ("1", "recent"): {
                "success": 2,
                "fail": 2,
                "otp_received": 2,
                "timeout": 2,
                "last_delivery_at": 990,
            },
            ("2", "historical"): {
                "success": 10,
                "fail": 0,
                "otp_received": 10,
                "last_delivery_at": 100,
            },
            ("3", "high-delivery"): {
                "success": 4,
                "fail": 1,
                "otp_received": 8,
                "timeout": 2,
                "last_delivery_at": 980,
            },
            ("4", "low-delivery"): {
                "success": 9,
                "fail": 1,
                "otp_received": 2,
                "timeout": 8,
                "last_delivery_at": 980,
            },
        }

        ranked = rank_sms_candidates(
            [historical, low_delivery, recent, high_delivery],
            stats,
            reliability_mode=True,
            now=1000,
            recent_success_window_seconds=300,
        )

        self.assertLess(ranked.index(recent), ranked.index(historical))
        self.assertLess(ranked.index(high_delivery), ranked.index(low_delivery))

    def test_risk_retry_legacy_threshold_excludes_no_number_outcomes(self):
        @dataclass
        class Candidate:
            country: str
            provider_id: str

        mature = Candidate("1", "mature")
        below_threshold = Candidate("2", "weak")

        ranked = rank_sms_candidates(
            [below_threshold, mature],
            {
                ("1", "mature"): {
                    "success": 1,
                    "fail": 10,
                    "no_numbers": 9,
                },
                ("2", "weak"): {"success": 1, "fail": 10},
            },
            reliability_mode=True,
        )

        self.assertEqual(ranked, [mature, below_threshold])

    def test_risk_retry_without_mature_routes_preserves_normal_fallback_order(self):
        @dataclass
        class Candidate:
            country: str
            provider_id: str

        preferred = Candidate("151", "3109")
        cold = Candidate("37", "3237")
        failed = Candidate("172", "3309")
        candidates = [failed, cold, preferred]
        stats = {("172", "3309"): {"fail": 3}}
        kwargs = {
            "priority_routes": (("151", "3109"),),
            "priority_countries": ("151", "37"),
            "now": 1000,
        }

        normal = rank_sms_candidates(candidates, stats, **kwargs)
        risk_retry = rank_sms_candidates(
            candidates,
            stats,
            reliability_mode=True,
            **kwargs,
        )

        self.assertEqual(risk_retry, normal)

    def test_phone_submission_gate_spaces_requests(self):
        clock = [10.0]
        sleeps: list[float] = []
        waits: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock[0] += seconds

        gate = PhoneSubmissionGate(
            concurrency=2,
            interval_seconds=0.75,
            now_fn=lambda: clock[0],
            sleep_fn=sleep,
        )
        self.assertEqual(
            gate.call(lambda value: value, "first", on_wait=waits.append),
            "first",
        )
        self.assertEqual(
            gate.call(lambda value: value, "second", on_wait=waits.append),
            "second",
        )
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.75)
        self.assertEqual(waits, [0.0, 0.75])

    def test_phone_submission_gate_shares_exponential_backoff(self):
        clock = [0.0]
        sleeps: list[float] = []
        outcomes = [
            {"status": 503, "error": "busy"},
            {"status": 503, "error": "busy"},
            {"status": 503, "error": "busy"},
            {"status": 200},
        ]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock[0] += seconds

        gate = PhoneSubmissionGate(
            concurrency=2,
            interval_seconds=0,
            now_fn=lambda: clock[0],
            sleep_fn=sleep,
        )
        retries: list[tuple[float, int]] = []
        waits: list[float] = []

        result = gate.call_with_retries(
            lambda: outcomes.pop(0),
            is_transient=is_transient_openai_error,
            max_attempts=4,
            on_retry=lambda delay, attempt: retries.append((delay, attempt)),
            on_wait=waits.append,
        )

        self.assertEqual(result, {"status": 200})
        self.assertEqual(sleeps, [2.0, 4.0, 8.0])
        self.assertEqual(retries, [(2.0, 1), (4.0, 2), (8.0, 3)])
        self.assertEqual(waits, [0.0, 2.0, 4.0, 8.0])
        self.assertEqual(gate.transient_streak, 0)

    def test_phone_submission_wait_observer_never_changes_gate_outcome(self):
        gate = PhoneSubmissionGate(concurrency=1, interval_seconds=0)

        self.assertEqual(
            gate.call(
                lambda: "ok",
                on_wait=lambda _elapsed: (_ for _ in ()).throw(
                    RuntimeError("telemetry unavailable")
                ),
            ),
            "ok",
        )

        stopped = threading.Event()
        stopped.set()
        waits: list[float] = []
        with self.assertRaisesRegex(RuntimeError, "task_stopped"):
            gate.call(lambda: None, stop_event=stopped, on_wait=waits.append)
        self.assertEqual(len(waits), 1)
        self.assertEqual(gate.status(), {"active": 0, "limit": 1, "waiting": 0})

    def test_phone_submission_gate_begin_run_clears_shared_backoff(self):
        clock = [50.0]
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock[0] += seconds

        gate = PhoneSubmissionGate(
            concurrency=2,
            interval_seconds=0,
            now_fn=lambda: clock[0],
            sleep_fn=sleep,
        )
        self.assertEqual(gate.report_transient(), 2.0)
        self.assertEqual(gate.report_transient(), 4.0)

        gate.begin_run()

        self.assertEqual(gate.call(lambda: "ok"), "ok")
        self.assertEqual(sleeps, [])
        self.assertEqual(gate.report_transient(), 2.0)

    def test_phone_submission_gate_ignores_retry_monitor_failures(self):
        clock = [0.0]
        outcomes = [
            {"status": 503, "error": "busy"},
            {"status": 200},
        ]
        gate = PhoneSubmissionGate(
            concurrency=1,
            interval_seconds=0,
            now_fn=lambda: clock[0],
            sleep_fn=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )

        result = gate.call_with_retries(
            lambda: outcomes.pop(0),
            is_transient=is_transient_openai_error,
            on_retry=lambda *_args: (_ for _ in ()).throw(RuntimeError("monitor unavailable")),
        )

        self.assertEqual(result, {"status": 200})

    def test_singleflight_cache_deduplicates_and_negative_caches(self):
        clock = [0.0]
        cache = SingleFlightTtlCache(now_fn=lambda: clock[0])
        loader_started = threading.Event()
        release_loader = threading.Event()
        calls: list[str] = []
        results: list[tuple[tuple[str, str], ...]] = []

        def loader():
            calls.append("load")
            loader_started.set()
            release_loader.wait(1)
            return (("151", "3109"),)

        def read():
            results.append(
                cache.get_or_load("routes", loader, ttl_seconds=60, empty_ttl_seconds=15)
            )

        first = threading.Thread(target=read)
        second = threading.Thread(target=read)
        first.start()
        self.assertTrue(loader_started.wait(1))
        second.start()
        release_loader.set()
        first.join(1)
        second.join(1)

        self.assertEqual(calls, ["load"])
        self.assertEqual(results, [(("151", "3109"),), (("151", "3109"),)])

        empty_calls: list[bool] = []

        def empty_loader():
            empty_calls.append(True)
            return ()

        self.assertEqual(cache.get_or_load("empty", empty_loader, ttl_seconds=60, empty_ttl_seconds=15), ())
        self.assertEqual(cache.get_or_load("empty", empty_loader, ttl_seconds=60, empty_ttl_seconds=15), ())
        self.assertEqual(len(empty_calls), 1)
        clock[0] = 16
        self.assertEqual(cache.get_or_load("empty", empty_loader, ttl_seconds=60, empty_ttl_seconds=15), ())
        self.assertEqual(len(empty_calls), 2)

    def test_transient_openai_error_detection(self):
        self.assertTrue(is_transient_openai_error({"status": 503, "error": "busy"}))
        self.assertTrue(is_transient_openai_error(RuntimeError("service temporarily unavailable")))
        self.assertFalse(is_transient_openai_error({"status": 400, "error": "invalid phone"}))

    def test_provider_capabilities_resend_only_handler_api_platforms(self):
        for platform, expected_ready_calls in (
            ("smsbower", 2),
            ("herosms", 2),
            ("5sim", 1),
        ):
            with self.subTest(platform=platform):
                factory = FakeMultiPlatformFactory({
                    (platform, "key-a"): {
                        "balance": 1.0,
                        "codes": [None, "654321"],
                    }
                })
                registry = SmsProviderRegistry(factory)
                registry.configure({
                    "sms_provider_pools": [
                        {"provider": platform, "enabled": True, "api_keys": ["key-a"]}
                    ]
                })
                provider = PooledSmsProvider(registry)
                provider.get_number_from_candidate("dr", "151", "any", "0.1", 0.04)
                provider.set_ready()

                self.assertEqual(provider.wait_code(timeout=1), "654321")
                self.assertEqual(
                    len([call for call in factory.calls if call[0] == "ready"]),
                    expected_ready_calls,
                )
                self.assertEqual(
                    len({call[3] for call in factory.calls if call[0] == "wait"}),
                    1,
                )
                provider.complete()

    def test_transient_poll_network_error_retries_same_activation(self):
        factory = FakeMultiPlatformFactory({
            ("smsbower", "key-a"): {
                "balance": 1.0,
                "codes": [RuntimeError("TLS connection reset"), "123456"],
            }
        })
        registry = SmsProviderRegistry(factory)
        registry.configure({
            "sms_provider_pools": [
                {"provider": "smsbower", "enabled": True, "api_keys": ["key-a"]}
            ]
        })
        provider = PooledSmsProvider(registry)
        activation, _phone = provider.get_number_from_candidate(
            "dr", "151", "any", "0.1", 0.04
        )
        provider.set_ready()

        self.assertEqual(provider.wait_code(timeout=2), "123456")
        self.assertEqual(
            {call[3] for call in factory.calls if call[0] == "wait"},
            {activation},
        )
        self.assertEqual(registry.public_statuses()[0]["in_flight"], 1)
        provider.complete()

    def test_isolated_sms_get_never_inherits_environment_proxy(self):
        sessions = []

        class Session:
            def __init__(self):
                self.trust_env = True
                self.calls = []
                sessions.append(self)

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                return type("Response", (), {"text": " ACCESS_BALANCE:1 "})()

        self.assertEqual(
            isolated_sms_get(
                "https://sms.example.test",
                session_factory=Session,
            ),
            "ACCESS_BALANCE:1",
        )
        self.assertFalse(sessions[0].trust_env)
        self.assertNotIn("proxy", sessions[0].calls[0][1])

        isolated_sms_get(
            "https://sms.example.test",
            proxy="http://127.0.0.1:7897",
            session_factory=Session,
        )
        self.assertFalse(sessions[1].trust_env)
        self.assertEqual(
            sessions[1].calls[0][1]["proxy"],
            "http://127.0.0.1:7897",
        )

    def test_proxy_protocol_gate_limits_each_proxy_and_adapts(self):
        gate = ProxyProtocolGate(
            default_limit=3,
            restore_successes=2,
            launch_interval_seconds=0,
        )
        active = 0
        maximum = 0
        lock = threading.Lock()

        def worker():
            nonlocal active, maximum
            with gate.acquire("http://proxy-a:7897"):
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                time.sleep(0.01)
                with lock:
                    active -= 1

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(maximum, 3)

        events = []
        gate.report(
            "http://proxy-a:7897",
            "TLS connection reset",
            on_limit_change=events.append,
        )
        gate.report(
            "http://proxy-a:7897",
            "HTTP 429",
            on_limit_change=events.append,
        )
        self.assertEqual(gate.snapshot("http://proxy-a:7897")["limit"], 2)
        self.assertEqual(gate.snapshot("http://proxy-b:7897")["limit"], 3)
        gate.report(
            "http://proxy-a:7897",
            success=True,
            on_limit_change=events.append,
        )
        gate.report(
            "http://proxy-a:7897",
            success=True,
            on_limit_change=events.append,
        )
        self.assertEqual(gate.snapshot("http://proxy-a:7897")["limit"], 3)
        self.assertEqual(
            [(row["kind"], row["old_limit"], row["new_limit"]) for row in events],
            [("degraded", 3, 2), ("restored", 2, 3)],
        )
        self.assertNotIn("http://proxy-a:7897", str(events))

    def test_protocol_gate_observer_failures_do_not_change_limits_or_leak_slots(self):
        gate = ProxyProtocolGate(default_limit=5, launch_interval_seconds=0)
        raising = lambda _value: (_ for _ in ()).throw(
            RuntimeError("telemetry unavailable")
        )

        waits = []
        with gate.acquire("private-proxy", on_wait=waits.append):
            self.assertEqual(gate.snapshot("private-proxy")["active"], 1)
        self.assertEqual(len(waits), 1)
        self.assertEqual(gate.snapshot("private-proxy")["active"], 0)

        gate.report("private-proxy", "TLS connection reset")
        self.assertEqual(
            gate.report(
                "private-proxy",
                "HTTP 429",
                on_limit_change=raising,
            ),
            4,
        )

    def test_proxy_protocol_gate_keeps_pressure_events_across_success(self):
        clock = [100.0]
        gate = ProxyProtocolGate(
            default_limit=5,
            now_fn=lambda: clock[0],
            launch_interval_seconds=0,
        )

        gate.report("proxy-a", "TLS connection reset")
        clock[0] += 20
        gate.report("proxy-a", success=True)
        clock[0] += 20
        gate.report("proxy-a", "HTTP 429")

        self.assertEqual(gate.snapshot("proxy-a")["limit"], 4)

    def test_protocol_pressure_classifier_covers_common_disconnect_shapes(self):
        for error in (
            "curl: (56) recv failure",
            "remote end closed connection without response",
            "server disconnected",
            "SSLERROR during handshake",
        ):
            with self.subTest(error=error):
                self.assertTrue(is_protocol_pressure_error(error))

    def test_route_infrastructure_classifier_covers_raw_transport_and_429(self):
        for error in (
            RuntimeError("TLS handshake failed"),
            ConnectionError(),
            RuntimeError("ProxyError: tunnel failed"),
            RuntimeError("curl: (7) failed to connect"),
            {"_status": 429, "error": "provider throttled"},
            {"status_code": "429"},
            "HTTP/status 429",
            "status_code: 429",
            RuntimeError("HTTPError: 429 Client Error"),
            "too many requests",
        ):
            with self.subTest(error=error):
                self.assertTrue(is_sms_route_infrastructure_error(error))

        self.assertFalse(is_sms_route_infrastructure_error("sms_timeout: no code received"))
        self.assertFalse(is_protocol_pressure_error("sms_timeout: no code received"))

    def test_proxy_protocol_gate_fake_clock_launches_at_one_second_offsets(self):
        clock = [100.0]
        gate = ProxyProtocolGate(
            default_limit=5,
            now_fn=lambda: clock[0],
            launch_interval_seconds=1,
        )
        starts = []

        for offset in range(5):
            clock[0] = 100.0 + offset
            with gate.acquire("proxy-a"):
                starts.append(gate.states[gate.key("proxy-a")].last_started_at - 100.0)

        self.assertEqual(starts, [0.0, 1.0, 2.0, 3.0, 4.0])

    def test_proxy_protocol_gate_default_restores_only_after_six_successes(self):
        clock = [100.0]
        gate = ProxyProtocolGate(
            default_limit=5,
            now_fn=lambda: clock[0],
            launch_interval_seconds=0,
        )
        events = []
        gate.report(
            "proxy-a",
            "TLS connection reset",
            on_limit_change=events.append,
        )
        clock[0] += 30
        gate.report("proxy-a", "HTTP 429", on_limit_change=events.append)
        self.assertEqual(gate.snapshot("proxy-a")["limit"], 4)

        for _ in range(5):
            gate.report("proxy-a", success=True, on_limit_change=events.append)
        self.assertEqual(gate.snapshot("proxy-a")["limit"], 4)
        gate.report("proxy-a", success=True, on_limit_change=events.append)
        self.assertEqual(gate.snapshot("proxy-a")["limit"], 5)
        self.assertEqual(
            [(row["kind"], row["old_limit"], row["new_limit"]) for row in events],
            [("degraded", 5, 4), ("restored", 4, 5)],
        )

    def test_proxy_protocol_gate_staggers_launches_and_supports_stop(self):
        gate = ProxyProtocolGate(default_limit=5, launch_interval_seconds=0.03)
        starts: list[float] = []
        starts_lock = threading.Lock()

        def worker():
            with gate.acquire("proxy-a"):
                with starts_lock:
                    starts.append(time.monotonic())
                time.sleep(0.12)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        ordered = sorted(starts)
        self.assertEqual(len(ordered), 5)
        self.assertTrue(all(b - a >= 0.02 for a, b in zip(ordered, ordered[1:])))

        blocker = ProxyProtocolGate(default_limit=1, launch_interval_seconds=0)
        stopped = threading.Event()
        waiter_done = threading.Event()
        errors: list[str] = []
        stopped_waits: list[float] = []

        def waiter():
            try:
                with blocker.acquire(
                    "proxy-a",
                    stop_event=stopped,
                    on_wait=stopped_waits.append,
                ):
                    pass
            except RuntimeError as exc:
                errors.append(str(exc))
            finally:
                waiter_done.set()

        with blocker.acquire("proxy-a"):
            waiting_thread = threading.Thread(target=waiter)
            waiting_thread.start()
            deadline = time.monotonic() + 1
            while blocker.snapshot("proxy-a")["waiting"] < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            stopped.set()
            self.assertTrue(waiter_done.wait(1))
        waiting_thread.join()
        self.assertEqual(errors, ["task_stopped"])
        self.assertEqual(len(stopped_waits), 1)
        self.assertEqual(blocker.snapshot("proxy-a")["waiting"], 0)

    def test_cleanup_queue_resumes_after_recreation(self):
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cleanup.json"
            queue = SmsCleanupQueue(path, now_fn=lambda: clock[0])
            first_id = queue.enqueue(
                platform="smsbower",
                key_fingerprint="fingerprint-a",
                activation_id="private-order-a",
                delay_seconds=0,
            )
            queue.enqueue(
                platform="smsbower",
                key_fingerprint="fingerprint-a",
                activation_id="private-order-a",
                delay_seconds=0,
            )
            first = queue.process(lambda _entry: False)
            self.assertEqual(first["processed"], 1)
            self.assertEqual(first["remaining"], 1)
            pending_payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(len(pending_payload["pending"]), 1)
            self.assertEqual(pending_payload["confirmed"], [])

            clock[0] += 61
            resumed = SmsCleanupQueue(path, now_fn=lambda: clock[0])
            seen = []
            second = resumed.process(lambda entry: seen.append(entry["id"]) or True)
            self.assertEqual(seen, [first_id])
            self.assertEqual(second["remaining"], 0)
            confirmed_payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(confirmed_payload["pending"], [])
            self.assertEqual(len(confirmed_payload["confirmed"]), 1)
            self.assertEqual(
                confirmed_payload["confirmed"][0]["refund_status"],
                "provider_refund_accepted",
            )
            self.assertNotIn("private-order-a", str(confirmed_payload["confirmed"]))

    def test_sms_errors_never_expose_raw_keys(self):
        key = "secret/key+with-hyphen"
        encoded_key = urllib.parse.quote_plus(key, safe="")
        error = f"request failed: api_key={key}&encoded={encoded_key}"
        self.assertEqual(
            redact_sms_secrets(error, [key]),
            "request failed: api_key=********&encoded=********",
        )

        factory = FakeFactory({key: {"balance": RuntimeError(error)}})
        pool = SmsKeyPool(factory)
        pool.configure([key])
        status = pool.preflight()[0]
        self.assertNotIn(key, str(status))
        self.assertNotIn(encoded_key, str(status))

    def test_sms_redaction_does_not_expand_mask_placeholders(self):
        self.assertEqual(
            redact_sms_secrets(
                "masked=*** existing=******** key=real-secret",
                ["***", "********", "real-secret"],
            ),
            "masked=*** existing=******** key=********",
        )

    def test_reconfigured_pool_redacts_key_bound_to_an_old_active_order(self):
        old_key = "old/secret+key"
        encoded_key = urllib.parse.quote_plus(old_key, safe="")
        error = RuntimeError(f"request api_key={old_key}&encoded={encoded_key}")
        factory = FakeFactory(
            {
                old_key: {"balance": 1.0, "code": error},
                "new-key": {"balance": 1.0},
            }
        )
        pool = SmsKeyPool(factory)
        pool.configure([old_key])
        pool.preflight()
        provider = PooledSmsBowerProvider(pool)
        provider.get_number_from_candidate("dr", "151", "1", "0.1", 0.04)

        pool.configure(["new-key"])
        with self.assertRaises(RuntimeError) as raised:
            provider.wait_code()

        message = str(raised.exception)
        self.assertNotIn(old_key, message)
        self.assertNotIn(encoded_key, message)
        self.assertIn("********", message)

    def test_alert_buffer_deduplicates_per_run(self):
        alerts = RuntimeAlertBuffer()
        self.assertIsNotNone(alerts.add("balance", "low", dedupe_key="key-a:balance"))
        self.assertIsNone(alerts.add("balance", "low", dedupe_key="key-a:balance"))
        alerts.begin_run()
        self.assertIsNotNone(alerts.add("balance", "low", dedupe_key="key-a:balance"))


if __name__ == "__main__":
    unittest.main()
