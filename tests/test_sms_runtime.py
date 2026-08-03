from __future__ import annotations

from dataclasses import dataclass
import tempfile
import threading
from pathlib import Path
import unittest
import urllib.parse

from mac_overrides.sms_runtime import (
    ExchangeRateCache,
    PhoneSubmissionGate,
    PooledSmsBowerProvider,
    RuntimeAlertBuffer,
    SingleFlightTtlCache,
    SmsCostLedger,
    SmsKeyPool,
    SmsRoutePolicy,
    is_transient_openai_error,
    migrate_performance_config,
    normalize_sms_keys,
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
        self.assertEqual(migrated["phone_max_attempts"], 15)
        self.assertEqual(migrated["phone_session_cycle_seconds"], 480)
        self.assertEqual(migrated["auth_session_retries"], 1)

        upgraded, changed = migrate_performance_config({
            "performance_policy_version": 4,
            "phone_max_attempts": 0,
            "auth_session_retries": 0,
        })
        self.assertTrue(changed)
        self.assertEqual(upgraded["phone_max_attempts"], 15)
        self.assertEqual(upgraded["auth_session_retries"], 1)
        self.assertEqual(upgraded["performance_policy_version"], 5)

        saved, changed = migrate_performance_config({
            "performance_policy_version": 5,
            "phone_max_attempts": 0,
            "auth_session_retries": 0,
        })
        self.assertFalse(changed)
        self.assertEqual(saved["phone_max_attempts"], 0)
        self.assertEqual(saved["auth_session_retries"], 0)
        self.assertEqual(saved["phone_session_cycle_seconds"], 480)

        over_limit, changed = migrate_performance_config({
            "performance_policy_version": 5,
            "phone_max_attempts": 17,
        })
        self.assertFalse(changed)
        self.assertEqual(over_limit["phone_max_attempts"], 15)

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
        policy = SmsRoutePolicy()
        self.assertEqual(policy.route_limit({}), 1)
        self.assertEqual(policy.route_limit({"otp_sent": 1}), 2)
        self.assertEqual(policy.route_limit({"success": 1}), 2)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="timeout"), 0)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="timeout"), 300)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="phone_rejected", error="already been used"), 600)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="fail", error="suspicious similar number"), 1800)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="transient_server"), 0)

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

    def test_phone_submission_gate_spaces_requests(self):
        clock = [10.0]
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock[0] += seconds

        gate = PhoneSubmissionGate(
            concurrency=2,
            interval_seconds=0.75,
            now_fn=lambda: clock[0],
            sleep_fn=sleep,
        )
        self.assertEqual(gate.call(lambda value: value, "first"), "first")
        self.assertEqual(gate.call(lambda value: value, "second"), "second")
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.75)

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

        result = gate.call_with_retries(
            lambda: outcomes.pop(0),
            is_transient=is_transient_openai_error,
            max_attempts=4,
            on_retry=lambda delay, attempt: retries.append((delay, attempt)),
        )

        self.assertEqual(result, {"status": 200})
        self.assertEqual(sleeps, [2.0, 4.0, 8.0])
        self.assertEqual(retries, [(2.0, 1), (4.0, 2), (8.0, 3)])
        self.assertEqual(gate.transient_streak, 0)

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
