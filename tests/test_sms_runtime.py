from __future__ import annotations

from dataclasses import dataclass
import tempfile
from pathlib import Path
import unittest

from mac_overrides.sms_runtime import (
    ExchangeRateCache,
    PhoneSubmissionGate,
    PooledSmsBowerProvider,
    RuntimeAlertBuffer,
    SmsCostLedger,
    SmsKeyPool,
    SmsRoutePolicy,
    is_transient_openai_error,
    migrate_performance_config,
    normalize_sms_keys,
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
        self.assertEqual(migrated["phone_max_attempts"], 10)
        self.assertEqual(migrated["phone_session_cycle_seconds"], 480)
        self.assertEqual(migrated["auth_session_retries"], 1)

        upgraded, changed = migrate_performance_config({
            "performance_policy_version": 4,
            "phone_max_attempts": 0,
            "auth_session_retries": 0,
        })
        self.assertTrue(changed)
        self.assertEqual(upgraded["phone_max_attempts"], 10)
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
        self.assertEqual(policy.route_limit({"success": 1}), 2)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="timeout"), 0)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="timeout"), 300)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="phone_rejected", error="already been used"), 600)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="fail", error="suspicious similar number"), 1800)
        self.assertEqual(policy.cooldown_for(candidate, ok=False, kind="transient_server"), 0)

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

    def test_transient_openai_error_detection(self):
        self.assertTrue(is_transient_openai_error({"status": 503, "error": "busy"}))
        self.assertTrue(is_transient_openai_error(RuntimeError("service temporarily unavailable")))
        self.assertFalse(is_transient_openai_error({"status": 400, "error": "invalid phone"}))

    def test_sms_errors_never_expose_raw_keys(self):
        key = "secret-key-with-hyphen"
        error = f"request failed: https://sms.example.invalid?api_key={key}"
        self.assertEqual(
            redact_sms_secrets(error, [key]),
            "request failed: https://sms.example.invalid?api_key=********",
        )

        factory = FakeFactory({key: {"balance": RuntimeError(error)}})
        pool = SmsKeyPool(factory)
        pool.configure([key])
        status = pool.preflight()[0]
        self.assertNotIn(key, str(status))

    def test_alert_buffer_deduplicates_per_run(self):
        alerts = RuntimeAlertBuffer()
        self.assertIsNotNone(alerts.add("balance", "low", dedupe_key="key-a:balance"))
        self.assertIsNone(alerts.add("balance", "low", dedupe_key="key-a:balance"))
        alerts.begin_run()
        self.assertIsNotNone(alerts.add("balance", "low", dedupe_key="key-a:balance"))


if __name__ == "__main__":
    unittest.main()
