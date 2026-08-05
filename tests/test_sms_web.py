from __future__ import annotations

from types import SimpleNamespace
import threading
import unittest

from mac_overrides import sms_runtime
from mac_overrides.runtime_policy import ACCOUNT_BANNED_MESSAGE, AccountBannedError
from mac_overrides.sms_web import SmsWebIntegration


class FakeKeyPool:
    def __init__(self) -> None:
        self.configured = None
        self.statuses = [
            {"index": 1, "status": "usable", "message": "可用"},
            {"index": 2, "status": "insufficient_balance", "message": "余额不足"},
            {"index": 3, "status": "usable", "message": "可用"},
        ]

    def configure(self, keys, **kwargs):
        self.configured = (list(keys), dict(kwargs))

    def has_keys(self):
        return bool(self.configured and self.configured[0])

    def preflight(self, *, proxy=""):
        self.proxy = proxy
        return list(self.statuses)

    def safe_error(self, error):
        return str(error)


class FakeAlerts:
    def __init__(self) -> None:
        self.rows = []

    def add(self, kind, message, **kwargs):
        self.rows.append((kind, message, kwargs))


class FakeLogs:
    def __init__(self) -> None:
        self.rows = []

    def add(self, message, level="info"):
        self.rows.append((message, level))


class FakePhoneGate:
    def call_with_retries(self, function, *args, **kwargs):
        kwargs.pop("is_transient", None)
        kwargs.pop("max_attempts", None)
        kwargs.pop("on_retry", None)
        return function(*args, **kwargs)


class FakeCostLedger:
    def __init__(self):
        self.leases = []
        self.finished = []

    def record_lease(self, task_id, lease):
        self.leases.append((task_id, lease.activation_id))

    def mark_finished(self, task_id, activation_id, outcome, detail="", *, details=None):
        self.finished.append((task_id, activation_id, outcome, detail, details or {}))

    def mark_code_received(self, task_id, activation_id):
        self.received = getattr(self, "received", [])
        self.received.append((task_id, activation_id))


class FakeTaskProgress:
    def __init__(self):
        self.stages = []
        self.statuses = []

    def set_stage(self, task_id, stage):
        self.stages.append((task_id, stage))

    def observe_task_state(self, task_id, status):
        self.statuses.append((task_id, status))


class SmsWebTests(unittest.TestCase):
    def setUp(self):
        self.pool = FakeKeyPool()
        self.alerts = FakeAlerts()
        noop = SimpleNamespace()
        self.integration = SmsWebIntegration(
            sms_runtime=sms_runtime,
            original_create_provider=lambda name, key, proxy="": (name, key, proxy),
            original_build_candidates=lambda _selector, rows, *_args: rows,
            original_adapter_get_number=lambda *_args, **_kwargs: None,
            original_adapter_wait_code=lambda *_args, **_kwargs: None,
            original_adapter_complete=lambda *_args, **_kwargs: None,
            original_adapter_cancel=lambda *_args, **_kwargs: None,
            original_classify_error=lambda _error: "other",
            original_record_result=lambda *_args, **_kwargs: None,
            original_send_phone_otp=lambda *_args, **_kwargs: None,
            key_pool=self.pool,
            cost_ledger=noop,
            phone_gate=noop,
            route_policy=noop,
            alerts=self.alerts,
            task_progress=noop,
            priority_countries=("151", "37"),
            priority_routes=(("151", "3109"),),
            blocked_routes=(),
            min_price_default=0.01,
            max_price_default="0.1",
            sms_keys_from_config=lambda value: list(value.get("sms_api_keys") or []),
            as_enabled=lambda value, default=True: default if value is None else bool(value),
            safe_error=str,
        )

    def test_clamps_sms_price_to_supported_range(self):
        self.assertEqual(self.integration.clamp_max_price("0.075"), "0.075")
        self.assertEqual(self.integration.clamp_max_price("0.11"), "0.11")
        self.assertEqual(self.integration.clamp_max_price("0"), "0.1")
        self.assertEqual(self.integration.clamp_max_price("0.51"), "0.1")
        self.assertEqual(self.integration.clamp_max_price("bad"), "0.1")

    def test_smart_candidates_are_not_limited_to_priority_countries(self):
        selector = SimpleNamespace(config={"max_price": "0.1", "sms_min_price": "0.01"}, stats={})
        old_priority = SimpleNamespace(country="151", provider_id="3109", price=0.04, count=10, score=1.0)
        unrestricted = SimpleNamespace(country="999", provider_id="1001", price=0.05, count=8, score=1.0)

        ranked = self.integration.smart_build_candidates(
            selector,
            [unrestricted, old_priority],
            1000.0,
            None,
            None,
        )

        self.assertIn(unrestricted, ranked)
        self.assertIn(old_priority, ranked)

    def test_recovered_no_number_fallback_is_removed_while_route_is_cooled(self):
        candidate = SimpleNamespace(
            country="37",
            provider_id="3237",
            price=0.04,
            count=10,
            score=1.0,
            fallback=True,
            cooldown_until=1200.0,
        )
        selector = SimpleNamespace(
            config={"max_price": "0.1", "sms_min_price": "0.01"},
            stats={
                ("37", "3237"): {
                    "cooldown_until": 1200.0,
                    "last_kind": "no_numbers",
                }
            },
        )
        ranked = self.integration.smart_build_candidates(
            selector,
            [candidate],
            1000.0,
            None,
            None,
        )
        self.assertEqual(ranked, [])

    def test_configure_and_preflight_use_all_keys_without_key_count_special_cases(self):
        logs = FakeLogs()
        config = {
            "sms_api_keys": ["key-a", "key-b", "key-c"],
            "service": "dr",
            "sms_min_price": "0.02",
            "max_price": "0.08",
            "proxy": "http://127.0.0.1:7897",
            "proxy_scope": {"sms": True},
        }

        statuses = self.integration.preflight_pool(config, logs=logs)

        keys, options = self.pool.configured
        self.assertEqual(keys, ["key-a", "key-b", "key-c"])
        self.assertEqual(options["service"], "dr")
        self.assertEqual(options["min_price"], 0.02)
        self.assertEqual(options["max_price"], 0.08)
        self.assertEqual(self.pool.proxy, "http://127.0.0.1:7897")
        self.assertEqual(statuses, self.pool.statuses)
        self.assertEqual(self.alerts.rows[0][0], "sms_balance_insufficient")
        self.assertIn("Key 2", logs.rows[0][0])

    def test_transient_openai_errors_bypass_route_penalty(self):
        self.assertEqual(
            self.integration.classify_error("The server had an error processing your request"),
            "transient_server",
        )
        self.assertEqual(self.integration.classify_error("phone_otp_empty"), "timeout")
        self.assertEqual(self.integration.classify_error("permanent failure"), "other")

    def test_route_results_cool_unavailable_route_and_remember_success(self):
        logs = FakeLogs()
        candidate = SimpleNamespace(country="37", provider_id="3237")
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={},
            country_stats={},
            log_fn=logs.add,
            _route_inflight=lambda _row, _now: 0,
        )

        def update_shared(key, route_update, country_update):
            route_row = route_update(dict(selector.stats.get(key) or {}))
            country_row = country_update(dict(selector.country_stats.get(key[0]) or {}))
            return route_row, country_row

        selector._update_shared_route_and_country = update_shared

        def record_result(_selector, _candidate, ok, error=""):
            key = (_candidate.country, _candidate.provider_id)
            row = dict(_selector.stats.get(key) or {})
            if ok:
                row["success"] = int(row.get("success") or 0) + 1
                row.pop("cooldown_until", None)
            else:
                row["fail"] = int(row.get("fail") or 0) + 1
                if "no_numbers" in str(error):
                    row["no_numbers"] = int(row.get("no_numbers") or 0) + 1
            _selector.stats[key] = row

        self.integration.original_record_result = record_result
        self.integration.original_classify_error = (
            lambda error: "no_numbers" if "no_numbers" in str(error) else "other"
        )
        self.integration.route_policy = sms_runtime.SmsRoutePolicy()

        self.integration.smart_record_result(selector, candidate, False, "no_numbers")

        failed = selector.stats[("37", "3237")]
        self.assertEqual(failed["no_numbers"], 1)
        self.assertGreater(failed["cooldown_until"], 0)
        self.assertIn("当前无可用号码冷却 300 秒", logs.rows[-1][0])

        self.integration.smart_record_result(selector, candidate, True)

        succeeded = selector.stats[("37", "3237")]
        self.assertEqual(succeeded["success"], 1)
        self.assertGreater(succeeded["last_success_at"], 0)
        self.assertNotIn("cooldown_until", succeeded)

    def test_wait_flow_does_not_cool_route_until_code_wait_really_fails(self):
        logs = FakeLogs()
        candidate = SimpleNamespace(country="37", provider_id="3237")
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={},
            country_stats={},
            log_fn=logs.add,
            _route_inflight=lambda _row, _now: 0,
        )

        def update_shared(key, route_update, country_update):
            return (
                route_update(dict(selector.stats.get(key) or {})),
                country_update(dict(selector.country_stats.get(key[0]) or {})),
            )

        selector._update_shared_route_and_country = update_shared
        records = []

        def record_result(_selector, _candidate, ok, error=""):
            records.append((ok, error))
            key = (_candidate.country, _candidate.provider_id)
            row = dict(_selector.stats.get(key) or {})
            row["fail"] = int(row.get("fail") or 0) + 1
            row["timeout"] = int(row.get("timeout") or 0) + 1
            _selector.stats[key] = row

        def cancel(_adapter, active, reason=""):
            if not active.meta.get("ready_recorded"):
                self.integration.smart_record_result(selector, candidate, False, reason)

        self.integration.original_record_result = record_result
        self.integration.original_adapter_wait_code = lambda *_args, **_kwargs: None
        self.integration.original_adapter_cancel = cancel
        self.integration.route_policy = sms_runtime.SmsRoutePolicy()
        adapter = SimpleNamespace(
            config={},
            provider=SimpleNamespace(set_ready=lambda: None),
            selector=selector,
        )
        lease = SimpleNamespace(activation_id="order-1", meta={"candidate": candidate})

        self.integration.adapter_mark_ready(adapter, lease)
        self.assertEqual(records, [])
        self.assertNotIn("cooldown_until", selector.stats.get(("37", "3237"), {}))

        self.assertIsNone(self.integration.adapter_wait_code(adapter, lease, timeout=30))
        self.assertEqual(records, [])

        self.integration.adapter_cancel(adapter, lease, reason="phone_otp_empty")
        self.assertEqual(records, [(False, "phone_otp_empty")])
        self.assertGreater(selector.stats[("37", "3237")]["cooldown_until"], 0)
        self.assertIn("短信验证码未送达冷却 600 秒", logs.rows[-1][0])

    def test_received_code_updates_route_once_and_clears_failure_streak(self):
        candidate = SimpleNamespace(country="37", provider_id="3237")
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={
                ("37", "3237"): {
                    "no_numbers_streak": 2,
                    "no_code_streak": 2,
                    "cooldown_until": 9999999999,
                }
            },
            country_stats={},
            candidates=[candidate],
            raw_rows=[{"country": "37"}],
            last_refresh=123.0,
        )

        def update_shared(key, route_update, country_update):
            route_row = route_update(dict(selector.stats.get(key) or {}))
            country_row = country_update(dict(selector.country_stats.get(key[0]) or {}))
            return route_row, country_row

        selector._update_shared_route_and_country = update_shared
        self.integration.route_policy = sms_runtime.SmsRoutePolicy(now_fn=lambda: 1000.0)
        self.integration.original_adapter_wait_code = lambda *_args, **_kwargs: "123456"
        self.integration.cost_ledger = FakeCostLedger()
        self.integration.task_progress = FakeTaskProgress()
        adapter = SimpleNamespace(
            config={"sms_task_id": "task-delivery"},
            selector=selector,
        )
        lease = SimpleNamespace(
            activation_id="order-delivery",
            meta={"candidate": candidate},
        )

        self.assertEqual(self.integration.adapter_wait_code(adapter, lease, timeout=30), "123456")
        # A repeated poll/result callback must not count the same code twice.
        self.assertEqual(self.integration.adapter_wait_code(adapter, lease, timeout=30), "123456")

        row = selector.stats[("37", "3237")]
        self.assertEqual(row["otp_received"], 1)
        self.assertEqual(row["last_delivery_at"], 1000.0)
        self.assertNotIn("no_numbers_streak", row)
        self.assertNotIn("no_code_streak", row)
        self.assertNotIn("cooldown_until", row)
        self.assertEqual(selector.candidates, [candidate])
        self.assertEqual(selector.raw_rows, [{"country": "37"}])
        self.assertEqual(selector.last_refresh, 123.0)

    def test_explicit_account_ban_cancels_active_order_once_and_raises_terminal_signal(self):
        acquired = []
        cancelled = []
        logs = FakeLogs()
        ledger = FakeCostLedger()
        progress = FakeTaskProgress()
        candidate = SimpleNamespace(country="37", provider_id="3237")
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={("37", "3237"): {"inflight": 1}},
            country_stats={},
        )
        selector._update_shared_route_and_country = lambda key, route_update, country_update: (
            route_update(dict(selector.stats.get(key) or {})),
            country_update(dict(selector.country_stats.get(key[0]) or {})),
        )
        lease = SimpleNamespace(
            activation_id="order-1",
            phone="+15550001111",
            meta={"candidate": candidate},
        )
        adapter = SimpleNamespace(
            config={"sms_task_id": "task-1"},
            provider=SimpleNamespace(),
            selector=selector,
        )
        transport = SimpleNamespace(config={"sms_task_id": "task-1"}, log_fn=logs.add)

        def acquire(*_args, **_kwargs):
            acquired.append("order-1")
            return lease

        self.integration.original_adapter_get_number = acquire
        self.integration.original_adapter_cancel = (
            lambda _adapter, active, reason="": cancelled.append((active.activation_id, reason))
        )
        self.integration.original_send_phone_otp = lambda *_args: {
            "_status": 403,
            "error": {
                "code": "account_suspended",
                "message": "This account has been suspended.",
            },
        }
        self.integration.phone_gate = FakePhoneGate()
        self.integration.cost_ledger = ledger
        self.integration.task_progress = progress

        active = self.integration.adapter_get_number(adapter)
        with self.assertRaisesRegex(AccountBannedError, f"^{ACCOUNT_BANNED_MESSAGE}$"):
            self.integration.send_phone_number_otp(transport, active.phone)

        self.integration.adapter_cancel(adapter, active, reason="later cleanup")
        self.assertEqual(acquired, ["order-1"])
        self.assertEqual(cancelled, [("order-1", ACCOUNT_BANNED_MESSAGE)])
        self.assertTrue(lease.meta["ready_recorded"])
        self.assertEqual(progress.statuses, [("task-1", "account_banned")])
        self.assertEqual(logs.rows[-1], (ACCOUNT_BANNED_MESSAGE, "error"))
        self.assertIn("account_suspended", self.integration.pop_account_banned_detail("task-1"))
        self.assertEqual(len(ledger.finished), 1)
        self.assertEqual(selector.stats[("37", "3237")], {"inflight": 1})

    def test_generic_403_phone_rejection_is_returned_without_terminal_cancellation(self):
        cancelled = []
        transport = SimpleNamespace(config={"sms_task_id": "task-2"}, log_fn=None)
        self.integration.original_send_phone_otp = lambda *_args: {
            "_status": 403,
            "error": {"code": "phone_rejected", "message": "region restriction"},
        }
        self.integration.original_adapter_cancel = lambda *_args, **_kwargs: cancelled.append(True)
        self.integration.phone_gate = FakePhoneGate()

        result = self.integration.send_phone_number_otp(transport, "+15550002222")

        self.assertEqual(result["error"]["code"], "phone_rejected")
        self.assertEqual(cancelled, [])

    def test_phone_rejection_marks_pooled_provider_before_adapter_cancel(self):
        calls = []

        class Provider:
            def mark_rejected(self):
                calls.append("mark_rejected")

            def cancel(self):
                calls.append("cancel")

        provider = Provider()
        adapter = SimpleNamespace(config={}, provider=provider, selector=None)
        lease = SimpleNamespace(activation_id="order-1", meta={})

        def cancel(active_adapter, _lease, reason=""):
            calls.append(("reason", reason))
            active_adapter.provider.cancel()

        self.integration.original_adapter_cancel = cancel
        self.integration.original_classify_error = (
            lambda error: "phone_rejected" if "rejected" in str(error) else "other"
        )

        self.integration.adapter_cancel(adapter, lease, reason="phone rejected")

        self.assertEqual(calls, ["mark_rejected", ("reason", "phone rejected"), "cancel"])

    def test_cancel_ledger_uses_confirmed_provider_receipt(self):
        ledger = FakeCostLedger()
        provider = SimpleNamespace(
            last_finish_receipt={
                "cancel_state": "confirmed",
                "provider_response": "ACCESS_CANCEL",
                "provider_status": "STATUS_CANCEL",
                "refund_status": "provider_refund_accepted",
            }
        )
        adapter = SimpleNamespace(
            config={"sms_task_id": "task-hero"},
            provider=provider,
            selector=None,
        )
        lease = SimpleNamespace(activation_id="hero-order", meta={})
        self.integration.cost_ledger = ledger

        self.integration.adapter_cancel(adapter, lease, reason="phone_otp_empty")

        self.assertEqual(ledger.finished[0][2], "cancel_confirmed")
        self.assertEqual(ledger.finished[0][4]["provider_status"], "STATUS_CANCEL")

    def test_cancel_error_is_not_recorded_as_cancelled(self):
        ledger = FakeCostLedger()
        provider = SimpleNamespace(
            last_finish_receipt={
                "cancel_state": "error",
                "refund_status": "provider_cancel_not_confirmed",
            }
        )
        adapter = SimpleNamespace(
            config={"sms_task_id": "task-hero-error"},
            provider=provider,
            selector=None,
        )
        lease = SimpleNamespace(activation_id="hero-order-error", meta={})
        self.integration.cost_ledger = ledger
        self.integration.original_adapter_cancel = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("herosms_cancel_rejected:BAD_STATUS")
        )

        result = self.integration.adapter_cancel(adapter, lease, reason="phone_otp_empty")

        self.assertIsNone(result)
        self.assertEqual(ledger.finished[0][2], "cancel_error")
        self.assertIn("herosms_cancel_rejected:BAD_STATUS", ledger.finished[0][3])
        self.assertNotEqual(ledger.finished[0][2], "cancelled")


if __name__ == "__main__":
    unittest.main()
