from __future__ import annotations

from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch

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

    def query_balances(self, *, proxy="", update_state=True):
        self.query_options = {"proxy": proxy, "update_state": update_state}
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
        on_wait = kwargs.pop("on_wait", None)
        kwargs.pop("stop_event", None)
        if callable(on_wait):
            on_wait(0.25)
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
        self.segments = []

    def set_stage(self, task_id, stage):
        self.stages.append((task_id, stage))

    def observe_task_state(self, task_id, status):
        self.statuses.append((task_id, status))

    def record_segment(self, task_id, code, elapsed_seconds):
        self.segments.append((task_id, code, elapsed_seconds))


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
            max_price_default="0.15",
            sms_keys_from_config=lambda value: list(value.get("sms_api_keys") or []),
            as_enabled=lambda value, default=True: default if value is None else bool(value),
            safe_error=str,
        )

    def test_clamps_sms_price_to_supported_range(self):
        self.assertEqual(self.integration.clamp_max_price("0.075"), "0.075")
        self.assertEqual(self.integration.clamp_max_price("0.11"), "0.11")
        self.assertEqual(self.integration.clamp_max_price("0.18"), "0.18")
        self.assertEqual(self.integration.clamp_max_price("0"), "0.15")
        self.assertEqual(self.integration.clamp_max_price("0.1801"), "0.15")
        self.assertEqual(self.integration.clamp_max_price("0.51"), "0.15")
        self.assertEqual(self.integration.clamp_max_price("bad"), "0.15")

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

    def test_smart_candidates_pass_country_stats_and_quality_switch(self):
        selector = SimpleNamespace(
            config={
                "max_price": "0.1",
                "sms_min_price": "0.01",
                "sms_quality_optimization": False,
            },
            stats={},
            country_stats={"37": {"success": 8, "fail": 2}},
        )
        candidate = SimpleNamespace(
            country="37",
            provider_id="3237",
            price=0.04,
            count=10,
            score=1.0,
        )

        with patch.object(
            sms_runtime,
            "rank_sms_candidates",
            return_value=[candidate],
        ) as rank:
            result = self.integration.smart_build_candidates(
                selector,
                [candidate],
                1000.0,
                None,
                None,
            )

        self.assertEqual(result, [candidate])
        self.assertIs(rank.call_args.kwargs["country_stats"], selector.country_stats)
        self.assertFalse(rank.call_args.kwargs["quality_optimization"])

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

    def test_risk_retry_mode_reaches_ranking_after_price_and_cooldown_filters(self):
        eligible = SimpleNamespace(
            country="1",
            provider_id="eligible",
            price=0.04,
            count=8,
            score=1.0,
        )
        cooled = SimpleNamespace(
            country="2",
            provider_id="cooled",
            price=0.04,
            count=8,
            score=1.0,
        )
        overpriced = SimpleNamespace(
            country="3",
            provider_id="overpriced",
            price=0.20,
            count=8,
            score=1.0,
        )
        selector = SimpleNamespace(
            config={
                "_phone_risk_retry": True,
                "max_price": "0.10",
                "sms_min_price": "0.01",
            },
            stats={
                ("2", "cooled"): {
                    "cooldown_until": 1200.0,
                    "last_kind": "timeout",
                }
            },
        )

        with patch.object(
            sms_runtime,
            "rank_sms_candidates",
            return_value=[eligible],
        ) as rank:
            result = self.integration.smart_build_candidates(
                selector,
                [cooled, overpriced, eligible],
                1000.0,
                None,
                None,
            )

        self.assertEqual(result, [eligible])
        self.assertEqual(rank.call_args.args[0], [eligible])
        self.assertTrue(rank.call_args.kwargs["reliability_mode"])

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
        self.assertFalse(self.alerts.rows[0][2]["persistent"])
        self.assertIn("Key 2", logs.rows[0][0])

    def test_only_runtime_balance_alert_is_non_persistent(self):
        kinds = (
            "insufficient_balance",
            "sms_balance_insufficient",
            "invalid",
            "rate_limited",
            "network_error",
        )

        for index, kind in enumerate(kinds, start=1):
            self.integration.runtime_alert({
                "kind": kind,
                "provider": "sms-provider",
                "index": index,
                "fingerprint": f"fingerprint-{index}",
                "message": f"status-{kind}",
            })

        self.assertEqual([row[0] for row in self.alerts.rows], list(kinds))
        self.assertFalse(self.alerts.rows[0][2]["persistent"])
        self.assertFalse(self.alerts.rows[1][2]["persistent"])
        self.assertTrue(all(row[2]["persistent"] for row in self.alerts.rows[2:]))

    def test_balance_query_uses_an_isolated_registry_and_returns_no_raw_keys(self):
        secret = "query-secret/key"
        calls = []

        def create_provider(provider, key, proxy=""):
            calls.append((provider, key, proxy))
            return SimpleNamespace(balance=lambda: "ACCESS_BALANCE:1.75")

        self.integration.original_create_provider = create_provider
        statuses = self.integration.query_balances({
            "sms_provider_pools": [
                {"provider": "smsbower", "enabled": True, "api_keys": [secret]},
            ],
            "proxy": "http://127.0.0.1:7897",
            "proxy_scope": {"sms": True},
        })

        self.assertIsNone(self.pool.configured)
        self.assertEqual(calls, [("smsbower", secret, "http://127.0.0.1:7897")])
        self.assertEqual(statuses[0]["balance_usd"], 1.75)
        self.assertEqual(statuses[0]["status"], "usable")
        self.assertNotIn(secret, str(statuses))

    def test_runtime_balance_refresh_is_read_only_and_failure_is_advisory(self):
        self.pool.configure(["key-a"])
        self.integration._sms_proxy = "http://127.0.0.1:7897"

        statuses = self.integration.refresh_balances()

        self.assertEqual(statuses, self.pool.statuses)
        self.assertEqual(
            self.pool.query_options,
            {
                "proxy": "http://127.0.0.1:7897",
                "update_state": False,
            },
        )
        self.pool.query_balances = lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("provider unavailable")
        )
        self.assertEqual(self.integration.refresh_balances(), [])

    def test_transient_openai_errors_bypass_route_penalty(self):
        self.assertEqual(
            self.integration.classify_error("The server had an error processing your request"),
            "transient_server",
        )
        self.assertEqual(self.integration.classify_error("phone_otp_empty"), "timeout")
        self.assertEqual(
            self.integration.classify_error("auth_context_page_mismatch: stale page"),
            "auth_context",
        )
        self.assertEqual(
            self.integration.classify_error(
                "phone_channel_mismatch: requested=sms actual=whatsapp"
            ),
            "phone_rejected",
        )
        self.assertEqual(self.integration.classify_error("sms_timeout: no code"), "timeout")
        self.assertEqual(self.integration.classify_error("permanent failure"), "other")

    def test_auth_context_failure_releases_route_without_scoring_it(self):
        scored = []
        persisted_keys = []
        self.integration.original_record_result = lambda *args: scored.append(args)
        candidate = SimpleNamespace(
            platform="smsbower",
            pool="main",
            country="1",
            provider_id="101",
        )
        key = ("1", "101")
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={key: {"inflight": 1, "fail": 0}},
            country_stats={},
            _route_inflight=lambda _row, _now: 0,
        )

        def update_shared(route, route_update):
            persisted_keys.append(route)
            return route_update(dict(selector.stats.get(route) or {}))

        selector._update_shared_stats = update_shared

        self.integration.smart_record_result(
            selector,
            candidate,
            False,
            "auth_context_cookies_missing: session expired",
        )

        self.assertEqual(scored, [])
        self.assertEqual(persisted_keys, [key])
        self.assertNotIn("inflight", selector.stats[key])
        self.assertEqual(selector.stats[key]["fail"], 0)
        self.assertFalse(
            any(isinstance(route, tuple) and len(route) == 3 for route in selector.stats)
        )

    def test_session_and_network_failures_never_pollute_route_stats(self):
        errors = (
            "oauth_session_invalid: sign-in session is no longer valid",
            "The server had an error processing your request",
            "sms_provider_poll_failed: TLS connection reset",
            RuntimeError("TLS handshake failed"),
            ConnectionError("socket closed"),
            RuntimeError("ProxyError: proxy tunnel failed"),
            RuntimeError("curl: (56) recv failure"),
            "HTTP 429",
            "status=429",
            {"_status": 429, "error": "too many requests"},
            "too many requests",
        )
        for index, error in enumerate(errors):
            with self.subTest(error=error):
                key = ("37", "3237")
                persisted_keys = []
                selector = SimpleNamespace(
                    lock=threading.RLock(),
                    stats={key: {"inflight": 1, "fail": 4}},
                    country_stats={"37": {"fail": 4, "updated_at": 123.0}},
                    _route_inflight=lambda _row, _now: 0,
                )

                def update_shared(route, route_update):
                    persisted_keys.append(route)
                    return route_update(dict(selector.stats.get(route) or {}))

                selector._update_shared_stats = update_shared
                selector._update_shared_route_and_country = lambda *_args: self.fail(
                    "route-neutral release must not update country stats"
                )
                scored = []
                self.integration.original_record_result = lambda *args: scored.append(args)
                candidate = SimpleNamespace(
                    platform="smsbower",
                    pool=f"pool-{index}",
                    country="37",
                    provider_id="3237",
                )

                self.integration.smart_record_result(selector, candidate, False, error)

                self.assertEqual(scored, [])
                self.assertEqual(persisted_keys, [key])
                self.assertEqual(selector.stats[key]["fail"], 4)
                self.assertNotIn("inflight", selector.stats[key])
                self.assertNotIn("cooldown_until", selector.stats[key])
                self.assertEqual(
                    selector.country_stats["37"],
                    {"fail": 4, "updated_at": 123.0},
                )

    def test_phone_context_preflight_runs_before_paid_number_allocation(self):
        calls = []
        self.integration.phone_context_preflight = (
            lambda _adapter, task_id: calls.append(("preflight", task_id))
        )
        self.integration.original_adapter_get_number = (
            lambda *_args, **_kwargs: calls.append(("allocate", "task-phone"))
            or SimpleNamespace(activation_id="order-1", meta={})
        )
        self.integration.cost_ledger = FakeCostLedger()
        self.integration.task_progress = FakeTaskProgress()
        adapter = SimpleNamespace(
            config={"sms_task_id": "task-phone"},
            provider=SimpleNamespace(current_order_meta={}),
            selector=None,
        )

        self.integration.adapter_get_number(adapter)

        self.assertEqual(
            calls,
            [("preflight", "task-phone"), ("allocate", "task-phone")],
        )

    def test_phone_context_recovery_failure_never_allocates_number(self):
        allocations = []

        def fail_preflight(_adapter, _task_id):
            raise RuntimeError("auth_context_page_mismatch")

        self.integration.phone_context_preflight = fail_preflight
        self.integration.original_adapter_get_number = (
            lambda *_args, **_kwargs: allocations.append(True)
        )
        adapter = SimpleNamespace(
            config={"sms_task_id": "task-phone"},
            provider=SimpleNamespace(),
            selector=None,
        )

        with self.assertRaisesRegex(RuntimeError, "auth_context_page_mismatch"):
            self.integration.adapter_get_number(adapter)

        self.assertEqual(allocations, [])

    def test_provider_poll_failure_releases_route_without_delivery_penalty(self):
        candidate = SimpleNamespace(
            platform="herosms",
            pool="explore",
            country="37",
            provider_id="3237",
        )
        key = ("37", "3237")
        persisted_keys = []
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={key: {"inflight": 1}},
            country_stats={},
            _route_inflight=lambda row, _now: int(row.get("inflight") or 0),
        )

        def update_shared(route, route_update):
            persisted_keys.append(route)
            return route_update(dict(selector.stats.get(route) or {}))

        selector._update_shared_stats = update_shared
        scored = []
        self.integration.original_record_result = (
            lambda *_args, **_kwargs: scored.append(True)
        )

        self.integration.smart_record_result(
            selector,
            candidate,
            False,
            "sms_provider_poll_failed: TLS connection reset",
        )

        self.assertEqual(scored, [])
        self.assertEqual(persisted_keys, [key])
        self.assertNotIn("inflight", selector.stats[key])
        self.assertNotIn("cooldown_until", selector.stats[key])
        self.assertFalse(
            any(isinstance(route, tuple) and len(route) == 3 for route in selector.stats)
        )

    def test_route_results_cool_unavailable_route_and_remember_success(self):
        logs = FakeLogs()
        candidate = SimpleNamespace(
            platform="smsbower",
            pool="preferred",
            country="37",
            provider_id="3237",
        )
        persisted_keys = []
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={},
            country_stats={},
            log_fn=logs.add,
            _route_inflight=lambda _row, _now: 0,
        )

        def update_shared(key, route_update):
            persisted_keys.append(key)
            return route_update(dict(selector.stats.get(key) or {}))

        selector._update_shared_stats = update_shared

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
        self.assertIn("当前无可用号码冷却 60 秒", logs.rows[-1][0])

        self.integration.smart_record_result(selector, candidate, True)

        succeeded = selector.stats[("37", "3237")]
        self.assertEqual(succeeded["success"], 1)
        self.assertGreater(succeeded["last_success_at"], 0)
        self.assertNotIn("cooldown_until", succeeded)
        self.assertTrue(persisted_keys)
        self.assertTrue(all(key == ("37", "3237") for key in persisted_keys))
        self.assertFalse(
            any(isinstance(key, tuple) and len(key) == 3 for key in selector.stats)
        )

    def test_success_timestamp_does_not_regress_when_callbacks_finish_out_of_order(self):
        clock = [1200.0]
        candidate = SimpleNamespace(country="37", provider_id="3237")
        key = ("37", "3237")
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={key: {}},
            country_stats={"37": {"updated_at": 900.0}},
            _route_inflight=lambda _row, _now: 0,
        )
        selector._update_shared_stats = lambda route, update: update(
            dict(selector.stats.get(route) or {})
        )

        def record_result(_selector, _candidate, ok, _error=""):
            row = dict(_selector.stats.get(key) or {})
            row["success"] = int(row.get("success") or 0) + int(bool(ok))
            _selector.stats[key] = row

        self.integration.original_record_result = record_result
        self.integration.route_policy = sms_runtime.SmsRoutePolicy(now_fn=lambda: clock[0])

        self.integration.smart_record_result(selector, candidate, True)
        clock[0] = 1100.0
        self.integration.smart_record_result(selector, candidate, True)

        self.assertEqual(selector.stats[key]["last_success_at"], 1200.0)
        self.assertEqual(selector.country_stats["37"]["updated_at"], 900.0)

    def test_result_timestamp_is_captured_before_persistence_wait(self):
        clock = [100.0]
        candidate = SimpleNamespace(country="37", provider_id="3237")
        key = ("37", "3237")
        selector = SimpleNamespace(
            lock=threading.RLock(),
            stats={key: {}},
            country_stats={},
            _route_inflight=lambda _row, _now: 0,
        )
        selector._update_shared_stats = lambda route, update: update(
            dict(selector.stats.get(route) or {})
        )

        def delayed_record_result(_selector, _candidate, _ok, _error=""):
            clock[0] = 300.0

        self.integration.original_record_result = delayed_record_result
        self.integration.route_policy = sms_runtime.SmsRoutePolicy(now_fn=lambda: clock[0])

        self.integration.smart_record_result(selector, candidate, True)

        self.assertEqual(selector.stats[key]["last_success_at"], 100.0)

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

        def update_shared(key, route_update):
            return route_update(dict(selector.stats.get(key) or {}))

        selector._update_shared_stats = update_shared
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
        self.assertIn("短信验证码未送达冷却 180 秒", logs.rows[-1][0])

    def test_phone_gate_and_provider_ready_record_segments_without_changing_results(self):
        progress = FakeTaskProgress()
        self.integration.task_progress = progress
        self.integration.phone_gate = FakePhoneGate()
        self.integration.original_send_phone_otp = lambda *_args: {"_status": 200}
        transport = SimpleNamespace(config={"sms_task_id": "task-timing"}, log_fn=None)

        result = self.integration.send_phone_number_otp(
            transport,
            "+15550001234",
        )

        self.assertEqual(result["_status"], 200)
        self.assertEqual(
            progress.segments[0],
            ("task-timing", "phone_slot_waiting", 0.25),
        )

        adapter = SimpleNamespace(
            config={"sms_task_id": "task-timing"},
            provider=SimpleNamespace(set_ready=lambda: None),
        )
        lease = SimpleNamespace(activation_id="order-timing", meta={})
        self.integration.adapter_mark_ready(adapter, lease)
        self.assertEqual(progress.segments[1][0:2], ("task-timing", "sms_provider_ready"))
        self.assertGreaterEqual(progress.segments[1][2], 0)

        adapter.provider = SimpleNamespace(
            set_ready=lambda: (_ for _ in ()).throw(RuntimeError("ready failed"))
        )
        with self.assertRaisesRegex(RuntimeError, "ready failed"):
            self.integration.adapter_mark_ready(adapter, lease)
        self.assertEqual(progress.segments[2][0:2], ("task-timing", "sms_provider_ready"))

    def test_segment_recorder_failure_never_masks_phone_result(self):
        self.integration.phone_gate = FakePhoneGate()
        self.integration.original_send_phone_otp = lambda *_args: {"_status": 200}
        self.integration.task_progress = SimpleNamespace(
            record_segment=lambda *_args: (_ for _ in ()).throw(
                RuntimeError("telemetry unavailable")
            )
        )

        result = self.integration.send_phone_number_otp(
            SimpleNamespace(config={"sms_task_id": "task-safe"}, log_fn=None),
            "+15550001234",
        )

        self.assertEqual(result["_status"], 200)

    def test_sms_timeout_returns_no_code_so_next_loop_can_allocate_new_phone(self):
        allocations = []
        cancellations = []

        def allocate(_adapter, **_kwargs):
            phone = f"phone-{len(allocations) + 1}"
            allocations.append(phone)
            return SimpleNamespace(
                activation_id=f"order-{len(allocations)}",
                phone=phone,
                meta={},
            )

        self.integration.original_adapter_get_number = allocate
        self.integration.original_adapter_wait_code = (
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("sms_timeout: 两轮短信等待结束后仍未收到验证码")
            )
        )
        self.integration.original_adapter_cancel = (
            lambda _adapter, _lease, reason="": cancellations.append(reason)
        )
        adapter = SimpleNamespace(
            config={},
            provider=SimpleNamespace(current_order_meta={}),
            selector=None,
        )

        first = self.integration.adapter_get_number(adapter)
        self.assertIsNone(self.integration.adapter_wait_code(adapter, first, timeout=30))
        self.integration.adapter_cancel(adapter, first, reason="phone_otp_empty")
        second = self.integration.adapter_get_number(adapter)

        self.assertEqual(allocations, ["phone-1", "phone-2"])
        self.assertEqual(cancellations, ["sms_timeout"])
        self.assertNotEqual(first.phone, second.phone)
        self.assertEqual(first.meta["sms_wait_failure"], "sms_timeout")

    def test_degraded_route_wait_plan_uses_mature_alternative(self):
        current = SimpleNamespace(country="1", provider_id="weak")
        alternative = SimpleNamespace(country="2", provider_id="mature")
        configured = []
        selector = SimpleNamespace(
            lock=threading.RLock(),
            config={"sms_quality_optimization": True},
            stats={
                ("1", "weak"): {"no_code_streak": 2, "timeout": 3},
                ("2", "mature"): {"otp_received": 7, "timeout": 2},
            },
            candidates=[current, alternative],
            raw_rows=[],
            last_refresh=1.0,
        )
        adapter = SimpleNamespace(
            config={},
            selector=selector,
            provider=SimpleNamespace(configure_wait_plan=configured.append),
        )
        lease = SimpleNamespace(
            activation_id="order-adaptive",
            meta={"candidate": current},
        )

        self.assertIsNone(self.integration.adapter_wait_code(adapter, lease))

        self.assertEqual(len(configured), 1)
        self.assertEqual(configured[0].first_seconds, 40)
        self.assertEqual(configured[0].second_seconds, 20)
        self.assertTrue(configured[0].early_switch)
        self.assertEqual(
            lease.meta["adaptive_wait_plan"],
            {"first_seconds": 40, "second_seconds": 20, "early_switch": True},
        )

    def test_rollback_guard_blocks_early_switch_for_an_inflight_wait(self):
        current = SimpleNamespace(country="1", provider_id="weak")
        alternative = SimpleNamespace(country="2", provider_id="mature")
        switch_checks = []
        guard_enabled = [True]
        self.integration.optimization_guard = SimpleNamespace(
            is_enabled=lambda configured: configured and guard_enabled[0]
        )
        selector = SimpleNamespace(
            lock=threading.RLock(),
            config={"sms_quality_optimization": True},
            stats={
                ("1", "weak"): {"no_code_streak": 2, "timeout": 3},
                ("2", "mature"): {"otp_received": 7, "timeout": 2},
            },
            candidates=[current, alternative],
            raw_rows=[],
            last_refresh=1.0,
        )
        adapter = SimpleNamespace(
            config={},
            selector=selector,
            provider=SimpleNamespace(
                configure_wait_plan=lambda _plan: None,
                configure_early_switch_check=switch_checks.append,
            ),
        )
        lease = SimpleNamespace(activation_id="order-inflight", meta={"candidate": current})

        with patch.object(
            sms_runtime,
            "has_better_mature_alternative",
            return_value=True,
        ):
            self.integration.adapter_wait_code(adapter, lease)
            self.assertEqual(len(switch_checks), 1)
            self.assertTrue(switch_checks[0]())

        guard_enabled[0] = False
        self.assertFalse(switch_checks[0]())

    def test_quality_switch_disables_adaptive_wait(self):
        current = SimpleNamespace(country="1", provider_id="weak")
        configured = []
        selector = SimpleNamespace(
            lock=threading.RLock(),
            config={"sms_quality_optimization": True},
            stats={("1", "weak"): {"no_code_streak": 5}},
            candidates=[current],
            raw_rows=[],
            last_refresh=1.0,
        )
        adapter = SimpleNamespace(
            config={"sms_quality_optimization": False},
            selector=selector,
            provider=SimpleNamespace(configure_wait_plan=configured.append),
        )
        lease = SimpleNamespace(
            activation_id="order-disabled",
            meta={"candidate": current},
        )

        self.assertIsNone(self.integration.adapter_wait_code(adapter, lease))

        self.assertEqual(configured, [])
        self.assertNotIn("adaptive_wait_plan", lease.meta)

    def test_received_code_updates_route_once_and_clears_failure_streak(self):
        candidate = SimpleNamespace(
            platform="herosms",
            pool="semi",
            country="37",
            provider_id="3237",
        )
        persisted_keys = []
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

        def update_shared(key, route_update):
            persisted_keys.append(key)
            return route_update(dict(selector.stats.get(key) or {}))

        selector._update_shared_stats = update_shared
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
        self.assertEqual(persisted_keys, [("37", "3237")])
        self.assertFalse(
            any(isinstance(key, tuple) and len(key) == 3 for key in selector.stats)
        )
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
        selector._update_shared_stats = lambda key, route_update: (
            route_update(dict(selector.stats.get(key) or {}))
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

        self.assertEqual(ledger.finished[0][2], "cancelled")
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
        self.assertEqual(ledger.finished[0][2], "cancel_failed")
        self.assertIn("herosms_cancel_rejected:BAD_STATUS", ledger.finished[0][3])
        self.assertNotEqual(ledger.finished[0][2], "cancelled")

    def test_herosms_deferred_cancel_is_queued_without_blocking_or_false_refund(self):
        captured = []

        class CleanupQueue:
            def enqueue(self, **kwargs):
                captured.append(kwargs)
                return "cleanup-entry"

        ledger = FakeCostLedger()
        provider = SimpleNamespace(
            current_order_meta={
                "platform": "herosms",
                "key_fingerprint": "fingerprint-a",
                "leased_at": 1000.0,
            },
            last_finish_receipt={
                "cancel_state": "error",
                "refund_status": "provider_cancel_not_confirmed",
            },
        )
        adapter = SimpleNamespace(
            config={"sms_task_id": "task-hero-pending"},
            provider=provider,
            selector=None,
        )
        lease = SimpleNamespace(
            activation_id="hero-order-pending",
            meta=dict(provider.current_order_meta),
        )
        self.integration.cleanup_queue = CleanupQueue()
        self.integration.cost_ledger = ledger
        self.integration.original_adapter_cancel = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            sms_runtime.HeroSmsCancellationDeferred(61, 120)
        )

        result = self.integration.adapter_cancel(adapter, lease, reason="sms_timeout")

        self.assertIsNone(result)
        self.assertEqual(lease.meta["sms_order_state"], "cancel_pending")
        self.assertEqual(captured[0]["delay_seconds"], 61.0)
        self.assertEqual(captured[0]["leased_at"], 1000.0)
        self.assertEqual(captured[0]["task_id"], "task-hero-pending")
        self.assertEqual(ledger.finished, [])


if __name__ == "__main__":
    unittest.main()
