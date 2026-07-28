from __future__ import annotations

from types import SimpleNamespace
import unittest

from mac_overrides import sms_runtime
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
        self.assertEqual(self.integration.clamp_max_price("0"), "0.1")
        self.assertEqual(self.integration.clamp_max_price("0.11"), "0.1")
        self.assertEqual(self.integration.clamp_max_price("bad"), "0.1")

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


if __name__ == "__main__":
    unittest.main()
