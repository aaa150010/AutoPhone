from __future__ import annotations

import threading
import unittest

from mac_overrides.notification_runtime import (
    RunNotificationLifecycle,
    aggregate_cost,
    aggregate_tasks,
)
from mac_overrides.run_notifications import RunAggregate, build_notification_message


class FakeExchange:
    def __init__(self, source="cache"):
        self.source = source

    def get_rate(self):
        return {"rate": 7.25, "source": self.source, "date": "2026-08-08"}


class FakeLedger:
    def __init__(self, orders):
        self.lock = threading.RLock()
        self.orders = orders


class FakeNotificationService:
    def __init__(self, config):
        self.config = config
        self.started = []
        self.closed = False

    def start_run(self, *args, **kwargs):
        self.started.append((args, kwargs))

    def close(self, **_kwargs):
        self.closed = True


class FakeNotifications:
    @staticmethod
    def validate_email_notification(value):
        return {"enabled": bool((value or {}).get("enabled"))}

    RunNotificationService = FakeNotificationService


class NotificationCostTests(unittest.TestCase):
    def test_lifecycle_begin_context_aggregate_and_cancel(self):
        now = [1000.0]
        lifecycle = RunNotificationLifecycle(
            notifications=FakeNotifications,
            ledger=None,
            exchange=None,
            progress_lookup=lambda task_id: {"entered_at": 1004} if task_id == "T001" else {},
            terminal_statuses={"failed"},
            sms_exhausted=lambda: False,
            clock=lambda: now[0],
            run_id_factory=lambda: "run-generated",
        )
        importer = type("Importer", (), {})()
        importer.lock = threading.RLock()
        importer.tasks = {
            "T001": {"task_id": "T001", "status": "success", "updated_at": 1005},
            "T002": {"task_id": "T002", "status": "failed"},
        }
        context = lifecycle.begin(importer, {"batch_id": "batch-1", "target_count": 2})
        self.assertEqual(context["run_id"], "batch-1")
        self.assertIs(lifecycle.context_for(), context)
        self.assertIs(lifecycle.context_for(importer), context)
        self.assertEqual(context["service"].started[0][0][1]["pending"], 2)

        replacement = lifecycle.begin(importer, {"batch_id": "batch-2", "target_count": 1})
        self.assertTrue(context["stop_event"].is_set())
        self.assertTrue(context["service"].closed)
        context = replacement

        aggregate, last_activity = lifecycle.aggregate(importer, context)
        self.assertEqual((aggregate.total, aggregate.succeeded, aggregate.failed), (2, 1, 1))
        self.assertEqual(last_activity, 1005)

        lifecycle.cancel(importer, context)
        self.assertTrue(context["stop_event"].is_set())
        self.assertTrue(context["service"].closed)
        self.assertIsNone(lifecycle.context_for())

    def test_zero_cost_is_explicit_and_both_currencies_are_rendered(self):
        message = build_notification_message(
            {"enabled": True, "username": "a@example.test", "password": "secret", "sender": "a@example.test", "recipients": ["b@example.test"]},
            "batch_completed",
            RunAggregate(total=1, succeeded=1),
        )
        body = message.get_content()
        self.assertIn("运行成本：¥0.00 / $0.0000", body)

    def test_zero_cost_does_not_claim_an_exchange_estimate(self):
        snapshot = aggregate_cost([], exchange=FakeExchange("fallback"))
        self.assertEqual(snapshot.exchange_source, "")
        self.assertEqual(snapshot.exchange_rate, 0.0)

    def test_live_ledger_is_snapshot_only_and_marks_open_or_unknown_orders(self):
        ledger = FakeLedger({
            "T001": {
                "a": {"price_usd": "0.12", "code_received": True, "status": "code_received"},
                "b": {"price_usd": None, "code_received": False, "status": "leased"},
            }
        })
        snapshot = aggregate_cost(
            [{"task_id": "T001", "status": "running"}],
            ledger=ledger,
            exchange=FakeExchange(),
        )
        self.assertEqual(snapshot.usd, 0.12)
        self.assertEqual(snapshot.cny, 0.87)
        self.assertEqual(snapshot.unknown_price_count, 1)
        self.assertEqual(snapshot.unsettled_order_count, 2)
        self.assertIn("a", ledger.orders["T001"])

    def test_fallback_exchange_is_marked_on_aggregate(self):
        aggregate, _ = aggregate_tasks(
            [{"task_id": "T001", "status": "success", "result": {"sms_cost_usd": 0.1}}],
            exchange=FakeExchange("fallback"),
            terminal_statuses={"failed"},
        )
        self.assertEqual(aggregate.cost_usd, 0.1)
        self.assertEqual(aggregate.cost_cny, 0.73)
        self.assertEqual(aggregate.cost_exchange_source, "fallback")
        self.assertIn("备用汇率", build_notification_message(
            {"enabled": True, "username": "a@example.test", "password": "secret", "sender": "a@example.test", "recipients": ["b@example.test"]},
            "batch_completed",
            aggregate,
        ).get_content())

    def test_ledger_order_already_persisted_in_task_outcomes_is_not_double_counted(self):
        ledger = FakeLedger({
            "T001": {
                "a": {"activation": "abc", "price_usd": 0.12, "code_received": True, "status": "completed"},
            }
        })
        snapshot = aggregate_cost(
            [{
                "task_id": "T001",
                "result": {
                    "sms_cost_usd": 0.12,
                    "sms_order_outcomes": [{"activation": "abc", "price_usd": 0.12, "code_received": True, "status": "completed"}],
                },
            }],
            ledger=ledger,
            exchange=FakeExchange(),
        )
        self.assertEqual(snapshot.usd, 0.12)

    def test_terminal_aggregate_without_outcomes_does_not_double_count_live_paid_order(self):
        ledger = FakeLedger({
            "T001": {
                "late": {
                    "activation": "late-order",
                    "price_usd": 0.12,
                    "code_received": True,
                    "status": "completed",
                },
            }
        })
        snapshot = aggregate_cost(
            [{
                "task_id": "T001",
                "status": "success",
                "result": {"sms_cost_usd": 0.12},
            }],
            ledger=ledger,
            exchange=FakeExchange(),
        )
        self.assertEqual(snapshot.usd, 0.12)
        self.assertEqual(snapshot.cny, 0.87)

    def test_live_ledger_for_a_task_missing_from_snapshot_is_still_counted(self):
        ledger = FakeLedger({
            "T-removed": {
                "a": {
                    "activation": "removed-order",
                    "price_usd": 0.08,
                    "code_received": True,
                    "status": "code_received",
                },
            }
        })
        snapshot = aggregate_cost(
            [{"task_id": "T-current", "status": "running"}],
            ledger=ledger,
            exchange=FakeExchange(),
        )
        self.assertEqual(snapshot.usd, 0.08)
        self.assertEqual(snapshot.cny, 0.58)


if __name__ == "__main__":
    unittest.main()
