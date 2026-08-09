"""Pure run-notification aggregation helpers.

This module is intentionally independent of the recovered importer.  It owns
the lifecycle-facing snapshot and cost calculation so ``web_gui.py`` only
needs to provide task rows, a progress lookup, and the SMS ledger.
"""

from __future__ import annotations

import copy
import math
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

try:
    from .run_notifications import RunAggregate
except ImportError:  # recovered web_gui imports override modules as top-level
    from run_notifications import RunAggregate


@dataclass(frozen=True, slots=True)
class CostSnapshot:
    """Non-destructive cost view for one notification event."""

    usd: float = 0.0
    cny: float = 0.0
    exchange_rate: float = 0.0
    exchange_source: str = ""
    unknown_price_count: int = 0
    unsettled_order_count: int = 0


def _number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def _safe_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _coerce_int(
    value: Any,
    default: int = 0,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    if minimum is not None:
        parsed = max(int(minimum), parsed)
    if maximum is not None:
        parsed = min(int(maximum), parsed)
    return parsed


def snapshot_ledger(ledger: Any) -> dict[str, list[dict[str, Any]]]:
    """Read active SMS orders while holding the ledger lock, without popping."""
    if ledger is None:
        return {}
    lock = getattr(ledger, "lock", None)
    orders = getattr(ledger, "orders", None)
    try:
        if lock is not None:
            with lock:
                source = copy.deepcopy(orders or {})
        else:
            source = copy.deepcopy(orders or {})
    except Exception:
        return {}
    result: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(source, Mapping):
        return result
    for task_id, task_orders in source.items():
        if not isinstance(task_orders, Mapping):
            continue
        result[str(task_id)] = [
            dict(order)
            for order in task_orders.values()
            if isinstance(order, Mapping)
        ]
    return result


def _rate_info(exchange: Any) -> tuple[float, str]:
    if exchange is None or not callable(getattr(exchange, "get_rate", None)):
        return 0.0, ""
    try:
        info = _safe_mapping(exchange.get_rate())
    except Exception:
        return 0.0, ""
    return _number(info.get("rate")) or 0.0, str(info.get("source") or "")[:32]


def _task_cost(task: Mapping[str, Any]) -> tuple[float, float, int, int]:
    result = _safe_mapping(task.get("result"))
    usd = _number(result.get("sms_cost_usd"))
    if usd is None:
        usd = _number(task.get("sms_cost_usd"))
    cny = _number(result.get("sms_cost_cny"))
    if cny is None:
        cny = _number(task.get("sms_cost_cny"))
    unknown = 0
    unsettled = 0
    outcomes = result.get("sms_order_outcomes")
    if not isinstance(outcomes, (list, tuple)):
        outcomes = task.get("sms_order_outcomes")
    if isinstance(outcomes, (list, tuple)):
        for outcome in outcomes:
            row = _safe_mapping(outcome)
            price = _number(row.get("price_usd"))
            status = str(row.get("status") or "").strip().lower()
            if price is None:
                unknown += 1
            if status and status not in {"completed", "cancelled"}:
                unsettled += 1
    return usd or 0.0, cny or 0.0, unknown, unsettled


def aggregate_cost(
    tasks: Iterable[Mapping[str, Any]],
    *,
    ledger: Any = None,
    exchange: Any = None,
    task_ids: Iterable[str] | None = None,
) -> CostSnapshot:
    """Combine completed task results and a live ledger snapshot."""
    task_rows = list(tasks)
    usd = 0.0
    cny = 0.0
    unknown = 0
    unsettled = 0
    task_ids_from_rows: set[str] = set()
    known_activations: dict[str, set[str]] = {}
    # A terminal task normally consumes its ledger during persistence.  If a
    # non-destructive notification snapshot races that cleanup, an older
    # result may contain only the aggregate price (without order outcomes).
    # Keep a per-task paid-cost budget so the same active order is not charged
    # a second time while still allowing genuinely additional orders through.
    aggregate_only_paid_budget: dict[str, float] = {}
    aggregate_only_cny_budget: dict[str, float] = {}
    for task in task_rows:
        if not isinstance(task, Mapping):
            continue
        task_identifier = str(task.get("task_id") or "")
        if task_identifier:
            task_ids_from_rows.add(task_identifier)
        outcomes = _safe_mapping(task.get("result")).get("sms_order_outcomes")
        if not isinstance(outcomes, (list, tuple)):
            outcomes = task.get("sms_order_outcomes")
        if isinstance(outcomes, (list, tuple)):
            known_activations[task_identifier] = {
                str(_safe_mapping(item).get("activation") or "")
                for item in outcomes
                if _safe_mapping(item).get("activation")
            }
        status = str(task.get("status") or "").strip().lower()
        terminal = status in {
            "success",
            "failed",
            "stopped",
            "stopped_before_start",
            "retryable_infra",
            "retryable_email",
            "repair_pending",
            "email_damaged",
            "account_banned",
        }
        if terminal and not isinstance(outcomes, (list, tuple)):
            # Use USD as the stable matching currency.  CNY-only records are
            # converted below once a current exchange rate is available.
            persisted_usd = _number(_safe_mapping(task.get("result")).get("sms_cost_usd"))
            if persisted_usd is None:
                persisted_usd = _number(task.get("sms_cost_usd"))
            if persisted_usd is not None and persisted_usd > 0:
                aggregate_only_paid_budget[task_identifier] = persisted_usd
            else:
                persisted_cny = _number(_safe_mapping(task.get("result")).get("sms_cost_cny"))
                if persisted_cny is None:
                    persisted_cny = _number(task.get("sms_cost_cny"))
                if persisted_cny is not None and persisted_cny > 0:
                    aggregate_only_cny_budget[task_identifier] = persisted_cny
        row_usd, row_cny, row_unknown, row_unsettled = _task_cost(task)
        usd += row_usd
        cny += row_cny
        unknown += row_unknown
        unsettled += row_unsettled

    rate, source = _rate_info(exchange)
    if rate:
        for task_id, cny_budget in aggregate_only_cny_budget.items():
            aggregate_only_paid_budget.setdefault(task_id, cny_budget / rate)
    live = snapshot_ledger(ledger)
    # The importer may remove a task row before its SMS ledger is settled.
    # Include both sources; activation fingerprints still prevent double count.
    live_task_ids = (
        {str(value) for value in task_ids if str(value)}
        if task_ids is not None
        else task_ids_from_rows | set(live)
    )
    for task_id in live_task_ids:
        for order in live.get(task_id, ()):
            activation = str(order.get("activation") or "")
            if activation and activation in known_activations.get(task_id, set()):
                continue
            price = _number(order.get("price_usd"))
            status = str(order.get("status") or "").strip().lower()
            code_received = bool(order.get("code_received"))
            if status and status not in {"completed", "cancelled"}:
                unsettled += 1
            if price is None:
                unknown += 1
            elif code_received:
                remaining_budget = aggregate_only_paid_budget.get(task_id)
                if remaining_budget is not None and remaining_budget + 1e-9 >= price:
                    # The persisted aggregate already accounts for this paid
                    # order, but its activation id was not retained.  Consume
                    # only the matching amount so a newer order is still
                    # reflected in the notification snapshot.
                    aggregate_only_paid_budget[task_id] = max(
                        0.0,
                        remaining_budget - price,
                    )
                    continue
                usd += price
                if rate:
                    cny += price * rate

    # A persisted CNY-only result is still useful: derive a display USD value
    # only when a current rate exists; no rate means the USD side remains zero.
    if not usd and cny and rate:
        usd = cny / rate
    if not cny and usd and rate:
        cny = usd * rate
    if not usd and not cny and not unknown and not unsettled:
        # A zero-cost batch does not depend on the exchange-rate source.
        rate, source = 0.0, ""
    return CostSnapshot(
        usd=round(usd, 4),
        cny=round(cny, 2),
        exchange_rate=round(rate, 6),
        exchange_source=source,
        unknown_price_count=unknown,
        unsettled_order_count=unsettled,
    )


def aggregate_tasks(
    tasks: Iterable[Mapping[str, Any]],
    *,
    context: Mapping[str, Any] | None = None,
    finished: bool = False,
    progress_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
    ledger: Any = None,
    exchange: Any = None,
    terminal_statuses: Iterable[str] = (),
    task_ids: Iterable[str] | None = None,
    now: int | None = None,
) -> tuple[RunAggregate, int]:
    """Build the safe aggregate and return its last activity timestamp."""
    rows = [dict(row) for row in tasks if isinstance(row, Mapping)]
    terminal = {str(value).strip().lower() for value in terminal_statuses}
    succeeded = failed = stopped = active = pending = 0
    last_activity = 0
    for task in rows:
        status = str(task.get("status") or "").strip().lower()
        if status == "success":
            succeeded += 1
        elif status in {"stopped", "stopped_before_start"}:
            stopped += 1
        elif status in terminal:
            failed += 1
        elif status == "queued":
            pending += 1
        else:
            active += 1
        for candidate in (
            task.get("updated_at"),
            task.get("created_at"),
            _safe_mapping(task.get("progress")).get("entered_at"),
            _safe_mapping(
                progress_lookup(str(task.get("task_id") or ""))
                if progress_lookup
                else {}
            ).get("entered_at"),
        ):
            try:
                last_activity = max(last_activity, int(candidate or 0))
            except (TypeError, ValueError):
                pass
    value = _safe_mapping(context)
    started_at = int(_number(value.get("started_at")) or 0)
    fallback_finished_at = (
        int(now) if now is not None else int(time.time())
    ) if finished else 0
    finished_at = int(_number(value.get("finished_at")) or fallback_finished_at)
    duration_end = finished_at or (int(now) if now is not None else int(time.time()))
    duration = max(0, duration_end - started_at) if started_at else 0
    cost = aggregate_cost(
        rows,
        ledger=ledger,
        exchange=exchange,
        task_ids=task_ids,
    )
    return RunAggregate(
        total=len(rows),
        succeeded=succeeded,
        failed=failed,
        stopped=stopped,
        active=active,
        pending=pending,
        duration_seconds=duration,
        cost_cny=cost.cny,
        cost_usd=cost.usd,
        cost_exchange_rate=cost.exchange_rate,
        cost_exchange_source=cost.exchange_source,
        cost_unknown_count=cost.unknown_price_count,
        cost_unsettled_count=cost.unsettled_order_count,
        started_at=started_at,
        finished_at=finished_at,
        last_activity_at=last_activity,
    ), last_activity


class RunNotificationLifecycle:
    """Own one importer's notification context and background observations."""

    def __init__(
        self,
        *,
        notifications: Any,
        ledger: Any,
        exchange: Any,
        progress_lookup: Callable[[str], Mapping[str, Any] | None],
        terminal_statuses: Iterable[str],
        sms_exhausted: Callable[[], bool],
        observe_resource_pressure: Callable[[Any], Any] | None = None,
        int_value: Callable[..., int] = _coerce_int,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        run_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.notifications = notifications
        self.ledger = ledger
        self.exchange = exchange
        self.progress_lookup = progress_lookup
        self.terminal_statuses = tuple(terminal_statuses)
        self.sms_exhausted = sms_exhausted
        self.observe_resource_pressure = observe_resource_pressure
        self.int_value = int_value
        self.clock = clock
        self.monotonic = monotonic
        self.run_id_factory = run_id_factory or (lambda: uuid.uuid4().hex)
        self._lock = threading.RLock()
        self._context: dict[str, Any] | None = None

    def _int_setting(self, value: Any, default: int, *, minimum: int) -> int:
        """Accept both the rich runtime converter and the plain ``int`` builtin."""
        try:
            return int(self.int_value(value, default, minimum=minimum))
        except TypeError:
            try:
                return max(minimum, int(self.int_value(value, default)))
            except (TypeError, ValueError):
                try:
                    return max(minimum, int(value))
                except (TypeError, ValueError):
                    return default
        except (ValueError, OverflowError):
            return default

    @staticmethod
    def task_snapshot(importer: Any) -> list[dict[str, Any]]:
        try:
            with importer.lock:
                return [copy.deepcopy(dict(task)) for task in importer.tasks.values()]
        except Exception:
            return []

    def aggregate(
        self,
        importer: Any,
        context: Mapping[str, Any] | None = None,
        *,
        finished: bool = False,
    ) -> tuple[RunAggregate, int]:
        rows = self.task_snapshot(importer)
        known_task_ids = {
            str(row.get("task_id") or "")
            for row in rows
            if str(row.get("task_id") or "")
        }
        if isinstance(context, dict):
            known_task_ids.update(
                str(value)
                for value in context.get("_task_ids", ())
                if str(value)
            )
            context["_task_ids"] = tuple(sorted(known_task_ids))
        return aggregate_tasks(
            rows,
            context=context,
            finished=finished,
            ledger=self.ledger,
            exchange=self.exchange,
            progress_lookup=self.progress_lookup,
            terminal_statuses=self.terminal_statuses,
            task_ids=known_task_ids,
        )

    def context_for(self, importer: Any = None) -> dict[str, Any] | None:
        if importer is not None:
            value = getattr(importer, "_gptphone_notification_context", None)
            if isinstance(value, dict):
                return value
        with self._lock:
            return self._context

    def watchdog(self, importer: Any, context: dict[str, Any]) -> None:
        stop_event = context["stop_event"]
        notification_deadline = self.monotonic() + 10.0
        while not stop_event.wait(2):
            if callable(self.observe_resource_pressure):
                try:
                    self.observe_resource_pressure(importer)
                except Exception:
                    pass
            if self.monotonic() < notification_deadline:
                continue
            notification_deadline = self.monotonic() + 10.0
            try:
                aggregate, last_activity_at = self.aggregate(importer, context)
                context["last_activity_at"] = (
                    last_activity_at or context.get("last_activity_at", 0)
                )
                context["service"].observe_run(
                    context["run_id"],
                    aggregate,
                    sms_exhausted=self.sms_exhausted(),
                )
            except Exception:
                continue

    def begin(self, importer: Any, settings: Any) -> dict[str, Any]:
        values = settings or {}
        config = self.notifications.validate_email_notification(
            values.get("email_notification") or {}
        )
        previous = self.context_for()
        if isinstance(previous, dict):
            # Closing the SMTP service does not stop its watchdog.  Signal the
            # old context first so a replacement run cannot leave a daemon
            # thread polling an obsolete importer forever.
            try:
                previous["stop_event"].set()
            except Exception:
                pass
            try:
                previous["service"].close(wait=False)
            except Exception:
                pass
        now = int(self.clock())
        context = {
            "run_id": str(values.get("batch_id") or self.run_id_factory()),
            "batch_id": str(values.get("batch_id") or ""),
            "batch_started_at": self._int_setting(
                values.get("batch_started_at"), now, minimum=0
            ),
            "service": self.notifications.RunNotificationService(config),
            "started_at": now,
            "finished_at": 0,
            "last_activity_at": now,
            "target": self._int_setting(
                values.get("target_count"), 1, minimum=1
            ),
            "stop_event": threading.Event(),
        }
        context["service"].start_run(
            context["run_id"],
            {"total": 0, "pending": context["target"]},
            batch_id=context["batch_id"],
        )
        importer._gptphone_notification_context = context
        with self._lock:
            self._context = context
        return context

    def cancel(self, importer: Any, context: dict[str, Any]) -> None:
        context["stop_event"].set()
        try:
            context["service"].close(wait=False)
        except Exception:
            pass
        if getattr(importer, "_gptphone_notification_context", None) is context:
            importer._gptphone_notification_context = None
        with self._lock:
            if self._context is context:
                self._context = None


__all__ = [
    "CostSnapshot",
    "RunNotificationLifecycle",
    "aggregate_cost",
    "aggregate_tasks",
    "snapshot_ledger",
]
