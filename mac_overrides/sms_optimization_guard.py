"""Credential-free rollback guard for SMS quality optimization."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import os
import threading
import time
from typing import Any, Callable, Mapping
import uuid


ROLLING_WINDOW_TASKS = 100
SUCCESS_RATE_BASELINE = 0.839
SUCCESS_RATE_FLOOR = 0.819


def _number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


@dataclass(frozen=True)
class SmsOptimizationBaseline:
    success_rate: float = SUCCESS_RATE_BASELINE
    cancellation_rate: float | None = None
    duplicate_order_rate: float | None = None
    cost_per_success_usd: float | None = None

    @classmethod
    def from_value(cls, value: Any) -> "SmsOptimizationBaseline":
        row = value if isinstance(value, Mapping) else {}
        success_rate = _number(row.get("success_rate"))
        return cls(
            success_rate=(
                SUCCESS_RATE_BASELINE if success_rate is None else min(1.0, success_rate)
            ),
            cancellation_rate=_number(row.get("cancellation_rate")),
            duplicate_order_rate=_number(row.get("duplicate_order_rate")),
            cost_per_success_usd=_number(row.get("cost_per_success_usd")),
        )


class SmsOptimizationGuard:
    """Disable adaptive SMS selection only on observed, bounded regressions."""

    def __init__(
        self,
        *,
        window_size: int = ROLLING_WINDOW_TASKS,
        on_disable: Callable[[dict[str, Any]], Any] | None = None,
        baseline_path: Path | None = None,
        state_path: Path | None = None,
        late_code_confirmation_source: bool = False,
    ) -> None:
        self.window_size = max(1, int(window_size))
        self.on_disable = on_disable
        self.baseline_path = Path(baseline_path) if baseline_path is not None else None
        self.state_path = (
            Path(state_path)
            if state_path is not None
            else (
                self.baseline_path.with_name("sms_optimization_state.json")
                if self.baseline_path is not None
                else None
            )
        )
        self.late_code_confirmation_source = bool(late_code_confirmation_source)
        self.lock = threading.RLock()
        self.enabled = False
        self.disabled_reason = ""
        self.manual_reset_armed = False
        self.baseline = SmsOptimizationBaseline()
        self.samples: deque[dict[str, Any]] = deque(maxlen=self.window_size)
        self.seen_tasks: set[str] = set()
        self._load_state()

    def _load_state(self) -> None:
        if self.state_path is None:
            return
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return
        if not isinstance(value, Mapping):
            return
        reason = str(value.get("disabled_reason") or "").strip().lower()
        if reason and len(reason) <= 100 and all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789_"
            for character in reason
        ):
            self.disabled_reason = reason

        self.manual_reset_armed = bool(value.get("manual_reset_armed"))
        restored: list[dict[str, Any]] = []
        raw_samples = value.get("samples")
        if isinstance(raw_samples, list):
            for raw in raw_samples[-self.window_size :]:
                if not isinstance(raw, Mapping):
                    continue
                task = str(raw.get("task") or "").strip().lower()
                if len(task) != 16 or any(character not in "0123456789abcdef" for character in task):
                    continue
                restored.append(
                    {
                        "task": task,
                        "success": bool(raw.get("success")),
                        "orders": max(0, min(100, int(_number(raw.get("orders")) or 0))),
                        "cancelled": max(0, min(100, int(_number(raw.get("cancelled")) or 0))),
                        "duplicates": max(0, min(100, int(_number(raw.get("duplicates")) or 0))),
                        "duplicate_observed": bool(raw.get("duplicate_observed")),
                        "cost_usd": _number(raw.get("cost_usd")),
                        "late_code_loss": bool(raw.get("late_code_loss")),
                    }
                )
        self.samples.extend(restored)
        self.seen_tasks.update(str(sample["task"]) for sample in restored)

    def _persist_state_locked(self) -> None:
        if self.state_path is None:
            return
        payload = {
            "version": 2,
            "disabled_reason": self.disabled_reason,
            "manual_reset_armed": self.manual_reset_armed,
            "samples": [dict(sample) for sample in self.samples],
            "metrics": self._metrics_locked(),
            "updated_at": int(time.time()),
        }
        temporary: Path | None = None
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_name(
                f".{self.state_path.name}.{uuid.uuid4().hex}.tmp"
            )
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.state_path)
        except OSError:
            return
        finally:
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def _metrics_locked(self) -> dict[str, Any]:
        samples = tuple(self.samples)
        successes = sum(1 for sample in samples if sample["success"])
        orders = sum(int(sample["orders"]) for sample in samples)
        cancelled = sum(int(sample["cancelled"]) for sample in samples)
        duplicates = sum(int(sample["duplicates"]) for sample in samples)
        late_losses = sum(1 for sample in samples if sample["late_code_loss"])
        successful_costs = [
            float(sample["cost_usd"])
            for sample in samples
            if sample["success"] and sample["cost_usd"] is not None
        ]
        metrics: dict[str, Any] = {
            "window_tasks": len(samples),
            "successes": successes,
            "success_rate": round(successes / len(samples), 4) if samples else None,
            "orders": orders,
            "cancelled_orders": cancelled,
            "duplicate_orders": duplicates,
            "confirmed_late_code_losses": late_losses,
            "cost_success_samples": len(successful_costs),
        }
        if successful_costs:
            metrics["cost_per_success_usd"] = round(
                sum(successful_costs) / len(successful_costs), 6
            )
        return metrics

    def _load_baseline(self) -> SmsOptimizationBaseline | None:
        if self.baseline_path is None:
            return None
        try:
            value = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(value, Mapping):
            return None
        baseline = SmsOptimizationBaseline.from_value(value)
        known = any(
            getattr(baseline, key) is not None
            for key in ("cancellation_rate", "duplicate_order_rate", "cost_per_success_usd")
        )
        return baseline if known else None

    def _persist_baseline_locked(self) -> None:
        if self.baseline_path is None or len(self.samples) < self.window_size:
            return
        samples = tuple(self.samples)
        orders = sum(int(sample["orders"]) for sample in samples)
        cancellations = sum(int(sample["cancelled"]) for sample in samples)
        duplicate_observed = any(bool(sample["duplicate_observed"]) for sample in samples)
        duplicates = sum(int(sample["duplicates"]) for sample in samples)
        successful_costs = [
            float(sample["cost_usd"])
            for sample in samples
            if sample["success"] and sample["cost_usd"] is not None
        ]
        payload: dict[str, Any] = {
            "version": 1,
            "sample_tasks": len(samples),
            "captured_at": int(time.time()),
        }
        if orders:
            payload["cancellation_rate"] = round(cancellations / orders, 6)
        if orders and duplicate_observed:
            payload["duplicate_order_rate"] = round(duplicates / orders, 6)
        if successful_costs:
            payload["cost_per_success_usd"] = round(
                sum(successful_costs) / len(successful_costs), 6
            )
        if len(payload) <= 3:
            return
        try:
            self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.baseline_path.with_suffix(self.baseline_path.suffix + ".tmp")
            temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            temporary.replace(self.baseline_path)
        except OSError:
            return

    @staticmethod
    def _task_key(task_id: Any) -> str:
        value = str(task_id or "").strip()
        if not value:
            return ""
        return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]

    @staticmethod
    def _sample(status: Any, result: Any) -> dict[str, Any]:
        row = result if isinstance(result, Mapping) else {}
        outcomes = row.get("sms_order_outcomes")
        orders = outcomes if isinstance(outcomes, list) else []
        cancellation_count = sum(
            1
            for order in orders
            if isinstance(order, Mapping)
            and str(order.get("status") or "").strip().lower() == "cancelled"
        )
        # A duplicate order must be explicitly confirmed by the provider-side
        # reconciliation path.  Multiple attempts alone are not evidence.
        duplicate_orders = _number(row.get("sms_duplicate_orders")) or 0.0
        cost = _number(row.get("sms_cost_usd"))
        return {
            "success": str(status or "").strip().lower() == "success",
            "orders": len(orders),
            "cancelled": cancellation_count,
            "duplicates": int(duplicate_orders),
            "duplicate_observed": "sms_duplicate_orders" in row,
            "cost_usd": cost,
            "late_code_loss": False,
        }

    def begin_run(self, enabled: Any, *, baseline: Any = None) -> None:
        with self.lock:
            requested = bool(enabled)
            supplied = (
                SmsOptimizationBaseline.from_value(baseline)
                if isinstance(baseline, Mapping)
                else None
            )
            self.baseline = supplied or self._load_baseline() or SmsOptimizationBaseline()
            if not requested:
                # A deliberate manual rollback starts a fresh, unoptimized
                # baseline collection.  Re-enabling it is the only reset for
                # an automatic shutdown.
                self.enabled = False
                self.disabled_reason = ""
                self._persist_state_locked()
                if not self.manual_reset_armed:
                    self.samples.clear()
                    self.seen_tasks.clear()
                    self.manual_reset_armed = True
                return
            if self.disabled_reason and not self.manual_reset_armed:
                # Keep an automatic safety shutdown across later batches.
                self.enabled = True
                return
            if self.manual_reset_armed:
                self.samples.clear()
                self.seen_tasks.clear()
                self.manual_reset_armed = False
            self.enabled = True
            self.disabled_reason = ""
            self._persist_state_locked()

    def is_enabled(self, configured: Any) -> bool:
        with self.lock:
            return bool(configured) and (not self.enabled or not self.disabled_reason)

    def observe_task(self, task_id: Any, status: Any, result: Any = None) -> dict[str, Any] | None:
        key = self._task_key(task_id)
        if not key:
            return None
        event = None
        with self.lock:
            if key in self.seen_tasks:
                return None
            # deque(maxlen=...) silently discards the oldest item. Remove its
            # matching hash first so both structures remain bounded together.
            if len(self.samples) >= self.window_size:
                oldest = self.samples.popleft()
                oldest_key = str(oldest.get("task") or "")
                if oldest_key:
                    self.seen_tasks.discard(oldest_key)
            self.seen_tasks.add(key)
            self.samples.append({"task": key, **self._sample(status, result)})
            if self.enabled:
                event = self._evaluate_locked()
            else:
                self._persist_baseline_locked()
            self._persist_state_locked()
        if event is not None and callable(self.on_disable):
            try:
                self.on_disable(dict(event))
            except Exception:
                pass
        return event

    def observe_confirmed_late_code_loss(self, task_id: Any) -> dict[str, Any] | None:
        """Record only a provider-confirmed code received after early release."""
        key = self._task_key(task_id)
        event = None
        with self.lock:
            for sample in self.samples:
                if sample.get("task") == key:
                    sample["late_code_loss"] = True
                    event = self._evaluate_locked()
                    self._persist_state_locked()
                    break
        if event is not None and callable(self.on_disable):
            try:
                self.on_disable(dict(event))
            except Exception:
                pass
        return event

    def _evaluate_locked(self) -> dict[str, Any] | None:
        if not self.enabled or self.disabled_reason or len(self.samples) < self.window_size:
            return None
        samples = tuple(self.samples)
        total = len(samples)
        metrics = self._metrics_locked()
        successes = int(metrics["successes"])
        success_rate = float(metrics["success_rate"])
        orders = int(metrics["orders"])
        cancelled = int(metrics["cancelled_orders"])
        duplicates = int(metrics["duplicate_orders"])
        late_losses = int(metrics["confirmed_late_code_losses"])
        successful_costs = [
            float(sample["cost_usd"])
            for sample in samples
            if sample["success"] and sample["cost_usd"] is not None
        ]
        reasons: list[str] = []
        if success_rate < SUCCESS_RATE_FLOOR:
            reasons.append("success_rate_below_819")
        if late_losses >= 2:
            reasons.append("two_confirmed_late_code_losses")
        if orders and self.baseline.cancellation_rate is not None:
            if cancelled / orders > self.baseline.cancellation_rate:
                reasons.append("cancellation_rate_increased")
        if orders and self.baseline.duplicate_order_rate is not None:
            if duplicates / orders > self.baseline.duplicate_order_rate:
                reasons.append("duplicate_order_rate_increased")
        if successful_costs and self.baseline.cost_per_success_usd is not None:
            cost_per_success = sum(successful_costs) / len(successful_costs)
            metrics["cost_per_success_usd"] = round(cost_per_success, 4)
            if cost_per_success > self.baseline.cost_per_success_usd * 1.10:
                reasons.append("cost_per_success_above_110_percent")
        if not reasons:
            return None
        self.disabled_reason = reasons[0]
        self._persist_state_locked()
        return {"kind": "sms_quality_optimization_disabled", "reasons": reasons, "metrics": metrics}

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "enabled": self.enabled,
                "disabled": bool(self.disabled_reason),
                "reason": self.disabled_reason,
                "manual_reset_required": bool(self.disabled_reason),
                "observed_tasks": len(self.samples),
                "window_tasks": self.window_size,
                "baseline_success_rate": self.baseline.success_rate,
                "cancellation_baseline_available": self.baseline.cancellation_rate is not None,
                "duplicate_baseline_available": self.baseline.duplicate_order_rate is not None,
                "cost_baseline_available": self.baseline.cost_per_success_usd is not None,
                "late_code_loss_auto_detection_available": self.late_code_confirmation_source,
                "metrics": self._metrics_locked(),
            }


__all__ = [
    "ROLLING_WINDOW_TASKS",
    "SUCCESS_RATE_BASELINE",
    "SUCCESS_RATE_FLOOR",
    "SmsOptimizationBaseline",
    "SmsOptimizationGuard",
]
