"""Pure configuration policies for optional runtime performance features."""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
import threading
from typing import Any, Callable, Iterator, Mapping

try:
    from .sms_provider_runtime import (
        legacy_sms_provider_keys,
        normalize_sms_provider_pools,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_provider_runtime import (  # type: ignore[no-redef]
        legacy_sms_provider_keys,
        normalize_sms_provider_pools,
    )


SMS_QUALITY_OPTIMIZATION = "sms_quality_optimization"
ADAPTIVE_TASK_CONCURRENCY = "adaptive_task_concurrency"
TASK_INFLIGHT_OPTIMIZATION = "task_inflight_optimization"
OPENAI_CONNECTIVITY_GUARD = "openai_connectivity_guard"
PERFORMANCE_FEATURE_DEFAULTS = {
    SMS_QUALITY_OPTIMIZATION: True,
    ADAPTIVE_TASK_CONCURRENCY: True,
    TASK_INFLIGHT_OPTIMIZATION: True,
    OPENAI_CONNECTIVITY_GUARD: True,
}
PERFORMANCE_POLICY_VERSION = 13
PHONE_MAX_ATTEMPTS_LIMIT = 45
TASK_INFLIGHT_LIMIT = 20
PERFORMANCE_DEFAULTS = {
    "auto_email_login_concurrency": 5,
    "phone_submission_concurrency": 2,
    "pixel_upload_concurrency": 2,
    "phone_max_attempts": PHONE_MAX_ATTEMPTS_LIMIT,
    "phone_attempts_per_provider": 15,
    "phone_session_cycle_seconds": 1800,
    "auth_session_retries": 1,
    "task_inflight_limit": TASK_INFLIGHT_LIMIT,
    "protocol_concurrency_ceiling": 12,
}

INFLIGHT_ROLLING_WINDOW_TASKS = 100
INFLIGHT_SUCCESS_RATE_FLOOR = 0.819

_TRUE_VALUES = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", "disabled"})


def as_bool(value: Any, default: bool = True) -> bool:
    """Normalize persisted/UI boolean values without making non-empty strings truthy."""
    if value is None or value == "":
        return bool(default)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE_VALUES:
            return True
        if normalized in _FALSE_VALUES:
            return False
        return bool(default)
    return bool(value)


def normalize_feature_flags(value: Any) -> dict[str, Any]:
    """Return a copy with both rollback switches present as real booleans."""
    config = dict(value or {}) if isinstance(value, Mapping) else {}
    for key, default in PERFORMANCE_FEATURE_DEFAULTS.items():
        config[key] = as_bool(config.get(key), default)
    return config


def migrate_performance_config(value: Any) -> tuple[dict[str, Any], bool]:
    """Apply one-time performance defaults while preserving later user choices."""
    config = dict(value or {}) if isinstance(value, dict) else {}
    try:
        version = int(config.get("performance_policy_version") or 0)
    except (TypeError, ValueError):
        version = 0
    migrated = version < PERFORMANCE_POLICY_VERSION
    if migrated:
        for key, default in PERFORMANCE_DEFAULTS.items():
            missing = key not in config or config.get(key) in (None, "")
            try:
                current = int(config.get(key)) if not missing else 0
            except (TypeError, ValueError):
                current = 0
                missing = True
            if key == "auth_session_retries":
                invalid = current < 0
            elif key == "task_inflight_limit":
                invalid = False
            else:
                invalid = current <= 0
            if missing or invalid or (
                version < 11
                and (
                    (key == "auto_email_login_concurrency" and current == 1)
                    or (key == "phone_max_attempts" and current in {9, 15})
                    or (key == "phone_session_cycle_seconds" and current == 480)
                )
            ):
                config[key] = default
        config["performance_policy_version"] = PERFORMANCE_POLICY_VERSION
    else:
        for key, default in PERFORMANCE_DEFAULTS.items():
            if key not in config:
                config[key] = default

    try:
        phone_max_attempts = int(config.get("phone_max_attempts") or 0)
    except (TypeError, ValueError):
        phone_max_attempts = 0
    if phone_max_attempts > PHONE_MAX_ATTEMPTS_LIMIT:
        config["phone_max_attempts"] = PHONE_MAX_ATTEMPTS_LIMIT

    try:
        task_concurrency = max(1, min(8, int(config.get("concurrency") or 5)))
    except (TypeError, ValueError):
        task_concurrency = 5
    config["concurrency"] = task_concurrency
    raw_inflight_limit = config.get("task_inflight_limit")
    try:
        inflight_limit = (
            TASK_INFLIGHT_LIMIT
            if raw_inflight_limit in (None, "")
            else int(raw_inflight_limit)
        )
    except (TypeError, ValueError):
        inflight_limit = TASK_INFLIGHT_LIMIT
    config["task_inflight_limit"] = max(1, min(TASK_INFLIGHT_LIMIT, inflight_limit))
    try:
        protocol_ceiling = int(config.get("protocol_concurrency_ceiling") or 12)
    except (TypeError, ValueError):
        protocol_ceiling = 12
    config["protocol_concurrency_ceiling"] = max(8, min(15, protocol_ceiling))
    try:
        email_concurrency = int(
            config.get("auto_email_login_concurrency")
            or PERFORMANCE_DEFAULTS["auto_email_login_concurrency"]
        )
    except (TypeError, ValueError):
        email_concurrency = PERFORMANCE_DEFAULTS["auto_email_login_concurrency"]
    config["auto_email_login_concurrency"] = max(
        1,
        min(task_concurrency, email_concurrency),
    )
    for key in ("phone_submission_concurrency", "pixel_upload_concurrency"):
        try:
            parsed = int(config.get(key) or PERFORMANCE_DEFAULTS[key])
        except (TypeError, ValueError):
            parsed = PERFORMANCE_DEFAULTS[key]
        maximum = 5 if key == "phone_submission_concurrency" else 3
        config[key] = max(1, min(maximum, parsed))

    pools = normalize_sms_provider_pools(
        config.get("sms_provider_pools"),
        legacy_provider=config.get("sms_provider") or "smsbower",
        legacy_keys=config.get("sms_api_keys"),
        legacy_key=config.get("sms_api_key"),
    )
    config["sms_provider_pools"] = pools
    config["sms_provider"] = str(pools[0].get("provider") or "smsbower")
    keys = legacy_sms_provider_keys(pools, config["sms_provider"])
    config["sms_api_keys"] = keys
    config["sms_api_key"] = keys[0] if keys else ""
    return config, migrated


@dataclass(frozen=True)
class TaskAdmissionPolicy:
    """Resolved limits for one importer run."""

    base_limit: int
    restore_ceiling: int
    absolute_ceiling: int
    adaptive: bool


def _nonnegative_number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


@dataclass(frozen=True)
class InflightRollbackBaseline:
    """Optional comparison rates captured before enabling in-flight expansion."""

    cancellation_rate: float | None = None
    duplicate_order_rate: float | None = None
    cost_per_success_usd: float | None = None

    @classmethod
    def from_value(cls, value: Any) -> "InflightRollbackBaseline":
        row = value if isinstance(value, Mapping) else {}
        return cls(
            cancellation_rate=_nonnegative_number(row.get("cancellation_rate")),
            duplicate_order_rate=_nonnegative_number(row.get("duplicate_order_rate")),
            cost_per_success_usd=_nonnegative_number(row.get("cost_per_success_usd")),
        )


class InflightAdmissionGate:
    """Bound per-batch in-flight work and stick to baseline after a regression."""

    _IMMEDIATE_REASONS = frozenset(
        {
            "protocol_pressure",
            "http_429",
            "session_invalidation",
            "repeated_connectivity_outage",
        }
    )

    def __init__(
        self,
        configured: Any = 5,
        *,
        limit: Any = TASK_INFLIGHT_LIMIT,
        enabled: Any = True,
        baseline: Any = None,
        window_size: int = INFLIGHT_ROLLING_WINDOW_TASKS,
        on_rollback: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        try:
            configured_limit = max(1, min(8, int(configured)))
        except (TypeError, ValueError):
            configured_limit = 5
        try:
            optimized_limit = max(1, min(TASK_INFLIGHT_LIMIT, int(limit)))
        except (TypeError, ValueError):
            optimized_limit = TASK_INFLIGHT_LIMIT

        optimization_requested = as_bool(enabled, True)
        self.optimization_requested = optimization_requested
        self.configured = configured_limit
        self.requested_limit = optimized_limit
        self.effective = (
            max(configured_limit, optimized_limit)
            if optimization_requested
            else configured_limit
        )
        self.optimized = optimization_requested and self.effective > configured_limit
        self.staged = self.optimized
        self.rolled_back = False
        self.suspended = False
        self.sticky_baseline = False
        self.resume_eligible = False
        self.reason = "optimized" if self.optimized else "configured_baseline"
        self.baseline = (
            baseline
            if isinstance(baseline, InflightRollbackBaseline)
            else InflightRollbackBaseline.from_value(baseline)
        )
        self.window_size = max(1, int(window_size))
        self.on_rollback = on_rollback
        self.condition = threading.Condition()
        self.active = 0
        self.waiting = 0
        self._stopped = False
        self._samples: deque[dict[str, Any]] = deque(maxlen=self.window_size)

    @staticmethod
    def _event_is_set(stop_event: Any) -> bool:
        if stop_event is None:
            return False
        checker = getattr(stop_event, "is_set", None)
        if callable(checker):
            return bool(checker())
        return bool(stop_event()) if callable(stop_event) else bool(stop_event)

    def snapshot(self) -> dict[str, Any]:
        """Return the complete credential-free public state for this batch."""
        with self.condition:
            return {
                "configured": self.configured,
                "baseline_concurrency": self.configured,
                "requested_limit": self.requested_limit,
                "effective": self.effective,
                "active": self.active,
                "waiting": self.waiting,
                "optimized": self.optimized,
                "staged": self.staged,
                "rolled_back": self.rolled_back,
                "suspended": self.suspended,
                "sticky_baseline": self.sticky_baseline,
                "resume_eligible": self.resume_eligible,
                "reason": self.reason,
            }

    @contextmanager
    def acquire(self, *, stop_event: Any = None) -> Iterator[None]:
        acquired = False
        registered_waiter = True
        with self.condition:
            self.waiting += 1
        try:
            while not acquired:
                with self.condition:
                    if self._stopped or self._event_is_set(stop_event):
                        self.waiting = max(0, self.waiting - 1)
                        registered_waiter = False
                        raise RuntimeError("task_stopped")
                    if self.active < self.effective:
                        self.active += 1
                        self.waiting = max(0, self.waiting - 1)
                        registered_waiter = False
                        acquired = True
                    else:
                        self.condition.wait(timeout=0.25)
        except BaseException:
            if registered_waiter:
                with self.condition:
                    self.waiting = max(0, self.waiting - 1)
            raise

        try:
            yield
        finally:
            if acquired:
                with self.condition:
                    self.active = max(0, self.active - 1)
                    self.condition.notify_all()

    def wake_all(self) -> None:
        with self.condition:
            self.condition.notify_all()

    def stop(self) -> None:
        with self.condition:
            self._stopped = True
            self.condition.notify_all()

    def suspend(self, reason: Any = "openai_connectivity_suspected") -> dict[str, Any] | None:
        """Temporarily return to baseline while preserving recovery eligibility."""
        stable_reason = str(reason or "").strip().lower()
        if stable_reason not in {
            "openai_connectivity_suspected",
            "openai_connectivity_outage",
            "openai_connectivity_recovering",
        }:
            stable_reason = "openai_connectivity_suspected"
        event: dict[str, Any] | None = None
        with self.condition:
            if self.rolled_back or self.sticky_baseline:
                return None
            old_limit = self.effective
            already_suspended = self.suspended
            self.effective = self.configured
            self.optimized = False
            self.suspended = True
            self.resume_eligible = bool(
                self.optimization_requested
                and self.requested_limit > self.configured
            )
            self.reason = stable_reason
            self.condition.notify_all()
            if not already_suspended or old_limit != self.effective:
                event = {
                    "kind": "task_inflight_optimization_suspended",
                    "reason": stable_reason,
                    "snapshot": self.snapshot_unlocked(),
                }
        return event

    def resume(self) -> dict[str, Any] | None:
        """Restore the configured in-flight expansion after healthy recovery."""
        event: dict[str, Any] | None = None
        with self.condition:
            if not self.suspended or self.rolled_back or self.sticky_baseline:
                return None
            old_limit = self.effective
            self.suspended = False
            can_expand = bool(
                self.resume_eligible
                and self.optimization_requested
                and self.requested_limit > self.configured
            )
            self.resume_eligible = False
            self.effective = (
                max(self.configured, self.requested_limit)
                if can_expand
                else self.configured
            )
            self.optimized = can_expand
            self.reason = "optimized" if can_expand else "configured_baseline"
            self.condition.notify_all()
            event = {
                "kind": "task_inflight_optimization_restored",
                "reason": "openai_connectivity_recovered",
                "old_limit": old_limit,
                "new_limit": self.effective,
                "snapshot": self.snapshot_unlocked(),
            }
        return event

    def snapshot_unlocked(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "baseline_concurrency": self.configured,
            "requested_limit": self.requested_limit,
            "effective": self.effective,
            "active": self.active,
            "waiting": self.waiting,
            "optimized": self.optimized,
            "staged": self.staged,
            "rolled_back": self.rolled_back,
            "suspended": self.suspended,
            "sticky_baseline": self.sticky_baseline,
            "resume_eligible": self.resume_eligible,
            "reason": self.reason,
        }

    def _rollback(self, reason: str) -> dict[str, Any] | None:
        event: dict[str, Any] | None = None
        with self.condition:
            if self.rolled_back:
                return None
            self.effective = self.configured
            self.optimized = False
            self.rolled_back = True
            self.suspended = False
            self.sticky_baseline = True
            self.resume_eligible = False
            self.reason = reason
            self.condition.notify_all()
            event = {
                "kind": "task_inflight_optimization_disabled",
                "reason": reason,
                "snapshot": {
                    "configured": self.configured,
                    "effective": self.effective,
                    "active": self.active,
                    "waiting": self.waiting,
                    "optimized": self.optimized,
                    "staged": self.staged,
                    "rolled_back": self.rolled_back,
                    "suspended": self.suspended,
                    "sticky_baseline": self.sticky_baseline,
                    "resume_eligible": self.resume_eligible,
                    "reason": self.reason,
                },
            }
        if callable(self.on_rollback):
            try:
                self.on_rollback(dict(event))
            except Exception:
                pass
        return event

    def report_pressure(self, reason: Any = "protocol_pressure") -> dict[str, Any] | None:
        """Apply an immediate rollback using only stable, non-secret reason codes."""
        normalized = str(reason or "").strip().lower()
        aliases = {
            "pressure": "protocol_pressure",
            "resource_pressure": "protocol_pressure",
            "infrastructure_pressure": "protocol_pressure",
            "rate_limited": "http_429",
            "429": "http_429",
            "session_invalid": "session_invalidation",
            "oauth_session_invalid": "session_invalidation",
            "auth_session_invalid": "session_invalidation",
        }
        stable_reason = aliases.get(normalized, normalized)
        if stable_reason not in self._IMMEDIATE_REASONS:
            stable_reason = "protocol_pressure"
        return self._rollback(stable_reason)

    def report_http_429(self) -> dict[str, Any] | None:
        return self._rollback("http_429")

    def report_session_invalidation(self) -> dict[str, Any] | None:
        return self._rollback("session_invalidation")

    @staticmethod
    def _task_sample(status: Any, result: Any) -> dict[str, Any]:
        row = result if isinstance(result, Mapping) else {}
        success = (
            bool(row.get("success"))
            if "success" in row
            else str(status or "").strip().lower() == "success"
        )
        outcomes = row.get("sms_order_outcomes")
        order_rows = outcomes if isinstance(outcomes, list) else []
        explicit_orders = _nonnegative_number(
            row.get("orders", row.get("order_count"))
        )
        orders = int(explicit_orders) if explicit_orders is not None else len(order_rows)
        explicit_cancelled = _nonnegative_number(
            row.get("cancelled", row.get("cancellations"))
        )
        cancelled = (
            int(explicit_cancelled)
            if explicit_cancelled is not None
            else sum(
                1
                for item in order_rows
                if isinstance(item, Mapping)
                and str(item.get("status") or "").strip().lower() == "cancelled"
            )
        )
        duplicates = int(
            _nonnegative_number(
                row.get("duplicates", row.get("sms_duplicate_orders"))
            )
            or 0
        )
        cost_usd = _nonnegative_number(row.get("cost_usd", row.get("sms_cost_usd")))
        late_code_loss = bool(
            row.get("late_code_loss") or row.get("confirmed_late_code_loss")
        )
        return {
            "success": success,
            "orders": orders,
            "cancelled": cancelled,
            "duplicates": duplicates,
            "cost_usd": cost_usd,
            "late_code_loss": late_code_loss,
        }

    def observe_task(self, status: Any, result: Any = None) -> dict[str, Any] | None:
        """Evaluate a completed task without retaining task identity or raw errors."""
        sample = self._task_sample(status, result)
        with self.condition:
            self._samples.append(sample)
            if (
                not self.optimized
                or self.rolled_back
                or len(self._samples) < self.window_size
            ):
                return None
            samples = tuple(self._samples)
            successes = sum(1 for item in samples if item["success"])
            success_rate = successes / len(samples)
            orders = sum(int(item["orders"]) for item in samples)
            cancelled = sum(int(item["cancelled"]) for item in samples)
            duplicates = sum(int(item["duplicates"]) for item in samples)
            late_losses = sum(1 for item in samples if item["late_code_loss"])
            known_cost = sum(
                float(item["cost_usd"])
                for item in samples
                if item["cost_usd"] is not None
            )

            reason = ""
            if success_rate < INFLIGHT_SUCCESS_RATE_FLOOR:
                reason = "success_rate_below_819"
            elif late_losses >= 2:
                reason = "two_confirmed_late_code_losses"
            elif (
                orders
                and self.baseline.cancellation_rate is not None
                and cancelled / orders > self.baseline.cancellation_rate
            ):
                reason = "cancellation_rate_increased"
            elif (
                orders
                and self.baseline.duplicate_order_rate is not None
                and duplicates / orders > self.baseline.duplicate_order_rate
            ):
                reason = "duplicate_order_rate_increased"
            elif (
                successes
                and self.baseline.cost_per_success_usd is not None
                and known_cost / successes > self.baseline.cost_per_success_usd * 1.10
            ):
                reason = "cost_per_success_above_110_percent"
        return self._rollback(reason) if reason else None


def resolve_task_admission(
    configured_limit: Any,
    *,
    run_mode: Any = "register",
    adaptive_enabled: Any = True,
) -> TaskAdmissionPolicy:
    """Enable conservative 8 -> 9 -> 10 admission only for registration runs."""
    try:
        task_limit = max(1, min(8, int(configured_limit)))
    except (TypeError, ValueError):
        task_limit = 5
    register_mode = str(run_mode or "register").strip().lower() == "register"
    adaptive = register_mode and task_limit == 8 and as_bool(adaptive_enabled, True)
    ceiling = 10 if adaptive else task_limit
    return TaskAdmissionPolicy(
        base_limit=task_limit,
        restore_ceiling=ceiling,
        absolute_ceiling=ceiling,
        adaptive=adaptive,
    )


def format_task_admission_event(event: Any) -> tuple[str, str] | None:
    """Format a credential-free admission event for the recovered logger."""
    value = dict(event or {}) if isinstance(event, Mapping) else {}
    try:
        old_limit = max(0, int(value.get("old_limit") or 0))
        new_limit = max(0, int(value.get("new_limit") or 0))
    except (TypeError, ValueError):
        return None
    if old_limit <= 0 or new_limit <= 0:
        return None
    kind = str(value.get("kind") or "")
    if kind == "restored":
        return (
            f"[任务并发/registration_admission] 连续成功，任务并发 {old_limit} -> {new_limit}",
            "info",
        )
    if kind == "resource_recovered":
        return (
            f"[任务并发/registration_admission] FD 水位恢复稳定，任务并发 {old_limit} -> {new_limit}",
            "info",
        )
    try:
        pause_seconds = max(0, int(value.get("pause_seconds") or 0))
    except (TypeError, ValueError):
        pause_seconds = 0
    reason = str(value.get("reason") or "")
    if kind == "resource_exhausted" or reason == "resource_fd_exhausted":
        return (
            "[任务并发/registration_admission] 文件描述符耗尽，"
            f"任务并发 {old_limit} -> {new_limit}，暂停新任务 {pause_seconds} 秒",
            "warn",
        )
    return (
        "[任务并发/registration_admission] 基础设施压力达到阈值，"
        f"任务并发 {old_limit} -> {new_limit}，暂停新任务 {pause_seconds} 秒",
        "warn",
    )
