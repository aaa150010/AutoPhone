"""Thread-safe SMS key pooling, balance checks, and cost accounting."""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
import threading
import time
from typing import Any, Callable, Iterator
import urllib.parse
import uuid

try:
    from .protocol_concurrency import (
        ProxyProtocolGate,
        ProtocolPressurePolicy,
        TransportProtocolCoordinator,
        _ProxyProtocolState,
        _notify_observer,
        is_http_429_error,
        is_protocol_pressure_error,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from protocol_concurrency import (  # type: ignore[no-redef]
        ProxyProtocolGate,
        ProtocolPressurePolicy,
        TransportProtocolCoordinator,
        _ProxyProtocolState,
        _notify_observer,
        is_http_429_error,
        is_protocol_pressure_error,
    )

try:
    from .performance_runtime import (
        PERFORMANCE_DEFAULTS,
        PERFORMANCE_POLICY_VERSION,
        PHONE_MAX_ATTEMPTS_LIMIT,
        migrate_performance_config,
    )
    from .sms_order_runtime import (
        ECB_DAILY_URL,
        ExchangeRateCache,
        HeroSmsCancellationDeferred,
        SmsCleanupQueue,
        SmsCostLedger,
        _herosms_min_cancel_seconds,
        _provider_exception_text,
        _safe_provider_token,
        confirm_herosms_cancellation,
        herosms_cancel_delay_seconds,
        safe_cancel_receipt,
    )
    from .sms_provider_runtime import (
        SECRET_MASK,
        SMS_PROVIDER_ALIASES,
        SMS_PROVIDER_DEFAULT_SERVICES,
        SmsProviderBatchHealth,
        flatten_sms_provider_keys,
        legacy_sms_provider_keys,
        normalize_sms_keys,
        normalize_sms_provider_name,
        normalize_sms_provider_pools,
    )
    from .sms_route_runtime import (
        SmsRoutePolicy,
        SmsWaitPlan,
        _candidate_value as _route_candidate_value,
        build_sms_wait_plan,
        candidate_route,
        delivery_quality,
        has_better_mature_alternative,
        is_degraded_route,
        is_mature_delivery_route,
        rank_sms_candidates,
        route_stat as _route_stat_value,
        wilson_lower_bound,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from performance_runtime import (  # type: ignore[no-redef]
        PERFORMANCE_DEFAULTS,
        PERFORMANCE_POLICY_VERSION,
        PHONE_MAX_ATTEMPTS_LIMIT,
        migrate_performance_config,
    )
    from sms_order_runtime import (  # type: ignore[no-redef]
        ECB_DAILY_URL,
        ExchangeRateCache,
        HeroSmsCancellationDeferred,
        SmsCleanupQueue,
        SmsCostLedger,
        _herosms_min_cancel_seconds,
        _provider_exception_text,
        _safe_provider_token,
        confirm_herosms_cancellation,
        herosms_cancel_delay_seconds,
        safe_cancel_receipt,
    )
    from sms_provider_runtime import (  # type: ignore[no-redef]
        SECRET_MASK,
        SMS_PROVIDER_ALIASES,
        SMS_PROVIDER_DEFAULT_SERVICES,
        SmsProviderBatchHealth,
        flatten_sms_provider_keys,
        legacy_sms_provider_keys,
        normalize_sms_keys,
        normalize_sms_provider_name,
        normalize_sms_provider_pools,
    )
    from sms_route_runtime import (  # type: ignore[no-redef]
        SmsRoutePolicy,
        SmsWaitPlan,
        _candidate_value as _route_candidate_value,
        build_sms_wait_plan,
        candidate_route,
        delivery_quality,
        has_better_mature_alternative,
        is_degraded_route,
        is_mature_delivery_route,
        rank_sms_candidates,
        route_stat as _route_stat_value,
        wilson_lower_bound,
    )

try:
    from .sms_balance_runtime import (
        query_key_pool_balances,
        query_registry_balances,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_balance_runtime import (  # type: ignore[no-redef]
        query_key_pool_balances,
        query_registry_balances,
    )



try:
    from .sms_network import (
        SMS_FIRST_WAIT_SECONDS,
        SMS_NETWORK_ATTEMPTS,
        SMS_POLL_INTERVAL_SECONDS,
        SMS_PREFLIGHT_MAX_WORKERS,
        SMS_SECOND_WAIT_SECONDS,
        SingleFlightTtlCache,
        _StaleSmsPreflight,
        _as_float,
        _candidate_route,
        _candidate_value,
        _route_stat,
        call_sms_with_retries,
        classify_key_error,
        isolated_sms_get,
        is_sms_route_infrastructure_error,
        is_transient_sms_network_error,
        key_fingerprint,
        parse_sms_balance,
        redact_sms_secrets,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_network import (  # type: ignore[no-redef]
        SMS_FIRST_WAIT_SECONDS,
        SMS_NETWORK_ATTEMPTS,
        SMS_POLL_INTERVAL_SECONDS,
        SMS_PREFLIGHT_MAX_WORKERS,
        SMS_SECOND_WAIT_SECONDS,
        SingleFlightTtlCache,
        _StaleSmsPreflight,
        _as_float,
        _candidate_route,
        _candidate_value,
        _route_stat,
        call_sms_with_retries,
        classify_key_error,
        isolated_sms_get,
        is_sms_route_infrastructure_error,
        is_transient_sms_network_error,
        key_fingerprint,
        parse_sms_balance,
        redact_sms_secrets,
    )

try:
    from .sms_key_pool import SmsKeyHealth, SmsKeyPool, PooledSmsBowerProvider, _SmsKeyReservation
    from .sms_provider_orchestration import SmsProviderRegistry, PooledSmsProvider, _sms_timeout_error
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_key_pool import SmsKeyHealth, SmsKeyPool, PooledSmsBowerProvider, _SmsKeyReservation  # type: ignore[no-redef]
    from sms_provider_orchestration import SmsProviderRegistry, PooledSmsProvider, _sms_timeout_error  # type: ignore[no-redef]


class PhoneSubmissionGate:
    def __init__(
        self,
        concurrency: int = 2,
        interval_seconds: float = 0.75,
        *,
        ceiling: int = 5,
        restore_successes: int = 4,
        now_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_limit = max(1, min(5, int(concurrency)))
        self.ceiling = max(self.base_limit, min(5, int(ceiling)))
        self.limit = self.base_limit
        self.restore_successes = max(1, int(restore_successes))
        self.interval_seconds = max(0.0, float(interval_seconds))
        self.now_fn = now_fn
        self.sleep_fn = sleep_fn
        self.spacing_lock = threading.Lock()
        self.status_condition = threading.Condition()
        self.active = 0
        self.waiting = 0
        self.last_started_at = 0.0
        self.not_before = 0.0
        self.transient_streak = 0
        self.success_streak = 0
        self.restorations = 0
        self.degradations = 0

    def begin_run(self) -> None:
        with self.spacing_lock:
            self.last_started_at = 0.0
            self.not_before = 0.0
            self.transient_streak = 0
        with self.status_condition:
            self.limit = self.base_limit
            self.success_streak = 0
            self.restorations = 0
            self.degradations = 0
            self.status_condition.notify_all()

    def configure(self, concurrency: Any) -> int:
        try:
            limit = int(concurrency)
        except (TypeError, ValueError):
            limit = 2
        with self.status_condition:
            self.base_limit = max(1, min(5, limit))
            self.ceiling = max(self.base_limit, 5)
            self.limit = self.base_limit
            self.success_streak = 0
            self.status_condition.notify_all()
            return self.limit

    def report_transient(self) -> float:
        with self.spacing_lock:
            self.transient_streak += 1
            delay = min(8.0, 2.0 ** self.transient_streak)
            self.not_before = max(self.not_before, self.now_fn() + delay)
        with self.status_condition:
            self.success_streak = 0
            if self.limit > self.base_limit:
                self.limit -= 1
                self.degradations += 1
                self.status_condition.notify_all()
        return delay

    def report_success(self) -> None:
        with self.spacing_lock:
            self.transient_streak = 0
        with self.status_condition:
            self.success_streak += 1
            if self.success_streak >= self.restore_successes and self.limit < self.ceiling:
                self.limit += 1
                self.success_streak = 0
                self.restorations += 1
                self.status_condition.notify_all()

    def report_business_failure(self) -> None:
        with self.spacing_lock:
            self.transient_streak = 0
        with self.status_condition:
            self.success_streak = 0

    def status(self) -> dict[str, int]:
        with self.status_condition:
            return {
                "active": self.active,
                "base": self.base_limit,
                "limit": self.limit,
                "ceiling": self.ceiling,
                "waiting": self.waiting,
                "success_streak": self.success_streak,
                "restorations": self.restorations,
                "degradations": self.degradations,
            }

    @staticmethod
    def _stopped(stop_event: Any) -> bool:
        return ProxyProtocolGate._stopped(stop_event)

    def _acquire(self, stop_event: Any) -> None:
        with self.status_condition:
            self.waiting += 1
        try:
            with self.status_condition:
                while True:
                    if self._stopped(stop_event):
                        raise RuntimeError("task_stopped")
                    if self.active < self.limit:
                        self.active += 1
                        return
                    self.status_condition.wait(timeout=0.25)
        finally:
            with self.status_condition:
                self.waiting = max(0, self.waiting - 1)

    def _release(self) -> None:
        with self.status_condition:
            self.active = max(0, self.active - 1)
            self.status_condition.notify_all()

    def _wait(self, seconds: float, stop_event: Any) -> None:
        remaining = max(0.0, float(seconds))
        if stop_event is None:
            self.sleep_fn(remaining)
            return
        while remaining > 0:
            if self._stopped(stop_event):
                raise RuntimeError("task_stopped")
            chunk = min(0.25, remaining)
            self.sleep_fn(chunk)
            remaining -= chunk

    def call(
        self,
        function: Callable[..., Any],
        *args: Any,
        stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        return self._call_once(
            function,
            *args,
            stop_event=stop_event,
            on_wait=on_wait,
            **kwargs,
        )

    def _call_once(
        self,
        function: Callable[..., Any],
        *args: Any,
        stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
        before_release: Callable[[Any, Exception | None], Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        wait_started = float(self.now_fn())
        acquired = False
        wait_reported = False
        try:
            self._acquire(stop_event)
            acquired = True
            while True:
                with self.spacing_lock:
                    now = self.now_fn()
                    wait_for = max(
                        self.interval_seconds - (now - self.last_started_at),
                        self.not_before - now,
                    )
                    if wait_for <= 0:
                        self.last_started_at = now
                        break
                if wait_for > 0:
                    self._wait(wait_for, stop_event)
            _notify_observer(
                on_wait,
                max(0.0, float(self.now_fn()) - wait_started),
            )
            wait_reported = True
            try:
                result = function(*args, **kwargs)
            except Exception as exc:
                if callable(before_release):
                    before_release(None, exc)
                raise
            if callable(before_release):
                before_release(result, None)
            return result
        finally:
            if not wait_reported:
                _notify_observer(
                    on_wait,
                    max(0.0, float(self.now_fn()) - wait_started),
                )
            if acquired:
                self._release()

    def call_with_retries(
        self,
        function: Callable[..., Any],
        *args: Any,
        is_transient: Callable[[Any], bool],
        should_retry: Callable[[Any], bool] | None = None,
        max_attempts: int = 4,
        on_retry: Callable[[float, int], None] | None = None,
        stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        attempts = max(1, int(max_attempts))
        last_error: Any = None
        for attempt in range(1, attempts + 1):
            outcome = {"transient": False, "retry_allowed": True, "delay": 0.0}

            def classify_before_release(result: Any, error: Exception | None) -> None:
                value = error if error is not None else result
                if is_transient(value):
                    outcome["transient"] = True
                    if callable(should_retry):
                        outcome["retry_allowed"] = bool(should_retry(value))
                    outcome["delay"] = self.report_transient()
                    return
                if error is not None:
                    self.report_business_failure()
                    return
                status = (
                    int(_as_float(result.get("_status") or result.get("status"), 0))
                    if isinstance(result, Mapping)
                    else 200
                )
                if not isinstance(result, Mapping) or 200 <= status < 300:
                    self.report_success()
                else:
                    self.report_business_failure()

            try:
                result = self._call_once(
                    function,
                    *args,
                    stop_event=stop_event,
                    on_wait=on_wait,
                    before_release=classify_before_release,
                    **kwargs,
                )
            except Exception as exc:
                if not outcome["transient"]:
                    raise
                last_error = exc
            else:
                if not outcome["transient"]:
                    return result
                last_error = result

            if not outcome["retry_allowed"]:
                if isinstance(last_error, Exception):
                    raise last_error
                return last_error

            delay = float(outcome["delay"])
            if attempt < attempts and callable(on_retry):
                try:
                    on_retry(delay, attempt)
                except Exception:
                    pass

        if isinstance(last_error, Exception):
            raise last_error
        return last_error


def is_transient_openai_error(value: Any) -> bool:
    status = None
    if isinstance(value, Mapping):
        error = value.get("error") or value.get("message") or ""
        if isinstance(error, Mapping):
            error = f"{error.get('code') or ''} {error.get('message') or ''}"
        for key in ("_status", "status", "status_code", "http_status"):
            if key not in value:
                continue
            try:
                status = int(float(value.get(key)))
            except (TypeError, ValueError):
                status = None
            break
        text = str(error).lower()
        if status == 0 or status == 429 or (status is not None and 500 <= status < 600):
            return True
        if status is not None and 400 <= status < 500:
            return False
    else:
        text = str(value or "").lower()
    if "sms_timeout" in text:
        return False
    return any(
        marker in text
        for marker in (
            "the server had an error processing your request",
            "internal server error",
            "temporarily unavailable",
            "service unavailable",
            "upstream connect error",
            "readtimeout",
            "connecttimeout",
            "timed out",
            "timeout",
            "connection reset",
            "connection aborted",
            "connection refused",
            "remote disconnected",
            "remote end closed connection",
            "server disconnected",
            "proxyerror",
            "proxy error",
            "network is unreachable",
            "temporary failure in name resolution",
            "name resolution",
        )
    )


class RuntimeAlertBuffer:
    def __init__(self, limit: int = 100) -> None:
        self.limit = max(1, int(limit))
        self.lock = threading.Lock()
        self.items: list[dict[str, Any]] = []
        self.seen: set[str] = set()
        self.sequence = 0
        self.generation = uuid.uuid4().hex

    def begin_run(self) -> None:
        with self.lock:
            self.items.clear()
            self.seen.clear()

    def add(
        self,
        kind: str,
        message: str,
        *,
        level: str = "warning",
        dedupe_key: str = "",
        persistent: bool = True,
        **extra: Any,
    ) -> dict[str, Any] | None:
        key = dedupe_key or f"{kind}:{message}"
        with self.lock:
            if key in self.seen:
                return None
            self.seen.add(key)
            self.sequence += 1
            item = {
                "id": f"sms-alert-{self.sequence}",
                "generation": self.generation,
                "kind": kind,
                "level": level,
                "message": str(message),
                "persistent": bool(persistent),
                "created_at": int(time.time()),
                **extra,
            }
            self.items.append(item)
            self.items = self.items[-self.limit :]
            return dict(item)

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(item) for item in self.items]


__all__ = [
    "PhoneSubmissionGate",
    "is_transient_openai_error",
    "RuntimeAlertBuffer",
]
