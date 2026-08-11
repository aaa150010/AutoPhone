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


SMS_PREFLIGHT_MAX_WORKERS = 8
SMS_NETWORK_ATTEMPTS = 3
SMS_FIRST_WAIT_SECONDS = 30
SMS_SECOND_WAIT_SECONDS = 30
SMS_POLL_INTERVAL_SECONDS = 3


def key_fingerprint(key: str) -> str:
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:10]


def redact_sms_secrets(value: Any, secrets: list[str]) -> str:
    text = str(value or "")
    candidates = [
        secret
        for secret in normalize_sms_keys(secrets)
        if not set(secret).issubset({"*"})
    ]
    for secret in sorted(candidates, key=len, reverse=True):
        variants = {
            secret,
            urllib.parse.quote(secret, safe=""),
            urllib.parse.quote_plus(secret, safe=""),
        }
        for variant in sorted(variants, key=len, reverse=True):
            text = text.replace(variant, SECRET_MASK)
    return text


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


class SingleFlightTtlCache:
    """Deduplicate concurrent loads and briefly cache empty results."""

    def __init__(self, *, now_fn: Callable[[], float] = time.monotonic) -> None:
        self.now_fn = now_fn
        self.condition = threading.Condition()
        self.values: dict[Any, tuple[float, Any]] = {}
        self.loading: set[Any] = set()

    def clear(self) -> None:
        with self.condition:
            self.values.clear()

    def get_or_load(
        self,
        key: Any,
        loader: Callable[[], Any],
        *,
        ttl_seconds: float,
        empty_ttl_seconds: float,
    ) -> Any:
        while True:
            with self.condition:
                now = self.now_fn()
                cached = self.values.get(key)
                if cached is not None and cached[0] > now:
                    return cached[1]
                if key not in self.loading:
                    self.loading.add(key)
                    break
                self.condition.wait()

        try:
            value = loader()
        except BaseException:
            with self.condition:
                self.loading.discard(key)
                self.condition.notify_all()
            raise

        ttl = ttl_seconds if value else empty_ttl_seconds
        with self.condition:
            now = self.now_fn()
            self.values[key] = (now + max(0.0, float(ttl)), value)
            self.loading.discard(key)
            self.condition.notify_all()
        return value


class _StaleSmsPreflight(RuntimeError):
    """Stop obsolete preflight work before it uses superseded credentials."""


def _candidate_route(candidate: Any) -> tuple[str, str]:
    return candidate_route(candidate)


def _candidate_value(candidate: Any, name: str, default: Any = None) -> Any:
    """Compatibility export retained for runtime monkeypatch consumers."""
    return _route_candidate_value(candidate, name, default)


def _route_stat(route_stats: Any, route: tuple[str, str]) -> dict[str, Any]:
    """Compatibility export retained for runtime monkeypatch consumers."""
    return _route_stat_value(route_stats, route)


def parse_sms_balance(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        for key in ("balance", "amount", "value"):
            if key in value:
                return parse_sms_balance(value[key])
    text = str(value or "").strip()
    if text.startswith("{"):
        try:
            return parse_sms_balance(json.loads(text))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    match = re.search(r"(?:ACCESS_BALANCE:)?\s*(-?\d+(?:\.\d+)?)", text, re.I)
    if not match:
        raise ValueError(f"无法解析 SMS 余额响应: {text[:120] or 'empty'}")
    return float(match.group(1))


def classify_key_error(error: Any) -> str:
    text = str(error or "").lower()
    if any(marker in text for marker in ("no_balance", "no balance", "insufficient balance", "余额不足")):
        return "insufficient_balance"
    if any(marker in text for marker in ("bad_key", "wrong_key", "invalid api key", "status=401", "status=403")):
        return "invalid"
    if any(marker in text for marker in ("status=429", "too many requests", "rate limit", "ratelimit")):
        return "rate_limited"
    if any(
        marker in text
        for marker in (
            "timed out",
            "timeout",
            "urlopen error",
            "connection",
            "network",
            "ssl",
            "temporary failure",
        )
    ):
        return "network_error"
    return "other"


def is_transient_sms_network_error(value: Any) -> bool:
    text = str(value or "").lower()
    return any(
        marker in text
        for marker in (
            "timed out",
            "timeout",
            "connection reset",
            "connection aborted",
            "connection refused",
            "remote disconnected",
            "proxyerror",
            "proxy error",
            "ssleoferror",
            "sslerror",
            "tls",
            "unexpected_eof",
            "temporary failure",
            "network is unreachable",
            "name resolution",
        )
    )


def call_sms_with_retries(
    function: Callable[[], Any],
    *,
    attempts: int = SMS_NETWORK_ATTEMPTS,
    sleep_fn: Callable[[float], None] = time.sleep,
    deadline: float | None = None,
    now_fn: Callable[[], float] = time.monotonic,
) -> Any:
    last_error: Exception | None = None
    for attempt in range(max(1, int(attempts))):
        try:
            return function()
        except Exception as exc:
            if not is_transient_sms_network_error(exc):
                raise
            last_error = exc
        if attempt + 1 >= max(1, int(attempts)):
            break
        delay = min(1.5, 0.25 * (2 ** attempt))
        if deadline is not None:
            remaining = float(deadline) - float(now_fn())
            if remaining <= 0:
                break
            delay = min(delay, remaining)
        if delay > 0:
            sleep_fn(delay)
    assert last_error is not None
    raise last_error


def isolated_sms_get(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    proxy: str = "",
    timeout: int = 30,
    as_json: bool = False,
    session_factory: Callable[[], Any] | None = None,
) -> Any:
    """Perform one SMS API GET without inheriting host proxy variables."""

    if session_factory is None:
        from curl_cffi import requests as curl_requests

        session_factory = lambda: curl_requests.Session(impersonate="chrome")
    session = session_factory()
    if hasattr(session, "trust_env"):
        session.trust_env = False
    request_kwargs: dict[str, Any] = {
        "params": dict(params or {}),
        "headers": dict(headers or {}),
        "timeout": max(1, int(timeout)),
    }
    if proxy:
        request_kwargs["proxy"] = str(proxy)
        request_kwargs["verify"] = False
    response = session.get(str(url), **request_kwargs)
    if as_json:
        return response.json()
    return str(getattr(response, "text", "") or "").strip()


def is_sms_route_infrastructure_error(value: Any) -> bool:
    """Return whether an SMS outcome says nothing about route quality."""
    if isinstance(value, Mapping):
        status_value = (
            value.get("_status")
            or value.get("status")
            or value.get("status_code")
        )
    else:
        status_value = (
            getattr(value, "status_code", None)
            or getattr(getattr(value, "response", None), "status_code", None)
        )
    if int(_as_float(status_value, 0)) == 429:
        return True

    type_name = "" if value is None else type(value).__name__
    text = f"{type_name}: {value or ''}".lower()
    if re.search(r"\b429\b", text) and any(
        marker in text
        for marker in ("http", "status", "too many requests", "rate limit")
    ):
        return True
    return any(
        marker in text
        for marker in (
            "tls",
            "ssl",
            "unexpected_eof",
            "connection",
            "connecterror",
            "connect error",
            "failed to connect",
            "remote disconnected",
            "server disconnected",
            "proxy",
            "curl",
            "network is unreachable",
            "name resolution",
            "too many requests",
            "rate limit",
            "ratelimit",
        )
    )


@dataclass
class SmsKeyHealth:
    key: str = field(repr=False)
    index: int = 0
    fingerprint: str = ""
    status: str = "unchecked"
    balance_usd: float | None = None
    message: str = ""
    in_flight: int = 0
    cooldown_until: float = 0.0
    last_checked_at: float = 0.0
    health_revision: int = 0

    def public(self, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
        return {
            "index": self.index,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "balance_usd": None if self.balance_usd is None else round(self.balance_usd, 4),
            "message": self.message,
            "in_flight": self.in_flight,
            "retry_after_seconds": max(0, int(self.cooldown_until - current)),
            "last_checked_at": int(self.last_checked_at or 0),
        }


@dataclass(frozen=True)
class _SmsKeyReservation:
    state: SmsKeyHealth
    health_revision: int


class SmsKeyPool:
    """Selects a healthy SMSBower account and binds each activation to it."""

    def __init__(
        self,
        provider_factory: Callable[..., Any],
        *,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.provider_factory = provider_factory
        self.now_fn = now_fn
        self.lock = threading.RLock()
        self.price_floor_cache = SingleFlightTtlCache(now_fn=now_fn)
        self.states: list[SmsKeyHealth] = []
        self.cursor = 0
        self.preflight_generation = 0
        self.service = "dr"
        self.min_price = 0.01
        self.max_price = 0.15
        self.logger: Callable[[str, str], None] | None = None
        self.alert_fn: Callable[[dict[str, Any]], None] | None = None
        self.exhausted_fn: Callable[[], None] | None = None
        self.alerted: set[tuple[str, str]] = set()
        self.exhaustion_reported = False

    def configure(
        self,
        keys: list[str],
        *,
        service: str = "dr",
        min_price: float = 0.01,
        max_price: float = 0.15,
        logger: Callable[[str, str], None] | None = None,
        alert_fn: Callable[[dict[str, Any]], None] | None = None,
        exhausted_fn: Callable[[], None] | None = None,
    ) -> None:
        normalized = normalize_sms_keys(keys)
        fingerprints = [key_fingerprint(key) for key in normalized]
        with self.lock:
            self.preflight_generation += 1
            existing = {state.fingerprint: state for state in self.states}
            if fingerprints != [state.fingerprint for state in self.states]:
                self.states = [
                    SmsKeyHealth(
                        key=key,
                        index=index,
                        fingerprint=fingerprint,
                        status=existing.get(fingerprint, SmsKeyHealth(key)).status,
                        balance_usd=existing.get(fingerprint, SmsKeyHealth(key)).balance_usd,
                        message=existing.get(fingerprint, SmsKeyHealth(key)).message,
                        cooldown_until=existing.get(fingerprint, SmsKeyHealth(key)).cooldown_until,
                        last_checked_at=existing.get(fingerprint, SmsKeyHealth(key)).last_checked_at,
                        health_revision=existing.get(fingerprint, SmsKeyHealth(key)).health_revision,
                    )
                    for index, (key, fingerprint) in enumerate(zip(normalized, fingerprints), start=1)
                ]
                self.cursor = 0
                self.alerted.clear()
                self.exhaustion_reported = False
            self.service = str(service or "dr").strip() or "dr"
            self.min_price = max(0.0, _as_float(min_price, 0.01))
            self.max_price = max(self.min_price, _as_float(max_price, 0.15))
            if logger is not None:
                self.logger = logger
            if alert_fn is not None:
                self.alert_fn = alert_fn
            if exhausted_fn is not None:
                self.exhausted_fn = exhausted_fn

    def begin_run(self) -> None:
        with self.lock:
            self.preflight_generation += 1
            for state in self.states:
                state.in_flight = 0
            self.alerted.clear()
            self.exhaustion_reported = False

    def reset_terminal_states(self) -> None:
        """Allow one fresh health check when a new registry batch is configured."""
        with self.lock:
            for state in self.states:
                if state.status not in {"insufficient_balance", "invalid"}:
                    continue
                state.status = "unchecked"
                state.message = "待检查"
                state.cooldown_until = 0.0
                state.health_revision += 1
            self.exhaustion_reported = False

    def has_keys(self) -> bool:
        with self.lock:
            return bool(self.states)

    def public_statuses(self) -> list[dict[str, Any]]:
        with self.lock:
            now = self.now_fn()
            return [state.public(now) for state in self.states]

    def safe_error(self, error: Any, extra_secrets: Any = None) -> str:
        with self.lock:
            secrets = [state.key for state in self.states]
        secrets.extend(normalize_sms_keys(extra_secrets))
        return redact_sms_secrets(error, secrets)

    def usable_count(self) -> int:
        with self.lock:
            return sum(1 for state in self.states if state.status == "usable")

    def unusable_count(self) -> int:
        with self.lock:
            return sum(1 for state in self.states if state.status != "usable")

    def all_balance_insufficient(self) -> bool:
        with self.lock:
            return bool(self.states) and all(state.status == "insufficient_balance" for state in self.states)

    def is_exhausted(self) -> bool:
        with self.lock:
            return self._hard_exhausted_locked()

    def _hard_exhausted_locked(self) -> bool:
        return bool(self.states) and all(state.status in {"insufficient_balance", "invalid"} for state in self.states)

    def _log(self, message: str, level: str = "info") -> None:
        if callable(self.logger):
            try:
                self.logger(message, level)
            except Exception:
                pass

    def _emit_alert_locked(self, state: SmsKeyHealth, kind: str, message: str) -> None:
        alert_key = (state.fingerprint, kind)
        if alert_key in self.alerted:
            return
        self.alerted.add(alert_key)
        payload = {
            "kind": kind,
            "index": state.index,
            "fingerprint": state.fingerprint,
            "message": message,
        }
        if callable(self.alert_fn):
            try:
                self.alert_fn(payload)
            except Exception:
                pass

    def _mark_error(
        self,
        state: SmsKeyHealth,
        error: Any,
        *,
        runtime: bool,
        expected_revision: int | None = None,
        expected_generation: int | None = None,
    ) -> str:
        kind = classify_key_error(error)
        now = self.now_fn()
        text = self.safe_error(error, [state.key])
        with self.lock:
            if expected_generation is not None and self.preflight_generation != expected_generation:
                return kind
            if expected_revision is not None and state.health_revision != expected_revision:
                return kind
            state.health_revision += 1
            state.last_checked_at = now
            if kind == "insufficient_balance":
                state.status = kind
                state.balance_usd = 0.0
                state.message = "余额不足"
                state.cooldown_until = 0.0
            elif kind == "invalid":
                state.status = kind
                state.message = "API Key 无效"
                state.cooldown_until = 0.0
            elif kind == "rate_limited":
                state.status = kind
                state.message = "请求限流，稍后重试"
                state.cooldown_until = now + 60
            elif kind == "network_error":
                state.status = kind
                state.message = "网络请求失败，稍后重试"
                state.cooldown_until = now + 30
            elif runtime:
                state.status = "usable"
                state.message = "可用"
                state.cooldown_until = 0.0
            else:
                state.status = "error"
                state.message = text[:160] or "余额查询失败"
                state.cooldown_until = 0.0
            if runtime and kind in {"insufficient_balance", "invalid", "rate_limited", "network_error"}:
                label = {
                    "insufficient_balance": "余额不足",
                    "invalid": "API Key 无效",
                    "rate_limited": "请求被限流",
                    "network_error": "网络异常",
                }[kind]
                message = f"SMS Key {state.index}（{state.fingerprint}）{label}，已切换其他 Key"
                self._emit_alert_locked(state, kind, message)
                self._log(message, "warn")
        return kind

    def report_error(self, state: SmsKeyHealth | None, error: Any, *, runtime: bool = True) -> str:
        if state is None:
            return classify_key_error(error)
        return self._mark_error(state, error, runtime=runtime)

    def _query_price_floor(
        self,
        proxy: str,
        states: list[SmsKeyHealth],
        *,
        expected_generation: int,
    ) -> float:
        with self.lock:
            service = self.service
            min_price = self.min_price
            max_price = self.max_price
        preferred = sorted(
            states,
            key=lambda state: (state.status != "usable", state.index),
        )[:2]
        cache_key = (
            tuple(state.fingerprint for state in preferred),
            service,
            min_price,
            max_price,
            key_fingerprint(proxy) if proxy else "direct",
        )

        def ensure_current() -> None:
            with self.lock:
                if self.preflight_generation != expected_generation:
                    raise _StaleSmsPreflight

        def load_price_floor() -> float | None:
            for state in preferred:
                ensure_current()
                try:
                    provider = self.provider_factory(state.key, proxy=proxy)
                    rows = provider.get_price_candidates(service=service)
                except Exception:
                    continue
                prices = []
                for row in rows or []:
                    if not isinstance(row, dict):
                        continue
                    price = _as_float(row.get("price"), -1)
                    count = int(_as_float(row.get("count"), 0))
                    if count > 0 and min_price <= price <= max_price:
                        prices.append(price)
                if prices:
                    return min(prices)
            return None

        if not preferred:
            return min_price
        ensure_current()
        value = self.price_floor_cache.get_or_load(
            cache_key,
            load_price_floor,
            ttl_seconds=60,
            empty_ttl_seconds=5,
        )
        return min_price if value is None else float(value)

    def query_balances(
        self,
        *,
        proxy: str = "",
        update_state: bool = True,
    ) -> list[dict[str, Any]]:
        return query_key_pool_balances(
            self,
            proxy=proxy,
            update_state=update_state,
            parse_balance=parse_sms_balance,
            max_workers=SMS_PREFLIGHT_MAX_WORKERS,
        )

    def preflight(self, *, proxy: str = "") -> list[dict[str, Any]]:
        with self.lock:
            states = list(self.states)
            self.preflight_generation += 1
            generation = self.preflight_generation
            revisions = {
                id(state): state.health_revision
                for state in states
            }
        if not states:
            return []

        def check_balance(
            state: SmsKeyHealth,
        ) -> tuple[SmsKeyHealth, int, float, float | None, Exception | None]:
            revision = revisions[id(state)]
            now = self.now_fn()
            try:
                provider = self.provider_factory(state.key, proxy=proxy)
                balance = parse_sms_balance(provider.balance())
            except Exception as exc:
                return state, revision, now, None, exc
            return state, revision, now, balance, None

        workers = min(SMS_PREFLIGHT_MAX_WORKERS, len(states))
        if workers == 1:
            results = [check_balance(states[0])]
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sms-preflight") as executor:
                results = list(executor.map(check_balance, states))

        try:
            price_floor = self._query_price_floor(
                proxy,
                [state for state, _revision, _now, balance, error in results if error is None and balance is not None],
                expected_generation=generation,
            )
        except _StaleSmsPreflight:
            return self.public_statuses()

        for state, revision, now, balance, error in results:
            if error is not None:
                self._mark_error(
                    state,
                    error,
                    runtime=False,
                    expected_revision=revision,
                    expected_generation=generation,
                )
                continue
            with self.lock:
                if self.preflight_generation != generation:
                    continue
                if state.health_revision != revision:
                    continue
                assert balance is not None
                state.health_revision += 1
                state.balance_usd = balance
                state.last_checked_at = now
                state.cooldown_until = 0.0
                if balance + 1e-9 < price_floor:
                    state.status = "insufficient_balance"
                    state.message = f"余额不足，最低可用报价 ${price_floor:.4f}"
                else:
                    state.status = "usable"
                    state.message = "可用"
        return self.public_statuses()

    def _state_selectable_locked(self, state: SmsKeyHealth, now: float) -> bool:
        if state.status in {"usable", "unchecked"}:
            return True
        if state.status in {"rate_limited", "network_error"} and state.cooldown_until <= now:
            return True
        return False

    def _reserve_state(self, excluded: set[str]) -> _SmsKeyReservation | None:
        with self.lock:
            now = self.now_fn()
            selectable = [
                state
                for state in self.states
                if state.fingerprint not in excluded and self._state_selectable_locked(state, now)
            ]
            if not selectable:
                return None
            count = max(1, len(self.states))
            state = min(
                selectable,
                key=lambda item: (item.in_flight, (item.index - 1 - self.cursor) % count),
            )
            state.in_flight += 1
            self.cursor = state.index % count
            return _SmsKeyReservation(state, state.health_revision)

    def _mark_success(self, reservation: _SmsKeyReservation) -> bool:
        with self.lock:
            state = reservation.state
            if state.health_revision != reservation.health_revision:
                return False
            state.health_revision += 1
            state.status = "usable"
            state.message = "可用"
            state.cooldown_until = 0.0
            return True

    def _release_state(self, state: SmsKeyHealth | None) -> None:
        callback = None
        with self.lock:
            if state is not None:
                state.in_flight = max(0, state.in_flight - 1)
            if self._hard_exhausted_locked() and not self.exhaustion_reported:
                self.exhaustion_reported = True
                callback = self.exhausted_fn
        if callable(callback):
            try:
                callback()
            except Exception:
                pass

    def query(self, method: str, *, proxy: str = "", **kwargs: Any) -> Any:
        excluded: set[str] = set()
        while True:
            reservation = self._reserve_state(excluded)
            if reservation is None:
                raise RuntimeError(self.unavailable_error())
            state = reservation.state
            try:
                provider = self.provider_factory(state.key, proxy=proxy)
                result = getattr(provider, method)(**kwargs)
            except Exception as exc:
                kind = self._mark_error(state, exc, runtime=True)
                self._release_state(state)
                if kind in {"insufficient_balance", "invalid", "rate_limited", "network_error"}:
                    excluded.add(state.fingerprint)
                    continue
                raise RuntimeError(self.safe_error(exc, [state.key])) from exc
            self._release_state(state)
            self._mark_success(reservation)
            return result

    def activate(
        self,
        method: str,
        *,
        proxy: str = "",
        price_usd: float | None = None,
        **kwargs: Any,
    ) -> tuple[Any, SmsKeyHealth, tuple[str, str]]:
        excluded: set[str] = set()
        while True:
            reservation = self._reserve_state(excluded)
            if reservation is None:
                raise RuntimeError(self.unavailable_error())
            state = reservation.state
            try:
                provider = self.provider_factory(state.key, proxy=proxy)
                activation = getattr(provider, method)(**kwargs)
            except Exception as exc:
                kind = self._mark_error(state, exc, runtime=True)
                self._release_state(state)
                if kind in {"insufficient_balance", "invalid", "rate_limited", "network_error"}:
                    excluded.add(state.fingerprint)
                    continue
                raise RuntimeError(self.safe_error(exc, [state.key])) from exc
            self._mark_success(reservation)
            return provider, state, activation

    def release(self, state: SmsKeyHealth | None) -> None:
        self._release_state(state)

    def unavailable_error(self) -> str:
        with self.lock:
            if self._hard_exhausted_locked():
                if any(state.status == "insufficient_balance" for state in self.states):
                    return "sms_balance_insufficient: 所有可用 SMS Key 余额不足"
                return "sms_key_pool_unavailable: 所有 SMS Key 均不可用"
            if self.states:
                return "sms_key_pool_temporarily_unavailable: SMS Key 暂时不可用"
            return "sms_key_missing: 请至少填写一个 SMS API Key"


class PooledSmsBowerProvider:
    """Provider-compatible facade that keeps an activation on its selected key."""

    SMART_ANY_PROVIDER_FALLBACK = True
    SMART_COUNTRY_SCOPE_FILTER = True
    SMART_FIXED_COUNTRY_FALLBACK = False

    def __init__(self, pool: SmsKeyPool, *, proxy: str = "") -> None:
        self.pool = pool
        self.proxy = proxy
        self.api_key = ""
        self.activation_id: str | None = None
        self.phone: str | None = None
        self._provider: Any = None
        self._state: SmsKeyHealth | None = None
        self._released = True
        self.current_order_meta: dict[str, Any] = {}

    def balance(self) -> str:
        statuses = self.pool.public_statuses()
        total = sum(float(item.get("balance_usd") or 0) for item in statuses if item.get("status") == "usable")
        return f"ACCESS_BALANCE:{total:.4f}"

    def get_price_candidates(self, service: str = "dr", countries: list[str] | None = None) -> list[dict[str, Any]]:
        return self.pool.query(
            "get_price_candidates",
            proxy=self.proxy,
            service=service,
            countries=countries,
        )

    def get_available_countries(self, service: str = "dr") -> Any:
        return self.pool.query("get_available_countries", proxy=self.proxy, service=service)

    def _activate(self, method: str, price_usd: float | None = None, **kwargs: Any) -> tuple[str, str]:
        if not self._released:
            raise RuntimeError("SMS provider already has an active activation")
        provider, state, activation = self.pool.activate(
            method,
            proxy=self.proxy,
            price_usd=price_usd,
            **kwargs,
        )
        try:
            activation_id, phone = activation
            activation_text = str(activation_id).strip()
            phone_text = str(phone).strip()
            if not activation_text or not phone_text:
                raise ValueError("empty activation")
            order_meta = {
                "key_index": state.index,
                "key_fingerprint": state.fingerprint,
                "balance_usd": state.balance_usd,
                "price_usd": None if price_usd is None else float(price_usd),
                "leased_at": time.time(),
            }
        except Exception:
            try:
                if hasattr(provider, "cancel"):
                    provider.cancel()
            except Exception as cleanup_error:
                self.pool.report_error(state, cleanup_error, runtime=True)
            finally:
                self.pool.release(state)
            raise RuntimeError("sms_activation_invalid_response") from None

        self._provider = provider
        self._state = state
        self._released = False
        self.activation_id = activation_text
        self.phone = phone_text
        self.current_order_meta = order_meta
        return self.activation_id, self.phone

    def get_number(
        self,
        service: str = "dr",
        country: str = "151",
        provider_ids: str = "",
        max_price: str = "",
    ) -> tuple[str, str]:
        return self._activate(
            "get_number",
            service=service,
            country=country,
            provider_ids=provider_ids,
            max_price=max_price,
        )

    def get_number_from_candidate(
        self,
        service: str,
        country: str,
        provider_ids: str,
        max_price: str,
        candidate_price: float,
    ) -> tuple[str, str]:
        return self._activate(
            "get_number_from_candidate",
            price_usd=candidate_price,
            service=service,
            country=country,
            provider_ids=provider_ids,
            max_price=max_price,
            candidate_price=candidate_price,
        )

    def wait_code(self, timeout: int = 300, interval: int = 3) -> str | None:
        if self._provider is None:
            raise RuntimeError("No active activation")
        try:
            try:
                return self._provider.wait_code(timeout=timeout, interval=interval)
            except TypeError:
                return self._provider.wait_code(timeout=timeout)
        except Exception as exc:
            self.pool.report_error(self._state, exc, runtime=True)
            self._release()
            key = self._state.key if self._state is not None else ""
            raise RuntimeError(self.pool.safe_error(exc, [key])) from exc

    def set_ready(self) -> None:
        if self._provider is not None and hasattr(self._provider, "set_ready"):
            try:
                self._provider.set_ready()
            except Exception as exc:
                self.pool.report_error(self._state, exc, runtime=True)
                self._release()
                key = self._state.key if self._state is not None else ""
                raise RuntimeError(self.pool.safe_error(exc, [key])) from exc

    def _finish(self, method: str) -> None:
        if self._provider is not None and hasattr(self._provider, method):
            try:
                getattr(self._provider, method)()
            except Exception as exc:
                self.pool.report_error(self._state, exc, runtime=True)
                key = self._state.key if self._state is not None else ""
                raise RuntimeError(self.pool.safe_error(exc, [key])) from exc
            finally:
                self._release()
        else:
            self._release()

    def _release(self) -> None:
        if self._released:
            return
        self._released = True
        self.pool.release(self._state)

    def complete(self) -> None:
        self._finish("complete")

    def cancel(self) -> None:
        self._finish("cancel")


def _sms_timeout_error(value: Any) -> bool:
    text = str(value or "").lower()
    return any(
        marker in text
        for marker in (
            "timeout",
            "timed out",
            "no code",
            "no sms",
            "verification code",
            "未收到验证码",
        )
    )


class SmsProviderRegistry:
    """Own one key pool per SMS platform and expose one aggregate provider."""

    def __init__(
        self,
        provider_factory: Callable[..., Any],
        *,
        legacy_pool: SmsKeyPool | None = None,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.provider_factory = provider_factory
        self.legacy_pool = legacy_pool
        self.now_fn = now_fn
        self.lock = threading.RLock()
        self.pools: dict[str, SmsKeyPool] = {}
        self.specs: list[dict[str, Any]] = []
        self.candidates: list[dict[str, Any]] = []
        self._task_attempt_counts: dict[str, dict[str, int]] = {}
        self.inventory: dict[str, list[dict[str, Any]]] = {}
        self.batch_health = SmsProviderBatchHealth()
        self.cursor = 0
        self.logger: Callable[[str, str], None] | None = None
        self.alert_fn: Callable[[dict[str, Any]], None] | None = None
        self.exhausted_fn: Callable[[], None] | None = None

    def task_attempt_counts(self, task_id: Any) -> dict[str, int]:
        key = str(task_id or "").strip()
        if not key:
            return {}
        with self.lock:
            return self._task_attempt_counts.setdefault(key, {})

    def clear_task_attempt_counts(self, task_id: Any) -> None:
        key = str(task_id or "").strip()
        if not key:
            return
        with self.lock:
            self._task_attempt_counts.pop(key, None)

    def snapshot_task_attempt_counts(self, task_id: Any) -> dict[str, int]:
        key = str(task_id or "").strip()
        if not key:
            return {}
        with self.lock:
            return {
                str(platform): max(0, int(count))
                for platform, count in self._task_attempt_counts.get(key, {}).items()
            }

    def _pool_for(self, provider: str) -> SmsKeyPool:
        current = self.pools.get(provider)
        if current is not None:
            return current
        if provider == "smsbower" and self.legacy_pool is not None:
            current = self.legacy_pool
        else:
            current = SmsKeyPool(
                lambda key, proxy="", _provider=provider: self.provider_factory(
                    _provider,
                    key,
                    proxy=proxy,
                ),
                now_fn=self.now_fn,
            )
        self.pools[provider] = current
        return current

    def configure(
        self,
        config: Any,
        *,
        min_price: float = 0.01,
        max_price: float = 0.15,
        logger: Callable[[str, str], None] | None = None,
        alert_fn: Callable[[dict[str, Any]], None] | None = None,
        exhausted_fn: Callable[[], None] | None = None,
    ) -> None:
        value = dict(config or {}) if isinstance(config, dict) else {}
        specs = normalize_sms_provider_pools(
            value.get("sms_provider_pools"),
            legacy_provider=value.get("sms_provider") or "smsbower",
            legacy_keys=value.get("sms_api_keys"),
            legacy_key=value.get("sms_api_key"),
        )
        with self.lock:
            self.batch_health.reset()
            self.specs = specs
            self.logger = logger
            self.alert_fn = alert_fn
            self.exhausted_fn = exhausted_fn
            self.candidates = []
            self.inventory = {}
            self.cursor = 0
            for spec in specs:
                provider = str(spec["provider"])
                pool = self._pool_for(provider)
                pool.configure(
                    list(spec.get("api_keys") or []),
                    service=str(spec.get("service") or SMS_PROVIDER_DEFAULT_SERVICES.get(provider, "dr")),
                    min_price=min_price,
                    max_price=max_price,
                    logger=logger,
                    alert_fn=lambda payload, _provider=provider: self._platform_alert(
                        _provider,
                        payload,
                    ),
                    exhausted_fn=lambda _provider=provider: self._platform_exhausted(_provider),
                )
                pool.reset_terminal_states()

    def _platform_alert(self, provider: str, payload: Any) -> None:
        value = dict(payload or {})
        value["provider"] = provider
        if callable(self.alert_fn):
            try:
                self.alert_fn(value)
            except Exception:
                pass

    def _platform_exhausted(self, _provider: str) -> None:
        provider = _provider
        added = self.batch_health.mark_exhausted(provider)
        if added and callable(self.logger):
            try:
                self.logger(
                    f"SMS 平台 {provider} 的全部 Key 本批次均不可用，后续任务将直接跳过该平台",
                    "warn",
                )
            except Exception:
                pass
        if self.is_exhausted() and callable(self.exhausted_fn):
            try:
                self.exhausted_fn()
            except Exception:
                pass

    def begin_run(self) -> None:
        with self.lock:
            pools = list(self.pools.values())
            self.candidates = []
            self.inventory = {}
            self._task_attempt_counts.clear()
        for pool in pools:
            pool.begin_run()

    def has_keys(self) -> bool:
        with self.lock:
            return any(
                bool(spec.get("enabled", True))
                and self.pools.get(str(spec.get("provider"))) is not None
                and self.pools[str(spec.get("provider"))].has_keys()
                for spec in self.specs
            )

    def public_statuses(self) -> list[dict[str, Any]]:
        with self.lock:
            specs = [dict(spec) for spec in self.specs]
            pools = dict(self.pools)
            inventory = {name: list(rows) for name, rows in self.inventory.items()}
        result: list[dict[str, Any]] = []
        for spec in specs:
            provider = str(spec.get("provider") or "")
            pool = pools.get(provider)
            if pool is None:
                continue
            inventory_rows = inventory.get(provider, [])
            inventory_count = sum(
                max(0, int(row.get("count") or 0)) for row in inventory_rows
            )
            prices = [
                float(row.get("price") or 0)
                for row in inventory_rows
                if float(row.get("price") or 0) > 0
            ]
            for row in pool.public_statuses():
                result.append(
                    {
                        **row,
                        "provider": provider,
                        "platform": provider,
                        "service": str(spec.get("service") or "dr"),
                        "enabled": bool(spec.get("enabled", True)),
                        "inventory_count": inventory_count,
                        "minimum_price": min(prices) if prices else None,
                    }
                )
        return result

    def safe_error(self, error: Any, extra_secrets: Any = None) -> str:
        with self.lock:
            pools = list(self.pools.values())
        text = str(error or "")
        for pool in pools:
            text = pool.safe_error(text, extra_secrets)
        return redact_sms_secrets(text, normalize_sms_keys(extra_secrets))

    def is_exhausted(self) -> bool:
        with self.lock:
            active = [
                self.pools.get(str(spec.get("provider")))
                for spec in self.specs
                if bool(spec.get("enabled", True))
            ]
        pools = [pool for pool in active if pool is not None and pool.has_keys()]
        return bool(pools) and all(pool.is_exhausted() for pool in pools)

    def all_balance_insufficient(self) -> bool:
        with self.lock:
            active = [
                self.pools.get(str(spec.get("provider")))
                for spec in self.specs
                if bool(spec.get("enabled", True))
            ]
        pools = [pool for pool in active if pool is not None and pool.has_keys()]
        return bool(pools) and all(pool.all_balance_insufficient() for pool in pools)

    def _active_specs(self) -> list[dict[str, Any]]:
        with self.lock:
            specs = [dict(spec) for spec in self.specs]
            pools = dict(self.pools)
        active: list[dict[str, Any]] = []
        for spec in specs:
            provider = str(spec.get("provider") or "")
            pool = pools.get(provider)
            if not bool(spec.get("enabled", True)) or pool is None or not pool.has_keys():
                continue
            if self.batch_health.is_exhausted(provider):
                continue
            if pool.is_exhausted():
                self._platform_exhausted(provider)
                continue
            active.append(spec)
        return active

    @staticmethod
    def _row_match(
        row: Any,
        *,
        country: str,
        provider_ids: str,
        price: float,
    ) -> bool:
        row_country = str(row.get("country") or "")
        row_provider = str(row.get("provider_id") or row.get("operator") or "")
        if country and row_country and row_country != country:
            return False
        if provider_ids and row_provider and row_provider != provider_ids:
            return False
        row_price = _as_float(row.get("price"), -1)
        return row_price < 0 or abs(row_price - price) <= 0.000001

    def query_balances(
        self,
        *,
        proxy: str = "",
        update_state: bool = True,
    ) -> list[dict[str, Any]]:
        return query_registry_balances(
            self,
            proxy=proxy,
            update_state=update_state,
            max_workers=SMS_PREFLIGHT_MAX_WORKERS,
        )

    def preflight(self, *, proxy: str = "") -> list[dict[str, Any]]:
        specs = self._active_specs()
        if not specs:
            return []

        def check(spec: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
            provider = str(spec.get("provider") or "")
            pool = self.pools[provider]
            statuses = pool.preflight(proxy=proxy)
            inventory = self._price_rows_for(spec, None, proxy=proxy)
            return provider, statuses, inventory

        workers = min(SMS_PREFLIGHT_MAX_WORKERS, len(specs))
        if workers == 1:
            results = [check(specs[0])]
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sms-platform-preflight") as executor:
                results = list(executor.map(check, specs))

        rows: list[dict[str, Any]] = []
        inventory_by_provider: dict[str, list[dict[str, Any]]] = {}
        for provider, statuses, inventory in results:
            inventory_by_provider[provider] = inventory
            total_inventory = sum(max(0, int(row.get("count") or 0)) for row in inventory)
            prices = [float(row.get("price") or 0) for row in inventory if float(row.get("price") or 0) > 0]
            for status in statuses:
                rows.append(
                    {
                        **status,
                        "provider": provider,
                        "platform": provider,
                        "inventory_count": total_inventory,
                        "minimum_price": min(prices) if prices else None,
                    }
                )
        with self.lock:
            self.inventory = inventory_by_provider
            self.candidates = [row for inventory in inventory_by_provider.values() for row in inventory]
        return rows

    def _price_rows_for(
        self,
        spec: dict[str, Any],
        countries: list[str] | None,
        *,
        proxy: str = "",
    ) -> list[dict[str, Any]]:
        provider_name = str(spec.get("provider") or "")
        pool = self.pools.get(provider_name)
        if pool is None:
            return []
        service = str(spec.get("service") or SMS_PROVIDER_DEFAULT_SERVICES.get(provider_name, "dr"))
        try:
            rows = pool.query(
                "get_price_candidates",
                proxy=proxy,
                service=service,
                countries=countries,
            )
        except Exception as exc:
            if callable(self.logger):
                try:
                    self.logger(
                        f"SMS 平台 {provider_name} 库存查询失败：{pool.safe_error(exc)}",
                        "warn",
                    )
                except Exception:
                    pass
            return []
        normalized: list[dict[str, Any]] = []
        for raw in rows or []:
            if not isinstance(raw, dict):
                continue
            row = dict(raw)
            row["platform"] = provider_name
            row["pool"] = provider_name
            row.setdefault("service", service)
            row["country"] = str(row.get("country") or "")
            row["provider_id"] = str(row.get("provider_id") or row.get("operator") or "")
            row["price"] = _as_float(row.get("price"), 0.0)
            row["count"] = max(0, int(_as_float(row.get("count"), 0)))
            if row["country"] and row["price"] >= 0:
                normalized.append(row)
        return normalized

    def get_price_candidates(
        self,
        service: str = "dr",
        countries: list[str] | None = None,
        *,
        proxy: str = "",
    ) -> list[dict[str, Any]]:
        del service
        specs = self._active_specs()
        rows: list[dict[str, Any]] = []
        for spec in specs:
            rows.extend(self._price_rows_for(spec, countries, proxy=proxy))
        with self.lock:
            self.candidates = list(rows)
        return rows

    def get_available_countries(self, service: str = "dr", *, proxy: str = "") -> list[str]:
        values: set[str] = set()
        for row in self.get_price_candidates(service=service, proxy=proxy):
            country = str(row.get("country") or "")
            if country:
                values.add(country)
        return sorted(values)

    def _candidate_specs(
        self,
        *,
        country: str,
        provider_ids: str,
        price: float,
        platform: str = "",
    ) -> list[dict[str, Any]]:
        specs = self._active_specs()
        with self.lock:
            candidates = list(self.candidates)
        matched: list[str] = []
        for row in candidates:
            row_platform = str(row.get("platform") or row.get("pool") or "")
            if platform and row_platform != platform:
                continue
            if self._row_match(row, country=country, provider_ids=provider_ids, price=price):
                if row_platform and row_platform not in matched:
                    matched.append(row_platform)
        active_names = [str(spec.get("provider") or "") for spec in specs]
        preferred = list(matched)
        if platform and platform in active_names and platform not in preferred:
            preferred.append(platform)
        names = preferred + [name for name in active_names if name not in preferred]
        # Inventory-capable platforms still supply the route, but the starting
        # platform rotates so a valid provider with an empty inventory response
        # is not permanently starved.
        if len(names) > 1:
            with self.lock:
                offset = self.cursor % len(names)
                self.cursor += 1
            names = names[offset:] + names[:offset]
        ordered = [spec for name in names for spec in specs if spec.get("provider") == name]
        ordered.extend(spec for spec in specs if spec not in ordered)
        return ordered

    def activate(
        self,
        method: str,
        *,
        proxy: str = "",
        price_usd: float | None = None,
        platform: str = "",
        attempt_counts: dict[str, int] | None = None,
        max_attempts_per_platform: int = 0,
        **kwargs: Any,
    ) -> tuple[Any, SmsKeyPool, SmsKeyHealth, Any, dict[str, Any]]:
        country = str(kwargs.get("country") or "")
        provider_ids = str(kwargs.get("provider_ids") or "")
        candidate_price = _as_float(price_usd, -1)
        specs = self._candidate_specs(
            country=country,
            provider_ids=provider_ids,
            price=candidate_price,
            platform=platform,
        )
        if not specs:
            raise RuntimeError("sms_provider_pool_unavailable: 所有启用 SMS 平台均不可用")
        errors: list[str] = []
        for spec in specs:
            provider_name = str(spec.get("provider") or "")
            if (
                attempt_counts is not None
                and max_attempts_per_platform > 0
                and int(attempt_counts.get(provider_name) or 0) >= max_attempts_per_platform
            ):
                continue
            pool = self.pools.get(provider_name)
            if pool is None:
                continue
            if attempt_counts is not None:
                attempt_counts[provider_name] = int(attempt_counts.get(provider_name) or 0) + 1
            service = str(spec.get("service") or SMS_PROVIDER_DEFAULT_SERVICES.get(provider_name, "dr"))
            call_kwargs = dict(kwargs)
            call_kwargs["service"] = service
            try:
                provider, state, activation = pool.activate(
                    method,
                    proxy=proxy,
                    price_usd=price_usd,
                    **call_kwargs,
                )
                meta = {
                    "platform": provider_name,
                    "provider": provider_name,
                    "service": service,
                    "key_index": state.index,
                    "key_fingerprint": state.fingerprint,
                    "balance_usd": state.balance_usd,
                    "country": country,
                    "provider_id": provider_ids,
                    "price_usd": None if price_usd is None else float(price_usd),
                }
                return provider, pool, state, activation, meta
            except Exception as exc:
                errors.append(self.safe_error(f"{provider_name}: {exc}"))
                if pool.is_exhausted():
                    self._platform_exhausted(provider_name)
                continue
        detail = "; ".join(errors) or "所有启用 SMS 平台均已达到单平台尝试上限"
        raise RuntimeError(f"sms_provider_pool_unavailable: {detail}")


class PooledSmsProvider:
    """Provider-compatible facade for an order selected from any platform."""

    SMART_ANY_PROVIDER_FALLBACK = True
    SMART_COUNTRY_SCOPE_FILTER = True
    SMART_FIXED_COUNTRY_FALLBACK = False

    def __init__(self, registry: SmsProviderRegistry, *, proxy: str = "") -> None:
        self.registry = registry
        self.proxy = proxy
        self.api_key = ""
        self.activation_id: str | None = None
        self.phone: str | None = None
        self._provider: Any = None
        self._pool: SmsKeyPool | None = None
        self._state: SmsKeyHealth | None = None
        self._released = True
        self._resend_attempted = False
        self._reject_requested = False
        self._poll_lock = threading.Lock()
        self._poll_generation = 0
        self._cancel_attempted = False
        self.max_attempts_per_platform = 15
        self._platform_attempts: dict[str, int] = {}
        self._task_id = ""
        self._early_switch_check: Callable[[], bool] | None = None
        self.current_order_meta: dict[str, Any] = {}
        self.last_finish_receipt: dict[str, str] = {}

    def bind_task(self, task_id: Any) -> None:
        key = str(task_id or "").strip()
        if not key or key == self._task_id:
            return
        self._task_id = key
        self._platform_attempts = self.registry.task_attempt_counts(key)

    def configure_wait_plan(self, plan: Any) -> None:
        """Attach a route decision without changing the recovered wait signature."""
        if isinstance(plan, SmsWaitPlan):
            value = {
                "first_seconds": plan.first_seconds,
                "second_seconds": plan.second_seconds,
                "early_switch": plan.early_switch,
                "degraded": plan.degraded,
            }
        elif isinstance(plan, dict):
            value = dict(plan)
        else:
            value = {}
        self.current_order_meta["adaptive_wait_plan"] = {
            "first_seconds": max(1, min(60, int(value.get("first_seconds") or 30))),
            "second_seconds": max(1, min(60, int(value.get("second_seconds") or 30))),
            "early_switch": bool(value.get("early_switch")),
            "degraded": bool(value.get("degraded")),
        }

    def configure_early_switch_check(self, check: Any) -> None:
        self._early_switch_check = check if callable(check) else None

    def can_cancel_immediately(self) -> bool:
        platform = normalize_sms_provider_name(
            self.current_order_meta.get("platform")
            or self.current_order_meta.get("provider")
        )
        if platform == "herosms":
            leased_at = _as_float(self.current_order_meta.get("leased_at"), time.time())
            if time.time() - leased_at < 120:
                return False
        return callable(getattr(self._provider, "cancel", None))

    def balance(self) -> str:
        total = sum(
            float(row.get("balance_usd") or 0)
            for row in self.registry.public_statuses()
            if row.get("status") == "usable"
        )
        return f"ACCESS_BALANCE:{total:.4f}"

    def get_price_candidates(self, service: str = "dr", countries: list[str] | None = None) -> list[dict[str, Any]]:
        return self.registry.get_price_candidates(
            service=service,
            countries=countries,
            proxy=self.proxy,
        )

    def get_available_countries(self, service: str = "dr") -> list[str]:
        return self.registry.get_available_countries(service=service, proxy=self.proxy)

    def _activate(self, method: str, price_usd: float | None = None, **kwargs: Any) -> tuple[str, str]:
        if not self._released:
            raise RuntimeError("SMS provider already has an active activation")
        provider, pool, state, activation, meta = self.registry.activate(
            method,
            proxy=self.proxy,
            price_usd=price_usd,
            attempt_counts=self._platform_attempts,
            max_attempts_per_platform=self.max_attempts_per_platform,
            **kwargs,
        )
        try:
            activation_id, phone = activation
            activation_text = str(activation_id).strip()
            phone_text = str(phone).strip()
            if not activation_text or not phone_text:
                raise ValueError("empty activation")
        except Exception:
            try:
                if hasattr(provider, "cancel"):
                    provider.cancel()
            except Exception as cleanup_error:
                pool.report_error(state, cleanup_error, runtime=True)
            finally:
                pool.release(state)
            raise RuntimeError("sms_activation_invalid_response") from None
        self._provider = provider
        self._pool = pool
        self._state = state
        self._released = False
        self._resend_attempted = False
        self._reject_requested = False
        self._cancel_attempted = False
        self._early_switch_check = None
        self.last_finish_receipt = {}
        self.activation_id = activation_text
        self.phone = phone_text
        self.current_order_meta = {
            **meta,
            "leased_at": time.time(),
            "order_state": "leased",
        }
        return activation_text, phone_text

    def get_number(self, service: str = "dr", country: str = "151", provider_ids: str = "", max_price: str = "") -> tuple[str, str]:
        return self._activate(
            "get_number",
            service=service,
            country=country,
            provider_ids=provider_ids,
            max_price=max_price,
        )

    def get_number_from_candidate(
        self,
        service: str,
        country: str,
        provider_ids: str,
        max_price: str,
        candidate_price: float,
        platform: str = "",
    ) -> tuple[str, str]:
        return self._activate(
            "get_number_from_candidate",
            price_usd=candidate_price,
            service=service,
            country=country,
            provider_ids=provider_ids,
            max_price=max_price,
            candidate_price=candidate_price,
            platform=platform,
        )

    def _wait_once(self, timeout: int, interval: int) -> str | None:
        try:
            return self._provider.wait_code(timeout=timeout, interval=interval)
        except TypeError:
            return self._provider.wait_code(timeout=timeout)

    def _resend(self) -> None:
        platform = normalize_sms_provider_name(
            self.current_order_meta.get("platform")
            or self.current_order_meta.get("provider")
        )
        if platform == "5sim":
            return
        method = getattr(self._provider, "set_ready", None)
        if callable(method):
            method()

    def _ensure_activation(self, activation_id: str, generation: int) -> None:
        if (
            generation != self._poll_generation
            or str(self.activation_id or "") != activation_id
            or self._released
        ):
            raise RuntimeError(
                "sms_activation_replaced: 短信轮询结果所属订单已被替换"
            )

    def _wait_round(
        self,
        activation_id: str,
        generation: int,
        *,
        timeout: int,
        interval: int,
    ) -> str | None:
        deadline = time.monotonic() + max(1, int(timeout))

        def poll() -> str | None:
            self._ensure_activation(activation_id, generation)
            remaining = max(1, math.ceil(deadline - time.monotonic()))
            code = self._wait_once(remaining, interval)
            self._ensure_activation(activation_id, generation)
            return code

        try:
            return call_sms_with_retries(poll, deadline=deadline)
        except Exception as exc:
            if "sms_activation_replaced" in str(exc):
                raise
            if self._pool is not None:
                self._pool.report_error(self._state, exc, runtime=True)
            detail = self.registry.safe_error(exc)
            raise RuntimeError(
                f"sms_provider_poll_failed: {detail or type(exc).__name__}"
            ) from exc

    def wait_code(self, timeout: int = 300, interval: int = 3) -> str | None:
        if self._provider is None:
            raise RuntimeError("No active activation")
        if not self._poll_lock.acquire(blocking=False):
            raise RuntimeError(
                "sms_poll_already_active: 当前短信订单已有轮询线程"
            )
        self._poll_generation += 1
        generation = self._poll_generation
        activation_id = str(self.activation_id or "")
        configured_plan = self.current_order_meta.get("adaptive_wait_plan")
        wait_plan = configured_plan if isinstance(configured_plan, dict) else {}
        if wait_plan:
            round_timeout = max(1, int(wait_plan.get("first_seconds") or SMS_FIRST_WAIT_SECONDS))
            second_timeout = max(1, int(wait_plan.get("second_seconds") or SMS_SECOND_WAIT_SECONDS))
        else:
            round_timeout = min(SMS_FIRST_WAIT_SECONDS, max(1, int(timeout)))
            second_timeout = min(SMS_SECOND_WAIT_SECONDS, max(1, int(timeout)))
        del interval
        poll_interval = SMS_POLL_INTERVAL_SECONDS
        self.current_order_meta["order_state"] = "waiting"
        try:
            code = self._wait_round(
                activation_id,
                generation,
                timeout=round_timeout,
                interval=poll_interval,
            )
            if code:
                self.current_order_meta["order_state"] = "code_received"
                return code
            # An early release is only safe after the selector re-confirms a
            # better mature route.  A missing or failed callback must retain
            # the current order for its second wait round.
            still_has_alternative = False
            if bool(wait_plan.get("early_switch")) and callable(self._early_switch_check):
                try:
                    still_has_alternative = bool(self._early_switch_check())
                except Exception:
                    still_has_alternative = False
            if (
                bool(wait_plan.get("early_switch"))
                and still_has_alternative
                and self.can_cancel_immediately()
            ):
                self.current_order_meta["order_state"] = "switch_requested"
                raise RuntimeError(
                    "sms_timeout_early_switch: 退化线路等待 40 秒仍无验证码，已有更优成熟线路可用"
                )
            self._resend_attempted = True
            platform = normalize_sms_provider_name(
                self.current_order_meta.get("platform")
                or self.current_order_meta.get("provider")
            )
            if platform != "5sim":
                try:
                    call_sms_with_retries(self._resend)
                except Exception as exc:
                    if self._pool is not None:
                        self._pool.report_error(self._state, exc, runtime=True)
                    detail = self.registry.safe_error(exc)
                    raise RuntimeError(
                        f"sms_provider_ready_failed: {detail or type(exc).__name__}"
                    ) from exc
            code = self._wait_round(
                activation_id,
                generation,
                timeout=second_timeout,
                interval=poll_interval,
            )
            if code:
                self.current_order_meta["order_state"] = "code_received"
                return code
            raise RuntimeError(
                "sms_timeout: 两轮短信等待结束后仍未收到验证码"
            )
        finally:
            self._poll_lock.release()

    def set_ready(self) -> None:
        method = getattr(self._provider, "set_ready", None)
        if not callable(method):
            return
        try:
            call_sms_with_retries(method)
            self.current_order_meta["order_state"] = "ready"
        except Exception as exc:
            if self._pool is not None:
                self._pool.report_error(self._state, exc, runtime=True)
            detail = self.registry.safe_error(exc)
            raise RuntimeError(
                f"sms_provider_ready_failed: {detail or type(exc).__name__}"
            ) from exc

    def _release(self) -> None:
        if self._released:
            return
        self._released = True
        if self._pool is not None:
            self._pool.release(self._state)

    def _cancel_provider(self, platform: str) -> dict[str, str]:
        provider = self._provider
        if platform == "herosms" and callable(getattr(provider, "_api", None)):
            return confirm_herosms_cancellation(
                provider,
                self.activation_id,
                leased_at=self.current_order_meta.get("leased_at"),
                defer_early=True,
                on_wait=lambda seconds: self.registry._log(
                    f"HeroSMS 订单处于前置取消保护期，已安排约 {int(seconds)} 秒后后台取消并核对返款",
                    "warn",
                ),
            )
        callback = getattr(provider, "cancel", None)
        result = callback() if callable(callback) else None
        receipt = safe_cancel_receipt(result)
        return receipt or {
            "cancel_state": "confirmed",
            "refund_status": "provider_cancel_accepted",
        }

    def _reject_provider(self) -> dict[str, str]:
        provider = self._provider
        platform = normalize_sms_provider_name(
            self.current_order_meta.get("platform")
            or self.current_order_meta.get("provider")
        )
        if platform != "5sim":
            return self._cancel_provider(platform)

        reject_error: Exception | None = None
        for name in ("ban", "reject"):
            callback = getattr(provider, name, None)
            if not callable(callback):
                continue
            try:
                callback()
                return {
                    "cancel_state": "confirmed",
                    "refund_status": "provider_rejection_confirmed",
                }
            except Exception as exc:
                reject_error = exc
                break

        if reject_error is None:
            rest_get = getattr(provider, "_rest_get", None)
            activation_id = str(self.activation_id or "").strip()
            if callable(rest_get) and activation_id:
                try:
                    safe_id = urllib.parse.quote(activation_id, safe="")
                    rest_get(f"/user/ban/{safe_id}")
                    return {
                        "cancel_state": "confirmed",
                        "refund_status": "provider_rejection_confirmed",
                    }
                except Exception as exc:
                    reject_error = exc

        cancel = getattr(provider, "cancel", None)
        if callable(cancel):
            try:
                cancel()
                return {
                    "cancel_state": "unconfirmed",
                    "refund_status": "provider_cancel_unverified",
                }
            except Exception as cancel_error:
                if reject_error is None:
                    reject_error = cancel_error
        if reject_error is not None:
            raise reject_error
        return {
            "cancel_state": "unconfirmed",
            "refund_status": "provider_cancel_unverified",
        }

    def _finish(self, method: str) -> dict[str, str]:
        if method in {"cancel", "reject"} and self._cancel_attempted:
            return dict(self.last_finish_receipt)
        if method in {"cancel", "reject"}:
            self._cancel_attempted = True
        receipt: dict[str, str] = {}
        try:
            if method == "reject":
                receipt = self._reject_provider()
            elif method == "cancel":
                platform = normalize_sms_provider_name(
                    self.current_order_meta.get("platform")
                    or self.current_order_meta.get("provider")
                )
                receipt = self._cancel_provider(platform)
            else:
                callback = getattr(self._provider, method, None)
                if callable(callback):
                    result = callback()
                    receipt = safe_cancel_receipt(result)
            self.last_finish_receipt = safe_cancel_receipt(receipt)
            self.current_order_meta["order_state"] = (
                "cancelled" if method in {"cancel", "reject"} else "completed"
            )
            return dict(self.last_finish_receipt)
        except Exception as exc:
            if method in {"cancel", "reject"}:
                self.last_finish_receipt = {
                    "cancel_state": "error",
                    "refund_status": "provider_cancel_not_confirmed",
                }
                self.current_order_meta["order_state"] = "cancel_failed"
                platform = normalize_sms_provider_name(
                    self.current_order_meta.get("platform")
                    or self.current_order_meta.get("provider")
                )
                if platform == "herosms":
                    self._platform_attempts[platform] = self.max_attempts_per_platform
            if self._pool is not None:
                self._pool.report_error(self._state, exc, runtime=True)
                raise RuntimeError(self.registry.safe_error(exc)) from exc
            raise
        finally:
            self._release()

    def complete(self) -> dict[str, str]:
        return self._finish("complete")

    def mark_rejected(self) -> None:
        self._reject_requested = True

    def reject(self) -> dict[str, str]:
        self._reject_requested = False
        return self._finish("reject")

    def cancel(self) -> dict[str, str]:
        if self._reject_requested:
            return self.reject()
        return self._finish("cancel")


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
