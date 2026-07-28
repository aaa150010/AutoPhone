"""Thread-safe SMS key pooling, balance checks, and cost accounting."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


SECRET_MASK = "********"
ECB_DAILY_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
SMS_PREFLIGHT_MAX_WORKERS = 8
PERFORMANCE_POLICY_VERSION = 5
PERFORMANCE_DEFAULTS = {
    "phone_max_attempts": 10,
    "phone_session_cycle_seconds": 480,
    "auth_session_retries": 1,
}


def normalize_sms_keys(value: Any = None, legacy: Any = "") -> list[str]:
    """Normalize the canonical key list without interpreting key punctuation."""
    if isinstance(value, (list, tuple)):
        candidates = value
    elif isinstance(value, str) and value.strip():
        candidates = [value]
    elif legacy is not None:
        candidates = [legacy]
    else:
        candidates = []

    result: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate or "").strip()
        if not key or key == SECRET_MASK or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def migrate_performance_config(value: Any) -> tuple[dict[str, Any], bool]:
    """Apply the one-time performance defaults while preserving later user choices."""
    config = dict(value or {}) if isinstance(value, dict) else {}
    try:
        version = int(config.get("performance_policy_version") or 0)
    except (TypeError, ValueError):
        version = 0
    migrated = version < PERFORMANCE_POLICY_VERSION
    if migrated:
        for key, default in PERFORMANCE_DEFAULTS.items():
            try:
                current = int(config.get(key) or 0)
            except (TypeError, ValueError):
                current = 0
            if current <= 0:
                config[key] = default
        config["performance_policy_version"] = PERFORMANCE_POLICY_VERSION
    else:
        for key, default in PERFORMANCE_DEFAULTS.items():
            if key not in config:
                config[key] = default

    keys = normalize_sms_keys(config.get("sms_api_keys"), config.get("sms_api_key"))
    config["sms_api_keys"] = keys
    config["sms_api_key"] = keys[0] if keys else ""
    return config, migrated


def key_fingerprint(key: str) -> str:
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:10]


def redact_sms_secrets(value: Any, secrets: list[str]) -> str:
    text = str(value or "")
    for secret in sorted(normalize_sms_keys(secrets), key=len, reverse=True):
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


def _candidate_value(candidate: Any, name: str, default: Any = None) -> Any:
    if isinstance(candidate, dict):
        return candidate.get(name, default)
    return getattr(candidate, name, default)


def _route_stat(route_stats: Any, route: tuple[str, str]) -> dict[str, Any]:
    if not isinstance(route_stats, dict):
        return {}
    value = route_stats.get(route)
    if not isinstance(value, dict):
        value = route_stats.get(f"{route[0]}::{route[1]}")
    return value if isinstance(value, dict) else {}


def rank_sms_candidates(
    candidates: list[Any],
    route_stats: Any,
    *,
    priority_routes: tuple[tuple[str, str], ...] = (),
    priority_countries: tuple[str, ...] = (),
    minimum_proven_rate: float = 0.10,
) -> list[Any]:
    """Rank proven routes by accepted-number yield without losing cold starts."""
    route_priority = {route: index for index, route in enumerate(priority_routes)}
    country_priority = {country: index for index, country in enumerate(priority_countries)}
    default_route_priority = len(route_priority)
    default_country_priority = len(country_priority)

    def key(candidate: Any) -> tuple[Any, ...]:
        route = (
            str(_candidate_value(candidate, "country", "") or ""),
            str(_candidate_value(candidate, "provider_id", "") or ""),
        )
        stat = _route_stat(route_stats, route)
        success = max(
            int(_as_float(stat.get("success"), 0)),
            int(_as_float(stat.get("otp_received"), 0)),
        )
        failures = max(0, int(_as_float(stat.get("fail"), 0)))
        no_numbers = max(0, int(_as_float(stat.get("no_numbers"), 0)))
        classified_failures = sum(
            max(0, int(_as_float(stat.get(name), 0)))
            for name in ("phone_rejected", "register_rejected", "invalid_auth_step", "timeout")
        )
        rejected = max(0, failures - no_numbers, classified_failures)
        attempts = success + rejected
        acceptance_rate = success / attempts if attempts else 0.0
        preferred = route in route_priority

        if success > 0 and acceptance_rate >= minimum_proven_rate:
            tier = 0
        elif attempts == 0 and preferred:
            tier = 1
        elif success > 0:
            tier = 2
        elif attempts == 0:
            tier = 3
        else:
            tier = 4

        return (
            tier,
            -acceptance_rate,
            -success,
            route_priority.get(route, default_route_priority),
            country_priority.get(route[0], default_country_priority),
            -_as_float(_candidate_value(candidate, "score", 0.0), 0.0),
            _as_float(_candidate_value(candidate, "price", 999.0), 999.0),
            -int(_as_float(_candidate_value(candidate, "count", 0), 0)),
        )

    return sorted(candidates, key=key)


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
        self.max_price = 0.1
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
        max_price: float = 0.1,
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
            self.max_price = max(self.min_price, _as_float(max_price, 0.1))
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


class PhoneSubmissionGate:
    def __init__(
        self,
        concurrency: int = 2,
        interval_seconds: float = 0.75,
        *,
        now_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.semaphore = threading.BoundedSemaphore(max(1, int(concurrency)))
        self.interval_seconds = max(0.0, float(interval_seconds))
        self.now_fn = now_fn
        self.sleep_fn = sleep_fn
        self.spacing_lock = threading.Lock()
        self.last_started_at = 0.0
        self.not_before = 0.0
        self.transient_streak = 0

    def begin_run(self) -> None:
        with self.spacing_lock:
            self.last_started_at = 0.0
            self.not_before = 0.0
            self.transient_streak = 0

    def report_transient(self) -> float:
        with self.spacing_lock:
            self.transient_streak += 1
            delay = min(8.0, 2.0 ** self.transient_streak)
            self.not_before = max(self.not_before, self.now_fn() + delay)
            return delay

    def report_success(self) -> None:
        with self.spacing_lock:
            self.transient_streak = 0

    def call(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        with self.semaphore:
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
                    self.sleep_fn(wait_for)
            return function(*args, **kwargs)

    def call_with_retries(
        self,
        function: Callable[..., Any],
        *args: Any,
        is_transient: Callable[[Any], bool],
        max_attempts: int = 4,
        on_retry: Callable[[float, int], None] | None = None,
        **kwargs: Any,
    ) -> Any:
        attempts = max(1, int(max_attempts))
        last_error: Any = None
        for attempt in range(1, attempts + 1):
            try:
                result = self.call(function, *args, **kwargs)
            except Exception as exc:
                if not is_transient(exc):
                    self.report_success()
                    raise
                last_error = exc
            else:
                if not is_transient(result):
                    self.report_success()
                    return result
                last_error = result

            delay = self.report_transient()
            if attempt < attempts and callable(on_retry):
                try:
                    on_retry(delay, attempt)
                except Exception:
                    pass

        if isinstance(last_error, Exception):
            raise last_error
        return last_error


def is_transient_openai_error(value: Any) -> bool:
    if isinstance(value, dict):
        error = value.get("error") or value.get("message") or ""
        if isinstance(error, dict):
            error = f"{error.get('code') or ''} {error.get('message') or ''}"
        status = int(_as_float(value.get("_status") or value.get("status"), 0))
        text = str(error).lower()
        if status in {500, 502, 503, 504}:
            return True
    else:
        text = str(value or "").lower()
    return any(
        marker in text
        for marker in (
            "the server had an error processing your request",
            "internal server error",
            "temporarily unavailable",
            "service unavailable",
            "upstream connect error",
        )
    )


class SmsRoutePolicy:
    """Tracks short-lived route limits and consecutive no-code outcomes."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.no_code_streaks: dict[tuple[str, str], int] = {}

    @staticmethod
    def key(candidate: Any) -> tuple[str, str]:
        return (
            str(getattr(candidate, "country", "") or ""),
            str(getattr(candidate, "provider_id", "") or ""),
        )

    @staticmethod
    def route_limit(stat: Any) -> int:
        row = stat if isinstance(stat, dict) else {}
        proven = any(
            int(_as_float(row.get(name), 0)) > 0
            for name in ("otp_sent", "otp_received", "success")
        )
        return 2 if proven else 1

    def reset(self) -> None:
        with self.lock:
            self.no_code_streaks.clear()

    def cooldown_for(self, candidate: Any, *, ok: bool, kind: str, error: Any = "") -> int:
        route = self.key(candidate)
        text = str(error or "").lower()
        if not all(route):
            return 0
        with self.lock:
            if ok:
                self.no_code_streaks.pop(route, None)
                return 0
            if kind == "transient_server":
                return 0
            if kind in {"timeout", "no_code"}:
                streak = self.no_code_streaks.get(route, 0) + 1
                if streak >= 2:
                    self.no_code_streaks.pop(route, None)
                    return 300
                self.no_code_streaks[route] = streak
                return 0
            self.no_code_streaks.pop(route, None)
            if any(marker in text for marker in ("similar", "suspicious", "try another number", "too many accounts")):
                return 1800
            if kind == "phone_rejected" or any(
                marker in text for marker in ("already been used", "number is already used", "used too many times")
            ):
                return 600
            return 0


class RuntimeAlertBuffer:
    def __init__(self, limit: int = 100) -> None:
        self.limit = max(1, int(limit))
        self.lock = threading.Lock()
        self.items: list[dict[str, Any]] = []
        self.seen: set[str] = set()
        self.sequence = 0

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


class ExchangeRateCache:
    def __init__(
        self,
        path: Path,
        *,
        fetcher: Callable[[], bytes] | None = None,
        now_fn: Callable[[], float] = time.time,
        ttl_seconds: int = 86400,
        fallback_rate: float = 7.20,
    ) -> None:
        self.path = Path(path)
        self.fetcher = fetcher or self._fetch_ecb
        self.now_fn = now_fn
        self.ttl_seconds = ttl_seconds
        self.fallback_rate = fallback_rate
        self.lock = threading.Lock()

    @staticmethod
    def _fetch_ecb() -> bytes:
        with urllib.request.urlopen(ECB_DAILY_URL, timeout=5) as response:
            return response.read(262144)

    @staticmethod
    def parse_ecb(payload: bytes) -> tuple[float, str]:
        root = ET.fromstring(payload)
        usd = None
        cny = None
        rate_date = ""
        for element in root.iter():
            if element.attrib.get("time"):
                rate_date = element.attrib["time"]
            currency = element.attrib.get("currency")
            if currency == "USD":
                usd = _as_float(element.attrib.get("rate"), 0)
            elif currency == "CNY":
                cny = _as_float(element.attrib.get("rate"), 0)
        if not usd or not cny:
            raise ValueError("ECB 汇率响应缺少 USD 或 CNY")
        return cny / usd, rate_date

    def _read(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def get_rate(self) -> dict[str, Any]:
        with self.lock:
            now = self.now_fn()
            cached = self._read()
            fetched_at = _as_float(cached.get("fetched_at"), 0)
            cached_rate = _as_float(cached.get("rate"), 0)
            if cached_rate > 0 and now - fetched_at < self.ttl_seconds:
                return {**cached, "source": "cache"}
            try:
                rate, rate_date = self.parse_ecb(self.fetcher())
                value = {
                    "rate": round(rate, 6),
                    "date": rate_date,
                    "fetched_at": int(now),
                    "source": "ecb",
                }
                self._write(value)
                return value
            except Exception:
                if cached_rate > 0:
                    return {**cached, "source": "stale_cache"}
                return {
                    "rate": self.fallback_rate,
                    "date": time.strftime("%Y-%m-%d", time.localtime(now)),
                    "fetched_at": int(now),
                    "source": "fallback",
                }


class SmsCostLedger:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.orders: dict[str, dict[str, dict[str, Any]]] = {}

    def clear(self) -> None:
        with self.lock:
            self.orders.clear()

    @staticmethod
    def _activation_key(activation_id: Any) -> str:
        return hashlib.sha256(str(activation_id or "").encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _candidate_value(candidate: Any, name: str, default: Any = None) -> Any:
        if isinstance(candidate, dict):
            return candidate.get(name, default)
        return getattr(candidate, name, default)

    def record_lease(self, task_id: str, lease: Any) -> None:
        meta = lease.meta if isinstance(getattr(lease, "meta", None), dict) else {}
        candidate = meta.get("candidate")
        price = meta.get("price_usd")
        if price is None:
            price = self._candidate_value(candidate, "price")
        activation_key = self._activation_key(getattr(lease, "activation_id", ""))
        order = {
            "activation": activation_key,
            "key_index": meta.get("key_index"),
            "key_fingerprint": meta.get("key_fingerprint") or "",
            "country": self._candidate_value(candidate, "country", ""),
            "provider_id": self._candidate_value(candidate, "provider_id", ""),
            "price_usd": None if price is None else round(_as_float(price), 4),
            "status": "leased",
            "code_received": False,
            "leased_at": int(time.time()),
        }
        with self.lock:
            self.orders.setdefault(task_id, {})[activation_key] = order

    def mark_code_received(self, task_id: str, activation_id: Any) -> None:
        activation_key = self._activation_key(activation_id)
        with self.lock:
            order = self.orders.get(task_id, {}).get(activation_key)
            if order is not None:
                order["code_received"] = True
                order["status"] = "code_received"
                order["code_received_at"] = int(time.time())

    def mark_finished(self, task_id: str, activation_id: Any, status: str, reason: str = "") -> None:
        activation_key = self._activation_key(activation_id)
        with self.lock:
            order = self.orders.get(task_id, {}).get(activation_key)
            if order is not None:
                order["status"] = status
                if reason:
                    order["reason"] = reason
                order["finished_at"] = int(time.time())

    def summary(self, task_id: str, exchange: ExchangeRateCache, *, pop: bool = True) -> dict[str, Any]:
        with self.lock:
            task_orders = self.orders.pop(task_id, {}) if pop else dict(self.orders.get(task_id, {}))
            outcomes = [dict(order) for order in task_orders.values()]
        paid = [order for order in outcomes if order.get("code_received") and order.get("price_usd") is not None]
        if not paid:
            return {
                "sms_cost_usd": None,
                "sms_cost_cny": None,
                "sms_exchange_rate": None,
                "sms_exchange_date": "",
                "sms_order_outcomes": outcomes,
            }
        usd = round(sum(float(order["price_usd"]) for order in paid), 4)
        rate_info = exchange.get_rate()
        rate = float(rate_info["rate"])
        return {
            "sms_cost_usd": usd,
            "sms_cost_cny": round(usd * rate, 2),
            "sms_exchange_rate": round(rate, 6),
            "sms_exchange_date": str(rate_info.get("date") or ""),
            "sms_exchange_source": str(rate_info.get("source") or ""),
            "sms_order_outcomes": outcomes,
        }
