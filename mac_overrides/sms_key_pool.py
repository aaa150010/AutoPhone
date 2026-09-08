"""SMS key health, key pool and the single-provider facade.

Split out of ``sms_runtime.py``; the original module re-exports these
classes for compatibility.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import re
import threading
import time
from typing import Any, Callable

try:
    from .sms_provider_runtime import (
        normalize_sms_keys,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_provider_runtime import (  # type: ignore[no-redef]
        normalize_sms_keys,
    )

try:
    from .sms_balance_runtime import query_key_pool_balances
    from .sms_network import (
        SMS_PREFLIGHT_MAX_WORKERS,
        SingleFlightTtlCache,
        _StaleSmsPreflight,
        _as_float,
        classify_key_error,
        key_fingerprint,
        parse_sms_balance,
        redact_sms_secrets,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_balance_runtime import query_key_pool_balances  # type: ignore[no-redef]
    from sms_network import (  # type: ignore[no-redef]
        SMS_PREFLIGHT_MAX_WORKERS,
        SingleFlightTtlCache,
        _StaleSmsPreflight,
        _as_float,
        classify_key_error,
        key_fingerprint,
        parse_sms_balance,
        redact_sms_secrets,
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
                state.message = f"网络异常：{text[:120] or '接码平台未返回连接详情'}"
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
                except Exception as exc:
                    self._log(
                        f"[Key池选号/price_floor] 平台 {state.fingerprint} 价格候选查询失败，"
                        f"本次价格底线计算跳过该平台（{type(exc).__name__}）",
                        "warn",
                    )
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
            except Exception as exc:
                self._log(
                    f"[Key池告警/exhausted] Key 池耗尽回调执行失败，耗尽告警可能丢失"
                    f"（{type(exc).__name__}）",
                    "error",
                )

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


__all__ = [
    "SmsKeyHealth",
    "SmsKeyPool",
    "PooledSmsBowerProvider",
]
