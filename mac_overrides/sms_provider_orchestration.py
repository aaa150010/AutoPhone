"""Multi-provider SMS registry and the pooled provider facade.

Split out of ``sms_runtime.py``; the original module re-exports these
classes for compatibility.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import math
import threading
import urllib.parse
import time
from typing import Any, Callable

try:
    from .sms_order_runtime import (
        confirm_herosms_cancellation,
        safe_cancel_receipt,
    )
    from .sms_provider_runtime import (
        SMS_PROVIDER_DEFAULT_SERVICES,
        SmsProviderBatchHealth,
        normalize_sms_keys,
        normalize_sms_provider_name,
        normalize_sms_provider_pools,
    )
    from .sms_route_runtime import (
        SmsWaitPlan,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_order_runtime import (  # type: ignore[no-redef]
        confirm_herosms_cancellation,
        safe_cancel_receipt,
    )
    from sms_provider_runtime import (  # type: ignore[no-redef]
        SMS_PROVIDER_DEFAULT_SERVICES,
        SmsProviderBatchHealth,
        normalize_sms_keys,
        normalize_sms_provider_name,
        normalize_sms_provider_pools,
    )
    from sms_route_runtime import (  # type: ignore[no-redef]
        SmsWaitPlan,
    )

# Dense-then-sparse status polling: most SMS codes land within the first
# seconds after send, so each wait round opens with a tightly polled window
# and then falls back to the historic cadence. The dense window stays short
# so provider getStatus rate limits are only briefly stressed.
_SMS_DENSE_POLL_SECONDS = 10
_SMS_DENSE_POLL_INTERVAL_SECONDS = 1

try:
    from .sms_balance_runtime import query_registry_balances
    from .sms_network import (
        SMS_FIRST_WAIT_SECONDS,
        SMS_POLL_INTERVAL_SECONDS,
        SMS_PREFLIGHT_MAX_WORKERS,
        SMS_SECOND_WAIT_SECONDS,
        _as_float,
        call_sms_with_retries,
        redact_sms_secrets,
    )
    from .sms_key_pool import SmsKeyHealth, SmsKeyPool, _PooledSmsActivationMixin
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_balance_runtime import query_registry_balances  # type: ignore[no-redef]
    from sms_network import (  # type: ignore[no-redef]
        SMS_FIRST_WAIT_SECONDS,
        SMS_POLL_INTERVAL_SECONDS,
        SMS_PREFLIGHT_MAX_WORKERS,
        SMS_SECOND_WAIT_SECONDS,
        _as_float,
        call_sms_with_retries,
        redact_sms_secrets,
    )
    from sms_key_pool import (  # type: ignore[no-redef]
        SmsKeyHealth,
        SmsKeyPool,
        _PooledSmsActivationMixin,
    )


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
            except Exception as exc:
                # Alert failures must never break provider orchestration.
                _note_stderr("sms_orchestration_alert_fn", exc)

    def _platform_exhausted(self, _provider: str) -> None:
        provider = _provider
        added = self.batch_health.mark_exhausted(provider)
        if added and callable(self.logger):
            try:
                self.logger(
                    f"SMS 平台 {provider} 的全部 Key 本批次均不可用，后续任务将直接跳过该平台",
                    "warn",
                )
            except Exception as exc:
                # Telemetry must not mask the exhaustion being reported.
                _note_stderr("sms_orchestration_exhausted_warn", exc)
        if self.is_exhausted() and callable(self.exhausted_fn):
            try:
                self.exhausted_fn()
            except Exception as exc:
                # Exhausted-notification failures must not break selection.
                _note_stderr("sms_orchestration_exhausted_fn", exc)

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
                except Exception as exc:
                    # Telemetry must not mask the inventory failure surfaced above.
                    _note_stderr("sms_orchestration_inventory_warn", exc)
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


class PooledSmsProvider(_PooledSmsActivationMixin):
    """Provider-compatible facade for an order selected from any platform."""

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
        slices: list[tuple[int, int]] = []
        dense = min(_SMS_DENSE_POLL_SECONDS, max(1, int(timeout)))
        if dense < int(timeout):
            slices.append((dense, _SMS_DENSE_POLL_INTERVAL_SECONDS))
        slices.append((max(1, int(timeout) - (dense if dense < int(timeout) else 0)), max(1, int(interval))))
        for index, (slice_timeout, slice_interval) in enumerate(slices):
            remaining = max(0, math.ceil(deadline - time.monotonic()))
            if remaining <= 0:
                return None
            if index == len(slices) - 1:
                # Keep the round bounded by its deadline even if the dense
                # slice overran on transient-error retries.
                slice_timeout = min(slice_timeout, max(1, remaining))
            try:
                code = call_sms_with_retries(
                    lambda st=slice_timeout, si=slice_interval: self._polled_slice(
                        activation_id, generation, st, si,
                    ),
                    deadline=deadline,
                )
            except Exception as exc:
                if "sms_activation_replaced" in str(exc):
                    raise
                if self._pool is not None:
                    self._pool.report_error(self._state, exc, runtime=True)
                detail = self.registry.safe_error(exc)
                raise RuntimeError(
                    f"sms_provider_poll_failed: {detail or type(exc).__name__}"
                ) from exc
            if code:
                return code
        return None

    def _polled_slice(
        self,
        activation_id: str,
        generation: int,
        timeout: int,
        interval: int,
    ) -> str | None:
        self._ensure_activation(activation_id, generation)
        code = self._wait_once(timeout, interval)
        self._ensure_activation(activation_id, generation)
        return code

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

    def _cancel_provider(self, platform: str) -> dict[str, str]:
        provider = self._provider
        if platform == "herosms" and callable(getattr(provider, "_api", None)):
            return confirm_herosms_cancellation(
                provider,
                self.activation_id,
                leased_at=self.current_order_meta.get("leased_at"),
                defer_early=True,
                # SmsKeyPool owns the configured logger; the registry facade
                # only exposes safe_error/alert plumbing without an _log alias.
                on_wait=lambda seconds: self._pool._log(
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


__all__ = [
    "SmsProviderRegistry",
    "PooledSmsProvider",
]
