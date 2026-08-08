"""Web/runtime integration for adaptive SMS execution."""

from __future__ import annotations

from threading import RLock
import time
from typing import Any, Callable


SMS_MAX_PRICE_HARD_LIMIT = 0.18

try:
    from .runtime_policy import (
        ACCOUNT_BANNED_MESSAGE,
        AccountBannedError,
        is_explicit_account_banned,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from runtime_policy import (  # type: ignore[no-redef]
        ACCOUNT_BANNED_MESSAGE,
        AccountBannedError,
        is_explicit_account_banned,
    )

try:
    from .auth_session_runtime import is_session_invalid
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from auth_session_runtime import is_session_invalid  # type: ignore[no-redef]


def _call_log(log_fn: Any, message: str, level: str = "info") -> None:
    if not callable(log_fn):
        return
    try:
        log_fn(message, level)
    except TypeError as exc:
        if "positional argument" not in str(exc) and "arguments" not in str(exc):
            raise
        log_fn(message)


class SmsWebIntegration:
    def __init__(
        self,
        *,
        sms_runtime: Any,
        original_create_provider: Callable[..., Any],
        original_build_candidates: Callable[..., Any],
        original_adapter_get_number: Callable[..., Any],
        original_adapter_wait_code: Callable[..., Any],
        original_adapter_complete: Callable[..., Any],
        original_adapter_cancel: Callable[..., Any],
        original_classify_error: Callable[..., Any],
        original_record_result: Callable[..., Any],
        original_send_phone_otp: Callable[..., Any],
        key_pool: Any,
        cost_ledger: Any,
        phone_gate: Any,
        route_policy: Any,
        alerts: Any,
        task_progress: Any,
        priority_countries: tuple[str, ...],
        priority_routes: tuple[tuple[str, str], ...],
        blocked_routes: tuple[tuple[str, str], ...],
        min_price_default: float,
        max_price_default: str,
        sms_keys_from_config: Callable[[dict[str, Any]], list[str]],
        as_enabled: Callable[[Any, bool], bool],
        safe_error: Callable[[Any], str],
        provider_registry: Any = None,
        phone_context_preflight: Callable[[Any, str], Any] | None = None,
        cleanup_queue: Any = None,
        optimization_guard: Any = None,
        max_price_hard_limit: float = SMS_MAX_PRICE_HARD_LIMIT,
    ) -> None:
        self.sms_runtime = sms_runtime
        self.original_create_provider = original_create_provider
        self.original_build_candidates = original_build_candidates
        self.original_adapter_get_number = original_adapter_get_number
        self.original_adapter_wait_code = original_adapter_wait_code
        self.original_adapter_complete = original_adapter_complete
        self.original_adapter_cancel = original_adapter_cancel
        self.original_classify_error = original_classify_error
        self.original_record_result = original_record_result
        self.original_send_phone_otp = original_send_phone_otp
        self.key_pool = key_pool
        self.cost_ledger = cost_ledger
        self.phone_gate = phone_gate
        self.route_policy = route_policy
        self.alerts = alerts
        self.task_progress = task_progress
        self.priority_countries = priority_countries
        self.priority_routes = priority_routes
        self.blocked_routes = blocked_routes
        self.min_price_default = min_price_default
        self.max_price_default = max_price_default
        try:
            self.max_price_hard_limit = max(0.01, float(max_price_hard_limit))
        except (TypeError, ValueError):
            self.max_price_hard_limit = SMS_MAX_PRICE_HARD_LIMIT
        self.sms_keys_from_config = sms_keys_from_config
        self.as_enabled = as_enabled
        self.safe_error_fn = safe_error
        self.provider_registry = provider_registry
        self.phone_context_preflight = phone_context_preflight
        self.cleanup_queue = cleanup_queue
        self.optimization_guard = optimization_guard
        self._sms_proxy = ""
        self._active_lease_lock = RLock()
        self._active_leases: dict[str, tuple[Any, Any]] = {}
        self._account_banned_details: dict[str, str] = {}

    def safe_error(self, error: Any) -> str:
        return self.safe_error_fn(error)

    def _route_now(self) -> float:
        clock = getattr(self.route_policy, "now_fn", None)
        try:
            return float(clock()) if callable(clock) else time.time()
        except Exception:
            return time.time()

    def _record_segment(self, task_id: Any, code: str, elapsed_seconds: Any) -> None:
        try:
            recorder = getattr(self.task_progress, "record_segment", None)
            if task_id and callable(recorder):
                recorder(task_id, code, elapsed_seconds)
        except Exception:
            pass

    def clamp_max_price(self, value: Any) -> str:
        try:
            price = float(str(value or "").strip())
        except (TypeError, ValueError):
            return self.max_price_default
        if price <= 0 or price > self.max_price_hard_limit:
            return self.max_price_default
        return f"{price:g}"

    def _sms_quality_enabled(self, config: Any) -> bool:
        value = config if isinstance(config, dict) else {}
        configured = self.as_enabled(value.get("sms_quality_optimization"), True)
        guard = self.optimization_guard
        checker = getattr(guard, "is_enabled", None)
        if callable(checker):
            try:
                return bool(checker(configured))
            except Exception:
                # Guard telemetry must never change the configured behavior.
                return configured
        return configured



    def smart_build_candidates(
        self,
        selector: Any,
        raw_rows: Any,
        now: float,
        allowed_countries: Any,
        blocked_countries: Any,
    ) -> Any:
        rows = self.original_build_candidates(
            selector,
            raw_rows,
            now,
            allowed_countries,
            blocked_countries,
        )
        # The recovered selector intentionally exposes a short no-number
        # fallback window.  That fallback is unsafe for concurrent runs: it
        # can immediately hand the same known-empty route back to another
        # worker.  Keep only routes whose cooldown has actually elapsed.
        route_stats = getattr(selector, "stats", {}) or {}
        filtered_rows = []
        for item in rows or []:
            key = self.sms_runtime._candidate_route(item)
            stat = route_stats.get(key) if isinstance(route_stats, dict) else None
            if not isinstance(stat, dict) and isinstance(route_stats, dict):
                stat = route_stats.get("::".join(key))
            stat = stat if isinstance(stat, dict) else {}
            cooldown_until = self.sms_runtime._as_float(
                stat.get("cooldown_until"),
            )
            last_kind = str(stat.get("last_kind") or "").strip().lower()
            if cooldown_until > float(now) and last_kind in {
                "no_numbers",
                "timeout",
                "no_code",
            }:
                continue
            filtered_rows.append(item)
        rows = filtered_rows
        full_config = getattr(selector, "config", {}) or {}
        try:
            max_price = float(str(full_config.get("max_price") or self.max_price_default).strip())
        except (TypeError, ValueError):
            max_price = float(self.max_price_default)
        try:
            min_price = float(str(full_config.get("sms_min_price") or self.min_price_default).strip())
        except (TypeError, ValueError):
            min_price = self.min_price_default
        route_order = self.priority_routes
        blocked_routes = set(self.blocked_routes)
        if not rows:
            return rows
        rows = [
            item
            for item in rows
            if (
                str(getattr(item, "country", "")),
                str(getattr(item, "provider_id", "")),
            )
            not in blocked_routes
            and min_price <= float(getattr(item, "price", 999.0) or 999.0) <= max_price
        ]
        return self.sms_runtime.rank_sms_candidates(
            rows,
            getattr(selector, "stats", {}),
            country_stats=getattr(selector, "country_stats", {}),
            priority_routes=route_order,
            priority_countries=self.priority_countries,
            now=now,
            reliability_mode=bool(full_config.get("_phone_risk_retry")),
            quality_optimization=self._sms_quality_enabled(full_config),
        )

    def _invalidate_candidate_cache(self, selector: Any, candidate: Any = None) -> None:
        """Force the next worker to rediscover inventory after an empty route."""
        if selector is None:
            return
        lock = getattr(selector, "lock", None)
        try:
            if lock is not None:
                with lock:
                    selector.candidates = []
                    selector.raw_rows = []
                    selector.last_refresh = 0.0
            else:
                selector.candidates = []
                selector.raw_rows = []
                selector.last_refresh = 0.0
        except Exception:
            # Cache invalidation must never mask the provider outcome.
            pass

        # The recovered module keeps a process-global discovery cache.  It is
        # deliberately cleared only after a route outcome that proves the
        # advertised inventory stale (no number or SMS timeout).
        try:
            refresh = getattr(type(selector), "refresh", None)
            module_globals = getattr(refresh, "__globals__", {})
            cache = module_globals.get("_DISCOVERY_CACHE")
            cache_lock = module_globals.get("_DISCOVERY_CACHE_LOCK")
            if isinstance(cache, dict):
                route = self.sms_runtime._candidate_route(candidate)
                def discard_stale() -> None:
                    if not all(route):
                        cache.clear()
                        return
                    for cache_key, cached in list(cache.items()):
                        rows = cached[1] if isinstance(cached, tuple) and len(cached) > 1 else ()
                        if any(
                            isinstance(row, dict)
                            and self.sms_runtime._candidate_route(row) == route
                            for row in rows or ()
                        ):
                            cache.pop(cache_key, None)

                if cache_lock is not None:
                    with cache_lock:
                        discard_stale()
                else:
                    discard_stale()
        except Exception:
            pass

    def create_provider(self, name: str, api_key: str, proxy: str = "") -> Any:
        if self.provider_registry is not None and self.provider_registry.has_keys():
            return self.sms_runtime.PooledSmsProvider(self.provider_registry, proxy=proxy)
        if str(name or "").strip().lower() == "smsbower" and self.key_pool.has_keys():
            return self.sms_runtime.PooledSmsBowerProvider(self.key_pool, proxy=proxy)
        return self.original_create_provider(name, api_key, proxy=proxy)

    @staticmethod
    def adapter_task_id(adapter: Any) -> str:
        config = getattr(adapter, "config", None) or {}
        return str(config.get("sms_task_id") or config.get("run_id") or "")

    @staticmethod
    def transport_task_id(transport: Any) -> str:
        config = getattr(transport, "config", None) or {}
        return str(config.get("sms_task_id") or config.get("run_id") or "")

    def _remember_active_lease(self, task_id: str, adapter: Any, lease: Any) -> None:
        if not task_id:
            return
        with self._active_lease_lock:
            self._active_leases[task_id] = (adapter, lease)

    def _forget_active_lease(self, task_id: str, lease: Any) -> None:
        if not task_id:
            return
        with self._active_lease_lock:
            active = self._active_leases.get(task_id)
            if active is not None and active[1] is lease:
                self._active_leases.pop(task_id, None)

    def _ledger_state(self, task_id: str, lease: Any, state: str) -> None:
        callback = getattr(self.cost_ledger, "mark_state", None)
        if task_id and callable(callback):
            callback(task_id, getattr(lease, "activation_id", ""), state)

    def _cancel_outcome(
        self,
        adapter: Any,
        reason: str,
        error: Exception | None = None,
    ) -> tuple[str, str, dict[str, str]]:
        provider = getattr(adapter, "provider", None)
        receipt = self.sms_runtime.safe_cancel_receipt(
            getattr(provider, "last_finish_receipt", None)
        )
        safe_reason = self.safe_error(reason or "")
        if error is not None:
            safe_cancel_error = self.safe_error(error)
            detail = "; ".join(
                item for item in (safe_reason, f"cancel_error={safe_cancel_error}") if item
            )
            return "cancel_failed", detail, receipt
        if receipt.get("cancel_state") == "confirmed":
            return "cancelled", safe_reason, receipt
        return "cancel_failed", safe_reason, receipt

    def _mark_cancel_finished(
        self,
        task_id: str,
        lease: Any,
        adapter: Any,
        reason: str,
        error: Exception | None = None,
    ) -> None:
        status, detail, receipt = self._cancel_outcome(adapter, reason, error)
        self.cost_ledger.mark_finished(
            task_id,
            getattr(lease, "activation_id", ""),
            status,
            detail,
            details=receipt,
        )

    def _queue_cancel_cleanup(self, adapter: Any, lease: Any, error: Any) -> bool:
        if self.cleanup_queue is None:
            return False
        provider = getattr(adapter, "provider", None)
        meta = {
            **dict(getattr(provider, "current_order_meta", None) or {}),
            **dict(getattr(lease, "meta", None) or {}),
        }
        platform = str(meta.get("platform") or meta.get("provider") or "")
        delay = float(getattr(error, "retry_after_seconds", 0) or 0)
        if delay <= 0:
            delay = (
                self.sms_runtime.herosms_cancel_delay_seconds(meta.get("leased_at"))
                if platform == "herosms"
                else 15
            )
        try:
            entry_id = self.cleanup_queue.enqueue(
                platform=platform,
                key_fingerprint=meta.get("key_fingerprint"),
                activation_id=getattr(lease, "activation_id", ""),
                delay_seconds=delay,
                error_code=type(error).__name__ if isinstance(error, Exception) else error,
                leased_at=meta.get("leased_at"),
                task_id=self.adapter_task_id(adapter),
            )
        except Exception:
            return False
        return bool(entry_id)

    def _retry_cleanup_entry(self, entry: dict[str, Any]) -> bool:
        if self.provider_registry is None:
            return False
        platform = self.sms_runtime.normalize_sms_provider_name(entry.get("platform"))
        pool = self.provider_registry.pools.get(platform)
        if pool is None:
            return False
        fingerprint = str(entry.get("key_fingerprint") or "")
        with pool.lock:
            state = next(
                (row for row in pool.states if row.fingerprint == fingerprint),
                None,
            )
        if state is None:
            return False
        provider = self.original_create_provider(platform, state.key, proxy=self._sms_proxy)
        provider.activation_id = str(entry.get("activation_id") or "")
        if platform == "herosms":
            receipt = self.sms_runtime.confirm_herosms_cancellation(
                provider,
                provider.activation_id,
                leased_at=float(entry.get("leased_at") or time.time()),
                defer_early=True,
            )
            confirmed = receipt.get("cancel_state") == "confirmed"
            if confirmed:
                self.cost_ledger.mark_finished(
                    str(entry.get("task_id") or ""),
                    provider.activation_id,
                    "cancelled",
                    details=receipt,
                )
            return confirmed
        callback = getattr(provider, "cancel", None)
        if not callable(callback):
            return False
        callback()
        return True

    def cancel_active_lease(self, task_id: str, reason: str) -> None:
        if not task_id:
            return
        with self._active_lease_lock:
            active = self._active_leases.pop(task_id, None)
        if active is None:
            return
        adapter, lease = active
        meta = dict(getattr(lease, "meta", None) or {})
        if meta.get("gptphone_terminal_cancelled"):
            return
        meta["gptphone_terminal_cancelled"] = True
        meta["gptphone_session_invalid_cancelled"] = is_session_invalid(reason)
        meta["ready_recorded"] = True
        meta["sms_order_state"] = "cancel_pending"
        lease.meta = meta
        self._ledger_state(task_id, lease, "cancel_pending")
        cancel_error = None
        try:
            self.original_adapter_cancel(adapter, lease, reason=reason)
        except Exception as exc:
            cancel_error = exc
            queued = self._queue_cancel_cleanup(adapter, lease, exc)
            meta = dict(getattr(lease, "meta", None) or {})
            meta["sms_order_state"] = "cancel_pending" if queued else "cancel_failed"
            lease.meta = meta
            self._ledger_state(task_id, lease, meta["sms_order_state"])
        else:
            meta = dict(getattr(lease, "meta", None) or {})
            receipt = self.sms_runtime.safe_cancel_receipt(
                getattr(getattr(adapter, "provider", None), "last_finish_receipt", None)
            )
            confirmed = receipt.get("cancel_state") == "confirmed"
            queued = False if confirmed else self._queue_cancel_cleanup(
                adapter,
                lease,
                "provider_cancel_unconfirmed",
            )
            meta["sms_order_state"] = "cancelled" if confirmed else (
                "cancel_pending" if queued else "cancel_failed"
            )
            lease.meta = meta
            self._ledger_state(task_id, lease, meta["sms_order_state"])
        try:
            if meta.get("sms_order_state") == "cancel_pending":
                self._ledger_state(task_id, lease, "cancel_pending")
            else:
                self._mark_cancel_finished(
                    task_id,
                    lease,
                    adapter,
                    reason,
                    cancel_error,
                )
        except Exception:
            pass

    def _cancel_account_banned_lease(self, task_id: str) -> None:
        self.cancel_active_lease(task_id, ACCOUNT_BANNED_MESSAGE)

    def _raise_account_banned(self, transport: Any, technical_value: Any) -> None:
        task_id = self.transport_task_id(transport)
        technical_detail = self.safe_error(technical_value)
        if task_id:
            with self._active_lease_lock:
                self._account_banned_details[task_id] = technical_detail[:1000]
            self._cancel_account_banned_lease(task_id)
            self.task_progress.observe_task_state(task_id, "account_banned")
        _call_log(getattr(transport, "log_fn", None), ACCOUNT_BANNED_MESSAGE, "error")
        raise AccountBannedError(technical_detail)

    def pop_account_banned_detail(self, task_id: Any) -> str:
        key = str(task_id or "").strip()
        if not key:
            return ""
        with self._active_lease_lock:
            return self._account_banned_details.pop(key, "")

    def ensure_account_active(self, transport: Any, response: Any) -> Any:
        if is_explicit_account_banned(response):
            self._raise_account_banned(transport, response)
        return response

    def adapter_get_number(self, adapter: Any, **kwargs: Any) -> Any:
        task_id = self.adapter_task_id(adapter)
        provider = getattr(adapter, "provider", None)
        config = getattr(adapter, "config", None) or {}
        bind_task = getattr(provider, "bind_task", None)
        if task_id and callable(bind_task):
            bind_task(task_id)
        if provider is not None and hasattr(provider, "max_attempts_per_platform"):
            try:
                provider.max_attempts_per_platform = max(
                    1,
                    min(15, int(config.get("phone_attempts_per_provider") or 15)),
                )
            except (TypeError, ValueError):
                provider.max_attempts_per_platform = 15
        if callable(self.phone_context_preflight):
            self.phone_context_preflight(adapter, task_id)
        if task_id:
            self.task_progress.set_stage(task_id, "phone_acquiring")
        lease = self.original_adapter_get_number(adapter, **kwargs)
        meta = dict(getattr(lease, "meta", None) or {})
        provider_meta = dict(
            getattr(getattr(adapter, "provider", None), "current_order_meta", None) or {}
        )
        for key, value in provider_meta.items():
            if value is not None:
                meta[key] = value
        candidate = meta.get("candidate")
        if meta.get("price_usd") is None and candidate is not None:
            meta["price_usd"] = getattr(candidate, "price", None)
        lease.meta = meta
        meta["sms_order_state"] = "leased"
        lease.meta = meta
        if task_id:
            self._remember_active_lease(task_id, adapter, lease)
            self.cost_ledger.record_lease(task_id, lease)
            self._ledger_state(task_id, lease, "leased")
            self.task_progress.set_stage(task_id, "phone_submitting")
        return lease

    def adapter_mark_ready(self, adapter: Any, lease: Any) -> None:
        task_id = self.adapter_task_id(adapter)
        if task_id:
            self.task_progress.set_stage(task_id, "sms_waiting")
        provider = getattr(adapter, "provider", None)
        if provider is not None and hasattr(provider, "set_ready"):
            ready_started = time.monotonic()
            try:
                provider.set_ready()
            finally:
                self._record_segment(
                    task_id,
                    "sms_provider_ready",
                    time.monotonic() - ready_started,
                )
        meta = dict(getattr(lease, "meta", None) or {})
        meta["ready_sent"] = True
        meta["sms_order_state"] = "ready"
        lease.meta = meta
        self._ledger_state(task_id, lease, "ready")

    def adapter_wait_code(self, adapter: Any, lease: Any, timeout: int = 180) -> Any:
        task_id = self.adapter_task_id(adapter)
        if task_id:
            self.task_progress.set_stage(task_id, "sms_waiting")
        meta = dict(getattr(lease, "meta", None) or {})
        meta["sms_order_state"] = "waiting"
        lease.meta = meta
        self._ledger_state(task_id, lease, "waiting")
        candidate = meta.get("candidate")
        selector = getattr(adapter, "selector", None)
        adapter_config = getattr(adapter, "config", None) or {}
        selector_config = getattr(selector, "config", None) or {}
        quality_config = (
            adapter_config
            if "sms_quality_optimization" in adapter_config
            else selector_config
        )
        if candidate is not None and selector is not None and self._sms_quality_enabled(quality_config):
            stat = self._route_stat_snapshot(selector, candidate)

            def better_mature_alternative() -> bool:
                # The rolling guard can disable optimization while this
                # order is already in its first wait round.  Recheck here so
                # in-flight orders retain 40+20 but never early-release.
                if not self._sms_quality_enabled(quality_config):
                    return False
                return self.sms_runtime.has_better_mature_alternative(
                    candidate,
                    getattr(selector, "candidates", ()),
                    getattr(selector, "stats", {}),
                    country_stats=getattr(selector, "country_stats", {}),
                    priority_routes=self.priority_routes,
                    priority_countries=self.priority_countries,
                    now=self._route_now(),
                    reliability_mode=bool(
                        adapter_config.get("_phone_risk_retry")
                        or selector_config.get("_phone_risk_retry")
                    ),
                    quality_optimization=True,
                )

            better_alternative = better_mature_alternative()
            wait_plan = self.sms_runtime.build_sms_wait_plan(
                stat,
                optimization_enabled=True,
                better_mature_alternative=better_alternative,
            )
            if wait_plan.degraded:
                provider = getattr(adapter, "provider", None)
                configure_wait_plan = getattr(provider, "configure_wait_plan", None)
                if callable(configure_wait_plan):
                    configure_wait_plan(wait_plan)
                configure_switch_check = getattr(
                    provider,
                    "configure_early_switch_check",
                    None,
                )
                if wait_plan.early_switch and callable(configure_switch_check):
                    configure_switch_check(better_mature_alternative)
                meta = dict(getattr(lease, "meta", None) or {})
                meta["adaptive_wait_plan"] = {
                    "first_seconds": wait_plan.first_seconds,
                    "second_seconds": wait_plan.second_seconds,
                    "early_switch": wait_plan.early_switch,
                }
                lease.meta = meta
        try:
            code = self.original_adapter_wait_code(adapter, lease, timeout=timeout)
        except Exception as exc:
            meta = dict(getattr(lease, "meta", None) or {})
            candidate = meta.get("candidate")
            error_text = str(exc or "").lower()
            error_kind = self.classify_error(exc)
            if error_kind in {"no_numbers", "timeout", "no_code"}:
                self._invalidate_candidate_cache(
                    getattr(adapter, "selector", None),
                    candidate,
                )
            # The recovered signup loop changes numbers only when wait_code
            # returns an empty value. Pooled providers raise sms_timeout after
            # their two polling rounds, so normalize that one terminal wait
            # outcome into the adapter's existing no-code contract.
            if error_kind == "timeout" and "sms_timeout" in error_text:
                early_switch = "sms_timeout_early_switch" in error_text
                meta["sms_wait_failure"] = (
                    "sms_timeout_early_switch" if early_switch else "sms_timeout"
                )
                meta["sms_order_state"] = "timeout"
                lease.meta = meta
                log_fn = getattr(adapter, "log_fn", None)
                if not callable(log_fn):
                    log_fn = getattr(getattr(adapter, "selector", None), "log_fn", None)
                _call_log(
                    log_fn,
                    (
                        "  [SMS] 退化线路等待 40 秒仍未送达，释放当前号码并切换更优成熟线路"
                        if early_switch
                        else "  [SMS] 短信验证码在两轮等待后仍未送达，释放当前号码并切换新号码"
                    ),
                    "warn",
                )
                return None
            raise
        meta = dict(getattr(lease, "meta", None) or {})
        candidate = meta.get("candidate")
        if code:
            if not meta.get("otp_received_recorded") and candidate is not None:
                selector = getattr(adapter, "selector", None)
                now = self._route_now()
                if selector is not None:
                    self._update_route_stat(
                        selector,
                        candidate,
                        lambda stat: self.route_policy.record_delivery(stat, now=now),
                    )
                meta["otp_received_recorded"] = True
                meta["sms_order_state"] = "code_received"
                lease.meta = meta
            if task_id:
                self.cost_ledger.mark_code_received(task_id, getattr(lease, "activation_id", ""))
                self.task_progress.set_stage(task_id, "sms_verifying")
        else:
            # A clean no-code response is still evidence that the cached
            # inventory is stale; scoring remains the adapter cancel path's
            # responsibility so this cannot double-count a timeout.
            self._invalidate_candidate_cache(
                getattr(adapter, "selector", None),
                candidate,
            )
        return code

    def adapter_complete(self, adapter: Any, lease: Any) -> Any:
        task_id = self.adapter_task_id(adapter)
        try:
            result = self.original_adapter_complete(adapter, lease)
        except Exception as exc:
            if task_id:
                self.cost_ledger.mark_finished(
                    task_id,
                    getattr(lease, "activation_id", ""),
                    "complete_error",
                    self.safe_error(exc),
                )
            raise
        if task_id:
            self._forget_active_lease(task_id, lease)
            self.cost_ledger.mark_finished(
                task_id,
                getattr(lease, "activation_id", ""),
                "completed",
            )
        meta = dict(getattr(lease, "meta", None) or {})
        meta["sms_order_state"] = "completed"
        lease.meta = meta
        self._ledger_state(task_id, lease, "completed")
        return result

    def adapter_cancel(self, adapter: Any, lease: Any, reason: str = "") -> Any:
        task_id = self.adapter_task_id(adapter)
        meta = dict(getattr(lease, "meta", None) or {})
        cancel_reason = reason
        if str(reason or "").strip() == "phone_otp_empty" and meta.get("sms_wait_failure"):
            cancel_reason = str(meta["sms_wait_failure"])
        if meta.get("gptphone_terminal_cancelled"):
            self._forget_active_lease(task_id, lease)
            return None
        meta["sms_order_state"] = "cancel_pending"
        lease.meta = meta
        self._ledger_state(task_id, lease, "cancel_pending")
        provider = getattr(adapter, "provider", None)
        mark_rejected = getattr(provider, "mark_rejected", None)
        if self.classify_error(cancel_reason) == "phone_rejected" and callable(mark_rejected):
            mark_rejected()
        try:
            result = self.original_adapter_cancel(adapter, lease, reason=cancel_reason)
        except Exception as exc:
            queued = self._queue_cancel_cleanup(adapter, lease, exc)
            meta = dict(getattr(lease, "meta", None) or {})
            meta["sms_order_state"] = "cancel_pending" if queued else "cancel_failed"
            lease.meta = meta
            self._ledger_state(task_id, lease, meta["sms_order_state"])
            if task_id:
                self._forget_active_lease(task_id, lease)
                if not queued:
                    try:
                        self._mark_cancel_finished(task_id, lease, adapter, cancel_reason, exc)
                    except Exception:
                        pass
                return None
            raise
        meta = dict(getattr(lease, "meta", None) or {})
        receipt = self.sms_runtime.safe_cancel_receipt(
            getattr(getattr(adapter, "provider", None), "last_finish_receipt", None)
        )
        confirmed = receipt.get("cancel_state") == "confirmed"
        queued = False if confirmed else self._queue_cancel_cleanup(
            adapter,
            lease,
            "provider_cancel_unconfirmed",
        )
        meta["sms_order_state"] = "cancelled" if confirmed else (
            "cancel_pending" if queued else "cancel_failed"
        )
        lease.meta = meta
        self._ledger_state(task_id, lease, meta["sms_order_state"])
        if task_id:
            self._forget_active_lease(task_id, lease)
            if confirmed or not queued:
                self._mark_cancel_finished(task_id, lease, adapter, cancel_reason)
        return result

    def classify_error(self, error: Any) -> str:
        if is_session_invalid(error):
            return "auth_session"
        if self.sms_runtime.is_transient_openai_error(error):
            return "transient_server"
        text = str(error or "").lower()
        if any(
            marker in text
            for marker in (
                "phone_flow_mfa_regressed",
                "phone_flow_login_regressed",
                "auth_context_page_mismatch",
                "auth_context_cookies_missing",
                "auth_context_task_mismatch",
                "auth_context_generation_mismatch",
            )
        ):
            return "auth_context"
        if "phone_channel_mismatch" in text:
            return "phone_rejected"
        if any(
            marker in text
            for marker in (
                "sms_provider_ready_failed",
                "sms_provider_poll_failed",
                "sms_activation_replaced",
                "sms_poll_already_active",
            )
        ) or self.sms_runtime.is_sms_route_infrastructure_error(error):
            return "provider_network"
        if any(
            marker in text
            for marker in ("phone_otp_empty", "no sms code", "no verification code", "未收到验证码")
        ):
            return "timeout"
        if "sms_timeout" in text:
            return "timeout"
        return self.original_classify_error(error)

    def _update_route_stat(
        self,
        selector: Any,
        candidate: Any,
        update_fn: Callable[..., Any],
    ) -> None:
        if selector is None or candidate is None:
            return
        key = self.sms_runtime._candidate_route(candidate)
        country, provider_id = key
        if not country or not provider_id:
            return
        with selector.lock:
            try:
                route_row = selector._update_shared_stats(key, update_fn)
            except Exception:
                # Route telemetry must never take down a registration if its
                # local stats file is temporarily unavailable.
                stat = dict(selector.stats.get(key) or {})
                selector.stats[key] = update_fn(stat)
            else:
                selector.stats[key] = route_row

    def _release_route_without_score(self, selector: Any, candidate: Any) -> None:
        now = self._route_now()

        def update(stat: Any) -> dict[str, Any]:
            row = dict(stat or {})
            inflight = selector._route_inflight(row, now)
            if inflight > 1:
                row["inflight"] = inflight - 1
            else:
                row.pop("inflight", None)
                row.pop("lease_until", None)
            return row

        self._update_route_stat(selector, candidate, update)

    def _set_route_cooldown(self, selector: Any, candidate: Any, seconds: int) -> None:
        until = self._route_now() + max(0, int(seconds))

        def update(stat: Any) -> dict[str, Any]:
            row = dict(stat or {})
            row["cooldown_until"] = max(float(row.get("cooldown_until") or 0), until)
            return row

        self._update_route_stat(selector, candidate, update)

    def _route_stat_snapshot(self, selector: Any, candidate: Any) -> dict[str, Any]:
        key = self.sms_runtime._candidate_route(candidate)
        country, provider_id = key
        if not country or not provider_id:
            return {}
        with selector.lock:
            value = selector.stats.get(key)
            if not isinstance(value, dict):
                value = selector.stats.get("::".join(key))
            return dict(value or {})

    def smart_record_result(self, selector: Any, candidate: Any, ok: bool, error: Any = "") -> Any:
        kind = self.classify_error(error)
        if not ok and kind in {
            "transient_server",
            "auth_session",
            "auth_context",
            "provider_network",
        }:
            self._release_route_without_score(selector, candidate)
            return None
        outcome_now = self._route_now()
        result = self.original_record_result(selector, candidate, ok, error)
        if ok:
            def remember_success(stat: Any) -> dict[str, Any]:
                row = self.route_policy.update_stat_for_outcome(
                    stat,
                    ok=True,
                    kind="success",
                    now=outcome_now,
                )
                row["last_success_at"] = max(
                    self.sms_runtime._as_float(row.get("last_success_at"), 0.0),
                    outcome_now,
                )
                return row

            self._update_route_stat(selector, candidate, remember_success)
        elif kind in {"no_numbers", "timeout", "no_code"}:
            self._update_route_stat(
                selector,
                candidate,
                lambda stat: self.route_policy.update_stat_for_outcome(
                    stat,
                    ok=False,
                    kind=kind,
                    now=outcome_now,
                ),
            )
            self._invalidate_candidate_cache(selector, candidate)
        stat = self._route_stat_snapshot(selector, candidate)
        cooldown = self.route_policy.cooldown_for(
            candidate,
            ok=bool(ok),
            kind=kind,
            error=error,
            stat=stat,
        )
        if cooldown > 0:
            self._set_route_cooldown(selector, candidate, cooldown)
            log_fn = getattr(selector, "log_fn", None)
            reason = {
                "no_numbers": "当前无可用号码",
                "timeout": "短信验证码未送达",
                "no_code": "短信验证码未送达",
            }.get(kind, "线路失败")
            _call_log(
                log_fn,
                f"  [SMS智能] 线路 {getattr(candidate, 'pool', '') or getattr(candidate, 'platform', '') or 'SMS'}/"
                f"{getattr(candidate, 'country', '-')}/"
                f"{getattr(candidate, 'provider_id', '-')} 因{reason}冷却 {cooldown} 秒",
                "warn",
            )
        return result

    def route_limit(self, _selector: Any, _candidate: Any, stat: Any, _now: float) -> int:
        return self.route_policy.route_limit(stat)

    def send_phone_number_otp(self, transport: Any, phone: str, channel: str = "sms") -> Any:
        task_id = self.transport_task_id(transport)

        def on_retry(delay: float, _attempt: int) -> None:
            log_fn = getattr(transport, "log_fn", None)
            _call_log(
                log_fn,
                f"  [Codex] 手机提交遇到临时服务错误，{delay:g} 秒后使用新的请求上下文重试当前号码",
                "warn",
            )

        def on_wait(elapsed_seconds: float) -> None:
            self._record_segment(
                task_id,
                "phone_slot_waiting",
                elapsed_seconds,
            )

        try:
            result = self.phone_gate.call_with_retries(
                self.original_send_phone_otp,
                transport,
                phone,
                channel,
                is_transient=self.sms_runtime.is_transient_openai_error,
                max_attempts=4,
                on_retry=on_retry,
                on_wait=on_wait,
                stop_event=(getattr(transport, "config", None) or {}).get("_stop_requested"),
            )
        except Exception as exc:
            if is_explicit_account_banned(exc):
                self._raise_account_banned(transport, exc)
            if is_session_invalid(exc):
                self.cancel_active_lease(self.transport_task_id(transport), "oauth_session_invalid")
            raise
        if is_session_invalid(result):
            self.cancel_active_lease(self.transport_task_id(transport), "oauth_session_invalid")
        result = self.ensure_account_active(transport, result)
        try:
            status = int(result.get("_status") or 0) if isinstance(result, dict) else 0
        except (TypeError, ValueError):
            status = 0
        if 200 <= status < 300:
            task_id = self.transport_task_id(transport)
            with self._active_lease_lock:
                active = self._active_leases.get(task_id)
            if active is not None:
                lease = active[1]
                meta = dict(getattr(lease, "meta", None) or {})
                meta["sms_order_state"] = "submitted"
                lease.meta = meta
                self._ledger_state(task_id, lease, "submitted")
        return result

    def runtime_alert(self, payload: Any) -> None:
        value = dict(payload or {})
        provider = str(value.get("provider") or "")
        kind = str(value.get("kind") or "sms_warning")
        prefix = f"{provider} " if provider else ""
        self.alerts.add(
            kind,
            f"{prefix}{str(value.get('message') or 'SMS Key 状态异常')}",
            level="warning",
            dedupe_key=f"runtime:{provider}:{value.get('fingerprint')}:{kind}",
            persistent=kind not in {"insufficient_balance", "sms_balance_insufficient"},
            provider=provider,
            key_index=value.get("index"),
            fingerprint=value.get("fingerprint") or "",
        )

    def configure_pool(self, config: Any, *, logs: Any = None, importer: Any = None) -> str:
        del importer
        value = dict(config or {})
        keys = self.sms_keys_from_config(value)
        proxy_scope = dict(value.get("proxy_scope") or {})
        sms_proxy = (
            str(value.get("proxy") or "")
            if self.as_enabled(proxy_scope.get("sms"), False)
            else ""
        )
        self._sms_proxy = sms_proxy

        def exhausted() -> None:
            message = "所有 SMS 平台和 Key 均已耗尽，停止创建新短信订单，已领取号码处理完成后安全停止"
            self.alerts.add(
                "sms_pool_exhausted",
                message,
                level="error",
                dedupe_key="runtime:all_sms_keys_exhausted",
                persistent=True,
            )
            if logs is not None:
                logs.add(message, "error")

        logger = logs.add if logs is not None else None
        try:
            min_price = float(value.get("sms_min_price") or self.min_price_default)
        except (TypeError, ValueError):
            min_price = self.min_price_default
        options = {
            "min_price": min_price,
            "max_price": float(self.clamp_max_price(value.get("max_price"))),
            "logger": logger,
            "alert_fn": self.runtime_alert,
            "exhausted_fn": exhausted,
        }
        if self.provider_registry is not None:
            self.provider_registry.configure(value, **options)
        else:
            self.key_pool.configure(
                keys,
                service=str(value.get("service") or "dr"),
                **options,
            )
        if self.cleanup_queue is not None:
            try:
                self.cleanup_queue.start_worker(self._retry_cleanup_entry)
            except Exception:
                pass
        return sms_proxy

    def query_balances(self, config: Any) -> list[dict[str, Any]]:
        """Check form credentials in an isolated registry with no runtime mutation."""
        value = dict(config or {})
        proxy_scope = dict(value.get("proxy_scope") or {})
        sms_proxy = (
            str(value.get("proxy") or "")
            if self.as_enabled(proxy_scope.get("sms"), False)
            else ""
        )
        try:
            min_price = float(value.get("sms_min_price") or self.min_price_default)
        except (TypeError, ValueError):
            min_price = self.min_price_default
        registry = self.sms_runtime.SmsProviderRegistry(self.original_create_provider)
        registry.configure(
            value,
            min_price=min_price,
            max_price=float(self.clamp_max_price(value.get("max_price"))),
        )
        statuses = registry.query_balances(proxy=sms_proxy)
        if not statuses:
            raise ValueError("请至少填写一个 SMS API Key")
        return statuses

    def preflight_pool(self, config: Any, *, logs: Any = None, importer: Any = None):
        proxy = self.configure_pool(config, logs=logs, importer=importer)
        pool = self.provider_registry or self.key_pool
        if not pool.has_keys():
            raise ValueError("请至少填写一个 SMS API Key")
        if self.cleanup_queue is not None:
            try:
                self.cleanup_queue.process(self._retry_cleanup_entry)
            except Exception:
                pass
        statuses = pool.preflight(proxy=proxy)
        insufficient = [row for row in statuses if row.get("status") == "insufficient_balance"]
        usable = [row for row in statuses if row.get("status") == "usable"]
        if statuses and len(insufficient) == len(statuses):
            raise ValueError("所有 SMS Key 余额不足")
        if not usable:
            details = "；".join(
                f"{row.get('provider') or 'SMS'} Key {row.get('index')}: "
                f"{row.get('message') or row.get('status')}"
                for row in statuses
            )
            raise ValueError(f"所有 SMS 平台和 Key 均不可用{f'：{details}' if details else ''}")
        inventory_known = any("inventory_count" in row for row in statuses)
        providers_with_inventory = {
            str(row.get("provider") or "")
            for row in usable
            if int(row.get("inventory_count") or 0) > 0
        }
        if inventory_known and not providers_with_inventory:
            raise ValueError("所有启用 SMS 平台当前均无可用库存")
        if insufficient:
            indexes = "、".join(
                f"{row.get('provider') + ' ' if row.get('provider') else ''}Key {row.get('index')}"
                for row in insufficient
            )
            message = f"{len(insufficient)} 个 SMS Key 余额不足（{indexes}），其余平台或 Key 仍可运行"
            self.alerts.add(
                "sms_balance_insufficient",
                message,
                level="warning",
                dedupe_key=f"preflight:balance:{indexes}",
                persistent=False,
            )
            if logs is not None:
                logs.add(message, "warn")
        unavailable = [
            row
            for row in statuses
            if row.get("status") not in {"usable", "insufficient_balance"}
        ]
        if unavailable:
            indexes = "、".join(
                f"{row.get('provider') + ' ' if row.get('provider') else ''}Key {row.get('index')}"
                for row in unavailable
            )
            message = f"{len(unavailable)} 个 SMS Key 不可用（{indexes}），本次运行已停用"
            self.alerts.add(
                "sms_key_unavailable",
                message,
                level="warning",
                dedupe_key=f"preflight:unavailable:{indexes}",
                persistent=False,
            )
            if logs is not None:
                logs.add(message, "warn")
        return statuses
