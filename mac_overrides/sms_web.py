"""Web/runtime integration for adaptive SMS execution."""

from __future__ import annotations

from threading import RLock
import time
from typing import Any, Callable

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
        self.sms_keys_from_config = sms_keys_from_config
        self.as_enabled = as_enabled
        self.safe_error_fn = safe_error
        self.provider_registry = provider_registry
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

    def clamp_max_price(self, value: Any) -> str:
        try:
            price = float(str(value or "").strip())
        except (TypeError, ValueError):
            return self.max_price_default
        if price <= 0 or price > 0.5:
            return self.max_price_default
        return f"{price:g}"



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
            if not isinstance(stat, dict) and len(key) == 3 and isinstance(route_stats, dict):
                stat = route_stats.get(key[-2:]) or route_stats.get("::".join(key[-2:]))
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
            priority_routes=route_order,
            priority_countries=self.priority_countries,
            now=now,
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
        lease.meta = meta
        try:
            self.original_adapter_cancel(adapter, lease, reason=reason)
        except Exception:
            pass
        try:
            self.cost_ledger.mark_finished(
                task_id,
                getattr(lease, "activation_id", ""),
                "cancelled",
                self.safe_error(reason),
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
        if provider is not None and hasattr(provider, "max_attempts_per_platform"):
            try:
                provider.max_attempts_per_platform = max(
                    1,
                    min(15, int(config.get("phone_attempts_per_provider") or 15)),
                )
            except (TypeError, ValueError):
                provider.max_attempts_per_platform = 15
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
        if task_id:
            self._remember_active_lease(task_id, adapter, lease)
            self.cost_ledger.record_lease(task_id, lease)
            self.task_progress.set_stage(task_id, "phone_submitting")
        return lease

    def adapter_mark_ready(self, adapter: Any, lease: Any) -> None:
        task_id = self.adapter_task_id(adapter)
        if task_id:
            self.task_progress.set_stage(task_id, "sms_waiting")
        provider = getattr(adapter, "provider", None)
        if provider is not None and hasattr(provider, "set_ready"):
            provider.set_ready()
        meta = dict(getattr(lease, "meta", None) or {})
        meta["ready_sent"] = True
        lease.meta = meta

    def adapter_wait_code(self, adapter: Any, lease: Any, timeout: int = 180) -> Any:
        task_id = self.adapter_task_id(adapter)
        if task_id:
            self.task_progress.set_stage(task_id, "sms_waiting")
        try:
            code = self.original_adapter_wait_code(adapter, lease, timeout=timeout)
        except Exception as exc:
            candidate = dict(getattr(lease, "meta", None) or {}).get("candidate")
            if self.classify_error(exc) in {"no_numbers", "timeout", "no_code"}:
                self._invalidate_candidate_cache(
                    getattr(adapter, "selector", None),
                    candidate,
                )
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
        return result

    def adapter_cancel(self, adapter: Any, lease: Any, reason: str = "") -> Any:
        task_id = self.adapter_task_id(adapter)
        meta = dict(getattr(lease, "meta", None) or {})
        if meta.get("gptphone_terminal_cancelled"):
            self._forget_active_lease(task_id, lease)
            return None
        provider = getattr(adapter, "provider", None)
        mark_rejected = getattr(provider, "mark_rejected", None)
        if self.classify_error(reason) == "phone_rejected" and callable(mark_rejected):
            mark_rejected()
        try:
            return self.original_adapter_cancel(adapter, lease, reason=reason)
        finally:
            if task_id:
                self._forget_active_lease(task_id, lease)
                self.cost_ledger.mark_finished(
                    task_id,
                    getattr(lease, "activation_id", ""),
                    "cancelled",
                    self.safe_error(reason or ""),
                )

    def classify_error(self, error: Any) -> str:
        if is_session_invalid(error):
            return "auth_session"
        if self.sms_runtime.is_transient_openai_error(error):
            return "transient_server"
        text = str(error or "").lower()
        if any(
            marker in text
            for marker in ("phone_otp_empty", "no sms code", "no verification code", "未收到验证码")
        ):
            return "timeout"
        return self.original_classify_error(error)

    @staticmethod
    def _update_route_stat(selector: Any, candidate: Any, update_fn: Callable[..., Any]) -> None:
        if selector is None or candidate is None:
            return
        platform = str(
            getattr(candidate, "platform", "")
            or getattr(candidate, "pool", "")
            or ""
        )
        country = str(getattr(candidate, "country", "") or "")
        provider_id = str(getattr(candidate, "provider_id", "") or "")
        key = (platform, country, provider_id) if platform else (country, provider_id)
        if not country or not provider_id:
            return
        with selector.lock:
            if len(key) == 3:
                stat = selector.stats.get(key)
                if not isinstance(stat, dict):
                    stat = selector.stats.get(key[-2:]) or selector.stats.get("::".join(key[-2:]))
                selector.stats[key] = update_fn(dict(stat or {}))
                return
            try:
                route_row, country_row = selector._update_shared_route_and_country(
                    key,
                    update_fn,
                    lambda stat: dict(stat or {}),
                )
                selector.stats[key] = route_row
                selector.country_stats[str(getattr(candidate, "country", ""))] = country_row
            except Exception:
                stat = dict(selector.stats.get(key) or {})
                selector.stats[key] = update_fn(stat)

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

    @staticmethod
    def _route_stat_snapshot(selector: Any, candidate: Any) -> dict[str, Any]:
        platform = str(
            getattr(candidate, "platform", "")
            or getattr(candidate, "pool", "")
            or ""
        )
        country = str(getattr(candidate, "country", "") or "")
        provider_id = str(getattr(candidate, "provider_id", "") or "")
        key = (platform, country, provider_id) if platform else (country, provider_id)
        if not country or not provider_id:
            return {}
        with selector.lock:
            value = selector.stats.get(key)
            if not isinstance(value, dict) and len(key) == 3:
                value = selector.stats.get(key[-2:]) or selector.stats.get("::".join(key[-2:]))
            return dict(value or {})

    def smart_record_result(self, selector: Any, candidate: Any, ok: bool, error: Any = "") -> Any:
        kind = self.classify_error(error)
        if not ok and kind in {"transient_server", "auth_session"}:
            self._release_route_without_score(selector, candidate)
            return None
        result = self.original_record_result(selector, candidate, ok, error)
        outcome_now = self._route_now()
        if ok:
            def remember_success(stat: Any) -> dict[str, Any]:
                row = self.route_policy.update_stat_for_outcome(
                    stat,
                    ok=True,
                    kind="success",
                    now=outcome_now,
                )
                row["last_success_at"] = outcome_now
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
        def on_retry(delay: float, _attempt: int) -> None:
            log_fn = getattr(transport, "log_fn", None)
            _call_log(
                log_fn,
                f"  [Codex] 手机提交遇到临时服务错误，{delay:g} 秒后使用新的请求上下文重试当前号码",
                "warn",
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
            )
        except Exception as exc:
            if is_explicit_account_banned(exc):
                self._raise_account_banned(transport, exc)
            if is_session_invalid(exc):
                self.cancel_active_lease(self.transport_task_id(transport), "oauth_session_invalid")
            raise
        if is_session_invalid(result):
            self.cancel_active_lease(self.transport_task_id(transport), "oauth_session_invalid")
        return self.ensure_account_active(transport, result)

    def runtime_alert(self, payload: Any) -> None:
        value = dict(payload or {})
        provider = str(value.get("provider") or "")
        prefix = f"{provider} " if provider else ""
        self.alerts.add(
            str(value.get("kind") or "sms_warning"),
            f"{prefix}{str(value.get('message') or 'SMS Key 状态异常')}",
            level="warning",
            dedupe_key=f"runtime:{provider}:{value.get('fingerprint')}:{value.get('kind')}",
            persistent=True,
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
        return sms_proxy

    def preflight_pool(self, config: Any, *, logs: Any = None, importer: Any = None):
        proxy = self.configure_pool(config, logs=logs, importer=importer)
        pool = self.provider_registry or self.key_pool
        if not pool.has_keys():
            raise ValueError("请至少填写一个 SMS API Key")
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
