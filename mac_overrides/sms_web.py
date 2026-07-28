"""Web/runtime integration for adaptive SMS execution."""

from __future__ import annotations

import time
from typing import Any, Callable


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

    def safe_error(self, error: Any) -> str:
        return self.safe_error_fn(error)

    def clamp_max_price(self, value: Any) -> str:
        try:
            price = float(str(value or "").strip())
        except (TypeError, ValueError):
            return self.max_price_default
        if price <= 0 or price > 0.1:
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
        priority = {country: index for index, country in enumerate(self.priority_countries)}
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
            and str(getattr(item, "country", "")) in priority
            and min_price <= float(getattr(item, "price", 999.0) or 999.0) <= max_price
        ]
        return self.sms_runtime.rank_sms_candidates(
            rows,
            getattr(selector, "stats", {}),
            priority_routes=route_order,
            priority_countries=self.priority_countries,
        )

    def create_provider(self, name: str, api_key: str, proxy: str = "") -> Any:
        if str(name or "").strip().lower() == "smsbower" and self.key_pool.has_keys():
            return self.sms_runtime.PooledSmsBowerProvider(self.key_pool, proxy=proxy)
        return self.original_create_provider(name, api_key, proxy=proxy)

    @staticmethod
    def adapter_task_id(adapter: Any) -> str:
        config = getattr(adapter, "config", None) or {}
        return str(config.get("sms_task_id") or config.get("run_id") or "")

    def adapter_get_number(self, adapter: Any, **kwargs: Any) -> Any:
        task_id = self.adapter_task_id(adapter)
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
        code = self.original_adapter_wait_code(adapter, lease, timeout=timeout)
        if code and task_id:
            self.cost_ledger.mark_code_received(task_id, getattr(lease, "activation_id", ""))
            self.task_progress.set_stage(task_id, "sms_verifying")
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
            self.cost_ledger.mark_finished(
                task_id,
                getattr(lease, "activation_id", ""),
                "completed",
            )
        return result

    def adapter_cancel(self, adapter: Any, lease: Any, reason: str = "") -> Any:
        task_id = self.adapter_task_id(adapter)
        try:
            return self.original_adapter_cancel(adapter, lease, reason=reason)
        finally:
            if task_id:
                self.cost_ledger.mark_finished(
                    task_id,
                    getattr(lease, "activation_id", ""),
                    "cancelled",
                    self.safe_error(reason or ""),
                )

    def classify_error(self, error: Any) -> str:
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
        if candidate is None:
            return
        key = (
            str(getattr(candidate, "country", "")),
            str(getattr(candidate, "provider_id", "")),
        )
        if not all(key):
            return
        with selector.lock:
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
        now = time.time()

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
        until = time.time() + max(0, int(seconds))

        def update(stat: Any) -> dict[str, Any]:
            row = dict(stat or {})
            row["cooldown_until"] = max(float(row.get("cooldown_until") or 0), until)
            return row

        self._update_route_stat(selector, candidate, update)

    def smart_record_result(self, selector: Any, candidate: Any, ok: bool, error: Any = "") -> Any:
        kind = self.classify_error(error)
        if not ok and kind == "transient_server":
            self._release_route_without_score(selector, candidate)
            return None
        result = self.original_record_result(selector, candidate, ok, error)
        cooldown = self.route_policy.cooldown_for(candidate, ok=bool(ok), kind=kind, error=error)
        if cooldown > 0:
            self._set_route_cooldown(selector, candidate, cooldown)
            log_fn = getattr(selector, "log_fn", None)
            if callable(log_fn):
                log_fn(
                    f"  [SMS智能] 线路 {getattr(candidate, 'country', '-')}/"
                    f"{getattr(candidate, 'provider_id', '-')} 冷却 {cooldown} 秒",
                    "warn",
                )
        return result

    def route_limit(self, _selector: Any, _candidate: Any, stat: Any, _now: float) -> int:
        return self.route_policy.route_limit(stat)

    def send_phone_number_otp(self, transport: Any, phone: str, channel: str = "sms") -> Any:
        def on_retry(delay: float, _attempt: int) -> None:
            log_fn = getattr(transport, "log_fn", None)
            if callable(log_fn):
                log_fn(
                    f"  [Codex] 手机提交遇到临时服务错误，{delay:g} 秒后复用同一号码",
                    "warn",
                )

        return self.phone_gate.call_with_retries(
            self.original_send_phone_otp,
            transport,
            phone,
            channel,
            is_transient=self.sms_runtime.is_transient_openai_error,
            max_attempts=4,
            on_retry=on_retry,
        )

    def runtime_alert(self, payload: Any) -> None:
        value = dict(payload or {})
        self.alerts.add(
            str(value.get("kind") or "sms_warning"),
            str(value.get("message") or "SMS Key 状态异常"),
            level="warning",
            dedupe_key=f"runtime:{value.get('fingerprint')}:{value.get('kind')}",
            persistent=True,
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
            message = "所有 SMS Key 均已耗尽，停止创建新短信订单，已领取号码处理完成后安全停止"
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
        self.key_pool.configure(
            keys,
            service=str(value.get("service") or "dr"),
            min_price=min_price,
            max_price=float(self.clamp_max_price(value.get("max_price"))),
            logger=logger,
            alert_fn=self.runtime_alert,
            exhausted_fn=exhausted,
        )
        return sms_proxy

    def preflight_pool(self, config: Any, *, logs: Any = None, importer: Any = None):
        proxy = self.configure_pool(config, logs=logs, importer=importer)
        if not self.key_pool.has_keys():
            raise ValueError("请至少填写一个 SMS API Key")
        statuses = self.key_pool.preflight(proxy=proxy)
        insufficient = [row for row in statuses if row.get("status") == "insufficient_balance"]
        usable = [row for row in statuses if row.get("status") == "usable"]
        if statuses and len(insufficient) == len(statuses):
            raise ValueError("所有 SMS Key 余额不足")
        if not usable:
            details = "；".join(
                f"Key {row.get('index')}: {row.get('message') or row.get('status')}"
                for row in statuses
            )
            raise ValueError(f"所有 SMS Key 均不可用{f'：{details}' if details else ''}")
        if insufficient:
            indexes = "、".join(str(row.get("index")) for row in insufficient)
            message = f"{len(insufficient)} 个 SMS Key 余额不足（Key {indexes}），其余 Key 仍可运行"
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
            indexes = "、".join(str(row.get("index")) for row in unavailable)
            message = f"{len(unavailable)} 个 SMS Key 不可用（Key {indexes}），本次运行已停用"
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
