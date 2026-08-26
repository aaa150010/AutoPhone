"""Free registration manager with isolated storage and selectable drivers."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import copy
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping, Sequence

try:
    from .free_failure_runtime import (
        FreeFailureRuntimeMixin,
        canonical_failure,
        completed_result_state,
        exception_to_failure,
        sanitize_failure_text,
        sanitize_log_message,
        sanitize_proxy_attempts,
    )
    from .free_mailbox_otp import MailboxUrlOtpProvider
    from .free_proxy_health import is_proxy_health_failure
    from .free_register_common import (
        FREE_STAGE_LABELS,
        FIXED_PASSWORD,
        FreeMailbox,
        FreeRegisterError,
        FreeTwoFaPending,
        ProxyBinding,
        TERMINAL_STATUSES,
        fingerprint as _fingerprint,
        mask_proxy as _mask_proxy,
        random_birthdate,
        random_display_name,
        safe_log_message as _safe_log_message,
    )
    from .free_runtime_info import runtime_info
    from .free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore
    from .free_register_scheduler import FreeRegisterSchedulerMixin
    from .free_roxy_runtime import RoxyBrowserClient, RoxyRegistrationRunner
    from .free_roxy_lifecycle import RoxyCleanupStore, RoxyLifecycle
    from .free_log_runtime import FreeLogStore
    from .free_live_check import build_free_live_check_service
    from .free_plan_check import build_free_plan_check_service
    from .free_protocol_runtime import FreeProtocolMixin
    from .free_camoufox_runtime import CamoufoxRegistrationRunner, shutdown_camoufox_pools
except ImportError:
    from free_failure_runtime import (  # type: ignore[no-redef]
        FreeFailureRuntimeMixin,
        canonical_failure,
        completed_result_state,
        exception_to_failure,
        sanitize_failure_text,
        sanitize_log_message,
        sanitize_proxy_attempts,
    )
    from free_mailbox_otp import MailboxUrlOtpProvider  # type: ignore[no-redef]
    from free_proxy_health import is_proxy_health_failure  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FREE_STAGE_LABELS, FIXED_PASSWORD, FreeMailbox, FreeRegisterError, FreeTwoFaPending,
        ProxyBinding, TERMINAL_STATUSES,
        fingerprint as _fingerprint, mask_proxy as _mask_proxy,
        random_birthdate, random_display_name, safe_log_message as _safe_log_message,
    )
    from free_runtime_info import runtime_info  # type: ignore[no-redef]
    from free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore  # type: ignore[no-redef]
    from free_register_scheduler import FreeRegisterSchedulerMixin  # type: ignore[no-redef]
    from free_roxy_runtime import RoxyBrowserClient, RoxyRegistrationRunner  # type: ignore[no-redef]
    from free_roxy_lifecycle import RoxyCleanupStore, RoxyLifecycle  # type: ignore[no-redef]
    from free_log_runtime import FreeLogStore  # type: ignore[no-redef]
    from free_live_check import build_free_live_check_service  # type: ignore[no-redef]
    from free_plan_check import build_free_plan_check_service  # type: ignore[no-redef]
    from free_protocol_runtime import FreeProtocolMixin  # type: ignore[no-redef]
    from free_camoufox_runtime import CamoufoxRegistrationRunner, shutdown_camoufox_pools  # type: ignore[no-redef]
class FreeRegisterManager(FreeFailureRuntimeMixin, FreeRegisterSchedulerMixin, FreeProtocolMixin):
    # These nodes run before the flow confirms that a new account was created.
    # A failure here did not consume the mailbox, so the row can be dispatched
    # again while the task history remains failed for diagnosis.
    _REUSABLE_PRE_REGISTRATION_FAILURES = frozenset({
        "free_run_stop",
        "free_proxy_binding", "free_proxy_lease",
        "proxy_protocol_mismatch", "proxy_auth_rejected", "proxy_dns_failed",
        "proxy_connect_timeout", "proxy_connection_reset", "proxy_tls_certificate_error", "proxy_connect_failed",
        "free_roxy_api",
        "free_roxy_window_quota_exhausted",
        "free_roxy_create",
        "free_roxy_open",
        "free_roxy_connect",
        "free_roxy_signup_bootstrap",
        "free_roxy_signup_email", "free_roxy_signup_email_submit", "free_camoufox_dependency", "free_camoufox_launch", "free_camoufox_signup", "free_camoufox_browser", "oauth_create_node", "free_proxy_geo", "free_protocol_preflight", "free_protocol_warmup",
        "roxy_circuit_open",
    })

    def __init__(self, data_dir: str | Path, *, progress: Any = None, log_fn: Callable[[str, str], None] | None = None, runner: Callable[..., Mapping[str, Any]] | None = None, proxy_probe: Callable[[str, str], str] | None = None, proxy_chatgpt_probe: Callable[[str], int] | None = None, diagnostic_store: Any = None) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.pool = FreeMailboxPool(self.data_dir)
        self.proxies = FreeProxyPool(self.data_dir)
        self.task_store = FreeTaskStore(self.data_dir)
        self.log_store = FreeLogStore(self.data_dir, diagnostic_store=diagnostic_store)
        self.progress = progress
        self.log_fn = log_fn or self.log_store.add
        self.runner = runner or self._run_protocol
        self._custom_runner = runner is not None
        self.proxy_probe = proxy_probe
        self.proxy_chatgpt_probe = proxy_chatgpt_probe
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._executor: ThreadPoolExecutor | None = None
        self._futures: set[Future[Any]] = set()
        self._tasks: dict[str, dict[str, Any]] = self.task_store.load()
        self._batch_id = ""
        self._roxy_failures = 0
        self._roxy_circuit_open = False
        self._roxy_circuit_opened_at = 0.0
        self._circuit_stop_requested = False
        self._user_stop_requested = False
        self._last_config: dict[str, Any] = {}
        self.roxy_cleanup_store = RoxyCleanupStore(self.data_dir / "roxy_cleanup.json")
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._recover_interrupted_tasks()
        self.live_checks = build_free_live_check_service(
            self.data_dir,
            pool=self.pool, proxies=self.proxies, log_store=self.log_store,
            proxy_probe=self.proxy_probe, task_store=self.task_store,
        )
        self.plan_checks = build_free_plan_check_service(
            self.data_dir,
            pool=self.pool,
            task_store=self.task_store,
            log_store=self.log_store,
            task_updater=self._sync_plan_task_snapshot,
        )

    def _log(self, message: str, level: str = "info", **fields: Any) -> None:
        if callable(self.log_fn):
            try:
                self.log_fn(sanitize_log_message(message), level, **fields)
            except TypeError:
                # Third-party callbacks from older integrations only accept
                # (message, level); retain compatibility while the built-in
                # FreeLogStore receives the structured fields above.
                try:
                    self.log_fn(sanitize_log_message(message), level)
                except Exception:
                    pass
            except Exception:
                pass

    def _task_log(self, task_id: str, message: str, level: str = "info", **fields: Any) -> None:
        text = str(message or "")
        with self._lock:
            task_snapshot = dict(self._tasks.get(task_id) or {})
        diagnostic_store = getattr(self.log_store, "diagnostic_store", None)
        if diagnostic_store is not None and task_snapshot.get("email"):
            try:
                email_text = str(task_snapshot.get("email") or "")
                local_part, at, domain = email_text.partition("@")
                masked_email = f"{local_part[:1]}***@{domain[:80]}" if at and local_part and domain else "已脱敏账号"
                fields.setdefault("subject_kind", "email")
                fields.setdefault("subject_ref_fingerprint", diagnostic_store.fingerprint(email_text))
                fields.setdefault("subject_display", masked_email)
            except Exception:
                pass
        structured = re.match(r"^\[([^\]/]+)/([^\]/]+)(?:/([^\]]+))?\]\s*(.*)$", text)
        if structured:
            first, second, third, detail = structured.groups()
            if first == task_id:
                payload = dict(fields)
                payload.setdefault("task_id", task_id)
                self._log(text, level, **payload)
                return
            label = first if third is None else second
            code = second if third is None else third
            payload = dict(fields)
            payload.setdefault("task_id", task_id)
            payload.setdefault("node_code", code)
            payload.setdefault("node_label", label)
            self._log(f"[{task_id}/{label}/{code}] {detail}", level, **payload)
            return
        with self._lock:
            code = str(self._tasks.get(task_id, {}).get("stage") or "free_oauth_session")
        label = FREE_STAGE_LABELS.get(code, code)
        payload = dict(fields)
        payload.setdefault("task_id", task_id)
        payload.setdefault("node_code", code)
        payload.setdefault("node_label", label)
        self._log(f"[{task_id}/{label}/{code}] {text}", level, **payload)

    def _stage(self, task_id: str, code: str) -> None:
        changed = False
        if self.progress is not None and callable(getattr(self.progress, "set_stage", None)):
            try:
                changed = bool(self.progress.set_stage(task_id, code))
            except Exception:
                pass
        previous_code = ""
        previous_started = 0
        with self._lock:
            if task_id in self._tasks:
                previous_code = str(self._tasks[task_id].get("stage") or "")
                progress_before = self._tasks[task_id].get("progress") if isinstance(self._tasks[task_id].get("progress"), Mapping) else {}
                previous_started = int(progress_before.get("stage_started_at") or progress_before.get("started_at") or 0)
                changed = changed or previous_code != code
                self._tasks[task_id]["stage"] = code
                self._tasks[task_id]["updated_at"] = int(time.time())
                progress = self._tasks[task_id].setdefault("progress", {})
                stage_started_at = progress.get("stage_started_at")
                if previous_code != code or not stage_started_at:
                    stage_started_at = int(time.time())
                progress.update({
                    "stage": code,
                    "group": "free",
                    "started_at": progress.get("started_at") or int(time.time()),
                    "stage_started_at": stage_started_at,
                    "updated_at": int(time.time()),
                    "finished_at": None,
                })
                self.task_store.save(self._tasks)
        if changed:
            if previous_code and previous_code != code:
                duration_ms = max(0, int(time.time() - previous_started) * 1000) if previous_started else None
                self._log(
                    f"[{task_id}/{FREE_STAGE_LABELS.get(previous_code, previous_code)}/{previous_code}] 完成",
                    "success",
                    task_id=task_id, stage=previous_code,
                    stage_label=FREE_STAGE_LABELS.get(previous_code, previous_code),
                    node_code=previous_code,
                    node_label=FREE_STAGE_LABELS.get(previous_code, previous_code),
                    outcome="success", duration_ms=duration_ms,
                )
            label = FREE_STAGE_LABELS.get(code, code)
            self._log(
                f"[{task_id}/{label}/{code}] 开始", "info",
                task_id=task_id, stage=code, stage_label=label,
                node_code=code, node_label=label, outcome="started", attempt=1,
            )

    def _save_task(self, task_id: str, **values: Any) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            if "failure" in values and values.get("failure") is None:
                task.pop("failure", None)
                values = {key: value for key, value in values.items() if key != "failure"}
            task.update(values)
            task["updated_at"] = int(time.time())
            self.task_store.save(self._tasks)

    def _sync_plan_task_snapshot(self, row_id: str, result: Mapping[str, Any], promoted: bool) -> None:
        """Keep the in-memory public task view aligned with plan queue writes."""
        task_id = str(result.get("task_id") or "")
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                task = next(
                    (
                        item for item in self._tasks.values()
                        if str(item.get("row_id") or "") == str(row_id or "")
                    ),
                    None,
                )
            if not isinstance(task, dict):
                return
            task["result"] = copy.deepcopy(dict(result))
            task["updated_at"] = int(time.time())
            if promoted and str(task.get("status") or "") == "partial_success":
                task.update({"status": "success", "stage": "free_plan_check", "error": ""})
                task.pop("failure", None)
            self.task_store.save(self._tasks)

    def _finish_progress(self, task_id: str, outcome: str = "success") -> None:
        final_stage = ""
        final_label = ""
        duration_ms: int | None = None
        with self._lock:
            task = self._tasks.get(task_id)
            if task is not None:
                progress = task.setdefault("progress", {})
                final_stage = str(progress.get("stage") or task.get("stage") or "")
                final_label = FREE_STAGE_LABELS.get(final_stage, final_stage)
                started = int(progress.get("stage_started_at") or 0)
                duration_ms = max(0, int(time.time() - started) * 1000) if started else None
                progress["finished_at"] = int(time.time())
                progress["updated_at"] = int(time.time())
                self.task_store.save(self._tasks)
        if final_stage:
            self._log(
                f"[{task_id}/{final_label}/{final_stage}] 完成",
                "success" if outcome == "success" else "error" if outcome == "failed" else "warn",
                task_id=task_id, stage=final_stage, stage_label=final_label,
                node_code=final_stage, node_label=final_label,
                outcome=outcome, duration_ms=duration_ms,
            )
        if self.progress is not None and callable(getattr(self.progress, "finish", None)):
            try:
                self.progress.finish(task_id)
            except Exception:
                pass

    def _public_task(self, task: Mapping[str, Any]) -> dict[str, Any]:
        result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
        public = {key: copy.deepcopy(task[key]) for key in ("task_id", "incident_id", "ordinal", "slot_id", "slot_index", "concurrency_limit", "status", "created_at", "updated_at", "batch_id", "run_mode", "driver", "email", "row_id", "stage", "proxy_masked", "proxy_fingerprint", "profile_summary", "proxy_id", "proxy_scheme", "proxy_country", "proxy_group", "proxy_attempts", "cleanup_status") if key in task}
        public["account"] = public.get("email", "")
        mailbox_url = str(task.get("mailbox_url") or "").strip()
        if not mailbox_url and task.get("row_id"):
            try:
                mailbox = self.pool.entry(str(task.get("row_id") or ""))
                mailbox_url = str(getattr(mailbox, "mailbox_url", "") or "").strip() if mailbox is not None else ""
            except Exception:
                mailbox_url = ""
        # Expose only availability; the credential-bearing URL is revealed by
        # the dedicated endpoint after an explicit user action.
        public["has_mailbox_url"] = bool(mailbox_url)
        public["stage_label"] = FREE_STAGE_LABELS.get(str(public.get("stage") or ""), str(public.get("stage") or ""))
        public["result"] = {
            key: copy.deepcopy(result[key])
            for key in ("account_flow", "plan_type", "subscription_plan", "has_active_subscription", "plus_trial_eligible", "eligible_campaign_id", "plan_check_status", "plan_check_task_id", "plan_checked_at", "plan_error_code", "plan_http_status", "plan_retry_after_until", "twofa_status", "twofa_error", "has_access_token")
            if key in result
        }
        public["result"]["has_access_token"] = bool(result.get("access_token"))
        public["result"]["has_password"] = bool(result.get("password"))
        public["result"]["has_totp"] = bool(result.get("totp_secret"))
        public["result"]["has_credential"] = bool(result.get("credential_line"))
        for key, value in tuple(public["result"].items()):
            if isinstance(value, str):
                public["result"][key] = sanitize_failure_text(value, 300)
        if "proxy_attempts" in public:
            public["proxy_attempts"] = sanitize_proxy_attempts(public["proxy_attempts"])
        for key in ("profile_summary", "proxy_masked", "cleanup_status"):
            if key in public:
                public[key] = sanitize_failure_text(public[key], 300)
        progress = None
        if self.progress is not None and callable(getattr(self.progress, "progress", None)):
            try:
                progress = self.progress.progress(task.get("task_id"))
            except Exception:
                progress = None
        if isinstance(progress, Mapping):
            public["progress"] = copy.deepcopy(progress)
            if isinstance(progress.get("timing"), Mapping):
                public["timing"] = copy.deepcopy(progress["timing"])
        elif isinstance(task.get("progress"), Mapping):
            public["progress"] = copy.deepcopy(task["progress"])
        if isinstance(task.get("failure"), Mapping):
            failure = canonical_failure(task["failure"])
            if failure is not None:
                public["failure"] = failure
                public["error"] = failure["public_message"]
        return public

    def public_tasks(self) -> list[dict[str, Any]]:
        with self._lock:
            tasks = sorted(
                self._tasks.values(),
                key=lambda item: (
                    -int(item.get("created_at") or 0),
                    int(item.get("ordinal") or 0),
                    str(item.get("task_id") or ""),
                ),
            )
            return [self._public_task(task) for task in tasks]

    def public_logs(self, task_id: str = "") -> list[dict[str, Any]]:
        return self.log_store.snapshot(task_id)

    def recover_roxy_cleanup(self, config: Mapping[str, Any]) -> dict[str, int]:
        """Explicitly retry owned Roxy cleanup records.

        This method performs network calls only when a caller explicitly
        requests recovery (for example a Free preflight/cleanup button).
        Unknown/unmarked profiles are never scanned for deletion.
        """
        roxy = dict(config.get("roxybrowser") or {})
        roxy["lifecycle_store_path"] = str(self.data_dir / "roxy_cleanup.json")
        client = RoxyBrowserClient(roxy, log_fn=self._log)
        lifecycle = RoxyLifecycle(
            client,
            self.roxy_cleanup_store,
            log_fn=self._log,
            verify_timeout=float(roxy.get("cleanup_verify_timeout") or 8),
            verify_interval=float(roxy.get("cleanup_verify_interval") or 0.25),
            retries=int(roxy.get("api_retries") or 3),
        )
        intents = lifecycle.recover_creation_intents(limit=100)
        pending = lifecycle.recover_pending(limit=100)
        return {
            "examined": int(intents.get("examined") or 0) + int(pending.get("examined") or 0),
            "recovered": int(intents.get("recovered") or 0) + int(pending.get("recovered") or 0),
            "failed": int(intents.get("failed") or 0) + int(pending.get("failed") or 0),
        }

    def delete_tasks(self, task_ids: Sequence[str]) -> int:
        selected = {str(task_id or "").strip() for task_id in task_ids}
        selected.discard("")
        if not selected:
            raise ValueError("请选择要删除的 Free 任务")
        with self._lock:
            active = [task_id for task_id in selected if task_id in self._tasks and str(self._tasks[task_id].get("status") or "") not in TERMINAL_STATUSES]
            if active:
                raise ValueError(f"选中的 Free 任务中有 {len(active)} 条仍在排队或运行，请停止并等待任务结束后再删除")
            existing = [task_id for task_id in selected if task_id in self._tasks]
            for task_id in existing:
                self._tasks.pop(task_id, None)
            if existing:
                self.task_store.save(self._tasks)
        if existing:
            self.log_store.delete_tasks(existing)
        return len(existing)

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            tasks = self.public_tasks()
            active = sum(1 for task in tasks if task.get("status") not in TERMINAL_STATUSES)
            success = sum(1 for task in tasks if task.get("status") == "success")
            failed = sum(1 for task in tasks if task.get("status") == "failed")
            return {
                **runtime_info(),
                # Keep the batch marked running until every Future callback
                # has persisted its final task/log state.  Checking only
                # terminal task statuses races teardown and can leave an
                # atomic log temp file being written after a caller observes
                # running=False.
                "running": bool(self._executor and self._futures),
                "batch_id": self._batch_id,
                "tasks": tasks,
                "pool": {
                    "total": len(self.pool.entries()),
                    "available": self._available_count(),
                    "proxies": len(self.proxies.values()),
                },
                "proxy_groups": self.proxies.group_summaries() if callable(getattr(self.proxies, "group_summaries", None)) else [],
                "proxy_selection": {"country": "", "group": ""},
                "driver": str(next((task.get("driver") for task in reversed(list(self._tasks.values())) if task.get("batch_id") == self._batch_id), "protocol") or "protocol"),
                "scheduler": {
                    "concurrency": max(1, min(int(self._last_config.get("concurrency") or self._last_config.get("free_concurrency") or 3), 16)),
                    "active_slots": sum(1 for task in tasks if task.get("status") == "running"),
                    "queued_slots": sum(1 for task in tasks if task.get("status") == "queued"),
                    "roxy_circuit_open": bool(self._roxy_circuit_open),
                    "roxy_failures": int(self._roxy_failures),
                    "roxy_circuit_opened_at": self._roxy_circuit_opened_at or None,
                },
                "roxy_cleanup": {
                    "pending": len(self.roxy_cleanup_store.pending()),
                    "records": len(self.roxy_cleanup_store.records()),
                },
                "summary": {
                    "total": len(tasks),
                    "active": active,
                    "success": success,
                    "failed": failed,
                    "stopped": sum(1 for task in tasks if task.get("status") == "stopped"),
                },
            }

    def _available_count(self) -> int:
        return len(self.pool.available(10_000))

    def preflight(self, config: Mapping[str, Any], *, proxy_content: str = "") -> dict[str, Any]:
        with self._lock:
            if self.public_state().get("running"):
                raise FreeRegisterError(
                    "free_run_preflight",
                    "预检 Free 注册",
                    "Free 注册任务运行中，暂不能执行会回收 Roxy Profile 的批次预检",
                    retryable=False,
                )
        driver = str(config.get("driver") or "protocol").strip().lower()
        if driver not in {"protocol", "roxybrowser", "camoufox"}:
            raise FreeRegisterError("free_config", "Free 注册预检", "Free 注册链路无效", retryable=False)
        cleanup_result = {"examined": 0, "recovered": 0, "failed": 0}
        if driver == "roxybrowser" and not self._custom_runner:
            # Re-check while holding the same manager lock immediately before
            # the recovery scan; a start request cannot race this cleanup.
            with self._lock:
                if self.public_state().get("running"):
                    raise FreeRegisterError(
                        "free_run_preflight",
                        "预检 Free 注册",
                        "Free 注册任务运行中，暂不能执行 Roxy Profile 回收预检",
                        retryable=False,
                    )
                cleanup_result = self.recover_roxy_cleanup(config)
        protocol_result = {}
        if driver == "protocol" and not self._custom_runner:
            protocol_result = self.protocol_preflight(config)
        self.proxies.configure_policy(
            failure_threshold=int(config.get("proxy_failure_threshold") or 2),
            quarantine_seconds=int(config.get("proxy_quarantine_seconds") or 600),
            tls_verify=bool(config.get("proxy_tls_verify", True)),
            tls_compat_fallback=bool(config.get("proxy_tls_compat_fallback", True)),
            socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "auto"),
            allocation_mode="healthy_random",
        )
        available = self._available_count()
        requested = max(1, min(int(config.get("target_count") or 1), 200))
        target = min(requested, available)
        if target <= 0:
            raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", "Free 邮箱池没有可用邮箱", retryable=False)
        bindings = self.proxies.bind(
            target,
            content=proxy_content,
            probe=self.proxy_probe,
            probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
            driver=driver,
            perform_probe=False,
        )
        roxy_result = {"driver": driver}
        camoufox_result = {"driver": driver}
        if driver == "roxybrowser" and not self._custom_runner:
            roxy_result = RoxyRegistrationRunner.preflight(config)
        if driver == "camoufox" and not self._custom_runner:
            camoufox_result = CamoufoxRegistrationRunner.preflight(config)
        return {
            **runtime_info(),
            "driver": driver,
            "target_count": target,
            "mailboxes": available,
            "proxies": len(bindings),
            "protocol": protocol_result,
            "roxy": roxy_result,
            "camoufox": camoufox_result,
            "roxy_cleanup": cleanup_result,
            "proxy_selection": {"country": "", "group": ""},
        }

    def preflight_proxies(self, *, proxy_content: str = "", probe_url: str = "https://chatgpt.com/", driver: str = "protocol", country: str | None = None, group: str | None = None, scheme: str | None = None, tls_verify: bool = True, tls_compat_fallback: bool = True, socks5_dns_mode: str = "declared") -> dict[str, Any]:
        """Probe the isolated Free proxy pool without consuming mailboxes or tasks."""
        self.proxies.configure_policy(
            tls_verify=tls_verify,
            tls_compat_fallback=tls_compat_fallback,
            socks5_dns_mode=socks5_dns_mode,
        )
        if proxy_content.strip() and scheme:
            self.proxies.default_scheme = str(scheme).strip().lower()
        values = self.proxies.values(proxy_content)
        if not values:
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "请先粘贴或保存至少一个 Free 代理", retryable=False)
        diagnostics: list[dict[str, Any]] = []
        for index, value in enumerate(values, 1):
            try:
                self.proxies.bind(
                    1,
                    content=value,
                    probe=self.proxy_probe,
                    probe_url=probe_url,
                    driver=driver,
                    perform_probe=True,
                )
                row = dict((getattr(self.proxies, "_last_bind_diagnostics", ()) or [{}])[0])
                row.setdefault("index", index)
                row.setdefault("available", True)
                row.setdefault("http_status", 200)
                row.setdefault("failure_node", "")
                row.setdefault("failure_reason", "")
            except Exception as exc:
                failure = exception_to_failure(
                    exc,
                    node_code=str(getattr(exc, "error_code", "") or "proxy_connect_failed"),
                    node_label=str(getattr(exc, "node_label", "") or "代理连接失败"),
                )
                parsed = self.proxies._parse_lines(value, country="", group="", scheme=self.proxies.default_scheme)
                record = parsed[0] if parsed else {}
                row = {
                    "index": index,
                    "masked": _mask_proxy(value),
                    "fingerprint": str(record.get("proxy_id") or ""),
                    "scheme": str(record.get("scheme") or self.proxies.default_scheme),
                    "available": False,
                    "http_status": failure.get("http_status"),
                    "local_to_proxy_ms": None,
                    "proxy_to_target_ms": None,
                    "failure_node": failure.get("node_code") or "proxy_connect_failed",
                    "failure_reason": failure.get("technical_summary") or failure.get("public_message") or "代理请求失败",
                }
            row["index"] = index
            diagnostics.append(row)
        return {
            **runtime_info(),
            "proxies": len([row for row in diagnostics if row.get("available")]),
            "rows": diagnostics,
        }

    def start(self, config: Mapping[str, Any], *, pool_content: str = "", proxy_content: str = "", row_ids: Sequence[str] = ()) -> dict[str, Any]:
        with self._lock:
            # Keep the production manager boundary aligned with the Free
            # contract even for callers that bypass the HTTP config store.
            normalized_config = dict(config)
            normalized_config["auto_set_2fa"] = True
            self._last_config = copy.deepcopy(normalized_config)
            if self.public_state().get("running"):
                raise FreeRegisterError("free_run_start", "启动 Free 注册", "已有 Free 注册任务运行中", retryable=False)
            return self._start_locked(
                normalized_config,
                pool_content=pool_content,
                proxy_content=proxy_content,
                row_ids=row_ids,
            )

    def _start_locked(
        self,
        config: Mapping[str, Any],
        *,
        pool_content: str,
        proxy_content: str,
        row_ids: Sequence[str],
    ) -> dict[str, Any]:
        """Start a batch while ``start`` still owns the manager lock.

        Preflight can make a local Roxy API call, but the reservation and
        executor creation remain one transaction.  Releasing the lock between
        the running check and mailbox/proxy reservation allowed two concurrent
        start requests to both pass the check.
        """
        # Validate the full-protocol bridge before importing or leasing any
        # mailbox/proxy rows. Custom runners are test/integration adapters
        # and intentionally retain their existing contract.
        requested_driver = str(config.get("driver") or "protocol").strip().lower()
        cleanup_result = {"examined": 0, "recovered": 0, "failed": 0}
        if requested_driver == "roxybrowser" and not self._custom_runner:
            cleanup_result = self.recover_roxy_cleanup(config)
            if cleanup_result.get("failed"):
                self._log(
                    f"[RoxyBrowser/free_roxy_cleanup] 启动前仍有 {cleanup_result['failed']} 个 Profile 待清理，继续启动会保留队列",
                    "warn",
                )
        if requested_driver == "protocol" and not self._custom_runner:
            self.protocol_preflight(config)
        if pool_content.strip():
            self.pool.import_text(pool_content)
        # The argument is typed as str; this guard keeps the import conditional
        # while preserving the existing transaction body below.
        if proxy_content is None:
            proxy_content = ""
        if proxy_content is not None:
            if proxy_content.strip():
                self.proxies.import_text(proxy_content, scheme=str(config.get("proxy_default_scheme") or "http"))
            available_count = self._available_count()
            configured_free_count = config.get("target_count", config.get("free_target_count"))
            try:
                configured_free_count_value = int(configured_free_count)
            except (TypeError, ValueError):
                configured_free_count_value = 1
            requested_count = max(1, min(configured_free_count_value, 200))
            target_count = max(1, min(requested_count, available_count))
            requested_row_ids = {str(value or "").strip() for value in row_ids if str(value or "").strip()}
            if requested_row_ids:
                if len(requested_row_ids) > 200:
                    raise FreeRegisterError(
                        "free_pool_preflight",
                        "Free 邮箱池预检",
                        "单批次最多选择 200 个 Free 邮箱",
                        retryable=False,
                    )
                all_available = self.pool.available(10_000)
                rows = [row for row in all_available if row.row_id in requested_row_ids]
                if len(rows) != len(requested_row_ids):
                    raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", "快捷运行所选邮箱中有记录不存在或当前不可用", retryable=False)
                target_count = len(rows)
            else:
                rows = self.pool.available(target_count)
            if len(rows) < target_count:
                raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", f"Free 邮箱数量不足：需要 {target_count} 条，当前只有 {len(rows)} 条", retryable=False)
            driver = str(config.get("driver") or "protocol").strip().lower()
            if driver not in {"protocol", "roxybrowser", "camoufox"}:
                raise FreeRegisterError("free_config", "启动 Free 注册", "Free 注册链路无效", retryable=False)
            if driver == "roxybrowser" and not self._custom_runner:
                RoxyRegistrationRunner.preflight(config)
            if driver == "camoufox" and not self._custom_runner:
                CamoufoxRegistrationRunner.preflight(config)
            self.proxies.configure_policy(
                failure_threshold=int(config.get("proxy_failure_threshold") or 2),
                quarantine_seconds=int(config.get("proxy_quarantine_seconds") or 600),
                tls_verify=bool(config.get("proxy_tls_verify", True)),
                tls_compat_fallback=bool(config.get("proxy_tls_compat_fallback", True)),
                socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "auto"),
                allocation_mode="healthy_random",
            )
            bindings = self.proxies.bind(
                target_count,
                probe=self.proxy_probe,
                probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
                driver=driver,
                perform_probe=False,
            )
            batch_id = f"free-{int(time.time())}-{secrets.token_hex(4)}"
            now = int(time.time())
            workers = max(1, min(int(config.get("concurrency") or config.get("free_concurrency") or 3), target_count, 16))
            leased_bindings: list[ProxyBinding] = []
            created_task_ids: list[str] = []
            reserved = False
            try:
                self.pool.reserve(rows, batch_id)
                reserved = True
                for ordinal, (row, binding) in enumerate(zip(rows, bindings), 1):
                    task_id = f"{batch_id}-{ordinal}"
                    self._tasks[task_id] = {"task_id": task_id, "ordinal": ordinal, "slot_id": f"{batch_id}-slot-{((ordinal - 1) % workers) + 1}", "slot_index": ((ordinal - 1) % workers) + 1, "concurrency_limit": workers, "status": "queued", "created_at": now, "updated_at": now, "batch_id": batch_id, "run_mode": "free_register", "driver": driver, "proxy_allocation_mode": str(config.get("proxy_allocation_mode") or "healthy_random"), "email": row.email, "row_id": row.row_id, "mailbox_url": row.mailbox_url, "proxy": binding.proxy, "proxy_id": binding.proxy_id, "proxy_scheme": binding.scheme, "proxy_country": binding.country, "proxy_group": binding.group, "proxy_masked": binding.masked, "proxy_fingerprint": binding.fingerprint, "expected_exit_ip": binding.exit_ip, "registration_ip": "", "exit_ip": binding.exit_ip, "proxy_attempts": [], "cleanup_status": "pending", "progress": {"stage": "free_oauth_session", "group": "free", "started_at": now, "updated_at": now, "finished_at": None}, "result": {"twofa_status": "", "driver": driver, "expected_exit_ip": binding.exit_ip, "proxy_country": binding.country, "proxy_group": binding.group}}
                    self._tasks[task_id]["device_id"] = f"free-{secrets.token_hex(16)}"
                    created_task_ids.append(task_id)
                    self.proxies.lease(binding, owner=task_id, batch_id=batch_id, task_id=task_id)
                    leased_bindings.append(binding)
                    self.pool.update(row.row_id, status="queued", batch_id=batch_id, driver=driver, proxy=binding.proxy, proxy_masked=binding.masked, proxy_fingerprint=binding.fingerprint, expected_exit_ip=binding.exit_ip, exit_ip=binding.exit_ip, proxy_id=binding.proxy_id, proxy_country=binding.country, proxy_group=binding.group)
                    # Proxy preflight is an internal transport check; do not
                    # expose a successful validation stage in task logs.
                self.task_store.save(self._tasks)
            except Exception:
                for index, binding in reversed(list(enumerate(leased_bindings))):
                    try:
                        owner = created_task_ids[index] if index < len(created_task_ids) else batch_id
                        self.proxies.release(binding, owner=owner)
                    except Exception:
                        pass
                if reserved:
                    for row in rows:
                        try:
                            self.pool.update(row.row_id, status="available", batch_id="", stage="", driver="", proxy="", proxy_masked="", proxy_fingerprint="", expected_exit_ip="", exit_ip="", proxy_id="", proxy_country="", proxy_group="")
                        except Exception:
                            pass
                for task_id in created_task_ids:
                    self._tasks.pop(task_id, None)
                self.task_store.save(self._tasks)
                raise
            self._batch_id = batch_id
            self._roxy_failures = 0
            self._roxy_circuit_open = False
            self._roxy_circuit_opened_at = 0.0
            self._circuit_stop_requested = False
            self._user_stop_requested = False
            self._stop.clear()
            self._heartbeat_stop.clear()
            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, args=(batch_id,), name=f"free-proxy-heartbeat-{batch_id[-8:]}", daemon=True)
            self._heartbeat_thread.start()
            self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="free-register")
            for task_id in list(self._tasks):
                if self._tasks[task_id].get("batch_id") != batch_id:
                    continue
                future = self._executor.submit(self._worker, task_id, dict(config))
                self._futures.add(future)
                future.add_done_callback(self._future_done)
            self._log(f"[启动 Free 注册/free_run_start] 已准备 {target_count} 个邮箱，{workers} 并发", "success")
            return {
                "batch_id": batch_id,
                "tasks": self.public_tasks(),
                "state": self.public_state(),
                "roxy_cleanup": cleanup_result,
            }

    def _future_done(self, future: Future[Any]) -> None:
        cleanup_config: dict[str, Any] | None = None
        cleanup_camoufox = False
        executor: ThreadPoolExecutor | None = None
        with self._lock:
            if future not in self._futures:
                return
            is_last = len(self._futures) == 1
            if is_last:
                executor = self._executor
                self._heartbeat_stop.set()
                if not self._custom_runner:
                    driver = str(self._last_config.get("driver") or "").strip().lower()
                    if driver == "roxybrowser":
                        cleanup_config = copy.deepcopy(self._last_config)
                    elif driver == "camoufox":
                        cleanup_camoufox = True
            self.task_store.save(self._tasks)
        if cleanup_config is not None:
            try:
                result = self.recover_roxy_cleanup(cleanup_config)
                if result.get("examined"):
                    self._log(
                        f"[RoxyBrowser/free_roxy_cleanup] 批次结束回收：检查={result['examined']}，已释放={result['recovered']}，待重试={result['failed']}",
                        "info" if not result.get("failed") else "warn",
                    )
            except Exception as exc:
                self._log(
                    f"[RoxyBrowser/free_roxy_cleanup] 批次结束回收失败（{type(exc).__name__}）",
                    "warn",
                )
        if cleanup_camoufox:
            try:
                shutdown_camoufox_pools()
            except Exception as exc:
                self._log(f"[Camoufox/free_camoufox_launch] 批次结束回收浏览器池失败（{type(exc).__name__}）", "warn")
        with self._lock:
            self._futures.discard(future)
            if not self._futures and self._executor is executor and executor is not None:
                executor.shutdown(wait=False, cancel_futures=False)
                self._executor = None
                self.task_store.save(self._tasks)

    def _heartbeat_loop(self, owner: str) -> None:
        while not self._heartbeat_stop.wait(20):
            try:
                heartbeat_batch = getattr(self.proxies, "heartbeat_batch", None)
                if callable(heartbeat_batch):
                    heartbeat_batch(owner, lease_seconds=180)
                else:
                    self.proxies.heartbeat(owner, lease_seconds=180)
            except Exception:
                self._log(f"[{owner}/Free 代理租约/free_proxy_lease] 租约续期失败，任务将依靠过期时间恢复", "warn")

    def stop(self) -> None:
        self._stop.set()
        self._user_stop_requested = True
        with self._lock:
            for task_id, task in self._tasks.items():
                if task.get("batch_id") == self._batch_id and task.get("status") == "queued":
                    failure = {
                        "node_code": "free_run_stop", "node_label": "停止 Free 注册",
                        "error_code": "free_run_stopped",
                        "public_message": "停止 Free 注册 [停止 Free 注册/free_run_stop]：任务在执行前被用户停止",
                        "technical_summary": "任务在执行前被用户停止", "retryable": True,
                        "action_hint": "可重新选择该邮箱启动 Free 注册",
                    }
                    failure, _ = self._persist_task_failure(
                        task_id, task, status="stopped", failure=failure,
                    )
                    self.pool.update(
                        task["row_id"], status="stopped", stage=failure["node_code"],
                        error=failure["public_message"], failure=failure,
                    )
                    self._finish_progress(task_id, "stopped")
                    self._release_task_lease(task)
            self.task_store.save(self._tasks)
        self._log("[停止 Free 注册/free_stop] 已请求停止，运行中的账号不切换代理", "warn")

    def rerun(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        """Start a fresh batch for a failed task without losing its diagnostics."""
        normalized = str(task_id or "").strip()
        with self._lock:
            task = copy.deepcopy(self._tasks.get(normalized))
        if not task:
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "没有找到对应的 Free 任务", retryable=False)
        if str(task.get("status") or "") not in {"failed", "stopped"}:
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "只有失败或已停止的 Free 任务可以重跑", retryable=False)
        row_id = str(task.get("row_id") or "")
        row_state = self.pool._row_state(row_id) if row_id else {}
        pool_status = str(row_state.get("status") or "")
        if pool_status == "pending_rerun":
            self.pool.update(
                row_id, status="available", batch_id="", stage="", error="",
                reusable_after_failure=False,
            )
            pool_status = "available"
        if not row_id or pool_status != "available" or not any(row.row_id == row_id for row in self.pool.available(10_000)):
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "该账号当前不可重跑，请先在 Free 邮箱中心恢复为可用", retryable=False, error_code="free_rerun_mailbox_unavailable")
        self._log(f"[{normalized}/重跑 Free 账号/free_rerun] 使用待重跑邮箱重新创建独立批次，并重新分配代理", "info")
        return self.start(config, row_ids=[row_id])

    def retry_twofa(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(str(task_id))
            if task is None:
                row = self.pool.entry(str(task_id))
                saved = self.pool.result(str(task_id)) if row is not None else {}
                if row is not None and saved.get("twofa_status") == "pending" and saved.get("proxy"):
                    recovered_driver = str(saved.get("driver") or config.get("driver") or "protocol").strip().lower()
                    # Roxy is only the registration source.  Once its Profile
                    # is closed, 2FA retry deliberately moves to the shared
                    # protocol transport and never reopens or creates a
                    # browser Profile.
                    if recovered_driver == "roxybrowser":
                        recovered_driver = "protocol"
                    now = int(time.time())
                    recovered_task_id = f"free-2fa-{now}-{secrets.token_hex(4)}"
                    task = {
                        "task_id": recovered_task_id,
                        "ordinal": 1,
                        "status": "twofa_pending",
                        "created_at": now,
                        "updated_at": now,
                        "batch_id": str(saved.get("batch_id") or "free-2fa-retry"),
                        "run_mode": "free_register",
                        "email": row.email,
                        "row_id": row.row_id,
                        "mailbox_url": row.mailbox_url,
                        "proxy": str(saved.get("proxy") or ""),
                        "proxy_masked": _mask_proxy(saved.get("proxy")),
                        "proxy_fingerprint": _fingerprint(saved.get("proxy")),
                        "exit_ip": str(saved.get("exit_ip") or ""),
                        "driver": recovered_driver,
                        "result": saved,
                    }
                    self._tasks[recovered_task_id] = task
            if task is None or task.get("status") != "twofa_pending":
                raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该任务当前没有待重试的 2FA", retryable=False)
            result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
            driver = str(task.get("driver") or result.get("driver") or config.get("driver") or "protocol").strip().lower()
            if driver == "roxybrowser":
                driver = "protocol"
            if driver not in {"protocol", "camoufox"}:
                raise FreeRegisterError(
                    "free_twofa_retry", "重试 Free 账号 2FA",
                    "该任务的注册链路不支持 2FA 重试",
                    retryable=False, error_code="free_twofa_retry_driver_unsupported",
                )
            task["driver"] = driver
            task["status"] = "queued"
            task["updated_at"] = int(time.time())
            self.task_store.save(self._tasks)
            self._stop.clear()
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="free-2fa-retry")
            resolved_task_id = str(task["task_id"])
            retry_config = dict(config)
            retry_config["auto_set_2fa"] = True
            future = self._executor.submit(self._worker, resolved_task_id, retry_config, True)
            self._futures.add(future)
            future.add_done_callback(self._future_done)
            return self._public_task(task)

    def secret(self, task_ids: Sequence[str], kind: str, *, row_ids: Sequence[str] = ()) -> str:
        if kind not in {"token", "password", "totp", "proxy", "credential"}:
            raise FreeRegisterError("free_secret", "读取 Free 敏感字段", "不支持的敏感字段类型", retryable=False)
        values: list[str] = []
        seen_rows: set[str] = set()
        with self._lock:
            for task_id in task_ids:
                task = self._tasks.get(str(task_id))
                if not task:
                    continue
                seen_rows.add(str(task.get("row_id") or ""))
                result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
                value = {"token": result.get("access_token"), "password": result.get("password"), "totp": result.get("totp_secret"), "proxy": task.get("proxy"), "credential": result.get("credential_line")}.get(kind)
                if value:
                    values.append(str(value))
            for row_id in row_ids:
                normalized = str(row_id or "")
                if not normalized or normalized in seen_rows:
                    continue
                result = self.pool.result(normalized)
                private_state = self.pool._row_state(normalized)
                value = {"token": result.get("access_token"), "password": result.get("password"), "totp": result.get("totp_secret"), "proxy": result.get("proxy") or private_state.get("proxy"), "credential": result.get("credential_line")}.get(kind)
                if value:
                    values.append(str(value))
        return "\n".join(values)

    def temporary_totp(self, task_ids: Sequence[str] = (), *, row_ids: Sequence[str] = ()) -> dict[str, Any]:
        """Generate current 6-digit TOTP values without returning the seed."""
        secrets: list[str] = []
        seen_rows: set[str] = set()
        with self._lock:
            for task_id in task_ids:
                task = self._tasks.get(str(task_id))
                if not task:
                    continue
                row_id = str(task.get("row_id") or "")
                seen_rows.add(row_id)
                result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
                secret = str(result.get("totp_secret") or "").strip()
                if secret:
                    secrets.append(secret)
            for row_id in row_ids:
                normalized = str(row_id or "").strip()
                if not normalized or normalized in seen_rows:
                    continue
                seen_rows.add(normalized)
                result = self.pool.result(normalized)
                secret = str(result.get("totp_secret") or "").strip()
                if secret:
                    secrets.append(secret)
        if not secrets:
            raise FreeRegisterError(
                "free_totp",
                "读取 Free 临时 2FA 验证码",
                "选中的 Free 账号没有已启用的 2FA",
                retryable=False,
                error_code="free_totp_missing",
            )
        now = time.time()
        return {
            "code": "\n".join(self._totp_code(secret, now=now) for secret in secrets),
            "remaining": max(1, 30 - (int(now) % 30)),
        }

    def _verify_binding(self, task: Mapping[str, Any], config: Mapping[str, Any]) -> str:
        binding = ProxyBinding(
            str(task.get("proxy") or ""),
            str(task.get("proxy_fingerprint") or ""),
            str(task.get("proxy_masked") or ""),
            str(task.get("exit_ip") or ""),
            proxy_id=str(task.get("proxy_id") or ""),
            scheme=str(task.get("proxy_scheme") or ""),
            country=str(task.get("proxy_country") or ""),
            group=str(task.get("proxy_group") or ""),
        )
        if not binding.proxy:
            raise FreeRegisterError("free_proxy_lease", "读取 Free 代理租约", "代理租约记录不存在或已损坏", retryable=False)
        current = self.proxies.verify(
            binding,
            probe=self.proxy_probe,
            probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
        )
        if isinstance(task, dict):
            task["exit_ip"] = current
            task_id = str(task.get("task_id") or "")
            if task_id:
                self._save_task(task_id, exit_ip=current)
            row_id = str(task.get("row_id") or "")
            if row_id:
                self.pool.update(row_id, exit_ip=current)
        return current

    def _assert_batch_proxy_uniqueness(self, task: Mapping[str, Any]) -> None:
        """Compatibility hook: shared proxy allocation permits batch collisions."""
        _ = task

    def _release_task_lease(self, task: Mapping[str, Any]) -> None:
        try:
            binding = ProxyBinding(
                str(task.get("proxy") or ""),
                str(task.get("proxy_fingerprint") or ""),
                str(task.get("proxy_masked") or ""),
                str(task.get("expected_exit_ip") or task.get("exit_ip") or ""),
                proxy_id=str(task.get("proxy_id") or ""),
            )
            self.proxies.release(binding, owner=str(task.get("task_id") or ""))
            self._save_task(str(task.get("task_id") or ""), cleanup_status="released")
        except Exception as exc:
            self._save_task(str(task.get("task_id") or ""), cleanup_status=f"release_failed:{type(exc).__name__}")

    def _record_proxy_failure(self, task: Mapping[str, Any], exc: BaseException) -> None:
        proxy_id = str(task.get("proxy_id") or "")
        task_id = str(task.get("task_id") or "")
        with self._lock:
            current = self._tasks.get(task_id)
            if current is not None:
                attempts = current.setdefault("proxy_attempts", [])
                attempts.append({
                    "proxy_id": proxy_id,
                    "stage": str(getattr(exc, "node_code", "free_proxy")),
                    "retryable": bool(getattr(exc, "retryable", True)),
                    "message": _safe_log_message(exc),
                    "at": int(time.time()),
                })
                current["proxy_attempts"] = attempts[-10:]
                self.task_store.save(self._tasks)
        node_code = str(getattr(exc, "node_code", "free_proxy"))
        if proxy_id and is_proxy_health_failure(exc):
            self.proxies.record_failure(proxy_id, node_code=node_code, message=_safe_log_message(exc))

    @classmethod
    def _can_reuse_mailbox_after_failure(
        cls,
        node_code: str,
        error: BaseException | None = None,
    ) -> bool:
        normalized = str(node_code or "")
        if normalized in cls._REUSABLE_PRE_REGISTRATION_FAILURES:
            return True
        # A 429 from the OAuth bootstrap or first email-identification POST
        # happens before an OTP is dispatched. Return that mailbox to the
        # available pool while retaining the failed task diagnostic. Generic
        # email-identifier transport failures may have consumed the request,
        # so they remain pending for explicit rerun.
        if normalized in {"free_oauth_session", "free_email_identifier"}:
            try:
                status = int(getattr(error, "provider_status", 0) or 0)
            except (TypeError, ValueError):
                status = 0
            if status == 429:
                return True
            if bool(getattr(error, "proxy_retryable", False)):
                return True
        return False

    def _restore_mailbox_after_pre_registration_failure(self, task: Mapping[str, Any], failure: Mapping[str, Any]) -> None:
        """Return an unconsumed mailbox to the pool without hiding task history."""
        row_id = str(task.get("row_id") or "")
        if not row_id:
            return
        try:
            provider_status = int(failure.get("http_status") or 0)
        except (TypeError, ValueError):
            provider_status = 0
        try:
            retry_after = max(0, int(float(failure.get("retry_after_seconds") or 0)))
        except (TypeError, ValueError):
            retry_after = 0
        cooldown_until = None
        if provider_status == 429:
            # AutoRegister's BrowserSession uses a 300s circuit when the
            # provider omits Retry-After. Keep the mailbox selectable only
            # after that window, without replaying the failed request.
            cooldown_until = time.time() + max(retry_after, 300)
        self.pool.update(
            row_id,
            status="available",
            batch_id="",
            stage="",
            proxy="",
            proxy_masked="",
            proxy_fingerprint="",
            proxy_id="",
            proxy_scheme="",
            proxy_country="",
            proxy_group="",
            expected_exit_ip="",
            registration_ip="",
            exit_ip="",
            error=str(failure.get("public_message") or "Free 注册前置节点失败"),
            failure=copy.deepcopy(dict(failure)),
            reusable_after_failure=True,
            cooldown_until=cooldown_until or 0,
        )
        self._log(
            f"[{task.get('task_id', '')}/释放 Free 邮箱/free_mailbox_released] "
            "任务未确认账号创建，邮箱已自动恢复为可用，失败日志保留",
            "warn",
        )

    def _runner_for(self, config: Mapping[str, Any]) -> Callable[..., Mapping[str, Any]]:
        if self._custom_runner:
            return self.runner
        if str(config.get("driver") or "protocol").strip().lower() == "roxybrowser":
            # Keep Profile ownership outside task payloads while giving every
            # worker the same persistent journal for restart recovery.
            return RoxyRegistrationRunner(
                lifecycle_store_path=str(self.data_dir / "roxy_cleanup.json"),
            )
        if str(config.get("driver") or "protocol").strip().lower() == "camoufox":
            return CamoufoxRegistrationRunner(
                lifecycle_store_path=str(self.data_dir / "camoufox_cleanup.json"),
            )
        return self._run_protocol

    def _worker(self, task_id: str, config: dict[str, Any], twofa_retry: bool = False) -> None:
        self._maybe_recover_roxy_circuit(config)
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            if task.get("driver") == "roxybrowser" and self._roxy_circuit_open:
                failure = {
                    "node_code": "roxy_circuit_open",
                    "node_label": "RoxyBrowser 批次熔断",
                    "error_code": "roxy_circuit_open",
                    "public_message": "RoxyBrowser 批次熔断 [RoxyBrowser 批次熔断/roxy_circuit_open]：基础设施连续失败，未启动该账号",
                    "technical_summary": "RoxyBrowser 基础设施连续失败",
                    "retryable": True,
                }
                failure, _ = self._persist_task_failure(
                    task_id, task, status="failed", failure=failure,
                )
                self._restore_mailbox_after_pre_registration_failure(task, failure)
                self._release_task_lease(task)
                return
            task["status"] = "running"
            if twofa_retry:
                task.pop("failure", None)
            task["updated_at"] = int(time.time())
            snapshot = dict(task)
            snapshot_driver = str(snapshot.get("driver") or config.get("driver") or "protocol").strip().lower()
        task_config = dict(config)
        task_config["driver"] = snapshot_driver
        self._log(f"[{task_id}/free_oauth_session] Free 任务开始", "info")
        task_log = lambda message, level="info", **fields: self._task_log(task_id, message, level, **fields)
        try:
            if self._stop.is_set():
                raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在执行前已停止", retryable=False)
            retry_limit = max(0, min(5, int(task_config.get("proxy_retry_count") or 0)))
            # Proxy binding is intentionally not an exit-IP gate.  The
            # protocol runner performs the real ChatGPT/Auth/Sentinel
            # preflight before consuming the mailbox; browser drivers perform
            # their own page/profile connectivity checks.
            self._assert_batch_proxy_uniqueness(snapshot)
            runner = self._runner_for(task_config)
            attempt = 0
            while True:
                try:
                    result = dict(runner(snapshot, task_config, self._stop, self._stage, task_log, twofa_retry=twofa_retry))
                    break
                except FreeRegisterError as exc:
                    error_node = str(getattr(exc, "node_code", ""))
                    network_failure = is_proxy_health_failure(exc)
                    pre_profile = error_node in {"free_roxy_create", "free_roxy_open", "free_roxy_connect", "free_roxy_api"}
                    # OAuth bootstrap and the first email-identification POST
                    # are both route-level protocol nodes.  HTML login/error
                    # envelopes from either node may be retried on another
                    # healthy pool proxy when the flow marks them explicitly
                    # ``proxy_retryable``; business OTP/page failures do not.
                    protocol_pre_email = error_node in {
                        "free_protocol_preflight", "free_oauth_session", "free_email_identifier",
                    }
                    camoufox_pre_email = error_node == "free_camoufox_navigation" and bool(getattr(exc, "proxy_retryable", False))
                    can_retry_pre_email = ((pre_profile or protocol_pre_email) and network_failure) or (protocol_pre_email and bool(getattr(exc, "proxy_retryable", False))) or camoufox_pre_email
                    if not can_retry_pre_email or attempt >= retry_limit or self._stop.is_set():
                        raise
                    if network_failure: self._record_proxy_failure(snapshot, exc)
                    attempt += 1
                    switched = self._switch_pre_profile_proxy(snapshot, task_config)
                    self._assert_batch_proxy_uniqueness(snapshot)
                    with self._lock:
                        current = self._tasks.get(task_id)
                        if current is not None:
                            current.setdefault("proxy_attempts", []).append({"proxy_id": snapshot.get("proxy_id", ""), "stage": exc.node_code, "retryable": True, "message": _safe_log_message(exc), "attempt": attempt, "switched": switched, "at": int(time.time())})
                            self.task_store.save(self._tasks)
                    self._log(f"[{task_id}/Free 预注册重试/{exc.node_code}] 代理连接异常，{'切换备用代理' if switched else '重试当前代理'}（第 {attempt + 1} 次）", "warn")
            post_registration_failure = None
            verified_exit_ip = ""
            result.update({
                "task_id": task_id,
                "batch_id": snapshot.get("batch_id", ""),
                "proxy": snapshot.get("proxy", ""),
                "expected_exit_ip": snapshot.get("expected_exit_ip", ""),
                "registration_ip": result.get("registration_ip") or snapshot.get("expected_exit_ip") or snapshot.get("exit_ip", ""),
                "exit_ip": verified_exit_ip or snapshot.get("exit_ip") or result.get("exit_ip") or result.get("registration_ip", ""),
                "driver": snapshot.get("driver") or config.get("driver") or "protocol",
                "proxy_id": snapshot.get("proxy_id", ""),
                "proxy_scheme": snapshot.get("proxy_scheme", ""),
                "proxy_country": snapshot.get("proxy_country", ""),
                "proxy_group": snapshot.get("proxy_group", ""),
            })
            with self._lock:
                current = self._tasks.get(task_id)
                if current is not None:
                    current.setdefault("proxy_attempts", []).append({"proxy_id": snapshot.get("proxy_id", ""), "stage": "free_result_save", "outcome": "success", "at": int(time.time())})
                    current["proxy_attempts"] = current["proxy_attempts"][-10:]
            self._save_task(task_id, profile_summary=result.get("profile_summary", ""), registration_ip=result.get("registration_ip", ""))
            status, result, result_failure = completed_result_state(
                result,
                post_registration_failure=post_registration_failure,
            )
            if result_failure:
                result_failure, result = self._persist_task_failure(
                    task_id, snapshot, status=status, failure=result_failure, result=result,
                )
            else:
                self._save_task(task_id, status=status, result=result, failure=None)
                self.pool.save_result(snapshot["row_id"], result)
            self.pool.update(
                snapshot["row_id"], status=status, stage="free_result_save",
                registration_ip=result.get("registration_ip", ""),
                error=(result_failure or {}).get("public_message", ""),
                failure=result_failure,
            )
            self._stage(task_id, "free_result_save")
            self._finish_progress(task_id, "success" if status == "success" else "partial")
            self._release_task_lease(snapshot)
            failure_identity = f"{(result_failure or {}).get('node_label', '后置检查')}/{(result_failure or {}).get('node_code', 'unknown')}"
            result_label = "完成" if status == "success" else f"注册完成，{failure_identity}{'待重试' if status == 'twofa_pending' else '待处理'}"
            self._log(f"[{task_id}/free_result_save] Free 任务{result_label}", "success" if status == "success" else "warn")
        except FreeRegisterError as exc:
            node_code = str(exc.node_code or "free_protocol")
            node_label = str(exc.node_label or FREE_STAGE_LABELS.get(node_code, node_code))
            action_hint = str(getattr(exc, "action_hint", "") or "")
            if not action_hint:
                action_hint = {
                    "oauth_create_node": "检查 Node/SentinelRunner 路径、Node 运行时和当前代理连通性",
                    "free_proxy_lease": "检查代理租约记录和代理池状态",
                    "proxy_protocol_mismatch": "确认代理声明协议与服务商端口匹配",
                    "proxy_auth_rejected": "确认代理用户名、密码和白名单",
                    "proxy_dns_failed": "确认代理主机名和 DNS 可达性",
                    "proxy_connect_timeout": "确认代理地址、端口和网络可达性",
                    "proxy_connection_reset": "更换代理或稍后重试连接",
                    "proxy_tls_certificate_error": "确认代理证书链和 TLS 配置",
                    "proxy_connect_failed": "确认代理地址、端口和认证信息",
                    "free_roxy_create": "检查 RoxyBrowser API、工作区和项目配置",
                    "free_roxy_open": "检查 RoxyBrowser Profile 是否可打开且保持无头",
                    "free_roxy_connect": "检查 Roxy 返回的 debugger/webdriver 地址和驱动文件",
                    "free_oauth_security_challenge": "当前代理或会话遇到安全验证，请更换代理后重试",
                    "free_camoufox_navigation": "检查 Camoufox 代理、浏览器导航状态和上游 HTTP 状态",
                    "free_email_otp_wait": "确认邮箱取件 URL 可用，并在服务端发送验证码后重试",
                    "free_email_otp_validate": "确认验证码属于本次请求，必要时使用受控重发",
                    "free_oauth_callback": "检查 OAuth 回调地址、state 和当前会话是否一致",
                    "free_access_token": "检查 OAuth code、PKCE 和 Sentinel 会话是否过期",
                }.get(node_code, "根据节点日志检查上游响应和当前代理")
            failure = exception_to_failure(exc)
            if action_hint and not failure.get("action_hint"):
                failure["action_hint"] = action_hint
            error_node = node_code
            quota_failure = error_node == "free_roxy_window_quota_exhausted"
            if quota_failure:
                # A server-side window quota is a resource stop, not a
                # browser API circuit failure.  Stop admission for queued
                # tasks while keeping their mailbox/proxy reusable.
                with self._lock:
                    self._stop.set()
                    self._circuit_stop_requested = True
                self._log(f"[{task_id}/RoxyBrowser 窗口额度/free_roxy_window_quota_exhausted] 已停止继续创建窗口，等待遗留 Profile 清理", "error")
            circuit_failure = bool(self._roxy_circuit_open and error_node in {"free_roxy_api", "free_roxy_create", "free_roxy_open", "free_roxy_connect"})
            terminal_status = "failed" if quota_failure or circuit_failure or not self._stop.is_set() else "stopped"
            failure, _ = self._persist_task_failure(
                task_id, snapshot, status=terminal_status, failure=failure,
            )
            if self._can_reuse_mailbox_after_failure(exc.node_code, exc):
                self._restore_mailbox_after_pre_registration_failure(snapshot, failure)
            else:
                self.pool.update(
                    snapshot["row_id"], status="pending_rerun", stage=exc.node_code,
                    error=failure["public_message"], failure=failure,
                    reusable_after_failure=False,
                )
                self._log(
                    f"[{task_id}/Free 邮箱待重跑/free_mailbox_pending_rerun] "
                    "账号已进入注册流程，邮箱未自动恢复为可用；可从任务行重跑或邮箱中心手动恢复",
                    "warn",
                )
            self._finish_progress(task_id, "failed" if terminal_status == "failed" else "stopped")
            self._record_proxy_failure(snapshot, exc)
            self._roxy_failure(snapshot, exc)
            self._release_task_lease(snapshot)
            self._log(
                f"[{task_id}/{node_label}/{node_code}] {failure['public_message']}", "error",
                task_id=task_id, stage=node_code, stage_label=node_label,
                node_code=node_code, node_label=node_label,
                error_code=failure.get("error_code"), provider_code=failure.get("provider_code"),
                http_status=failure.get("http_status"), outcome="failed",
                diagnostic=failure.get("technical_summary"), action_hint=action_hint,
                retryable=failure.get("retryable"),
                page_type=failure.get("page_type"), safe_page=failure.get("safe_page"),
                content_type=failure.get("content_type"),
                session_rebuilds=failure.get("session_rebuilds"),
            )
        except FreeTwoFaPending as pending:
            # A retry can fail after the account and token already exist. Keep
            # the task retryable and persist the token/plan context instead of
            # turning the recoverable 2FA state into a generic protocol error.
            with self._lock:
                current = self._tasks.get(task_id, {})
                saved = current.get("result") if isinstance(current.get("result"), Mapping) else {}
            result = dict(saved)
            result.update({
                "access_token": pending.token,
                "plan_type": str(result.get("plan_type") or pending.plan_type or "free"),
                "subscription_plan": str(result.get("subscription_plan") or result.get("plan_type") or pending.plan_type or "free"),
                "plus_trial_eligible": bool(result.get("plus_trial_eligible", pending.plus_trial_eligible)),
                "twofa_status": "pending",
                "twofa_error": _safe_log_message(pending),
                "has_access_token": bool(pending.token),
            })
            failure = exception_to_failure(pending)
            result["twofa_failure"] = copy.deepcopy(failure)
            failure, result = self._persist_task_failure(
                task_id, snapshot, status="twofa_pending", failure=failure, result=result,
            )
            self.pool.update(snapshot["row_id"], status="twofa_pending", stage=failure["node_code"], error=failure["public_message"], failure=failure)
            self._stage(task_id, "free_twofa_activate")
            self._finish_progress(task_id, "partial")
            self._release_task_lease(snapshot)
            self._log(
                f"[{task_id}/激活 Free 账号 2FA/free_twofa_activate] 2FA 重试未完成，保留待重试状态：{_safe_log_message(pending)}",
                "warn", task_id=task_id, node_code=failure["node_code"],
                node_label=failure["node_label"], error_code=failure["error_code"],
                provider_code=failure.get("provider_code"), http_status=failure.get("http_status"),
                outcome="partial", diagnostic=failure.get("technical_summary"),
                action_hint=failure.get("action_hint"), retryable=failure.get("retryable"),
                page_type=failure.get("page_type"), safe_page=failure.get("safe_page"),
                content_type=failure.get("content_type"), session_rebuilds=failure.get("session_rebuilds"),
            )
        except Exception as exc:
            failure, classified_exc, current_stage, current_label = (
                self._persist_unexpected_task_failure(task_id, snapshot, exc)
            )
            self._finish_progress(task_id, "failed")
            self._record_proxy_failure(snapshot, classified_exc)
            self._roxy_failure(snapshot, classified_exc)
            self._release_task_lease(snapshot)
            self._log(
                f"[{task_id}/{current_label}/{current_stage}] {failure['public_message']}",
                "error", task_id=task_id, node_code=failure["node_code"],
                node_label=failure["node_label"], error_code=failure["error_code"],
                outcome="failed", diagnostic=failure.get("technical_summary"),
                action_hint=failure.get("action_hint"), retryable=failure.get("retryable"),
                page_type=failure.get("page_type"), safe_page=failure.get("safe_page"),
                content_type=failure.get("content_type"), session_rebuilds=failure.get("session_rebuilds"),
            )

__all__ = ["FIXED_PASSWORD", "FreeMailboxPool", "FreeProxyPool", "FreeRegisterError", "FreeRegisterManager", "MailboxUrlOtpProvider", "ProxyBinding", "random_birthdate", "random_display_name"]
