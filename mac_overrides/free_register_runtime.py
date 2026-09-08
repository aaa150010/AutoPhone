"""Free registration manager with isolated storage and selectable drivers."""

from __future__ import annotations

import atexit
from concurrent.futures import Future
import copy
import os
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

try:
    from .diagnostic_writer import DiagnosticEventWriter, LogContext
    from .free_failure_runtime import (
        FreeFailureRuntimeMixin,
        PRIVATE_ACCOUNT_RESULT_KEYS,
        canonical_failure,
        completed_result_state,
        exception_to_failure,
        has_account_result,
        merge_account_result_fields,
        normalize_password_result,
        sanitize_failure_text,
        sanitize_log_message,
        sanitize_public_bool,
        sanitize_public_email,
        sanitize_public_http_status,
        sanitize_public_identifier,
        sanitize_public_manual_prompt,
        sanitize_public_number,
        sanitize_proxy_attempts,
        sanitize_public_scheme,
        sanitize_public_status,
        sanitize_public_progress,
        sanitize_public_timestamp,
        sanitize_public_timing,
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
        mask_email as _mask_email,
        mask_proxy as _mask_proxy,
        proxy_transport_value,
        random_birthdate,
        random_display_name,
        safe_log_message as _safe_log_message,
    )
    from .free_account_service import password_retry_allowed
    from .free_runtime_info import runtime_info
    from .free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore, _account_material_line
    from .free_storage_adapters import build_free_storage_adapters
    from .free_storage import ManagerOwnerConflict
    from .free_register.mailbox_lease import MailboxLeaseCoordinator
    from .free_register.retry_policy import consecutive_same_failures
    from .free_register_scheduler import FreeRegisterSchedulerMixin
    from .free_log_runtime import FreeLogStore
    from .free_live_check import build_free_live_check_service
    from .free_plan_check import build_free_plan_check_service
    from .free_protocol_runtime import FreeProtocolMixin
    from .free_register_bands import FreeRegisterProjectionMixin, FreeRegisterTimingMixin
    from .free_register_preflight import FreeRegisterPreflightMixin
    from .free_register_startup import FreeRegisterStartupMixin
    from .free_register_retry import FreeRegisterRetryMixin
    from .free_camoufox.runner import CamoufoxRunner
    from .free_camoufox_runtime import (
        CamoufoxRegistrationRunner,
        annotate_camoufox_debug_session,
        camoufox_debug_state,
        close_camoufox_debug_browsers,
    )
    from .free_notifications import FreeBatchNotificationAdapter
    from .free_priority_executor import PriorityExecutor
except ImportError:
    from diagnostic_writer import DiagnosticEventWriter, LogContext  # type: ignore[no-redef]
    from free_failure_runtime import (  # type: ignore[no-redef]
        FreeFailureRuntimeMixin,
        PRIVATE_ACCOUNT_RESULT_KEYS,
        canonical_failure,
        completed_result_state,
        exception_to_failure,
        has_account_result,
        merge_account_result_fields,
        normalize_password_result,
        sanitize_failure_text,
        sanitize_log_message,
        sanitize_public_bool,
        sanitize_public_email,
        sanitize_public_http_status,
        sanitize_public_identifier,
        sanitize_public_manual_prompt,
        sanitize_public_number,
        sanitize_proxy_attempts,
        sanitize_public_scheme,
        sanitize_public_status,
        sanitize_public_progress,
        sanitize_public_timestamp,
        sanitize_public_timing,
    )
    from free_mailbox_otp import MailboxUrlOtpProvider  # type: ignore[no-redef]
    from free_proxy_health import is_proxy_health_failure  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FREE_STAGE_LABELS, FIXED_PASSWORD, FreeMailbox, FreeRegisterError, FreeTwoFaPending,
        ProxyBinding, TERMINAL_STATUSES,
        fingerprint as _fingerprint, mask_email as _mask_email, mask_proxy as _mask_proxy,
        proxy_transport_value,
        random_birthdate, random_display_name, safe_log_message as _safe_log_message,
    )
    from free_account_service import password_retry_allowed  # type: ignore[no-redef]
    from free_runtime_info import runtime_info  # type: ignore[no-redef]
    from free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore, _account_material_line  # type: ignore[no-redef]
    from free_storage_adapters import build_free_storage_adapters  # type: ignore[no-redef]
    from free_storage import ManagerOwnerConflict  # type: ignore[no-redef]
    from free_register.mailbox_lease import MailboxLeaseCoordinator  # type: ignore[no-redef]
    from free_register.retry_policy import consecutive_same_failures  # type: ignore[no-redef]
    from free_register_scheduler import FreeRegisterSchedulerMixin  # type: ignore[no-redef]
    from free_log_runtime import FreeLogStore  # type: ignore[no-redef]
    from free_live_check import build_free_live_check_service  # type: ignore[no-redef]
    from free_plan_check import build_free_plan_check_service  # type: ignore[no-redef]
    from free_protocol_runtime import FreeProtocolMixin  # type: ignore[no-redef]
    from free_register_bands import FreeRegisterProjectionMixin, FreeRegisterTimingMixin  # type: ignore[no-redef]
    from free_register_preflight import FreeRegisterPreflightMixin  # type: ignore[no-redef]
    from free_register_startup import FreeRegisterStartupMixin  # type: ignore[no-redef]
    from free_register_retry import FreeRegisterRetryMixin  # type: ignore[no-redef]
    from free_camoufox.runner import CamoufoxRunner  # type: ignore[no-redef]
    from free_camoufox_runtime import (  # type: ignore[no-redef]
        CamoufoxRegistrationRunner,
        annotate_camoufox_debug_session,
        camoufox_debug_state,
        close_camoufox_debug_browsers,
    )
    from free_notifications import FreeBatchNotificationAdapter  # type: ignore[no-redef]
    from free_priority_executor import PriorityExecutor  # type: ignore[no-redef]
class FreeRegisterManager(
    FreeFailureRuntimeMixin,
    FreeRegisterSchedulerMixin,
    FreeRegisterPreflightMixin,
    FreeRegisterStartupMixin,
    FreeRegisterRetryMixin,
    FreeProtocolMixin,
    FreeRegisterTimingMixin,
    FreeRegisterProjectionMixin,
):
    # These nodes run before the flow confirms that a new account was created.
    # A failure here did not consume the mailbox, so the row can be dispatched
    # again while the task history remains failed for diagnosis.
    _REUSABLE_PRE_REGISTRATION_FAILURES = frozenset({
        "free_run_stop",
        "free_proxy_binding", "free_proxy_lease",
        "proxy_protocol_mismatch", "proxy_auth_rejected", "proxy_dns_failed",
        "proxy_connect_timeout", "proxy_connection_reset", "proxy_tls_certificate_error", "proxy_connect_failed",
        "free_camoufox_dependency", "oauth_create_node", "free_proxy_geo", "free_protocol_preflight", "free_protocol_warmup",
    })

    def __init__(self, data_dir: str | Path, *, progress: Any = None, log_fn: Callable[[str, str], None] | None = None, runner: Callable[..., Mapping[str, Any]] | None = None, proxy_probe: Callable[[str, str], str] | None = None, proxy_chatgpt_probe: Callable[[str], int] | None = None, diagnostic_store: Any = None, manual_broker: Any = None, notification_config_getter: Callable[[], Any] | None = None, config_provider: Callable[[], Mapping[str, Any]] | None = None, storage_adapters: Any = None) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        # Production Free data lives under an explicitly isolated
        # ``free_register`` directory.  It uses one shared SQLite store for
        # mailbox, proxy, task and result state; arbitrary temporary/custom
        # directories retain the historical JSON stores unless a caller
        # injects adapters explicitly.
        if storage_adapters is None and self.data_dir.name == "free_register":
            storage_adapters = build_free_storage_adapters(self.data_dir)
        self.storage_adapters = storage_adapters
        self.storage = getattr(storage_adapters, "storage", None)
        self.mailbox_leases = None
        if storage_adapters is not None:
            try:
                self.pool = storage_adapters.mailboxes
                self.proxies = storage_adapters.proxies
                self.task_store = storage_adapters.tasks
            except AttributeError as exc:
                raise TypeError(
                    "storage_adapters must expose mailboxes, proxies and tasks"
                ) from exc
            self.task_repository = getattr(storage_adapters, "task_repository", None)
            if self.task_repository is None and self.storage is not None:
                try:
                    from .free_register.task_repository import FreeTaskRepository
                except ImportError:  # pragma: no cover
                    from free_register.task_repository import FreeTaskRepository  # type: ignore[no-redef]
                self.task_repository = FreeTaskRepository(
                    self.data_dir,
                    storage=self.storage,
                )
            if self.storage is not None:
                self.mailbox_leases = MailboxLeaseCoordinator(self.storage)
        else:
            self.pool = FreeMailboxPool(self.data_dir)
            self.proxies = FreeProxyPool(self.data_dir)
            self.task_store = FreeTaskStore(self.data_dir)
            self.task_repository = None
        # Structured diagnostics are the source of truth for the production
        # Free manager.  Keep the legacy JSON projection available only for
        # callers that do not provide a DiagnosticStore (older integrations
        # and focused unit tests still rely on that callback contract).
        log_options: dict[str, Any] = {}
        if diagnostic_store is not None and self.data_dir.name == "free_register":
            log_options.update({
                "legacy_projection": False,
                "cleanup_legacy": True,
                "strict_diagnostic_reads": True,
            })
        self.log_store = FreeLogStore(
            self.data_dir,
            diagnostic_store=diagnostic_store,
            **log_options,
        )
        self.progress = progress
        self.log_fn = log_fn or self.log_store.add
        self.runner = runner or self._run_protocol
        self._custom_runner = runner is not None
        self.proxy_probe = proxy_probe
        self.proxy_chatgpt_probe = proxy_chatgpt_probe
        self.manual_broker = manual_broker
        self.config_provider = config_provider
        self._free_notification = FreeBatchNotificationAdapter(notification_config_getter) if callable(notification_config_getter) else None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._executor: PriorityExecutor | None = None
        self._futures: set[Future[Any]] = set()
        # Keep the driver on each Future so terminal cleanup never follows the
        # previous batch's global configuration.
        self._future_drivers: dict[Future[Any], str] = {}
        self._tasks: dict[str, dict[str, Any]] = self.task_store.load()
        if self.mailbox_leases is not None:
            # Expired claims are recovered before dispatch.  This only clears
            # leases owned by this isolated Free database and never changes
            # proxy health or ordinary registration state.
            try:
                self.mailbox_leases.recover()
            except Exception:
                pass
        self._batch_id = ""
        self._circuit_stop_requested = False
        self._user_stop_requested = False
        self._last_config: dict[str, Any] = {}
        self._stage_started_mono: dict[str, float] = {}
        self._task_started_mono: dict[str, float] = {}
        # Adapter timing is diagnostic-only.  Keep a short checkpoint window
        # so a profile with many substeps does not synchronously rewrite the
        # entire task table for every callback while holding the manager lock.
        self._timing_checkpoint_mono: dict[str, float] = {}
        self._manual_generations: dict[str, int] = {}
        self._retry_leases: dict[str, str] = {}
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        # Process-level fencing is intentionally lazy: constructing a second
        # manager for an idle/test directory must not claim the runtime, while
        # a real batch must have one durable owner shared across processes.
        self._manager_owner_id = f"free-manager-{os.getpid()}-{secrets.token_hex(8)}"
        self._manager_owner_epoch = 0
        self._manager_owner_acquired = False
        self._manager_owner_fence_reported = False
        self._runtime_fenced = False
        if self._owner_storage() is not None:
            atexit.register(self._release_runtime_owner)
        # Set while ``start`` is assembling a new batch.  The manager keeps
        # the previous completed batch id for UI history, so using
        # ``_batch_id`` alone cannot identify which rows belong to a failed
        # startup rollback.
        self._startup_batch_id = ""
        # Set while the final Future callback is joining executor/heartbeat
        # threads. This closes the small window where no Future remains but a
        # new start/retry could otherwise replace the still-draining handles.
        self._shutdown_pending = False
        self._reconcile_account_results_from_history()
        # Do not classify active rows as interrupted while another live
        # manager still owns the database.  This is the critical handoff
        # guard for LaunchAgent reloads: the old worker gets time to drain,
        # and a new manager cannot rewrite its task history underneath it.
        self._runtime_fenced = self._runtime_owner_is_live()
        if not self._runtime_fenced:
            self._recover_interrupted_tasks()
        for existing_id, existing_task in self._tasks.items():
            if str(existing_task.get("status") or "") in {"queued", "running"} and existing_task.get("retry_key"):
                self._retry_leases[str(existing_task["retry_key"])] = str(existing_id)
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
            config_provider=self._plan_config,
            task_updater=self._sync_plan_task_snapshot,
        )

    def _plan_config(self) -> Mapping[str, Any]:
        """Return the normalized Free settings used by post-registration calls."""
        if callable(self.config_provider):
            try:
                value = self.config_provider()
            except Exception:
                value = None
            if isinstance(value, Mapping):
                return value
        return self._last_config

    # ------------------------------------------------------------------
    # Process owner fencing
    # ------------------------------------------------------------------
    def _owner_storage(self) -> Any | None:
        storage = getattr(self, "storage", None)
        if storage is None or not callable(getattr(storage, "acquire_manager_owner", None)):
            return None
        return storage

    def _runtime_owner_is_live(self) -> bool:
        """Return whether another manager currently fences this database."""
        storage = self._owner_storage()
        if storage is None:
            return False
        try:
            status = storage.manager_owner_status()
        except Exception:
            # An unavailable metadata read must not make a fresh process
            # overwrite active task rows. Treat the runtime as fenced until a
            # later explicit start can establish ownership atomically.
            return True
        return bool(isinstance(status, Mapping) and status.get("active"))

    def _acquire_runtime_owner(self) -> None:
        """Claim the isolated Free database before reserving any resources."""
        storage = self._owner_storage()
        if storage is None:
            return
        if self._manager_owner_acquired:
            if self._owner_current():
                return
            self._runtime_fenced = True
            raise FreeRegisterError(
                "free_process_owner",
                "Free 进程所有权",
                "当前 Free 进程已失去数据库所有权，拒绝继续写入",
                retryable=True,
                error_code="free_manager_epoch_mismatch",
                action_hint="停止当前服务并等待旧任务退出后重新启动",
            )
        try:
            owner = storage.acquire_manager_owner(
                self._manager_owner_id,
                pid=os.getpid(),
            )
        except ManagerOwnerConflict as exc:
            self._runtime_fenced = True
            raise FreeRegisterError(
                "free_process_owner",
                "Free 进程所有权",
                "已有 Free 注册进程正在运行，请先等待上一批任务停止",
                retryable=True,
                error_code="free_manager_already_running",
                action_hint="调用停止并等待任务完成，或确认旧进程已退出后重试",
                provider_code=str(exc.owner.get("pid") or ""),
            ) from exc
        except Exception as exc:
            raise FreeRegisterError(
                "free_process_owner",
                "Free 进程所有权",
                "Free 进程所有权暂时无法建立",
                retryable=True,
                error_code="free_manager_owner_store_failed",
                action_hint="检查 Free SQLite 数据库权限和锁状态后重试",
                provider_code=type(exc).__name__,
            ) from exc
        self._manager_owner_epoch = int(owner.get("epoch") or 0)
        self._manager_owner_acquired = True
        self._runtime_fenced = False
        self._manager_owner_fence_reported = False

    def _ensure_runtime_owner(self) -> None:
        """Require a valid owner for retry/continuation writes."""
        self._acquire_runtime_owner()

    def _owner_current(self) -> bool:
        storage = self._owner_storage()
        if storage is None or not self._manager_owner_acquired:
            return True
        try:
            return bool(
                storage.manager_owner_is_current(
                    self._manager_owner_id,
                    self._manager_owner_epoch,
                )
            )
        except Exception:
            return False

    def _record_owner_fenced(self, *, task_id: str = "") -> None:
        """Emit one credential-free event when a stale worker is fenced."""
        if self._manager_owner_fence_reported:
            return
        self._manager_owner_fence_reported = True
        try:
            self._log(
                f"[{task_id or 'free'}/Free 进程所有权/free_process_owner] "
                "旧 worker 写入被拒绝，数据库已由新进程接管",
                "warn",
                task_id=task_id,
                node_code="free_process_owner",
                node_label="Free 进程所有权",
                outcome="stale_writer_rejected",
                error_code="free_manager_epoch_mismatch",
                workflow="lifecycle",
            )
        except Exception:
            pass

    def _release_runtime_owner(self) -> None:
        storage = self._owner_storage()
        if storage is None or not self._manager_owner_acquired:
            return
        owner_id = self._manager_owner_id
        epoch = self._manager_owner_epoch
        self._manager_owner_acquired = False
        try:
            storage.release_manager_owner(owner_id, epoch)
        except Exception:
            # Process exit/cleanup is best effort; a dead PID and TTL let the
            # next manager reclaim the fence even if this write fails.
            pass

    def _reconcile_account_results_from_history(self) -> int:
        """Restore missing private result fields from immutable task history.

        Older runtimes could replace a successful result with a later failure
        envelope.  Task snapshots still contain the account evidence, so fill
        only missing private fields in the durable row.  Status and diagnostic
        fields remain owned by the latest result and are never rewritten here.
        """
        grouped: dict[str, list[tuple[float, int, Mapping[str, Any]]]] = {}
        for index, task in enumerate(self._tasks.values()):
            if not isinstance(task, Mapping):
                continue
            row_id = str(task.get("row_id") or "").strip()
            if not row_id:
                continue
            candidates: list[Mapping[str, Any]] = []
            result = task.get("result")
            if isinstance(result, Mapping):
                candidates.append(result)
            # A few pre-1.6 snapshots stored result fields at task level.
            candidates.append(task)
            for candidate in candidates:
                if not has_account_result(candidate):
                    continue
                try:
                    order = float(candidate.get("updated_at") or task.get("updated_at") or task.get("created_at") or 0)
                except (TypeError, ValueError):
                    order = 0.0
                grouped.setdefault(row_id, []).append((order, index, candidate))

        repaired_count = 0
        for row_id, candidates in grouped.items():
            reader = getattr(self.pool, "result_with_status", None)
            if callable(reader):
                try:
                    durable, readable = reader(row_id)
                except Exception:
                    readable = False
                    durable = {}
                if not readable:
                    self._log(
                        "Free 账号结果历史回填跳过：结果文件暂时无法读取",
                        "warn",
                        node_code="free_result_store",
                        node_label="读取 Free 账号结果",
                        outcome="storage_warning",
                    )
                    continue
            else:
                try:
                    durable = self.pool.result(row_id)
                except Exception:
                    continue
            if not isinstance(durable, Mapping):
                durable = {}
            history_fields: dict[str, Any] = {}
            for _order, _index, candidate in sorted(candidates, key=lambda item: (item[0], item[1])):
                for key in PRIVATE_ACCOUNT_RESULT_KEYS:
                    value = candidate.get(key)
                    if value is None or value is False or (isinstance(value, str) and not value.strip()):
                        continue
                    history_fields[key] = copy.deepcopy(value)
            if not history_fields:
                continue
            repaired = merge_account_result_fields(history_fields, durable)
            if repaired == dict(durable):
                continue
            try:
                self.pool.save_result(row_id, repaired)
                repaired_count += 1
            except Exception:
                self._log(
                    "Free 账号结果历史回填写入失败，保留现有结果",
                    "warn",
                    node_code="free_result_store",
                    node_label="保存 Free 账号结果",
                    outcome="storage_warning",
                )
        return repaired_count

    def _log(self, message: str, level: str = "info", **fields: Any) -> None:
        if callable(self.log_fn):
            # Keep task-scoped lifecycle events on the same diagnostic scope
            # as the terminal failure.  The facade's fallback driver is
            # ``free`` for manager-level messages, but a concrete task knows
            # whether it is running protocol or Camoufox.
            payload = dict(fields)
            task_id = str(payload.get("task_id") or "").strip()
            if not task_id:
                match = re.match(r"^\[([^/\]]+)(?:/|\])", str(message or ""))
                candidate = str(match.group(1) or "").strip() if match else ""
                if candidate.startswith("free-"):
                    task_id = candidate
            if task_id and not payload.get("driver"):
                try:
                    with self._lock:
                        task = self._tasks.get(task_id)
                    driver = str(task.get("driver") or "").strip() if isinstance(task, Mapping) else ""
                    if driver:
                        payload["driver"] = driver
                except Exception:
                    pass
            try:
                self.log_fn(sanitize_log_message(message), level, **payload)
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

    def _manual_generation(self, task_id: str, _stage_code: str = "") -> int:
        """Return the current opaque generation used by manual OTP input."""
        with self._lock:
            return max(0, int(self._manual_generations.get(str(task_id), 0)))

    def _mailbox_verification_state(
        self,
        task_id: str,
        state: Mapping[str, Any] | None,
    ) -> None:
        """Publish only the non-sensitive OTP wait phase to the task table."""
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return
        changed = False
        with self._lock:
            task = self._tasks.get(normalized_task_id)
            if not isinstance(task, dict):
                return
            if state is None:
                changed = task.pop("mailbox_verification", None) is not None
            elif isinstance(state, Mapping):
                phase = str(state.get("phase") or "").strip().lower()
                if phase not in {"automatic", "manual"}:
                    return
                try:
                    opened_at = max(0, int(state.get("opened_at") or 0))
                    deadline_at = max(opened_at, int(state.get("deadline_at") or 0))
                except (TypeError, ValueError):
                    return
                value = {
                    "phase": phase,
                    "stage": str(state.get("stage") or task.get("stage") or "")[:100],
                    "opened_at": opened_at,
                    "deadline_at": deadline_at,
                }
                if task.get("mailbox_verification") != value:
                    task["mailbox_verification"] = value
                    changed = True
            if changed:
                task["updated_at"] = int(time.time())
        if changed:
            self._save_tasks_safely("邮箱验证码等待状态更新")

    def _save_task(self, task_id: str, **values: Any) -> None:
        changed = False
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            if "failure" in values and values.get("failure") is None:
                task.pop("failure", None)
                values = {key: value for key, value in values.items() if key != "failure"}
            task.update(values)
            task["updated_at"] = int(time.time())
            changed = True
        if changed:
            self._save_tasks_safely("任务字段更新")

    def _save_tasks_safely(self, context: str = "Free 任务状态") -> bool:
        """Persist task state without allowing storage outages to strand workers.

        Worker completion callbacks run outside the request that created the
        task.  A transient disk/serialization error must therefore be
        observable, but it must not prevent Future bookkeeping and executor
        cleanup from running.
        """
        # A worker from a superseded manager may still unwind after a
        # controlled reload. Never let its in-memory snapshot overwrite the
        # new owner's task state.
        if self._manager_owner_acquired and not self._owner_current():
            self._record_owner_fenced()
            return False
        save_error: Exception | None = None
        with self._lock:
            try:
                # Keep snapshot creation and the atomic replacement in the
                # same manager critical section. Otherwise a delayed older
                # snapshot can finish after a newer worker state and roll the
                # persisted task table backwards.
                snapshot = copy.deepcopy(self._tasks)
                self.task_store.save(snapshot)
                # SQLite adapters advance a durable revision on every write.
                # Copy the returned CAS metadata back into the manager's
                # in-memory map so the next callback does not repeatedly write
                # an intentionally stale snapshot. Legacy JSON stores do not
                # return revisions and are left untouched.
                if self.storage_adapters is not None:
                    for task_id, saved in snapshot.items():
                        current = self._tasks.get(task_id)
                        if not isinstance(current, dict) or not isinstance(saved, Mapping):
                            continue
                        for key in ("revision", "created_at", "updated_at", "status"):
                            if key in saved:
                                current[key] = copy.deepcopy(saved[key])
            except Exception as exc:
                save_error = exc
        if save_error is None:
            return True
        self._log(
            f"[Free 任务状态/free_task_store] {context}保存失败（{type(save_error).__name__}），继续清理运行资源",
            "error",
            node_code="free_task_store",
            node_label="保存 Free 任务状态",
            outcome="error",
            failure={
                "error_code": "free_task_store_write_failed",
                "technical_summary": f"{context}保存失败（{type(save_error).__name__}）",
                "retryable": True,
                "action_hint": "检查 Free 数据目录权限和可用空间；任务仍会继续执行并清理资源",
            },
            workflow="storage",
        )
        return False

    @staticmethod
    def _run_after_submission_gate(
        gate: threading.Event,
        callback: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> Any:
        gate.wait()
        return callback(*args, **dict(kwargs))

    def _submit_registered_worker(
        self,
        callback: Callable[..., Any],
        /,
        *args: Any,
        driver: str,
        priority: int,
        **kwargs: Any,
    ) -> Future[Any]:
        """Register all Future ownership before a worker can finish.

        PriorityExecutor workers can start as soon as ``submit`` returns. A
        short gate keeps an instant worker from firing its done callback until
        the manager has recorded the Future, its transport, and the callback.
        Callers already hold ``self._lock`` while mutating batch ownership.
        """
        executor = self._executor
        if executor is None:
            raise RuntimeError("Free executor is not available")
        gate = threading.Event()
        future = executor.submit(
            self._run_after_submission_gate,
            gate,
            callback,
            tuple(args),
            dict(kwargs),
            priority=priority,
        )
        try:
            self._futures.add(future)
            self._future_drivers[future] = str(driver or "protocol").strip().lower()
            future.add_done_callback(self._future_done)
        except Exception:
            self._futures.discard(future)
            self._future_drivers.pop(future, None)
            future.cancel()
            raise
        finally:
            gate.set()
        return future

    def _sync_plan_task_snapshot(self, row_id: str, result: Mapping[str, Any], promoted: bool) -> None:
        """Keep the in-memory public task view aligned with plan queue writes."""
        task_id = str(result.get("task_id") or "")
        changed = False
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
            changed = True
        if changed:
            self._save_tasks_safely("套餐检查结果同步")

    def import_mailboxes(
        self,
        content: str,
        *,
        join_current_batch: bool = False,
        config: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append Free mailboxes and optionally enqueue them into this run.

        Import is append-only while a batch is active.  Joining the active
        batch is an explicit opt-in because it changes that batch's target;
        the default merely makes the rows available to the next dispatch.
        """
        with self._lock:
            before = {str(row.row_id) for row in self.pool.entries()}
            imported, skipped = self.pool.import_text_with_stats(str(content or ""))
            added_rows = [row for row in self.pool.entries() if str(row.row_id) not in before]
            running = bool(
                self._executor
                or self._shutdown_pending
                or (
                    self._heartbeat_thread is not None
                    and self._heartbeat_thread.is_alive()
                )
            )
            result: dict[str, Any] = {
                "imported": int(imported),
                "skipped": int(skipped),
                "queued": 0,
                "active_batch_joined": 0,
                "skipped_items": [],
                "running": running,
            }
            if not running or not join_current_batch or not added_rows:
                if running and added_rows:
                    marker = getattr(self.pool, "mark_next_batch_priority", None)
                    if callable(marker):
                        try:
                            marker([row.row_id for row in added_rows])
                        except Exception:
                            self._log("[Free 邮箱池/free_pool_priority] 新增邮箱下一批优先标记失败", "warn")
                    result["next_batch"] = len(added_rows)
                    result["reason"] = "运行中的批次未扩展；新增邮箱已加入下一批优先队列"
                return result

            active_tasks = [
                task for task in self._tasks.values()
                if str(task.get("batch_id") or "") == str(self._batch_id or "")
                and str(task.get("status") or "") in {"queued", "running"}
            ]
            batch_id = str(self._batch_id or "")
            base_config = dict(config or self._last_config)
            driver = str(
                (active_tasks[0].get("driver") if active_tasks else base_config.get("driver"))
                or "protocol"
            ).strip().lower()
            workers = max(1, min(int(base_config.get("concurrency") or 3), 16))
            for row in added_rows:
                if str(self.pool._row_state(row.row_id).get("status") or "available") != "available":
                    result["skipped_items"].append({"row_id": row.row_id, "reason": "邮箱当前不可用"})
                    continue
                binding: ProxyBinding | None = None
                task_id = ""
                reserved = False
                mailbox_lease_acquired = False
                submitted = False
                try:
                    bindings = self.proxies.bind(
                        1,
                        probe=self.proxy_probe,
                        probe_url=str(base_config.get("proxy_probe_url") or "https://chatgpt.com/"),
                        driver=driver,
                        perform_probe=False,
                    )
                    if not bindings:
                        raise FreeRegisterError("free_proxy_binding", "绑定 Free 代理", "当前没有可用健康代理", retryable=True)
                    binding = bindings[0]
                    ordinal = max((int(item.get("ordinal") or 0) for item in self._tasks.values()), default=0) + 1
                    task_id = f"{batch_id}-import-{secrets.token_hex(3)}"
                    now = int(time.time())
                    row_state = self.pool._row_state(row.row_id)
                    mailbox_source = str(row_state.get("source") or "url").strip().lower()
                    task = {
                        "task_id": task_id,
                        "ordinal": ordinal,
                        "slot_id": f"{batch_id}-import",
                        "slot_index": 0,
                        "concurrency_limit": workers,
                        "status": "queued",
                        "created_at": now,
                        "updated_at": now,
                        "timing": self._timing_record({"created_at": now}),
                        "batch_id": batch_id,
                        "run_mode": "free_register",
                        "driver": driver,
                        "proxy_allocation_mode": "healthy_random",
                        "email": row.email,
                        "row_id": row.row_id,
                        "mailbox_url": row.mailbox_url,
                        "mailbox_source": mailbox_source,
                        "service_token": str(row_state.get("service_token") or "") if mailbox_source == "remail" else "",
                        "proxy": binding.proxy,
                        "proxy_id": binding.proxy_id,
                        "proxy_scheme": binding.scheme,
                        "proxy_effective_scheme": getattr(binding, "effective_scheme", "") or binding.scheme,
                        "proxy_country": binding.country,
                        "proxy_group": binding.group,
                        "proxy_masked": binding.masked,
                        "proxy_fingerprint": binding.fingerprint,
                        "expected_exit_ip": binding.exit_ip,
                        "registration_ip": "",
                        "exit_ip": binding.exit_ip,
                        "proxy_attempts": [],
                        "cleanup_status": "pending",
                        "progress": {"stage": "free_oauth_session", "group": "free", "started_at": now, "updated_at": now, "finished_at": None},
                        "result": {"twofa_status": "", "driver": driver, "expected_exit_ip": binding.exit_ip},
                    }
                    self.pool.reserve([row], batch_id)
                    reserved = True
                    if self.mailbox_leases is not None:
                        lease = self.mailbox_leases.acquire(
                            row.row_id,
                            task_id=task_id,
                            batch_id=batch_id,
                            driver=driver,
                        )
                        if lease is None:
                            raise FreeRegisterError(
                                "free_mailbox_lease",
                                "预留 Free 邮箱租约",
                                "Free 邮箱租约已被其他任务占用",
                                retryable=True,
                                error_code="free_mailbox_lease_conflict",
                            )
                        mailbox_lease_acquired = True
                    self.proxies.lease(binding, owner=task_id, batch_id=batch_id, task_id=task_id)
                    self.pool.update(
                        row.row_id,
                        status="queued",
                        batch_id=batch_id,
                        stage="free_oauth_session",
                        driver=driver,
                        proxy=binding.proxy,
                        proxy_masked=binding.masked,
                        proxy_fingerprint=binding.fingerprint,
                        expected_exit_ip=binding.exit_ip,
                        exit_ip=binding.exit_ip,
                        proxy_id=binding.proxy_id,
                        proxy_country=binding.country,
                        proxy_group=binding.group,
                    )
                    self._tasks[task_id] = task
                    # Persist the task before submitting the worker.  A very
                    # fast custom runner can finish before the request thread
                    # reaches its final save, so the completion callback must
                    # never observe an unknown task on disk.
                    self._save_tasks_safely("运行中导入任务初始状态")
                    self._submit_registered_worker(
                        self._worker,
                        task_id,
                        dict(base_config),
                        driver=driver,
                        priority=10,
                    )
                    submitted = True
                    result["queued"] += 1
                    result["active_batch_joined"] += 1
                except Exception as exc:
                    if submitted:
                        # The callback will reconcile this task; leave its
                        # lease and state intact if a post-submit operation
                        # fails.
                        result["skipped_items"].append({"row_id": row.row_id, "reason": "已提交到当前批次"})
                        continue
                    self._tasks.pop(task_id, None)
                    if mailbox_lease_acquired and self.mailbox_leases is not None:
                        try:
                            self.mailbox_leases.release(task_id=task_id, reusable=True)
                        except Exception as release_exc:
                            self._log(
                                f"[导入回滚/import_rollback] 任务 {task_id} 邮箱租约释放失败，"
                                f"可能留下悬挂租约（{type(release_exc).__name__}）",
                                "warn",
                            )
                    if binding is not None:
                        try:
                            self.proxies.release(binding, owner=task_id or batch_id)
                        except Exception as release_exc:
                            self._log(
                                f"[导入回滚/import_rollback] 任务 {task_id} 代理释放失败，"
                                f"代理可能被占用（{type(release_exc).__name__}）",
                                "warn",
                            )
                    if reserved:
                        try:
                            self.pool.update(row.row_id, status="available", batch_id="", stage="")
                        except Exception as release_exc:
                            self._log(
                                f"[导入回滚/import_rollback] 邮箱行 {row.row_id} 状态回滚失败，"
                                f"可能保持已占用（{type(release_exc).__name__}）",
                                "warn",
                            )
                    self._save_tasks_safely("运行中导入回滚")
                    result["skipped_items"].append({"row_id": row.row_id, "reason": _safe_log_message(exc)[:240]})
            self._save_tasks_safely("运行中导入后的 Free 任务状态")
            return result







    def _heartbeat_loop(self, owner: str, stop_event: threading.Event | None = None) -> None:
        # ``stop_event`` is captured by the thread so a later batch cannot
        # clear this batch's shutdown signal. The optional argument preserves
        # compatibility for integrations that call the private helper.
        event = stop_event or self._heartbeat_stop
        while not event.wait(20):
            if self._manager_owner_acquired:
                if not self._owner_current():
                    self._record_owner_fenced()
                    break
                storage = self._owner_storage()
                if storage is not None:
                    try:
                        if not storage.renew_manager_owner(
                            self._manager_owner_id,
                            self._manager_owner_epoch,
                            pid=os.getpid(),
                        ):
                            self._record_owner_fenced()
                            break
                    except Exception:
                        self._log(
                            f"[{owner}/Free 进程所有权/free_process_owner] 进程租约续期失败，等待 TTL 恢复",
                            "warn",
                            node_code="free_process_owner",
                            node_label="Free 进程所有权",
                            outcome="renew_failed",
                            workflow="lifecycle",
                        )
                        # Do not renew resource leases after losing the
                        # process fence; a replacement must be able to take
                        # them over safely.
                        break
            try:
                heartbeat_batch = getattr(self.proxies, "heartbeat_batch", None)
                if callable(heartbeat_batch):
                    heartbeat_batch(owner, lease_seconds=180)
                else:
                    self.proxies.heartbeat(owner, lease_seconds=180)
            except Exception:
                self._log(f"[{owner}/Free 代理租约/free_proxy_lease] 租约续期失败，任务将依靠过期时间恢复", "warn")
            # Mailbox claims are held while queued/running workers prepare the
            # transport. Keep them alive for long queues and slow browser
            # startup, and let the coordinator refresh its CAS revision so a
            # later email-submit confirmation remains valid.
            coordinator = self.mailbox_leases
            if coordinator is None:
                continue
            with self._lock:
                mailbox_leases = [
                    (
                        str(task.get("task_id") or ""),
                        str(task.get("row_id") or ""),
                    )
                    for task in self._tasks.values()
                    if str(task.get("batch_id") or "") == str(owner or "")
                    and str(task.get("status") or "").strip().lower()
                    in {"queued", "running"}
                    # Continuation tasks (2FA/password retries) reuse the
                    # account session and deliberately do not claim a fresh
                    # mailbox.  Only registration tasks have a lease to
                    # renew; filtering here also avoids a warning every
                    # heartbeat for those continuations.
                    and str(task.get("retry_mode") or "registration").strip().lower()
                    == "registration"
                    and str(task.get("task_id") or "").strip()
                    and str(task.get("row_id") or "").strip()
                ]
            for task_id, row_id in mailbox_leases:
                try:
                    if not coordinator.renew(
                        task_id=task_id,
                        row_id=row_id,
                        lease_seconds=180,
                    ):
                        self._log(
                            f"[{task_id}/Free 邮箱租约/free_mailbox_lease] "
                            "邮箱租约续期未成功，任务将依靠过期时间恢复",
                            "warn",
                            task_id=task_id,
                            node_code="free_mailbox_lease",
                            node_label="续期 Free 邮箱租约",
                            outcome="renew_failed",
                            failure={
                                "error_code": "free_mailbox_lease_renew_failed",
                                "technical_summary": "邮箱租约续期未成功",
                                "retryable": True,
                                "action_hint": "检查 Free 邮箱数据库状态；过期租约会自动恢复。",
                            },
                            workflow="cleanup",
                        )
                except Exception as exc:
                    self._log(
                        f"[{task_id}/Free 邮箱租约/free_mailbox_lease] "
                        f"邮箱租约续期失败（{type(exc).__name__}）",
                        "warn",
                        task_id=task_id,
                        node_code="free_mailbox_lease",
                        node_label="续期 Free 邮箱租约",
                        outcome="renew_failed",
                        failure={
                            "error_code": "free_mailbox_lease_renew_failed",
                            "technical_summary": f"邮箱租约续期失败（{type(exc).__name__}）",
                            "retryable": True,
                            "action_hint": "检查 Free 邮箱数据库状态；过期租约会自动恢复。",
                        },
                        workflow="cleanup",
                    )

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
            self._save_tasks_safely("停止任务状态")
        self._log("[停止 Free 注册/free_stop] 已请求停止，运行中的账号不切换代理", "warn")
        with self._lock:
            idle = not self._futures and self._executor is None
        if idle:
            self._release_runtime_owner()


    @staticmethod
    def _result_marker_true(value: Any) -> bool:
        """Parse persisted capability markers without ``bool('false')`` bugs."""
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value != 0
        return str(value or "").strip().lower() in {
            "1", "true", "yes", "on", "enabled", "complete", "completed", "success",
        }

    @staticmethod
    def _has_existing_account_result(*results: Mapping[str, Any] | None) -> bool:
        """Recognize account evidence without treating failure-only rows as accounts."""
        for result in results:
            if not isinstance(result, Mapping):
                continue
            if has_account_result(result):
                return True
            status = str(result.get("status") or "").strip().lower()
            if status in {"success", "partial_success", "twofa_pending"}:
                return True
            if any(
                FreeRegisterManager._result_marker_true(result.get(key))
                for key in (
                    "has_access_token",
                    "has_password",
                    "has_totp",
                    "has_credential",
                    "registration_completed",
                    "oauth_callback_completed",
                    "account_created",
                )
            ):
                return True
        return False







    def secret(self, task_ids: Sequence[str], kind: str, *, row_ids: Sequence[str] = ()) -> str:
        if kind not in {"token", "password", "totp", "proxy", "credential", "email"}:
            raise FreeRegisterError("free_secret", "读取 Free 敏感字段", "不支持的敏感字段类型", retryable=False)
        values: list[str] = []
        seen_rows: set[str] = set()
        with self._lock:
            for task_id in task_ids:
                task = self._tasks.get(str(task_id))
                if not task:
                    continue
                row_id = str(task.get("row_id") or "").strip()
                seen_rows.add(row_id)
                result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
                if kind == "email":
                    mailbox = self.pool.entry(row_id) if row_id else None
                    # Prefer the private pool row: a recovered/legacy task may
                    # carry a masked public projection in ``task.email``.
                    value = getattr(mailbox, "email", "") or task.get("email", "")
                elif kind == "credential":
                    mailbox = self.pool.entry(row_id) if row_id else None
                    value = _account_material_line(
                        str(task.get("email") or getattr(mailbox, "email", "")),
                        str(getattr(mailbox, "mailbox_url", "") or ""),
                        result,
                    )
                else:
                    value = {"token": result.get("access_token"), "password": result.get("password"), "totp": result.get("totp_secret"), "proxy": task.get("proxy")}.get(kind)
                if value:
                    values.append(str(value))
            for row_id in row_ids:
                normalized = str(row_id or "")
                if not normalized or normalized in seen_rows:
                    continue
                result = self.pool.result(normalized)
                private_state = self.pool._row_state(normalized)
                if kind == "email":
                    mailbox = self.pool.entry(normalized)
                    value = getattr(mailbox, "email", "") or result.get("email", "")
                elif kind == "credential":
                    mailbox = self.pool.entry(normalized)
                    value = _account_material_line(
                        str(getattr(mailbox, "email", "") or result.get("email") or ""),
                        str(getattr(mailbox, "mailbox_url", "") or ""),
                        result,
                    )
                else:
                    value = {"token": result.get("access_token"), "password": result.get("password"), "totp": result.get("totp_secret"), "proxy": result.get("proxy") or private_state.get("proxy")}.get(kind)
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

    def _mailbox_lease_callbacks(
        self,
        task: Mapping[str, Any],
    ) -> tuple[Callable[..., bool] | None, Callable[..., bool] | None]:
        """Build paired confirm/abort callbacks for the email-submit boundary.

        The transport adapters deliberately know nothing about SQLite or the
        manager. The abort half is intentionally narrower than generic
        cleanup: it succeeds only for the just-created confirmation and only
        when the adapter explicitly proves its submit primitive never began.
        """
        coordinator = self.mailbox_leases
        if coordinator is None:
            return None, None
        task_id = str(task.get("task_id") or "").strip()
        row_id = str(task.get("row_id") or "").strip()
        batch_id = str(task.get("batch_id") or "").strip()
        driver = str(task.get("driver") or "protocol").strip().lower() or "protocol"
        if not task_id or not row_id:
            return None, None
        state = {"confirmed": False, "abortable": False}

        def callback_task_id(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> str:
            return str(
                kwargs.get("task_id")
                or (args[0] if args else task_id)
                or task_id
            ).strip()

        def confirm(*args: Any, **kwargs: Any) -> bool:
            # Accept the modern keyword contract and the legacy positional
            # task-id callback shape used by a few integrations.
            if callback_task_id(args, kwargs) != task_id:
                return False
            # A confirmation recovered from SQLite or reused by a later
            # transport attempt is no longer reversible. This read also
            # prevents stale in-memory callback state from authorizing abort.
            if coordinator.is_confirmed(task_id=task_id, row_id=row_id):
                state["confirmed"] = True
                state["abortable"] = False
                return True
            outcome = coordinator.confirm(
                task_id=task_id,
                row_id=row_id,
                batch_id=batch_id,
                driver=driver,
            )
            state["confirmed"] = bool(outcome)
            state["abortable"] = bool(outcome)
            return bool(outcome)

        def abort(*args: Any, **kwargs: Any) -> bool:
            if callback_task_id(args, kwargs) != task_id:
                return False
            if kwargs.get("submission_definitely_not_started") is not True:
                return False
            if not state["confirmed"] or not state["abortable"]:
                return False
            # Consume the one-shot authorization before touching storage. If
            # the CAS fails, conservatively retain the confirmed marker.
            state["abortable"] = False
            outcome = coordinator.abort_confirmation(
                task_id=task_id,
                row_id=row_id,
                submission_definitely_not_started=True,
            )
            if outcome:
                state["confirmed"] = False
            return bool(outcome)

        return confirm, abort

    def _mailbox_confirm_callback(self, task: Mapping[str, Any]) -> Callable[..., bool] | None:
        """Compatibility accessor for integrations that only accept confirm."""
        confirm, _abort = self._mailbox_lease_callbacks(task)
        return confirm

    def _mailbox_confirmed(self, task: Mapping[str, Any]) -> bool:
        coordinator = self.mailbox_leases
        if coordinator is None:
            return False
        try:
            task_id = str(task.get("task_id") or "")
            row_id = str(task.get("row_id") or "")
            # Prefer the explicit durable lookup.  It remains valid after the
            # temporary resource lease expires or its sidecar is removed.
            durable_checker = getattr(coordinator, "is_confirmed_durable", None)
            if callable(durable_checker):
                return bool(durable_checker(task_id=task_id, row_id=row_id))
            return bool(coordinator.is_confirmed(task_id=task_id, row_id=row_id))
        except Exception:
            # An unreadable confirmation marker is not proof that submission
            # never started.  Keep the mailbox protected and disable proxy
            # replay until storage health is restored.
            return True

    def _release_task_lease(self, task: Mapping[str, Any]) -> None:
        # A stale worker must not release a lease that a replacement manager
        # has already acquired for the same task id.
        if self._manager_owner_acquired and not self._owner_current():
            self._record_owner_fenced(task_id=str(task.get("task_id") or ""))
            return
        task_id = str(task.get("task_id") or "")
        release_error: Exception | None = None
        try:
            binding = ProxyBinding(
                str(task.get("proxy") or ""),
                str(task.get("proxy_fingerprint") or ""),
                str(task.get("proxy_masked") or ""),
                str(task.get("expected_exit_ip") or task.get("exit_ip") or ""),
                proxy_id=str(task.get("proxy_id") or ""),
            )
            self.proxies.release(binding, owner=task_id)
        except Exception as exc:
            # Lease cleanup is best effort. Preserve the cleanup error in the
            # task snapshot, but never let it prevent the worker's remaining
            # failure handling or executor bookkeeping.
            release_error = exc

        mailbox_release_error: Exception | None = None
        if self.mailbox_leases is not None and task_id:
            try:
                # The coordinator decides whether the row is still reusable
                # from its confirmed marker and current durable status.
                self.mailbox_leases.release(
                    task_id=task_id,
                    row_id=str(task.get("row_id") or ""),
                    reusable=True,
                )
            except Exception as exc:
                mailbox_release_error = exc

        cleanup_error = release_error or mailbox_release_error
        cleanup_status = "released" if cleanup_error is None else f"release_failed:{type(cleanup_error).__name__}"
        with self._lock:
            current = self._tasks.get(task_id)
            if current is not None:
                current["cleanup_status"] = cleanup_status
                current["updated_at"] = int(time.time())
        self._save_tasks_safely("代理租约释放后")
        if release_error is not None:
            self._log(
                f"[{task_id}/释放 Free 代理/free_proxy_release] 代理租约释放失败（{type(release_error).__name__}）",
                "warn",
                task_id=task_id,
                node_code="free_proxy_release",
                node_label="释放 Free 代理",
                outcome="cleanup_failed",
                failure={
                    "error_code": "free_proxy_release_failed",
                    "technical_summary": f"代理租约释放失败（{type(release_error).__name__}）",
                    "retryable": True,
                    "action_hint": "检查代理池状态，过期租约会自动恢复。",
                },
                workflow="cleanup",
            )
        if mailbox_release_error is not None:
            self._log(
                f"[{task_id}/释放 Free 邮箱/free_mailbox_release] 邮箱租约释放失败（{type(mailbox_release_error).__name__}）",
                "warn",
                task_id=task_id,
                node_code="free_mailbox_release",
                node_label="释放 Free 邮箱",
                outcome="cleanup_failed",
                failure={
                    "error_code": "free_mailbox_release_failed",
                    "technical_summary": f"邮箱租约释放失败（{type(mailbox_release_error).__name__}）",
                    "retryable": True,
                    "action_hint": "检查 Free 邮箱租约状态，过期租约会自动恢复。",
                },
                workflow="cleanup",
            )

    def _persist_partial_result(
        self,
        task: Mapping[str, Any],
        values: Mapping[str, Any],
        *,
        stage_code: str = "",
    ) -> bool:
        """Merge protocol-side milestone fields into the durable account result.

        Called by the protocol mixin at the exact moment a value becomes
        server-side authoritative (a TOTP secret right after enroll, a
        password right after a successful add) so a later failure or process
        exit cannot lose single-issue material.  A persistence failure never
        propagates into the registration flow; the final result save remains
        the authoritative writer.
        """
        row_id = str(task.get("row_id") or "")
        if not row_id or not isinstance(values, Mapping) or not values:
            return False
        try:
            current = self.pool.result(row_id)
            merged = dict(current) if isinstance(current, Mapping) else {}
            merged.update(copy.deepcopy(dict(values)))
            self.pool.save_result(row_id, merged)
            stage_label = FREE_STAGE_LABELS.get(str(stage_code or ""), str(stage_code or "free_result_save"))
            self._log(
                f"[{task.get('task_id') or ''}/{stage_label}/{stage_code or 'free_result_save'}] "
                "关键材料已即时写入账号结果",
                "info",
                task_id=str(task.get("task_id") or ""),
                node_code=str(stage_code or "free_result_save"),
                node_label=stage_label,
                outcome="persisted",
            )
            return True
        except Exception as exc:
            self._log(
                f"[{task.get('task_id') or ''}/关键材料即时落库/{stage_code or 'free_result_save'}] "
                f"写入失败（{type(exc).__name__}），最终结果保存仍会重试",
                "warn",
                task_id=str(task.get("task_id") or ""),
                node_code=str(stage_code or "free_result_save"),
                node_label="即时保存关键材料",
                outcome="persist_failed",
            )
            return False

    _MAILBOX_DEGRADE_ERRORS = frozenset({
        "mailbox_timeout",
        "mailbox_code_timeout",
        "mailbox_parse_failed",
        "mailbox_url_invalid",
        "mailbox_error",
    })
    _MAILBOX_DEGRADE_THRESHOLD = 3

    @classmethod
    def _is_mailbox_source_failure(cls, failure: Mapping[str, Any]) -> bool:
        """True when the failure proves the mailbox source itself is broken."""
        error_code = str(failure.get("error_code") or "").strip().lower()
        node_code = str(failure.get("node_code") or "").strip().lower()
        if error_code in cls._MAILBOX_DEGRADE_ERRORS:
            return True
        text = f"{error_code} {node_code}"
        if any(marker in text for marker in ("mailbox_parse", "mailbox_url", "mailbox_timeout", "mailbox_code_timeout")):
            return True
        return (
            any(marker in text for marker in ("邮箱验证码等待已达到调用方时间预算", "邮箱取件请求已达到本轮时间预算"))
            and "mailbox" in f"{failure.get('public_message') or ''}".lower()
        )

    def _maybe_degrade_mailbox_source(self, snapshot: Mapping[str, Any], failure: Mapping[str, Any]) -> None:
        """After N consecutive mailbox-source failures, park the row as
        unavailable (manual restore only).  A row whose OTP source keeps
        timing out must not keep being re-selected by later batches."""
        row_id = str(snapshot.get("row_id") or "")
        if not row_id or not self._is_mailbox_source_failure(failure):
            return
        try:
            row_state = self.pool._row_state(row_id)
        except Exception:
            return
        try:
            consecutive = max(0, int(row_state.get("mailbox_otp_failures") or 0))
        except (TypeError, ValueError):
            consecutive = 0
        consecutive += 1
        if consecutive < self._MAILBOX_DEGRADE_THRESHOLD:
            try:
                self.pool.update(row_id, mailbox_otp_failures=consecutive)
            except Exception:
                pass
            return
        try:
            self.pool.update(
                row_id,
                status="unavailable",
                mailbox_otp_failures=0,
                error="邮箱取件连续失败，已自动降级；请在邮箱中心手动恢复",
                degraded_reason="free_mailbox_degraded",
            )
            self._log(
                f"[{snapshot.get('task_id') or ''}/邮箱源连续失败降级/free_mailbox_degraded] "
                f"邮箱连续 {self._MAILBOX_DEGRADE_THRESHOLD} 次取件失败，已降级为不可用；请在邮箱中心手动恢复",
                "error",
                task_id=str(snapshot.get("task_id") or ""),
                node_code="free_mailbox_degraded",
                node_label="邮箱源连续失败降级",
                outcome="degraded",
            )
        except Exception as exc:
            self._log(
                f"[{snapshot.get('task_id') or ''}/邮箱源连续失败降级/free_mailbox_degraded] "
                f"邮箱降级写库或告警记录失败，坏邮箱可能继续接单（{type(exc).__name__}）",
                "error",
                task_id=str(snapshot.get("task_id") or ""),
                node_code="free_mailbox_degraded",
                node_label="邮箱源连续失败降级",
                outcome="error",
            )

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
                    "http_status": getattr(exc, "provider_status", None),
                    "at": int(time.time()),
                })
                current["proxy_attempts"] = attempts[-10:]
                self._save_tasks_safely("记录代理失败")
        node_code = str(getattr(exc, "node_code", "free_proxy"))
        if proxy_id and is_proxy_health_failure(exc):
            try:
                self.proxies.record_failure(
                    proxy_id,
                    node_code=node_code,
                    message=_safe_log_message(exc),
                    http_status=getattr(exc, "provider_status", None),
                )
            except Exception as record_error:
                # Proxy health bookkeeping is advisory from the worker's
                # perspective. A pool write failure must not skip the lease
                # release that follows this method in the error path.
                self._log(
                    f"[{task_id}/记录 Free 代理失败/free_proxy_health] "
                    f"代理健康状态保存失败（{type(record_error).__name__}）",
                    "warn",
                    task_id=task_id,
                    node_code="free_proxy_health",
                    node_label="记录 Free 代理失败",
                    outcome="cleanup_failed",
                    failure={
                        "error_code": "free_proxy_health_write_failed",
                        "technical_summary": f"代理健康状态保存失败（{type(record_error).__name__}）",
                        "retryable": True,
                        "action_hint": "检查 Free 代理池存储状态；本次租约仍会继续释放。",
                    },
                    workflow="cleanup",
                )

    @classmethod
    def _can_reuse_mailbox_after_failure(
        cls,
        node_code: str,
        error: BaseException | None = None,
    ) -> bool:
        normalized = str(node_code or "")
        if normalized in cls._REUSABLE_PRE_REGISTRATION_FAILURES:
            return True
        # Camoufox uses a few broad legacy node labels for compatibility.  Do
        # not infer mailbox safety from those labels: a browser process can
        # disappear after the email/OTP request has already been submitted.
        # Only errors that are provably raised before a context/page exists may
        # restore the mailbox automatically.
        if normalized in {"free_camoufox_launch", "free_camoufox_browser", "free_camoufox_signup"}:
            error_code = str(getattr(error, "error_code", "") or "").strip().lower()
            return error_code in {
                "camoufox_pool_empty",
                "camoufox_browser_launch_failed",
                "camoufox_context_create_failed",
                "camoufox_page_create_failed",
                "camoufox_browser_recycle_failed",
                "camoufox_loop_missing",
            }
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
        # Re-check immediately before the lifecycle write.  The caller may
        # have classified the failure before another process persisted the
        # email-submit confirmation; in that case making the row available
        # would allow a second task to reuse an already-consumed address.
        if self._mailbox_confirmed(task):
            self._log(
                f"[{task.get('task_id', '')}/Free 邮箱待重跑/free_mailbox_pending_rerun] "
                "检测到已确认的邮箱提交，跳过自动恢复为可用",
                "warn",
                task_id=str(task.get("task_id") or ""),
                node_code="free_mailbox_pending_rerun",
                node_label="Free 邮箱待重跑",
                outcome="protected",
            )
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
        if str(config.get("driver") or "protocol").strip().lower() == "camoufox":
            camoufox_artifact_dir = self.data_dir / "camoufox_debug"
            return CamoufoxRunner(
                lifecycle_store_path=str(self.data_dir / "camoufox_cleanup.json"),
                debug_artifact_dir=str(camoufox_artifact_dir),
            )
        return self._run_protocol

    @staticmethod
    def _twofa_auto_retry_allowed(result: Mapping[str, Any]) -> bool:
        """Classify a pending 2FA result before scheduling an automatic retry.

        Only transport/session-transient failures are replayed.  Rate limits,
        security challenges, account restrictions and an explicitly invalid
        TOTP remain manual ``twofa_pending`` states so the service is never
        hammered with a known-bad request.
        """
        failure = result.get("twofa_failure") if isinstance(result.get("twofa_failure"), Mapping) else {}
        if isinstance(failure, Mapping) and failure.get("retryable") is False:
            return False
        try:
            status = int(failure.get("http_status") or 0)
        except (TypeError, ValueError):
            status = 0
        if status in {400, 401, 403, 409, 422, 429}:
            return False
        text = " ".join(
            str(failure.get(key) or "").lower()
            for key in ("error_code", "provider_code", "public_message", "technical_summary")
        )
        blocked = ("challenge", "captcha", "security", "account_disabled", "account_banned", "suspended", "invalid_totp", "invalid code", "rate_limit", "429")
        return not any(marker in text for marker in blocked)

    def _schedule_auto_twofa_retry(
        self,
        task: Mapping[str, Any],
        result: Mapping[str, Any],
        config: Mapping[str, Any],
    ) -> str:
        """Enqueue one bounded 2FA retry and return its task id, if any."""
        if str(result.get("twofa_status") or "").strip().lower() != "pending":
            return ""
        # The key is intentionally presence-sensitive for compatibility with
        # direct/integration manager callers from older releases. Production
        # requests pass a normalized FreeConfigStore snapshot containing this
        # bounded setting (default: two additional attempts).
        if "twofa_auto_retry_attempts" not in config:
            return ""
        try:
            limit = max(0, min(2, int(config.get("twofa_auto_retry_attempts") or 0)))
            attempt = int(task.get("retry_attempt") or 0)
        except (TypeError, ValueError):
            return ""
        if limit <= attempt or not self._twofa_auto_retry_allowed(result):
            return ""
        try:
            queued = self._enqueue_retry(
                task,
                config,
                retry_node="free_twofa_activate",
                twofa_retry=True,
            )
            retry_id = str(queued.get("task_id") or "") if isinstance(queued, Mapping) else ""
            if retry_id:
                self._save_task(str(task.get("task_id") or ""), auto_twofa_retry_task_id=retry_id)
            return retry_id
        except Exception as exc:
            # Automatic recovery is best-effort; preserve the original 2FA
            # incident and leave the account in its manual pending state.
            self._log(
                f"[{task.get('task_id', '')}/2FA 自动重试/free_twofa_activate] 自动重试入队失败（{type(exc).__name__}）",
                "warn",
                task_id=str(task.get("task_id") or ""),
                node_code="free_twofa_activate",
                node_label="激活 Free 账号 2FA",
                outcome="retry_enqueue_failed",
            )
            return ""

    def _worker(
        self,
        task_id: str,
        config: dict[str, Any],
        twofa_retry: bool = False,
        password_retry: bool = False,
    ) -> None:
        if twofa_retry and password_retry:
            raise FreeRegisterError(
                "free_retry", "重试 Free 任务",
                "2FA 重试和密码重试不能同时提交",
                retryable=False, error_code="free_retry_modes_conflict",
            )
        if self._manager_owner_acquired and not self._owner_current():
            self._record_owner_fenced(task_id=str(task_id or ""))
            return
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task["status"] = "running"
            if twofa_retry or password_retry:
                task.pop("failure", None)
            task["updated_at"] = int(time.time())
            self._mark_execution_started(task_id, persist=False)
            snapshot = dict(task)
            snapshot_driver = str(snapshot.get("driver") or config.get("driver") or "protocol").strip().lower()
            # Publish the running transition before invoking transport code.
            # A storage outage is diagnosed by the safe helper but does not
            # strand the worker or suppress its normal finally/lease cleanup.
            self._save_tasks_safely("任务进入运行状态")
        task_config = dict(config)
        task_config["driver"] = snapshot_driver
        if self.manual_broker is not None:
            task_config["_manual_verification_broker"] = self.manual_broker
            task_config["_manual_generation_getter"] = self._manual_generation
        task_config["_mailbox_verification_state_fn"] = self._mailbox_verification_state
        # Mid-flight durable persistence for protocol-side milestones (2FA
        # secret before activation, password after a successful add).  Uses
        # the same config-carried callback pattern as the mailbox lease hooks
        # so the protocol mixin stays decoupled from the pool.
        task_config["_persist_partial_result"] = (
            lambda values, *, stage_code="": self._persist_partial_result(
                snapshot, values, stage_code=stage_code,
            )
        )
        if not twofa_retry and not password_retry:
            confirm_mailbox, abort_mailbox = self._mailbox_lease_callbacks(snapshot)
            if confirm_mailbox is not None:
                task_config["_confirm_mailbox_lease"] = confirm_mailbox
            if abort_mailbox is not None:
                task_config["_abort_mailbox_lease_confirmation"] = abort_mailbox
        start_node = "free_password_enroll" if password_retry else "free_twofa_enroll" if twofa_retry else "free_oauth_session"
        self._log(f"[{task_id}/{start_node}] Free 任务开始", "info")
        task_log = lambda message, level="info", **fields: self._task_log(task_id, message, level, **fields)
        # Keep adapter-level timings attached to this task without changing
        # the historical runner callable signature or protocol ordering.
        task_config["_timing_substep"] = (
            lambda stage_code, code, elapsed_ms, outcome="success": self._record_timing_substep(
                task_id, stage_code, code, elapsed_ms, outcome,
            )
        )
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
                    runner_kwargs: dict[str, Any] = {}
                    # Preserve compatibility with older custom runners: only
                    # pass a keyword for the continuation mode being used.
                    if twofa_retry:
                        runner_kwargs["twofa_retry"] = True
                    if password_retry:
                        runner_kwargs["password_retry"] = True
                    result = dict(runner(snapshot, task_config, self._stop, self._stage, task_log, **runner_kwargs))
                    if snapshot_driver == "protocol":
                        result = self._sanitize_protocol_result(result)
                    break
                except FreeRegisterError as exc:
                    error_node = str(getattr(exc, "node_code", ""))
                    failed_proxy_id = str(snapshot.get("proxy_id") or "")
                    network_failure = is_proxy_health_failure(exc)
                    # OAuth bootstrap and the first email-identification POST
                    # are both route-level protocol nodes.  HTML login/error
                    # envelopes from either node may be retried on another
                    # healthy pool proxy when the flow marks them explicitly
                    # ``proxy_retryable``; business OTP/page failures do not.
                    protocol_pre_email = error_node in {
                        "free_protocol_preflight", "free_oauth_session", "free_email_identifier",
                    }
                    camoufox_proxy_retryable = bool(getattr(exc, "proxy_retryable", False))
                    camoufox_pre_email = (
                        error_node == "free_camoufox_navigation" and camoufox_proxy_retryable
                    ) or (
                        error_node == "free_camoufox_launch"
                        and str(getattr(exc, "error_code", "") or "") == "camoufox_context_create_failed"
                        and camoufox_proxy_retryable
                    )
                    # A proxy retry is safe only before the mailbox submit
                    # boundary.  Once the durable confirmation exists, a
                    # route-level error must terminate as pending_rerun rather
                    # than replaying registration on another proxy.
                    durable_mailbox_confirmed = self._mailbox_confirmed(snapshot)
                    can_retry_pre_email = (
                        not durable_mailbox_confirmed
                        and (
                            (protocol_pre_email and network_failure)
                            or (protocol_pre_email and bool(getattr(exc, "proxy_retryable", False)))
                            or camoufox_pre_email
                        )
                    )
                    # Same-error short circuit: an unchanged node+error_code
                    # failing three times in a row (two recorded attempts plus
                    # this one) is evidence the failure is not proxy-bound, so
                    # further proxy switching would only burn the mailbox.
                    with self._lock:
                        prior_attempts = list(self._tasks.get(task_id, {}).get("proxy_attempts") or [])
                    same_failures = consecutive_same_failures(
                        prior_attempts,
                        {"node_code": exc.node_code, "error_code": str(getattr(exc, "error_code", "") or "")},
                    )
                    if same_failures >= 2 and attempt < retry_limit and can_retry_pre_email and not self._stop.is_set():
                        raise FreeRegisterError(
                            exc.node_code,
                            exc.node_label,
                            f"同一错误已连续 {same_failures + 1} 次失败，停止自动重试",
                            retryable=bool(exc.retryable),
                            provider_status=getattr(exc, "provider_status", None),
                            provider_code=str(getattr(exc, "provider_code", "") or ""),
                            error_code="free_retry_short_circuit",
                            action_hint="同一错误连续失败通常与代理无关；请检查邮箱来源、账号状态或稍后重跑",
                        ) from exc
                    if not can_retry_pre_email or attempt >= retry_limit or self._stop.is_set():
                        raise
                    if network_failure or camoufox_pre_email:
                        self._record_proxy_failure(snapshot, exc)
                    attempt += 1
                    switched = self._switch_pre_profile_proxy(snapshot, task_config)
                    self._assert_batch_proxy_uniqueness(snapshot)
                    with self._lock:
                        current = self._tasks.get(task_id)
                        if current is not None:
                            current.setdefault("proxy_attempts", []).append({"proxy_id": failed_proxy_id, "stage": exc.node_code, "error_code": str(getattr(exc, "error_code", "") or ""), "retryable": True, "message": _safe_log_message(exc), "http_status": getattr(exc, "provider_status", None), "attempt": attempt, "switched": switched, "at": int(time.time())})
                            self._save_tasks_safely("记录代理切换")
                    if bool(getattr(exc, "proxy_retryable", False)) and not switched:
                        # A route-level access denial must not replay against
                        # the same proxy when no healthy replacement exists.
                        raise
                    self._log(f"[{task_id}/Free 预注册重试/{exc.node_code}] 代理连接异常，{'切换备用代理' if switched else '重试当前代理'}（第 {attempt + 1} 次）", "warn")
            if self._manager_owner_acquired and not self._owner_current():
                self._record_owner_fenced(task_id=task_id)
                return
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
                "proxy_effective_scheme": snapshot.get("proxy_effective_scheme", "") or snapshot.get("proxy_scheme", ""),
                "proxy_country": snapshot.get("proxy_country", ""),
                "proxy_group": snapshot.get("proxy_group", ""),
            })
            with self._lock:
                current = self._tasks.get(task_id)
                if current is not None:
                    current.setdefault("proxy_attempts", []).append({"proxy_id": snapshot.get("proxy_id", ""), "stage": "free_result_save", "outcome": "success", "at": int(time.time())})
                    current["proxy_attempts"] = current["proxy_attempts"][-10:]
            # Continuations return a partial envelope. Merge it fill-only with
            # the account result captured before the retry so Token, TOTP and
            # plan fields cannot disappear when an adapter returns only the
            # field it changed.
            if twofa_retry or password_retry:
                prior_result = snapshot.get("result") if isinstance(snapshot.get("result"), Mapping) else {}
                result = merge_account_result_fields(prior_result, result)
            if snapshot_driver == "protocol":
                result = self._sanitize_protocol_result(result)
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
                mailbox_otp_failures=0,
            )
            self._stage(task_id, "free_result_save")
            self._finish_progress(task_id, "success" if status == "success" else "partial")
            if status == "twofa_pending":
                self._schedule_auto_twofa_retry(snapshot, result, task_config)
            self._release_task_lease(snapshot)
            failure_identity = f"{(result_failure or {}).get('node_label', '后置检查')}/{(result_failure or {}).get('node_code', 'unknown')}"
            result_label = "完成" if status == "success" else f"注册完成，{failure_identity}{'待重试' if status == 'twofa_pending' else '待处理'}"
            self._log(f"[{task_id}/free_result_save] Free 任务{result_label}", "success" if status == "success" else "warn")
        except FreeRegisterError as exc:
            if self._manager_owner_acquired and not self._owner_current():
                self._record_owner_fenced(task_id=task_id)
                return
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
            terminal_status = "failed" if not self._stop.is_set() else "stopped"
            if password_retry:
                # Password continuation failure is recoverable account state,
                # not a fresh registration failure. Keep the Token and expose
                # the password marker so the same independent retry remains
                # available without replaying signup.
                prior = snapshot.get("result") if isinstance(snapshot.get("result"), Mapping) else {}
                pending_result = merge_account_result_fields(
                    prior,
                    {
                        "password_status": "pending",
                        "password_error": _safe_log_message(exc),
                        "password_failure": failure,
                    },
                )
                failure, _ = self._persist_task_failure(
                    task_id, snapshot, status="partial_success", failure=failure,
                    result=pending_result,
                )
                terminal_status = "partial_success"
            else:
                failure, _ = self._persist_task_failure(
                    task_id, snapshot, status=terminal_status, failure=failure,
                )
            debug_session_id = str(failure.get("debug_session_id") or "")
            if debug_session_id:
                with self._lock:
                    incident_ref = str(self._tasks.get(task_id, {}).get("incident_id") or "")
                if incident_ref:
                    annotate_camoufox_debug_session(debug_session_id, incident_ref)
            if password_retry:
                # This mailbox was never re-reserved for the continuation. Do
                # not route its failure through the registration-only
                # ``pending_rerun``/mailbox-release message; leave the row in a
                # visible partial state so the independent password action can
                # be invoked again.
                self.pool.update(
                    snapshot["row_id"], status="partial_success", stage="free_password_enroll",
                    error=failure["public_message"], failure=failure,
                    reusable_after_failure=False,
                )
            elif self._mailbox_confirmed(snapshot):
                # Confirmation is the irreversible email-submit boundary. A
                # transport response such as 429 after that point must never
                # return the address to the fresh-registration pool.
                self.pool.update(
                    snapshot["row_id"], status="pending_rerun", stage=exc.node_code,
                    error=failure["public_message"], failure=failure,
                    reusable_after_failure=False,
                )
                self._log(
                    f"[{task_id}/Free 邮箱待重跑/free_mailbox_pending_rerun] "
                    "邮箱已提交，保留 pending_rerun 供显式重跑",
                    "warn",
                )
            elif self._can_reuse_mailbox_after_failure(exc.node_code, exc):
                self._restore_mailbox_after_pre_registration_failure(snapshot, failure)
                self._maybe_degrade_mailbox_source(snapshot, failure)
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
                self._maybe_degrade_mailbox_source(snapshot, failure)
            # Keep the persisted progress cursor aligned with the first real
            # failure.  The runner may raise before it gets a chance to emit
            # its own stage transition; recording the failed node here makes
            # the timing row, task table and diagnostic event agree.
            if node_code:
                self._stage(
                    task_id,
                    node_code,
                    previous_outcome="failed" if terminal_status == "failed" else "interrupted",
                    previous_failure_code=str(failure.get("error_code") or node_code),
                    previous_retryable=failure.get("retryable") if isinstance(failure.get("retryable"), bool) else None,
                )
            self._finish_progress(
                task_id,
                "partial" if terminal_status == "partial_success"
                else "failed" if terminal_status == "failed" else "stopped",
            )
            self._record_proxy_failure(snapshot, exc)
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
                debug_session_id=failure.get("debug_session_id"),
                debug_artifact_id=failure.get("debug_artifact_id") or failure.get("artifact_id"),
                artifact_id=failure.get("artifact_id") or failure.get("debug_artifact_id"),
            )
        except FreeTwoFaPending as pending:
            if self._manager_owner_acquired and not self._owner_current():
                self._record_owner_fenced(task_id=task_id)
                return
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
            self._stage(
                task_id,
                failure.get("node_code") or "free_twofa_activate",
                previous_outcome="failed",
                previous_failure_code=str(failure.get("error_code") or "free_twofa_pending"),
                previous_retryable=failure.get("retryable") if isinstance(failure.get("retryable"), bool) else None,
            )
            self._finish_progress(task_id, "partial")
            self._release_task_lease(snapshot)
            # The protocol/browser runner commonly signals a recoverable 2FA
            # failure by raising ``FreeTwoFaPending`` rather than returning a
            # result envelope.  Feed that path through the same bounded
            # automatic retry policy as returned ``twofa_status=pending``
            # results; the original task and incident remain intact.
            self._schedule_auto_twofa_retry(snapshot, result, task_config)
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
            if self._manager_owner_acquired and not self._owner_current():
                self._record_owner_fenced(task_id=task_id)
                return
            failure, classified_exc, current_stage, current_label = (
                self._persist_unexpected_task_failure(
                    task_id,
                    snapshot,
                    exc,
                    twofa_retry=twofa_retry,
                    password_retry=password_retry,
                )
            )
            debug_session_id = str(failure.get("debug_session_id") or "")
            if debug_session_id:
                with self._lock:
                    incident_ref = str(self._tasks.get(task_id, {}).get("incident_id") or "")
                if incident_ref:
                    annotate_camoufox_debug_session(debug_session_id, incident_ref)
            if current_stage:
                self._stage(
                    task_id,
                    current_stage,
                    previous_outcome="interrupted" if (twofa_retry or password_retry) else "failed",
                    previous_failure_code=str(failure.get("error_code") or current_stage),
                    previous_retryable=failure.get("retryable") if isinstance(failure.get("retryable"), bool) else None,
                )
            continuation = bool(twofa_retry or password_retry)
            self._finish_progress(task_id, "partial" if continuation else "failed")
            self._record_proxy_failure(snapshot, classified_exc)
            self._release_task_lease(snapshot)
            self._log(
                f"[{task_id}/{current_label}/{current_stage}] {failure['public_message']}",
                "warn" if continuation else "error", task_id=task_id, node_code=failure["node_code"],
                node_label=failure["node_label"], error_code=failure["error_code"],
                outcome="partial" if continuation else "failed", diagnostic=failure.get("technical_summary"),
                action_hint=failure.get("action_hint"), retryable=failure.get("retryable"),
                page_type=failure.get("page_type"), safe_page=failure.get("safe_page"),
                content_type=failure.get("content_type"), session_rebuilds=failure.get("session_rebuilds"),
                debug_session_id=failure.get("debug_session_id"),
                debug_artifact_id=failure.get("debug_artifact_id") or failure.get("artifact_id"),
                artifact_id=failure.get("artifact_id") or failure.get("debug_artifact_id"),
            )

__all__ = ["FIXED_PASSWORD", "FreeMailboxPool", "FreeProxyPool", "FreeRegisterError", "FreeRegisterManager", "MailboxUrlOtpProvider", "ProxyBinding", "random_birthdate", "random_display_name"]
