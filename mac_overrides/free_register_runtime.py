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
    from .free_timing import FREE_TIMING_SUBSTEPS
    from .free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore, _account_material_line
    from .free_storage_adapters import build_free_storage_adapters
    from .free_storage import ManagerOwnerConflict
    from .free_register.mailbox_lease import MailboxLeaseCoordinator
    from .free_register_scheduler import FreeRegisterSchedulerMixin
    from .free_log_runtime import FreeLogStore
    from .free_live_check import build_free_live_check_service
    from .free_plan_check import build_free_plan_check_service
    from .free_protocol_runtime import FreeProtocolMixin
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
    from free_timing import FREE_TIMING_SUBSTEPS  # type: ignore[no-redef]
    from free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore, _account_material_line  # type: ignore[no-redef]
    from free_storage_adapters import build_free_storage_adapters  # type: ignore[no-redef]
    from free_storage import ManagerOwnerConflict  # type: ignore[no-redef]
    from free_register.mailbox_lease import MailboxLeaseCoordinator  # type: ignore[no-redef]
    from free_register_scheduler import FreeRegisterSchedulerMixin  # type: ignore[no-redef]
    from free_log_runtime import FreeLogStore  # type: ignore[no-redef]
    from free_live_check import build_free_live_check_service  # type: ignore[no-redef]
    from free_plan_check import build_free_plan_check_service  # type: ignore[no-redef]
    from free_protocol_runtime import FreeProtocolMixin  # type: ignore[no-redef]
    from free_camoufox.runner import CamoufoxRunner  # type: ignore[no-redef]
    from free_camoufox_runtime import (  # type: ignore[no-redef]
        CamoufoxRegistrationRunner,
        annotate_camoufox_debug_session,
        camoufox_debug_state,
        close_camoufox_debug_browsers,
    )
    from free_notifications import FreeBatchNotificationAdapter  # type: ignore[no-redef]
    from free_priority_executor import PriorityExecutor  # type: ignore[no-redef]
class FreeRegisterManager(FreeFailureRuntimeMixin, FreeRegisterSchedulerMixin, FreeProtocolMixin):
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

    @staticmethod
    def _timing_record(task: dict[str, Any]) -> dict[str, Any]:
        value = task.get("timing")
        started_at = int(task.get("created_at") or time.time())
        if not isinstance(value, dict):
            value = {
                "started_at": started_at,
                "queued_at": started_at,
                "execution_started_at": None,
                "finished_at": None,
                "elapsed_ms": 0,
                "elapsed_seconds": 0.0,
                "queue_elapsed_seconds": 0.0,
                "execution_elapsed_seconds": 0.0,
                "stages": [],
            }
            task["timing"] = value
        value.setdefault("started_at", started_at)
        value.setdefault("queued_at", value.get("started_at") or started_at)
        value.setdefault("execution_started_at", None)
        value.setdefault("finished_at", None)
        value.setdefault("elapsed_ms", 0)
        value.setdefault("elapsed_seconds", 0.0)
        value.setdefault("queue_elapsed_seconds", 0.0)
        value.setdefault("execution_elapsed_seconds", 0.0)
        value.setdefault("stages", [])
        value.setdefault("substeps", [])
        return value

    def _mark_execution_started(self, task_id: str, *, persist: bool = True) -> bool:
        """Record the worker start boundary for both timing and progress."""
        normalized = str(task_id or "").strip()
        if not normalized:
            return False
        now_wall = int(time.time())
        now_mono = time.monotonic()
        changed = False
        queued_at = now_wall
        stage_code = ""
        with self._lock:
            task = self._tasks.get(normalized)
            if not isinstance(task, dict):
                return False
            timing = self._timing_record(task)
            queued_at = int(timing.get("queued_at") or timing.get("started_at") or task.get("created_at") or now_wall)
            stage_code = str(task.get("stage") or "")
            timing["queued_at"] = queued_at
            if timing.get("execution_started_at") is None:
                timing["execution_started_at"] = now_wall
                timing["queue_elapsed_seconds"] = round(max(0, now_wall - queued_at), 3)
                timing["execution_elapsed_seconds"] = 0.0
                changed = True
            self._task_started_mono.setdefault(normalized, now_mono)
            progress = task.setdefault("progress", {})
            progress["timing"] = copy.deepcopy(timing)
            progress["updated_at"] = now_wall
            task["updated_at"] = now_wall
        if self.progress is not None and callable(getattr(self.progress, "mark_execution_started", None)):
            try:
                set_stage = getattr(self.progress, "set_stage", None)
                if callable(set_stage) and stage_code:
                    try:
                        set_stage(normalized, stage_code, now=queued_at)
                    except TypeError:
                        set_stage(normalized, stage_code)
                self.progress.mark_execution_started(normalized, now=now_wall)
            except TypeError:
                try:
                    self.progress.mark_execution_started(normalized)
                except Exception:
                    pass
            except Exception:
                pass
        if changed and persist:
            self._save_tasks_safely("任务开始执行计时")
        return True

    def _record_timing_substep(
        self,
        task_id: str,
        stage_code: str,
        code: str,
        elapsed_ms: Any,
        outcome: str = "success",
    ) -> None:
        """Append a credential-safe, aggregated adapter timing sample.

        Adapter callbacks run inside browser/mailbox workers.  A timing error
        is deliberately best-effort and can never alter the registration
        result.  Samples are kept in memory between short checkpoints; stage
        transitions and terminal persistence save the complete snapshot as
        usual.
        """
        normalized_stage = str(stage_code or "").strip()
        normalized_code = str(code or "").strip()
        label = FREE_TIMING_SUBSTEPS.get(normalized_code)
        if not normalized_stage or not label or normalized_stage not in FREE_STAGE_LABELS:
            return
        try:
            duration = max(0, int(elapsed_ms))
        except (TypeError, ValueError):
            return
        normalized_outcome = str(outcome or "success").strip()[:40] or "success"
        now_wall = int(time.time())
        now_mono = time.monotonic()
        key = f"{normalized_stage}:{normalized_code}"
        poll_codes = {
            "mailbox_poll_scan", "mailbox_detail_refresh", "mailbox_provider_refresh",
        }
        row_snapshot: dict[str, Any] | None = None
        timing_snapshot: dict[str, Any] | None = None
        checkpoint_requested = False
        checkpoint_task_id = str(task_id or "")
        with self._lock:
            task = self._tasks.get(checkpoint_task_id)
            if not isinstance(task, dict) or str(task.get("status") or "").strip().lower() in TERMINAL_STATUSES:
                return
            timing = self._timing_record(task)
            rows = timing.setdefault("substeps", [])
            if not isinstance(rows, list):
                rows = []
                timing["substeps"] = rows
            row = next(
                (
                    item for item in rows
                    if isinstance(item, dict) and item.get("key") == key
                ),
                None,
            )
            if row is None:
                row = {
                    "key": key,
                    "stage_code": normalized_stage,
                    "stage_label": FREE_STAGE_LABELS.get(normalized_stage, normalized_stage),
                    "code": normalized_code,
                    "label": label,
                    "duration_ms": duration,
                    "elapsed_seconds": round(duration / 1000.0, 3),
                    "first_duration_ms": duration,
                    "last_duration_ms": duration,
                    "max_duration_ms": duration,
                    "visits": 1,
                    "outcome": normalized_outcome,
                    "last_recorded_at": now_wall,
                }
                rows.append(row)
            else:
                previous_total = max(0, int(row.get("duration_ms") or 0))
                previous_visits = max(0, int(row.get("visits") or 0))
                row["duration_ms"] = previous_total + duration
                row["elapsed_seconds"] = round((previous_total + duration) / 1000.0, 3)
                row["last_duration_ms"] = duration
                row["max_duration_ms"] = max(int(row.get("max_duration_ms") or 0), duration)
                row["visits"] = previous_visits + 1
                row["outcome"] = normalized_outcome
                row["last_recorded_at"] = now_wall
            # Checkpoint the first sample, then at most once per second.  A
            # non-success outcome is flushed immediately so an early failure
            # remains visible even if the worker exits before its terminal
            # callback.  Terminal/stage saves still persist every in-memory
            # sample regardless of this advisory checkpoint.
            normalized_task_id = str(task_id or "")
            has_checkpoint = normalized_task_id in self._timing_checkpoint_mono
            last_checkpoint = self._timing_checkpoint_mono.get(normalized_task_id, 0.0)
            checkpoint_due = (
                not has_checkpoint
                or now_mono - last_checkpoint >= 1.0
                or normalized_outcome not in {"success", "skipped"}
            )
            should_save = bool(checkpoint_due)
            row_snapshot = dict(row)
            if should_save:
                # Copy only the timing object while holding the manager lock;
                # the potentially slow disk operation happens below after the
                # lock is released.  A checkpoint is advisory and never
                # replaces the authoritative stage/terminal save paths.
                try:
                    timing_snapshot = copy.deepcopy(timing)
                except Exception:
                    timing_snapshot = None
                checkpoint_requested = timing_snapshot is not None
                if checkpoint_requested:
                    # Reserve the interval before leaving the lock so two
                    # concurrent adapter callbacks do not both rewrite the
                    # same task snapshot.  A failed write is released below.
                    self._timing_checkpoint_mono[normalized_task_id] = now_mono
        if checkpoint_requested and timing_snapshot is not None:
            try:
                self.task_store.save_timing(checkpoint_task_id, timing_snapshot)
            except Exception as exc:
                # Timing persistence is diagnostic only; the worker's normal
                # result save path remains authoritative.  Allow a later
                # callback to retry after a storage failure.
                with self._lock:
                    if self._timing_checkpoint_mono.get(checkpoint_task_id) == now_mono:
                        self._timing_checkpoint_mono.pop(checkpoint_task_id, None)
                self._log(
                    f"[{checkpoint_task_id}/保存 Free 任务计时/free_task_timing_checkpoint] "
                    f"计时 checkpoint 保存失败（{type(exc).__name__}）",
                    "warn",
                    task_id=checkpoint_task_id,
                    node_code="free_task_timing_checkpoint",
                    node_label="保存 Free 任务计时",
                    outcome="storage_warning",
                )
        if row_snapshot is not None and normalized_code not in poll_codes:
            self._log(
                f"[{task_id}/{label}/{normalized_stage}] 子步骤完成 "
                f"duration_ms={int(row_snapshot.get('last_duration_ms') or 0)} "
                f"outcome={normalized_outcome}",
                "info" if normalized_outcome in {"success", "skipped"} else "warn",
                task_id=task_id,
                stage=normalized_stage,
                stage_label=FREE_STAGE_LABELS.get(normalized_stage, normalized_stage),
                node_code=normalized_stage,
                node_label=FREE_STAGE_LABELS.get(normalized_stage, normalized_stage),
                substep_code=normalized_code,
                substep_label=label,
                duration_ms=int(row_snapshot.get("last_duration_ms") or 0),
                outcome=normalized_outcome,
            )

    def _append_timing_stage(
        self,
        task: dict[str, Any],
        code: str,
        duration_ms: int,
        *,
        outcome: str = "success",
        started_at: int | None = None,
        finished_at: int | None = None,
        failure_code: str = "",
        retryable: bool | None = None,
    ) -> None:
        timing = self._timing_record(task)
        stages = timing.setdefault("stages", [])
        label = FREE_STAGE_LABELS.get(code, code)
        attempt = 1 + sum(1 for item in stages if str(item.get("code") or "") == code)
        stage_duration = max(0, int(duration_ms))
        record: dict[str, Any] = {
            "code": code,
            "label": label,
            "group": "free",
            "duration_ms": stage_duration,
            "elapsed_seconds": round(stage_duration / 1000.0, 3),
            "outcome": str(outcome or "success"),
            "attempt": attempt,
            "visits": attempt,
            "started_at": int(started_at) if started_at is not None else None,
            "entered_at": int(started_at) if started_at is not None else None,
            "finished_at": int(finished_at) if finished_at is not None else None,
            "left_at": int(finished_at) if finished_at is not None else None,
            "failure_code": str(failure_code or ""),
            "retryable": retryable if isinstance(retryable, bool) else None,
            "proxy_attempts": len(task.get("proxy_attempts") or ()) if isinstance(task.get("proxy_attempts"), (list, tuple)) else 0,
        }
        stages.append(record)
        if len(stages) > 200:
            del stages[:-200]
        slowest = max(stages, key=lambda item: int(item.get("duration_ms") or 0), default=None)
        if slowest:
            timing["slowest_node"] = {"code": slowest.get("code", ""), "label": slowest.get("label", ""), "duration_ms": int(slowest.get("duration_ms") or 0)}

    def _stage(
        self,
        task_id: str,
        code: str,
        *,
        previous_outcome: str = "success",
        previous_failure_code: str = "",
        previous_retryable: bool | None = None,
    ) -> None:
        changed = False
        persist = False
        now_wall = int(time.time())
        now_mono = time.monotonic()
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
                self._tasks[task_id]["updated_at"] = now_wall
                task_timing = self._timing_record(self._tasks[task_id])
                self._task_started_mono.setdefault(task_id, now_mono)
                if previous_code != code and previous_code:
                    previous_mono = self._stage_started_mono.pop(task_id, None)
                    duration_ms = int(max(0.0, (now_mono - previous_mono) * 1000.0)) if previous_mono is not None else max(0, (now_wall - previous_started) * 1000)
                    self._append_timing_stage(
                        self._tasks[task_id],
                        previous_code,
                        duration_ms,
                        outcome=previous_outcome,
                        started_at=previous_started or None,
                        finished_at=now_wall,
                        failure_code=previous_failure_code,
                        retryable=previous_retryable,
                    )
                if previous_code != code or task_id not in self._stage_started_mono:
                    self._stage_started_mono[task_id] = now_mono
                    self._manual_generations[task_id] = self._manual_generations.get(task_id, 0) + (1 if previous_code != code else 0)
                progress = self._tasks[task_id].setdefault("progress", {})
                stage_started_at = progress.get("stage_started_at")
                if previous_code != code or not stage_started_at:
                    stage_started_at = now_wall
                progress.update({
                    "stage": code,
                    "group": "free",
                    "started_at": progress.get("started_at") or int(time.time()),
                    "stage_started_at": stage_started_at,
                    "stage_duration_ms": 0,
                    "total_elapsed_ms": int(max(0.0, (now_mono - self._task_started_mono[task_id]) * 1000.0)),
                    "updated_at": now_wall,
                    "finished_at": None,
                })
                task_timing["finished_at"] = None
                task_timing["elapsed_ms"] = int(max(0.0, (now_mono - self._task_started_mono[task_id]) * 1000.0))
                task_timing["elapsed_seconds"] = round(task_timing["elapsed_ms"] / 1000.0, 3)
                persist = True
        if persist:
            self._save_tasks_safely("阶段状态更新")
        if changed:
            if previous_code and previous_code != code:
                duration_ms = None
                with self._lock:
                    current_timing = self._timing_record(self._tasks.get(task_id, {})) if task_id in self._tasks else {}
                    if current_timing:
                        for item in reversed(current_timing.get("stages") or []):
                            if item.get("code") == previous_code:
                                duration_ms = int(item.get("duration_ms") or 0)
                                break
                if duration_ms is None:
                    duration_ms = max(0, (now_wall - previous_started) * 1000) if previous_started else None
                self._log(
                    f"[{task_id}/{FREE_STAGE_LABELS.get(previous_code, previous_code)}/{previous_code}] 完成",
                    "success" if previous_outcome == "success" else "warn",
                    task_id=task_id, stage=previous_code,
                    stage_label=FREE_STAGE_LABELS.get(previous_code, previous_code),
                    node_code=previous_code,
                    node_label=FREE_STAGE_LABELS.get(previous_code, previous_code),
                    outcome=previous_outcome, duration_ms=duration_ms,
                    failure_code=previous_failure_code,
                    retryable=previous_retryable,
                )
            label = FREE_STAGE_LABELS.get(code, code)
            self._log(
                f"[{task_id}/{label}/{code}] 开始", "info",
                task_id=task_id, stage=code, stage_label=label,
                node_code=code, node_label=label, outcome="started", attempt=1,
            )

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

    def _finish_progress(self, task_id: str, outcome: str = "success") -> None:
        final_stage = ""
        final_label = ""
        duration_ms: int | None = None
        persist = False
        with self._lock:
            task = self._tasks.get(task_id)
            if task is not None:
                progress = task.setdefault("progress", {})
                task.pop("mailbox_verification", None)
                final_stage = str(progress.get("stage") or task.get("stage") or "")
                final_label = FREE_STAGE_LABELS.get(final_stage, final_stage)
                started = int(progress.get("stage_started_at") or 0)
                now_wall = int(time.time())
                now_mono = time.monotonic()
                stage_mono = self._stage_started_mono.pop(task_id, None)
                duration_ms = int(max(0.0, (now_mono - stage_mono) * 1000.0)) if stage_mono is not None else max(0, (now_wall - started) * 1000) if started else None
                if final_stage and duration_ms is not None:
                    final_failure = task.get("failure") if isinstance(task.get("failure"), Mapping) else {}
                    self._append_timing_stage(
                        task,
                        final_stage,
                        duration_ms,
                        outcome=outcome,
                        started_at=started or None,
                        finished_at=now_wall,
                        failure_code=str(final_failure.get("error_code") or "") if final_failure else "",
                        retryable=(bool(final_failure.get("retryable")) if final_failure and "retryable" in final_failure else None),
                    )
                    progress["stage_duration_ms"] = duration_ms
                task_started = self._task_started_mono.pop(task_id, None)
                timing = self._timing_record(task)
                total_ms = int(max(0.0, (now_mono - task_started) * 1000.0)) if task_started is not None else max(0, (now_wall - int(timing.get("started_at") or now_wall)) * 1000)
                started_at = int(timing.get("started_at") or task.get("created_at") or now_wall)
                queued_at = int(timing.get("queued_at") or started_at)
                execution_started_at = timing.get("execution_started_at")
                if execution_started_at is not None:
                    try:
                        execution_started_at = int(execution_started_at)
                    except (TypeError, ValueError):
                        execution_started_at = None
                queue_seconds = max(
                    0.0,
                    float(execution_started_at - queued_at)
                    if execution_started_at is not None else float(now_wall - queued_at),
                )
                execution_ms = max(
                    0,
                    int((now_mono - task_started) * 1000.0)
                    if task_started is not None
                    else (now_wall - execution_started_at) * 1000
                    if execution_started_at is not None else 0,
                )
                timing.update({
                    "started_at": started_at,
                    "queued_at": queued_at,
                    "execution_started_at": execution_started_at,
                    "finished_at": now_wall,
                    "elapsed_ms": total_ms,
                    "elapsed_seconds": round(total_ms / 1000.0, 3),
                    "queue_elapsed_seconds": round(queue_seconds, 3),
                    "execution_elapsed_seconds": round(execution_ms / 1000.0, 3),
                })
                progress["timing"] = copy.deepcopy(timing)
                progress["total_elapsed_ms"] = total_ms
                progress["finished_at"] = now_wall
                progress["updated_at"] = now_wall
                parent_id = str(task.get("retry_of") or "").strip()
                if parent_id and parent_id in self._tasks:
                    parent = self._tasks[parent_id]
                    child_status = str(task.get("status") or "").strip()
                    # A continuation is represented as a child task, while
                    # the original registration row remains visible in the
                    # task table.  Carry the latest account result back to
                    # that parent so a successful password/2FA retry cannot
                    # leave the original row showing stale capabilities.
                    if child_status in {"success", "partial_success", "twofa_pending"}:
                        child_result = task.get("result")
                        parent_result = parent.get("result")
                        if isinstance(child_result, Mapping):
                            parent["result"] = merge_account_result_fields(
                                parent_result if isinstance(parent_result, Mapping) else {},
                                child_result,
                            )
                    parent.update({
                        "retry_task_id": str(task.get("task_id") or ""),
                        "retry_status": child_status,
                        "retry_updated_at": now_wall,
                        "retry_resolved": child_status in {"success", "partial_success"},
                    })
                persist = True
                self._timing_checkpoint_mono.pop(task_id, None)
        if persist:
            self._save_tasks_safely("阶段进度完成")
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
        # The task journal and mailbox result file are persisted separately.
        # A continuation can finish after the original task snapshot was
        # written (or before a process restart), so use the durable account
        # result as a fill/override source for the public capability view.
        row_id = str(task.get("row_id") or "").strip()
        if row_id:
            try:
                durable_result = self.pool.result(row_id)
            except Exception:
                durable_result = {}
            if isinstance(durable_result, Mapping) and durable_result:
                result = merge_account_result_fields(result, durable_result)
        if result:
            result = normalize_password_result(result)
        # Keep the worker's raw address private.  ``email`` remains in the
        # public shape for old UI clients, but is always the masked display
        # value; callers that need the credential must use an explicit secret
        # or reveal endpoint keyed by ``row_id``.
        private_email = str(task.get("email") or "").strip()
        if not private_email and row_id:
            try:
                mailbox = self.pool.entry(row_id)
                private_email = str(getattr(mailbox, "email", "") or "").strip() if mailbox is not None else ""
            except Exception:
                private_email = ""
        email_masked = sanitize_public_email(private_email)
        subject_fingerprint = ""
        diagnostic_store = getattr(getattr(self, "log_store", None), "diagnostic_store", None)
        fingerprint_fn = getattr(diagnostic_store, "fingerprint", None)
        if callable(fingerprint_fn) and private_email:
            try:
                subject_fingerprint = str(fingerprint_fn(private_email) or "").strip().lower()
            except Exception:
                subject_fingerprint = ""
        if not re.fullmatch(r"[0-9a-f]{32}", subject_fingerprint):
            subject_fingerprint = _fingerprint(private_email) if private_email else ""
        public: dict[str, Any] = {}
        # Every scalar copied from a task snapshot is normalized by its
        # semantic type.  This keeps a malformed/hand-edited row from
        # smuggling a URL or credential through an otherwise innocuous field.
        identifier_fields = {
            "task_id", "incident_id", "slot_id", "batch_id", "run_mode",
            "driver", "row_id", "stage", "proxy_fingerprint", "proxy_id",
            "retry_of", "retry_task_id",
        }
        status_fields = {"status", "cleanup_status", "retry_status"}
        number_fields = {
            "ordinal", "slot_index", "concurrency_limit", "created_at",
            "updated_at", "retry_attempt", "retry_updated_at",
        }
        for key in identifier_fields:
            if key in task:
                limit = 40 if key == "driver" else 160
                safe = sanitize_public_identifier(task.get(key), limit=limit)
                public[key] = safe
        for key in status_fields:
            if key in task:
                safe = sanitize_public_status(task.get(key))
                public[key] = safe
        for key in number_fields:
            if key in task:
                safe = sanitize_public_number(
                    task.get(key), integer=True, minimum=0, default=None
                )
                public[key] = 0 if safe is None else safe
        if "proxy_scheme" in task:
            safe_scheme = sanitize_public_scheme(task.get("proxy_scheme"))
            public["proxy_scheme"] = safe_scheme
        if "proxy_effective_scheme" in task:
            safe_scheme = sanitize_public_scheme(task.get("proxy_effective_scheme"))
            public["proxy_effective_scheme"] = safe_scheme
        for key in ("proxy_masked", "profile_summary"):
            if key in task:
                public[key] = sanitize_failure_text(task.get(key), 300)
        if "proxy_attempts" in task:
            public["proxy_attempts"] = sanitize_proxy_attempts(task.get("proxy_attempts"))
        if "retry_resolved" in task:
            public["retry_resolved"] = sanitize_public_bool(task.get("retry_resolved"))
        # These keys remain in the legacy response shape, but their retired
        # allocation dimensions are deliberately blank for the shared pool.
        if "proxy_country" in task:
            public["proxy_country"] = ""
        if "proxy_group" in task:
            public["proxy_group"] = ""
        public["email"] = email_masked
        public["email_masked"] = email_masked
        public["subject_ref_fingerprint"] = subject_fingerprint
        # Free uses one shared healthy_random proxy pool.  Keep the legacy
        # response keys for clients, but never expose historical country/group
        # values as if they were still allocation dimensions.
        if "proxy_country" in public:
            public["proxy_country"] = ""
        if "proxy_group" in public:
            public["proxy_group"] = ""
        verification = public.get("mailbox_verification")
        if isinstance(verification, Mapping):
            phase = sanitize_public_status(
                verification.get("phase"),
                allowed={"automatic", "manual"},
                default="automatic",
            )
            opened_value = sanitize_public_number(
                verification.get("opened_at"), integer=True, minimum=0, default=0
            )
            deadline_value = sanitize_public_number(
                verification.get("deadline_at"), integer=True, minimum=0, default=0
            )
            if opened_value is not None and deadline_value is not None:
                opened_at = int(opened_value)
                deadline_at = max(opened_at, int(deadline_value))
                public["mailbox_verification"] = {
                    "phase": phase,
                    "stage": sanitize_public_identifier(
                        verification.get("stage") or public.get("stage"), limit=120
                    ),
                    "opened_at": opened_at,
                    "deadline_at": deadline_at,
                }
            else:
                public.pop("mailbox_verification", None)
        if not public.get("incident_id"):
            diagnostic_store = getattr(getattr(self, "log_store", None), "diagnostic_store", None)
            if diagnostic_store is not None:
                try:
                    matches = diagnostic_store.search({
                        "task_id": str(task.get("task_id") or ""),
                        "first_node_code": "mailbox_parser_unmatched",
                        "limit": 1,
                    })
                    if matches:
                        incident_id = sanitize_public_identifier(matches[0].get("incident_id"), limit=160)
                        if incident_id:
                            public["incident_id"] = incident_id
                except Exception:
                    pass
        # ``account`` is a legacy alias consumed by a few clients.  It must
        # follow the same masked representation and never reintroduce the
        # private address.
        public["account"] = email_masked
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
        public["stage_label"] = FREE_STAGE_LABELS.get(
            str(public.get("stage") or ""), str(public.get("stage") or "")
        )
        public["result"] = {}
        result_identifier_fields = {
            "account_flow", "plan_type", "subscription_plan", "eligible_campaign_id",
            "plan_check_task_id", "plan_error_code",
        }
        result_status_fields = {"plan_check_status", "password_status", "twofa_status"}
        result_text_fields = {"twofa_error"}
        for key in result_identifier_fields:
            if key in result:
                safe = sanitize_public_identifier(result.get(key), limit=160)
                public["result"][key] = safe
        for key in result_status_fields:
            if key in result:
                safe = sanitize_public_status(result.get(key))
                public["result"][key] = safe
        for key in result_text_fields:
            if key in result:
                public["result"][key] = sanitize_failure_text(result.get(key), 300)
        for key in ("has_active_subscription", "plus_trial_eligible", "password_set_after_registration"):
            if key in result:
                public["result"][key] = sanitize_public_bool(result.get(key))
        if "plan_checked_at" in result:
            public["result"]["plan_checked_at"] = sanitize_public_timestamp(
                result.get("plan_checked_at"), default=None
            )
        if "plan_retry_after_until" in result:
            public["result"]["plan_retry_after_until"] = sanitize_public_timestamp(
                result.get("plan_retry_after_until"), default=None
            )
        if "plan_http_status" in result:
            public["result"]["plan_http_status"] = sanitize_public_http_status(
                result.get("plan_http_status"), default=None
            )
        # Capability markers are derived from private evidence rather than
        # copied credentials.  Explicit persisted booleans are accepted only
        # when they parse cleanly.
        public["result"]["has_access_token"] = sanitize_public_bool(
            result.get("has_access_token"), default=bool(result.get("access_token"))
        )
        public["result"]["has_password"] = bool(result.get("password"))
        public["result"]["has_totp"] = bool(result.get("totp_secret"))
        public["result"]["has_credential"] = bool(result.get("credential_line"))
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
            # Progress providers are extension points and may return legacy
            # arbitrary mappings. Project them before adding compatibility
            # aliases so a nested token/mailbox URL can never cross the API
            # boundary through ``progress`` or its embedded timing object.
            progress_public = sanitize_public_progress(progress)
            # The Free store historically called these fields ``stage`` and
            # ``stage_started_at`` while the shared progress component uses
            # ``code``, ``label`` and ``entered_at``. Normalize only the
            # public snapshot so persisted legacy rows remain untouched.
            progress_code = str(progress_public.get("code") or progress_public.get("stage") or public.get("stage") or "")
            progress_public.setdefault("code", progress_code)
            progress_public.setdefault("label", FREE_STAGE_LABELS.get(progress_code, progress_code))
            progress_public.setdefault("entered_at", progress_public.get("stage_started_at") or progress_public.get("started_at"))
            public["progress"] = progress_public
            if isinstance(progress_public.get("timing"), Mapping):
                public["timing"] = sanitize_public_timing(progress_public["timing"])
        elif isinstance(task.get("progress"), Mapping):
            progress_public = sanitize_public_progress(task["progress"])
            progress_code = str(progress_public.get("code") or progress_public.get("stage") or public.get("stage") or "")
            progress_public.setdefault("code", progress_code)
            progress_public.setdefault("label", FREE_STAGE_LABELS.get(progress_code, progress_code))
            progress_public.setdefault("entered_at", progress_public.get("stage_started_at") or progress_public.get("started_at"))
            public["progress"] = progress_public
        if self.manual_broker is not None:
            try:
                prompt = self.manual_broker.public(str(task.get("task_id") or ""))
            except Exception:
                prompt = {}
            prompt_public = sanitize_public_manual_prompt(prompt)
            if prompt_public.get("input_kind"):
                public["manual_verification"] = prompt_public
                public["capabilities"] = ["submit_manual_verification"]
                verification = public.get("mailbox_verification") if isinstance(public.get("mailbox_verification"), Mapping) else {}
                opened_value = sanitize_public_number(
                    prompt_public.get("opened_at") or verification.get("opened_at"),
                    integer=True, minimum=0, default=0,
                )
                deadline_value = sanitize_public_number(
                    prompt_public.get("deadline_at") or verification.get("deadline_at"),
                    integer=True, minimum=0, default=0,
                )
                public["mailbox_verification"] = {
                    "phase": "manual",
                    "stage": sanitize_public_identifier(
                        verification.get("stage") or task.get("stage"), limit=120
                    ),
                    "opened_at": int(opened_value or 0),
                    "deadline_at": max(int(opened_value or 0), int(deadline_value or 0)),
                }
        if isinstance(task.get("timing"), Mapping):
            legacy_timing_task = {
                "created_at": task.get("created_at"),
                "timing": copy.deepcopy(dict(task["timing"])),
            }
            public["timing"] = sanitize_public_timing(
                self._timing_record(legacy_timing_task)
            )
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
                    -int(
                        sanitize_public_number(
                            item.get("created_at"), integer=True, minimum=0, default=0
                        )
                        or 0
                    ),
                    0 if item.get("retry_of") else 1,
                    int(
                        sanitize_public_number(
                            item.get("ordinal"), integer=True, minimum=0, default=0
                        )
                        or 0
                    ),
                    sanitize_public_identifier(item.get("task_id"), limit=160),
                ),
            )
            return [self._public_task(task) for task in tasks]

    def public_logs(self, task_id: str = "") -> list[dict[str, Any]]:
        driver = ""
        if task_id:
            with self._lock:
                task = self._tasks.get(str(task_id))
            if isinstance(task, Mapping):
                driver = sanitize_public_identifier(task.get("driver"), limit=40).lower()
        try:
            return self.log_store.snapshot(task_id, workflow="register", driver=driver)
        except TypeError:
            # Third-party compatibility facades may still expose the legacy
            # one-argument snapshot signature.
            return self.log_store.snapshot(task_id)

    def delete_tasks(self, task_ids: Sequence[str]) -> int:
        selected = {str(task_id or "").strip() for task_id in task_ids}
        selected.discard("")
        if not selected:
            raise ValueError("请选择要删除的 Free 任务")
        persist = False
        with self._lock:
            active = [task_id for task_id in selected if task_id in self._tasks and str(self._tasks[task_id].get("status") or "") not in TERMINAL_STATUSES]
            if active:
                raise ValueError(f"选中的 Free 任务中有 {len(active)} 条仍在排队或运行，请停止并等待任务结束后再删除")
            existing = [task_id for task_id in selected if task_id in self._tasks]
            for task_id in existing:
                self._tasks.pop(task_id, None)
            if existing:
                persist = True
        if persist:
            self._save_tasks_safely("删除任务状态")
        if existing:
            self.log_store.delete_tasks(existing)
        return len(existing)

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            tasks = self.public_tasks()
            active = sum(1 for task in tasks if task.get("status") not in TERMINAL_STATUSES)
            success = sum(1 for task in tasks if task.get("status") == "success" and not task.get("retry_resolved"))
            failed = sum(1 for task in tasks if task.get("status") == "failed" and not task.get("retry_resolved"))
            def proxy_attempt_switched(attempt: Any) -> bool:
                if not isinstance(attempt, Mapping):
                    return False
                # New records store the decision as a boolean. Accept the
                # legacy outcome marker as well for persisted task histories.
                return bool(attempt.get("switched")) or str(attempt.get("outcome") or "").strip().lower() == "switched"

            def proxy_attempt_is_retry(attempt: Any) -> bool:
                if not isinstance(attempt, Mapping):
                    return False
                return bool(attempt.get("retryable")) or proxy_attempt_switched(attempt)

            retry_count = sum(
                max(0, int(task.get("retry_attempt") or 0))
                + sum(1 for attempt in (task.get("proxy_attempts") or ()) if proxy_attempt_is_retry(attempt))
                for task in tasks
            )
            proxy_switches = sum(
                sum(1 for attempt in (task.get("proxy_attempts") or ()) if proxy_attempt_switched(attempt))
                for task in tasks
            )
            slowest_node = None
            first_failure = None
            for task in sorted(
                tasks,
                key=lambda item: int(
                    sanitize_public_number(
                        item.get("created_at"), integer=True, minimum=0, default=0
                    )
                    or 0
                ),
            ):
                if task.get("retry_resolved"):
                    continue
                failure = task.get("failure") if isinstance(task.get("failure"), Mapping) else None
                if failure and first_failure is None:
                    first_failure = {"node_code": str(failure.get("node_code") or ""), "node_label": str(failure.get("node_label") or "")}
                candidate = task.get("timing", {}).get("slowest_node") if isinstance(task.get("timing"), Mapping) else None
                if isinstance(candidate, Mapping) and (slowest_node is None or int(candidate.get("duration_ms") or 0) > int(slowest_node.get("duration_ms") or 0)):
                    slowest_node = copy.deepcopy(dict(candidate))
            try:
                # Read the persisted settings for an idle manager as well as
                # for a running batch.  ``_last_config`` describes the last
                # batch and can otherwise make the debug bar report stale
                # headless/debug values after settings are changed.
                camoufox_debug = self.camoufox_debug_state()
            except Exception:
                camoufox_debug = {
                    "enabled": False,
                    "headless": True,
                    "capacity": 0,
                    "used": 0,
                    "available": 0,
                    "open_contexts": 0,
                    "pool_count": 0,
                    "sessions": [],
                }
            return {
                **runtime_info(),
                # Keep the batch marked running until every Future callback
                # has persisted its final task/log state.  Checking only
                # terminal task statuses races teardown and can leave an
                # atomic log temp file being written after a caller observes
                # running=False.
                # A final Future callback keeps the executor reference while
                # joining worker threads and the heartbeat. Do not report an
                # idle batch until those background writers have actually
                # stopped; callers commonly use this flag before tearing
                # down a temporary data directory.
                "running": bool(
                    self._executor
                    or (
                        self._heartbeat_thread is not None
                        and self._heartbeat_thread.is_alive()
                    )
                ),
                "batch_id": sanitize_public_identifier(self._batch_id, limit=160),
                "tasks": tasks,
                "pool": {
                    "total": len(self.pool.entries()),
                    "available": self._available_count(),
                    "proxies": len(self.proxies.values()),
                },
                # Free registration has one shared healthy_random pool;
                # country/group summaries are retained only by unrelated
                # network-tool flows and are intentionally absent here.
                "proxy_groups": [],
                "proxy_selection": {"country": "", "group": ""},
                "driver": sanitize_public_identifier(
                    next(
                        (
                            task.get("driver")
                            for task in reversed(list(self._tasks.values()))
                            if task.get("batch_id") == self._batch_id
                        ),
                        "protocol",
                    ),
                    limit=40,
                    default="protocol",
                ) or "protocol",
                "scheduler": {
                    "concurrency": max(1, min(int(self._last_config.get("concurrency") or self._last_config.get("free_concurrency") or 3), 16)),
                    "active_slots": sum(1 for task in tasks if task.get("status") == "running"),
                    "queued_slots": sum(1 for task in tasks if task.get("status") == "queued"),
                },
                "camoufox_debug": camoufox_debug,
                "summary": {
                    "total": len(tasks),
                    "active": active,
                    "success": success,
                    "failed": failed,
                    "stopped": sum(1 for task in tasks if task.get("status") == "stopped"),
                    "total_retries": retry_count,
                    "proxy_switches": proxy_switches,
                    "slowest_node": slowest_node,
                    "first_failure": first_failure,
                },
            }

    def camoufox_debug_state(self) -> dict[str, Any]:
        """Return the secret-free state of retained Camoufox debug pages."""
        config: Mapping[str, Any] = {}
        if callable(self.config_provider):
            try:
                candidate = self.config_provider()
                if isinstance(candidate, Mapping):
                    config = candidate
            except Exception:
                config = self._last_config
        if not config:
            config = self._last_config
        return camoufox_debug_state(self._camoufox_state_config(config))

    def close_camoufox_debug(self, session_id: str = "") -> dict[str, Any]:
        """Close one retained debug session or all retained sessions."""
        normalized = str(session_id or "").strip()
        # Keep the current normalized Camoufox settings available to the
        # aggregate close helper.  ``config`` used to be referenced here
        # without being initialized, so a valid close request could fail only
        # after the session-id validation path had succeeded.
        config: Mapping[str, Any] = {}
        if callable(self.config_provider):
            try:
                candidate = self.config_provider()
                if isinstance(candidate, Mapping):
                    config = candidate
            except Exception:
                config = self._last_config
        if not config:
            config = self._last_config
        if normalized:
            # The pool module owns the event-loop objects. Keep the public
            # manager boundary narrow and use its aggregate close helper for
            # now; an unknown id is reported without touching running tasks.
            state = self.camoufox_debug_state()
            known = {
                str(item.get("session_id") or "")
                for item in state.get("sessions", [])
                if isinstance(item, Mapping)
            }
            if normalized not in known:
                raise FreeRegisterError(
                    "free_camoufox_debug",
                    "关闭 Camoufox 调试窗口",
                    "指定的调试窗口不存在或已经关闭",
                    retryable=False,
                    error_code="camoufox_debug_session_not_found",
                )
        result = close_camoufox_debug_browsers(
            normalized,
            config=self._camoufox_state_config(config),
        )
        result["state"] = self.camoufox_debug_state()
        return result

    def _available_count(self) -> int:
        return len(self.pool.available(10_000))

    def _camoufox_state_config(self, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Build the runtime-only Camoufox config used for pool identity.

        The runner adds its artifact directory to the low-level browser config
        before creating a pool.  State and cleanup requests used to calculate a
        key from the persisted config alone, so every idle state poll could
        mistake the live pool for an obsolete one and shut it down.  Keep this
        private path out of persisted/public config while using the same value
        for admission, state and cleanup.
        """
        value = copy.deepcopy(dict(config or {}))
        browser = value.get("camoufox")
        if isinstance(browser, Mapping):
            browser_value = copy.deepcopy(dict(browser))
            browser_value.setdefault("_debug_artifact_dir", str(self.data_dir / "camoufox_debug"))
            value["camoufox"] = browser_value
        else:
            value["camoufox"] = {
                "_debug_artifact_dir": str(self.data_dir / "camoufox_debug"),
            }
        return value

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
                        except Exception:
                            pass
                    if binding is not None:
                        try:
                            self.proxies.release(binding, owner=task_id or batch_id)
                        except Exception:
                            pass
                    if reserved:
                        try:
                            self.pool.update(row.row_id, status="available", batch_id="", stage="")
                        except Exception:
                            pass
                    self._save_tasks_safely("运行中导入回滚")
                    result["skipped_items"].append({"row_id": row.row_id, "reason": _safe_log_message(exc)[:240]})
            self._save_tasks_safely("运行中导入后的 Free 任务状态")
            return result

    def preflight(self, config: Mapping[str, Any], *, proxy_content: str = "") -> dict[str, Any]:
        with self._lock:
            if self.public_state().get("running"):
                raise FreeRegisterError(
                    "free_run_preflight",
                    "预检 Free 注册",
                    "Free 注册任务运行中，暂不能执行批次预检",
                    retryable=False,
                )
        driver = str(config.get("driver") or "protocol").strip().lower()
        if driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError("free_config", "Free 注册预检", "Free 注册链路无效", retryable=False)
        protocol_result = {}
        if driver == "protocol" and not self._custom_runner:
            protocol_result = self.protocol_preflight(config)
        self.proxies.configure_policy(
            failure_threshold=int(config.get("proxy_failure_threshold") or 2),
            quarantine_seconds=int(config.get("proxy_quarantine_seconds") or 600),
            health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
            tls_verify=bool(config.get("proxy_tls_verify", True)),
            tls_compat_fallback=bool(config.get("proxy_tls_compat_fallback", True)),
            socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
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
            health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
        )
        camoufox_result = {"driver": driver}
        if driver == "camoufox" and not self._custom_runner:
                camoufox_result = CamoufoxRunner.preflight(config)
        return {
            **runtime_info(),
            "driver": driver,
            "target_count": target,
            "mailboxes": available,
            "proxies": len(bindings),
            "protocol": protocol_result,
            "camoufox": camoufox_result,
            "proxy_selection": {"country": "", "group": ""},
        }

    def preflight_proxies(self, *, proxy_content: str = "", probe_url: str = "https://chatgpt.com/", driver: str = "protocol", country: str | None = None, group: str | None = None, scheme: str | None = None, tls_verify: bool = True, tls_compat_fallback: bool = True, socks5_dns_mode: str = "declared", layered_probe: bool = False) -> dict[str, Any]:
        """Probe the isolated Free proxy pool without consuming mailboxes or tasks."""
        normalized_driver = str(driver or "protocol").strip().lower()
        if normalized_driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError(
                "free_config", "Free 代理预检", "Free 注册链路只能选择全协议或 Camoufox", retryable=False,
                error_code="free_driver_unsupported",
            )
        driver = normalized_driver
        self.proxies.configure_policy(
            tls_verify=tls_verify,
            tls_compat_fallback=tls_compat_fallback,
            socks5_dns_mode=socks5_dns_mode,
        )
        if proxy_content.strip() and scheme:
            self.proxies.default_scheme = str(scheme).strip().lower()
        saved_pool = not str(proxy_content or "").strip()
        values = self.proxies.values(proxy_content)
        if not values:
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "请先粘贴或保存至少一个 Free 代理", retryable=False)
        try:
            target_domain = str(urlsplit(str(probe_url or "")).hostname or "").lower()
        except (TypeError, ValueError):
            target_domain = ""
        # Probe adapters may include a credential-bearing value from their
        # transport exception. Keep a request-wide denylist so a stale or
        # misattributed exception cannot expose another row's credentials.
        all_proxy_secrets: set[str] = set()
        for candidate in values:
            try:
                parsed_candidate = self.proxies._parse_lines(
                    candidate,
                    country="",
                    group="",
                    scheme=self.proxies.default_scheme,
                )
                if parsed_candidate:
                    all_proxy_secrets.update(
                        str(parsed_candidate[0].get(key) or "")
                        for key in ("username", "password")
                        if str(parsed_candidate[0].get(key) or "")
                    )
            except Exception:
                continue
        diagnostics: list[dict[str, Any]] = []
        pool_health_write_errors: list[dict[str, str]] = []
        for index, value in enumerate(values, 1):
            try:
                layered = None
                if layered_probe and self.proxy_probe is None:
                    layered = self.proxies.layered_probe(value, probe_url)
                    if not layered.get("ok"):
                        raise FreeRegisterError(
                            str(layered.get("failure_node") or "free_proxy_preflight"),
                            "Free 代理分层探测",
                            str(layered.get("failure_reason") or "代理分层探测失败"),
                            retryable=True,
                            provider_status=layered.get("http_status")
                            or layered.get("https_status")
                            or layered.get("chatgpt_status"),
                        )
                # A layered probe already performed the transport and
                # ChatGPT-login requests. Reusing its result avoids issuing a
                # second full HTTPS request for the same proxy during one
                # preflight, which was a major source of slow diagnostics.
                self.proxies.bind(
                    1,
                    content=value,
                    probe=self.proxy_probe,
                    probe_url=probe_url,
                    driver=driver,
                    perform_probe=layered is None,
                )
                row = dict((getattr(self.proxies, "_last_bind_diagnostics", ()) or [{}])[0])
                row.setdefault("index", index)
                row.setdefault("available", True)
                row.setdefault("http_status", 200)
                row.setdefault("failure_node", "")
                row.setdefault("failure_reason", "")
                if row.get("available"):
                    # Keep successful rows on the same public contract as
                    # failures, while never attaching a fabricated failure.
                    row.setdefault("declared_scheme", row.get("scheme") or "")
                    row.setdefault("effective_scheme", row.get("scheme") or "")
                    row.setdefault("provider_status", row.get("http_status"))
                    row.setdefault("provider_code", "")
                if layered is not None:
                    row["layered_probe"] = layered
                    row["http_status"] = (
                        layered.get("http_status")
                        or layered.get("https_status")
                        or layered.get("chatgpt_status")
                    )
                    row["proxy_to_target_ms"] = layered.get("https_request_ms")
                if saved_pool:
                    # A successful manual recheck is explicit health evidence:
                    # clear quarantine and make the saved row eligible again.
                    parsed = self.proxies._parse_lines(value, country="", group="", scheme=self.proxies.default_scheme)
                    record = parsed[0] if parsed else {}
                    proxy_id = str(record.get("proxy_id") or "")
                    if proxy_id:
                        try:
                            self.proxies.record_success(
                                proxy_id,
                                latency_ms=row.get("proxy_to_target_ms"),
                                probe_mode=str(row.get("probe_mode") or "manual"),
                                effective_scheme=str(row.get("effective_scheme") or ""),
                                http_status=row.get("http_status"),
                            )
                        except Exception as health_exc:
                            # A successful transport probe remains successful
                            # even when the optional health snapshot cannot be
                            # persisted. Keep the row available and continue
                            # probing the rest of the pool; surface the write
                            # problem in the aggregate diagnostics instead of
                            # misclassifying a healthy proxy as unavailable.
                            pool_health_write_errors.append({
                                "proxy_id": proxy_id,
                                "error_type": type(health_exc).__name__,
                            })
                            self._log(
                                "[Free 代理预检/free_proxy_health] 代理健康状态保存失败，保留成功探测结果",
                                "warn",
                                node_code="free_proxy_health",
                                node_label="记录 Free 代理成功",
                                outcome="cleanup_failed",
                                failure={
                                    "error_code": "free_proxy_health_write_failed",
                                    "technical_summary": f"代理健康状态保存失败（{type(health_exc).__name__}）",
                                    "retryable": True,
                                    "action_hint": "检查 Free 代理池存储状态；本次探测结果仍有效。",
                                },
                                workflow="cleanup",
                            )
            except Exception as exc:
                failure = exception_to_failure(
                    exc,
                    node_code=str(
                        getattr(exc, "node_code", "")
                        or getattr(exc, "error_code", "")
                        or "proxy_connect_failed"
                    ),
                    node_label=str(getattr(exc, "node_label", "") or "代理连接失败"),
                )
                parsed = self.proxies._parse_lines(value, country="", group="", scheme=self.proxies.default_scheme)
                record = parsed[0] if parsed else {}
                proxy_secrets = sorted(all_proxy_secrets, key=len, reverse=True)
                for key in ("public_message", "technical_summary", "action_hint", "diagnostic"):
                    detail = str(failure.get(key) or "")
                    for secret in proxy_secrets:
                        detail = detail.replace(secret, "********")
                    if detail:
                        failure[key] = sanitize_failure_text(detail, 800 if key != "action_hint" else 300)
                declared_scheme = str(record.get("scheme") or self.proxies.default_scheme)
                transport_proxy = proxy_transport_value(
                    value,
                    driver=driver,
                    socks5_dns_mode=socks5_dns_mode,
                )
                try:
                    effective_scheme = str(urlsplit(transport_proxy).scheme or declared_scheme).lower()
                except (TypeError, ValueError):
                    effective_scheme = declared_scheme
                enriched_failure = canonical_failure({
                    **failure,
                    "declared_scheme": declared_scheme,
                    "transport_scheme": effective_scheme,
                    "target_domain": target_domain,
                    "request_stage": "manual_proxy_preflight",
                    "retry_count": 0,
                    "transport_error_code": (
                        failure.get("transport_error_code")
                        if str(failure.get("transport_error_code") or "") in {
                            "proxy_protocol_mismatch", "proxy_auth_rejected", "proxy_dns_failed",
                            "proxy_connect_timeout", "proxy_connection_reset",
                            "proxy_tls_certificate_error", "proxy_connect_failed", "tls_connection_failed",
                        }
                        else ""
                    ),
                }) or failure
                row = {
                    "index": index,
                    "masked": _mask_proxy(value),
                    "fingerprint": str(record.get("proxy_id") or ""),
                    "scheme": declared_scheme,
                    "declared_scheme": declared_scheme,
                    "effective_scheme": effective_scheme,
                    "available": False,
                    "http_status": enriched_failure.get("http_status"),
                    "provider_status": enriched_failure.get("http_status"),
                    "provider_code": enriched_failure.get("provider_code") or "",
                    "local_to_proxy_ms": None,
                    "proxy_to_target_ms": None,
                    "failure_node": enriched_failure.get("node_code") or "proxy_connect_failed",
                    "failure_reason": enriched_failure.get("technical_summary") or enriched_failure.get("public_message") or "代理请求失败",
                    "failure": enriched_failure,
                }
                if saved_pool and is_proxy_health_failure(exc):
                    proxy_id = str(record.get("proxy_id") or "")
                    if proxy_id:
                        try:
                            self.proxies.record_failure(
                                proxy_id,
                                node_code=str(enriched_failure.get("node_code") or "proxy_connect_failed"),
                                message=str(enriched_failure.get("technical_summary") or enriched_failure.get("public_message") or "代理请求失败"),
                                http_status=enriched_failure.get("http_status"),
                            )
                        except Exception as health_exc:
                            # Pool health bookkeeping is advisory. A storage
                            # outage must not abort the remaining proxy probes
                            # or prevent their failures from being aggregated
                            # into the single taskless preflight incident.
                            pool_health_write_errors.append({
                                "proxy_id": proxy_id,
                                "error_type": type(health_exc).__name__,
                            })
                            self._log(
                                "[Free 代理预检/free_proxy_health] 代理健康状态保存失败，继续检测其余代理",
                                "warn",
                                node_code="free_proxy_health",
                                node_label="记录 Free 代理失败",
                                outcome="cleanup_failed",
                                failure={
                                    "error_code": "free_proxy_health_write_failed",
                                    "technical_summary": f"代理健康状态保存失败（{type(health_exc).__name__}）",
                                    "retryable": True,
                                    "action_hint": "检查 Free 代理池存储状态；本次预检结果仍会汇总返回。",
                                },
                                workflow="cleanup",
                            )
            row["index"] = index
            diagnostics.append(row)
        result: dict[str, Any] = {
            **runtime_info(),
            "proxies": len([row for row in diagnostics if row.get("available")]),
            "rows": diagnostics,
        }
        if pool_health_write_errors:
            result["health_write_failures"] = len(pool_health_write_errors)
        failed_rows = [row for row in diagnostics if not row.get("available")]
        if not failed_rows:
            return result

        failures = [
            row.get("failure")
            for row in failed_rows
            if isinstance(row.get("failure"), Mapping)
        ]
        first_failure = failures[0] if failures else {}
        nodes = sorted({str(row.get("failure_node") or "") for row in failed_rows if row.get("failure_node")})
        http_statuses = sorted({
            int(row["http_status"])
            for row in failed_rows
            if isinstance(row.get("http_status"), int)
        })
        provider_codes = sorted({str(row.get("provider_code") or "") for row in failed_rows if row.get("provider_code")})
        declared_schemes = sorted({
            str(row.get("declared_scheme") or row.get("scheme") or "")
            for row in failed_rows
            if row.get("declared_scheme") or row.get("scheme")
        })
        effective_schemes = sorted({str(row.get("effective_scheme") or "") for row in failed_rows if row.get("effective_scheme")})
        proxy_fingerprints = [str(row.get("fingerprint") or "") for row in failed_rows if row.get("fingerprint")]
        failure_count = len(failed_rows)
        total_count = len(diagnostics)
        aggregate_node = str(first_failure.get("node_code") or (nodes[0] if nodes else "free_proxy_preflight"))
        aggregate_failure = canonical_failure({
            "node_code": aggregate_node,
            "node_label": first_failure.get("node_label") or "Free 代理预检",
            "error_code": first_failure.get("error_code") or "free_proxy_preflight_failed",
            "provider_code": provider_codes[0] if len(provider_codes) == 1 else "",
            "public_message": f"Free 代理连通性检测完成：共 {total_count} 条，失败 {failure_count} 条",
            "technical_summary": (
                f"代理预检失败 {failure_count}/{total_count}；"
                f"节点={','.join(nodes) or 'free_proxy_preflight'}；"
                f"HTTP={','.join(str(value) for value in http_statuses) or '-'}"
                + (f"；代理健康状态写入失败={len(pool_health_write_errors)}" if pool_health_write_errors else "")
            ),
            "retryable": bool(failures) and all(bool(item.get("retryable")) for item in failures),
            "http_status": http_statuses[0] if len(http_statuses) == 1 else None,
            "action_hint": first_failure.get("action_hint") or "按失败节点检查代理协议、认证、DNS 和目标站点响应后重试。",
            "declared_scheme": declared_schemes[0] if len(declared_schemes) == 1 else "",
            "transport_scheme": effective_schemes[0] if len(effective_schemes) == 1 else "",
            "target_domain": target_domain,
            "request_stage": "manual_proxy_preflight",
            "retry_count": 0,
            "transport_error_code": first_failure.get("transport_error_code") or "",
        }, default_node_code="free_proxy_preflight", default_node_label="Free 代理预检")
        if aggregate_failure is None:  # pragma: no cover - identity is populated above
            return result
        result.update({"failure_count": failure_count, "failure": aggregate_failure})

        log_store = getattr(self, "log_store", None)
        diagnostic_store = getattr(log_store, "diagnostic_store", None)
        incident_id = ""
        if diagnostic_store is not None:
            try:
                writer = getattr(log_store, "diagnostic_writer", None)
                if writer is None:
                    writer = DiagnosticEventWriter(
                        diagnostic_store,
                        context=LogContext(
                            chain="free",
                            workflow="proxy_preflight",
                            driver=str(driver or "protocol"),
                        ),
                    )
                incident_id = writer.record({
                    "level": "error",
                    "outcome": "error",
                    "chain": "free",
                    "workflow": "proxy_preflight",
                    "driver": str(driver or "protocol"),
                    "node_code": aggregate_failure.get("node_code"),
                    "node_label": aggregate_failure.get("node_label"),
                    "message": aggregate_failure.get("public_message"),
                    "failure": aggregate_failure,
                    "transport": {
                        "failure_count": failure_count,
                        "total_count": total_count,
                        "target_domain": target_domain,
                        "nodes": ",".join(nodes),
                        "http_statuses": ",".join(str(value) for value in http_statuses),
                        "provider_statuses": ",".join(str(row.get("provider_status")) for row in failed_rows if row.get("provider_status") is not None),
                        "provider_codes": ",".join(provider_codes),
                        "declared_schemes": ",".join(declared_schemes),
                        "effective_schemes": ",".join(effective_schemes),
                        "proxy_fingerprints": ",".join(proxy_fingerprints),
                        "health_write_failures": len(pool_health_write_errors),
                    },
                })
            except Exception:
                incident_id = ""
        if incident_id:
            result["incident_id"] = incident_id
            for row in failed_rows:
                row["incident_id"] = incident_id
        return result

    def start(self, config: Mapping[str, Any], *, pool_content: str = "", proxy_content: str = "", row_ids: Sequence[str] = ()) -> dict[str, Any]:
        normalized_config = dict(config)
        # Preserve explicit security-step choices at the manager boundary.
        # Older code forced 2FA on here, which made an explicit ``false`` from
        # the UI ineffective and also caused password-only runs to enter MFA.
        normalized_config.setdefault("auto_set_password", False)
        normalized_config.setdefault("auto_set_2fa", True)
        # HTTP callers normally pass a FreeConfigStore-normalized snapshot.
        # Keep direct manager integrations on the same production defaults
        # without changing explicit protocol or DNS choices.
        if not str(normalized_config.get("proxy_default_scheme") or "").strip():
            normalized_config["proxy_default_scheme"] = "socks5"
        if not str(normalized_config.get("proxy_socks5_dns_mode") or "").strip():
            normalized_config["proxy_socks5_dns_mode"] = "remote"
        # Keep the manager boundary strict even when a caller bypasses the
        # HTTP config store. Legacy browser tasks remain readable from history,
        # but a new start request must never reserve rows or touch a removed
        # transport.
        requested_driver = str(normalized_config.get("driver") or "protocol").strip().lower()
        if requested_driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError(
                "free_config", "启动 Free 注册", "Free 注册链路只能选择全协议或 Camoufox", retryable=False,
                error_code="free_driver_unsupported",
            )
        normalized_config["driver"] = requested_driver
        start_attempted = False
        try:
            with self._lock:
                # Keep the production manager boundary aligned with the Free
                # contract even for callers that bypass the HTTP config store.
                if self.public_state().get("running"):
                    raise FreeRegisterError("free_run_start", "启动 Free 注册", "已有 Free 注册任务运行中", retryable=False)
                start_attempted = True
                self._last_config = copy.deepcopy(normalized_config)
                return self._start_locked(
                    normalized_config,
                    pool_content=pool_content,
                    proxy_content=proxy_content,
                    row_ids=row_ids,
                )
        except Exception:
            # ``_start_locked`` owns the manager lock while reserving rows and
            # creating the worker runtime.  Drain any partially-created
            # runtime only after that lock has been released; joining a worker
            # here would deadlock when it is waiting to enter ``_worker``.
            if start_attempted:
                self._rollback_failed_startup()
                with self._lock:
                    idle_owner = not self._futures and self._executor is None
                if idle_owner:
                    self._release_runtime_owner()
            raise

    def _rollback_failed_startup(self) -> None:
        """Drain a batch whose executor/heartbeat could not be assembled.

        A normal worker completion owns its own cleanup path.  Startup is
        different: a constructor or submit failure can happen after only a
        subset of tasks has been registered, so this method first detaches
        Future callbacks, waits for the executor, and then releases every
        task's leases.  It is intentionally idempotent and only acts on the
        batch marker set by the current ``start`` call.
        """
        with self._lock:
            batch_id = str(self._startup_batch_id or "").strip()
            if not batch_id:
                return
            self._stop.set()
            self._user_stop_requested = True
            heartbeat_stop = self._heartbeat_stop
            heartbeat_stop.set()
            heartbeat_thread = self._heartbeat_thread
            executor = self._executor
            # Detach callbacks before cancelling.  ``Future.cancel`` invokes
            # callbacks synchronously for an already-queued future; leaving
            # them in ``_futures`` could recursively enter normal batch
            # teardown while this startup rollback is still collecting rows.
            futures = tuple(self._futures)
            self._futures.clear()
            self._future_drivers.clear()
            task_ids = [
                str(task.get("task_id") or task_id)
                for task_id, task in self._tasks.items()
                if str(task.get("batch_id") or "") == batch_id
            ]
            self._shutdown_pending = True

        for future in futures:
            try:
                future.cancel()
            except Exception:
                pass
        if executor is not None:
            try:
                executor.shutdown(wait=True, cancel_futures=True)
            except TypeError:
                try:
                    executor.shutdown(wait=True)
                except Exception:
                    pass
            except Exception:
                # The worker state and lease cleanup below remain authoritative
                # even when an injected/third-party executor cannot shut down
                # cleanly.
                pass
        if heartbeat_thread is not None and heartbeat_thread is not threading.current_thread():
            try:
                heartbeat_thread.join(timeout=5)
            except Exception:
                pass

        # A running worker may switch to a replacement proxy or confirm the
        # mailbox while the executor drains.  Refresh the task snapshots after
        # the wait so cleanup targets the worker's latest durable binding.
        with self._lock:
            tasks = [
                copy.deepcopy(self._tasks[task_id])
                for task_id in task_ids
                if task_id in self._tasks
            ]
        for task in tasks:
            try:
                self._release_task_lease(task)
            except Exception as exc:
                self._log(
                    f"[{task.get('task_id', '')}/启动回滚/free_startup_rollback] "
                    f"资源释放失败（{type(exc).__name__}）",
                    "warn",
                    task_id=str(task.get("task_id") or ""),
                    node_code="free_startup_rollback",
                    node_label="Free 启动回滚",
                    outcome="cleanup_failed",
                )
            # The legacy JSON pool has no mailbox lease coordinator.  Its
            # startup rows were not yet submitted to a transport, so return
            # them explicitly after the proxy release above.  SQLite-backed
            # pools use ``MailboxLeaseCoordinator`` as the source of truth.
            if self.mailbox_leases is None and str(task.get("status") or "").strip().lower() in {"queued", "reserved"}:
                row_id = str(task.get("row_id") or "").strip()
                if row_id:
                    try:
                        self.pool.update(
                            row_id,
                            status="available",
                            batch_id="",
                            stage="",
                            driver="",
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
                        )
                    except Exception:
                        pass

        with self._lock:
            # Mark rows terminal for one save before removing them.  The
            # SQLite compatibility adapter intentionally deletes only terminal
            # stale rows, so this first checkpoint makes the subsequent empty
            # snapshot eligible to remove a partially-created startup task.
            for task_id, task in list(self._tasks.items()):
                if str(task.get("batch_id") or "") != batch_id:
                    continue
                task["status"] = "stopped"
                task["cleanup_status"] = task.get("cleanup_status") or "released"
                task["updated_at"] = int(time.time())
        self._save_tasks_safely("启动失败回滚终态")
        with self._lock:
            for task_id, task in list(self._tasks.items()):
                if str(task.get("batch_id") or "") == batch_id:
                    self._tasks.pop(task_id, None)
            if self._executor is executor:
                self._executor = None
            if self._heartbeat_thread is heartbeat_thread:
                self._heartbeat_thread = None
            self._shutdown_pending = False
            self._startup_batch_id = ""
            self._batch_id = ""
            self._stage_started_mono = {
                key: value for key, value in self._stage_started_mono.items()
                if key in self._tasks
            }
            self._task_started_mono = {
                key: value for key, value in self._task_started_mono.items()
                if key in self._tasks
            }
            self._timing_checkpoint_mono = {
                key: value for key, value in self._timing_checkpoint_mono.items()
                if key in self._tasks
            }
        self._save_tasks_safely("启动失败回滚")
        self._release_runtime_owner()

    def _start_locked(
        self,
        config: Mapping[str, Any],
        *,
        pool_content: str,
        proxy_content: str,
        row_ids: Sequence[str],
    ) -> dict[str, Any]:
        """Start a batch while ``start`` still owns the manager lock.

        The reservation and executor creation remain one transaction. Releasing
        the lock between
        the running check and mailbox/proxy reservation allowed two concurrent
        start requests to both pass the check.
        """
        # Establish process ownership before protocol/Camoufox preflight or
        # any pool mutation.  A second Flask/LaunchAgent instance therefore
        # fails cleanly without touching the old worker's rows.
        self._acquire_runtime_owner()
        # Validate the full-protocol bridge before importing or leasing any
        # mailbox/proxy rows. Custom runners are test/integration adapters
        # and intentionally retain their existing contract.
        requested_driver = str(config.get("driver") or "protocol").strip().lower()
        if requested_driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError(
                "free_config", "启动 Free 注册", "Free 注册链路只能选择全协议或 Camoufox", retryable=False,
                error_code="free_driver_unsupported",
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
            # An available pool row is not automatically a new-registration
            # candidate: an operator may have restored a previously completed
            # account to ``available`` by hand.  Check durable and historical
            # account evidence before calculating the batch or touching a
            # proxy lease.  This keeps the guard effective for both explicit
            # selections and automatic pool dispatch.
            available_rows = self.pool.available(10_000)
            protected_rows = [
                row for row in available_rows
                if self._registration_account_exists(row.row_id)
            ]
            protected_ids = {row.row_id for row in protected_rows}
            registration_rows = [
                row for row in available_rows
                if row.row_id not in protected_ids
            ]
            available_count = len(registration_rows)
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
                # Check explicitly selected rows even when their pool status
                # is currently pending/unavailable; otherwise a completed
                # account could be hidden behind a generic availability error
                # and later replayed after a manual status change.
                requested_protected = {
                    row_id for row_id in requested_row_ids
                    if row_id not in protected_ids
                    and self._registration_account_exists(row_id)
                }
                requested_protected.update(requested_row_ids & protected_ids)
                if requested_protected:
                    raise FreeRegisterError(
                        "free_run_account_result_exists",
                        "启动 Free 注册",
                        "所选邮箱已有已保存的 Free 账号结果，不能再次走整条注册流程；请使用已有账号登录、2FA 重试或测活",
                        retryable=False,
                        error_code="free_run_account_result_exists",
                        action_hint="移除已完成账号，或使用已有账号登录、2FA 重试和测活入口",
                    )
                rows = [row for row in registration_rows if row.row_id in requested_row_ids]
                if len(rows) != len(requested_row_ids):
                    raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", "快捷运行所选邮箱中有记录不存在或当前不可用", retryable=False)
                target_count = len(rows)
            else:
                rows = registration_rows[:target_count]
            if not rows:
                if protected_rows and not requested_row_ids:
                    raise FreeRegisterError(
                        "free_run_account_result_exists",
                        "启动 Free 注册",
                        "可用邮箱均已有已保存的 Free 账号结果，不能再次走整条注册流程；请使用已有账号登录、2FA 重试或测活",
                        retryable=False,
                        error_code="free_run_account_result_exists",
                        action_hint="使用已有账号登录、2FA 重试或测活入口，或导入尚未注册的邮箱",
                    )
                raise FreeRegisterError(
                    "free_pool_preflight",
                    "Free 邮箱池预检",
                    "Free 邮箱池没有可用于新注册的邮箱",
                    retryable=False,
                    error_code="free_pool_empty",
                )
            if len(rows) < target_count:
                raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", f"Free 邮箱数量不足：需要 {target_count} 条，当前只有 {len(rows)} 条", retryable=False)
            driver = str(config.get("driver") or "protocol").strip().lower()
            if driver not in {"protocol", "camoufox"}:
                raise FreeRegisterError("free_config", "启动 Free 注册", "Free 注册链路无效", retryable=False)
            if driver == "camoufox" and not self._custom_runner:
                CamoufoxRunner.preflight(config)
            # Import pasted proxies only after mailbox/result guards pass.  A
            # rejected duplicate-registration attempt must not mutate the
            # shared proxy pool or its health history.
            if proxy_content.strip():
                self.proxies.import_text(proxy_content, scheme=str(config.get("proxy_default_scheme") or "socks5"))
            self.proxies.configure_policy(
                failure_threshold=int(config.get("proxy_failure_threshold") or 2),
                quarantine_seconds=int(config.get("proxy_quarantine_seconds") or 600),
                health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
                tls_verify=bool(config.get("proxy_tls_verify", True)),
                tls_compat_fallback=bool(config.get("proxy_tls_compat_fallback", True)),
                socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
                allocation_mode="healthy_random",
            )
            bindings = self.proxies.bind(
                target_count,
                probe=self.proxy_probe,
                probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
                driver=driver,
                perform_probe=False,
                health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
            )
            batch_id = f"free-{int(time.time())}-{secrets.token_hex(4)}"
            self._startup_batch_id = batch_id
            now = int(time.time())
            workers = max(1, min(int(config.get("concurrency") or config.get("free_concurrency") or 3), target_count, 16))
            leased_bindings: list[ProxyBinding] = []
            created_task_ids: list[str] = []
            leased_mailboxes: list[str] = []
            reserved = False
            try:
                self.pool.reserve(rows, batch_id)
                reserved = True
                for ordinal, (row, binding) in enumerate(zip(rows, bindings), 1):
                    task_id = f"{batch_id}-{ordinal}"
                    row_state = self.pool._row_state(row.row_id) if callable(getattr(self.pool, "_row_state", None)) else {}
                    source = str(row_state.get("source") or "url").strip().lower()
                    self._tasks[task_id] = {"task_id": task_id, "ordinal": ordinal, "slot_id": f"{batch_id}-slot-{((ordinal - 1) % workers) + 1}", "slot_index": ((ordinal - 1) % workers) + 1, "concurrency_limit": workers, "status": "queued", "created_at": now, "updated_at": now, "timing": self._timing_record({"created_at": now}), "batch_id": batch_id, "run_mode": "free_register", "driver": driver, "proxy_allocation_mode": str(config.get("proxy_allocation_mode") or "healthy_random"), "email": row.email, "row_id": row.row_id, "mailbox_url": row.mailbox_url, "mailbox_source": source, "service_token": str(row_state.get("service_token") or "") if source == "remail" else "", "proxy": binding.proxy, "proxy_id": binding.proxy_id, "proxy_scheme": binding.scheme, "proxy_effective_scheme": getattr(binding, "effective_scheme", "") or binding.scheme, "proxy_country": binding.country, "proxy_group": binding.group, "proxy_masked": binding.masked, "proxy_fingerprint": binding.fingerprint, "expected_exit_ip": binding.exit_ip, "registration_ip": "", "exit_ip": binding.exit_ip, "proxy_attempts": [], "cleanup_status": "pending", "progress": {"stage": "free_oauth_session", "group": "free", "started_at": now, "updated_at": now, "finished_at": None}, "result": {"twofa_status": "", "driver": driver, "expected_exit_ip": binding.exit_ip, "proxy_country": binding.country, "proxy_group": binding.group}}
                    self._tasks[task_id]["device_id"] = f"free-{secrets.token_hex(16)}"
                    created_task_ids.append(task_id)
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
                        leased_mailboxes.append(task_id)
                    self.proxies.lease(binding, owner=task_id, batch_id=batch_id, task_id=task_id)
                    leased_bindings.append(binding)
                    self.pool.update(row.row_id, status="queued", batch_id=batch_id, driver=driver, proxy=binding.proxy, proxy_masked=binding.masked, proxy_fingerprint=binding.fingerprint, expected_exit_ip=binding.exit_ip, exit_ip=binding.exit_ip, proxy_id=binding.proxy_id, proxy_country=binding.country, proxy_group=binding.group)
                    # Proxy preflight is an internal transport check; do not
                    # expose a successful validation stage in task logs.
                self._save_tasks_safely("启动任务初始状态")
            except Exception:
                if self.mailbox_leases is not None:
                    for task_id in reversed(leased_mailboxes):
                        try:
                            self.mailbox_leases.release(task_id=task_id, reusable=True)
                        except Exception:
                            pass
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
                self._save_tasks_safely("启动失败回滚")
                raise
            self._batch_id = batch_id
            self._circuit_stop_requested = False
            self._user_stop_requested = False
            self._stop.clear()
            # Each batch owns its own event. Reusing one shared Event lets a
            # newly started batch clear the stop signal before an old
            # heartbeat thread has observed it, so the old thread can resume
            # renewing released leases.
            heartbeat_stop = threading.Event()
            self._heartbeat_stop = heartbeat_stop
            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, args=(batch_id, heartbeat_stop), name=f"free-proxy-heartbeat-{batch_id[-8:]}", daemon=True)
            self._heartbeat_thread.start()
            self._executor = PriorityExecutor(max_workers=workers, thread_name_prefix="free-register")
            for task_id in list(self._tasks):
                if self._tasks[task_id].get("batch_id") != batch_id:
                    continue
                self._submit_registered_worker(
                    self._worker,
                    task_id,
                    dict(config),
                    driver=driver,
                    priority=10,
                )
            self._startup_batch_id = ""
            self._log(f"[启动 Free 注册/free_run_start] 已准备 {target_count} 个邮箱，{workers} 并发", "success")
            return {
                "batch_id": batch_id,
                "tasks": self.public_tasks(),
                "state": self.public_state(),
            }

    def _future_done(self, future: Future[Any]) -> None:
        executor: PriorityExecutor | None = None
        completed_batch_id = ""
        heartbeat_thread: threading.Thread | None = None
        heartbeat_stop: threading.Event | None = None
        is_last = False
        with self._lock:
            if future not in self._futures:
                return
            executor = self._executor
            # Remove the completed Future while holding the manager lock so
            # concurrent completion callbacks cannot clean up the same task
            # twice.
            self._futures.discard(future)
            self._future_drivers.pop(future, None)
            is_last = not self._futures
            if is_last:
                self._shutdown_pending = True
                heartbeat_stop = self._heartbeat_stop
                heartbeat_thread = self._heartbeat_thread
                heartbeat_stop.set()
            # Completion callbacks must always continue into Future and
            # executor cleanup even when the task store is temporarily
            # unavailable.
            self._save_tasks_safely("任务完成回调")
        if not is_last:
            return
        # Wait outside the manager lock. Other executor workers may still be
        # unwinding, and the heartbeat can be finishing a diagnostic callback
        # that needs the same lock. Keeping the lock while joining would turn
        # a normal shutdown into a deadlock.
        if executor is not None:
            try:
                executor.shutdown(wait=True, cancel_futures=False)
            except Exception:
                # The worker result and task state are already durable; a
                # best-effort shutdown failure must not strand the manager.
                pass
        if heartbeat_thread is not None and heartbeat_thread is not threading.current_thread():
            try:
                heartbeat_thread.join(timeout=2)
            except Exception:
                pass
        with self._lock:
            if not self._futures and self._executor is executor:
                completed_batch_id = str(self._batch_id or "")
                # Keep the executor reference (and ``running`` state) visible
                # until the final durable checkpoint has completed.  The
                # checkpoint can still emit a structured storage-warning log;
                # publishing ``None`` first lets callers tear down a temporary
                # data directory while that callback is writing ``tasks.json``
                # or ``logs.json``.
                self._save_tasks_safely("批次完成回调")
                # No new batch/retry may enter while ``_shutdown_pending`` is
                # true.  Re-check ownership after the checkpoint so a future
                # lifecycle change cannot clear a replacement executor.
                if not self._futures and self._executor is executor:
                    self._executor = None
                    if self._heartbeat_thread is heartbeat_thread and (
                        heartbeat_thread is None or not heartbeat_thread.is_alive()
                    ):
                        self._heartbeat_thread = None
                    self._shutdown_pending = False
        if completed_batch_id:
            self._release_runtime_owner()
        if completed_batch_id and self._free_notification is not None:
            try:
                with self._lock:
                    batch_tasks = [
                        copy.deepcopy(task)
                        for task in self._tasks.values()
                        if str(task.get("batch_id") or "") == completed_batch_id
                    ]
                self._free_notification.submit(batch_tasks, batch_id=completed_batch_id)
            except Exception:
                # Notification delivery is advisory and must never affect the
                # persisted registration result or retry queue.
                pass

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

    def rerun(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        """Queue a failed account without starting a competing Free batch."""
        normalized = str(task_id or "").strip()
        with self._lock:
            original = copy.deepcopy(self._tasks.get(normalized))
        if not original:
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "没有找到对应的 Free 任务", retryable=False)
        if str(original.get("status") or "") not in {"failed", "stopped", "pending_rerun"}:
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "只有失败或已停止的 Free 任务可以重跑", retryable=False)
        failure = original.get("failure") if isinstance(original.get("failure"), Mapping) else {}
        node_code = str(failure.get("node_code") or original.get("stage") or "free_rerun")
        return self._enqueue_retry(original, config, retry_node=node_code, twofa_retry=False)

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

    def _registration_account_exists(
        self,
        row_id: str,
        *snapshots: Mapping[str, Any] | None,
    ) -> bool:
        """Check durable and historical task snapshots before a new signup."""
        candidates: list[Mapping[str, Any] | None] = list(snapshots)
        reader = getattr(self.pool, "result_with_status", None)
        if callable(reader):
            try:
                durable, readable = reader(str(row_id or ""))
            except Exception as exc:
                raise FreeRegisterError(
                    "free_result_store",
                    "读取 Free 账号结果",
                    "Free 账号结果暂时无法确认，为避免重复注册已停止本次操作",
                    retryable=True,
                    error_code="free_result_read_failed",
                    action_hint="检查 Free 结果文件和数据目录权限后重试",
                    provider_code=type(exc).__name__,
                ) from exc
            if not readable:
                raise FreeRegisterError(
                    "free_result_store",
                    "读取 Free 账号结果",
                    "Free 账号结果暂时无法确认，为避免重复注册已停止本次操作",
                    retryable=True,
                    error_code="free_result_read_failed",
                    action_hint="检查 Free 结果文件和数据目录权限后重试",
                )
        else:
            try:
                durable = self.pool.result(str(row_id or ""))
            except Exception as exc:
                raise FreeRegisterError(
                    "free_result_store",
                    "读取 Free 账号结果",
                    "Free 账号结果暂时无法确认，为避免重复注册已停止本次操作",
                    retryable=True,
                    error_code="free_result_read_failed",
                    action_hint="检查 Free 结果文件和数据目录权限后重试",
                    provider_code=type(exc).__name__,
                ) from exc
        candidates.append(durable if isinstance(durable, Mapping) else None)
        # A previous successful task can outlive a later failure task.  Keep
        # that account evidence even when a legacy result file was truncated.
        for task in self._tasks.values():
            if str(task.get("row_id") or "") != str(row_id or ""):
                continue
            candidates.append(task)
            result = task.get("result")
            candidates.append(result if isinstance(result, Mapping) else None)
        return self._has_existing_account_result(*candidates)

    def _enqueue_retry(
        self,
        original: Mapping[str, Any],
        config: Mapping[str, Any],
        *,
        retry_node: str,
        twofa_retry: bool = False,
        password_retry: bool = False,
    ) -> dict[str, Any]:
        if twofa_retry and password_retry:
            raise FreeRegisterError(
                "free_retry",
                "重试 Free 任务",
                "2FA 重试和密码重试不能同时提交",
                retryable=False,
                error_code="free_retry_modes_conflict",
            )
        continuation = bool(twofa_retry or password_retry)
        row_id = str(original.get("row_id") or "").strip()
        if not row_id:
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "任务没有绑定 Free 邮箱", retryable=False)
        self._ensure_runtime_owner()
        retry_key = f"{row_id}:{retry_node}"
        with self._lock:
            active_id = self._retry_leases.get(retry_key)
            if active_id:
                active = self._tasks.get(active_id)
                if active and str(active.get("status") or "") in {"queued", "running"}:
                    return self._public_task(active)
                self._retry_leases.pop(retry_key, None)
            row_state = self.pool._row_state(row_id)
            pool_status = str(row_state.get("status") or "")
            # Password continuation is a post-registration operation. Read the
            # durable result before touching mailbox/proxy state so a stale
            # task snapshot cannot accidentally replay signup.
            saved_result: dict[str, Any] = {}
            if password_retry:
                stored = self.pool.result(row_id)
                if isinstance(stored, Mapping):
                    saved_result = copy.deepcopy(dict(stored))
                snapshot_result = original.get("result")
                if isinstance(snapshot_result, Mapping):
                    saved_result = merge_account_result_fields(snapshot_result, saved_result)
                if not str(saved_result.get("access_token") or "").strip():
                    raise FreeRegisterError(
                        "free_password_retry",
                        "重试 Free 账号密码设置",
                        "原账号没有可用 access token",
                        retryable=False,
                        error_code="free_password_retry_token_missing",
                    )
                if not password_retry_allowed(saved_result):
                    raise FreeRegisterError(
                        "free_password_retry",
                        "重试 Free 账号密码设置",
                        "该账号当前没有可补设的密码状态",
                        retryable=False,
                        error_code="free_password_retry_not_pending",
                    )
            # This must run before changing a pending row back to available or
            # reserving it again.  Two-factor retries are continuations of an
            # existing account and intentionally bypass this registration guard.
            if not continuation and self._registration_account_exists(row_id, original):
                raise FreeRegisterError(
                    "free_rerun",
                    "重跑 Free 账号",
                    "该邮箱已有已保存的 Free 账号结果，不能再次走整条注册流程；请使用 2FA 重试、已有账号登录或测活",
                    retryable=False,
                    error_code="free_rerun_account_result_exists",
                    action_hint="使用“重试 2FA”、已有账号登录或测活；不要重复提交注册邮箱",
                )
            if not continuation:
                if pool_status == "pending_rerun":
                    self.pool.update(row_id, status="available", batch_id="", stage="", error="", reusable_after_failure=False)
                    pool_status = "available"
                if pool_status != "available" or self.pool.entry(row_id) is None:
                    raise FreeRegisterError("free_rerun", "重跑 Free 账号", "该账号当前不可重跑，请先在 Free 邮箱中心恢复为可用", retryable=False, error_code="free_rerun_mailbox_unavailable")
            elif twofa_retry:
                if pool_status not in {"twofa_pending", "available", "pending_rerun"}:
                    raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该账号当前没有可重试的 2FA 状态", retryable=False)
            else:
                # A password continuation may follow a partial 2FA result or a
                # legacy pending-rerun row. It must never require the mailbox to
                # be reset to ``available`` and must reject an active task.
                if pool_status in {"queued", "running", "reserved"}:
                    raise FreeRegisterError(
                        "free_password_retry",
                        "重试 Free 账号密码设置",
                        "该账号当前已有续跑任务",
                        retryable=False,
                        error_code="free_password_retry_active",
                    )

            active_batch = bool(
                self._executor
                or self._shutdown_pending
                or (
                    self._heartbeat_thread is not None
                    and self._heartbeat_thread.is_alive()
                )
            )
            if active_batch and (self._executor is None or not self._futures):
                # The final callback has begun executor shutdown. Its queue
                # already contains sentinels, so a continuation cannot be
                # submitted safely until the batch is fully drained.
                raise FreeRegisterError(
                    "free_retry",
                    "重试 Free 任务",
                    "Free 批次正在收尾，请稍后重试",
                    retryable=True,
                    error_code="free_batch_shutdown_pending",
                )
            batch_id = str(self._batch_id or "") if active_batch else f"free-retry-{int(time.time())}-{secrets.token_hex(4)}"
            driver = str(original.get("driver") or config.get("driver") or "protocol").strip().lower()
            if driver not in {"protocol", "camoufox"}:
                raise FreeRegisterError("free_rerun", "重跑 Free 账号", "Free 注册链路无效", retryable=False)
            mailbox = self.pool.entry(row_id)
            if mailbox is None:
                raise FreeRegisterError("free_rerun", "重跑 Free 账号", "Free 邮箱记录不存在", retryable=False)
            reserved = False
            mailbox_lease_acquired = False
            if not continuation:
                self.pool.reserve([mailbox], batch_id)
                reserved = True
            proxy_content = ""
            binding: ProxyBinding | None = None
            retry_id = ""
            submitted = False
            # ``active_batch`` is false when this retry must create its own
            # heartbeat/executor.  Track that intent before starting either so
            # a constructor/thread-start failure can still unwind cleanly.
            created_executor = not active_batch
            previous_batch_id = self._batch_id
            previous_last_config = copy.deepcopy(self._last_config)
            try:
                # Retry tasks may be created without passing through
                # ``start``/``preflight``.  Apply the same transport policy
                # before binding so a production ``remote`` SOCKS5 DNS mode
                # is not accidentally downgraded to local resolution.
                self.proxies.configure_policy(
                    failure_threshold=int(config.get("proxy_failure_threshold") or 2),
                    quarantine_seconds=int(config.get("proxy_quarantine_seconds") or 600),
                    health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
                    tls_verify=bool(config.get("proxy_tls_verify", True)),
                    tls_compat_fallback=bool(config.get("proxy_tls_compat_fallback", True)),
                    socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
                    allocation_mode="healthy_random",
                )
                # Keep a password continuation on the proxy that created the
                # account whenever its durable identity is still present. This
                # avoids changing the authenticated network context and also
                # avoids treating a post-registration retry as a new signup.
                original_proxy = str(
                    original.get("proxy") or row_state.get("proxy") or ""
                ).strip()
                original_proxy_id = str(
                    original.get("proxy_id") or row_state.get("proxy_id") or ""
                ).strip()
                original_proxy_available = False
                matched_proxy_record: Mapping[str, Any] | None = None
                if password_retry and (original_proxy or original_proxy_id):
                    try:
                        records = self.proxies._load()  # type: ignore[attr-defined]
                    except Exception:
                        records = []
                    for record in records if isinstance(records, list) else []:
                        if not isinstance(record, Mapping):
                            continue
                        configured = str(record.get("_normalized") or "").strip()
                        record_id = str(record.get("proxy_id") or "").strip()
                        if (original_proxy_id and record_id == original_proxy_id) or (original_proxy and configured == original_proxy):
                            original_proxy_available = True
                            matched_proxy_record = record
                            # Older task snapshots persisted the address but
                            # not the pool identity. Recover the authoritative
                            # ID so lease/release and health bookkeeping target
                            # the same row.
                            if not original_proxy_id:
                                original_proxy_id = record_id
                            if not original_proxy:
                                original_proxy = configured
                            break
                if password_retry and original_proxy and original_proxy_available:
                    record = matched_proxy_record or {}
                    record_scheme = str(record.get("scheme") or "").strip().lower()
                    record_effective_scheme = str(
                        record.get("effective_scheme") or record_scheme
                    ).strip().lower()
                    binding = ProxyBinding(
                        original_proxy,
                        str(original.get("proxy_fingerprint") or original_proxy_id or _fingerprint(original_proxy)),
                        str(original.get("proxy_masked") or record.get("masked") or _mask_proxy(original_proxy)),
                        str(original.get("expected_exit_ip") or original.get("exit_ip") or row_state.get("exit_ip") or ""),
                        proxy_id=original_proxy_id,
                        scheme=str(original.get("proxy_scheme") or row_state.get("proxy_scheme") or record_scheme),
                        country=str(original.get("proxy_country") or row_state.get("proxy_country") or record.get("country") or ""),
                        group=str(original.get("proxy_group") or row_state.get("proxy_group") or record.get("group") or ""),
                        effective_scheme=str(original.get("proxy_effective_scheme") or original.get("proxy_scheme") or row_state.get("proxy_scheme") or record_effective_scheme),
                    )
                else:
                    bindings = self.proxies.bind(
                        1,
                        content=proxy_content,
                        probe=self.proxy_probe,
                        probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
                        driver=driver,
                        perform_probe=False,
                        health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
                    )
                    if not bindings:
                        raise FreeRegisterError("free_proxy_binding", "绑定 Free 代理", "当前没有可用健康代理", retryable=True)
                    binding = bindings[0]
                now = int(time.time())
                retry_id = f"{batch_id}-{secrets.token_hex(3)}"
                if not continuation and self.mailbox_leases is not None:
                    lease = self.mailbox_leases.acquire(
                        row_id,
                        task_id=retry_id,
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
                workers = max(1, min(int(config.get("concurrency") or self._last_config.get("concurrency") or 3), 16))
                # A task snapshot may intentionally expose only capability
                # flags after restart, while the private result file still
                # contains the account password needed for an existing-login
                # or 2FA retry.  Merge the durable result as a fill-only
                # fallback; never copy secrets into the public task shape.
                original_result = (
                    dict(original.get("result") or {})
                    if isinstance(original.get("result"), Mapping) else {}
                )
                saved_result = self.pool.result(row_id)
                merged_result = merge_account_result_fields(
                    original_result,
                    saved_result if isinstance(saved_result, Mapping) else {},
                )
                if password_retry:
                    # The durable continuation marker is authoritative; a
                    # stale task snapshot must not turn a pending password into
                    # an already-enabled result.
                    merged_result["password_status"] = "pending"
                task = {
                    "task_id": retry_id,
                    "ordinal": int(original.get("ordinal") or 1),
                    "slot_id": f"{batch_id}-retry",
                    "slot_index": 0,
                    "concurrency_limit": workers,
                    "status": "queued",
                    "created_at": now,
                    "updated_at": now,
                    "timing": self._timing_record({"created_at": now}),
                    "batch_id": batch_id,
                    "run_mode": "free_register",
                    "driver": driver,
                    "email": mailbox.email,
                    "row_id": row_id,
                    "mailbox_url": mailbox.mailbox_url,
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
                    "retry_of": str(original.get("task_id") or ""),
                    "retry_attempt": int(original.get("retry_attempt") or 0) + 1,
                    "retry_node_code": retry_node,
                    "retry_key": retry_key,
                    "manual_generation": 0,
                    "progress": {"stage": "free_twofa_enroll" if twofa_retry else "free_password_eligibility" if password_retry else "free_oauth_session", "group": "free", "started_at": now, "updated_at": now, "finished_at": None},
                    "result": merged_result or saved_result or {"twofa_status": ""},
                    "retry_mode": "password" if password_retry else "twofa" if twofa_retry else "registration",
                }
                self._tasks[retry_id] = task
                self._retry_leases[retry_key] = retry_id
                self.proxies.lease(binding, owner=retry_id, batch_id=batch_id, task_id=retry_id)
                self.pool.update(row_id, status="queued", batch_id=batch_id, stage=retry_node, driver=driver, proxy=binding.proxy, proxy_masked=binding.masked, proxy_fingerprint=binding.fingerprint, expected_exit_ip=binding.exit_ip, exit_ip=binding.exit_ip, proxy_id=binding.proxy_id, proxy_country=binding.country, proxy_group=binding.group)
                retry_config = dict(config)
                retry_config.setdefault("auto_set_password", False)
                retry_config.setdefault("auto_set_2fa", True)
                # Make the retry durable before a worker can complete.  This
                # is especially important for custom runners that return
                # synchronously from submit().
                self._save_tasks_safely("重试任务初始状态")
                if not active_batch:
                    self._last_config = copy.deepcopy(retry_config)
                    self._batch_id = batch_id
                    self._stop.clear()
                    self._user_stop_requested = False
                    heartbeat_stop = threading.Event()
                    self._heartbeat_stop = heartbeat_stop
                    self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, args=(batch_id, heartbeat_stop), name=f"free-proxy-heartbeat-{batch_id[-8:]}", daemon=True)
                    self._heartbeat_thread.start()
                    self._executor = PriorityExecutor(max_workers=workers, thread_name_prefix="free-retry")
                self._submit_registered_worker(
                    self._worker,
                    retry_id,
                    retry_config,
                    twofa_retry,
                    password_retry,
                    driver=driver,
                    priority=0,
                )
                submitted = True
                self._save_tasks_safely("重试任务提交后")
                self._log(f"[{retry_id}/Free 重试/{retry_node}] 已排队（第 {task['retry_attempt']} 次）", "info", task_id=retry_id, retry_of=task["retry_of"], retry_node_code=retry_node)
                return self._public_task(task)
            except Exception:
                # After submit the worker owns the task and lease.  Keep the
                # persisted state intact if a later callback/save fails.
                if submitted:
                    raise
                self._tasks.pop(retry_id, None)
                if mailbox_lease_acquired and self.mailbox_leases is not None:
                    try:
                        self.mailbox_leases.release(task_id=retry_id, reusable=True)
                    except Exception:
                        pass
                if binding is not None:
                    try:
                        self.proxies.release(binding, owner=retry_id or batch_id)
                    except Exception:
                        pass
                self._retry_leases.pop(retry_key, None)
                if reserved:
                    try:
                        self.pool.update(row_id, status="available", batch_id="", stage="", driver="", proxy="", proxy_masked="", proxy_fingerprint="", expected_exit_ip="", exit_ip="", proxy_id="", proxy_country="", proxy_group="")
                    except Exception:
                        pass
                if created_executor and not self._futures:
                    try:
                        self._heartbeat_stop.set()
                        if self._heartbeat_thread is not None and self._heartbeat_thread is not threading.current_thread():
                            self._heartbeat_thread.join(timeout=1)
                    except Exception:
                        pass
                    if self._executor is not None:
                        try:
                            # No worker was submitted on this rollback path;
                            # wait for the idle executor threads so a caller
                            # can safely tear down a temporary data directory
                            # immediately after the exception.
                            self._executor.shutdown(wait=True, cancel_futures=True)
                        except Exception:
                            pass
                    self._executor = None
                    self._heartbeat_thread = None
                    self._batch_id = previous_batch_id
                    self._last_config = previous_last_config
                self._save_tasks_safely("重试任务回滚")
                if created_executor and not self._futures:
                    self._release_runtime_owner()
                raise

    def retry_twofa(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        normalized = str(task_id or "").strip()
        with self._lock:
            task = copy.deepcopy(self._tasks.get(normalized))
        if task is None:
            row = self.pool.entry(normalized)
            saved = self.pool.result(normalized) if row is not None else {}
            if row is None or saved.get("twofa_status") != "pending":
                raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该任务当前没有待重试的 2FA", retryable=False)
            row_state = self.pool._row_state(row.row_id)
            source = str(row_state.get("source") or "url").strip().lower()
            task = {"task_id": normalized, "row_id": row.row_id, "email": row.email, "mailbox_url": row.mailbox_url, "mailbox_source": source, "service_token": str(row_state.get("service_token") or "") if source == "remail" else "", "result": saved, "driver": saved.get("driver") or "protocol", "status": "twofa_pending"}
        if str(task.get("status") or "") != "twofa_pending":
            raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该任务当前没有待重试的 2FA", retryable=False)
        return self._enqueue_retry(task, config, retry_node="free_twofa_activate", twofa_retry=True)

    def retry_password(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        """Queue only the pending post-registration password operation.

        The continuation is deliberately keyed off the durable result rather
        than the task's public status. A process restart or a later 2FA failure
        can change that status while the account Token and pending password
        marker remain valid.
        """
        normalized = str(task_id or "").strip()
        with self._lock:
            task = copy.deepcopy(self._tasks.get(normalized))
        if task is None:
            row = self.pool.entry(normalized)
            saved = self.pool.result(normalized) if row is not None else {}
            if row is None or not isinstance(saved, Mapping):
                raise FreeRegisterError(
                    "free_password_retry", "重试 Free 账号密码设置",
                    "没有找到对应的 Free 任务", retryable=False,
                )
            task = {
                "task_id": normalized,
                "row_id": row.row_id,
                "email": row.email,
                "mailbox_url": row.mailbox_url,
                "result": dict(saved),
                "driver": saved.get("driver") or "protocol",
                "status": str(saved.get("status") or "partial_success"),
                "proxy": "",
            }
        result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
        durable = self.pool.result(str(task.get("row_id") or normalized))
        merged = merge_account_result_fields(result, durable if isinstance(durable, Mapping) else {})
        if not str(merged.get("access_token") or "").strip():
            raise FreeRegisterError(
                "free_password_retry", "重试 Free 账号密码设置",
                "原账号没有可用 access token", retryable=False,
                error_code="free_password_retry_token_missing",
            )
        if not password_retry_allowed(merged):
            raise FreeRegisterError(
                "free_password_retry", "重试 Free 账号密码设置",
                "该账号当前没有可补设的密码状态", retryable=False,
                error_code="free_password_retry_not_pending",
            )
        task["result"] = merged
        status = str(task.get("status") or "")
        if status in {"queued", "running"}:
            raise FreeRegisterError(
                "free_password_retry", "重试 Free 账号密码设置",
                "该账号当前已有运行中的任务", retryable=False,
                error_code="free_password_retry_active",
            )
        # Historical failed/pending-rerun snapshots are valid continuation
        # sources as long as the durable account evidence above is present.
        return self._enqueue_retry(
            task,
            config,
            retry_node="free_password_enroll",
            password_retry=True,
        )

    def batch_retry(self, task_ids: Sequence[str], config: Mapping[str, Any]) -> dict[str, Any]:
        """Queue selected failed/2FA tasks independently and report each result."""
        selected = list(dict.fromkeys(str(value or "").strip() for value in task_ids if str(value or "").strip()))
        accepted: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for task_id in selected[:200]:
            try:
                with self._lock:
                    task = copy.deepcopy(self._tasks.get(task_id))
                if task is None:
                    rejected.append({"task_id": task_id, "reason": "任务不存在"})
                    continue
                status = str(task.get("status") or "")
                failure = task.get("failure") if isinstance(task.get("failure"), Mapping) else {}
                result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
                if (
                    password_retry_allowed(result)
                    and status in {"success", "partial_success", "twofa_pending", "failed", "pending_rerun"}
                ):
                    queued = self.retry_password(task_id, config)
                elif failure and self._batch_retry_blocked(failure):
                    skipped.append({"task_id": task_id, "reason": "当前失败节点不可自动重试，请按诊断建议处理"})
                    continue
                elif status == "twofa_pending":
                    queued = self.retry_twofa(task_id, config)
                elif status in {"failed", "stopped", "pending_rerun"}:
                    queued = self.rerun(task_id, config)
                else:
                    skipped.append({"task_id": task_id, "reason": "当前状态不可重试"})
                    continue
                accepted.append({"task_id": task_id, "retry_task": queued})
            except Exception as exc:
                rejected.append({"task_id": task_id, "reason": _safe_log_message(exc)[:240]})
        if len(selected) > 200:
            rejected.extend({"task_id": task_id, "reason": "单次最多重试 200 条"} for task_id in selected[200:])
        return {
            "accepted": accepted,
            "accepted_count": len(accepted),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "rejected": rejected,
            "rejected_count": len(rejected),
        }

    @staticmethod
    def _batch_retry_blocked(failure: Mapping[str, Any]) -> bool:
        """Keep known business/security failures out of bulk replay."""
        if failure.get("retryable") is False:
            return True
        try:
            status = int(failure.get("http_status") or 0)
        except (TypeError, ValueError):
            status = 0
        if status in {400, 401, 403, 409, 422, 429}:
            return True
        text = " ".join(
            str(failure.get(key) or "").lower()
            for key in ("node_code", "error_code", "provider_code", "public_message", "technical_summary")
        )
        return any(marker in text for marker in (
            "challenge", "captcha", "security", "account_disabled", "account_banned",
            "suspended", "invalid_totp", "invalid code", "rate_limit", "429",
        ))

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
                            current.setdefault("proxy_attempts", []).append({"proxy_id": failed_proxy_id, "stage": exc.node_code, "retryable": True, "message": _safe_log_message(exc), "http_status": getattr(exc, "provider_status", None), "attempt": attempt, "switched": switched, "at": int(time.time())})
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
