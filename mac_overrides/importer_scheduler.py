"""Target-aware task scheduling for the recovered importer."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import threading
import time
from typing import Any, Callable
import uuid


_MAX_WORKER_CAPACITY = 12
_QUEUE_NODE = "[排队等待/queue_waiting]"


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _is_relogin(settings: dict[str, Any]) -> bool:
    return str(settings.get("run_mode") or "").strip().lower() == "relogin"


def _is_sha256_row_id(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


class ObservedPhaseGate:
    """Record phase-gate waits without changing the recovered gate contract."""

    def __init__(
        self,
        gate: Any,
        on_wait: Callable[[float], Any] | None = None,
        *,
        now_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self.gate = gate
        self.on_wait = on_wait
        self.now_fn = now_fn

    def acquire(self, stop_event: Any) -> None:
        started = float(self.now_fn())
        try:
            self.gate.acquire(stop_event)
        finally:
            if callable(self.on_wait):
                try:
                    self.on_wait(max(0.0, float(self.now_fn()) - started))
                except Exception:
                    pass

    def release(self) -> None:
        self.gate.release()

    def status(self) -> dict[str, int]:
        return self.gate.status()


def _selected_run_target(
    settings: dict[str, Any],
    mailbox_error_type: type[Exception],
) -> int | None:
    bindings = settings.get("_gptphone_run_mailbox_rows")
    if not bindings:
        return None
    if not isinstance(bindings, Sequence) or isinstance(bindings, (str, bytes)):
        raise mailbox_error_type("本次运行的邮箱行绑定参数无效")

    selected: set[tuple[str, int]] = set()
    for binding in bindings:
        if not isinstance(binding, Mapping):
            raise mailbox_error_type("本次运行的邮箱行绑定参数无效")
        row_id = str(binding.get("row_id") or "").strip().lower()
        try:
            line_no = int(binding.get("line_no") or 0)
        except (TypeError, ValueError):
            line_no = 0
        if not _is_sha256_row_id(row_id) or line_no <= 0:
            raise mailbox_error_type("本次运行的邮箱行绑定参数无效")
        selected.add((row_id, line_no))
    return len(selected)


def _relogin_entries(
    pool: Any,
    settings: dict[str, Any],
    mailbox_error_type: type[Exception],
) -> list[Any]:
    bindings = settings.get("_gptphone_relogin_rows")
    if not isinstance(bindings, list) or not bindings:
        raise mailbox_error_type("重登邮箱绑定为空，请刷新邮箱列表后重试")
    try:
        entries, _errors = pool._entries_unlocked()
    except Exception as exc:
        raise mailbox_error_type("重登邮箱解析失败，请检查邮箱池格式") from exc

    by_row_id = {
        hashlib.sha256(str(getattr(entry, "source_row", "") or "").encode("utf-8")).hexdigest(): entry
        for entry in entries
        if str(getattr(entry, "source_row", "") or "")
    }
    selected: list[Any] = []
    seen_keys: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            raise mailbox_error_type("重登邮箱绑定无效，请刷新邮箱列表后重试")
        row_id = str(binding.get("row_id") or "").strip().lower()
        expected_email = str(binding.get("email") or "").strip().lower()
        entry = by_row_id.get(row_id)
        actual_email = str(getattr(entry, "email", "") or "").strip().lower()
        entry_key = str(getattr(entry, "key", "") or "").strip()
        if (
            entry is None
            or not expected_email
            or not hmac.compare_digest(actual_email, expected_email)
            or not entry_key
            or entry_key in seen_keys
        ):
            raise mailbox_error_type("邮箱列表已变化，请刷新后重试")
        seen_keys.add(entry_key)
        selected.append(entry)
    return selected


def start_bounded_importer(
    importer: Any,
    settings: dict[str, Any],
    *,
    mailbox_error_type: type[Exception],
    manual_code_factory: Callable[[], Any],
    phase_gate_factory: Callable[[int], Any],
    executor_factory: Callable[..., Any] = ThreadPoolExecutor,
    thread_factory: Callable[..., Any] = threading.Thread,
    task_admission: Any = None,
    email_phase_gate_factory: Callable[[int], Any] | None = None,
    node_phase_gate_factory: Callable[[int], Any] | None = None,
    on_task_started: Callable[[str, float], Any] | None = None,
) -> None:
    """Start only the requested number of reserved pool entries."""
    relogin = _is_relogin(settings)
    if relogin:
        validation_settings = dict(settings)
        validation_settings.update(
            sms_provider="localpool",
            sms_api_key="relogin-disabled",
        )
        importer.settings_validation(validation_settings, remote=False)
    else:
        importer.settings_validation(settings, remote=True)
    pool = importer._pool(settings)
    selected_target = _selected_run_target(settings, mailbox_error_type)
    relogin_entries = _relogin_entries(pool, settings, mailbox_error_type) if relogin else []
    pool_summary = pool.summary()
    available = len(relogin_entries) if relogin else int(pool_summary.get("available") or 0)
    if selected_target is not None and not relogin:
        selected_total = int(pool_summary.get("total") or 0)
        if selected_total != selected_target or available != selected_target:
            raise mailbox_error_type("所选邮箱已变化、缺失或不可用，请刷新邮箱列表后重试")
    if available <= 0:
        raise mailbox_error_type("没有可运行的邮箱")

    requested = (
        selected_target
        if selected_target is not None
        else _bounded_int(settings.get("target_count"), 1, 1, available)
    )
    target = min(available, requested)
    concurrency = _bounded_int(settings.get("concurrency"), 5, 1, 8)
    worker_count = min(target, concurrency)
    worker_capacity = worker_count
    if task_admission is not None:
        try:
            worker_capacity = min(
                target,
                _MAX_WORKER_CAPACITY,
                max(worker_count, int(task_admission.snapshot().get("ceiling") or worker_count)),
            )
        except Exception:
            worker_capacity = worker_count
    email_login_concurrency = _bounded_int(
        settings.get("auto_email_login_concurrency"),
        min(5, worker_count),
        1,
        worker_count,
    )
    node_concurrency = _bounded_int(
        settings.get("node_concurrency"),
        min(3, worker_count),
        1,
        worker_count,
    )
    reserved: list[tuple[str, int, Any, bool]] = []
    executor = None
    futures: list[Any] = []
    admission_tracks_pending = False
    startup_gate = threading.Event()
    startup_ready = threading.Event()
    batch_id = str(settings.get("batch_id") or "").strip()
    batch_started_at = _bounded_int(settings.get("batch_started_at"), 0, 0, 4_102_444_800)

    def finish_before_admission(
        entry: Any,
        task_id: str,
        *,
        stopped: bool,
        cause: Exception | None = None,
    ) -> None:
        restore_error = ""
        if not relogin:
            try:
                restored = bool(pool.restore_entry(entry, reason="stopped_before_start"))
                if not restored:
                    restore_error = "邮箱池未确认归还"
            except Exception as exc:
                restore_error = f"邮箱归还失败（{type(exc).__name__}）"

        if cause is not None:
            error = f"{_QUEUE_NODE} 任务准入失败（{type(cause).__name__}）"
            if restore_error:
                error = f"{error}；{restore_error}"
            elif not relogin:
                error = f"{error}；邮箱已归还"
            status = "failed"
        elif restore_error:
            error = f"{_QUEUE_NODE} 停止清理失败：{restore_error}"
            status = "failed"
        else:
            error = "未启动，已停止"
            status = "stopped"

        try:
            values = {"status": status, "error": error}
            if status == "failed":
                values["technical_error"] = error
            importer._task_state(task_id, **values)
        except Exception as exc:
            try:
                importer._log(
                    f"{task_id} {_QUEUE_NODE} 任务终态写入失败（{type(exc).__name__}）",
                    "error",
                )
            except Exception:
                pass

        if restore_error:
            try:
                importer._log(f"{task_id} {error}", "error")
            except Exception:
                pass
        if stopped:
            with importer.lock:
                importer.cancelled_waiting += 1

    def run_after_start(
        task_settings: dict[str, Any],
        ordinal: int,
        entry: Any,
        task_id: str,
        queued_at: float,
    ) -> None:
        startup_gate.wait()
        if not startup_ready.is_set():
            return
        if task_admission is None:
            importer._run_one(task_settings, ordinal, entry, task_id)
            return

        wait_seconds = 0.0

        def observed_wait(value: float) -> None:
            nonlocal wait_seconds
            wait_seconds = max(0.0, float(value))

        business_started = False
        try:
            acquire_options = {
                "stop_event": importer.stop_event,
                "on_wait": observed_wait,
                "queued_at": queued_at,
            }
            if admission_tracks_pending:
                acquire_options["registered_pending"] = True
            with task_admission.acquire(
                **acquire_options,
            ):
                if callable(on_task_started):
                    try:
                        on_task_started(task_id, wait_seconds)
                    except Exception:
                        pass
                business_started = True
                importer._run_one(task_settings, ordinal, entry, task_id)
        except Exception as exc:
            if business_started:
                raise
            if isinstance(exc, RuntimeError) and str(exc) == "task_stopped":
                finish_before_admission(entry, task_id, stopped=True)
                return
            finish_before_admission(entry, task_id, stopped=False, cause=exc)
            raise RuntimeError(
                f"{_QUEUE_NODE} 任务准入失败（{type(exc).__name__}）"
            ) from exc

    with importer.lock:
        if importer.running:
            raise RuntimeError("已有导入任务正在运行")
        importer.stop_event.clear()
        importer.manual_codes = manual_code_factory()
        email_factory = email_phase_gate_factory or phase_gate_factory
        node_factory = node_phase_gate_factory or phase_gate_factory
        importer.auto_email_phase_gate = email_factory(email_login_concurrency)
        importer.node_gate = node_factory(node_concurrency)
        importer.task_concurrency = worker_count
        importer.task_admission = task_admission
        importer.running = True
        importer.tasks = {}
        importer.cancelled_waiting = 0
        importer.futures = []
        importer.future_assignments = {}
        importer.active_task_ids = set()
        importer._gptphone_preselected_task_ids = set()

        try:
            for index in range(target):
                entry = relogin_entries[index] if relogin else pool.lease(lease_seconds=3600)
                ordinal = index + 1
                task_id = f"T{ordinal:03d}-{uuid.uuid4().hex[:6]}"
                reserved.append((task_id, ordinal, entry, not relogin))
                if relogin:
                    importer._gptphone_preselected_task_ids.add(task_id)
                importer._task_state(
                    task_id,
                    status="queued",
                    email=entry.email,
                    account=importer._account_label(entry),
                    source_row=importer._source_row(entry),
                    ordinal=ordinal,
                    batch_id=batch_id,
                    batch_started_at=batch_started_at,
                    run_mode="relogin" if relogin else "register",
                )

            register_pending = getattr(task_admission, "register_pending", None)
            if callable(register_pending):
                register_pending(target)
                admission_tracks_pending = True

            executor = executor_factory(
                max_workers=worker_capacity,
                thread_name_prefix="email-auth-import",
            )
            importer.executor = executor
            for task_id, ordinal, entry, _restore_on_cancel in reserved:
                try:
                    queued_at = float(task_admission.now_fn()) if task_admission is not None else time.monotonic()
                except Exception:
                    queued_at = time.monotonic()
                future = executor.submit(
                    run_after_start,
                    copy.deepcopy(settings),
                    ordinal,
                    entry,
                    task_id,
                    queued_at,
                )
                futures.append(future)
                importer.future_assignments[future] = (pool, entry, task_id)
            importer.futures = futures
            watcher = thread_factory(
                target=importer._watch,
                name="email-auth-watch",
                daemon=True,
            )
            watcher.start()
            startup_ready.set()
            startup_gate.set()
        except Exception:
            importer.stop_event.set()
            startup_gate.set()
            cleanup_failures = 0
            for future in futures:
                try:
                    was_cancelled = future.cancel()
                except Exception:
                    cleanup_failures += 1
                else:
                    if was_cancelled and admission_tracks_pending:
                        try:
                            task_admission.discard_pending()
                        except Exception:
                            cleanup_failures += 1
            if executor is not None:
                try:
                    executor.shutdown(wait=True, cancel_futures=True)
                except Exception:
                    cleanup_failures += 1
            if admission_tracks_pending:
                try:
                    task_admission.clear_pending()
                except Exception:
                    cleanup_failures += 1
            cleanup_diagnostics: list[str] = []
            for task_id, _ordinal, entry, restore_on_cancel in reserved:
                if not restore_on_cancel:
                    continue
                try:
                    restored = bool(pool.restore_entry(entry, reason="batch_start_failed"))
                    if not restored:
                        cleanup_failures += 1
                        cleanup_diagnostics.append(
                            f"{task_id} {_QUEUE_NODE} 启动失败清理失败：邮箱池未确认归还"
                        )
                except Exception as exc:
                    cleanup_failures += 1
                    cleanup_diagnostics.append(
                        f"{task_id} {_QUEUE_NODE} 启动失败清理失败："
                        f"邮箱归还失败（{type(exc).__name__}）"
                    )
            for diagnostic in cleanup_diagnostics:
                try:
                    importer._log(diagnostic, "error")
                except Exception:
                    pass
            try:
                if cleanup_failures:
                    importer._log(f"启动失败清理有 {cleanup_failures} 项未完成", "error")
            except Exception:
                pass
            finally:
                importer.executor = None
                importer.futures = []
                importer.future_assignments = {}
                importer._gptphone_preselected_task_ids = set()
                importer.tasks = {}
                importer.running = False
            raise

    try:
        if relogin:
            message = (
                f"无手机号重登启动: 目标邮箱 {target}/{available}，实际任务并发 {worker_count}，"
                f"Node 并发 {node_concurrency}，邮箱验证码槽 {email_login_concurrency}；"
                "仅更新原 SUB2 账号，跳过 SMS 预检和号码申请"
            )
        else:
            message = (
                f"导入任务启动: 目标邮箱 {target}/{available}，基础任务并发 {worker_count}，"
                f"健康上限 {worker_capacity}，"
                f"Node 并发 {node_concurrency}，邮箱验证码槽 {email_login_concurrency}；"
                "仅预留本批目标邮箱，验证码通过后立即释放，号码/SUB2 保持并发"
            )
        importer._log(message, "success")
    except Exception:
        pass


def stop_bounded_importer(importer: Any) -> None:
    """Stop pending work without racing the recovered watcher assignment cleanup."""
    importer.stop_event.set()
    task_admission = getattr(importer, "task_admission", None)
    if task_admission is not None:
        try:
            task_admission.wake_all()
        except Exception:
            pass
    cleanup_failures = 0
    try:
        importer.manual_codes.cancel_all()
    except Exception:
        cleanup_failures += 1
    with importer.lock:
        futures = list(importer.futures)
        executor = importer.executor
        preselected_task_ids = set(getattr(importer, "_gptphone_preselected_task_ids", set()))
        assignments = {
            future: importer.future_assignments.pop(future, None)
            for future in futures
        }

    cancelled = 0
    for future in futures:
        try:
            was_cancelled = future.cancel()
        except Exception:
            cleanup_failures += 1
            continue
        if not was_cancelled:
            continue
        if task_admission is not None:
            discard_pending = getattr(task_admission, "discard_pending", None)
            if callable(discard_pending):
                try:
                    discard_pending()
                except Exception:
                    cleanup_failures += 1
        assignment = assignments.get(future)
        if assignment is None:
            continue
        pool, entry, task_id = assignment
        restore_error = ""
        if task_id not in preselected_task_ids:
            try:
                restored = bool(pool.restore_entry(entry, reason="stopped_before_start"))
                if not restored:
                    restore_error = "邮箱池未确认归还"
            except Exception as exc:
                restore_error = f"邮箱归还失败（{type(exc).__name__}）"
            if restore_error:
                cleanup_failures += 1
        try:
            if restore_error:
                error = f"{_QUEUE_NODE} 停止清理失败：{restore_error}"
                importer._task_state(
                    task_id,
                    status="failed",
                    error=error,
                    technical_error=error,
                )
            else:
                importer._task_state(task_id, status="stopped", error="未启动，已停止")
        except Exception:
            cleanup_failures += 1
        cancelled += 1

    with importer.lock:
        importer.cancelled_waiting += cancelled
    if executor is not None:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            cleanup_failures += 1
    try:
        importer._log(
            f"已停止：取消 {cancelled} 个等待任务，正在运行任务已请求中断并执行邮箱清理",
            "warn",
        )
        if cleanup_failures:
            importer._log(f"停止清理有 {cleanup_failures} 项未完成", "error")
    except Exception:
        pass


__all__ = [
    "ObservedPhaseGate",
    "start_bounded_importer",
    "stop_bounded_importer",
]
