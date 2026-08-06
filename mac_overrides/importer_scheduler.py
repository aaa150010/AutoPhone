"""Target-aware task scheduling for the recovered importer."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import threading
from typing import Any, Callable
import uuid


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _is_relogin(settings: dict[str, Any]) -> bool:
    return str(settings.get("run_mode") or "").strip().lower() == "relogin"


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
        if not row_id or line_no <= 0 or len(row_id) > 128:
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
    relogin_entries = _relogin_entries(pool, settings, mailbox_error_type) if relogin else []
    pool_summary = pool.summary()
    available = len(relogin_entries) if relogin else int(pool_summary.get("available") or 0)
    if available <= 0:
        raise mailbox_error_type("没有可运行的邮箱")

    selected_target = _selected_run_target(settings, mailbox_error_type)
    requested = (
        selected_target
        if selected_target is not None
        else _bounded_int(settings.get("target_count"), 1, 1, available)
    )
    target = min(available, requested)
    concurrency = _bounded_int(settings.get("concurrency"), 1, 1, 100)
    worker_count = min(target, concurrency)
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
    startup_gate = threading.Event()
    startup_ready = threading.Event()
    batch_id = str(settings.get("batch_id") or "").strip()
    batch_started_at = _bounded_int(settings.get("batch_started_at"), 0, 0, 4_102_444_800)

    def run_after_start(*args: Any) -> None:
        startup_gate.wait()
        if startup_ready.is_set():
            importer._run_one(*args)

    with importer.lock:
        if importer.running:
            raise RuntimeError("已有导入任务正在运行")
        importer.stop_event.clear()
        importer.manual_codes = manual_code_factory()
        importer.auto_email_phase_gate = phase_gate_factory(email_login_concurrency)
        importer.node_gate = phase_gate_factory(node_concurrency)
        importer.task_concurrency = worker_count
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

            executor = executor_factory(
                max_workers=worker_count,
                thread_name_prefix="email-auth-import",
            )
            importer.executor = executor
            for task_id, ordinal, entry, _restore_on_cancel in reserved:
                future = executor.submit(
                    run_after_start,
                    copy.deepcopy(settings),
                    ordinal,
                    entry,
                    task_id,
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
                    future.cancel()
                except Exception:
                    cleanup_failures += 1
            if executor is not None:
                try:
                    executor.shutdown(wait=True, cancel_futures=True)
                except Exception:
                    cleanup_failures += 1
            for _task_id, _ordinal, entry, restore_on_cancel in reserved:
                if not restore_on_cancel:
                    continue
                try:
                    pool.restore_entry(entry, reason="batch_start_failed")
                except Exception:
                    cleanup_failures += 1
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
                f"导入任务启动: 目标邮箱 {target}/{available}，实际任务并发 {worker_count}，"
                f"Node 并发 {node_concurrency}，邮箱验证码槽 {email_login_concurrency}；"
                "仅预留本批目标邮箱，验证码通过后立即释放，号码/SUB2 保持并发"
            )
        importer._log(message, "success")
    except Exception:
        pass


def stop_bounded_importer(importer: Any) -> None:
    """Stop pending work without racing the recovered watcher assignment cleanup."""
    importer.stop_event.set()
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
        assignment = assignments.get(future)
        if assignment is None:
            continue
        pool, entry, task_id = assignment
        if task_id not in preselected_task_ids:
            try:
                pool.restore_entry(entry, reason="stopped_before_start")
            except Exception:
                cleanup_failures += 1
        try:
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
            f"已停止：取消 {cancelled} 个等待任务，正在运行任务立即中断并归还邮箱",
            "warn",
        )
        if cleanup_failures:
            importer._log(f"停止清理有 {cleanup_failures} 项未完成", "error")
    except Exception:
        pass
