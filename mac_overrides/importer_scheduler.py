"""Target-aware task scheduling for the recovered importer."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import inspect
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


def _accepts_keyword(callback: Callable[..., Any], name: str) -> bool:
    try:
        parameters = inspect.signature(callback).parameters
    except (TypeError, ValueError):
        return False
    parameter = parameters.get(name)
    return bool(
        parameter
        and parameter.kind
        in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
    ) or any(item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values())


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
    inflight_gate: Any = None,
    staged_inflight: bool = False,
    email_phase_gate_factory: Callable[[int], Any] | None = None,
    node_phase_gate_factory: Callable[[int], Any] | None = None,
    on_task_started: Callable[[str, float], Any] | None = None,
    batch_manifest: Any = None,
    batch_reserve: Callable[..., Sequence[Any]] | None = None,
) -> None:
    """Start only the requested number of reserved pool entries."""
    relogin = _is_relogin(settings)
    if relogin:
        # Relogin retains the original scheduler path regardless of callers'
        # optional gate arguments.
        inflight_gate = None
    staged_inflight = bool(staged_inflight and inflight_gate is not None)
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
    batch_id = str(settings.get("batch_id") or "").strip()
    dynamic_append_enabled = bool(batch_id and not relogin)
    scheduling_capacity = concurrency if dynamic_append_enabled else worker_count
    dynamic_capacity = max(target, scheduling_capacity)
    worker_capacity = scheduling_capacity
    # The optional in-flight gate expands executor staging while preserving
    # the recovered ``concurrency`` admission baseline inside each worker.
    if inflight_gate is not None and not relogin:
        try:
            inflight_snapshot = inflight_gate.snapshot()
            worker_capacity = min(
                dynamic_capacity,
                max(
                    scheduling_capacity,
                    int(inflight_snapshot.get("effective") or scheduling_capacity),
                ),
            )
        except Exception:
            pass
    if task_admission is not None:
        try:
            admission_capacity = min(
                dynamic_capacity,
                _MAX_WORKER_CAPACITY,
                max(
                    scheduling_capacity,
                    int(task_admission.snapshot().get("ceiling") or scheduling_capacity),
                ),
            )
            worker_capacity = admission_capacity
            if inflight_gate is not None and not relogin:
                worker_capacity = min(
                    dynamic_capacity,
                    max(
                        admission_capacity,
                        int(inflight_gate.snapshot().get("effective") or admission_capacity),
                    ),
                )
        except Exception:
            worker_capacity = scheduling_capacity
    email_login_concurrency = _bounded_int(
        settings.get("auto_email_login_concurrency"),
        min(5, scheduling_capacity),
        1,
        scheduling_capacity,
    )
    node_concurrency = _bounded_int(
        settings.get("node_concurrency"),
        min(3, scheduling_capacity),
        1,
        scheduling_capacity,
    )
    reserved: list[tuple[str, int, Any, bool]] = []
    executor = None
    futures: list[Any] = []
    admission_tracks_pending = False
    startup_gate = threading.Event()
    startup_ready = threading.Event()
    append_condition = threading.Condition(importer.lock)
    batch_started_at = _bounded_int(settings.get("batch_started_at"), 0, 0, 4_102_444_800)
    task_specs = [
        (f"T{ordinal:03d}-{uuid.uuid4().hex[:6]}", ordinal)
        for ordinal in range(1, target + 1)
    ]
    batch_prepared = False
    batch_committed = False
    reserve_handles_rollback = False
    reservation_returned = False

    def begin_batch(entries: Sequence[Any]) -> None:
        nonlocal batch_prepared
        if batch_manifest is None or not batch_id:
            return
        if len(entries) != target:
            raise mailbox_error_type("运行批次预选成员数量与目标数量不一致")
        members = []
        for (task_id, ordinal), entry in zip(task_specs, entries, strict=True):
            source_row = str(getattr(entry, "source_row", "") or "")
            members.append(
                {
                    "task_id": task_id,
                    "ordinal": ordinal,
                    "row_id": source_row,
                    "line_no": int(getattr(entry, "line_no", 0) or 0),
                }
            )
        prepare = getattr(batch_manifest, "prepare", None)
        callback = prepare if callable(prepare) else batch_manifest.begin
        callback(settings, target=target, members=members)
        batch_prepared = True

    def commit_batch(_entries: Sequence[Any] = ()) -> None:
        nonlocal batch_committed
        if batch_manifest is None or not batch_id or batch_committed:
            return
        callback = getattr(batch_manifest, "commit_prepared", None)
        if callable(callback):
            callback(batch_id)
        batch_committed = True

    def rollback_batch(_entries: Sequence[Any] = (), _error: Exception | None = None) -> None:
        nonlocal batch_prepared
        if batch_manifest is None or not batch_id or not batch_prepared or batch_committed:
            return
        callback = getattr(batch_manifest, "rollback_prepared", None)
        if callable(callback):
            callback(batch_id)
        batch_prepared = False

    def record_batch(method: str, *args: Any, **kwargs: Any) -> None:
        if batch_manifest is None or not batch_id:
            return
        callback = getattr(batch_manifest, method, None)
        if not callable(callback):
            return
        try:
            callback(*args, **kwargs)
        except Exception as exc:
            try:
                importer._log(
                    f"[运行批次对账/run_batch_manifest] {method} 更新失败（{type(exc).__name__}）",
                    "error",
                )
            except Exception:
                pass

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
            record_batch("observe_task", task_id, status)
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
        wait_seconds = 0.0

        def observed_wait(value: float) -> None:
            nonlocal wait_seconds
            wait_seconds = max(0.0, float(value))

        business_started = False

        def observe_inflight_result() -> None:
            if inflight_gate is None:
                return
            observer = getattr(inflight_gate, "observe_task", None)
            if not callable(observer):
                return
            try:
                with importer.lock:
                    task = copy.deepcopy(importer.tasks.get(task_id) or {})
                observer(task.get("status"), task.get("result"))
            except Exception:
                # Rollback telemetry must never change task outcome semantics.
                pass

        def run_admitted() -> None:
            nonlocal business_started
            if task_admission is None or staged_inflight:
                if callable(on_task_started):
                    try:
                        on_task_started(task_id, 0.0)
                    except Exception:
                        pass
                record_batch("mark_started", task_id)
                business_started = True
                importer._run_one(task_settings, ordinal, entry, task_id)
                return
            acquire_options = {
                "stop_event": importer.stop_event,
                "on_wait": observed_wait,
                "queued_at": queued_at,
            }
            if admission_tracks_pending:
                acquire_options["registered_pending"] = True
            with task_admission.acquire(**acquire_options):
                if callable(on_task_started):
                    try:
                        on_task_started(task_id, wait_seconds)
                    except Exception:
                        pass
                record_batch("mark_started", task_id)
                business_started = True
                importer._run_one(task_settings, ordinal, entry, task_id)

        try:
            if inflight_gate is None:
                run_admitted()
            else:
                with inflight_gate.acquire(stop_event=importer.stop_event):
                    try:
                        run_admitted()
                    finally:
                        observe_inflight_result()
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
        importer.inflight_gate = inflight_gate
        importer.running = True
        importer.tasks = {}
        importer.cancelled_waiting = 0
        importer.futures = []
        importer.future_assignments = {}
        importer.active_task_ids = set()
        importer._gptphone_preselected_task_ids = set()
        importer._gptphone_batch_manifest = batch_manifest
        importer._gptphone_append_accepting = dynamic_append_enabled
        importer._gptphone_run_settings = copy.deepcopy(settings)

        try:
            if relogin:
                selected_entries = list(relogin_entries[:target])
                begin_batch(selected_entries)
                reserved.extend(
                    (task_id, ordinal, entry, False)
                    for (task_id, ordinal), entry in zip(
                        task_specs,
                        selected_entries,
                        strict=True,
                    )
                )
                commit_batch(selected_entries)
            elif callable(batch_reserve):
                reserve_options = {
                    "lease_seconds": 3600,
                    "before_reserve": begin_batch,
                }
                if batch_id and _accepts_keyword(batch_reserve, "lease_owner_batch_id"):
                    reserve_options["lease_owner_batch_id"] = batch_id
                if _accepts_keyword(batch_reserve, "after_reserve"):
                    reserve_options["after_reserve"] = commit_batch
                if _accepts_keyword(batch_reserve, "on_reserve_failed"):
                    reserve_options["on_reserve_failed"] = rollback_batch
                    reserve_handles_rollback = True
                selected_entries = list(
                    batch_reserve(
                        pool,
                        target,
                        **reserve_options,
                    )
                )
                reservation_returned = True
                if len(selected_entries) != target:
                    raise mailbox_error_type("运行批次原子预留数量与目标数量不一致")
                reserved.extend(
                    (task_id, ordinal, entry, True)
                    for (task_id, ordinal), entry in zip(
                        task_specs,
                        selected_entries,
                        strict=True,
                    )
                )
                commit_batch(selected_entries)
            else:
                preview_entries, preview_errors = pool._entries_unlocked()
                if preview_errors or len(preview_entries) < target:
                    raise mailbox_error_type("运行批次无法冻结完整成员")
                begin_batch(preview_entries[:target])
                for (task_id, ordinal) in task_specs:
                    entry = pool.lease(lease_seconds=3600)
                    reserved.append((task_id, ordinal, entry, True))
                commit_batch([item[2] for item in reserved])

            for task_id, ordinal, entry, _restore_on_cancel in reserved:
                if batch_manifest is not None and batch_id:
                    source_row = str(getattr(entry, "source_row", "") or "")
                    batch_manifest.reserve(
                        batch_id,
                        task_id,
                        row_identity=source_row,
                        line_no=int(getattr(entry, "line_no", 0) or 0),
                    )
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
            if callable(register_pending) and not staged_inflight:
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

            def append_entries(entries: Sequence[Any]) -> dict[str, int]:
                appended = list(entries)
                if not appended:
                    return {"joined_current_batch": 0, "queued_current_batch": 0}
                with append_condition:
                    if (
                        not importer.running
                        or importer.stop_event.is_set()
                        or not getattr(importer, "_gptphone_append_accepting", False)
                        or importer.executor is None
                    ):
                        raise RuntimeError("current_batch_closed")
                    next_ordinal = max(
                        (int((task or {}).get("ordinal") or 0) for task in importer.tasks.values()),
                        default=0,
                    )
                    appended_specs = [
                        (f"T{next_ordinal + index:03d}-{uuid.uuid4().hex[:6]}", next_ordinal + index, entry)
                        for index, entry in enumerate(appended, start=1)
                    ]
                    staged_gate = threading.Event()
                    staged_committed = threading.Event()
                    staged_futures: list[tuple[Any, Any, str]] = []
                    created_task_ids: list[str] = []
                    pending_registered = False

                    def run_staged(*args: Any) -> None:
                        staged_gate.wait()
                        if staged_committed.is_set():
                            run_after_start(*args)

                    try:
                        for task_id, ordinal, entry in appended_specs:
                            importer._task_state(
                                task_id,
                                status="queued",
                                email=entry.email,
                                account=importer._account_label(entry),
                                source_row=importer._source_row(entry),
                                ordinal=ordinal,
                                batch_id=batch_id,
                                batch_started_at=batch_started_at,
                                run_mode="register",
                            )
                            created_task_ids.append(task_id)
                            try:
                                queued_at = (
                                    float(task_admission.now_fn())
                                    if task_admission is not None
                                    else time.monotonic()
                                )
                            except Exception:
                                queued_at = time.monotonic()
                            future = importer.executor.submit(
                                run_staged,
                                copy.deepcopy(settings),
                                ordinal,
                                entry,
                                task_id,
                                queued_at,
                            )
                            staged_futures.append((future, entry, task_id))

                        if callable(register_pending) and not staged_inflight:
                            register_pending(len(appended_specs))
                            pending_registered = True
                        if batch_manifest is not None and batch_id:
                            batch_manifest.append_members(
                                batch_id,
                                [
                                    {
                                        "task_id": task_id,
                                        "ordinal": ordinal,
                                        "row_id": str(getattr(entry, "source_row", "") or ""),
                                        "line_no": int(getattr(entry, "line_no", 0) or 0),
                                    }
                                    for task_id, ordinal, entry in appended_specs
                                ],
                            )
                    except Exception:
                        if pending_registered:
                            discard_pending = getattr(task_admission, "discard_pending", None)
                            if callable(discard_pending):
                                try:
                                    discard_pending(len(appended_specs))
                                except Exception:
                                    pass
                        staged_gate.set()
                        for future, _entry, _task_id in staged_futures:
                            try:
                                future.cancel()
                            except Exception:
                                pass
                        for task_id in created_task_ids:
                            importer.tasks.pop(task_id, None)
                        raise

                    for future, entry, task_id in staged_futures:
                        importer.futures.append(future)
                        importer.future_assignments[future] = (pool, entry, task_id)
                    staged_committed.set()
                    staged_gate.set()
                    append_condition.notify_all()
                    return {
                        "joined_current_batch": len(appended_specs),
                        "queued_current_batch": len(appended_specs),
                    }

            importer._gptphone_append_entries = append_entries

            def watch_and_reconcile() -> None:
                try:
                    observed = 0
                    while True:
                        with append_condition:
                            current = list(importer.futures)
                            if observed >= len(current):
                                importer._gptphone_append_accepting = False
                                break
                            future = current[observed]
                            observed += 1
                        try:
                            future.result()
                        except Exception:
                            pass
                    importer._watch()
                finally:
                    if batch_manifest is not None and batch_id:
                        try:
                            with importer.lock:
                                task_snapshot = copy.deepcopy(dict(importer.tasks))
                            batch_manifest.finalize(
                                batch_id,
                                tasks=task_snapshot,
                                reason="batch_finished",
                            )
                        except Exception as exc:
                            try:
                                importer._log(
                                    "[运行批次对账/run_batch_manifest] 批次结束对账失败"
                                    f"（{type(exc).__name__}）",
                                    "error",
                                )
                            except Exception:
                                pass

            watcher = thread_factory(
                target=watch_and_reconcile,
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
                importer._gptphone_append_accepting = False
                importer._gptphone_append_entries = None
                importer._gptphone_run_settings = None
                importer._gptphone_preselected_task_ids = set()
                importer.tasks = {}
                importer.running = False
            if batch_manifest is not None and batch_id and batch_committed:
                try:
                    batch_manifest.finalize(
                        batch_id,
                        tasks={},
                        reason="batch_start_failed",
                    )
                except Exception as exc:
                    try:
                        importer._log(
                            "[运行批次对账/run_batch_manifest] 启动失败批次对账失败"
                            f"（{type(exc).__name__}）",
                            "error",
                        )
                    except Exception:
                        pass
            elif (
                batch_manifest is not None
                and batch_id
                and batch_prepared
                and (not reserve_handles_rollback or reservation_returned)
            ):
                try:
                    rollback_batch()
                except Exception as exc:
                    try:
                        importer._log(
                            "[运行批次对账/run_batch_manifest] 启动失败预备清单回滚失败"
                            f"（{type(exc).__name__}）",
                            "error",
                        )
                    except Exception:
                        pass
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
    inflight_gate = getattr(importer, "inflight_gate", None)
    if inflight_gate is not None:
        try:
            stop = getattr(inflight_gate, "stop", None)
            if callable(stop):
                stop()
            else:
                inflight_gate.wake_all()
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
            batch_manifest = getattr(importer, "_gptphone_batch_manifest", None)
            if batch_manifest is not None:
                batch_manifest.observe_task(task_id, "failed" if restore_error else "stopped")
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
