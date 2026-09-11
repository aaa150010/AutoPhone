"""Timing/stage bookkeeping and public projection mixins for FreeRegisterManager.

Split out of ``free_register_runtime.py``; the manager composes these mixins
so each responsibility band keeps its own module.  Both mixins rely on
attributes and methods defined by the manager (``self._lock``,
``self._tasks``, ``self._save_task``, ``self._log`` ...).
"""

from __future__ import annotations

import copy
import re
import sys
import time
from typing import Any, Mapping, Sequence

try:
    from .free_failure_runtime import (
        canonical_failure,
        merge_account_result_fields,
        normalize_password_result,
        sanitize_public_bool,
        sanitize_public_email,
        sanitize_public_http_status,
        sanitize_public_identifier,
        sanitize_public_manual_prompt,
        sanitize_public_number,
        sanitize_public_progress,
        sanitize_public_scheme,
        sanitize_public_status,
        sanitize_public_timestamp,
        sanitize_public_timing,
        sanitize_failure_text,
        sanitize_proxy_attempts,
    )
    from .free_register_common import (
        FREE_STAGE_LABELS,
        FreeRegisterError,
        TERMINAL_STATUSES,
        fingerprint as _fingerprint,
    )
    from .free_runtime_info import runtime_info
    from .free_timing import FREE_TIMING_SUBSTEPS
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_failure_runtime import (  # type: ignore[no-redef]
        canonical_failure,
        merge_account_result_fields,
        normalize_password_result,
        sanitize_public_bool,
        sanitize_public_email,
        sanitize_public_http_status,
        sanitize_public_identifier,
        sanitize_public_manual_prompt,
        sanitize_public_number,
        sanitize_public_progress,
        sanitize_public_scheme,
        sanitize_public_status,
        sanitize_public_timestamp,
        sanitize_public_timing,
        sanitize_failure_text,
        sanitize_proxy_attempts,
    )
    from free_register_common import (  # type: ignore[no-redef]
        FREE_STAGE_LABELS,
        FreeRegisterError,
        TERMINAL_STATUSES,
        fingerprint as _fingerprint,
    )
    from free_runtime_info import runtime_info  # type: ignore[no-redef]
    from free_camoufox_runtime import (  # type: ignore[no-redef]
        camoufox_debug_state,
        close_camoufox_debug_browsers,
    )
    from free_timing import FREE_TIMING_SUBSTEPS  # type: ignore[no-redef]



def _runtime_module() -> Any:
    """Resolve the composing runtime module lazily.

    ``camoufox_debug_state`` / ``close_camoufox_debug_browsers`` stay addressable
    on ``free_register_runtime`` so existing tests and integrations can patch
    them there; resolving through the module keeps that contract intact.
    """
    try:
        from . import free_register_runtime as runtime
    except ImportError:  # macOS launcher imports overrides as top-level modules.
        import free_register_runtime as runtime  # type: ignore[no-redef]
    return runtime

class FreeRegisterTimingMixin:
    """Execution-start markers, per-stage timing and task log helpers."""

    def _note_quiet(self, where: str, exc: BaseException) -> None:
        """Record a swallowed telemetry/projection fallback on stderr."""
        try:
            print(f"[free_register_bands/{where}] {type(exc).__name__}", file=sys.stderr)
        except Exception:
            return

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
                except Exception as exc:
                    # Progress telemetry must not break band evaluation.
                    self._note_quiet("band_execution_started_compat", exc)
            except Exception as exc:
                # Progress telemetry must not break band evaluation.
                self._note_quiet("band_execution_started", exc)
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
            except Exception as exc:
                # Stage progress is best-effort UI state.
                self._note_quiet("progress_set_stage", exc)
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


class FreeRegisterProjectionMixin:
    """Secret-free public projections consumed by the dashboard."""

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
            except Exception as exc:
                # Finish bookkeeping must not mask the task result.
                self._note_quiet("progress_finish", exc)

    def _public_task(
        self,
        task: Mapping[str, Any],
        durable_results: Mapping[str, Mapping[str, Any]] | None = None,
        mailbox_index: Mapping[str, Any] | None = None,
        task_incidents: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
        # The task journal and mailbox result file are persisted separately.
        # A continuation can finish after the original task snapshot was
        # written (or before a process restart), so use the durable account
        # result as a fill/override source for the public capability view.
        row_id = str(task.get("row_id") or "").strip()
        if row_id:
            durable_result = dict((durable_results or {}).get(row_id) or {})
            if not durable_result:
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
            mailbox = (mailbox_index or {}).get(row_id)
            if mailbox is None:
                try:
                    mailbox = self.pool.entry(row_id)
                except Exception:
                    mailbox = None
            private_email = str(getattr(mailbox, "email", "") or "").strip() if mailbox is not None else ""
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
            "retry_of", "retry_task_id", "retry_mode",
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
            task_key = str(task.get("task_id") or "")
            incident_id = str((task_incidents or {}).get(task_key) or "")
            if not incident_id and diagnostic_store is not None:
                try:
                    matches = diagnostic_store.search({
                        "task_id": task_key,
                        "first_node_code": "mailbox_parser_unmatched",
                        "limit": 1,
                    })
                    if matches:
                        incident_id = sanitize_public_identifier(matches[0].get("incident_id"), limit=160)
                except Exception as exc:
                    # Diagnostic enrichment must not change the public payload.
                    self._note_quiet("incident_id_enrich", exc)
            if incident_id:
                public["incident_id"] = sanitize_public_identifier(incident_id, limit=160)
        # ``account`` is a legacy alias consumed by a few clients.  It must
        # follow the same masked representation and never reintroduce the
        # private address.
        public["account"] = email_masked
        mailbox_url = str(task.get("mailbox_url") or "").strip()
        if not mailbox_url and row_id:
            mailbox = (mailbox_index or {}).get(row_id)
            if mailbox is None:
                try:
                    mailbox = self.pool.entry(str(row_id))
                except Exception:
                    mailbox = None
            mailbox_url = str(getattr(mailbox, "mailbox_url", "") or "").strip() if mailbox is not None else ""
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

    def _bulk_task_incidents(self, task_ids_with_missing: list[str]) -> dict[str, str]:
        """Resolve one newest mailbox-parser incident per task in a single query."""
        diagnostic_store = getattr(getattr(self, "log_store", None), "diagnostic_store", None)
        batch_reader = getattr(diagnostic_store, "search_task_nodes", None)
        if callable(batch_reader):
            try:
                matches = batch_reader(task_ids_with_missing, "mailbox_parser_unmatched")
                if isinstance(matches, Mapping):
                    return dict(matches)
            except Exception as exc:
                self._note_quiet("parser_unmatched_reader", exc)
        return {}

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
            # Durable results and mailbox rows are resolved in bulk so each
            # state read stays at two storage queries instead of two per task.
            row_ids = [str(task.get("row_id") or "").strip() for task in tasks]
            row_ids = [row_id for row_id in row_ids if row_id]
            durable_results = self._bulk_durable_results(row_ids)
            mailbox_index = self._bulk_mailbox_index(row_ids)
            missing_incident_ids = [
                str(task.get("task_id") or "")
                for task in tasks
                if not str(task.get("incident_id") or "").strip()
            ]
            task_incidents = self._bulk_task_incidents(missing_incident_ids) if missing_incident_ids else {}
            return [
                self._public_task(task, durable_results, mailbox_index, task_incidents)
                for task in tasks
            ]

    def _bulk_durable_results(self, row_ids: Sequence[str]) -> dict[str, Mapping[str, Any]]:
        bulk_reader = getattr(self.pool, "results_bulk", None)
        if callable(bulk_reader):
            try:
                bulk = bulk_reader(row_ids)
                if isinstance(bulk, Mapping):
                    return bulk
            except Exception as exc:
                self._note_quiet("results_bulk_reader", exc)
        # Compatibility fallback for pool facades without the bulk reader.
        results: dict[str, Mapping[str, Any]] = {}
        for row_id in row_ids:
            try:
                result = self.pool.result(row_id)
            except Exception:
                result = {}
            if isinstance(result, Mapping) and result:
                results[row_id] = result
        return results

    def _bulk_mailbox_index(self, row_ids: Sequence[str]) -> dict[str, Any]:
        index_reader = getattr(self.pool, "mailbox_index", None)
        if callable(index_reader):
            try:
                index = index_reader()
                if isinstance(index, Mapping):
                    return index
            except Exception as exc:
                self._note_quiet("mailbox_index_reader", exc)
        return {}

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
        runtime = _runtime_module()
        return runtime.camoufox_debug_state(self._camoufox_state_config(config))

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
        runtime = _runtime_module()
        result = runtime.close_camoufox_debug_browsers(
            normalized,
            config=self._camoufox_state_config(config),
        )
        result["state"] = self.camoufox_debug_state()
        return result

    def _available_count(self) -> int:
        counter = getattr(self.pool, "available_count", None)
        if callable(counter):
            return max(0, int(counter()))
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


__all__ = [
    "FreeRegisterTimingMixin",
    "FreeRegisterProjectionMixin",
]
