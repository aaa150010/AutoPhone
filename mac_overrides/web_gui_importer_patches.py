"""Importer lifecycle patches for the recovered web GUI, hosted by web_gui.

Every patched callable receives the hosting ``web_gui`` module as its first
``host`` argument so late-bound module globals (including test rebindings of
``_ORIGINAL_*`` names and runtime singletons) keep their original semantics.
"""

from __future__ import annotations

import copy
import threading
import uuid


def patched_importer_start(host, self, settings):
    internal = copy.deepcopy(dict(settings or {}))
    additional_retries = host._int_value(internal.get("auth_session_retries"), 1, minimum=0, maximum=4)
    internal["auth_session_retries"] = additional_retries + 1
    already_running = bool(self.status(internal).get("running"))
    preflight_sms_statuses = internal.pop(
        "_gptphone_sms_preflight_statuses",
        (),
    )
    task_admission = getattr(self, "task_admission", None)
    inflight_gate = getattr(self, "inflight_gate", None)
    staged_inflight = False
    node_phase_gate = None
    if not already_running:
        host._SMS_QUALITY_GUARD.begin_run(
            host._performance_runtime_ext.as_bool(
                internal.get("sms_quality_optimization"),
                True,
            ),
            baseline=internal.get("sms_optimization_baseline"),
        )
        admission_policy = host._performance_runtime_ext.resolve_task_admission(
            internal.get("concurrency"),
            run_mode=internal.get("run_mode"),
            adaptive_enabled=internal.get("adaptive_task_concurrency"),
        )
        task_limit = admission_policy.base_limit
        internal["concurrency"] = task_limit
        node_limit = host._int_value(
            internal.get("node_concurrency"),
            task_limit,
            minimum=1,
            maximum=task_limit,
        )
        phase_adaptive = admission_policy.adaptive and node_limit == task_limit
        phase_ceiling = (
            admission_policy.restore_ceiling if phase_adaptive else node_limit
        )
        node_phase_gate = host._phase_concurrency_ext.AdjustablePhaseGate(
            node_limit,
            ceiling=phase_ceiling,
        )
        protocol_baseline = min(task_limit, node_limit)
        inflight_expansion = (
            str(internal.get("run_mode") or "register").strip().lower() == "register"
            and host._performance_runtime_ext.as_bool(
                internal.get("task_inflight_optimization"),
                True,
            )
            and host._int_value(
                internal.get("task_inflight_limit"),
                20,
                minimum=1,
                maximum=20,
            ) > task_limit
        )
        protocol_healthy_ceiling = (
            host._int_value(
                internal.get("protocol_concurrency_ceiling"),
                12,
                minimum=8,
                maximum=15,
            )
            if inflight_expansion
            else protocol_baseline
        )
        next_proxy = str(internal.get("proxy") or "").strip()
        next_batch_id = str(internal.get("batch_id") or "").strip()
        with host._OPENAI_CONNECTIVITY._callback_lock:
            host._PROTOCOL_GATE.begin_run(
                protocol_baseline,
                healthy_ceiling=protocol_healthy_ceiling,
            )
            host._OPENAI_CONNECTIVITY.begin_run(
                proxy=next_proxy,
                enabled=host._performance_runtime_ext.as_bool(
                    internal.get("openai_connectivity_guard"), True,
                ),
            )
            host._CONNECTIVITY_PROXY = next_proxy
            host._CONNECTIVITY_BATCH_ID = next_batch_id
        host._SMS_PHONE_GATE.configure(
            host._int_value(
                internal.get("phone_submission_concurrency"),
                2,
                minimum=1,
                maximum=5,
            )
        )
        host._SMS_PHONE_GATE.begin_run()

        def log_task_limit_change(event):
            if phase_adaptive:
                try:
                    phase_limit = max(
                        1,
                        min(phase_ceiling, int((event or {}).get("new_limit") or task_limit)),
                    )
                    phase_reason = str((event or {}).get("reason") or "task_admission")
                    node_phase_gate.set_capacity(phase_limit, reason=phase_reason)
                    host._PROTOCOL_GATE.synchronize_capacity(phase_limit)
                except Exception as exc:
                    # Capacity observability must not break task state updates.
                    try:
                        self._log(
                            "[任务并发/registration_admission] 容量同步失败，"
                            f"协议门与实际并发可能脱节（{type(exc).__name__}）",
                            "error",
                        )
                    except Exception:
                        pass
            formatted = host._performance_runtime_ext.format_task_admission_event(event)
            if formatted is None:
                return
            message, level = formatted
            try:
                self._log(message, level)
            except Exception:
                pass

        task_admission = host._adaptive_concurrency_ext.AdaptiveConcurrencyGate(
            task_limit,
            ceiling=admission_policy.absolute_ceiling,
            restore_ceiling=admission_policy.restore_ceiling,
            # With the feature switch off this gate remains only as the
            # scheduler's compatibility wrapper.  It may pause for pressure,
            # but it must not alter the configured fixed task concurrency.
            minimum=(min(4, task_limit) if admission_policy.adaptive else task_limit),
            immediate_reset_limit=(task_limit if admission_policy.adaptive else None),
            adaptive_enabled=admission_policy.adaptive,
            require_backlog_for_restore=True,
            on_change=log_task_limit_change,
        )
        inflight_gate = None
        if str(internal.get("run_mode") or "register").strip().lower() != "relogin":
            inflight_baseline = (
                internal["task_inflight_baseline"]
                if "task_inflight_baseline" in internal
                else host._SMS_QUALITY_GUARD.inflight_rollback_baseline()
            )
            inflight_gate = host._performance_runtime_ext.InflightAdmissionGate(
                task_limit,
                limit=internal.get("task_inflight_limit", 20),
                enabled=internal.get("task_inflight_optimization", True),
                baseline=inflight_baseline,
                on_rollback=lambda event: self._log(
                    "[任务在途/task_inflight] 优化已自动回退到配置并发："
                    f"{event.get('reason', 'unknown')}",
                    "warn",
                ),
            )
        _CURRENT_TASK_ADMISSION = task_admission
        _CURRENT_INFLIGHT_GATE = inflight_gate
        host._PROTOCOL_COORDINATOR.synchronize_connectivity_pause(
            host._CONNECTIVITY_PROXY, inflight_gate,
        )
        staged_inflight = host._inflight_pipeline_runtime_ext.optimization_active(
            inflight_gate
        )
        host._TASK_PROGRESS.reset()
        with host._TASK_FAILURES_LOCK:
            host._TASK_FAILURES.clear()
    selection = set()
    for item in internal.get("_gptphone_run_mailbox_rows") or ():
        if not isinstance(item, dict):
            continue
        try:
            line_no = int(item.get("line_no") or 0)
        except (TypeError, ValueError):
            line_no = 0
        row_id = str(item.get("row_id") or "").strip().lower()
        if row_id and line_no > 0:
            selection.add((row_id, line_no))
    selection_token = host._MAILBOX_RUN_SELECTION.set(frozenset(selection))
    priority_token = host._MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.set(
        not selection
        and str(internal.get("run_mode") or "register").strip().lower() != "relogin"
    )
    lease_filter_token = None
    if str(internal.get("run_mode") or "").strip().lower() != "relogin":
        lease_filter_token = host._MAILBOX_LEASE_FILTER_ACTIVE.set(True)
    notification_context = None

    def observed_phase_gate(limit, segment_code):
        return host._importer_scheduler_ext.ObservedPhaseGate(
            host._runtime.AutoEmailPhaseGate(limit),
            lambda elapsed: host._record_task_segment(
                host._TASK_CONTEXT.get(),
                segment_code,
                elapsed,
            ),
        )

    def observed_node_phase_gate(limit):
        gate = node_phase_gate or host._runtime.AutoEmailPhaseGate(limit)
        return host._importer_scheduler_ext.ObservedPhaseGate(
            gate,
            lambda elapsed: host._record_task_segment(
                host._TASK_CONTEXT.get(),
                "node_slot_waiting",
                elapsed,
            ),
        )

    def task_started(task_id, elapsed):
        host._TASK_PROGRESS.mark_execution_started(task_id)
        host._record_task_segment(task_id, "task_slot_waiting", elapsed)

    try:
        if not already_running:
            notification_context = host._begin_notification_run(self, internal)
            host._PROTOCOL_COORDINATOR.synchronize_connectivity_pause(
                host._CONNECTIVITY_PROXY, inflight_gate,
                on_paused=lambda _state: host._set_stall_notifications_suspended(True),
            )
        result = host._importer_scheduler_ext.start_bounded_importer(
            self,
            internal,
            mailbox_error_type=host._runtime.MailboxPoolError,
            manual_code_factory=host._runtime.ManualCodeCoordinator,
            phase_gate_factory=host._runtime.AutoEmailPhaseGate,
            task_admission=task_admission,
            inflight_gate=inflight_gate,
            staged_inflight=staged_inflight,
            email_phase_gate_factory=lambda limit: observed_phase_gate(
                limit,
                "email_slot_waiting",
            ),
            node_phase_gate_factory=observed_node_phase_gate,
            on_task_started=task_started,
            batch_manifest=host._RUN_BATCH_MANIFEST,
            batch_reserve=host._reserve_mailbox_batch,
        )
        if notification_context is not None:
            with self.lock:
                actual_target = len(self.tasks)
            if actual_target > 0:
                notification_context["target"] = actual_target
            aggregate, last_activity_at = host._notification_aggregate(self, notification_context)
            notification_context["last_activity_at"] = last_activity_at or notification_context["started_at"]
            notification_context["service"].observe_run(notification_context["run_id"], aggregate)
            host._notify_sms_balances(self, preflight_sms_statuses)
            monitor = threading.Thread(
                target=host._notification_watchdog,
                args=(self, notification_context),
                name="run-notification-watchdog",
                daemon=True,
            )
            notification_context["monitor"] = monitor
            monitor.start()
        return result
    except Exception:
        if notification_context is not None:
            host._cancel_notification_run(self, notification_context)
        if not already_running:
            if _CURRENT_TASK_ADMISSION is task_admission:
                _CURRENT_TASK_ADMISSION = None
            if _CURRENT_INFLIGHT_GATE is inflight_gate:
                _CURRENT_INFLIGHT_GATE = None
            host._TASK_PROGRESS.reset()
            with host._TASK_FAILURES_LOCK:
                host._TASK_FAILURES.clear()
        raise
    finally:
        if lease_filter_token is not None:
            host._MAILBOX_LEASE_FILTER_ACTIVE.reset(lease_filter_token)
        host._MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.reset(priority_token)
        host._MAILBOX_RUN_SELECTION.reset(selection_token)




def patched_importer_run_one(
    host,
    self,
    settings,
    ordinal,
    assigned_entry=None,
    assigned_task_id="",
):
    run_mode = str((settings or {}).get("run_mode") or "register").strip().lower()
    task_id = str(assigned_task_id or "").strip()
    if not task_id:
        task_id = f"T{int(ordinal):03d}-{uuid.uuid4().hex[:6]}"
    host._MAILBOX_TOTP_SECRET_CONTEXT.set("")
    host._TASK_TOTP_SECRETS.clear(task_id)
    host._TOTP_PATCHES.reset_task_state()
    host._MANUAL_VERIFICATION.cancel_task(task_id)
    token = host._RUN_MODE_CONTEXT.set(run_mode)
    task_token = host._TASK_CONTEXT.set(task_id)
    checkpoint_token = host._CHECKPOINT_CONTEXT.set(
        host._checkpoint_context_for_entry(self, settings, assigned_entry, task_id)
    )
    admission_token = host._TASK_ADMISSION_CONTEXT.set(getattr(self, "task_admission", None))
    try:
        return host._ORIGINAL_IMPORTER_RUN_ONE(
            self,
            settings,
            ordinal,
            assigned_entry,
            task_id,
        )
    finally:
        transport = host._transport_for_task(task_id)
        challenge_runtime = host._auth_challenge_runtime_ext
        clear_challenge = getattr(challenge_runtime, "clear_transport_context", None)
        if callable(clear_challenge) and transport is not None:
            try:
                clear_challenge(transport)
            except Exception:
                pass
        if not host._SMS_TRANSPORT_REGISTRY.close_task(task_id):
            host._SMS_TRANSPORT_REGISTRY.close_task(task_id)
        host._AUTH_SESSIONS.clear(task_id)
        host._SMS_PROVIDER_REGISTRY.clear_task_attempt_counts(task_id)
        host._MAILBOX_TOTP_SECRET_CONTEXT.set("")
        host._TASK_TOTP_SECRETS.clear(task_id)
        host._TOTP_PATCHES.reset_task_state()
        host._MANUAL_VERIFICATION.cancel_task(task_id)
        if transport is not None:
            try:
                delattr(transport, "_gptphone_totp_manual_secret")
            except AttributeError:
                pass
        host._PHASE1_CHECKPOINTS_COORDINATOR.release(transport)
        host._TASK_ADMISSION_CONTEXT.reset(admission_token)
        host._CHECKPOINT_CONTEXT.reset(checkpoint_token)
        host._TASK_CONTEXT.reset(task_token)
        host._RUN_MODE_CONTEXT.reset(token)


def patched_importer_stop(host, self):
    stop_event = getattr(self, "stop_event", None)
    set_stopped = getattr(stop_event, "set", None)
    if callable(set_stopped):
        set_stopped()
    host._MANUAL_VERIFICATION.cancel_all()
    host._OPENAI_CONNECTIVITY.wake_waiters()
    host._PROTOCOL_GATE.wake_all()
    context = host._notification_context_for(self)
    if isinstance(context, dict):
        try:
            aggregate, _last_activity_at = host._notification_aggregate(self, context)
            context["service"].mark_manual_stop(context["run_id"], aggregate)
        except Exception:
            pass
    return host._importer_scheduler_ext.stop_bounded_importer(self)


def unfinished_batch_task_ids(host, importer):
    terminal = set(host._task_progress_ext.TERMINAL_TASK_STATUSES)
    rows = host._notification_task_snapshot(importer)
    rows.sort(key=lambda task: host._int_value(task.get("ordinal"), 0, minimum=0))
    return tuple(
        str(task.get("task_id") or "").strip()
        for task in rows
        if str(task.get("task_id") or "").strip()
        and str(task.get("status") or "").strip().lower() not in terminal
    )


def reconcile_finished_batch(host, importer, context):
    manifest = getattr(importer, "_gptphone_batch_manifest", None)
    batch_id = str((context or {}).get("batch_id") or "").strip()
    if manifest is None or not batch_id:
        return None
    with importer.lock:
        tasks = copy.deepcopy(dict(importer.tasks))
    summary = manifest.finalize(
        batch_id,
        tasks=tasks,
        reason="watch_returned_with_unfinished_tasks",
    )
    terminal = set(host._task_progress_ext.TERMINAL_TASK_STATUSES)
    reconciled = []
    for member in summary.get("members") or ():
        if not isinstance(member, dict) or not member.get("reconciled_missing"):
            continue
        task_id = str(member.get("task_id") or "").strip()
        current = tasks.get(task_id) if isinstance(tasks.get(task_id), dict) else {}
        if not task_id or str(current.get("status") or "").strip().lower() in terminal:
            continue
        cause = "任务未产生终态，已由批次清单补记失败"
        failure = host._run_batch_runtime_ext.reconciliation_failure(
            "batch_member_missing_terminal",
            cause,
        )
        result = dict(current.get("result") or {})
        result.update(
            batch_id=batch_id,
            reconciled_by_batch_manifest=True,
            reconcile_reason="watch_returned_with_unfinished_tasks",
            failure=failure,
        )
        importer._task_state(
            task_id,
            status="failed",
            error=failure["public_message"],
            technical_error=failure["technical_summary"],
            failure=failure,
            result=result,
        )
        reconciled.append(task_id)
    if reconciled:
        importer._log(
            "[运行批次对账/batch_member_missing_terminal] "
            f"已补写 {len(reconciled)} 个缺失终态任务：{', '.join(reconciled)}",
            "warn",
        )
    return summary


def patched_importer_watch(host, self):
    context = host._notification_context_for(self)
    watch_failed = False
    try:
        return host._ORIGINAL_IMPORTER_WATCH(self)
    except BaseException:
        watch_failed = True
        raise
    finally:
        if isinstance(context, dict):
            host._importer_watch_runtime_ext.finalize_importer_watch(
                self,
                context,
                watch_failed=watch_failed,
                aggregate_fn=host._notification_aggregate,
                unfinished_fn=host._unfinished_batch_task_ids,
                reconcile_fn=host._reconcile_finished_batch,
                sms_exhausted_fn=host._SMS_PROVIDER_REGISTRY.is_exhausted,
            )
        admission = getattr(self, "task_admission", None)
        if admission is not None:
            try:
                capacity = admission.snapshot()
                self._log(
                    "[任务并发/registration_admission] 批次并发汇总："
                    f"基础 {capacity.get('base', 0)}，峰值 {capacity.get('peak_limit', 0)}，"
                    f"常规恢复 {capacity.get('restorations', 0)} 次，"
                    f"快速升档 {capacity.get('burst_promotions', 0)} 次，"
                    f"快速撤销 {capacity.get('burst_revocations', 0)} 次，"
                    f"降档 {capacity.get('degradations', 0)} 次，"
                    f"累计排队 {capacity.get('total_wait_seconds', 0)} 秒",
                    "info",
                )
            except Exception:
                pass
        try:
            with self.lock:
                active_task_ids = set(getattr(self, "active_task_ids", set()) or ())
                futures = list(getattr(self, "futures", ()) or ())
            futures_done = all(
                callable(getattr(future, "done", None)) and future.done()
                for future in futures
            )
            if not active_task_ids and futures_done:
                host._SMS_TRANSPORT_REGISTRY.clear()
                pending = host._SMS_TRANSPORT_REGISTRY.snapshot().get("pending_cleanup", 0)
                if pending:
                    self._log(
                        "[运行结束清理/transport_cleanup] "
                        f"仍有 {pending} 个 Transport 等待下次安全重试",
                        "warn",
                    )
        except Exception:
            pass


def patched_pre_auth_session_retryable(host, result):
    if any(
        marker in str(result or "").lower()
        for marker in ("relogin_phone_required",)
    ):
        return False
    if host._runtime_policy_ext.is_account_banned_failure(result):
        return False
    if host._is_auth_session_reset_failure(result):
        # The recovered importer owns the configured whole-session retry
        # limit. Do not impose a second, hidden cap here.
        return True
    if host._RUN_MODE_CONTEXT.get() == "relogin":
        return host._runtime_policy_ext.is_relogin_transient_failure(result)
    if host._runtime_policy_ext.should_retry_expired_sub2_session(result):
        return True
    return host._ORIGINAL_PRE_AUTH_SESSION_RETRYABLE(result)


def patched_password_credentials_rejected(host, result):
    if host._RUN_MODE_CONTEXT.get() == "relogin":
        return False
    return host._ORIGINAL_PASSWORD_CREDENTIALS_REJECTED(result)


def patched_persist_result(host, self, settings, task_id, entry, result, *, error="", status="failed"):
    persisted_settings = host._result_persistence_runtime_ext.settings_with_absolute_results_dir(
        settings,
        self.data_dir,
    )
    if status == "success":
        host._TASK_PROGRESS.set_stage(task_id, "finalizing_save")
    failure = None
    failure_statuses = set(host._task_progress_ext.TERMINAL_TASK_STATUSES).difference(
        {"success", "stopped", "stopped_before_start"}
    )
    secrets = host._failure_secrets(self, entry, settings)
    batch_id = str((settings or {}).get("batch_id") or "").strip()[:80]
    batch_started_at = host._int_value((settings or {}).get("batch_started_at"), 0, minimum=0)
    if isinstance(result, dict):
        risk_status = host._actionable_phone_risk_status(getattr(entry, "email", ""))
        if risk_status.get("active"):
            result["phone_risk_retry"] = True
            result["phone_risk_label"] = "手机号风控重试：已启用成熟线路优先"
            result["phone_risk_reason_code"] = str(
                risk_status.get("reason_code") or "oauth_session_invalid"
            )
        progress_snapshot = host._TASK_PROGRESS.progress(task_id) or {}
        if isinstance(progress_snapshot.get("timing"), dict):
            result["timing"] = copy.deepcopy(progress_snapshot["timing"])
        run_mode = str((settings or {}).get("run_mode") or "").strip().lower()
        if run_mode == "relogin":
            result["run_mode"] = "relogin"
        if host._is_auth_session_reset_failure(result, error):
            result["resume_stage"] = "fresh_oauth"
        if batch_id:
            result["batch_id"] = batch_id
            result["batch_started_at"] = batch_started_at
        host._sms_cost_history_ext.attach_task_sms_cost(result, task_id, host._SMS_COST_LEDGER, host._SMS_EXCHANGE_RATE)
        if str(status or "").strip().lower() in failure_statuses:
            failure = host._classify_task_failure(
                task_id,
                result,
                error,
                status=status,
                secrets=secrets,
            )
            result["failure"] = failure
            error = failure["public_message"]
    try:
        persisted = host._ORIGINAL_PERSIST_RESULT(
            self,
            persisted_settings,
            task_id,
            entry,
            result,
            error=error,
            status=status,
        )
    except Exception as exc:
        host._TASK_PROGRESS.set_stage(task_id, "finalizing_save")
        persistence_failure = host._error_observability_ext.classify_failure(
            error=f"result_persistence_failed: {exc}",
            progress=host._TASK_PROGRESS.progress(task_id),
            status="failed",
            secrets=secrets,
        )
        host._remember_task_failure(task_id, persistence_failure)
        raise RuntimeError(persistence_failure["public_message"]) from exc
    host._TASK_PROGRESS.finish(task_id)
    timing_snapshot = (host._TASK_PROGRESS.progress(task_id) or {}).get("timing")
    if isinstance(timing_snapshot, dict):
        if isinstance(result, dict):
            result["timing"] = copy.deepcopy(timing_snapshot)
    metadata_persisted = host._result_persistence_runtime_ext.apply_result_json_metadata(
        persisted_settings,
        self.data_dir,
        task_id,
        getattr(entry, "email", ""),
        timing=timing_snapshot if isinstance(timing_snapshot, dict) else None,
        batch_id=batch_id,
        batch_started_at=batch_started_at,
        failure=failure,
        status=status,
        account_banned_detail=host._ACCOUNT_BANNED_DETAIL_CONTEXT.get(""),
        account_banned_message=host._runtime_policy_ext.ACCOUNT_BANNED_MESSAGE,
        secrets=secrets,
        atomic_write_json=host._runtime.atomic_write_json,
        sanitize_failure_detail=host._error_observability_ext.sanitize_failure_detail,
        logger=getattr(self, "_log", None),
    )
    host._sms_cost_history_ext.note_persisted_result(self.data_dir, persisted_settings, task_id, getattr(entry, "email", ""))
    if batch_id and metadata_persisted:
        try:
            host._RUN_BATCH_MANIFEST.mark_persisted(batch_id, task_id, status)
        except KeyError:
            pass
        except Exception as exc:
            try:
                self._log(
                    "[运行批次对账/run_batch_manifest] 结果持久化计数更新失败"
                    f"（{type(exc).__name__}）",
                    "error",
                )
            except Exception:
                pass
    terminal_text = " ".join(
        str(value or "")
        for value in (
            error,
            result.get("error") if isinstance(result, dict) else "",
            result.get("error_code") if isinstance(result, dict) else "",
        )
    ).lower()
    if host._phase1_checkpoint_hooks_ext.should_delete_checkpoint(
        status,
        invalid_session=host._is_auth_session_reset_failure(result, error),
        values=(terminal_text,),
    ):
        host._PHASE1_CHECKPOINTS_COORDINATOR.cleanup_terminal(
            identity=host._checkpoint_context_for_entry(self, settings, entry, task_id)
        )
    return persisted


def patched_retire_after_failure(host, self, settings, pool, entry, task_id, result, error):
    if str((settings or {}).get("run_mode") or "").strip().lower() == "relogin":
        safe_error = host._error_observability_ext.sanitize_failure_detail(
            error,
            secrets=host._failure_secrets(self, entry, settings),
        ) or "重登未返回错误详情"
        self._persist_result(
            settings,
            task_id,
            entry,
            result if isinstance(result, dict) else {},
            error=safe_error,
            status="failed",
        )
        try:
            pool.remove_entry(entry, reason="relogin_failed")
        except Exception:
            pass
        public_result = host._runtime._public_result(result if isinstance(result, dict) else {})
        self._task_state(
            task_id,
            status="failed",
            error=safe_error,
            technical_error=safe_error,
            result=public_result,
        )
        try:
            self._log(f"{task_id} 无手机号重登失败: {safe_error}", "error")
        except Exception:
            pass
        return None
    if host._is_auth_session_reset_failure(result, error):
        if isinstance(result, dict):
            result["resume_stage"] = "fresh_oauth"
    password_rejected = False
    if isinstance(result, dict):
        try:
            password_rejected = bool(self._password_credentials_rejected(result))
        except Exception:
            password_rejected = False
    if password_rejected:
        pool.mark_damaged_entry(entry, reason=host._PASSWORD_DAMAGED_MESSAGE)
        self._persist_result(
            settings,
            task_id,
            entry,
            result,
            error=error,
            status="email_damaged",
        )
        public_result = host._runtime._public_result(result)
        self._task_state(
            task_id,
            status="email_damaged",
            error=host._PASSWORD_DAMAGED_MESSAGE,
            technical_error=host._PASSWORD_DAMAGED_MESSAGE,
            result=public_result,
        )
        try:
            self._log(
                f"{task_id} [验证邮箱密码/email_password] {host._PASSWORD_DAMAGED_MESSAGE}",
                "error",
            )
        except Exception:
            pass
        return None

    if not host._runtime_policy_ext.is_account_banned_failure(result, error):
        return host._ORIGINAL_RETIRE_AFTER_FAILURE(
            self,
            settings,
            pool,
            entry,
            task_id,
            result,
            error,
        )

    message = host._runtime_policy_ext.ACCOUNT_BANNED_MESSAGE
    technical_detail = host._SMS_WEB.pop_account_banned_detail(task_id)
    if not technical_detail:
        value = result if isinstance(result, dict) else {}
        technical_source = next(
            (
                value.get(key)
                for key in ("technical_error", "phase2_error", "error")
                if value.get(key)
            ),
            error,
        )
        technical_detail = host._safe_runtime_error(technical_source)
    token = host._ACCOUNT_BANNED_DETAIL_CONTEXT.set(str(technical_detail or message)[:1000])
    try:
        self._persist_result(
            settings,
            task_id,
            entry,
            result if isinstance(result, dict) else {},
            error=message,
            status="account_banned",
        )
    finally:
        host._ACCOUNT_BANNED_DETAIL_CONTEXT.reset(token)

    removal_error = ""
    try:
        removed_from_pool = host._mailbox_retention_ext.remove_banned_entry(
            pool,
            entry,
            host._ORIGINAL_POOL_REMOVE_ENTRY,
            reason="account_banned",
        )
    except Exception as exc:
        removed_from_pool = False
        removal_error = host._safe_runtime_error(exc)
    if not removed_from_pool:
        pool.mark_damaged_entry(entry, reason=message)

    public_result = host._runtime._public_result(result if isinstance(result, dict) else {})
    if isinstance(public_result, dict):
        public_result = dict(public_result)
        for key in ("technical_error", "phase2_error", "local_oauth_exchange_error"):
            public_result.pop(key, None)
        if "error" in public_result:
            public_result["error"] = message
    self._task_state(
        task_id,
        status="account_banned",
        error=message,
        technical_error=message,
        result=public_result,
    )
    try:
        if removed_from_pool:
            self._log(f"{message}；已从邮箱池移除", "error")
        else:
            detail = removal_error or "未找到对应的邮箱源行"
            self._log(
                f"{task_id} [检查 OpenAI 账号状态/account_banned] {message}；"
                f"邮箱池移除失败：{detail}；已标记损坏",
                "error",
            )
    except Exception:
        pass
    return None


def patched_task_state(host, self, task_id: str, **values):
    values = dict(values)
    status = str(values.get("status") or "").strip().lower()
    failure_statuses = set(host._task_progress_ext.TERMINAL_TASK_STATUSES).difference({"success", "stopped", "stopped_before_start"})
    if status in failure_statuses:
        task_result = values.get("result") if isinstance(values.get("result"), dict) else {}
        failure = host._classify_task_failure(
            task_id,
            task_result,
            values.get("technical_error") or values.get("error") or values.get("reason") or "",
            status=status,
        )
        values["failure"] = failure
        values["error"] = failure["public_message"]
        values["technical_error"] = failure["technical_summary"]
        if task_result:
            task_result = dict(task_result)
            task_result["failure"] = failure
            values["result"] = task_result
    if status == "success":
        host._clear_known_node_failure(task_id)
        auth_sessions = host._AUTH_SESSIONS
        if auth_sessions is not None:
            auth_sessions.clear(task_id)
    if status in host._task_progress_ext.TERMINAL_TASK_STATUSES and status != "success":
        try:
            failure = values.get("failure") if isinstance(values.get("failure"), dict) else {}
            task_record = getattr(self, "_tasks", {}).get(task_id, {}) if isinstance(getattr(self, "_tasks", {}), dict) else {}
            incident_id = host._DIAGNOSTIC_STORE.record({
                "level": "error" if status not in {"stopped", "stopped_before_start"} else "warn",
                "outcome": "error" if status not in {"stopped", "stopped_before_start"} else "stopped",
                "task_id": task_id,
                "batch_id": values.get("batch_id") or task_record.get("batch_id") or "",
                "chain": "ordinary",
                "workflow": "run",
                "driver": "sms_oauth",
                "subject_kind": "email" if (task_record.get("email") or task_record.get("account")) else "",
                "subject_ref": task_record.get("email") or task_record.get("account") or "",
                "subject_display": task_record.get("email") or task_record.get("account") or "",
                "node_code": failure.get("node_code") or values.get("stage") or "task_terminal",
                "node_label": failure.get("node_label") or "任务终态",
                "message": failure.get("public_message") or values.get("error") or values.get("reason") or "任务进入终态",
                "failure": failure,
            })
            if incident_id:
                values["incident_id"] = incident_id
        except Exception:
            pass
    result = host._ORIGINAL_TASK_STATE(self, task_id, **values)
    batch_manifest = host._RUN_BATCH_MANIFEST
    if batch_manifest is not None and status:
        try:
            batch_manifest.observe_task(task_id, status)
        except KeyError:
            pass
        except Exception as exc:
            try:
                self._log(
                    "[运行批次对账/run_batch_manifest] 任务状态落盘失败"
                    f"（{type(exc).__name__}）",
                    "error",
                )
            except Exception:
                pass
    if status == "authorizing":
        host._TASK_CONTEXT.set(str(task_id or ""))
    host._TASK_PROGRESS.observe_task_state(task_id, status)
    if status in host._task_progress_ext.TERMINAL_TASK_STATUSES:
        admission = getattr(self, "task_admission", None)
        observe_resources = getattr(admission, "observe_resource_ratio", None)
        if callable(observe_resources):
            resource_snapshot = host._transport_lifecycle_ext.process_resource_snapshot()
            if resource_snapshot.fd_ratio is not None:
                observe_resources(resource_snapshot.fd_ratio)
        # The 83.9% reference is a completed-attempt baseline.  User stops
        # and scheduler cancellations are not completed attempts and must not
        # lower the observed success rate.
        completed_attempt = status not in {
            "stopped",
            "stopped_before_start",
            "cancelled",
            "canceled",
        }
        rollback_event = (
            host._SMS_QUALITY_GUARD.observe_task(
                task_id,
                status,
                values.get("result"),
            )
            if completed_attempt
            else None
        )
        if rollback_event is not None:
            try:
                metrics = rollback_event.get("metrics") or {}
                reasons = "、".join(rollback_event.get("reasons") or ())
                self._log(
                    "[短信质量优化/sms_quality_optimization] 已自动关闭优化："
                    f"{reasons or 'rolling_window_regression'}；"
                    f"窗口 {metrics.get('window_tasks', 0)}，"
                    f"成功率 {metrics.get('success_rate', 0):.2%}",
                    "warn",
                )
            except Exception:
                pass
        progress = host._TASK_PROGRESS.progress(task_id)
        admission = getattr(self, "task_admission", None)
        if admission is not None:
            if status == "success":
                admission.report_success(task_id)
            else:
                if status == "account_banned" and host._is_fast_account_banned_progress(progress):
                    try:
                        admission.report_account_banned(task_id)
                    except Exception:
                        pass
                detail = (
                    values.get("technical_error")
                    or values.get("error")
                    or values.get("reason")
                    or ""
                )
                failure = values.get("failure") if isinstance(values.get("failure"), dict) else {}
                main_chain_pressure, pressure_failure = host._is_main_chain_pressure_source(
                    task_id,
                    detail,
                    failure=failure,
                )
                node_pressure = (
                    main_chain_pressure
                    and host._error_observability_ext.is_retryable_node_failure(detail)
                )
                protocol_pressure = (
                    main_chain_pressure
                    and (
                        host._is_rate_limited_failure(pressure_failure)
                        or host._sms_runtime_ext.is_protocol_pressure_error(detail)
                    )
                )
                if node_pressure or protocol_pressure:
                    host._report_task_pressure(
                        task_id,
                        detail,
                        node_code=(
                            failure.get("node_code")
                            if node_pressure
                            else "protocol_pressure"
                        ),
                        immediate=True,
                    )
                admission.report_failure(task_id)
    if status in host._task_progress_ext.TERMINAL_TASK_STATUSES:
        host._SMS_PROVIDER_REGISTRY.clear_task_attempt_counts(task_id)
    if status in host._task_progress_ext.TERMINAL_TASK_STATUSES and host._TASK_CONTEXT.get() == str(task_id or ""):
        host._TASK_CONTEXT.set("")
    return result


def patched_chain_event(
    host,
    events,
    state,
    *,
    detail="",
    extra=None,
    log_fn=None,
    tag="info",
):
    task_id = host._TASK_CONTEXT.get()
    if task_id:
        host._TASK_PROGRESS.observe_chain_state(task_id, state)
    if str(state or "").strip().upper() in {"SENTINEL_READY", "TOKEN_EXCHANGED", "DONE"}:
        host._clear_known_node_failure(task_id)
    if (
        str(state or "").strip().upper() == "RUNTIME_CONTEXT_ISSUE"
        and str(detail or "").strip().lower() == "warn:code_verifier_present"
    ):
        return host._ORIGINAL_CHAIN_EVENT(
            events,
            state,
            detail=detail,
            extra=extra,
            log_fn=None,
            tag=tag,
        )
    retrying_node = (
        str(state or "").strip().upper() == "FAILED"
        and host._error_observability_ext.is_retryable_node_failure(detail)
    )
    if not retrying_node:
        return host._ORIGINAL_CHAIN_EVENT(
            events,
            state,
            detail=detail,
            extra=extra,
            log_fn=log_fn,
            tag=tag,
        )

    host._report_task_pressure(task_id, detail)

    # Keep the FAILED event in the persisted chain for diagnosis. The chain
    # may immediately create a fresh bridge and continue, so emit a retry
    # notice instead of a terminal-looking red failure line.
    host._ORIGINAL_CHAIN_EVENT(
        events,
        state,
        detail=detail,
        extra=extra,
        log_fn=None,
        tag=tag,
    )
    retry_message = host._error_observability_ext.format_node_retry_log("", detail)
    if log_fn and retry_message:
        try:
            log_fn(retry_message, "warn")
        except TypeError:
            log_fn(retry_message)


def patched_chain_emit(host, log_fn, message, tag="info"):
    raw = str(message or "")
    if "[SentinelRunner]" in raw:
        if "token 生成成功" in raw:
            host._clear_known_node_failure(host._TASK_CONTEXT.get())
            coordinator = host._PROTOCOL_COORDINATOR
            if coordinator is not None:
                coordinator.observe_connectivity_result(
                    "sentinel.openai.com",
                    succeeded=True,
                    task_id=host._TASK_CONTEXT.get(),
                    proxy=host._CONNECTIVITY_PROXY,
                )
        elif "token 生成失败" in raw:
            coordinator = host._PROTOCOL_COORDINATOR
            if coordinator is not None:
                coordinator.observe_connectivity_result(
                    "sentinel.openai.com",
                    raw,
                    task_id=host._TASK_CONTEXT.get(),
                    proxy=host._CONNECTIVITY_PROXY,
                )
    if host._error_observability_ext.is_node_retry_log(raw):
        retry_message = host._error_observability_ext.format_node_retry_log("", raw)
        return host._ORIGINAL_CHAIN_EMIT(log_fn, retry_message, "warn")
    return host._ORIGINAL_CHAIN_EMIT(log_fn, message, tag)


def observe_runtime_fd_pressure(host, importer):
    admission = getattr(importer, "task_admission", None)
    observer = getattr(admission, "observe_resource_ratio", None)
    if not callable(observer):
        return None
    try:
        ratio = host._transport_lifecycle_ext.process_fd_ratio()
        return observer(ratio) if ratio is not None else None
    except Exception:
        return None


def notify_sms_balances(host, importer, statuses):
    """Forward sanitized preflight balances to the active run notification."""
    try:
        context = host._notification_context_for(importer)
        if not isinstance(context, dict) or not statuses:
            return ()
        service = context.get("service")
        observer = getattr(service, "observe_sms_balances", None)
        if not callable(observer):
            return ()
        aggregate, last_activity_at = host._notification_aggregate(importer, context)
        context["last_activity_at"] = last_activity_at or context.get(
            "last_activity_at",
            context.get("started_at", 0),
        )
        return observer(context.get("run_id"), aggregate, statuses)
    except Exception:
        # Notification delivery is advisory and must never abort registration.
        return ()




