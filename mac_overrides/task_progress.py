"""Thread-safe task progress tracking for the recovered runtime."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import math
from threading import RLock
import time
from typing import Any, Callable


STAGE_GROUPS = ("queue", "oauth", "email", "phone", "sms", "free", "finalizing")

SEGMENTS = {
    "task_slot_waiting": "等待任务槽",
    "node_slot_waiting": "等待 Node 槽",
    "email_slot_waiting": "等待邮箱槽",
    "protocol_slot_waiting": "等待协议槽",
    "phone_slot_waiting": "等待手机号提交槽",
    "phone_submit_http": "手机号提交接口",
    "sentinel_refresh": "Sentinel 刷新",
    "sms_provider_ready": "接码平台确认订单",
}


@dataclass(frozen=True, slots=True)
class StageDefinition:
    code: str
    label: str
    group: str


def _stage(code: str, label: str, group: str) -> StageDefinition:
    return StageDefinition(code=code, label=label, group=group)


STAGES = {
    item.code: item
    for item in (
        _stage("queue_waiting", "排队等待", "queue"),
        _stage("queue_reserved", "邮箱已预留", "queue"),
        _stage("oauth_create_node", "OAuth 创建节点", "oauth"),
        _stage("oauth_session", "建立 OAuth 会话", "oauth"),
        _stage("oauth_authorize_node", "OAuth 授权节点", "oauth"),
        _stage("email_slot_waiting", "等待邮箱验证槽", "email"),
        _stage("email_login", "邮箱登录", "email"),
        _stage("email_password", "验证邮箱密码", "email"),
        _stage("email_code_waiting", "等待邮箱验证码", "email"),
        _stage("email_code_verifying", "验证邮箱验证码", "email"),
        _stage("mfa_otp_verifying", "验证 2FA 动态码", "email"),
        _stage("free_oauth_session", "Free OAuth 会话", "free"),
        _stage("free_email_identifier", "识别 Free 注册邮箱", "free"),
        _stage("free_email_password", "验证 Free 注册密码", "free"),
        _stage("free_email_otp_wait", "等待 Free 邮箱验证码", "free"),
        _stage("free_existing_login_password", "验证已有 Free 账号密码", "free"),
        _stage("free_existing_login_otp", "等待已有 Free 账号登录验证码", "free"),
        _stage("free_email_otp_validate", "验证 Free 邮箱验证码", "free"),
        _stage("free_account_create", "创建 Free 账号", "free"),
        _stage("free_oauth_callback", "Free OAuth 回调", "free"),
        _stage("free_access_token", "获取 Free access token", "free"),
        _stage("free_plan_check", "查询 Free 套餐资格", "free"),
        _stage("free_twofa_enroll", "注册 Free 账号 2FA", "free"),
        _stage("free_twofa_activate", "激活 Free 账号 2FA", "free"),
        _stage("free_twofa_reauth_csrf", "2FA 重认证 CSRF", "free"),
        _stage("free_twofa_reauth_signin", "启动 2FA 重认证", "free"),
        _stage("free_twofa_reauth_authorize", "打开 2FA 重认证授权页面", "free"),
        _stage("free_twofa_otp_wait", "等待 2FA 邮箱验证码", "free"),
        _stage("free_twofa_otp_validate", "验证 2FA 邮箱验证码", "free"),
        _stage("free_twofa_reauth_callback", "刷新 2FA 重认证会话", "free"),
        _stage("free_password_eligibility", "检查 Free 账号密码资格", "free"),
        _stage("free_password_reauth_csrf", "密码设置重认证 CSRF", "free"),
        _stage("free_password_reauth_signin", "启动密码设置重认证", "free"),
        _stage("free_password_reauth_authorize", "打开密码设置授权页面", "free"),
        _stage("free_password_otp_wait", "等待密码设置邮箱验证码", "free"),
        _stage("free_password_otp_validate", "验证密码设置邮箱验证码", "free"),
        _stage("free_password_enroll", "打开新密码页面", "free"),
        _stage("free_password_add", "提交 Free 账号密码", "free"),
        _stage("free_password_callback", "刷新密码设置会话", "free"),
        _stage("free_result_save", "保存 Free 注册结果", "free"),
        _stage("phone_submitting", "正在提交手机号", "phone"),
        _stage("phone_acquiring", "正在获取手机号", "phone"),
        _stage("sms_waiting", "等待短信验证码", "sms"),
        _stage("sms_verifying", "验证短信验证码", "sms"),
        _stage("finalizing_profile", "完善账号资料", "finalizing"),
        _stage("finalizing_callback", "获取 OAuth 回调", "finalizing"),
        _stage("finalizing_token", "交换 OAuth Token", "finalizing"),
        _stage("finalizing_upload", "上传账号凭据", "finalizing"),
        _stage("finalizing_save", "保存任务结果", "finalizing"),
    )
}


TASK_STATUS_STAGES = {
    "queued": "queue_waiting",
    "leased": "queue_reserved",
    "authorizing": "oauth_create_node",
    "waiting_auto_email_slot": "email_slot_waiting",
    "waiting_manual_login_turn": "email_slot_waiting",
    "reading_email_baseline": "email_login",
    "email_baseline_ready": "email_login",
    "email_login_started": "email_login",
    "waiting_auto_email_code": "email_code_waiting",
    "waiting_gptmail_email_code": "email_code_waiting",
    "waiting_manual_email_code": "email_code_waiting",
    "email_code_submitted": "email_code_verifying",
}


CHAIN_STATE_STAGES = {
    "START": "oauth_create_node",
    "CHAT_REQUIREMENTS_READY": "oauth_authorize_node",
    "OAUTH_STARTED": "oauth_authorize_node",
    "SENTINEL_READY": "email_login",
    "PASSWORD_REQUIRED": "email_password",
    "PASSWORD_VERIFIED": "email_login",
    "MFA_OTP_REQUIRED": "email_code_waiting",
    "MFA_OTP_VERIFIED": "mfa_otp_verifying",
    "EMAIL_OTP_REQUIRED": "email_code_waiting",
    "EMAIL_OTP_VERIFIED": "phone_acquiring",
    "PHONE_REQUIRED": "phone_acquiring",
    "PHONE_SEND_REJECTED": "phone_submitting",
    "PHONE_OTP_SENT": "sms_waiting",
    "PHONE_OTP_VERIFIED": "finalizing_profile",
    "CONSENT_REQUIRED": "finalizing_callback",
    "CALLBACK_RECEIVED": "finalizing_token",
    "TOKEN_EXCHANGED": "finalizing_upload",
    "UPLOADED": "finalizing_save",
    "UPLOAD_SKIPPED": "finalizing_save",
    "DONE": "finalizing_save",
}


TERMINAL_TASK_STATUSES = frozenset(
    {
        "success",
        "failed",
        "stopped",
        "stopped_before_start",
        "retryable_infra",
        "retryable_email",
        "repair_pending",
        "email_damaged",
        "account_banned",
        "twofa_pending",
    }
)


def stage_for_task_status(status: Any) -> str | None:
    return TASK_STATUS_STAGES.get(str(status or "").strip().lower())


def stage_for_chain_state(state: Any) -> str | None:
    return CHAIN_STATE_STAGES.get(str(state or "").strip().upper())


def is_active_progress(progress: Any, status: Any = "") -> bool:
    if not isinstance(progress, dict):
        return False
    normalized_status = str(status or "").strip().lower()
    return progress.get("finished_at") is None and normalized_status not in TERMINAL_TASK_STATUSES


class TaskProgressTracker:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = RLock()
        self._tasks: dict[str, dict[str, Any]] = {}

    def _timestamp(self, now: float | int | None = None) -> int:
        return int(self._clock() if now is None else now)

    def reset(self) -> None:
        with self._lock:
            self._tasks.clear()

    def set_stage(self, task_id: Any, code: str, *, now: float | int | None = None) -> bool:
        key = str(task_id or "").strip()
        stage = STAGES.get(str(code or ""))
        if not key or stage is None:
            return False
        timestamp = self._timestamp(now)
        with self._lock:
            current = self._tasks.get(key)
            if current and current.get("finished_at") is not None:
                return False
            if current and current.get("code") == stage.code:
                return False
            if current is None:
                current = {
                    "code": stage.code,
                    "label": stage.label,
                    "group": stage.group,
                    "entered_at": timestamp,
                    "finished_at": None,
                    "timing": {
                        "started_at": timestamp,
                        "queued_at": timestamp,
                        "execution_started_at": None,
                        "finished_at": None,
                        "elapsed_seconds": 0,
                        "queue_elapsed_seconds": 0,
                        "execution_elapsed_seconds": 0,
                        "stages": [],
                    },
                }
                self._tasks[key] = current
            else:
                self._close_current_stage(current, timestamp)
                current.update(
                    {
                        "code": stage.code,
                        "label": stage.label,
                        "group": stage.group,
                        "entered_at": timestamp,
                    }
                )
            self._record_stage_visit(current, stage)
            return True

    def mark_execution_started(
        self,
        task_id: Any,
        *,
        now: float | int | None = None,
    ) -> bool:
        key = str(task_id or "").strip()
        if not key:
            return False
        timestamp = self._timestamp(now)
        with self._lock:
            current = self._tasks.get(key)
            if current is None or current.get("finished_at") is not None:
                return False
            timing = current.setdefault("timing", {})
            if timing.get("execution_started_at") is not None:
                return False
            queued_at = int(
                timing.get("queued_at")
                or timing.get("started_at")
                or current.get("entered_at")
                or timestamp
            )
            timing["queued_at"] = queued_at
            timing["execution_started_at"] = timestamp
            timing["queue_elapsed_seconds"] = max(0, timestamp - queued_at)
            timing["execution_elapsed_seconds"] = 0
            return True

    @staticmethod
    def _stage_rows(current: dict[str, Any]) -> list[dict[str, Any]]:
        timing = current.setdefault("timing", {})
        rows = timing.setdefault("stages", [])
        return rows if isinstance(rows, list) else []

    def _record_stage_visit(
        self,
        current: dict[str, Any],
        stage: StageDefinition,
    ) -> None:
        rows = self._stage_rows(current)
        row = next((item for item in rows if item.get("code") == stage.code), None)
        if row is None:
            rows.append(
                {
                    "code": stage.code,
                    "label": stage.label,
                    "group": stage.group,
                    "elapsed_seconds": 0,
                    "visits": 1,
                }
            )
        else:
            row["visits"] = max(0, int(row.get("visits") or 0)) + 1

    def record_segment(
        self,
        task_id: Any,
        code: str,
        elapsed_seconds: Any,
    ) -> bool:
        key = str(task_id or "").strip()
        segment_code = str(code or "").strip()
        label = SEGMENTS.get(segment_code)
        if not key or label is None:
            return False
        try:
            elapsed = float(elapsed_seconds)
        except (TypeError, ValueError):
            return False
        if not math.isfinite(elapsed):
            return False
        elapsed = max(0.0, elapsed)
        with self._lock:
            current = self._tasks.get(key)
            if current is None or current.get("finished_at") is not None:
                return False
            timing = current.setdefault("timing", {})
            segments = timing.setdefault("segments", [])
            if not isinstance(segments, list):
                segments = []
                timing["segments"] = segments
            row = next(
                (
                    item
                    for item in segments
                    if isinstance(item, dict) and item.get("code") == segment_code
                ),
                None,
            )
            if row is None:
                segments.append(
                    {
                        "code": segment_code,
                        "label": label,
                        "elapsed_seconds": round(elapsed, 3),
                        "visits": 1,
                    }
                )
            else:
                row["elapsed_seconds"] = round(
                    max(0.0, float(row.get("elapsed_seconds") or 0.0)) + elapsed,
                    3,
                )
                row["visits"] = max(0, int(row.get("visits") or 0)) + 1
            return True

    def _close_current_stage(self, current: dict[str, Any], timestamp: int) -> None:
        entered_at = int(current.get("entered_at") or timestamp)
        elapsed = max(0, timestamp - entered_at)
        for row in self._stage_rows(current):
            if row.get("code") == current.get("code"):
                row["elapsed_seconds"] = max(
                    0,
                    int(row.get("elapsed_seconds") or 0),
                ) + elapsed
                break

    def _public_progress(self, current: dict[str, Any], timestamp: int) -> dict[str, Any]:
        value = copy.deepcopy(current)
        timing = value.get("timing") if isinstance(value.get("timing"), dict) else {}
        started_at = int(timing.get("started_at") or value.get("entered_at") or timestamp)
        queued_at = int(timing.get("queued_at") or started_at)
        execution_started_at = timing.get("execution_started_at")
        finished_at = timing.get("finished_at")
        end = int(finished_at) if finished_at is not None else timestamp
        timing["elapsed_seconds"] = max(0, end - started_at)
        timing["queued_at"] = queued_at
        timing["queue_elapsed_seconds"] = max(
            0,
            (int(execution_started_at) if execution_started_at is not None else end)
            - queued_at,
        )
        timing["execution_elapsed_seconds"] = (
            max(0, end - int(execution_started_at))
            if execution_started_at is not None
            else 0
        )
        if finished_at is None:
            current_elapsed = max(0, timestamp - int(value.get("entered_at") or timestamp))
            for row in timing.get("stages") or []:
                if row.get("code") == value.get("code"):
                    row["elapsed_seconds"] = max(
                        0,
                        int(row.get("elapsed_seconds") or 0),
                    ) + current_elapsed
                    break
        value["timing"] = timing
        return value

    def finish(self, task_id: Any, *, now: float | int | None = None) -> bool:
        key = str(task_id or "").strip()
        if not key:
            return False
        timestamp = self._timestamp(now)
        with self._lock:
            current = self._tasks.get(key)
            if current is None or current.get("finished_at") is not None:
                return False
            self._close_current_stage(current, timestamp)
            current["finished_at"] = timestamp
            timing = current.get("timing") if isinstance(current.get("timing"), dict) else {}
            timing["finished_at"] = timestamp
            timing["elapsed_seconds"] = max(
                0,
                timestamp - int(timing.get("started_at") or timestamp),
            )
            queued_at = int(timing.get("queued_at") or timing.get("started_at") or timestamp)
            execution_started_at = timing.get("execution_started_at")
            timing["queue_elapsed_seconds"] = max(
                0,
                (int(execution_started_at) if execution_started_at is not None else timestamp)
                - queued_at,
            )
            timing["execution_elapsed_seconds"] = (
                max(0, timestamp - int(execution_started_at))
                if execution_started_at is not None
                else 0
            )
            current["timing"] = timing
            return True

    def observe_task_state(self, task_id: Any, status: Any, *, now: float | int | None = None) -> bool:
        normalized = str(status or "").strip().lower()
        if normalized in TERMINAL_TASK_STATUSES:
            return self.finish(task_id, now=now)
        code = stage_for_task_status(normalized)
        return self.set_stage(task_id, code, now=now) if code else False

    def observe_chain_state(self, task_id: Any, state: Any, *, now: float | int | None = None) -> bool:
        code = stage_for_chain_state(state)
        return self.set_stage(task_id, code, now=now) if code else False

    def progress(self, task_id: Any) -> dict[str, Any] | None:
        key = str(task_id or "").strip()
        with self._lock:
            value = self._tasks.get(key)
            return self._public_progress(value, self._timestamp()) if value is not None else None

    def decorate_runtime(self, runtime: dict[str, Any]) -> None:
        tasks = runtime.get("tasks")
        task_rows = tasks if isinstance(tasks, list) else []
        counts = {group: 0 for group in STAGE_GROUPS}
        running = bool(runtime.get("running"))
        now = self._timestamp()

        with self._lock:
            tracked = {
                task_id: self._public_progress(value, now)
                for task_id, value in self._tasks.items()
            }

        for task in task_rows:
            if not isinstance(task, dict):
                continue
            task_id = str(task.get("task_id") or "").strip()
            status = str(task.get("status") or "").strip().lower()
            progress = tracked.get(task_id)
            if progress is None and status not in TERMINAL_TASK_STATUSES:
                fallback_code = stage_for_task_status(status)
                fallback = STAGES.get(fallback_code or "")
                if fallback is not None:
                    progress = {
                        "code": fallback.code,
                        "label": fallback.label,
                        "group": fallback.group,
                        "entered_at": int(task.get("updated_at") or task.get("created_at") or now),
                        "finished_at": None,
                        "timing": {
                            "started_at": int(task.get("created_at") or task.get("updated_at") or now),
                            "queued_at": int(task.get("created_at") or task.get("updated_at") or now),
                            "execution_started_at": None,
                            "finished_at": None,
                            "elapsed_seconds": max(
                                0,
                                now - int(task.get("created_at") or task.get("updated_at") or now),
                            ),
                            "queue_elapsed_seconds": max(
                                0,
                                now - int(task.get("created_at") or task.get("updated_at") or now),
                            ),
                            "execution_elapsed_seconds": 0,
                            "stages": [
                                {
                                    "code": fallback.code,
                                    "label": fallback.label,
                                    "group": fallback.group,
                                    "elapsed_seconds": max(
                                        0,
                                        now - int(task.get("updated_at") or task.get("created_at") or now),
                                    ),
                                    "visits": 1,
                                }
                            ],
                        },
                    }
            if progress is not None:
                task["progress"] = progress
            if not running or status in TERMINAL_TASK_STATUSES:
                continue
            group = str((progress or {}).get("group") or "queue")
            counts[group if group in counts else "queue"] += 1

        runtime["stage_counts"] = counts
