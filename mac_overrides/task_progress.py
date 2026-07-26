"""Thread-safe task progress tracking for the recovered runtime."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
import time
from typing import Any, Callable


STAGE_GROUPS = ("queue", "oauth", "email", "phone", "sms", "finalizing")


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
        _stage("phone_acquiring", "正在获取手机号", "phone"),
        _stage("phone_submitting", "正在提交手机号", "phone"),
        _stage("sms_waiting", "等待短信验证码", "sms"),
        _stage("sms_verifying", "验证短信验证码", "sms"),
        _stage("finalizing_profile", "完善账号资料", "finalizing"),
        _stage("finalizing_callback", "获取 OAuth 回调", "finalizing"),
        _stage("finalizing_token", "交换 OAuth Token", "finalizing"),
        _stage("finalizing_upload", "上传账号凭据", "finalizing"),
        _stage("finalizing_nvtoken", "上传 nvtoken", "finalizing"),
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
    "CHAT_REQUIREMENTS_READY": "oauth_session",
    "OAUTH_STARTED": "oauth_authorize_node",
    "SENTINEL_READY": "email_login",
    "PASSWORD_REQUIRED": "email_password",
    "PASSWORD_VERIFIED": "email_login",
    "MFA_OTP_REQUIRED": "email_code_waiting",
    "MFA_OTP_VERIFIED": "email_code_verifying",
    "EMAIL_OTP_REQUIRED": "email_code_waiting",
    "EMAIL_OTP_VERIFIED": "email_code_verifying",
    "PHONE_REQUIRED": "phone_acquiring",
    "PHONE_SEND_REJECTED": "phone_acquiring",
    "PHONE_OTP_SENT": "sms_waiting",
    "PHONE_OTP_VERIFIED": "finalizing_profile",
    "CONSENT_REQUIRED": "finalizing_profile",
    "CALLBACK_RECEIVED": "finalizing_callback",
    "TOKEN_EXCHANGED": "finalizing_token",
    "UPLOADED": "finalizing_upload",
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
            self._tasks[key] = {
                "code": stage.code,
                "label": stage.label,
                "group": stage.group,
                "entered_at": timestamp,
                "finished_at": None,
            }
            return True

    def finish(self, task_id: Any, *, now: float | int | None = None) -> bool:
        key = str(task_id or "").strip()
        if not key:
            return False
        timestamp = self._timestamp(now)
        with self._lock:
            current = self._tasks.get(key)
            if current is None or current.get("finished_at") is not None:
                return False
            current["finished_at"] = timestamp
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
            return dict(value) if value is not None else None

    def decorate_runtime(self, runtime: dict[str, Any]) -> None:
        tasks = runtime.get("tasks")
        task_rows = tasks if isinstance(tasks, list) else []
        counts = {group: 0 for group in STAGE_GROUPS}
        running = bool(runtime.get("running"))
        now = self._timestamp()

        with self._lock:
            tracked = {task_id: dict(value) for task_id, value in self._tasks.items()}

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
                    }
            if progress is not None:
                task["progress"] = progress
            if not running or status in TERMINAL_TASK_STATUSES:
                continue
            group = str((progress or {}).get("group") or "queue")
            counts[group if group in counts else "queue"] += 1

        runtime["stage_counts"] = counts
