"""Refresh-safe background operations for mailbox administration."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
import math
import re
import threading
import time
from typing import Any
import uuid


MAILBOX_OPERATION_KINDS = frozenset({"quota", "openai_test"})
_COUNTER_KEYS = (
    "succeeded",
    "failed",
    "skipped",
    "tested",
    "rate_limited",
    "not_ready",
)
_ERROR_CODE_PATTERN = re.compile(r"^[a-z0-9_]{1,80}$")
_STATUS_KIND_PATTERN = re.compile(r"^[a-z0-9_]{1,40}$")
_KIND_LABELS = {
    "quota": "OpenAI 额度批量查询",
    "openai_test": "OpenAI 批量测试",
}


class MailboxOperationRequestError(ValueError):
    """A public request validation error raised before a worker starts."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class MailboxOperationAlreadyRunning(RuntimeError):
    """Raised when a different mailbox batch is already active."""

    def __init__(self, operation: Mapping[str, Any]) -> None:
        self.operation = dict(operation)
        super().__init__("已有邮箱批量操作正在执行")


@dataclass
class _MailboxOperation:
    job_id: str
    kind: str
    bindings: tuple[tuple[str, int], ...]
    created_at: float
    updated_at: float
    status: str = "running"
    completed: int = 0
    counters: dict[str, int] = field(
        default_factory=lambda: {key: 0 for key in _COUNTER_KEYS}
    )
    row_updates: dict[tuple[str, int], dict[str, Any]] = field(default_factory=dict)
    finished_at: float | None = None
    node_code: str = ""
    node_label: str = ""
    error_code: str = ""
    error: str = ""
    done: threading.Event = field(default_factory=threading.Event, repr=False)


def _safe_count(value: Any, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(parsed, maximum))


def _safe_error_code(value: Any, fallback: str) -> str:
    code = str(value or "").strip().lower()
    return code if _ERROR_CODE_PATTERN.fullmatch(code) else fallback


def _safe_number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return int(number) if number.is_integer() else number


def _safe_timestamp(value: Any) -> int | None:
    number = _safe_number(value)
    return max(0, int(number)) if number is not None else None


def _public_quota_window(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    result = {
        field: _safe_number(value.get(field))
        for field in (
            "remaining_percent",
            "limit_window_seconds",
            "reset_at",
            "reset_after_seconds",
            "queried_at",
        )
    }
    status = str(value.get("status") or "").strip().lower()
    if status in {"available", "exhausted"}:
        result["status"] = status
    return result if result.get("remaining_percent") is not None else None


def _openai_status_label(kind: str, status_code: int | None) -> str:
    if status_code == 200 or kind == "healthy":
        return "200 健康"
    if status_code == 401 or kind == "unauthorized":
        return "401 Token失效"
    if status_code == 404:
        return "404 OpenAI 接口不存在或模型不支持"
    if status_code == 429 or kind == "rate_limited":
        return "429 额度受限"
    labels = {
        "credentials_missing": "缺少 OpenAI OAuth 凭据",
        "network_error": "网络错误",
        "not_ready": "未上传",
        "remote_disconnected": "远端连接中断",
        "timeout": "超时",
        "unlinked": "未关联",
        "untested": "未测试",
    }
    if kind in labels:
        return labels[kind]
    if status_code is not None:
        return f"HTTP {status_code}"
    return "OpenAI 测试失败"


def _public_row_update(kind: str, value: Any) -> dict[str, Any] | None:
    """Whitelist one completed row; never retain worker-provided free text."""

    if not isinstance(value, Mapping):
        return None
    row_id = str(value.get("row_id") or "").strip().lower()
    try:
        line_no = int(value.get("line_no") or 0)
    except (TypeError, ValueError):
        return None
    if not row_id or len(row_id) > 256 or line_no <= 0:
        return None
    result: dict[str, Any] = {"row_id": row_id, "line_no": line_no}

    if kind == "quota":
        status = str(value.get("status") or "").strip().lower()
        result["quota_status"] = status if status in {"ok", "error"} else "error"
        result["quota_queried_at"] = _safe_timestamp(value.get("queried_at"))
        result["quota_5h"] = _public_quota_window(value.get("quota_5h"))
        result["quota_7d"] = _public_quota_window(value.get("quota_7d"))
        if result["quota_status"] == "error":
            code = _safe_error_code(value.get("code"), "openai_quota_failed")
            result["quota_error_code"] = code
            result["quota_error"] = (
                "查询 OpenAI 额度失败：网络请求失败，请检查当前显式代理"
                if "network" in code or "timeout" in code
                else f"查询 OpenAI 额度失败（错误码 {code}）"
            )
        else:
            result["quota_error"] = ""
        return result

    raw_status = value.get("sub2_status")
    if not isinstance(raw_status, Mapping):
        return None
    status_kind = str(raw_status.get("kind") or "").strip().lower()
    if not _STATUS_KIND_PATTERN.fullmatch(status_kind):
        status_kind = "untested"
    raw_code = _safe_number(raw_status.get("status_code", raw_status.get("code")))
    status_code = int(raw_code) if raw_code is not None and 100 <= raw_code <= 599 else None
    is_abnormal = status_code == 401 or status_kind == "unauthorized"
    is_rate_limited = status_code == 429 or status_kind == "rate_limited"
    is_test_failure = (
        not is_abnormal
        and not is_rate_limited
        and status_kind not in {"healthy", "unlinked", "not_linked", "not_ready", "untested"}
    )
    result["sub2_status"] = {
        "kind": status_kind,
        "status_code": status_code,
        "label": _openai_status_label(status_kind, status_code),
        "tested_at": _safe_timestamp(raw_status.get("tested_at")),
        "is_error": is_abnormal or is_test_failure,
        "is_abnormal": is_abnormal,
        "is_test_failure": is_test_failure,
        "needs_rerun": status_code in {401, 404} or status_kind in {"unauthorized", "not_found"},
        "linked": status_kind not in {"unlinked", "not_linked", "not_ready"},
    }
    return result


def _chunk_counters(kind: str, result: Mapping[str, Any], chunk_size: int) -> dict[str, int]:
    counters = {key: 0 for key in _COUNTER_KEYS}
    if kind == "quota":
        counters["succeeded"] = _safe_count(result.get("queried"), chunk_size)
        counters["failed"] = _safe_count(result.get("failed"), chunk_size)
        counters["skipped"] = _safe_count(result.get("skipped"), chunk_size)
        return counters

    counters["tested"] = _safe_count(result.get("tested"), chunk_size)
    counters["succeeded"] = _safe_count(result.get("healthy"), chunk_size)
    counters["failed"] = _safe_count(
        result.get("failed", result.get("test_failures", result.get("test_failed"))),
        chunk_size,
    )
    counters["rate_limited"] = _safe_count(result.get("rate_limited"), chunk_size)
    counters["not_ready"] = _safe_count(result.get("not_ready"), chunk_size)
    counters["skipped"] = counters["not_ready"]
    return counters


class MailboxBatchOperationManager:
    """Run one bounded mailbox batch while exposing only redacted aggregates."""

    def __init__(
        self,
        *,
        chunk_size: int = 5,
        max_rows: int = 10_000,
        terminal_ttl_seconds: float = 6 * 60 * 60,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self._chunk_size = max(1, int(chunk_size))
        self._max_rows = max(1, int(max_rows))
        self._terminal_ttl_seconds = max(0.0, float(terminal_ttl_seconds))
        self._now_fn = now_fn
        self._lock = threading.RLock()
        self._current: _MailboxOperation | None = None
        self._last_created_at = 0.0

    def start(
        self,
        kind: str,
        rows: Any,
        worker: Callable[[dict[str, Any]], Mapping[str, Any]],
    ) -> tuple[dict[str, Any], bool]:
        normalized_kind = str(kind or "").strip().lower()
        if normalized_kind not in MAILBOX_OPERATION_KINDS:
            raise MailboxOperationRequestError(
                "mailbox_operation_kind_invalid",
                "不支持的邮箱批量操作",
            )
        bindings = self._normalize_bindings(rows)
        now = float(self._now_fn())
        with self._lock:
            self._expire_locked(now)
            active = self._current
            if active is not None and active.status == "running":
                if active.kind == normalized_kind and active.bindings == bindings:
                    return self._public(active), False
                raise MailboxOperationAlreadyRunning(self._public(active))
            created_at = max(
                now,
                math.nextafter(self._last_created_at, math.inf),
            )
            self._last_created_at = created_at
            operation = _MailboxOperation(
                job_id=uuid.uuid4().hex,
                kind=normalized_kind,
                bindings=bindings,
                created_at=created_at,
                updated_at=created_at,
            )
            self._current = operation

        thread = threading.Thread(
            target=self._run,
            args=(operation, worker),
            name=f"mailbox-{normalized_kind}-{operation.job_id[:8]}",
            daemon=True,
        )
        try:
            thread.start()
        except Exception:
            self._fail(operation, "mailbox_operation_thread_failed")
        with self._lock:
            return self._public(operation), True

    def snapshot(self) -> dict[str, Any] | None:
        with self._lock:
            self._expire_locked(float(self._now_fn()))
            return self._public(self._current) if self._current is not None else None

    def wait(self, job_id: str, timeout: float | None = None) -> dict[str, Any] | None:
        with self._lock:
            operation = self._current
            if operation is None or operation.job_id != str(job_id or ""):
                return None
            done = operation.done
        done.wait(timeout)
        with self._lock:
            return self._public(operation)

    def _normalize_bindings(self, rows: Any) -> tuple[tuple[str, int], ...]:
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)) or not rows:
            raise MailboxOperationRequestError(
                "mailbox_operation_rows_required",
                "请先选择要处理的邮箱",
            )
        if len(rows) > self._max_rows:
            raise MailboxOperationRequestError(
                "mailbox_operation_batch_too_large",
                f"单次最多处理 {self._max_rows} 个邮箱",
            )
        bindings: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()
        for item in rows:
            if not isinstance(item, Mapping):
                raise MailboxOperationRequestError(
                    "mailbox_operation_rows_invalid",
                    "邮箱批量操作参数无效",
                )
            row_id = str(item.get("row_id") or "").strip().lower()
            try:
                line_no = int(item.get("line_no") or 0)
            except (TypeError, ValueError):
                line_no = 0
            binding = (row_id, line_no)
            if not row_id or len(row_id) > 256 or line_no <= 0 or binding in seen:
                raise MailboxOperationRequestError(
                    "mailbox_operation_rows_invalid",
                    "邮箱批量操作参数无效",
                )
            seen.add(binding)
            bindings.append(binding)
        return tuple(bindings)

    def _expire_locked(self, now: float) -> None:
        operation = self._current
        if (
            operation is not None
            and operation.status != "running"
            and operation.finished_at is not None
            and now - operation.finished_at >= self._terminal_ttl_seconds
        ):
            self._current = None

    def _run(
        self,
        operation: _MailboxOperation,
        worker: Callable[[dict[str, Any]], Mapping[str, Any]],
    ) -> None:
        try:
            for offset in range(0, len(operation.bindings), self._chunk_size):
                chunk = operation.bindings[offset : offset + self._chunk_size]
                reported: set[tuple[str, int]] = set()

                def on_row_completed(
                    update: Any,
                    *,
                    _chunk: tuple[tuple[str, int], ...] = chunk,
                    _reported: set[tuple[str, int]] = reported,
                ) -> None:
                    public_update = _public_row_update(operation.kind, update)
                    if public_update is None:
                        return
                    row_id = public_update["row_id"]
                    line_no = public_update["line_no"]
                    binding = (row_id, line_no)
                    with self._lock:
                        if (
                            operation.status != "running"
                            or binding not in _chunk
                            or binding in _reported
                        ):
                            return
                        _reported.add(binding)
                        operation.row_updates[binding] = public_update
                        operation.completed = min(
                            len(operation.bindings),
                            operation.completed + 1,
                        )
                        operation.updated_at = max(
                            operation.updated_at,
                            float(self._now_fn()),
                        )

                payload = {
                    "rows": [
                        {"row_id": row_id, "line_no": line_no}
                        for row_id, line_no in chunk
                    ],
                    "_on_row_completed": on_row_completed,
                }
                try:
                    result = worker(payload)
                except Exception:
                    self._fail(operation, "mailbox_operation_worker_failed")
                    return
                if not isinstance(result, Mapping):
                    self._fail(operation, "mailbox_operation_result_invalid")
                    return
                if not result.get("ok"):
                    self._fail(
                        operation,
                        _safe_error_code(
                            result.get("code"),
                            "mailbox_operation_batch_failed",
                        ),
                    )
                    return
                counters = _chunk_counters(operation.kind, result, len(chunk))
                with self._lock:
                    operation.completed = min(
                        len(operation.bindings),
                        operation.completed + len(chunk) - len(reported),
                    )
                    for key, value in counters.items():
                        operation.counters[key] += value
                    operation.updated_at = max(
                        operation.updated_at,
                        float(self._now_fn()),
                    )
            with self._lock:
                operation.status = "completed"
                operation.finished_at = max(
                    operation.updated_at,
                    float(self._now_fn()),
                )
                operation.updated_at = operation.finished_at
                operation.done.set()
        finally:
            self._fail(operation, "mailbox_operation_worker_failed")

    def _fail(self, operation: _MailboxOperation, error_code: str) -> None:
        label = _KIND_LABELS.get(operation.kind, "邮箱批量操作")
        safe_code = _safe_error_code(error_code, "mailbox_operation_batch_failed")
        with self._lock:
            if operation.status != "running":
                return
            operation.status = "failed"
            operation.node_code = "mailbox_batch_operation"
            operation.node_label = "邮箱后台批量操作"
            operation.error_code = safe_code
            operation.error = f"{label}失败：后台批次未完成（错误码 {safe_code}）"
            operation.finished_at = max(
                operation.updated_at,
                float(self._now_fn()),
            )
            operation.updated_at = operation.finished_at
            operation.done.set()

    @staticmethod
    def _public(operation: _MailboxOperation) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "job_id": operation.job_id,
            "kind": operation.kind,
            "status": operation.status,
            "total": len(operation.bindings),
            "completed": operation.completed,
            "created_at": operation.created_at,
            "updated_at": operation.updated_at,
            "finished_at": operation.finished_at,
            "row_updates": deepcopy(list(operation.row_updates.values())),
            **{key: int(operation.counters.get(key) or 0) for key in _COUNTER_KEYS},
        }
        if operation.error:
            payload.update(
                node_code=operation.node_code,
                node_label=operation.node_label,
                error_code=operation.error_code,
                error=operation.error,
            )
        return payload


class MailboxBatchRouteController:
    """Keep mailbox list and batch HTTP behavior out of the route assembly module."""

    def __init__(
        self,
        *,
        module: Any,
        mailbox_admin: Any,
        public_state: Callable[[], Mapping[str, Any]],
        logs: Any,
        manager: MailboxBatchOperationManager | None = None,
    ) -> None:
        self.module = module
        self.mailbox_admin = mailbox_admin
        self.public_state = public_state
        self.logs = logs
        self.manager = manager or MailboxBatchOperationManager()

    def mailboxes(self):
        return self.module.jsonify(self.mailbox_payload())

    def mailbox_payload(self) -> dict[str, Any]:
        listed = self.mailbox_admin.list_mailboxes()
        payload = dict(listed) if isinstance(listed, Mapping) else {
            "ok": False,
            "counts": {},
            "rows": [],
        }
        payload["operation"] = self.manager.snapshot()
        return payload

    def openai_test(self):
        data, error = self._request_data()
        if error is not None:
            return error
        tester = getattr(self.mailbox_admin, "openai_test", None)
        worker = tester if callable(tester) else self.mailbox_admin.sub2_test
        if data.get("background") is True:
            return self._start_background("openai_test", data, worker)
        try:
            result = worker(data)
            if not isinstance(result, Mapping):
                return self.module.jsonify(
                    ok=False,
                    error="本机 OpenAI 批量连接测试失败",
                ), 502
            response = dict(result)
            if response.get("ok"):
                response["mailboxes"] = self.mailbox_payload()
                response["state"] = self.public_state()
                return self.module.jsonify(response)
            return self.module.jsonify(response), self._openai_error_status(response)
        except Exception:
            self.logs.add("本机 OpenAI 批量连接测试失败", "error")
            return self.module.jsonify(
                ok=False,
                error="本机 OpenAI 批量连接测试失败",
            ), 502

    def quota(self):
        data, error = self._request_data()
        if error is not None:
            return error
        worker = self.mailbox_admin.query_openai_quotas
        if data.get("background") is True:
            return self._start_background("quota", data, worker)
        try:
            result = worker(data)
            if not isinstance(result, Mapping):
                return self.module.jsonify(ok=False, error="OpenAI 额度查询失败"), 502
            if result.get("ok"):
                return self.module.jsonify(result)
            response = dict(result)
            code = str(response.get("code") or "")
            status = 409 if code == "mailbox_rows_stale" else 400
            if code.startswith("openai_quota_"):
                status = 503
            return self.module.jsonify(response), status
        except Exception:
            self.logs.add("邮箱管理 OpenAI 额度查询失败", "error")
            return self.module.jsonify(
                ok=False,
                code="openai_quota_failed",
                error="查询 OpenAI 额度失败：未返回可用诊断",
            ), 502

    def _request_data(self) -> tuple[dict[str, Any], Any | None]:
        data = self.module.request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return {}, (self.module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400)
        return data, None

    def _start_background(
        self,
        kind: str,
        data: Mapping[str, Any],
        worker: Callable[[dict[str, Any]], Mapping[str, Any]],
    ):
        try:
            operation, created = self.manager.start(kind, data.get("rows"), worker)
            return self.module.jsonify(
                ok=True,
                background=True,
                created=created,
                operation=operation,
            ), 202
        except MailboxOperationRequestError as exc:
            return self.module.jsonify(
                ok=False,
                code=exc.code,
                error=exc.public_message,
            ), 400
        except MailboxOperationAlreadyRunning as exc:
            return self.module.jsonify(
                ok=False,
                code="mailbox_operation_already_running",
                error="已有邮箱批量操作正在执行，请等待完成",
                operation=exc.operation,
            ), 409

    @staticmethod
    def _openai_error_status(response: Mapping[str, Any]) -> int:
        code = str(response.get("code") or "")
        if code == "mailbox_rows_stale":
            return 409
        if code.startswith("sub2_admin_") or code in {
            "sub2_batch_failed",
            "openai_test_batch_failed",
        }:
            return 502
        if code in {"sub2_not_configured", "openai_test_not_configured"}:
            return 503
        return 400


__all__ = [
    "MailboxBatchOperationManager",
    "MailboxBatchRouteController",
    "MailboxOperationAlreadyRunning",
    "MailboxOperationRequestError",
]
