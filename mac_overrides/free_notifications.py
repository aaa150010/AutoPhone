"""Credential-safe aggregate notifications for Free registration batches.

The ordinary notification queue remains the transport boundary.  This adapter
only adds a Free-specific summary payload and never receives mailbox URLs,
passwords, tokens, OTPs, TOTP secrets, or proxy credentials.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from email.message import EmailMessage
import re
import threading
import time
from typing import Any

try:
    from .notification_queue import NotificationQueue
    from .run_notifications import SmtpNotificationSender, validate_email_notification
except ImportError:  # pragma: no cover
    from notification_queue import NotificationQueue  # type: ignore[no-redef]
    from run_notifications import SmtpNotificationSender, validate_email_notification  # type: ignore[no-redef]


_BATCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_INCIDENT_RE = re.compile(r"^LOG-[A-Za-z0-9._:-]{1,80}$")
_FREE_DRIVER_LABELS = {
    "protocol": "协议",
    "camoufox": "Camoufox",
}


def _safe_free_driver(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in _FREE_DRIVER_LABELS else "unknown"


def _free_chain_display(drivers: Any) -> str:
    values = {
        _safe_free_driver(item)
        for item in (drivers or ())
    }
    if not values:
        values = {"unknown"}
    labels = [
        _FREE_DRIVER_LABELS.get(driver, "未知链路")
        for driver in ("protocol", "camoufox", "unknown")
        if driver in values
    ]
    return " + ".join(labels)


def _mask_email(value: Any) -> str:
    raw = str(value or "").strip()
    local, at, domain = raw.partition("@")
    if not at or not local or not domain:
        return "<邮箱>"
    return f"{local[:1]}***@{domain[:80]}"


def summarize_free_batch(tasks: Any, *, batch_id: str = "") -> dict[str, Any]:
    raw_rows = [item for item in (tasks or ()) if isinstance(item, Mapping)]
    # A 2FA/rerun child is a continuation of the same mailbox account.  Batch
    # summaries should report the latest outcome once, while retaining each
    # task's incident in the diagnostic store.  Prefer the newest timestamp,
    # then the explicit retry attempt when clocks have only second precision.
    latest: dict[str, Mapping[str, Any]] = {}
    for item in raw_rows:
        key = str(item.get("row_id") or item.get("task_id") or "").strip()
        if not key:
            continue
        try:
            rank = (
                int(item.get("created_at") or 0),
                int(item.get("retry_attempt") or 0),
                1 if item.get("retry_of") else 0,
            )
        except (TypeError, ValueError):
            rank = (0, 0, 0)
        previous = latest.get(key)
        if previous is None:
            latest[key] = item
            continue
        try:
            previous_rank = (
                int(previous.get("created_at") or 0),
                int(previous.get("retry_attempt") or 0),
                1 if previous.get("retry_of") else 0,
            )
        except (TypeError, ValueError):
            previous_rank = (0, 0, 0)
        if rank >= previous_rank:
            latest[key] = item
    rows = list(latest.values())
    driver_codes = sorted({_safe_free_driver(item.get("driver")) for item in rows})
    if not driver_codes:
        driver_codes = ["unknown"]
    driver = driver_codes[0] if len(driver_codes) == 1 else "mixed"
    chain = _free_chain_display(driver_codes)
    safe_batch = str(batch_id or "").strip()
    if not _BATCH_RE.fullmatch(safe_batch):
        safe_batch = ""
    counts = {"total": len(rows), "success": 0, "failed": 0, "partial": 0, "twofa_pending": 0, "stopped": 0}
    total_ms = 0
    slowest: dict[str, Any] | None = None
    first_failure: dict[str, Any] | None = None
    incidents: list[str] = []
    emails: list[str] = []
    for task in rows:
        status = str(task.get("status") or "").strip().lower()
        if status == "success": counts["success"] += 1
        elif status == "twofa_pending": counts["twofa_pending"] += 1
        elif status == "partial_success": counts["partial"] += 1
        elif status == "stopped": counts["stopped"] += 1
        elif status == "failed": counts["failed"] += 1
        timing = task.get("timing") if isinstance(task.get("timing"), Mapping) else {}
        try: elapsed = max(0, int(timing.get("elapsed_ms") or 0))
        except (TypeError, ValueError): elapsed = 0
        total_ms += elapsed
        candidate = timing.get("slowest_node") if isinstance(timing.get("slowest_node"), Mapping) else None
        if candidate:
            try: duration = max(0, int(candidate.get("duration_ms") or 0))
            except (TypeError, ValueError): duration = 0
            if slowest is None or duration > int(slowest.get("duration_ms") or 0):
                slowest = {"code": str(candidate.get("code") or "")[:80], "label": str(candidate.get("label") or "")[:120], "duration_ms": duration}
        failure = task.get("failure") if isinstance(task.get("failure"), Mapping) else {}
        if failure and first_failure is None:
            first_failure = {"code": str(failure.get("node_code") or "")[:80], "label": str(failure.get("node_label") or "")[:120]}
        incident = str(task.get("incident_id") or "").strip()
        if _INCIDENT_RE.fullmatch(incident) and incident not in incidents:
            incidents.append(incident)
        email = _mask_email(task.get("email"))
        if email not in emails:
            emails.append(email)
    average_duration_ms = round(total_ms / len(rows)) if rows else 0
    return {
        "batch_id": safe_batch,
        "driver": driver,
        "drivers": driver_codes,
        "chain": chain,
        **counts,
        "average_duration_ms": average_duration_ms,
        "average_duration_seconds": round(average_duration_ms / 1000, 3),
        "slowest_node": slowest,
        "first_failure": first_failure,
        "incident_ids": incidents[:20],
        "emails": emails[:200],
    }


class FreeBatchNotificationAdapter:
    """At-most-once asynchronous Free batch summary sender."""

    def __init__(self, config_getter: Callable[[], Any]) -> None:
        self._config_getter = config_getter
        self._lock = threading.RLock()
        self._sent_batches: set[str] = set()
        self._queue: NotificationQueue | None = None

    def _queue_for(self, config: Any) -> NotificationQueue | None:
        try:
            normalized = validate_email_notification(config)
        except Exception:
            return None
        if not normalized.get("enabled") or not normalized.get("events", {}).get("batch_completed", True):
            return None
        sender = SmtpNotificationSender(normalized)

        def send(summary: Mapping[str, Any]) -> None:
            message = EmailMessage()
            chain = str(summary.get("chain") or "未知链路")
            message["Subject"] = (
                f"[GPT 注册中心][{chain}] Free 注册汇总"
            )
            settings = sender._settings
            message["From"] = settings.sender
            message["To"] = ", ".join(settings.recipients)
            slowest = summary.get("slowest_node") or {}
            failure = summary.get("first_failure") or {}
            result_parts = [
                f"成功 {summary.get('success', 0)}",
                f"失败 {summary.get('failed', 0)}",
                f"共 {summary.get('total', 0)} 个",
            ]
            for label, key in (
                ("部分成功", "partial"),
                ("2FA 待重试", "twofa_pending"),
                ("停止", "stopped"),
            ):
                value = summary.get(key, 0)
                if value:
                    result_parts.append(f"{label} {value}")
            lines = [
                f"结果：{' ｜ '.join(result_parts)}",
                f"链路：{chain}",
                f"平均耗时：{summary.get('average_duration_seconds', 0)} 秒",
                f"最慢节点：{slowest.get('label') or '-'} ({int(slowest.get('duration_ms') or 0)} ms)",
                f"首个失败节点：{failure.get('label') or '-'}",
                f"脱敏日志 ID：{', '.join(summary.get('incident_ids') or ()) or '-'}",
            ]
            message.set_content("\n".join(lines))
            sender._send_message(message)

        return NotificationQueue(send_fn=send, capacity=8)

    def submit(self, tasks: Any, *, batch_id: str = "") -> bool:
        summary = summarize_free_batch(tasks, batch_id=batch_id)
        key = str(summary.get("batch_id") or "")
        if not key:
            return False
        with self._lock:
            if key in self._sent_batches:
                return False
            queue = self._queue
            if queue is None:
                queue = self._queue_for(self._config_getter())
                if queue is None:
                    return False
                self._queue = queue
            if not queue.submit(summary):
                return False
            self._sent_batches.add(key)
            return True

    def close(self) -> None:
        with self._lock:
            queue = self._queue
        if queue is not None:
            queue.close(wait=False)


__all__ = ["FreeBatchNotificationAdapter", "summarize_free_batch"]
