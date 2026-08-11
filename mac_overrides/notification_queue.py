"""Bounded asynchronous delivery queue for runtime notifications."""

from __future__ import annotations

from collections.abc import Callable
import queue
import smtplib
import socket
import ssl
import threading
import time
from typing import Any


NOTIFICATION_QUEUE_CAPACITY = 16


def _delivery_failure(error: BaseException) -> tuple[str, str]:
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return "smtp_authentication_failed", "SMTP 账号或授权码认证失败"
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return "smtp_recipients_refused", "SMTP 服务端拒绝收件地址"
    if isinstance(error, smtplib.SMTPSenderRefused):
        return "smtp_sender_refused", "SMTP 服务端拒绝发件地址"
    if isinstance(error, (socket.gaierror,)):
        return "smtp_dns_failed", "SMTP 域名 DNS 解析失败"
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "smtp_timeout", "SMTP 连接或发送超时"
    if isinstance(error, ssl.SSLError):
        return "smtp_tls_failed", "SMTP TLS 握手失败"
    if isinstance(error, ConnectionRefusedError):
        return "smtp_connection_refused", "SMTP 服务器拒绝连接"
    if isinstance(error, OSError):
        return "smtp_network_failed", "SMTP 网络连接失败"
    return "smtp_delivery_failed", f"SMTP 发送异常（{type(error).__name__}）"


class NotificationQueue:
    """A bounded, single-worker daemon queue with one delivery attempt per item."""

    def __init__(
        self,
        send_fn: Callable[[Any], Any],
        *,
        notification_type: type[Any] | tuple[type[Any], ...] | None = None,
        capacity: int = NOTIFICATION_QUEUE_CAPACITY,
        thread_factory: Callable[..., Any] = threading.Thread,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        if capacity <= 0:
            raise ValueError("notification queue capacity must be positive")
        self._send_fn = send_fn
        self._notification_type = notification_type
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=capacity)
        self._capacity = capacity
        self._thread_factory = thread_factory
        self._now_fn = now_fn
        self._condition = threading.Condition()
        self._thread: Any = None
        self._closing = False
        self._outstanding = 0
        self._in_flight = 0
        self._submitted = 0
        self._sent = 0
        self._failed = 0
        self._dropped = 0
        self._last_event = ""
        self._last_result = ""
        self._last_timestamp = 0
        self._last_error_code = ""
        self._last_error = ""

    def _ensure_worker_locked(self) -> None:
        if self._thread is not None:
            return
        self._thread = self._thread_factory(
            target=self._worker,
            name="run-notification-email",
            daemon=True,
        )
        self._thread.start()

    def submit(self, notification: Any) -> bool:
        if self._notification_type is not None and not isinstance(
            notification,
            self._notification_type,
        ):
            raise TypeError("notification must be a RunNotification")
        with self._condition:
            if self._closing:
                self._dropped += 1
                self._last_event = str(getattr(notification, "event", "") or "")
                self._last_result = "failed"
                self._last_error_code = "notification_queue_closed"
                self._last_error = "通知队列已关闭"
                self._last_timestamp = int(self._now_fn())
                return False
            try:
                self._queue.put_nowait(notification)
            except queue.Full:
                self._dropped += 1
                self._last_event = str(getattr(notification, "event", "") or "")
                self._last_result = "failed"
                self._last_error_code = "notification_queue_full"
                self._last_error = "通知队列已满"
                self._last_timestamp = int(self._now_fn())
                return False
            self._outstanding += 1
            self._submitted += 1
            self._last_event = str(getattr(notification, "event", "") or "")
            self._last_result = "queued"
            self._last_timestamp = int(self._now_fn())
            self._ensure_worker_locked()
            self._condition.notify_all()
            return True

    def _worker(self) -> None:
        while True:
            try:
                notification = self._queue.get(timeout=0.05)
            except queue.Empty:
                with self._condition:
                    if self._closing and self._outstanding == 0:
                        self._condition.notify_all()
                        return
                continue

            with self._condition:
                self._in_flight += 1
                self._last_event = str(getattr(notification, "event", "") or "")
            delivered = False
            try:
                self._send_fn(notification)
                delivered = True
            except Exception as exc:
                delivered = False
                error_code, error_message = _delivery_failure(exc)
            finally:
                with self._condition:
                    self._in_flight -= 1
                    self._outstanding -= 1
                    if delivered:
                        self._sent += 1
                        self._last_result = "sent"
                        self._last_error_code = ""
                        self._last_error = ""
                    else:
                        self._failed += 1
                        self._last_result = "failed"
                        self._last_error_code = error_code
                        self._last_error = error_message
                    self._last_timestamp = int(self._now_fn())
                    self._condition.notify_all()
                self._queue.task_done()

    def wait_until_idle(self, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._condition:
            while self._outstanding:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def close(self, *, wait: bool = True, timeout: float = 2.0) -> None:
        with self._condition:
            self._closing = True
            thread = self._thread
            self._condition.notify_all()
        if wait and thread is not None:
            thread.join(timeout=max(0.0, timeout))

    def public_status(self) -> dict[str, Any]:
        with self._condition:
            thread = self._thread
            try:
                worker_running = bool(thread and thread.is_alive())
            except Exception:
                worker_running = False
            return {
                "queue_capacity": self._capacity,
                "queue_depth": self._queue.qsize(),
                "in_flight": self._in_flight,
                "worker_running": worker_running,
                "submitted": self._submitted,
                "sent": self._sent,
                "failed": self._failed,
                "dropped": self._dropped,
                "last_event": self._last_event,
                "last_result": self._last_result,
                "event": self._last_event,
                "status": self._last_result,
                "timestamp": self._last_timestamp,
                "error_code": self._last_error_code,
                "error": self._last_error,
            }
