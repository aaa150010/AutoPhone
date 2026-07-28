"""Safe, asynchronous email notifications for importer runs."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from email.message import EmailMessage
import math
import queue
import re
import smtplib
import threading
import time
from typing import Any


SMTP_TIMEOUT_SECONDS = 10
NOTIFICATION_QUEUE_CAPACITY = 16

EVENT_BATCH_COMPLETED = "batch_completed"
EVENT_UNEXPECTED_STOP = "unexpected_stop"
EVENT_STALLED = "stalled"
EVENT_SMS_EXHAUSTED = "sms_exhausted"
EVENT_MANUAL_STOP = "manual_stop"
NOTIFICATION_EVENTS = (
    EVENT_BATCH_COMPLETED,
    EVENT_UNEXPECTED_STOP,
    EVENT_STALLED,
    EVENT_SMS_EXHAUSTED,
    EVENT_MANUAL_STOP,
)
DEFAULT_EVENT_SETTINGS = {
    EVENT_BATCH_COMPLETED: True,
    EVENT_UNEXPECTED_STOP: True,
    EVENT_STALLED: True,
    EVENT_SMS_EXHAUSTED: True,
    EVENT_MANUAL_STOP: False,
}

QQ_SMTP_HOST = "smtp.qq.com"
QQ_SMTP_PORT = 465
_EVENT_LABELS = {
    EVENT_BATCH_COMPLETED: "批次完成",
    EVENT_UNEXPECTED_STOP: "异常结束",
    EVENT_STALLED: "运行停滞",
    EVENT_SMS_EXHAUSTED: "SMS Key 已耗尽",
    EVENT_MANUAL_STOP: "手动停止",
}
_ADDRESS_PATTERN = re.compile(r"^[^@\s<>]+@[^@\s<>]+$")


class NotificationConfigError(ValueError):
    """Raised when an enabled notification configuration is incomplete."""


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    return default


def _text(value: Any) -> str:
    return str(value or "").strip()


def _first(config: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in config:
            return config[name]
    return None


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def normalize_recipients(value: Any) -> list[str]:
    """Trim recipient addresses and deduplicate them case-insensitively."""
    candidates: list[Any] = []
    if isinstance(value, str):
        candidates.extend(re.split(r"[,;\n\r]+", value))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, str):
                candidates.extend(re.split(r"[,;\n\r]+", item))
            else:
                candidates.append(item)
    elif value is not None:
        candidates.append(value)

    result: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        recipient = _text(candidate)
        key = recipient.casefold()
        if not recipient or key in seen:
            continue
        seen.add(key)
        result.append(recipient)
    return result


def normalize_email_notification(value: Any = None) -> dict[str, Any]:
    """Return the canonical ``email_notification`` configuration."""
    source = dict(value) if isinstance(value, Mapping) else {}

    username = _text(_first(source, "username", "smtp_username", "account"))
    password = _text(
        _first(
            source,
            "password",
            "smtp_password",
            "authorization_code",
            "auth_code",
        )
    )
    sender = _text(_first(source, "sender", "from_address", "from")) or username
    recipients = normalize_recipients(
        _first(source, "recipients", "recipient_emails", "recipient")
    )

    raw_events = source.get("events")
    event_source = raw_events if isinstance(raw_events, Mapping) else {}
    events = {
        event: _as_bool(
            event_source.get(event, source.get(event)),
            default,
        )
        for event, default in DEFAULT_EVENT_SETTINGS.items()
    }

    return {
        "enabled": _as_bool(source.get("enabled"), False),
        "provider": "qq",
        "smtp_host": QQ_SMTP_HOST,
        "smtp_port": QQ_SMTP_PORT,
        "security": "ssl",
        "username": username,
        "password": password,
        "sender": sender,
        "recipients": recipients,
        "stalled_minutes": _positive_int(source.get("stalled_minutes"), 10),
        "events": events,
    }


def _valid_address(value: str) -> bool:
    return (
        bool(_ADDRESS_PATTERN.fullmatch(value))
        and "\r" not in value
        and "\n" not in value
    )


def validate_email_notification(value: Any = None) -> dict[str, Any]:
    """Normalize and validate fields needed when notifications are enabled."""
    config = normalize_email_notification(value)
    if not config["enabled"]:
        return config

    invalid: list[str] = []
    if not config["username"]:
        invalid.append("username")
    if not config["password"]:
        invalid.append("password")
    if not _valid_address(config["sender"]):
        invalid.append("sender")
    if not config["recipients"] or not all(
        _valid_address(recipient) for recipient in config["recipients"]
    ):
        invalid.append("recipients")
    if invalid:
        fields = ", ".join(invalid)
        raise NotificationConfigError(
            f"enabled email_notification has invalid fields: {fields}"
        )
    return config


def _aggregate_value(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return parsed


@dataclass(frozen=True, slots=True)
class RunAggregate:
    """The only run data allowed to cross the email boundary."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    stopped: int = 0
    active: int = 0
    pending: int = 0
    duration_seconds: int = 0
    cost_cny: float = 0.0
    started_at: int = 0
    finished_at: int = 0
    last_activity_at: int = 0

    def __post_init__(self) -> None:
        for name in (
            "total",
            "succeeded",
            "failed",
            "stopped",
            "active",
            "pending",
            "duration_seconds",
            "started_at",
            "finished_at",
            "last_activity_at",
        ):
            object.__setattr__(
                self,
                name,
                _aggregate_value(getattr(self, name), name),
            )
        try:
            cost = float(self.cost_cny)
        except (TypeError, ValueError) as exc:
            raise ValueError("cost_cny must be a non-negative number") from exc
        if not math.isfinite(cost) or cost < 0:
            raise ValueError("cost_cny must be a non-negative number")
        object.__setattr__(self, "cost_cny", cost)

    @classmethod
    def from_value(cls, value: Any = None) -> RunAggregate:
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("run aggregate must be a RunAggregate or mapping")
        return cls(
            total=_aggregate_value(value.get("total", 0), "total"),
            succeeded=_aggregate_value(
                value.get("succeeded", value.get("success", 0)),
                "succeeded",
            ),
            failed=_aggregate_value(value.get("failed", 0), "failed"),
            stopped=_aggregate_value(value.get("stopped", 0), "stopped"),
            active=_aggregate_value(value.get("active", 0), "active"),
            pending=_aggregate_value(
                value.get("pending", value.get("queued", 0)),
                "pending",
            ),
            duration_seconds=_aggregate_value(value.get("duration_seconds", 0), "duration_seconds"),
            cost_cny=value.get("cost_cny", value.get("sms_cost_cny", 0)),
            started_at=_aggregate_value(value.get("started_at", 0), "started_at"),
            finished_at=_aggregate_value(value.get("finished_at", 0), "finished_at"),
            last_activity_at=_aggregate_value(value.get("last_activity_at", 0), "last_activity_at"),
        )

    @property
    def has_unfinished_work(self) -> bool:
        return self.active > 0 or self.pending > 0


@dataclass(frozen=True, slots=True)
class RunNotification:
    event: str
    aggregate: RunAggregate

    def __post_init__(self) -> None:
        if self.event not in NOTIFICATION_EVENTS:
            raise ValueError("unsupported notification event")


@dataclass(frozen=True, slots=True)
class _SmtpSettings:
    host: str
    port: int
    username: str = field(repr=False)
    password: str = field(repr=False)
    sender: str = field(repr=False)
    recipients: tuple[str, ...] = field(repr=False)


def _smtp_settings(config: Any) -> _SmtpSettings:
    normalized = validate_email_notification(config)
    if not normalized["enabled"]:
        raise NotificationConfigError("email_notification is disabled")
    return _SmtpSettings(
        host=normalized["smtp_host"],
        port=normalized["smtp_port"],
        username=normalized["username"],
        password=normalized["password"],
        sender=normalized["sender"],
        recipients=tuple(normalized["recipients"]),
    )


def _build_message(settings: _SmtpSettings, notification: RunNotification) -> EmailMessage:
    label = _EVENT_LABELS[notification.event]
    aggregate = notification.aggregate
    message = EmailMessage()
    message["Subject"] = (
        f"[自动接码机] {label}｜成功 {aggregate.succeeded} / "
        f"失败 {aggregate.failed} / 停止 {aggregate.stopped}"
    )
    message["From"] = settings.sender
    message["To"] = ", ".join(settings.recipients)
    lines = [
        f"事件：{label}",
        f"处理总数：{aggregate.total}",
        f"成功：{aggregate.succeeded}",
        f"失败：{aggregate.failed}",
        f"已停止：{aggregate.stopped}",
        f"运行中：{aggregate.active}",
        f"等待中：{aggregate.pending}",
    ]
    if aggregate.duration_seconds:
        minutes, seconds = divmod(aggregate.duration_seconds, 60)
        lines.append(f"运行耗时：{minutes} 分 {seconds} 秒")
    if aggregate.cost_cny:
        lines.append(f"运行成本：¥{aggregate.cost_cny:.2f}")
    if aggregate.started_at:
        lines.append(f"开始时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(aggregate.started_at))}")
    if aggregate.finished_at:
        lines.append(f"结束时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(aggregate.finished_at))}")
    message.set_content("\n".join(lines))
    return message


def build_notification_message(
    config: Any,
    event: str,
    aggregate: Any = None,
) -> EmailMessage:
    """Build a message whose dynamic content is limited to aggregate counts."""
    notification = RunNotification(event, RunAggregate.from_value(aggregate))
    return _build_message(_smtp_settings(config), notification)


class SmtpNotificationSender:
    """Deliver one notification through QQ Mail over SMTP SSL."""

    def __init__(
        self,
        config: Any,
        *,
        smtp_ssl_factory: Callable[..., Any] = smtplib.SMTP_SSL,
    ) -> None:
        self._settings = _smtp_settings(config)
        self._smtp_ssl_factory = smtp_ssl_factory

    def _send_message(self, message: EmailMessage) -> None:
        settings = self._settings
        with self._smtp_ssl_factory(
            settings.host,
            settings.port,
            timeout=SMTP_TIMEOUT_SECONDS,
        ) as client:
            client.login(settings.username, settings.password)
            client.send_message(
                message,
                from_addr=settings.sender,
                to_addrs=list(settings.recipients),
            )

    def send(self, notification: RunNotification) -> None:
        self._send_message(_build_message(self._settings, notification))

    def send_test(self) -> None:
        message = EmailMessage()
        message["Subject"] = "[自动接码机] 测试通知"
        message["From"] = self._settings.sender
        message["To"] = ", ".join(self._settings.recipients)
        message.set_content("自动接码机邮件通知配置测试成功。")
        self._send_message(message)

    __call__ = send


def send_test_notification(
    config: Any,
    *,
    smtp_ssl_factory: Callable[..., Any] = smtplib.SMTP_SSL,
) -> dict[str, Any]:
    """Send one explicit test message and return only safe delivery metadata."""
    sender = SmtpNotificationSender(
        config,
        smtp_ssl_factory=smtp_ssl_factory,
    )
    sender.send_test()
    return {
        "status": "sent",
        "event": "test",
        "timestamp": int(time.time()),
        "recipient_count": len(sender._settings.recipients),
    }


class NotificationQueue:
    """A bounded, single-worker daemon queue with one delivery attempt per item."""

    def __init__(
        self,
        send_fn: Callable[[RunNotification], Any],
        *,
        capacity: int = NOTIFICATION_QUEUE_CAPACITY,
        thread_factory: Callable[..., Any] = threading.Thread,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        if capacity <= 0:
            raise ValueError("notification queue capacity must be positive")
        self._send_fn = send_fn
        self._queue: queue.Queue[RunNotification] = queue.Queue(maxsize=capacity)
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

    def _ensure_worker_locked(self) -> None:
        if self._thread is not None:
            return
        self._thread = self._thread_factory(
            target=self._worker,
            name="run-notification-email",
            daemon=True,
        )
        self._thread.start()

    def submit(self, notification: RunNotification) -> bool:
        if not isinstance(notification, RunNotification):
            raise TypeError("notification must be a RunNotification")
        with self._condition:
            if self._closing:
                self._dropped += 1
                self._last_event = notification.event
                self._last_result = "failed"
                self._last_timestamp = int(self._now_fn())
                return False
            try:
                self._queue.put_nowait(notification)
            except queue.Full:
                self._dropped += 1
                self._last_event = notification.event
                self._last_result = "failed"
                self._last_timestamp = int(self._now_fn())
                return False
            self._outstanding += 1
            self._submitted += 1
            self._last_event = notification.event
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
                self._last_event = notification.event
            delivered = False
            try:
                self._send_fn(notification)
                delivered = True
            except Exception:
                delivered = False
            finally:
                with self._condition:
                    self._in_flight -= 1
                    self._outstanding -= 1
                    if delivered:
                        self._sent += 1
                        self._last_result = "sent"
                    else:
                        self._failed += 1
                        self._last_result = "failed"
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
            }


@dataclass(slots=True)
class _RunState:
    aggregate: RunAggregate
    last_progress_at: float
    manual_stop: bool = False
    finalized: bool = False
    triggered_events: set[str] = field(default_factory=set)


class RunNotificationCoordinator:
    """Translate lifecycle observations into at-most-once run events."""

    def __init__(
        self,
        config: Any,
        submit_fn: Callable[[RunNotification], Any],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = validate_email_notification(config)
        self._submit_fn = submit_fn
        self._clock = clock
        self._lock = threading.RLock()
        self._runs: dict[str, _RunState] = {}
        self._triggered_counts = {event: 0 for event in NOTIFICATION_EVENTS}

    @staticmethod
    def _run_key(run_id: Any) -> str:
        key = _text(run_id)
        if not key:
            raise ValueError("run_id is required")
        return key

    @staticmethod
    def _progress_signature(aggregate: RunAggregate) -> tuple[Any, ...]:
        return (
            aggregate.total,
            aggregate.succeeded,
            aggregate.failed,
            aggregate.stopped,
            aggregate.active,
            aggregate.pending,
            aggregate.cost_cny,
            aggregate.last_activity_at,
        )

    def _reserve_locked(
        self,
        state: _RunState,
        event: str,
    ) -> RunNotification | None:
        if event in state.triggered_events:
            return None
        state.triggered_events.add(event)
        self._triggered_counts[event] += 1
        if not self._config["enabled"] or not self._config["events"][event]:
            return None
        return RunNotification(event, state.aggregate)

    def _submit(self, notifications: list[RunNotification]) -> tuple[str, ...]:
        for notification in notifications:
            try:
                self._submit_fn(notification)
            except Exception:
                pass
        return tuple(notification.event for notification in notifications)

    def start_run(
        self,
        run_id: Any,
        aggregate: Any = None,
        *,
        now: float | None = None,
    ) -> bool:
        key = self._run_key(run_id)
        summary = RunAggregate.from_value(aggregate)
        timestamp = float(self._clock() if now is None else now)
        with self._lock:
            if key in self._runs:
                return False
            self._runs[key] = _RunState(summary, timestamp)
            return True

    def observe_run(
        self,
        run_id: Any,
        aggregate: Any,
        *,
        sms_exhausted: bool = False,
        now: float | None = None,
    ) -> tuple[str, ...]:
        key = self._run_key(run_id)
        summary = RunAggregate.from_value(aggregate)
        timestamp = float(self._clock() if now is None else now)
        notifications: list[RunNotification] = []
        with self._lock:
            state = self._runs.get(key)
            if state is None or state.finalized:
                return ()
            if self._progress_signature(summary) != self._progress_signature(state.aggregate):
                state.last_progress_at = timestamp
            state.aggregate = summary
            if sms_exhausted:
                notification = self._reserve_locked(state, EVENT_SMS_EXHAUSTED)
                if notification is not None:
                    notifications.append(notification)
            stalled_for = timestamp - state.last_progress_at
            if (
                summary.has_unfinished_work
                and stalled_for >= self._config["stalled_minutes"] * 60
            ):
                notification = self._reserve_locked(state, EVENT_STALLED)
                if notification is not None:
                    notifications.append(notification)
        return self._submit(notifications)

    def observe_sms_exhausted(
        self,
        run_id: Any,
        aggregate: Any,
        *,
        now: float | None = None,
    ) -> tuple[str, ...]:
        return self.observe_run(
            run_id,
            aggregate,
            sms_exhausted=True,
            now=now,
        )

    def check_stall(
        self,
        run_id: Any,
        aggregate: Any,
        *,
        now: float | None = None,
    ) -> tuple[str, ...]:
        return self.observe_run(run_id, aggregate, now=now)

    def mark_manual_stop(
        self,
        run_id: Any,
        aggregate: Any,
    ) -> tuple[str, ...]:
        key = self._run_key(run_id)
        summary = RunAggregate.from_value(aggregate)
        with self._lock:
            state = self._runs.get(key)
            if state is None or state.finalized:
                return ()
            state.aggregate = summary
            state.manual_stop = True
        return ()

    def finalize_run(
        self,
        run_id: Any,
        aggregate: Any,
        *,
        completed: bool = True,
    ) -> tuple[str, ...]:
        key = self._run_key(run_id)
        summary = RunAggregate.from_value(aggregate)
        notifications: list[RunNotification] = []
        with self._lock:
            state = self._runs.get(key)
            if state is None or state.finalized:
                return ()
            state.aggregate = summary
            state.finalized = True
            if state.manual_stop:
                event = EVENT_MANUAL_STOP
            elif completed:
                event = EVENT_BATCH_COMPLETED
            else:
                event = EVENT_UNEXPECTED_STOP
            notification = self._reserve_locked(state, event)
            if notification is not None:
                notifications.append(notification)
        return self._submit(notifications)

    def public_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "tracked_runs": len(self._runs),
                "active_runs": sum(
                    1 for state in self._runs.values() if not state.finalized
                ),
                "triggered_events": dict(self._triggered_counts),
            }

    start = start_run
    observe = observe_run
    manual_stop = mark_manual_stop
    finalize = finalize_run


class RunNotificationService:
    """Configured SMTP transport, daemon queue, and lifecycle coordinator."""

    def __init__(
        self,
        config: Any,
        *,
        clock: Callable[[], float] = time.monotonic,
        smtp_ssl_factory: Callable[..., Any] = smtplib.SMTP_SSL,
        thread_factory: Callable[..., Any] = threading.Thread,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.config = validate_email_notification(config)
        if self.config["enabled"]:
            sender = SmtpNotificationSender(
                self.config,
                smtp_ssl_factory=smtp_ssl_factory,
            )
            send_fn = sender.send
        else:
            send_fn = lambda _notification: None
        self.dispatcher = NotificationQueue(
            send_fn,
            capacity=NOTIFICATION_QUEUE_CAPACITY,
            thread_factory=thread_factory,
            now_fn=now_fn,
        )
        self.coordinator = RunNotificationCoordinator(
            self.config,
            self.dispatcher.submit,
            clock=clock,
        )

    def start_run(self, *args: Any, **kwargs: Any) -> bool:
        return self.coordinator.start_run(*args, **kwargs)

    def observe_run(self, *args: Any, **kwargs: Any) -> tuple[str, ...]:
        return self.coordinator.observe_run(*args, **kwargs)

    def observe_sms_exhausted(self, *args: Any, **kwargs: Any) -> tuple[str, ...]:
        return self.coordinator.observe_sms_exhausted(*args, **kwargs)

    def check_stall(self, *args: Any, **kwargs: Any) -> tuple[str, ...]:
        return self.coordinator.check_stall(*args, **kwargs)

    def mark_manual_stop(self, *args: Any, **kwargs: Any) -> tuple[str, ...]:
        return self.coordinator.mark_manual_stop(*args, **kwargs)

    def finalize_run(self, *args: Any, **kwargs: Any) -> tuple[str, ...]:
        return self.coordinator.finalize_run(*args, **kwargs)

    def wait_until_idle(self, timeout: float = 2.0) -> bool:
        return self.dispatcher.wait_until_idle(timeout)

    def close(self, *, wait: bool = True, timeout: float = 2.0) -> None:
        self.dispatcher.close(wait=wait, timeout=timeout)

    def public_status(self) -> dict[str, Any]:
        return {
            "enabled": self.config["enabled"],
            "recipient_count": len(self.config["recipients"]),
            **self.coordinator.public_status(),
            **self.dispatcher.public_status(),
        }

    start = start_run
    observe = observe_run
    manual_stop = mark_manual_stop
    finalize = finalize_run

    def __enter__(self) -> RunNotificationService:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()
