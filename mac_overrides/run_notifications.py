"""Safe, asynchronous email notifications for importer runs."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from email.message import EmailMessage
import math
import re
import smtplib
import threading
import time
from typing import Any

try:
    from .notification_queue import NOTIFICATION_QUEUE_CAPACITY, NotificationQueue
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from notification_queue import NOTIFICATION_QUEUE_CAPACITY, NotificationQueue


SMTP_TIMEOUT_SECONDS = 10

EVENT_BATCH_COMPLETED = "batch_completed"
EVENT_UNEXPECTED_STOP = "unexpected_stop"
EVENT_STALLED = "stalled"
EVENT_SMS_EXHAUSTED = "sms_exhausted"
EVENT_MANUAL_STOP = "manual_stop"
EVENT_SMS_BALANCE_LOW = "sms_balance_low"
NOTIFICATION_EVENTS = (
    EVENT_BATCH_COMPLETED,
    EVENT_UNEXPECTED_STOP,
    EVENT_STALLED,
    EVENT_SMS_EXHAUSTED,
    EVENT_MANUAL_STOP,
    EVENT_SMS_BALANCE_LOW,
)
DEFAULT_EVENT_SETTINGS = {
    EVENT_BATCH_COMPLETED: True,
    EVENT_UNEXPECTED_STOP: True,
    EVENT_STALLED: True,
    EVENT_SMS_EXHAUSTED: True,
    EVENT_MANUAL_STOP: False,
    EVENT_SMS_BALANCE_LOW: True,
}

QQ_SMTP_HOST = "smtp.qq.com"
QQ_SMTP_PORT = 465
_EVENT_LABELS = {
    EVENT_BATCH_COMPLETED: "批次完成",
    EVENT_UNEXPECTED_STOP: "异常结束",
    EVENT_STALLED: "运行停滞",
    EVENT_SMS_EXHAUSTED: "SMS Key 已耗尽",
    EVENT_MANUAL_STOP: "手动停止",
    EVENT_SMS_BALANCE_LOW: "SMS Key 余额不足",
}
_ADDRESS_PATTERN = re.compile(r"^[^@\s<>]+@[^@\s<>]+$")
_SAFE_BATCH_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_SAFE_TASK_ID_PATTERN = re.compile(r"^T\d{1,6}(?:-[A-Za-z0-9]{1,24})?$")
_SAFE_PROVIDER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$")
_SAFE_FINGERPRINT_PATTERN = re.compile(r"^[a-f0-9]{8,64}$")
SMS_BALANCE_ALERT_THRESHOLD_USD = 1.0
_TERMINATION_REASON_LABELS = {
    "unfinished_tasks": "批次监控已退出，但仍有任务未终态",
    "watch_returned_with_unfinished_tasks": "批次监控正常返回，但仍有任务未终态",
    "watch_failed": "批次监控发生异常并提前退出",
    "scheduler_returned_with_unfinished_tasks": "任务调度器已退出，但仍有任务未终态",
    "scheduler_watch_failed": "任务调度监控发生异常并提前退出",
    "process_shutdown": "运行进程退出，批次未能正常收尾",
    "service_replaced": "新批次启动前，上一批次仍未完成",
    "manual_stop": "用户主动停止了本批次",
    "unexpected_stop": "批次未按预期完成",
}
MAX_UNFINISHED_TASK_IDS = 200


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


def _safe_batch_id(value: Any) -> str:
    candidate = _text(value)
    return candidate if _SAFE_BATCH_ID_PATTERN.fullmatch(candidate) else ""


def _safe_task_ids(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        candidates = list(value)
    else:
        candidates = []
    result: list[str] = []
    seen: set[str] = set()
    for raw in candidates:
        candidate = _text(raw)
        if not _SAFE_TASK_ID_PATTERN.fullmatch(candidate) or candidate in seen:
            continue
        seen.add(candidate)
        result.append(candidate)
        if len(result) >= MAX_UNFINISHED_TASK_IDS:
            break
    return tuple(result)


def _safe_termination_reason(value: Any) -> str:
    candidate = _text(value).lower()
    return candidate if candidate in _TERMINATION_REASON_LABELS else ""


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
    cost_usd: float = 0.0
    cost_exchange_rate: float = 0.0
    cost_exchange_source: str = ""
    cost_unknown_count: int = 0
    cost_unsettled_count: int = 0

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
            "cost_unknown_count",
            "cost_unsettled_count",
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
        try:
            usd = float(self.cost_usd)
        except (TypeError, ValueError) as exc:
            raise ValueError("cost_usd must be a non-negative number") from exc
        if not math.isfinite(usd) or usd < 0:
            raise ValueError("cost_usd must be a non-negative number")
        object.__setattr__(self, "cost_usd", round(usd, 4))
        try:
            exchange_rate = float(self.cost_exchange_rate)
        except (TypeError, ValueError) as exc:
            raise ValueError("cost_exchange_rate must be a non-negative number") from exc
        if not math.isfinite(exchange_rate) or exchange_rate < 0:
            raise ValueError("cost_exchange_rate must be a non-negative number")
        object.__setattr__(self, "cost_exchange_rate", round(exchange_rate, 6))
        object.__setattr__(self, "cost_exchange_source", _text(self.cost_exchange_source)[:32])

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
            cost_usd=value.get("cost_usd", value.get("sms_cost_usd", 0)),
            cost_exchange_rate=value.get(
                "cost_exchange_rate", value.get("sms_exchange_rate", 0)
            ),
            cost_exchange_source=value.get(
                "cost_exchange_source", value.get("sms_exchange_source", "")
            ),
            cost_unknown_count=_aggregate_value(
                value.get("cost_unknown_count", value.get("unknown_price_count", 0)),
                "cost_unknown_count",
            ),
            cost_unsettled_count=_aggregate_value(
                value.get("cost_unsettled_count", value.get("unsettled_order_count", 0)),
                "cost_unsettled_count",
            ),
            started_at=_aggregate_value(value.get("started_at", 0), "started_at"),
            finished_at=_aggregate_value(value.get("finished_at", 0), "finished_at"),
            last_activity_at=_aggregate_value(value.get("last_activity_at", 0), "last_activity_at"),
        )

    @property
    def has_unfinished_work(self) -> bool:
        return self.active > 0 or self.pending > 0


@dataclass(frozen=True, slots=True)
class SmsBalanceAlert:
    """Credential-free description of one low-balance SMS key."""

    provider: str
    index: int
    fingerprint: str
    balance_usd: float
    threshold_usd: float = SMS_BALANCE_ALERT_THRESHOLD_USD

    def __post_init__(self) -> None:
        provider = _text(self.provider).lower()
        fingerprint = _text(self.fingerprint).lower()
        if not _SAFE_PROVIDER_PATTERN.fullmatch(provider):
            raise ValueError("invalid SMS provider")
        if not _SAFE_FINGERPRINT_PATTERN.fullmatch(fingerprint):
            raise ValueError("invalid SMS key fingerprint")
        try:
            index = int(self.index)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid SMS key index") from exc
        if index <= 0:
            raise ValueError("invalid SMS key index")
        try:
            balance = float(self.balance_usd)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid SMS key balance") from exc
        if (
            not math.isfinite(balance)
            or balance < 0
            or balance >= SMS_BALANCE_ALERT_THRESHOLD_USD
        ):
            raise ValueError("SMS key balance is not below the alert threshold")
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "index", min(index, 100000))
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "balance_usd", round(balance, 4))
        object.__setattr__(self, "threshold_usd", SMS_BALANCE_ALERT_THRESHOLD_USD)


def _coerce_sms_balance_alert(value: Any) -> SmsBalanceAlert | None:
    if isinstance(value, SmsBalanceAlert):
        return value
    if not isinstance(value, Mapping):
        return None
    if not _as_bool(value.get("enabled"), True):
        return None
    try:
        return SmsBalanceAlert(
            provider=value.get("provider", value.get("platform", "SMS")),
            index=value.get("index"),
            fingerprint=value.get("fingerprint"),
            balance_usd=value.get("balance_usd"),
        )
    except (TypeError, ValueError):
        return None


def _safe_balance_alerts(value: Any) -> tuple[SmsBalanceAlert, ...]:
    if isinstance(value, (list, tuple, set, frozenset)):
        candidates = value
    elif value is None:
        candidates = ()
    else:
        candidates = (value,)
    result: list[SmsBalanceAlert] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        alert = _coerce_sms_balance_alert(candidate)
        if alert is None or (alert.provider, alert.fingerprint) in seen:
            continue
        seen.add((alert.provider, alert.fingerprint))
        result.append(alert)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class RunNotification:
    event: str
    aggregate: RunAggregate
    batch_id: str = ""
    unfinished_task_ids: tuple[str, ...] = ()
    termination_reason: str = ""
    balance_alerts: tuple[SmsBalanceAlert, ...] = ()

    def __post_init__(self) -> None:
        if self.event not in NOTIFICATION_EVENTS:
            raise ValueError("unsupported notification event")
        object.__setattr__(self, "batch_id", _safe_batch_id(self.batch_id))
        object.__setattr__(
            self,
            "unfinished_task_ids",
            _safe_task_ids(self.unfinished_task_ids),
        )
        object.__setattr__(
            self,
            "termination_reason",
            _safe_termination_reason(self.termination_reason),
        )
        object.__setattr__(self, "balance_alerts", _safe_balance_alerts(self.balance_alerts))

    @property
    def unfinished_count(self) -> int:
        return max(
            self.aggregate.active + self.aggregate.pending,
            len(self.unfinished_task_ids),
        )


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
    unfinished = notification.unfinished_count
    is_unfinished_stop = (
        notification.event == EVENT_UNEXPECTED_STOP and unfinished > 0
    )
    label = "运行异常（仍有任务未终态）" if is_unfinished_stop else _EVENT_LABELS[notification.event]
    aggregate = notification.aggregate
    message = EmailMessage()
    subject_parts = [f"[自动接码机] {label}"]
    if notification.batch_id:
        subject_parts.append(f"批次 {notification.batch_id}")
    if notification.event == EVENT_SMS_BALANCE_LOW:
        subject_parts.append(f"低余额 Key {len(notification.balance_alerts)} 个")
    elif unfinished:
        subject_parts.append(f"未终态 {unfinished}")
    else:
        subject_parts.append(
            f"成功 {aggregate.succeeded} / 失败 {aggregate.failed} / 停止 {aggregate.stopped}"
        )
    message["Subject"] = "｜".join(subject_parts)
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
    if notification.batch_id:
        lines.insert(1, f"共享批次：{notification.batch_id}")
    if unfinished:
        lines.append(f"未终态任务数：{unfinished}")
    if notification.unfinished_task_ids:
        lines.append(f"未终态任务：{'、'.join(notification.unfinished_task_ids)}")
    if notification.termination_reason:
        lines.append(
            f"结束原因：{_TERMINATION_REASON_LABELS[notification.termination_reason]}"
        )
    if is_unfinished_stop:
        lines.append("状态说明：这不是批次最终结果；任务转为终态后仍会发送最终汇总。")
    if notification.event == EVENT_SMS_BALANCE_LOW:
        lines.append(f"余额提醒阈值：低于 ${SMS_BALANCE_ALERT_THRESHOLD_USD:.2f}")
        for alert in notification.balance_alerts:
            lines.append(
                f"低余额 Key：平台 {alert.provider} / Key {alert.index} / "
                f"指纹 {alert.fingerprint} / 当前余额 ${alert.balance_usd:.4f}"
            )
    if aggregate.duration_seconds:
        minutes, seconds = divmod(aggregate.duration_seconds, 60)
        lines.append(f"运行耗时：{minutes} 分 {seconds} 秒")
    # Every enabled event carries a cost line, including a zero-cost batch.
    # Unknown prices and open orders are explicitly marked so estimates are
    # never presented as the final provider charge.
    lines.append(
        f"运行成本：¥{aggregate.cost_cny:.2f} / ${aggregate.cost_usd:.4f}"
    )
    cost_flags: list[str] = []
    if aggregate.cost_unknown_count:
        cost_flags.append(f"未知价格 {aggregate.cost_unknown_count} 条")
    if aggregate.cost_unsettled_count:
        cost_flags.append(f"未结算订单 {aggregate.cost_unsettled_count} 条")
    if (
        aggregate.cost_exchange_rate <= 0
        and (aggregate.cost_usd > 0 or aggregate.cost_cny > 0)
    ):
        cost_flags.append("汇率未知")
    if cost_flags:
        lines.append("成本状态：暂估，" + "、".join(cost_flags))
    if aggregate.cost_exchange_source in {"fallback", "stale_cache"}:
        source_label = "备用汇率" if aggregate.cost_exchange_source == "fallback" else "过期缓存汇率"
        lines.append(f"汇率说明：使用{source_label}，最终扣费以供应商账单为准")
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
    *,
    batch_id: Any = "",
    unfinished_task_ids: Any = (),
    termination_reason: Any = "",
    balance_alerts: Any = (),
) -> EmailMessage:
    """Build a message from aggregate counts and strictly validated run metadata."""
    notification = RunNotification(
        event,
        RunAggregate.from_value(aggregate),
        batch_id=_safe_batch_id(batch_id),
        unfinished_task_ids=_safe_task_ids(unfinished_task_ids),
        termination_reason=_safe_termination_reason(termination_reason),
        balance_alerts=_safe_balance_alerts(balance_alerts),
    )
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


@dataclass(slots=True)
class _RunState:
    aggregate: RunAggregate
    last_progress_at: float
    batch_id: str = ""
    manual_stop: bool = False
    finalized: bool = False
    triggered_events: set[str] = field(default_factory=set)
    balance_alerted_keys: set[tuple[str, str]] = field(default_factory=set)


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
            aggregate.cost_usd,
            aggregate.cost_exchange_rate,
            aggregate.cost_exchange_source,
            aggregate.cost_unknown_count,
            aggregate.cost_unsettled_count,
            aggregate.last_activity_at,
        )

    def _reserve_locked(
        self,
        state: _RunState,
        event: str,
        *,
        unfinished_task_ids: Any = (),
        termination_reason: Any = "",
        balance_alerts: Any = (),
    ) -> RunNotification | None:
        if event in state.triggered_events:
            return None
        state.triggered_events.add(event)
        self._triggered_counts[event] += 1
        if not self._config["enabled"] or not self._config["events"][event]:
            return None
        return RunNotification(
            event,
            state.aggregate,
            batch_id=state.batch_id,
            unfinished_task_ids=_safe_task_ids(unfinished_task_ids),
            termination_reason=_safe_termination_reason(termination_reason),
            balance_alerts=_safe_balance_alerts(balance_alerts),
        )

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
        batch_id: Any = "",
        now: float | None = None,
    ) -> bool:
        key = self._run_key(run_id)
        summary = RunAggregate.from_value(aggregate)
        timestamp = float(self._clock() if now is None else now)
        with self._lock:
            if key in self._runs:
                return False
            self._runs[key] = _RunState(
                summary,
                timestamp,
                batch_id=_safe_batch_id(batch_id),
            )
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

    def observe_sms_balances(
        self,
        run_id: Any,
        aggregate: Any,
        statuses: Any,
        *,
        now: float | None = None,
    ) -> tuple[str, ...]:
        """Send one email per newly observed low-balance key in a run."""
        key = self._run_key(run_id)
        summary = RunAggregate.from_value(aggregate)
        alerts = _safe_balance_alerts(statuses)
        if not alerts:
            return ()
        notifications: list[RunNotification] = []
        with self._lock:
            state = self._runs.get(key)
            if state is None or state.finalized:
                return ()
            state.aggregate = summary
            fresh = [
                alert
                for alert in alerts
                if (alert.provider, alert.fingerprint) not in state.balance_alerted_keys
            ]
            if not fresh:
                return ()
            state.balance_alerted_keys.update(
                (alert.provider, alert.fingerprint) for alert in fresh
            )
            self._triggered_counts[EVENT_SMS_BALANCE_LOW] += 1
            if self._config["enabled"] and self._config["events"][EVENT_SMS_BALANCE_LOW]:
                notifications.append(
                    RunNotification(
                        EVENT_SMS_BALANCE_LOW,
                        state.aggregate,
                        batch_id=state.batch_id,
                        balance_alerts=tuple(fresh),
                    )
                )
        return self._submit(notifications)

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
        batch_id: Any = "",
        unfinished_task_ids: Any = (),
        termination_reason: Any = "",
    ) -> tuple[str, ...]:
        key = self._run_key(run_id)
        summary = RunAggregate.from_value(aggregate)
        safe_batch_id = _safe_batch_id(batch_id)
        safe_task_ids = _safe_task_ids(unfinished_task_ids)
        unfinished = summary.has_unfinished_work or bool(safe_task_ids)
        notifications: list[RunNotification] = []
        with self._lock:
            state = self._runs.get(key)
            if state is None or state.finalized:
                return ()
            state.aggregate = summary
            if safe_batch_id:
                state.batch_id = safe_batch_id
            if state.manual_stop:
                event = EVENT_MANUAL_STOP
                reason = _safe_termination_reason(termination_reason) or "manual_stop"
            elif completed and not unfinished:
                event = EVENT_BATCH_COMPLETED
                reason = ""
            else:
                event = EVENT_UNEXPECTED_STOP
                reason = (
                    _safe_termination_reason(termination_reason)
                    or ("unfinished_tasks" if unfinished else "unexpected_stop")
                )
            # A watcher can return while worker tasks are still alive.  That is
            # an actionable alert, but it is not the batch's final state.
            state.finalized = not unfinished
            notification = self._reserve_locked(
                state,
                event,
                unfinished_task_ids=safe_task_ids,
                termination_reason=reason,
            )
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
            notification_type=RunNotification,
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

    def observe_sms_balances(self, *args: Any, **kwargs: Any) -> tuple[str, ...]:
        return self.coordinator.observe_sms_balances(*args, **kwargs)

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
