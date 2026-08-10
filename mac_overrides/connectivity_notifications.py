"""Asynchronous email delivery for OpenAI connectivity incidents."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import re
import smtplib
import threading
import time
from typing import Any

try:
    from .notification_queue import NOTIFICATION_QUEUE_CAPACITY, NotificationQueue
    from .run_notifications import (
        EVENT_OPENAI_AUTH_CONNECTIVITY,
        OpenAIConnectivityNotification,
        SmtpNotificationSender,
        normalize_email_notification,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from notification_queue import NOTIFICATION_QUEUE_CAPACITY, NotificationQueue
    from run_notifications import (
        EVENT_OPENAI_AUTH_CONNECTIVITY,
        OpenAIConnectivityNotification,
        SmtpNotificationSender,
        normalize_email_notification,
    )


_SAFE_BATCH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_SAFE_EVENT_ID = re.compile(r"^[A-Za-z0-9]{1,64}$")
_SAFE_PROXY_FINGERPRINT = re.compile(r"^sha256:[a-f0-9]{16}$")


def _safe_capacity(value: Any) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return min(1_000, max(0, parsed))


class ConnectivityIncidentContextStore:
    """Keep notification identity bound to the incident that created it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._context: dict[str, Any] | None = None

    @staticmethod
    def _identity(payload: Any) -> tuple[str, str] | None:
        value = payload if isinstance(payload, Mapping) else {}
        event_id = str(value.get("event_id") or "").strip()
        fingerprint = str(value.get("proxy_fingerprint") or "").strip().lower()
        if not _SAFE_EVENT_ID.fullmatch(event_id):
            return None
        if not _SAFE_PROXY_FINGERPRINT.fullmatch(fingerprint):
            return None
        return event_id, fingerprint

    @staticmethod
    def _capacity(value: Any) -> dict[str, Any]:
        source = value if isinstance(value, Mapping) else {}
        baseline = _safe_capacity(source.get("baseline"))
        sticky_baseline = source.get("sticky_baseline") is True
        return {
            "baseline": baseline,
            "protocol_limit": _safe_capacity(
                source.get("limit", source.get("protocol_limit"))
            ),
            "healthy_ceiling": (
                baseline
                if sticky_baseline
                else _safe_capacity(source.get("healthy_ceiling"))
            ),
            "sticky_baseline": sticky_baseline,
        }

    def resolve(
        self,
        payload: Any,
        *,
        batch_id: Any,
        capacity: Any,
    ) -> dict[str, Any]:
        value = payload if isinstance(payload, Mapping) else {}
        identity = self._identity(value)
        current_capacity = self._capacity(capacity)
        kind = str(value.get("kind") or "").strip().lower()
        with self._lock:
            if kind == "outage" and identity is not None:
                safe_batch = str(batch_id or "").strip()
                self._context = {
                    "identity": identity,
                    "batch_id": safe_batch if _SAFE_BATCH_ID.fullmatch(safe_batch) else "",
                    **current_capacity,
                }
                return dict(self._context)
            if (
                kind == "recovery"
                and identity is not None
                and self._context is not None
                and self._context.get("identity") == identity
            ):
                matched = self._context
                self._context = None
                return dict(matched)
        return {"batch_id": "", **current_capacity}

    def build_notification(
        self,
        payload: Any,
        *,
        batch_id: Any,
        capacity: Any,
    ) -> OpenAIConnectivityNotification:
        value = payload if isinstance(payload, Mapping) else {}
        context = self.resolve(value, batch_id=batch_id, capacity=capacity)
        return OpenAIConnectivityNotification(
            kind=value.get("kind"),
            event_id=value.get("event_id"),
            batch_id=context.get("batch_id"),
            reason_code=value.get("reason_code"),
            affected_origins=tuple(value.get("affected_origins") or ()),
            detected_at=value.get("detected_at"),
            recovered_at=value.get("recovered_at"),
            duration_seconds=value.get("duration_seconds"),
            baseline=context.get("baseline"),
            protocol_limit=context.get("protocol_limit"),
            healthy_ceiling=context.get("healthy_ceiling"),
            sticky_baseline=context.get("sticky_baseline") is True,
            proxy_fingerprint=value.get("proxy_fingerprint"),
        )


class OpenAIConnectivityNotificationService:
    """Queue connectivity emails using the latest saved SMTP configuration."""

    def __init__(
        self,
        config_getter: Callable[[], Any],
        *,
        smtp_ssl_factory: Callable[..., Any] = smtplib.SMTP_SSL,
        thread_factory: Callable[..., Any] = threading.Thread,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.config_getter = config_getter
        self.smtp_ssl_factory = smtp_ssl_factory
        self.dispatcher = NotificationQueue(
            self._send,
            notification_type=OpenAIConnectivityNotification,
            capacity=NOTIFICATION_QUEUE_CAPACITY,
            thread_factory=thread_factory,
            now_fn=now_fn,
        )

    def _config(self) -> dict[str, Any]:
        value = self.config_getter()
        source = (
            value.get("email_notification")
            if isinstance(value, Mapping) and "email_notification" in value
            else value
        )
        return normalize_email_notification(source)

    def _send(self, notification: OpenAIConnectivityNotification) -> None:
        SmtpNotificationSender(
            self._config(),
            smtp_ssl_factory=self.smtp_ssl_factory,
        ).send_connectivity(notification)

    def submit(self, notification: OpenAIConnectivityNotification) -> bool:
        config = self._config()
        if not config["enabled"] or not config["events"][EVENT_OPENAI_AUTH_CONNECTIVITY]:
            return False
        return self.dispatcher.submit(notification)

    def public_status(self) -> dict[str, Any]:
        return self.dispatcher.public_status()

    def close(self, *, wait: bool = True, timeout: float = 2.0) -> None:
        self.dispatcher.close(wait=wait, timeout=timeout)
