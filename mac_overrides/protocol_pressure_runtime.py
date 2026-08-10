"""Main-chain pressure classification and task admission fallbacks."""

from __future__ import annotations

from typing import Any, Callable


class ProtocolPressurePolicy:
    """Classify main-chain pressure and coordinate task-level fallbacks."""

    MAILBOX_CODES = frozenset(
        {"email_code_timeout", "mailbox_login_failed", "mailbox_unavailable"}
    )
    MAILBOX_NODES = frozenset({"email_slot_waiting", "email_login"})
    MAILBOX_MARKERS = (
        "mailbox_", "gptmail_", "manual_code_timeout",
        "microsoft token refresh failed", "authenticated but not connected",
        "mailbox imap", "imaplib", "authenticationfailed",
    )
    MAIN_CHAIN_NODES = frozenset({
        "oauth_create_node", "oauth_session", "oauth_authorize_node",
        "email_password", "email_code_waiting", "email_code_verifying",
        "mfa_otp_verifying", "phone_submitting", "sms_verifying",
        "finalizing_profile", "finalizing_callback", "finalizing_token",
    })
    SMS_NODES = frozenset({"phone_acquiring", "sms_waiting"})
    SMS_CODES = frozenset({
        "phone_acquisition_failed", "sms_activation_replaced", "sms_key_missing",
        "sms_key_pool_temporarily_unavailable", "sms_no_code",
        "sms_poll_already_active", "sms_provider_poll_failed",
        "sms_provider_pool_unavailable", "sms_provider_ready_failed",
        "sms_route_pool_exhausted", "sms_timeout", "sms_wait_failed",
    })
    SMS_MARKERS = (
        "sms_provider_", "sms_key_", "sms_route_", "sms_activation_",
        "sms_poll_", "sms_timeout", "getnumber failed", "no_numbers",
    )

    def __init__(
        self,
        *,
        progress_getter: Callable[[Any], Any],
        classify_failure: Callable[..., Any],
        task_gate_getter: Callable[[], Any],
        inflight_gate_getter: Callable[[], Any],
        fd_exhaustion: Callable[[Any], bool],
    ) -> None:
        self.progress_getter = progress_getter
        self.classify_failure = classify_failure
        self.task_gate_getter = task_gate_getter
        self.inflight_gate_getter = inflight_gate_getter
        self.fd_exhaustion = fd_exhaustion

    def pressure_failure(
        self,
        task_id: Any,
        value: Any,
        *,
        failure: Any = None,
    ) -> dict[str, Any]:
        if isinstance(failure, dict) and failure:
            return failure
        try:
            candidate = self.classify_failure(
                result=value if isinstance(value, dict) else None,
                error="" if isinstance(value, dict) else value,
                progress=self.progress_getter(task_id),
                status="retryable_infra",
            )
            return candidate if isinstance(candidate, dict) else {}
        except Exception:
            return {}

    def is_mailbox_local(
        self,
        task_id: Any,
        value: Any,
        *,
        failure: Any = None,
    ) -> bool:
        progress = self.progress_getter(task_id)
        if str((progress or {}).get("code") or "").strip().lower() in self.MAILBOX_NODES:
            return True
        classified = self.pressure_failure(task_id, value, failure=failure)
        if str(classified.get("error_code") or "").strip().lower() in self.MAILBOX_CODES:
            return True
        text = str(value or "").strip().lower()
        return any(marker in text for marker in self.MAILBOX_MARKERS)

    def is_sms_local(
        self,
        task_id: Any,
        value: Any,
        *,
        failure: Any = None,
    ) -> bool:
        classified = failure if isinstance(failure, dict) else {}
        progress = self.progress_getter(task_id)
        progress_node = str((progress or {}).get("code") or "").strip().lower()
        node_code = str(classified.get("node_code") or "").strip().lower()
        error_code = str(classified.get("error_code") or "").strip().lower()
        if progress_node in self.SMS_NODES or node_code in self.SMS_NODES:
            return True
        if error_code in self.SMS_CODES:
            return True
        text = str(value or "").strip().lower()
        return any(marker in text for marker in self.SMS_MARKERS)

    def main_chain_source(
        self,
        task_id: Any,
        value: Any,
        *,
        failure: Any = None,
    ) -> tuple[bool, dict[str, Any]]:
        classified = self.pressure_failure(task_id, value, failure=failure)
        if self.is_mailbox_local(task_id, value, failure=classified):
            return False, classified
        if self.is_sms_local(task_id, value, failure=classified):
            return False, classified
        progress = self.progress_getter(task_id)
        node_code = str(
            (progress or {}).get("code") or classified.get("node_code") or ""
        ).strip().lower()
        return node_code in self.MAIN_CHAIN_NODES, classified

    @staticmethod
    def is_rate_limited(failure: Any) -> bool:
        if not isinstance(failure, dict):
            return False
        try:
            return int(failure.get("http_status")) == 429
        except (TypeError, ValueError):
            return False

    def report_task_pressure(
        self,
        task_id: Any,
        value: Any,
        *,
        node_code: Any = "",
        immediate: bool = False,
        inflight_permanent: bool = True,
    ) -> None:
        task_gate = self.task_gate_getter()
        inflight_gate = self.inflight_gate_getter()
        if task_gate is None and inflight_gate is None:
            return
        identifier = str(task_id or "").strip()
        code = str(node_code or "").strip().lower()
        if not code:
            code = str(
                self.pressure_failure(identifier, value).get("node_code")
                or "infrastructure_pressure"
            ).strip().lower()
        try:
            if inflight_permanent and inflight_gate is not None:
                reason = code or "protocol_pressure"
                if immediate or reason in {
                    "http_429", "oauth_rate_limit", "session_invalid",
                    "oauth_session_invalid",
                }:
                    inflight_gate.report_pressure(reason)
            if task_gate is None:
                return
            if self.fd_exhaustion(value):
                task_gate.report_resource_exhaustion(identifier, "resource_fd_exhausted")
                return
            task_gate.report_pressure(
                identifier,
                code or "infrastructure_pressure",
                immediate=bool(immediate),
            )
        except Exception:
            pass


__all__ = ["ProtocolPressurePolicy"]
