"""Central retry classification for Free registration tasks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


_BLOCKED_HTTP_STATUSES = frozenset({400, 401, 403, 409, 422, 429})
_BLOCKED_MARKERS = (
    "captcha",
    "challenge",
    "security",
    "invalid_totp",
    "invalid code",
    "rate_limit",
    "account_disabled",
    "account_banned",
    "suspended",
)
_PRE_SUBMISSION_NODES = frozenset({
    "free_run_stop",
    "free_proxy_binding",
    "free_proxy_lease",
    "free_protocol_preflight",
    "free_protocol_warmup",
    "free_camoufox_dependency",
    "free_camoufox_launch",
    "free_camoufox_navigation",
    "oauth_create_node",
    "proxy_protocol_mismatch",
    "proxy_auth_rejected",
    "proxy_dns_failed",
    "proxy_connect_timeout",
    "proxy_connection_reset",
    "proxy_tls_certificate_error",
    "proxy_connect_failed",
})


@dataclass(frozen=True, slots=True)
class RetryDecision:
    retry: bool
    reusable_mailbox: bool = False
    delay_seconds: float = 0.0
    reason: str = ""


class FreeRetryPolicy:
    def __init__(self, *, max_attempts: int = 3, base_delay_seconds: float = 1.0) -> None:
        self.max_attempts = max(1, int(max_attempts))
        self.base_delay_seconds = max(0.0, float(base_delay_seconds))

    @staticmethod
    def _failure(value: Any) -> Mapping[str, Any]:
        if isinstance(value, Mapping) and isinstance(value.get("failure"), Mapping):
            return value["failure"]
        return value if isinstance(value, Mapping) else {}

    def decide(self, value: Any, *, attempt: int = 0) -> RetryDecision:
        failure = self._failure(value)
        node = str(failure.get("node_code") or "").strip().lower()
        retryable = failure.get("retryable") is not False
        try:
            status = int(failure.get("http_status") or 0)
        except (TypeError, ValueError):
            status = 0
        text = " ".join(
            str(failure.get(key) or "").lower()
            for key in ("error_code", "provider_code", "public_message", "technical_summary")
        )
        blocked = status in _BLOCKED_HTTP_STATUSES or any(marker in text for marker in _BLOCKED_MARKERS)
        within_limit = max(0, int(attempt)) + 1 < self.max_attempts
        retry = retryable and within_limit and not blocked
        reusable = node in _PRE_SUBMISSION_NODES
        delay = self.base_delay_seconds * (2 ** max(0, int(attempt))) if retry else 0.0
        reason = "retryable_transient" if retry else "retry_blocked"
        if not within_limit:
            reason = "attempt_limit"
        elif blocked:
            reason = "business_or_security_stop"
        elif not retryable:
            reason = "explicit_non_retryable"
        return RetryDecision(retry, reusable, min(delay, 30.0), reason)


__all__ = ["FreeRetryPolicy", "RetryDecision"]
