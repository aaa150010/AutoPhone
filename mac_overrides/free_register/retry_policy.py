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


def consecutive_same_failures(history: Any, failure: Mapping[str, Any]) -> int:
    """Count how many trailing history entries match ``failure``'s identity.

    History entries are most-recent-last (the shape of ``proxy_attempts``).
    Identity is ``node_code`` + ``error_code``; entries missing both are
    never counted as a match.
    """
    node = str(failure.get("node_code") or "").strip().lower()
    error_code = str(failure.get("error_code") or "").strip().lower()
    if not node and not error_code:
        return 0
    count = 0
    for item in reversed(list(history) if isinstance(history, (list, tuple)) else []):
        if not isinstance(item, Mapping):
            break
        item_node = str(item.get("node_code") or item.get("stage") or "").strip().lower()
        item_error = str(item.get("error_code") or "").strip().lower()
        if node and item_node != node:
            break
        if error_code and item_error != error_code:
            break
        if not item_node and not item_error:
            break
        count += 1
    return count


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

    def decide(self, value: Any, *, attempt: int = 0, recent_same_failures: int = 0) -> RetryDecision:
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
        # A same-error short circuit only stops failures that the generic
        # rules would otherwise retry.  Business/security blocks already stop.
        same_error_stop = (
            recent_same_failures >= 2
            and not blocked
            and within_limit
            and retryable
        )
        retry = retryable and within_limit and not blocked and not same_error_stop
        reusable = node in _PRE_SUBMISSION_NODES
        delay = self.base_delay_seconds * (2 ** max(0, int(attempt))) if retry else 0.0
        reason = "retryable_transient" if retry else "retry_blocked"
        if not within_limit:
            reason = "attempt_limit"
        elif blocked:
            reason = "business_or_security_stop"
        elif not retryable:
            reason = "explicit_non_retryable"
        elif same_error_stop:
            reason = "same_error_short_circuit"
        return RetryDecision(retry, reusable, min(delay, 30.0), reason)


__all__ = ["FreeRetryPolicy", "RetryDecision", "consecutive_same_failures"]
