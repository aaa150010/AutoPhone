"""Pure recovery policies for the recovered authorization runtime."""

from __future__ import annotations

from typing import Any


_SUB2_EXPIRED_MARKERS = (
    "session not found or expired",
    "sub2_session_expired",
    "openai_oauth_session_not_found",
)
_POST_PHONE_STATES = {
    "PHONE_OTP_VERIFIED",
    "CALLBACK_RECEIVED",
}


def should_retry_expired_sub2_session(result: Any) -> bool:
    """Retry only when a completed phone flow outlived its SUB2 OAuth session."""
    if not isinstance(result, dict):
        return False
    error = " ".join(
        str(result.get(name) or "")
        for name in ("error", "phase2_error", "local_oauth_exchange_error", "technical_error")
    ).lower()
    if "sub2_exchange_failed" not in error:
        return False
    if not any(marker in error for marker in _SUB2_EXPIRED_MARKERS):
        return False

    events = result.get("codex_chain_events")
    if not isinstance(events, list):
        return False
    states = {
        str(item.get("state") or "")
        for item in events
        if isinstance(item, dict)
    }
    return bool(states.intersection(_POST_PHONE_STATES))
