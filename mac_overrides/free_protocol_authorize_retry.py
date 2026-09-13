"""Same-session single retry for the Free protocol authorize navigation.

The first plain HTTP 403 on an authorize navigation usually refreshes the
Cloudflare ``__cf_bm`` cookie inside the current session; one in-place retry
keeps that cookie and the same pool exit instead of burning both. Security
challenge pages and post-email steps keep their existing nodes and budgets.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, Callable

try:
    from .free_protocol_diagnostics import response_status
    from .free_protocol_security import is_security_challenge
except ImportError:  # pragma: no cover - top-level recovery import
    from free_protocol_diagnostics import response_status  # type: ignore[no-redef]
    from free_protocol_security import is_security_challenge  # type: ignore[no-redef]


__all__ = ["authorize_403_same_session_retry"]

_RETRY_DELAY_SECONDS = 1.0


def _log_compat(log: Callable[..., Any] | None, message: str, level: str) -> None:
    if not callable(log):
        return
    try:
        log(message, level)
    except TypeError:
        try:
            log(message)
        except Exception:
            # Log delivery must never break the authorize navigation.
            pass


def authorize_403_same_session_retry(
    navigate: Callable[[], Any],
    *,
    log: Callable[..., Any] | None = None,
    node_code: str = "free_oauth_session",
    node_label: str = "Free OAuth 会话",
    stop_requested: Callable[[], bool] | None = None,
) -> Any:
    """Run ``navigate`` once and retry it a single time in the same session.

    Only a plain 403 response envelope (never a security challenge page)
    triggers the in-place retry, so the refreshed Cloudflare cookie stays in
    the shared cookie jar. Any other response or exception is returned or
    raised unchanged for the existing node classification; the retry never
    consumes the challenge-switch budget.
    """
    first = navigate()
    if not isinstance(first, Mapping):
        return first
    if response_status(first) != 403 or is_security_challenge(first):
        return first
    if callable(stop_requested) and stop_requested():
        return first
    _log_compat(
        log,
        f"[{node_label}] authorize 导航返回 HTTP 403，保留当前会话与 CF Cookie 同会话重试一次"
        f"（节点 {node_code}，不消耗挑战换线预算）",
        "warn",
    )
    time.sleep(_RETRY_DELAY_SECONDS)
    return navigate()
