"""Request-scoped polling state for the shared mailbox OTP client."""

from __future__ import annotations

import time
from typing import Any, Callable

try:
    from .mailbox_url_runtime import (
        BASELINE_FALLBACK_MAX_ATTEMPTS,
        BASELINE_FALLBACK_POLL_MILESTONES,
        RECENT_BASELINE_CODE_WINDOW_SECONDS,
        MailboxScan,
        MailboxSelection,
        MailboxUrlClient,
        REQUEST_CLOCK_SKEW_SECONDS,
        select_latest_code,
    )
except ImportError:  # Loaded as a top-level runtime override.
    from mailbox_url_runtime import (  # type: ignore[no-redef]
        BASELINE_FALLBACK_MAX_ATTEMPTS,
        BASELINE_FALLBACK_POLL_MILESTONES,
        RECENT_BASELINE_CODE_WINDOW_SECONDS,
        MailboxScan,
        MailboxSelection,
        MailboxUrlClient,
        REQUEST_CLOCK_SKEW_SECONDS,
        select_latest_code,
    )


class MailboxRequestState:
    """Keep one mailbox request's baseline and fallback decisions isolated."""

    def __init__(self, client: MailboxUrlClient, *, now_fn: Callable[[], float] = time.time) -> None:
        self.client = client
        self.now_fn = now_fn
        self.last_scan: MailboxScan | None = None
        self.last_selection: MailboxSelection | None = None
        self.baseline_identities: frozenset[str] = frozenset()
        self.requested_at: float | None = None
        self.active = False
        self.max_poll_attempts = 30
        self.poll_attempt = 0
        self.baseline_fallback_attempts = 0
        self.baseline_fallback_age_seconds: int | None = None
        self.baseline_fallback_poll: int | None = None
        self.baseline_fallback_identities: set[str] = set()
        self.baseline_fallback_codes: set[str] = set()

    def configure_request(self, *, max_poll_attempts: int) -> None:
        self.max_poll_attempts = max(1, int(max_poll_attempts))

    def begin_request(self) -> None:
        if self.active:
            return
        self.baseline_identities = self.last_scan.identities if self.last_scan is not None else frozenset()
        self.requested_at = self.now_fn()
        self.active = True
        self.poll_attempt = 0
        self.baseline_fallback_age_seconds = None
        self.baseline_fallback_poll = None
        request_refresh = getattr(self.client, "_request_client_mailbox_refresh", None)
        if callable(request_refresh):
            request_refresh(force=True)

    def _baseline_fallback(
        self,
        scan: MailboxScan,
        *,
        reason: str,
    ) -> MailboxSelection | None:
        if self.baseline_fallback_attempts >= BASELINE_FALLBACK_MAX_ATTEMPTS:
            return None
        fallback_scan = MailboxScan(
            tuple(
                message
                for message in scan.messages
                if message.identity not in self.baseline_fallback_identities
                and message.code not in self.baseline_fallback_codes
            ),
            scan.page_fingerprint,
            scan.fetched_at,
            scan.diagnostics,
        )
        fallback = select_latest_code(
            fallback_scan,
            baseline_identities=self.baseline_identities,
            requested_at=self.requested_at,
            allow_baseline_fallback=True,
            recent_baseline_seconds=RECENT_BASELINE_CODE_WINDOW_SECONDS,
            baseline_fallback_reason=reason,
        )
        if not fallback.code:
            return None
        self.baseline_fallback_attempts += 1
        self.baseline_fallback_identities.add(fallback.identity)
        self.baseline_fallback_codes.add(fallback.code)
        self.baseline_fallback_poll = self.poll_attempt
        matched = next(
            (message for message in scan.messages if message.identity == fallback.identity),
            None,
        )
        if (
            matched is not None
            and matched.received_timestamp is not None
            and self.requested_at is not None
        ):
            self.baseline_fallback_age_seconds = max(
                0,
                int(self.requested_at - matched.received_timestamp),
            )
        self.last_selection = fallback
        return fallback

    def snapshot(self) -> MailboxSelection:
        scan = self.client.scan()
        if self.active:
            self.poll_attempt += 1
        self.last_scan = scan
        self.last_selection = select_latest_code(
            scan,
            baseline_identities=self.baseline_identities,
            requested_at=self.requested_at,
            include_existing=not self.active,
        )
        if (
            self.active
            and not self.last_selection.code
            and self.poll_attempt in BASELINE_FALLBACK_POLL_MILESTONES
            and self.poll_attempt <= self.max_poll_attempts
        ):
            self._baseline_fallback(scan, reason="mailbox_baseline_code_fallback")
        if self.active and not self.last_selection.code:
            request_refresh = getattr(self.client, "_request_client_mailbox_refresh", None)
            if callable(request_refresh):
                request_refresh()
        return self.last_selection

    def final_baseline_fallback(self) -> MailboxSelection:
        scan = self.client.scan()
        self.last_scan = scan
        self.last_selection = select_latest_code(
            scan,
            baseline_identities=self.baseline_identities,
            requested_at=self.requested_at,
            include_existing=not self.active,
        )
        if self.last_selection.code:
            return self.last_selection
        fallback = self._baseline_fallback(
            scan,
            reason="mailbox_final_baseline_code_fallback",
        )
        return fallback or self.last_selection

    def finish_request(self) -> None:
        if self.last_scan is not None:
            self.baseline_identities = self.last_scan.identities
        self.active = False
        self.requested_at = None
        finish_client_request = getattr(self.client, "_finish_client_mailbox_request", None)
        if callable(finish_client_request):
            finish_client_request()


def _runtime_state(provider: Any) -> MailboxRequestState:
    state = getattr(provider, "_generic_mailbox_state", None)
    if isinstance(state, MailboxRequestState):
        return state
    client = MailboxUrlClient(
        getattr(provider, "mailbox_url", ""),
        timeout_seconds=getattr(provider, "timeout_seconds", 15),
        proxy=getattr(provider, "proxy", ""),
    )
    state = MailboxRequestState(client)
    setattr(provider, "_generic_mailbox_state", state)
    return state


def runtime_snapshot(provider: Any) -> MailboxSelection:
    return _runtime_state(provider).snapshot()


def begin_runtime_request(provider: Any) -> None:
    _runtime_state(provider).begin_request()


def configure_runtime_request(provider: Any, *, max_poll_attempts: int) -> None:
    _runtime_state(provider).configure_request(max_poll_attempts=max_poll_attempts)


def final_runtime_baseline_fallback(provider: Any) -> MailboxSelection:
    return _runtime_state(provider).final_baseline_fallback()


def finish_runtime_request(provider: Any) -> None:
    state = getattr(provider, "_generic_mailbox_state", None)
    if isinstance(state, MailboxRequestState):
        state.finish_request()


def runtime_diagnostic(provider: Any) -> dict[str, Any]:
    state = getattr(provider, "_generic_mailbox_state", None)
    if not isinstance(state, MailboxRequestState) or state.last_selection is None:
        return {}
    diagnostics = state.last_selection.scan.diagnostics
    return {
        "reason": state.last_selection.reason,
        "baseline_fallback_attempts": int(state.baseline_fallback_attempts),
        "baseline_fallback_age_seconds": state.baseline_fallback_age_seconds,
        "baseline_fallback_poll": state.baseline_fallback_poll,
        "max_poll_attempts": int(state.max_poll_attempts),
        "listing_messages": diagnostics.listing_messages,
        "detail_links": diagnostics.detail_links,
        "detail_refreshed": diagnostics.detail_refreshed,
        "detail_refresh_pending": max(
            diagnostics.detail_links - diagnostics.detail_refreshed,
            0,
        ),
        "detail_errors": diagnostics.detail_errors,
        "refresh_error_code": diagnostics.refresh_error_code,
        "refresh_http_status": diagnostics.refresh_http_status,
        "openai_messages": diagnostics.openai_messages,
        "code_messages": diagnostics.code_messages,
        "otp_context_messages": diagnostics.otp_context_messages,
        "explicit_code_messages": diagnostics.explicit_code_messages,
        "bare_code_messages": diagnostics.bare_code_messages,
    }


__all__ = [
    "MailboxRequestState",
    "begin_runtime_request",
    "configure_runtime_request",
    "finish_runtime_request",
    "final_runtime_baseline_fallback",
    "runtime_diagnostic",
    "runtime_snapshot",
]
