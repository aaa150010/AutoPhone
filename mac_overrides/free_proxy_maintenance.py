"""Shared pool-level maintenance entry point for every Free proxy consumer.

Startup, live checks, plan rechecks and rebinds all allocate from the same
``healthy_random`` pool, so they must funnel replacement minting through one
gated, serialized path: while the pool-level challenge breaker is tripped or
the tunnel gateway fingerprint is blocked, maintenance is a no-op and the
operator's reset stays the single recovery entry.  A single caller-supplied
lock (shared across all consumers) prevents concurrent maintenance passes
from minting beyond the target deficit.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping
import threading

try:
    from .free_proxy_tunnel import ensure_target, resolve_target_size, template_from_config
    from .free_register_common import FreeRegisterError
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_proxy_tunnel import ensure_target, resolve_target_size, template_from_config  # type: ignore[no-redef]
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]


# Process-wide fallback lock so consumers that were not given the manager's
# lock (injected services, legacy callers) still serialize minting.
_DEFAULT_MAINTENANCE_LOCK = threading.Lock()


def maintain_proxy_pool(
    pool: Any,
    config: Mapping[str, Any],
    *,
    breaker: Any | None = None,
    lock: threading.Lock | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> int:
    """Bring the dispatchable pool back to its configured target size.

    Returns the number of tunnel rows minted.  A missing/disabled template or
    a zero target is a no-op (historical behavior).  When ``breaker`` reports
    a tripped pool breaker or a blocked gateway, minting is skipped entirely
    until an operator resets through the existing breaker-reset control.
    Mint exceptions propagate so the caller can attach structured
    diagnostics; the caller's own lock (or a shared default) serializes
    concurrent passes.
    """
    settings = config if isinstance(config, Mapping) else {}
    template = template_from_config(settings)
    if template is None:
        return 0
    target = resolve_target_size(settings)
    if target <= 0:
        return 0
    if breaker is not None:
        try:
            if breaker.tripped() or breaker.gateway_blocked():
                return 0
        except Exception:
            # A broken breaker probe must not wedge maintenance of an
            # otherwise healthy pool; fall through to normal minting.
            pass
    guard = lock or _DEFAULT_MAINTENANCE_LOCK
    with guard:
        return ensure_target(pool, template, target=target, on_progress=on_progress)


def pool_empty_error_code(breaker: Any | None) -> str:
    """Classify an empty-pool allocation failure for the shared consumers.

    ``free_proxy_breaker_tripped`` distinguishes "the operator must reset the
    pool circuit before anything can be allocated" from the plain
    ``free_proxy_pool_empty`` state where the pool simply has no healthy
    exit yet.
    """
    if breaker is not None:
        try:
            if breaker.tripped() or breaker.gateway_blocked():
                return "free_proxy_breaker_tripped"
        except Exception:
            pass
    return "free_proxy_pool_empty"


def is_pool_empty_error(exc: BaseException) -> bool:
    """True when a binder raised the store's pool-empty health error."""
    return (
        isinstance(exc, FreeRegisterError)
        and str(getattr(exc, "error_code", "") or "") == "free_proxy_pool_empty"
    )


def bind_with_pool_maintenance(
    bind: Callable[[], list[Any]],
    *,
    config: Mapping[str, Any],
    maintainer: Callable[[Mapping[str, Any]], int] | None = None,
    note_maintain_failure: Callable[[BaseException], None] | None = None,
) -> tuple[list[Any], BaseException | None]:
    """One shared-pool allocation with an empty-pool maintenance retry.

    ``bind`` performs the actual ``bind(...)`` call and returns bindings (or
    raises the store's pool-empty health error).  When the pool answers empty
    — an empty list or that error — ``maintainer`` runs once (breaker and
    gateway gates inside make it a no-op when the operator must reset first)
    and the bind is re-attempted.  Returns ``(bindings, last_empty_error)``:
    ``last_empty_error`` is set only when the final attempt still found no
    dispatchable proxy, so callers can raise their own breaker-aware error
    (see ``pool_empty_error_code``) while keeping their chain-specific
    exception type.  A maintenance failure never masks allocation: it is
    reported through ``note_maintain_failure`` and the retry still runs.
    """
    last_error: BaseException | None = None
    try:
        bindings = list(bind())
    except Exception as exc:
        if not is_pool_empty_error(exc):
            raise
        bindings, last_error = [], exc
    if bindings or maintainer is None:
        return bindings, last_error
    try:
        maintainer(config)
    except Exception as exc:
        if note_maintain_failure is not None:
            try:
                note_maintain_failure(exc)
            except Exception:
                pass
    try:
        bindings = list(bind())
    except Exception as exc:
        if not is_pool_empty_error(exc):
            raise
        bindings, last_error = [], exc
    if bindings:
        # The refill cleared the emptiness; the previous empty answer is no
        # longer the caller's concern.
        last_error = None
    return bindings, last_error


__all__ = [
    "bind_with_pool_maintenance",
    "is_pool_empty_error",
    "maintain_proxy_pool",
    "pool_empty_error_code",
]
