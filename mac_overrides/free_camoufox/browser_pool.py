"""Browser-pool boundary for the Free Camoufox runtime.

`CamoufoxBrowserPool` remains implemented by the battle-tested legacy module
for now.  This wrapper gives new code a stable dependency-injection point and
keeps pool lifecycle helpers out of registration state-machine code.  Lazy
resolution avoids importing optional browser packages during API startup.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Any, Mapping


def _legacy_runtime() -> Any:
    try:
        from .. import free_camoufox_runtime
        return free_camoufox_runtime
    except Exception:  # pragma: no cover - top-level recovery import
        import free_camoufox_runtime  # type: ignore
        return free_camoufox_runtime


@dataclass(frozen=True, slots=True)
class PoolAdmission:
    """Result metadata for an admission attempt."""

    accepted: bool
    pool_key: tuple[Any, ...] = ()
    reason: str = ""


class BrowserPoolGateway:
    """Dependency-injection gateway around the shared legacy pool registry."""

    def __init__(self, config: Mapping[str, Any], *, pool: Any | None = None) -> None:
        self.config = dict(config)
        self._pool = pool

    @property
    def pool(self) -> Any:
        if self._pool is None:
            self._pool = _legacy_runtime()._pool_for(self.config)
        return self._pool

    def register(self, **kwargs: Any) -> Any:
        return self.pool.register(**kwargs)

    def debug_state(self) -> dict[str, Any]:
        getter = getattr(self.pool, "debug_state", None)
        return dict(getter() if callable(getter) else {})

    def shutdown(self, *, force: bool = False) -> Any:
        closer = getattr(self.pool, "shutdown", None)
        if not callable(closer):
            return True
        try:
            return closer(force=force)
        except TypeError:
            return closer()


def pool_for(config: Mapping[str, Any]) -> Any:
    """Return the canonical pool for a normalized config."""

    return _legacy_runtime()._pool_for(config)


def pool_key(config: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(_legacy_runtime()._camoufox_pool_key(config))


def shutdown_pools(*, force: bool = False) -> dict[str, int]:
    return dict(_legacy_runtime().shutdown_camoufox_pools(force=force))


def debug_state(config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return dict(_legacy_runtime().camoufox_debug_state(config))


def annotate_debug_session(session_id: str, incident_id: str) -> bool:
    return bool(_legacy_runtime().annotate_camoufox_debug_session(session_id, incident_id))


def close_debug_browsers(
    session_id: str = "", *, config: Mapping[str, Any] | None = None,
) -> dict[str, int]:
    return dict(_legacy_runtime().close_camoufox_debug_browsers(session_id, config=config))


def __getattr__(name: str) -> Any:
    """Expose legacy pool classes for import compatibility."""

    if name in {"CamoufoxBrowserPool", "_BrowserSlot", "_DebugSession"}:
        return getattr(_legacy_runtime(), name)
    if name in {
        "_pool_for", "_camoufox_pool_key", "_pool_timeout",
        "_pool_shutdown_wait_budget", "_retire_idle_camoufox_pools",
        "_retire_idle_camoufox_pools_locked", "_shutdown_camoufox_pools_locked",
    }:
        return getattr(_legacy_runtime(), name)
    raise AttributeError(name)


__all__ = [
    "BrowserPoolGateway",
    "CamoufoxBrowserPool",
    "PoolAdmission",
    "annotate_debug_session",
    "close_debug_browsers",
    "debug_state",
    "pool_for",
    "pool_key",
    "shutdown_pools",
    "_pool_for",
    "_camoufox_pool_key",
    "_pool_timeout",
    "_pool_shutdown_wait_budget",
    "_retire_idle_camoufox_pools",
    "_retire_idle_camoufox_pools_locked",
    "_shutdown_camoufox_pools_locked",
]
