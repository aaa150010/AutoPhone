"""Fully asynchronous Free batch startup.

``/api/free/start`` historically performed protocol preflight, the full
mailbox-pool scan with per-row account evidence checks, proxy binding, and
executor creation inside the request thread, so the click froze for tens of
seconds.  This module moves that heavy section onto one background worker
while keeping the observable contract: validation errors still fail fast,
a second start is rejected while the first is pending, and startup failures
surface as structured diagnostic events instead of a blocked HTTP response.
"""

from __future__ import annotations

import inspect
import threading
from typing import Any, Mapping


class FreeStartAsyncCoordinator:
    """Owns the single background startup slot for one Free manager."""

    def __init__(self, manager: Any) -> None:
        self._manager = manager
        self._lock = threading.Lock()
        self._in_progress = False
        self._pending: dict[str, Any] | None = None
        self._error: dict[str, Any] | None = None

    @property
    def in_progress(self) -> bool:
        with self._lock:
            return self._in_progress

    def pending_summary(self) -> dict[str, Any]:
        with self._lock:
            if not self._in_progress:
                return {}
            return {
                "starting": True,
                "driver": str((self._pending or {}).get("driver") or ""),
                "requested_count": int((self._pending or {}).get("requested_count") or 0),
            }

    def last_error(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._error or {})

    def start_in_background(
        self,
        config: Mapping[str, Any],
        *,
        pool_content: str,
        proxy_content: str,
        row_ids: list[str],
        on_error: Any = None,
    ) -> dict[str, Any]:
        """Submit the batch start and return immediately.

        ``on_error`` receives the failure mapping when the background start
        raises; the HTTP layer uses it to publish a structured diagnostic
        event, keeping the original node code and Chinese label intact.
        """
        worker = threading.Thread(
            target=self._run_start,
            args=(
                dict(config),
                pool_content,
                proxy_content,
                list(row_ids),
                on_error,
            ),
            name="free-start-async",
            daemon=True,
        )
        with self._lock:
            if self._in_progress:
                raise FreeStartInProgressError()
            self._in_progress = True
            self._error = None
            self._pending = {
                "driver": str(config.get("driver") or "protocol").strip().lower(),
                "requested_count": _requested_count(config),
            }
        worker.start()
        # Deliberately no ``public_state`` here: the background start holds
        # the manager lock for its whole preparation section, so a lock-based
        # state read would block the HTTP response until preparation ends
        # (measured 39s with a Camoufox debug batch). The frontend reacts to
        # the ``starting`` flag and its 1s polling picks up progress.
        return {
            "batch_id": "",
            "async": True,
            "starting": True,
            "pending": self.pending_summary(),
            "tasks": [],
            "state": {"running": False, "starting": True, "tasks": [], "summary": {}},
        }

    def _run_start(
        self,
        config: Mapping[str, Any],
        pool_content: str,
        proxy_content: str,
        row_ids: list[str],
        on_error: Any,
    ) -> None:
        try:
            self._invoke_start(config, pool_content, proxy_content, row_ids)
        except Exception as exc:
            failure = start_failure_mapping(exc)
            with self._lock:
                self._error = failure
            if callable(on_error):
                try:
                    on_error(failure)
                except Exception:
                    # Error publication must not mask the original failure.
                    pass
        finally:
            with self._lock:
                self._in_progress = False
                self._pending = None

    def _invoke_start(
        self,
        config: Mapping[str, Any],
        pool_content: str,
        proxy_content: str,
        row_ids: list[str],
    ) -> Any:
        """Call manager.start, adapting to managers without row_ids support."""
        start = self._manager.start
        kwargs: dict[str, Any] = {"pool_content": pool_content, "proxy_content": proxy_content}
        if row_ids:
            kwargs["row_ids"] = row_ids
        try:
            inspect.signature(start).bind(config, **kwargs)
        except TypeError:
            kwargs.pop("row_ids", None)
        return start(config, **kwargs)


def start_failure_mapping(exc: BaseException) -> dict[str, Any]:
    """Project one start failure through the structured error contract."""
    node_code = getattr(exc, "node_code", "")
    node_label = getattr(exc, "node_label", "")
    error_code = getattr(exc, "error_code", "")
    retryable = bool(getattr(exc, "retryable", False))
    if node_code and node_label:
        return {
            "node_code": str(node_code),
            "node_label": str(node_label),
            "error_code": str(error_code or "free_run_start_failed"),
            "public_message": f"{node_label} [{node_label}/{node_code}]：{exc}",
            "technical_summary": str(exc),
            "retryable": retryable,
            "provider_code": str(getattr(exc, "provider_code", "") or ""),
        }
    return {
        "node_code": "free_run_start",
        "node_label": "启动 Free 注册",
        "error_code": "free_run_start_failed",
        "public_message": f"启动 Free 注册 [启动 Free 注册/free_run_start]：启动失败（{type(exc).__name__}）",
        "technical_summary": f"start failed ({type(exc).__name__})",
        "retryable": True,
        "provider_code": type(exc).__name__,
    }


class FreeStartInProgressError(RuntimeError):
    """Raised when a second async start is requested while one is pending."""


def _requested_count(config: Mapping[str, Any]) -> int:
    for key in ("target_count", "free_target_count"):
        try:
            return max(1, int(config.get(key)))
        except (TypeError, ValueError):
            continue
    return 1


__all__ = ["FreeStartAsyncCoordinator", "FreeStartInProgressError", "start_failure_mapping"]
