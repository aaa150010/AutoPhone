"""Browser slot, pool and debug-session registry for Camoufox.

Split out of ``free_camoufox_runtime``; every callable receives the hosting
runtime module as its first ``host`` argument so tests and integrations can
keep patching ``free_camoufox_runtime.<name>`` globals with unchanged
semantics.
"""

from __future__ import annotations

_host_module_ref = None


def _host_mod():
    """Return the hosting runtime module (bound at import time)."""
    return _host_module_ref

import asyncio
from collections import deque
from concurrent.futures import (
    CancelledError as FutureCancelledError,
    TimeoutError as FutureTimeoutError,
)
from dataclasses import dataclass
import inspect
import json
import math
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    from .deadline import (
        MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
        MANUAL_OTP_WINDOW_SECONDS,
        MAX_MANUAL_OTP_WINDOWS,
        RegistrationDeadline,
    )
except ImportError:  # pragma: no cover - top-level recovery import
    from free_camoufox.deadline import (  # type: ignore[no-redef]
        MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
        MANUAL_OTP_WINDOW_SECONDS,
        MAX_MANUAL_OTP_WINDOWS,
        RegistrationDeadline,
    )





@dataclass
class _BrowserSlot:
    manager: Any
    browser: Any
    semaphore: asyncio.Semaphore
    completed: int = 0
    generation: int = 0
    recycle_lock: asyncio.Lock | None = None
    idle_event: asyncio.Event | None = None
    active_contexts: int = 0
    draining: bool = False
    recycle_error: str = ""
    # Contexts retained by the optional debug mode remain attached to the
    # browser until the operator explicitly closes them. They count against
    # the slot's effective capacity even though the task semaphore is released.
    debug_holds: int = 0
    # Playwright may cancel a page coroutine as soon as the browser process
    # disappears, without raising its usual "browser has been closed" error.
    # Keep that signal on the slot so the worker can classify the cancellation
    # instead of exposing a bare concurrent.futures.CancelledError.
    disconnect_requested: bool = False


@dataclass
class _DebugSession:
    """A failed headed context kept available for manual inspection."""

    session_id: str
    task_id: str
    context: Any
    page: Any
    proxy_bridge: Any | None
    slot: host._BrowserSlot
    created_at: float
    artifact_id: str = ""
    incident_id: str = ""
    node_code: str = ""
    node_label: str = ""
    error_code: str = ""
    page_type: str = ""
    safe_page: str = ""
    proxy_fingerprint: str = ""
    trace: host._DebugTrace | None = None
    artifact_path: str = ""


class _HeldSemaphore:
    """Async context wrapper for a permit acquired by an admission helper."""

    def __init__(self, semaphore: asyncio.Semaphore) -> None:
        self.semaphore = semaphore
        self.released = False

    async def __aenter__(self) -> "_host_mod()._HeldSemaphore":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        if not self.released:
            self.released = True
            self.semaphore.release()


class _SlotAdmissionRace(Exception):
    """Internal signal to rescan the pool after a capacity race."""


class CamoufoxBrowserPool:
    """Dedicated asyncio thread with shared browsers and bounded contexts."""

    def __init__(self, config: Mapping[str, Any]) -> None:
        self.config = dict(config)
        # Debug mode is deliberately enabled by the normalized production
        # config. A retained page must be headed even if an older caller still
        # supplies ``headless=True``.
        self.debug_mode, self.headless = _host_mod()._effective_camoufox_headless(self.config)
        self.pool_size = max(1, int(self.config.get("pool_size") or 2))
        self.max_contexts = max(1, int(self.config.get("max_contexts_per_browser") or 3))
        self.context_start_interval = max(0, int(self.config.get("context_start_interval_ms") or 0)) / 1000.0
        self.startup_concurrency = max(1, int(self.config.get("startup_concurrency") or 4))
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        # ``shutdown()`` can be called while the async thread is still
        # initializing.  Keep that request separate from ``_closed`` so the
        # thread can finish its current ``run_until_complete`` before any
        # cleanup coroutine is scheduled.
        self._init_finished = threading.Event()
        self._shutdown_complete = threading.Event()
        self._closed = False
        self._shutdown_requested = threading.Event()
        self._shutdown_task: asyncio.Task[Any] | None = None
        self._init_error: BaseException | None = None
        self._slots: list[_host_mod()._BrowserSlot] = []
        self._global_semaphore: asyncio.Semaphore | None = None
        self._startup_semaphore: asyncio.Semaphore | None = None
        self._context_start_lock: asyncio.Lock | None = None
        self._admission_lock: asyncio.Lock | None = None
        self._next_context_start = 0.0
        self._lock = threading.Lock()
        self._debug_lock = threading.RLock()
        self._debug_sessions: dict[str, _host_mod()._DebugSession] = {}
        self._debug_closing: set[str] = set()
        # Ring buffer of swallowed best-effort failures (cleanup, artifact
        # bookkeeping, watcher cancellation). Only the failure site label and
        # exception class are kept; these never mask the surrounding outcome.
        self._quiet_failures: deque[dict[str, Any]] = deque(maxlen=40)
        self._start()

    def _note_quiet(self, where: str, exc: BaseException) -> None:
        """Record a swallowed best-effort failure without changing semantics.

        Deliberately lock-free: callers may already hold ``self._lock`` and a
        bounded ``deque.append`` is atomic under the GIL.
        """
        try:
            self._quiet_failures.append({
                "where": str(where or "")[:60],
                "error": type(exc).__name__,
                "at": round(time.time(), 3),
            })
        except Exception:
            # Even the quiet note must not break the surrounding best-effort path.
            return

    @staticmethod
    def _task_id_from_kwargs(kwargs: Mapping[str, Any]) -> str:
        nested = kwargs.get("config")
        if isinstance(nested, Mapping):
            value = nested.get("task_id")
            if value:
                return _host_mod()._safe_debug_task_id(value)
        value = kwargs.get("task_id")
        return _host_mod()._safe_debug_task_id(value)

    @staticmethod
    def _page_is_open(page: Any) -> bool:
        if page is None:
            return False
        try:
            checker = getattr(page, "is_closed", None)
            return not bool(checker()) if callable(checker) else True
        except Exception:
            # A page whose state cannot be read is not safe to retain: it is
            # usually already detached from a dead browser process.
            return False

    @staticmethod
    def _debug_retain_allowed(error: BaseException | None) -> bool:
        """Classify terminal errors whose live page is useful to inspect."""
        if error is None:
            return False
        code = str(getattr(error, "error_code", "") or "").strip().lower()
        node = str(getattr(error, "node_code", "") or "").strip().lower()
        page_type = str(getattr(error, "page_type", "") or "").strip().lower()
        if node == "free_run_stop" or code in {
            "free_run_stop", "camoufox_registration_timeout", "camoufox_pool_closed",
            "camoufox_browser_disconnected", "camoufox_context_create_failed",
            "camoufox_page_create_failed", "camoufox_browser_launch_failed",
            "camoufox_home_not_confirmed",
        }:
            return False
        # Keep the post-submit entry shell available in debug mode. This is
        # the only timeout whose live DOM/network trace can distinguish a
        # rejected email transition from a delayed verification navigation;
        # generic timeouts still close their context immediately below.
        if code == "camoufox_entry_transition_timeout":
            return True
        if any(marker in code for marker in ("timeout", "timed_out", "page_state_limit", "page_state_stuck")):
            return False
        if any(marker in code for marker in ("cancel", "stopped", "interrupted")):
            return False
        if code in {
            "free_camoufox_security_challenge",
            "free_oauth_security_challenge",
        } or page_type == "security":
            return True
        return True

    async def _retain_debug_context(
        self,
        *,
        context: Any,
        page: Any,
        proxy_bridge: Any | None,
        slot: _host_mod()._BrowserSlot,
        kwargs: Mapping[str, Any],
        error: BaseException | None = None,
    ) -> bool:
        if not self.debug_mode or not self._page_is_open(page):
            return False
        # The artifact capture below can take several seconds.  During that
        # window the slot may have been disconnected or moved to a replacement
        # browser.  Keep the generation observed for this context and validate
        # it again immediately before installing the debug hold.
        retention_generation = getattr(slot, "generation", 0)
        session_id = f"cam-debug-{uuid.uuid4().hex[:12]}"
        artifact_id = f"cam-artifact-{uuid.uuid4().hex[:12]}"
        nested = kwargs.get("config") if isinstance(kwargs.get("config"), Mapping) else {}
        task_id = self._task_id_from_kwargs(kwargs)
        incident_id = _host_mod()._safe_incident_id(
            getattr(error, "incident_id", "") or nested.get("incident_id")
            or kwargs.get("incident_id")
        )
        node_code = _host_mod().sanitize_failure_text(
            getattr(error, "node_code", "") or nested.get("node_code") or "free_camoufox_browser",
            120,
        )
        node_label = _host_mod().sanitize_failure_text(
            getattr(error, "node_label", "") or nested.get("node_label") or "Camoufox 注册页面",
            160,
        )
        error_code = _host_mod().sanitize_failure_text(
            getattr(error, "error_code", "") or "camoufox_debug_failure", 160,
        )
        page_type = _host_mod().sanitize_failure_text(
            getattr(error, "page_type", "") or "unknown", 80,
        )
        safe_page = _host_mod()._safe_event_url(getattr(error, "safe_page", "") or _host_mod()._safe_url(page)) or "页面地址未知"
        proxy_value = str(kwargs.get("proxy") or nested.get("proxy") or "")
        supplied_fingerprint = nested.get("proxy_fingerprint") or kwargs.get("proxy_fingerprint")
        proxy_fingerprint = _host_mod()._safe_proxy_fingerprint(supplied_fingerprint, proxy_value)
        trace = _host_mod()._page_debug_trace(page)
        artifact_root: Path | None = None
        raw_artifact_root = nested.get("_debug_artifact_dir") or self.config.get("_debug_artifact_dir")
        if raw_artifact_root:
            try:
                artifact_root = Path(str(raw_artifact_root)).expanduser()
            except (TypeError, ValueError, OSError):
                artifact_root = None
        artifact_summary = {
            "task_id": task_id,
            "incident_id": incident_id,
            "node_code": node_code,
            "node_label": node_label,
            "error_code": error_code,
            "page_type": page_type,
            "safe_page": safe_page,
            "proxy_fingerprint": proxy_fingerprint,
            "created_at": time.time(),
        }
        if artifact_root is not None:
            with _host_mod()._ARTIFACT_LOCK:
                _host_mod()._ARTIFACT_PROTECTED_SESSIONS.add(session_id)
        registered = False
        try:
            artifact = await _host_mod()._capture_debug_artifact(
                page=page,
                artifact_root=artifact_root,
                session_id=session_id,
                artifact_id=artifact_id,
                summary=artifact_summary,
                trace=trace,
            )
            session = _host_mod()._DebugSession(
                session_id=session_id,
                task_id=task_id,
                context=context,
                page=page,
                proxy_bridge=proxy_bridge,
                slot=slot,
                created_at=time.time(),
                artifact_id=artifact_id,
                incident_id=incident_id,
                node_code=node_code,
                node_label=node_label,
                error_code=error_code,
                page_type=page_type,
                safe_page=safe_page,
                proxy_fingerprint=proxy_fingerprint,
                trace=trace,
                artifact_path=str(artifact.get("artifact_path") or ""),
            )
            # Register the session and replace the active-context reservation
            # under one admission lock.  The close endpoint and the recycler
            # use this same lock, so neither can observe a session without its
            # capacity hold (or a hold without an owned session).
            if self._admission_lock is not None:
                async with self._admission_lock:
                    slots = getattr(self, "_slots", None)
                    slot_registered = (
                        slots is None
                        or any(candidate is slot for candidate in slots)
                    )
                    if (
                        not self._page_is_open(page)
                        or getattr(self, "_closed", False)
                        or not slot_registered
                        or getattr(slot, "generation", None) != retention_generation
                        or bool(getattr(slot, "draining", False))
                        or not self._browser_connected(getattr(slot, "browser", None))
                    ):
                        return False
                    with self._debug_lock:
                        if session_id not in self._debug_sessions:
                            self._debug_sessions[session_id] = session
                            slot.debug_holds += 1
                            registered = True
            else:
                slots = getattr(self, "_slots", None)
                slot_registered = (
                    slots is None
                    or any(candidate is slot for candidate in slots)
                )
                if (
                    not self._page_is_open(page)
                    or getattr(self, "_closed", False)
                    or not slot_registered
                    or getattr(slot, "generation", None) != retention_generation
                    or bool(getattr(slot, "draining", False))
                    or not self._browser_connected(getattr(slot, "browser", None))
                ):
                    return False
                with self._debug_lock:
                    if session_id not in self._debug_sessions:
                        self._debug_sessions[session_id] = session
                        slot.debug_holds += 1
                        registered = True
        finally:
            if not registered or artifact_root is None:
                with _host_mod()._ARTIFACT_LOCK:
                    _host_mod()._ARTIFACT_PROTECTED_SESSIONS.discard(session_id)
        if error is not None:
            for name, value in (
                ("debug_session_id", session_id),
                ("debug_artifact_id", artifact_id),
                ("artifact_id", artifact_id),
            ):
                try:
                    setattr(error, name, value)
                except Exception as exc:
                    # Enrichment must not mask the original browser failure.
                    self._note_quiet("error_enrich", exc)
        return True

    async def _close_debug_sessions_async(self, session_id: str = "") -> int:
        normalized = str(session_id or "").strip()
        with self._debug_lock:
            if normalized:
                selected = self._debug_sessions.get(normalized)
                sessions = [selected] if selected is not None and normalized not in self._debug_closing else []
            else:
                sessions = [item for key, item in self._debug_sessions.items() if key not in self._debug_closing]
            self._debug_closing.update(item.session_id for item in sessions if item is not None)
        closed = 0
        slots_to_recycle: list[_host_mod()._BrowserSlot] = []
        timeout = float(self.config.get("context_close_timeout_seconds") or 15)
        try:
            for session in sessions:
                if session is None:
                    continue
                context_closed = False
                try:
                    context_closed = await _host_mod()._close_context_safely(session.context, timeout)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    context_closed = False
                if not context_closed:
                    # A retained page can keep Playwright's context close
                    # waiting after a renderer/network failure. Close the
                    # visible page first, then retry the context once. The
                    # page-level close is sufficient to remove the operator's
                    # window, so do not keep a phantom debug hold if the
                    # detached context itself refuses to close.
                    page_close = getattr(session.page, "close", None)
                    if callable(page_close):
                        try:
                            page_closed = await _host_mod()._close_context_safely(session.page, min(timeout, 5.0))
                        except Exception:
                            page_closed = False
                    else:
                        page_closed = False
                    if page_closed:
                        try:
                            await _host_mod()._close_context_safely(session.context, min(timeout, 5.0))
                        except Exception as exc:
                            # Context close must not mask the original shutdown reason.
                            self._note_quiet("context_close_shutdown", exc)
                        context_closed = True
                bridge_error = ""
                bridge = session.proxy_bridge
                if bridge is not None and context_closed:
                    try:
                        bridge.close()
                    except Exception as exc:
                        # The context is already gone. Do not retain a phantom
                        # capacity hold solely because the local bridge failed
                        # to stop; keep a bounded marker for postmortem.
                        bridge_error = _host_mod().clean(type(exc).__name__, 120)
                with self._debug_lock:
                    self._debug_closing.discard(session.session_id)
                    if context_closed:
                        self._debug_sessions.pop(session.session_id, None)
                if context_closed:
                    if self._admission_lock is not None:
                        async with self._admission_lock:
                            session.slot.debug_holds = max(0, session.slot.debug_holds - 1)
                    else:
                        session.slot.debug_holds = max(0, session.slot.debug_holds - 1)
                    with _host_mod()._ARTIFACT_LOCK:
                        _host_mod()._ARTIFACT_PROTECTED_SESSIONS.discard(session.session_id)
                    if bridge_error and session.artifact_path:
                        # Incident annotation and bridge cleanup both update
                        # the same summary projection. Serialize the complete
                        # read/modify/write cycle so neither field can be lost
                        # when task failure persistence races window cleanup.
                        with _host_mod()._ARTIFACT_LOCK:
                            try:
                                summary_path = Path(session.artifact_path) / "summary.json"
                                payload = json.loads(summary_path.read_text(encoding="utf-8"))
                                if isinstance(payload, dict):
                                    payload["bridge_cleanup_error"] = bridge_error
                                    _host_mod()._atomic_artifact_write(summary_path, payload)
                            except Exception as exc:
                                # Artifact bookkeeping must not break the debug retention.
                                self._note_quiet("bridge_summary_update", exc)
                    # A retained context can postpone the normal
                    # max-registrations recycle. Once the final hold on an
                    # otherwise idle slot is released, perform that recycle
                    # before another task is admitted to the old browser.
                    try:
                        max_registrations = max(
                            1, int(self.config.get("max_registrations_per_browser") or 12),
                        )
                    except (TypeError, ValueError):
                        max_registrations = 12
                    if (
                        session.slot.debug_holds == 0
                        and session.slot.active_contexts == 0
                        and (
                            session.slot.completed >= max_registrations
                            or bool(session.slot.recycle_error)
                            or bool(session.slot.draining)
                        )
                        and all(existing is not session.slot for existing in slots_to_recycle)
                    ):
                        slots_to_recycle.append(session.slot)
                    closed += 1
        finally:
            with self._debug_lock:
                self._debug_closing.difference_update(
                    item.session_id for item in sessions if item is not None
                )
        # Run recycling only after all selected sessions have been removed and
        # their capacity holds released. This keeps an all-sessions close
        # request atomic from the pool's admission perspective.
        if not getattr(self, "_closed", False):
            for slot in slots_to_recycle:
                try:
                    await self._recycle_slot(
                        slot,
                        slot.generation,
                        "关闭最后 Camoufox 调试窗口后回收浏览器",
                    )
                except Exception:
                    # Closing a debug window must still report the successful
                    # context close even if a best-effort browser recycle
                    # fails; the next registration will surface recycle_error.
                    continue
        return closed

    async def _discard_debug_sessions_for_slot(self, slot: _host_mod()._BrowserSlot) -> int:
        """Forget unusable sessions after their owning browser disappeared."""
        with self._debug_lock:
            sessions = [
                item for item in self._debug_sessions.values()
                if item.slot is slot
            ]
            for item in sessions:
                self._debug_sessions.pop(item.session_id, None)
                self._debug_closing.discard(item.session_id)
        for session in sessions:
            try:
                await _host_mod()._close_context_safely(session.context, 1.0)
            except Exception as exc:
                if session.trace is not None:
                    session.trace.add(
                        "debug_session_context_close_failed",
                        message=f"调试会话 context 关闭失败（{type(exc).__name__}）",
                    )
            if session.proxy_bridge is not None:
                try:
                    session.proxy_bridge.close()
                except Exception as exc:
                    if session.trace is not None:
                        session.trace.add(
                            "debug_session_proxy_bridge_close_failed",
                            message=f"调试会话代理桥关闭失败（{type(exc).__name__}）",
                        )
            with _host_mod()._ARTIFACT_LOCK:
                _host_mod()._ARTIFACT_PROTECTED_SESSIONS.discard(session.session_id)
        if sessions:
            if self._admission_lock is not None:
                async with self._admission_lock:
                    slot.debug_holds = max(0, slot.debug_holds - len(sessions))
            else:
                slot.debug_holds = max(0, slot.debug_holds - len(sessions))
        return len(sessions)

    def _debug_close_timeout_budget(self, session_id: str = "") -> float:
        """Return a bounded wait budget for a synchronous debug close request.

        Contexts are closed serially on the pool loop.  Closing the last hold
        on a slot can then drain active work, tear down the old browser and
        launch a replacement.  A single-context timeout is therefore not a
        sufficient bound for ``close-all`` and can make an otherwise completed
        request look as though it failed while cleanup is still in flight.
        """
        context_timeout = _host_mod()._pool_timeout(self.config, "context_close_timeout_seconds", 15)
        browser_timeout = _host_mod()._pool_timeout(self.config, "browser_recycle_timeout_seconds", 45)
        drain_timeout = _host_mod()._pool_timeout(self.config, "browser_recycle_drain_timeout_seconds", 20)
        normalized = str(session_id or "").strip()
        with self._debug_lock:
            if normalized:
                candidate = self._debug_sessions.get(normalized)
                sessions = (
                    [candidate]
                    if candidate is not None and normalized not in self._debug_closing
                    else []
                )
            else:
                sessions = [
                    item for key, item in self._debug_sessions.items()
                    if key not in self._debug_closing
                ]
        sessions = [item for item in sessions if item is not None]
        if not sessions:
            return max(5.0, context_timeout + 5.0)
        # One slot can only be recycled once after its final retained context
        # closes.  Include both manager teardown and the fallback browser close
        # plus the bounded replacement launch, then add a small scheduling
        # margin for the cross-thread Future handoff.
        slots = {id(item.slot) for item in sessions}
        per_slot_recycle = drain_timeout + (browser_timeout * 2.0) + context_timeout
        return max(
            5.0,
            (len(sessions) * context_timeout)
            + (len(slots) * per_slot_recycle)
            + 5.0,
        )

    def close_debug_sessions(self, session_id: str = "") -> int:
        """Close retained contexts on the pool's asyncio thread.

        The manager and HTTP route run on ordinary worker threads, while page
        and context objects belong to this pool loop.  Always marshal the
        close operation instead of touching Playwright objects cross-thread.
        """
        if self._loop is None or not self._ready.is_set():
            return 0
        timeout = self._debug_close_timeout_budget(session_id)
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._close_debug_sessions_async(session_id), self._loop,
            )
            return int(future.result(timeout=timeout))
        except FutureTimeoutError:
            # The async close path has its own per-resource bounds.  Give it a
            # second, smaller drain window before cancellation so contexts
            # already detached from the task can finish and update debug_state.
            # This keeps a timed-out HTTP request observable instead of
            # leaving a half-closed session with an eagerly cancelled task.
            try:
                return int(future.result(timeout=max(5.0, min(timeout, 30.0))))
            except FutureTimeoutError:
                try:
                    future.cancel()
                except Exception as exc:
                    # Watcher cancellation must not mask the pool shutdown.
                    self._note_quiet("shutdown_watcher_cancel", exc)
            except Exception as exc:
                # Watcher cancellation must not mask the pool shutdown.
                self._note_quiet("shutdown_watcher_result", exc)
            return 0
        except Exception:
            return 0

    def debug_state(self) -> dict[str, Any]:
        """Return a secret-free snapshot suitable for the public Free state."""
        with self._debug_lock:
            sessions = list(self._debug_sessions.values())
            closing_sessions = {
                item.session_id for item in sessions
                if item.session_id in self._debug_closing
            }
        capacity = max(0, len(self._slots) * self.max_contexts)
        used = sum(max(0, int(slot.active_contexts) + int(slot.debug_holds)) for slot in self._slots)
        return {
            "enabled": bool(self.debug_mode),
            "headless": bool(self.headless),
            "capacity": capacity,
            "used": used,
            "available": max(0, capacity - used),
            "open_contexts": len(sessions),
            "closing_contexts": len(closing_sessions),
            "closing_sessions": sorted(closing_sessions),
            "browser_count": len(self._slots),
            "pool_count": 1,
            "sessions": [
                {
                    "session_id": item.session_id,
                    "task_id": item.task_id,
                    "node_code": item.node_code,
                    "node_label": item.node_label,
                    "error_code": item.error_code,
                    "page_type": item.page_type,
                    "safe_page": item.safe_page,
                    "proxy_fingerprint": item.proxy_fingerprint,
                    "artifact_id": item.artifact_id,
                    "incident_id": item.incident_id,
                    "created_at": item.created_at,
                }
                for item in sessions
            ],
        }

    def has_active_contexts(self) -> bool:
        return any(int(slot.active_contexts) > 0 for slot in self._slots)

    def is_idle(self) -> bool:
        return not self.has_active_contexts() and not self.has_debug_sessions()

    def annotate_debug_session(self, session_id: str, incident_id: str) -> bool:
        """Attach the manager-created incident to a retained debug session."""
        normalized_session = str(session_id or "").strip()
        normalized_incident = _host_mod()._safe_incident_id(incident_id)
        if not normalized_session or not normalized_incident:
            return False
        with self._debug_lock:
            session = self._debug_sessions.get(normalized_session)
            if session is None:
                return False
            session.incident_id = normalized_incident
            artifact_path = session.artifact_path
        if artifact_path:
            # Keep the lock around both read and atomic replace.  Locking only
            # the final write still permits a stale payload to overwrite a
            # bridge-cleanup marker written by the concurrent close path.
            with _host_mod()._ARTIFACT_LOCK:
                try:
                    summary_path = Path(artifact_path) / "summary.json"
                    payload = json.loads(summary_path.read_text(encoding="utf-8"))
                    if isinstance(payload, dict):
                        payload["incident_id"] = normalized_incident
                        _host_mod()._atomic_artifact_write(summary_path, payload)
                except Exception as exc:
                    # Artifact bookkeeping must not break the debug retention.
                    self._note_quiet("incident_summary_update", exc)
        return True

    def has_debug_sessions(self) -> bool:
        with self._debug_lock:
            return bool(self._debug_sessions)

    def _start(self) -> None:
        def target() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                try:
                    self._loop.run_until_complete(self._init_async())
                except BaseException as exc:
                    self._init_error = exc
                finally:
                    self._init_finished.set()
                    self._ready.set()
                if self._init_error is None and not self._shutdown_requested.is_set():
                    # A scheduled shutdown task performs cleanup and calls
                    # ``loop.stop`` only after that cleanup has completed.
                    self._loop.run_forever()

                # A shutdown request can arrive during initialization, before
                # ``run_forever`` has started.  In that case no callback can
                # drive the loop, so run the cleanup task synchronously here.
                # Initialization failures use the same path to reclaim any
                # managers opened before the failing slot.
                if not self._shutdown_complete.is_set():
                    shutdown_task = self._shutdown_task
                    if shutdown_task is not None:
                        if not shutdown_task.done():
                            self._loop.run_until_complete(shutdown_task)
                        else:
                            # Surface/consume a cleanup exception without
                            # preventing the completion signal in ``finally``.
                            try:
                                shutdown_task.result()
                            except BaseException as exc:
                                self._note_quiet("shutdown_task_result", exc)
                    else:
                        self._loop.run_until_complete(self._shutdown_async())
                    self._cancel_pending_tasks()
            finally:
                try:
                    self._loop.close()
                finally:
                    # Even an unexpected cleanup exception must make the pool's
                    # completion state observable to the registry.
                    self._shutdown_complete.set()
        self._thread = threading.Thread(target=target, name="gptphone-camoufox", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=90)

    async def _cancel_pending_tasks_async(self) -> None:
        """Cancel registration tasks before closing their browser managers."""
        current = asyncio.current_task()
        pending = [
            task for task in asyncio.all_tasks()
            if task is not current and not task.done()
        ]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _shutdown_and_stop_async(self) -> None:
        """Drain async work, close resources, then release the event loop."""
        try:
            # Force-cancel registration/context tasks first.  Calling
            # ``loop.stop`` before this drain was the source of pending-task
            # warnings and ``Event loop stopped before Future completed`` in
            # the two Camoufox incidents.
            await self._cancel_pending_tasks_async()
            await self._shutdown_async()
        finally:
            loop = self._loop
            if loop is not None and not loop.is_closed():
                loop.stop()

    def _schedule_shutdown(self) -> None:
        """Create the single shutdown task on the pool's asyncio thread."""
        loop = self._loop
        if loop is None or bool(getattr(loop, "is_closed", lambda: False)()):
            return
        task = self._shutdown_task
        if task is None or task.done():
            self._shutdown_task = loop.create_task(self._shutdown_and_stop_async())

    def _cancel_pending_tasks(self) -> None:
        if self._loop is None:
            return
        pending = [task for task in asyncio.all_tasks(self._loop) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    async def _init_async(self) -> None:
        AsyncCamoufox, _ = _host_mod()._load_camoufox_api()
        self._global_semaphore = asyncio.Semaphore(self.pool_size * self.max_contexts)
        self._startup_semaphore = asyncio.Semaphore(min(self.startup_concurrency, self.pool_size * self.max_contexts))
        self._context_start_lock = asyncio.Lock()
        self._admission_lock = asyncio.Lock()
        async def launch_slot(_index: int) -> tuple[int, Any, Any]:
            manager, browser = await self._launch_browser()
            return _index, manager, browser

        results = await asyncio.gather(
            *(launch_slot(index) for index in range(self.pool_size)),
            return_exceptions=True,
        )
        failures = [item for item in results if isinstance(item, BaseException)]
        if failures:
            close_timeout = _host_mod()._pool_timeout(self.config, "browser_recycle_timeout_seconds", 45)
            for item in results:
                if isinstance(item, BaseException):
                    continue
                _index, manager, browser = item
                manager_closed = True
                if manager is not None:
                    manager_closed = await _host_mod()._close_async_resource(
                        lambda manager=manager: manager.__aexit__(None, None, None),
                        close_timeout,
                    )
                if not manager_closed and browser is not None:
                    await _host_mod()._close_async_resource(browser.close, close_timeout)
            failure = failures[0]
            if isinstance(failure, _host_mod().CamoufoxBrowserError):
                raise failure
            raise _host_mod().CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox 浏览器池",
                "Camoufox 浏览器池启动失败",
                error_code="camoufox_browser_launch_failed",
                diagnostic=type(failure).__name__,
            ) from failure

        for result in sorted(results, key=lambda item: item[0]):
            _index, manager, browser = result
            slot = _host_mod()._BrowserSlot(
                manager, browser, asyncio.Semaphore(self.max_contexts),
                recycle_lock=asyncio.Lock(), idle_event=asyncio.Event(),
            )
            self._slots.append(slot)
            self._attach_browser_disconnect(slot)
            slot.idle_event.set()

    def _attach_browser_disconnect(self, slot: _host_mod()._BrowserSlot) -> None:
        """Schedule pool recovery when Playwright reports a dead browser."""
        browser = slot.browser
        on = getattr(browser, "on", None)
        if not callable(on):
            return
        generation = slot.generation

        def disconnected(*_args: Any, **_kwargs: Any) -> None:
            loop = self._loop
            if loop is None or self._closed:
                return

            def schedule_recycle() -> None:
                # A stale listener from a retired browser can fire after the
                # slot has already been replaced.  Do not mark the new browser
                # as disconnected in that case.
                if (
                    self._closed
                    or slot.generation != generation
                    or slot.browser is not browser
                ):
                    return
                slot.disconnect_requested = True
                try:
                    asyncio.create_task(
                        self._recycle_slot(slot, generation, "Camoufox 浏览器断开事件")
                    )
                except Exception as exc:
                    slot.recycle_error = _host_mod().clean(
                        f"camoufox_recycle_schedule_failed: {type(exc).__name__}", 240
                    )

            try:
                loop.call_soon_threadsafe(schedule_recycle)
            except Exception as exc:
                slot.recycle_error = _host_mod().clean(
                    f"camoufox_recycle_dispatch_failed: {type(exc).__name__}", 240
                )

        try:
            on("disconnected", disconnected)
        except Exception as exc:
            slot.recycle_error = _host_mod().clean(
                f"camoufox_disconnect_listener_failed: {type(exc).__name__}", 240
            )

    async def _launch_browser(self) -> tuple[Any, Any]:
        AsyncCamoufox, _ = _host_mod()._load_camoufox_api()
        last_error: BaseException | None = None
        attempts = max(1, int(self.config.get("browser_launch_attempts") or 3))
        for attempt in range(attempts):
            launch_options = {
                "headless": self.headless,
                "block_images": bool(self.config.get("block_images", True) and self.headless),
                "enable_cache": False,
            }
            if launch_options["block_images"]:
                # Camoufox requires an explicit acknowledgement because image
                # blocking can affect WAF detection and page behavior.
                launch_options["i_know_what_im_doing"] = True
            manager = AsyncCamoufox(
                **launch_options,
            )
            try:
                if self._startup_semaphore is None:
                    browser = await manager.__aenter__()
                else:
                    async with self._startup_semaphore:
                        browser = await manager.__aenter__()
                return manager, browser
            except BaseException as exc:
                last_error = exc
                try:
                    await manager.__aexit__(type(exc), exc, exc.__traceback__)
                except Exception as close_exc:
                    # Manager close must not mask the original browser failure.
                    self._note_quiet("manager_exit", close_exc)
                if attempt + 1 < attempts:
                    await asyncio.sleep(min(2 ** attempt, 5))
        raise _host_mod().CamoufoxBrowserError(
            "free_camoufox_launch", "启动 Camoufox 浏览器池",
            "Camoufox 浏览器进程启动失败",
            error_code="camoufox_browser_launch_failed",
            diagnostic=type(last_error).__name__ if last_error else "unknown",
        ) from last_error

    async def _shutdown_async(self) -> None:
        # Debug sessions own live contexts and proxy bridges. Close them before
        # their browser managers so no bridge/thread survives pool shutdown.
        await self._close_debug_sessions_async()
        # A disconnected context may refuse close; once the pool itself is
        # shutting down there is no live window to preserve, so clear the
        # registry and holds rather than leaving stale capacity in state.
        for slot in list(self._slots):
            if slot.debug_holds:
                await self._discard_debug_sessions_for_slot(slot)
        slots, self._slots = self._slots, []
        for slot in slots:
            manager = slot.manager
            browser = slot.browser
            manager_timeout = float(self.config.get("browser_recycle_timeout_seconds") or 45)
            browser_timeout = float(self.config.get("context_close_timeout_seconds") or 15)
            manager_closed = True
            if manager is not None:
                manager_closed = await _host_mod()._close_async_resource(
                    lambda manager=manager: manager.__aexit__(None, None, None),
                    manager_timeout,
                )
            if (manager is None or not manager_closed) and browser is not None:
                await _host_mod()._close_async_resource(browser.close, browser_timeout)

    async def _register_async(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        if self._global_semaphore is None or not self._slots:
            raise _host_mod().CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器池没有可用进程", error_code="camoufox_pool_empty")
        registration_timeout = float(self.config.get("registration_timeout_seconds") or 600)
        fallback_deadline = time.monotonic() + max(0.0, registration_timeout)
        controller = kwargs.get("deadline_controller")
        if controller is None:
            supplied_config = kwargs.get("config")
            if isinstance(supplied_config, Mapping):
                controller = supplied_config.get("_deadline_controller")
        if controller is None:
            controller = RegistrationDeadline(registration_timeout)
        effective_kwargs = dict(kwargs)
        effective_config = dict(kwargs.get("config") or {})
        effective_config["_deadline_controller"] = controller
        effective_kwargs["config"] = effective_config
        effective_kwargs["deadline_controller"] = controller
        restart_attempted = False
        while True:
            try:
                async with self._global_semaphore:
                    task = asyncio.create_task(self._register_with_slot(effective_kwargs))
                    safety_deadline = time.monotonic() + registration_timeout + max(
                        30.0,
                        float(self.config.get("context_close_timeout_seconds") or 15)
                        + float(self.config.get("browser_recycle_timeout_seconds") or 45)
                        + float(self.config.get("browser_recycle_drain_timeout_seconds") or 20)
                        + (MANUAL_OTP_WINDOW_SECONDS * MAX_MANUAL_OTP_WINDOWS)
                        + MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
                    )
                    try:
                        while True:
                            if task.done():
                                return await task
                            expired_value = _host_mod()._deadline_controller_call(controller, "is_expired")
                            if expired_value is _host_mod()._DEADLINE_CONTROLLER_MISSING:
                                expired = time.monotonic() >= fallback_deadline
                            else:
                                try:
                                    expired = bool(expired_value)
                                except Exception:
                                    expired = time.monotonic() >= fallback_deadline
                            paused = _host_mod()._deadline_controller_bool(controller, "is_paused")
                            prompt_active = _host_mod()._deadline_controller_bool(controller, "manual_prompt_active")
                            handoff_active = _host_mod()._deadline_controller_bool(controller, "manual_handoff_active")
                            post_submit_grace = _host_mod()._deadline_controller_bool(controller, "manual_submission_grace_active")
                            otp_wait_active = _host_mod()._deadline_controller_bool(controller, "otp_wait_active")
                            remaining_value = _host_mod()._deadline_controller_call(controller, "remaining")
                            if remaining_value is _host_mod()._DEADLINE_CONTROLLER_MISSING:
                                remaining = max(0.0, fallback_deadline - time.monotonic())
                            else:
                                try:
                                    remaining = float(remaining_value)
                                    if not math.isfinite(remaining):
                                        raise ValueError
                                except (TypeError, ValueError, OverflowError):
                                    remaining = max(0.0, fallback_deadline - time.monotonic())
                            if expired and otp_wait_active and not paused and not handoff_active:
                                requested_handoff = _host_mod()._deadline_controller_call(
                                    controller, "request_manual_handoff"
                                )
                                if requested_handoff is not _host_mod()._DEADLINE_CONTROLLER_MISSING:
                                    paused = True
                                    handoff_active = True
                            if (
                                (
                                    expired
                                    and not (paused or prompt_active or handoff_active or post_submit_grace)
                                )
                                or (
                                    paused
                                    and otp_wait_active
                                    and not (prompt_active or handoff_active or post_submit_grace)
                                )
                                or time.monotonic() >= safety_deadline
                            ):
                                if paused and not prompt_active and not handoff_active:
                                    _host_mod()._deadline_controller_call(controller, "resume_manual", "timeout")
                                task.cancel()
                                try:
                                    await asyncio.wait_for(
                                        asyncio.shield(task),
                                        timeout=max(1.0, min(30.0, safety_deadline - time.monotonic() + 1.0)),
                                    )
                                except BaseException as cancel_exc:
                                    self._note_quiet("registration_task_cancel", cancel_exc)
                                raise _host_mod().CamoufoxBrowserError(
                                    "free_camoufox_browser", "Camoufox 注册页面",
                                    "浏览器注册超时，已取消当前 context 并回收进程",
                                    error_code="camoufox_registration_timeout",
                                )
                            await asyncio.sleep(
                                min(0.25, max(0.01, remaining)) if not paused
                                else 0.25
                            )
                    finally:
                        if not task.done():
                            task.cancel()
                        try:
                            await asyncio.wait_for(asyncio.shield(task), timeout=5.0)
                        except BaseException as cancel_exc:
                            self._note_quiet("registration_drain_cancel", cancel_exc)
            except asyncio.TimeoutError as exc:
                raise _host_mod().CamoufoxBrowserError(
                    "free_camoufox_browser", "Camoufox 注册页面",
                    "浏览器注册超时，已取消当前 context 并回收进程",
                    error_code="camoufox_registration_timeout",
                ) from exc
            except _host_mod().CamoufoxBrowserError as exc:
                # Context/page creation failures happen before the remote
                # signup page exists and are safe to retry once after the pool
                # has recycled the disconnected process.  Once navigation has
                # started, preserve the original failure to avoid replaying a
                # potentially submitted signup.
                if (
                    not restart_attempted
                    and getattr(exc, "safe_restart", False)
                    and exc.error_code in {
                        "camoufox_browser_disconnected",
                        "camoufox_context_create_failed",
                        "camoufox_page_create_failed",
                        "camoufox_browser_recycle_failed",
                    }
                ):
                    restart_attempted = True
                    await asyncio.sleep(0.2)
                    continue
                raise

    @staticmethod
    def _browser_connected(browser: Any) -> bool:
        try:
            checker = getattr(browser, "is_connected", None)
            return bool(checker()) if callable(checker) else browser is not None
        except Exception:
            return False

    async def _wait_context_start_slot(self) -> None:
        if self.context_start_interval <= 0 or self._context_start_lock is None:
            return
        async with self._context_start_lock:
            now = asyncio.get_running_loop().time()
            if self._next_context_start > now:
                await asyncio.sleep(self._next_context_start - now)
            self._next_context_start = asyncio.get_running_loop().time() + self.context_start_interval

    async def _release_active_context(
        self,
        slot: _host_mod()._BrowserSlot,
        *,
        debug_retained: bool,
        debug_context: Any | None = None,
        debug_hold_registered: bool = False,
    ) -> None:
        """Release the admission reservation after task cleanup completes.

        Closing a retained context is marshalled onto this same asyncio loop,
        but it can still run between the retention coroutine and this final
        bookkeeping step.  Only add a debug hold while the context is still
        registered; otherwise a close that already removed the session would
        leave an unowned capacity reservation behind.
        """
        # New retention calls atomically install their hold before this method
        # runs.  ``debug_hold_registered`` prevents a concurrent close from
        # being undone by the worker's final bookkeeping.  The fallback path
        # remains for older direct callers that only registered a session.
        retain_hold = bool(debug_retained) and not debug_hold_registered
        if retain_hold:
            sessions = getattr(self, "_debug_sessions", None)
            if isinstance(sessions, dict):
                debug_lock = getattr(self, "_debug_lock", None)
                if debug_lock is not None:
                    with debug_lock:
                        retain_hold = any(
                            item is not None
                            and (debug_context is None or getattr(item, "context", None) is debug_context)
                            for item in sessions.values()
                        )
                else:
                    retain_hold = any(
                        item is not None
                        and (debug_context is None or getattr(item, "context", None) is debug_context)
                        for item in sessions.values()
                    )
        if self._admission_lock is not None:
            async with self._admission_lock:
                slot.active_contexts = max(0, slot.active_contexts - 1)
                if retain_hold:
                    slot.debug_holds += 1
                if slot.active_contexts == 0 and slot.idle_event is not None:
                    slot.idle_event.set()
        else:
            slot.active_contexts = max(0, slot.active_contexts - 1)
            if retain_hold:
                slot.debug_holds += 1
            if slot.active_contexts == 0 and slot.idle_event is not None:
                slot.idle_event.set()

    async def _acquire_slot_permit(self, slot: _host_mod()._BrowserSlot) -> _host_mod()._HeldSemaphore | None:
        """Atomically reserve one active context and its semaphore permit.

        Debug contexts release the task semaphore while remaining attached to
        the browser.  The active-context reservation therefore has to happen
        under the same admission lock as the debug-hold check; otherwise two
        waiters can both observe the same free capacity and overbook a slot.
        """
        await slot.semaphore.acquire()
        reserved = False
        try:
            if self._admission_lock is not None:
                async with self._admission_lock:
                    available = (
                        not slot.draining
                        and not (
                            slot.recycle_lock is not None
                            and slot.recycle_lock.locked()
                        )
                        and slot.active_contexts + slot.debug_holds < self.max_contexts
                    )
                    if available:
                        slot.active_contexts += 1
                        reserved = True
                        if slot.idle_event is not None:
                            slot.idle_event.clear()
            else:
                available = (
                    not slot.draining
                    and not (
                        slot.recycle_lock is not None
                        and slot.recycle_lock.locked()
                    )
                    and slot.active_contexts + slot.debug_holds < self.max_contexts
                )
                if available:
                    slot.active_contexts += 1
                    reserved = True
                    if slot.idle_event is not None:
                        slot.idle_event.clear()
            if available:
                return _host_mod()._HeldSemaphore(slot.semaphore)
        except BaseException:
            if reserved:
                await self._release_active_context(slot, debug_retained=False)
            slot.semaphore.release()
            raise
        slot.semaphore.release()
        return None

    async def _register_with_slot(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        while True:
            try:
                return await self._register_with_slot_once(kwargs)
            except _host_mod()._SlotAdmissionRace:
                await asyncio.sleep(0)

    async def _select_admission_slot(self) -> _host_mod()._BrowserSlot:
        """Pick a healthy slot, attempting one recovery when the pool is empty."""
        recovery_attempted = False
        while True:
            available = [
                slot for slot in self._slots
                if not slot.draining
                and not (
                    slot.recycle_lock is not None
                    and slot.recycle_lock.locked()
                )
                and self._browser_connected(slot.browser)
            ]
            if available:
                # Retained debug contexts stay open and consume a real browser
                # context slot even after their task Future has completed.
                idle = [
                    item for item in available
                    if not item.semaphore.locked()
                    and item.active_contexts + item.debug_holds < self.max_contexts
                ]
                if idle:
                    slot = min(
                        idle,
                        key=lambda item: (
                            item.active_contexts + item.debug_holds,
                            item.completed,
                        ),
                    )
                    break
                # Sleep until a candidate slot reports idle instead of
                # rebuilding the whole candidate list every 50 ms; the 0.25s
                # timeout keeps the recovery branch below reachable.
                waiters = [
                    asyncio.ensure_future(item.idle_event.wait())
                    for item in available
                    if item.idle_event is not None
                ]
                if waiters:
                    _done, pending = await asyncio.wait(
                        waiters,
                        timeout=0.25,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for waiter in pending:
                        waiter.cancel()
                else:
                    await asyncio.sleep(0.05)
                continue
            # A disconnect callback or registration-limit cleanup can already
            # be rebuilding every slot.  Treat that as a transient admission
            # state and let the in-flight recycler finish.  The old code set
            # ``recovery_attempted`` before finding a candidate and immediately
            # reported ``browser_disconnected`` here, which raced the normal
            # replacement launch and caused the RNBG5WMB failure.
            recycling = [
                slot for slot in self._slots
                if slot.draining or (
                    slot.recycle_lock is not None
                    and slot.recycle_lock.locked()
                )
            ]
            # A recycler owns the slot lock for its entire close/launch cycle.
            # Keep admission waiting while any candidate is in that cycle. A
            # completed-but-draining slot with an explicit recycle error is
            # already terminal for this pool and should retain the existing
            # structured ``recycle_failed`` result; a draining slot without
            # an error is handed to the recovery branch below.
            if any(
                slot.recycle_lock is not None and slot.recycle_lock.locked()
                for slot in recycling
            ):
                await asyncio.sleep(0.2)
                continue
            if any(slot.recycle_error for slot in recycling):
                failure = _host_mod().CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器进程回收后重新启动失败",
                    retryable=True, error_code="camoufox_browser_recycle_failed",
                    diagnostic=next(
                        slot.recycle_error for slot in recycling if slot.recycle_error
                    ),
                )
                setattr(failure, "safe_restart", True)
                raise failure
            # A browser can disappear between the health check and context
            # creation.  Rebuild one disconnected slot before reporting that
            # the pool is empty; this mirrors the reference pool's admission
            # recovery and prevents a transient process exit from consuming a
            # whole task.
            if not recovery_attempted:
                recoverable = next(
                    (
                        slot for slot in self._slots
                        if slot.recycle_lock is None or not slot.recycle_lock.locked()
                    ),
                    None,
                )
                if recoverable is not None:
                    recovery_attempted = True
                    generation = recoverable.generation
                    await self._recycle_slot(recoverable, generation, "浏览器池没有可用进程")
                    continue
            recycle_errors = [slot.recycle_error for slot in self._slots if slot.recycle_error]
            if recycle_errors:
                failure = _host_mod().CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器进程回收后重新启动失败",
                    retryable=True, error_code="camoufox_browser_recycle_failed",
                    diagnostic=recycle_errors[0],
                )
                setattr(failure, "safe_restart", True)
                raise failure
            failure = _host_mod().CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox",
                "浏览器池没有可用进程", error_code="camoufox_browser_disconnected",
                retryable=True,
            )
            setattr(failure, "safe_restart", True)
            raise failure
        return slot

    async def _run_registration_on_slot(
        self,
        slot: _host_mod()._BrowserSlot,
        kwargs: Mapping[str, Any],
        permit: Any,
        timing_fn: Any,
    ) -> dict[str, Any]:
        """Run one registration inside an acquired slot permit context."""
        async with permit:
            recycle_required = False
            generation = slot.generation
            context = None
            page = None
            proxy_bridge: _host_mod().Socks5HttpBridge | None = None
            debug_failure = False
            debug_retain_allowed = True
            debug_retained = False
            debug_error: BaseException | None = None
            trace: _host_mod()._DebugTrace | None = None
            try:
                if slot.draining or not self._browser_connected(slot.browser):
                    recycle_required = True
                    failure = _host_mod().CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox",
                        "浏览器进程已断开", error_code="camoufox_browser_disconnected",
                        retryable=True,
                    )
                    setattr(failure, "safe_restart", True)
                    raise failure
                context_started = time.monotonic()
                try:
                    await self._wait_context_start_slot()
                    context_proxy = _host_mod()._proxy_config(str(kwargs.get("proxy") or ""))
                    if (
                        context_proxy
                        and context_proxy.get("username")
                        and context_proxy.get("password")
                        and str(context_proxy.get("server") or "").lower().startswith(("socks5://", "socks5h://"))
                    ):
                        proxy_bridge = _host_mod().Socks5HttpBridge(str(kwargs.get("proxy") or ""))
                        context_proxy = proxy_bridge.proxy_config
                    context = await _host_mod()._new_context(
                        slot.browser,
                        proxy=context_proxy,
                    )
                    _host_mod().emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_context_create",
                        (time.monotonic() - context_started) * 1000,
                        "success",
                    )
                except _host_mod().CamoufoxBrowserError:
                    _host_mod().emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_context_create",
                        (time.monotonic() - context_started) * 1000,
                        "error",
                    )
                    raise
                except Exception as exc:
                    _host_mod().emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_context_create",
                        (time.monotonic() - context_started) * 1000,
                        "error",
                    )
                    recycle_required = True
                    if _host_mod()._browser_process_lost(exc):
                        recycle_required = True
                        failure = _host_mod().CamoufoxBrowserError(
                            "free_camoufox_launch", "创建 Camoufox 浏览器 context",
                            "Camoufox 浏览器进程无法创建 context",
                            error_code="camoufox_context_create_failed",
                            diagnostic="browser process lost",
                        )
                        setattr(failure, "safe_restart", True)
                        raise failure from exc
                    failure = _host_mod().CamoufoxBrowserError(
                        "free_camoufox_launch", "创建 Camoufox 浏览器 context",
                        "Camoufox context 创建失败",
                        error_code="camoufox_context_create_failed",
                        diagnostic=_host_mod()._context_failure_diagnostic(exc),
                    )
                    # Context creation is before any email submission. With
                    # an explicit task proxy, a non-runtime context error can
                    # safely switch to a healthy pool entry and replay the
                    # untouched task. Browser-runtime errors must stay local
                    # so they are not misreported as proxy health failures.
                    setattr(
                        failure,
                        "proxy_retryable",
                        bool(kwargs.get("proxy"))
                        and "reason=proxy_or_transport" in failure.diagnostic,
                    )
                    raise failure from exc
                page_started = time.monotonic()
                try:
                    page = await context.new_page()
                    _host_mod().emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_page_create",
                        (time.monotonic() - page_started) * 1000,
                        "success",
                    )
                except Exception as exc:
                    _host_mod().emit_timing(
                        timing_fn,
                        "free_camoufox_signup",
                        "camoufox_page_create",
                        (time.monotonic() - page_started) * 1000,
                        "error",
                    )
                    recycle_required = True
                    if _host_mod()._browser_process_lost(exc):
                        recycle_required = True
                        failure = _host_mod().CamoufoxBrowserError(
                            "free_camoufox_launch", "创建 Camoufox 注册页面",
                            "Camoufox 浏览器进程无法创建页面",
                            error_code="camoufox_page_create_failed",
                            diagnostic="browser process lost",
                        )
                        setattr(failure, "safe_restart", True)
                        raise failure from exc
                    raise _host_mod().CamoufoxBrowserError(
                        "free_camoufox_launch", "创建 Camoufox 注册页面",
                        "Camoufox context 无法创建页面",
                        error_code="camoufox_page_create_failed",
                        diagnostic=type(exc).__name__,
                    ) from exc
                trace = _host_mod()._page_debug_trace(page)
                flow_kwargs = dict(kwargs)
                flow_kwargs.setdefault("startup_gate", self._startup_semaphore)
                result = await _host_mod()._browser_flow(page, **flow_kwargs)
                slot.completed += 1
                recycle_required = slot.completed >= max(1, int(self.config.get("max_registrations_per_browser") or 12))
                return result
            except asyncio.CancelledError as exc:
                # ``asyncio.wait_for`` cancels this coroutine for a normal
                # registration timeout, but Playwright can also cancel it when
                # the Firefox process disappears.  The latter has an empty
                # exception message, so relying on ``_host_mod()._browser_process_lost``
                # alone turns into a bare concurrent.futures.CancelledError
                # at the synchronous pool boundary.  Use the slot health and
                # disconnect callback marker to preserve a stable node.
                recycle_required = True
                debug_failure = True
                debug_retain_allowed = False
                if self._closed:
                    failure = _host_mod().CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox 浏览器池",
                        "Camoufox 浏览器池已关闭，当前注册被取消",
                        retryable=False,
                        error_code="camoufox_pool_closed",
                        diagnostic="cancellation_source=pool_shutdown",
                        safe_page=_host_mod()._safe_url(page) if page is not None else "",
                        page_type="unknown",
                    )
                    _host_mod()._mark_recycle_required(failure, "pool closed during registration")
                    debug_error = failure
                    raise failure from exc
                browser_disconnected = bool(
                    getattr(slot, "disconnect_requested", False)
                ) or not self._browser_connected(getattr(slot, "browser", None))
                if browser_disconnected:
                    failure = _host_mod().CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox 浏览器池",
                        "Camoufox 浏览器进程在注册过程中退出",
                        retryable=True,
                        error_code="camoufox_browser_disconnected",
                        diagnostic="cancellation_source=browser_disconnect; browser_process_lost=true",
                        safe_page=_host_mod()._safe_url(page) if page is not None else "",
                        page_type="unknown",
                    )
                    # The page may already have submitted an email/OTP when
                    # the process vanished.  Never replay the whole flow from
                    # this path, even though the browser pool itself is
                    # recycled for the next task.
                    setattr(failure, "safe_restart", False)
                    _host_mod()._mark_recycle_required(failure, "browser process lost during registration")
                    debug_error = failure
                    raise failure from exc
                # Leave an ordinary timeout/external cancellation untouched so
                # the surrounding wait_for (or caller) can classify it as a
                # timeout/stop rather than incorrectly blaming the browser.
                debug_error = None
                raise
            except _host_mod().CamoufoxBrowserError as exc:
                debug_failure = True
                debug_error = exc
                if getattr(exc, "recycle_required", False) or exc.error_code in {
                    "camoufox_browser_disconnected",
                    "camoufox_context_create_failed",
                    "camoufox_page_create_failed",
                }:
                    recycle_required = True
                    debug_retain_allowed = False
                elif not self._debug_retain_allowed(exc):
                    debug_retain_allowed = False
                raise
            except _host_mod().FreeRegisterError as exc:
                debug_failure = True
                debug_error = exc
                if not self._debug_retain_allowed(exc):
                    debug_retain_allowed = False
                raise
            except Exception as exc:
                debug_failure = True
                debug_error = exc
                safe_page = _host_mod()._safe_url(page) if page is not None else ""
                page_type = "unknown"
                if page is not None:
                    try:
                        page_type = await _host_mod()._page_state(page)
                    except Exception:
                        page_type = "unknown"
                if isinstance(exc, (asyncio.TimeoutError, TimeoutError, FutureTimeoutError)):
                    recycle_required = True
                    debug_retain_allowed = False
                    failure = _host_mod().CamoufoxBrowserError(
                        "free_camoufox_page_state", "Camoufox 注册页面",
                        "Camoufox 浏览器流程超时，已回收当前 context",
                        retryable=True,
                        error_code="camoufox_browser_flow_timeout",
                        diagnostic=f"exception_type={type(exc).__name__}; safe_page={safe_page}; page_type={page_type}",
                        safe_page=safe_page,
                        page_type=page_type,
                    )
                    _host_mod()._mark_recycle_required(failure, "generic flow timeout")
                    debug_error = failure
                    raise failure from exc
                if _host_mod()._browser_process_lost(exc):
                    recycle_required = True
                    debug_retain_allowed = False
                    failure = _host_mod().CamoufoxBrowserError(
                        "free_camoufox_launch", "启动 Camoufox 浏览器池",
                        "Camoufox 浏览器进程已断开",
                        error_code="camoufox_browser_disconnected",
                        diagnostic="browser process lost",
                        safe_page=safe_page, page_type=page_type,
                    )
                    setattr(failure, "safe_restart", False)
                    debug_error = failure
                    raise failure from exc
                failure = _host_mod().CamoufoxBrowserError(
                    "free_camoufox_browser", "Camoufox 注册页面", f"浏览器流程异常（{type(exc).__name__}）",
                    error_code="camoufox_browser_flow_failed",
                    diagnostic=json.dumps({
                        "exception": type(exc).__name__,
                        "detail": _host_mod()._camoufox_error_detail(exc),
                        "kwargs": sorted(str(key) for key in kwargs.keys()),
                        "safe_page": safe_page,
                        "page_type": page_type,
                    }, ensure_ascii=False)[:500],
                    safe_page=safe_page, page_type=page_type,
                )
                debug_error = failure
                raise failure from exc
            finally:
                if context is not None and debug_failure and debug_retain_allowed:
                    try:
                        debug_retained = await self._retain_debug_context(
                            context=context,
                            page=page,
                            proxy_bridge=proxy_bridge,
                            slot=slot,
                            kwargs=kwargs,
                            error=debug_error,
                        )
                    except Exception:
                        # Retention is diagnostic-only; never mask the actual
                        # registration failure if a fake/old Playwright API
                        # rejects the inspection hook.
                        debug_retained = False
                if context is not None and not debug_retained:
                    closed = await _host_mod()._close_context_safely(
                        context,
                        float(self.config.get("context_close_timeout_seconds") or 15),
                    )
                    if not closed:
                        recycle_required = True
                if proxy_bridge is not None and not debug_retained:
                    try:
                        proxy_bridge.close()
                    except Exception:
                        recycle_required = True
                if debug_retained:
                    # Keep the browser process and its page available for the
                    # operator; ordinary per-task cleanup must not trigger a
                    # recycle behind the scenes.
                    recycle_required = False
                await self._release_active_context(
                    slot,
                    debug_retained=debug_retained,
                    debug_context=context,
                    debug_hold_registered=debug_retained,
                )
                if recycle_required and generation == slot.generation and not self._closed:
                    await self._recycle_slot(slot, generation, "达到单进程注册上限或 context 关闭异常")

    async def _register_with_slot_once(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        """Admit one task onto a healthy slot and run its registration."""
        timing_fn = kwargs.get("timing_fn")
        admission_started = time.monotonic()
        slot = await self._select_admission_slot()
        permit = await self._acquire_slot_permit(slot)
        if permit is None:
            # A debug context may have been retained after the slot selection;
            # return to the pool scan so another browser can admit this task.
            raise _host_mod()._SlotAdmissionRace()
        _host_mod().emit_timing(
            timing_fn,
            "free_camoufox_signup",
            "camoufox_pool_admission",
            (time.monotonic() - admission_started) * 1000,
            "success",
        )
        return await self._run_registration_on_slot(slot, kwargs, permit, timing_fn)

    async def _recycle_slot(self, slot: _host_mod()._BrowserSlot, generation: int, reason: str) -> None:
        lock = slot.recycle_lock
        if lock is None:
            return
        async with lock:
            if slot.generation != generation or self._closed:
                return
            old_manager, old_browser = slot.manager, slot.browser
            replacement_committed = False
            replacement_ready = False
            # Mark the slot as draining before any await.  Retention checks the
            # same admission lock, so a disconnect/recycle cannot admit a new
            # debug hold after the dead-browser check but before teardown.
            if self._admission_lock is not None:
                async with self._admission_lock:
                    if slot.generation != generation or self._closed:
                        return
                    slot.draining = True
            else:
                slot.draining = True

            async def close_resource(
                close_fn: Callable[[], Any], timeout: float,
            ) -> tuple[bool, bool]:
                """Close one async browser resource and report cancellation.

                ``asyncio.wait_for`` normally cancels its child when the
                surrounding recycle task is cancelled.  Keep that child in a
                task and shield it so we can finish (or explicitly cancel) the
                manager close before propagating cancellation; otherwise the
                slot has already detached its only reference to the old
                browser.
                """
                try:
                    result = close_fn()
                except asyncio.CancelledError:
                    return False, True
                except BaseException:
                    return False, False
                if not inspect.isawaitable(result):
                    return True, False
                task = asyncio.create_task(result)
                budget = max(0.1, float(timeout))
                try:
                    await asyncio.wait_for(asyncio.shield(task), timeout=budget)
                    return True, False
                except asyncio.TimeoutError:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return False, False
                except asyncio.CancelledError:
                    # The caller's cancellation is intentionally deferred
                    # until the child has had a bounded chance to finish.
                    try:
                        await asyncio.wait_for(asyncio.shield(task), timeout=budget)
                    except asyncio.TimeoutError:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                    except BaseException:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                    return False, True
                except BaseException:
                    return False, False

            try:
                if slot.browser is None or not self._browser_connected(slot.browser):
                    # A dead browser cannot keep a headed inspection window
                    # alive. Remove those holds before recycling so the slot
                    # cannot remain permanently full after a process exit.
                    await self._discard_debug_sessions_for_slot(slot)
                # A debug page is intentionally the last live artifact of a
                # failed task. Do not tear down its browser behind the
                # operator's back; the explicit close endpoint will release
                # the hold and perform the normal pool shutdown.
                if slot.debug_holds:
                    slot.draining = False
                    slot.recycle_error = ""
                    return
                if slot.active_contexts and slot.idle_event is not None:
                    try:
                        await asyncio.wait_for(
                            slot.idle_event.wait(),
                            timeout=float(self.config.get("browser_recycle_drain_timeout_seconds") or 20),
                        )
                    except asyncio.TimeoutError:
                        # Drain timeout falls through to the debug-holds recheck.
                        pass
                # A task that was already in its terminal cleanup can retain a
                # debug page while the drain event is being awaited. Re-check
                # immediately before touching the old browser; otherwise the
                # newly retained page could be closed behind the operator.
                if self._admission_lock is not None:
                    async with self._admission_lock:
                        if slot.debug_holds:
                            slot.draining = False
                            slot.recycle_error = ""
                            return
                elif slot.debug_holds:
                    slot.draining = False
                    slot.recycle_error = ""
                    return
                # Mark the slot as replaced only after the drain check. If
                # cancellation arrives during the wait, the finally block
                # restores draining=False on the still-usable old browser.
                slot.manager = None
                slot.browser = None
                slot.generation += 1
                slot.completed = 0
                replacement_committed = True
                close_cancelled = False
                resource_closed = False
                close_timeout = float(self.config.get("browser_recycle_timeout_seconds") or 45)
                if old_manager is not None:
                    resource_closed, close_cancelled = await close_resource(
                        lambda: old_manager.__aexit__(None, None, None),
                        close_timeout,
                    )
                if old_browser is not None and (not resource_closed or old_manager is None):
                    _browser_closed, browser_cancelled = await close_resource(
                        old_browser.close,
                        float(self.config.get("context_close_timeout_seconds") or 15),
                    )
                    resource_closed = bool(resource_closed or _browser_closed)
                    close_cancelled = bool(close_cancelled or browser_cancelled)
                if close_cancelled:
                    raise asyncio.CancelledError
                if self._closed:
                    return
                try:
                    manager, browser = await asyncio.wait_for(
                        self._launch_browser(),
                        timeout=float(self.config.get("browser_recycle_timeout_seconds") or 45),
                    )
                except Exception as exc:
                    slot.draining = True
                    error_code = str(getattr(exc, "error_code", "") or type(exc).__name__)
                    slot.recycle_error = _host_mod().clean(f"{error_code}: {type(exc).__name__}", 240)
                    return
                slot.manager, slot.browser, slot.draining, slot.recycle_error = manager, browser, False, ""
                # The disconnect marker belongs to the old browser generation;
                # clear it only after a replacement is fully attached so a
                # cancellation during the launch window still reports the
                # unavailable slot accurately.
                slot.disconnect_requested = False
                replacement_ready = True
                self._attach_browser_disconnect(slot)
            finally:
                if (
                    not replacement_committed
                    and slot.generation == generation
                    and slot.browser is old_browser
                    and not self._closed
                ):
                    # Cancellation during the drain wait leaves the original
                    # browser usable; make that fact visible to admission.
                    slot.draining = False
                    if self._browser_connected(old_browser):
                        # A stale/duplicate disconnect callback must not make
                        # a later, unrelated task cancellation look like a
                        # browser crash after the old slot is restored.
                        slot.disconnect_requested = False
                elif (
                    replacement_committed
                    and not replacement_ready
                    and slot.generation == generation + 1
                    and not self._closed
                    and slot.browser is None
                ):
                    # The old browser was detached but replacement did not
                    # finish. Keep the slot blocked and expose a stable error
                    # for the next registration instead of accepting work on
                    # a half-recycled slot.
                    slot.draining = True
                    if not slot.recycle_error:
                        slot.recycle_error = "browser_recycle_incomplete"

    def register(self, **kwargs: Any) -> dict[str, Any]:
        if self._closed:
            raise _host_mod().CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器池已关闭", error_code="camoufox_pool_closed")
        if not self._ready.is_set():
            if not self._ready.wait(timeout=90):
                raise _host_mod().CamoufoxBrowserError(
                    "free_camoufox_launch", "启动 Camoufox 浏览器池",
                    "Camoufox 浏览器池仍在初始化，请稍后重试",
                    retryable=True, error_code="camoufox_pool_init_pending",
                )
        if self._init_error:
            if isinstance(self._init_error, (_host_mod().CamoufoxDependencyError, _host_mod().CamoufoxBrowserError)):
                raise self._init_error
            raise _host_mod().CamoufoxBrowserError(
                "free_camoufox_launch", "启动 Camoufox", "浏览器池初始化失败",
                error_code="camoufox_pool_init_failed",
                diagnostic=_host_mod()._camoufox_error_detail(self._init_error),
            ) from self._init_error
        if self._loop is None:
            raise _host_mod().CamoufoxBrowserError("free_camoufox_launch", "启动 Camoufox", "浏览器事件循环不可用", error_code="camoufox_loop_missing")
        registration_timeout = float(self.config.get("registration_timeout_seconds") or 600)
        cleanup_budget = float(self.config.get("context_close_timeout_seconds") or 15)
        recycle_budget = float(self.config.get("browser_recycle_timeout_seconds") or 45)
        drain_budget = float(self.config.get("browser_recycle_drain_timeout_seconds") or 20)
        controller = kwargs.get("deadline_controller")
        if controller is None:
            supplied_config = kwargs.get("config")
            if isinstance(supplied_config, Mapping):
                controller = supplied_config.get("_deadline_controller")
        if controller is None:
            controller = RegistrationDeadline(registration_timeout)
        effective_kwargs = dict(kwargs)
        effective_config = dict(kwargs.get("config") or {})
        effective_config["_deadline_controller"] = controller
        effective_kwargs["config"] = effective_config
        effective_kwargs["deadline_controller"] = controller
        safety_deadline = time.monotonic() + registration_timeout + max(
            30.0,
            cleanup_budget + recycle_budget + drain_budget
            + (MANUAL_OTP_WINDOW_SECONDS * MAX_MANUAL_OTP_WINDOWS)
            + MANUAL_OTP_POST_SUBMIT_GRACE_SECONDS,
        )
        future = asyncio.run_coroutine_threadsafe(self._register_async(effective_kwargs), self._loop)
        try:
            # The async watchdog observes the pause-aware controller and
            # cancels the registration task when its active budget expires.
            # Keep this cross-thread wait as one bounded operation instead of
            # polling every 250ms: a Future test double (or a scheduler that
            # reports an immediate timeout) must not turn the caller into a
            # hot loop. The allowance covers the three independent broker
            # windows (entry, password and 2FA), post-submit handoff, and
            # context/recycle cleanup.
            wait_budget = max(0.25, safety_deadline - time.monotonic())
            return dict(future.result(timeout=wait_budget))
        except FutureCancelledError as exc:
            # ``run_coroutine_threadsafe`` translates an async
            # ``CancelledError`` into ``concurrent.futures.CancelledError``.
            # Do not let that low-level type escape to FreeRegisterManager's
            # generic exception path; preserve a stable, non-proxy
            # cancellation node for task diagnostics and mailbox safety.
            if self._closed:
                error_code = "camoufox_pool_closed"
                message = "Camoufox 浏览器池已关闭，当前注册被取消"
                source = "pool_shutdown"
            else:
                error_code = "camoufox_registration_cancelled"
                message = "Camoufox 注册任务被取消"
                source = "registration_future"
            failure = _host_mod().CamoufoxBrowserError(
                "free_camoufox_browser", "Camoufox 注册页面", message,
                retryable=False,
                error_code=error_code,
                diagnostic=f"cancellation_source={source}",
            )
            setattr(failure, "safe_restart", False)
            raise failure from exc
        except FutureTimeoutError as exc:
            # The async registration path already bounds page/context cleanup
            # and browser replacement.  Give those operations one final,
            # bounded drain window before cancelling the cross-thread Future;
            # cancelling immediately can interrupt the recycler after it has
            # detached the old browser and leave the caller with no observable
            # completion state.
            try:
                future.result(timeout=max(5.0, min(cleanup_budget + drain_budget + recycle_budget + 5, 30.0)))
            except FutureTimeoutError:
                try:
                    future.cancel()
                except Exception as cancel_exc:
                    # Watcher cancellation must not mask the registration timeout.
                    self._note_quiet("timeout_watcher_cancel", cancel_exc)
            except Exception as result_exc:
                # Telemetry must not mask the registration timeout raised below.
                self._note_quiet("timeout_watcher_result", result_exc)
            raise _host_mod().CamoufoxBrowserError("free_camoufox_browser", "Camoufox 注册页面", "浏览器注册超时", error_code="camoufox_registration_timeout") from exc

    def shutdown(self, *, force: bool = False) -> bool:
        completion = getattr(self, "_shutdown_complete", None)
        if completion is None:
            completion = threading.Event()
            self._shutdown_complete = completion
            if getattr(self, "_closed", False) and not getattr(self, "_thread", None):
                completion.set()
        with self._lock:
            if completion.is_set():
                return True
            if not force and (self.has_debug_sessions() or self.has_active_contexts()):
                # Batch completion must leave opted-in diagnostic pages and
                # active task contexts visible. They are closed only after the
                # operator releases the debug session or at process exit.
                return False
            self._closed = True
            shutdown_requested = getattr(self, "_shutdown_requested", None)
            if shutdown_requested is not None:
                shutdown_requested.set()
            loop = self._loop
            if loop is not None:
                try:
                    # Never stop the loop directly. The shutdown coroutine
                    # cancels/drains async work and closes every browser
                    # manager before issuing the final ``loop.stop``.
                    init_finished = getattr(self, "_init_finished", None)
                    if init_finished is None or init_finished.is_set():
                        loop.call_soon_threadsafe(self._schedule_shutdown)
                except (RuntimeError, AttributeError) as exc:
                    # The loop may already be in its final close phase. The
                    # completion event below determines whether cleanup really
                    # finished before the pool is removed from the registry.
                    self._note_quiet("shutdown_schedule", exc)
        thread = self._thread
        if thread is None:
            completion.set()
            return True
        if thread is threading.current_thread():
            return completion.is_set()
        thread.join(timeout=_host_mod()._pool_shutdown_wait_budget(self.config))
        if thread.is_alive():
            return False
        completion.set()
        return True


def _proxy_config(host, proxy: str) -> dict[str, Any] | None:
    config = host.proxy_transport_config(proxy, driver="camoufox")
    if not config:
        return None
    return {
        key: config[key]
        for key in ("server", "username", "password")
        if config.get(key)
    }


_POOL_LOCK = threading.RLock()
# Registry operations and browser-pool shutdown must share one lifecycle
# barrier.  Without it a settings read or a new task can obtain a pool after
# shutdown has marked it closed but before its event-loop thread has released
# the browser process.
_POOL_LIFECYCLE_LOCK = threading.RLock()
_POOLS: dict[tuple[Any, ...], CamoufoxBrowserPool] = {}


def _pool_timeout(host, config: Mapping[str, Any], key: str, default: float) -> float:
    """Normalize timeout values used to decide whether a pool is reusable."""
    try:
        value = float(config.get(key) or default)
    except (TypeError, ValueError, OverflowError):
        value = float(default)
    return max(0.001, value)


def _pool_shutdown_wait_budget(host, config: Mapping[str, Any]) -> float:
    """Bound a synchronous wait for the pool's event-loop thread to exit.

    ``_shutdown_async`` closes browser slots serially.  Each slot can spend
    one browser-recycle timeout in the manager context and one context-close
    timeout in its fallback browser close, so a single-slot budget undercounts
    the real cleanup window as soon as ``pool_size`` is greater than one.  The
    drain timeout and a small handoff margin cover a concurrent recycle that
    was already queued when shutdown started.
    """
    try:
        pool_size = max(1, int(config.get("pool_size") or 2))
    except (TypeError, ValueError, OverflowError):
        pool_size = 2
    context_timeout = host._pool_timeout(config, "context_close_timeout_seconds", 15)
    browser_timeout = host._pool_timeout(config, "browser_recycle_timeout_seconds", 45)
    drain_timeout = host._pool_timeout(
        config, "browser_recycle_drain_timeout_seconds", 20,
    )
    # Slot teardown is currently serial; keep this calculation conservative
    # until that ordering is deliberately changed and covered independently.
    return max(
        5.0,
        (pool_size * (browser_timeout + context_timeout))
        + drain_timeout
        + 10.0,
    )


def _camoufox_pool_key(host, config: Mapping[str, Any]) -> tuple[Any, ...]:
    """Build the identity used to reuse a compatible browser pool."""
    debug_mode, effective_headless = host._effective_camoufox_headless(config)
    # ``_debug_artifact_dir`` is injected only by the runner and is absent
    # from persisted settings read by the public debug-state endpoint. It is
    # an output location, not a browser capability; including it would make
    # the state poller retire the live registration pool as "obsolete".
    return (
        debug_mode, effective_headless, int(config.get("pool_size") or 2),
        int(config.get("max_contexts_per_browser") or 3), bool(config.get("block_images", True)),
        int(config.get("context_start_interval_ms") or 175),
        int(config.get("startup_concurrency") or 4),
        int(config.get("max_registrations_per_browser") or 12),
        int(config.get("browser_launch_attempts") or 3),
        host._pool_timeout(config, "registration_timeout_seconds", 600),
        host._pool_timeout(config, "context_close_timeout_seconds", 15),
        host._pool_timeout(config, "browser_recycle_timeout_seconds", 45),
        host._pool_timeout(config, "browser_recycle_drain_timeout_seconds", 20),
    )


def _retire_idle_camoufox_pools_locked(
    host,
    *, current_key: tuple[Any, ...] | None = None,
) -> dict[str, int]:
    """Close pools made obsolete by a config change once they are idle.

    A pool with an active task or an operator-held debug context is deliberately
    left registered.  This makes a settings change non-destructive while still
    preventing an idle old browser process from accumulating forever.
    """
    with host._POOL_LOCK:
        candidates = list(host._POOLS.items())
    closed = 0
    retained = 0
    for key, pool in candidates:
        if current_key is not None and key == current_key:
            continue
        try:
            has_debug = bool(getattr(pool, "has_debug_sessions", lambda: False)())
            has_active = bool(getattr(pool, "has_active_contexts", lambda: False)())
        except Exception:
            retained += 1
            continue
        if has_debug or has_active:
            retained += 1
            continue
        try:
            # ``shutdown`` may still be unwinding its event-loop thread.  A
            # closed pool is no longer a valid admission owner, so detach it
            # now and let that thread finish independently.  Keeping it in the
            # registry caused the next task to inherit a closed/empty pool and
            # surface ``camoufox_pool_shutdown_pending``.
            if bool(getattr(pool, "_closed", False)):
                with host._POOL_LOCK:
                    if host._POOLS.get(key) is pool:
                        host._POOLS.pop(key, None)
                        closed += 1
                continue
            try:
                result = pool.shutdown(force=False)
            except TypeError:
                result = pool.shutdown()
            if result is False:
                retained += 1
                continue
            with host._POOL_LOCK:
                if host._POOLS.get(key) is pool:
                    host._POOLS.pop(key, None)
                    closed += 1
        except Exception:
            retained += 1
    return {"closed_pools": closed, "retained_pools": retained}


def _retire_idle_camoufox_pools(
    host,
    *, current_key: tuple[Any, ...] | None = None,
) -> dict[str, int]:
    """Serialize idle-pool retirement with pool lookup and shutdown."""
    with host._POOL_LIFECYCLE_LOCK:
        return host._retire_idle_camoufox_pools_locked(current_key=current_key)


def _pool_for(host, config: Mapping[str, Any]) -> host.CamoufoxBrowserPool:
    key = host._camoufox_pool_key(config)
    with host._POOL_LIFECYCLE_LOCK:
        # Reconcile pools from a previous settings identity before admitting a
        # new one. Held debug windows and active tasks are retained by design.
        host._retire_idle_camoufox_pools_locked(current_key=key)
        # A pool marked closed has already received a shutdown request. Keep
        # its object alive through its own daemon event-loop thread, but remove
        # it from the registry immediately so a new task can obtain a healthy
        # replacement. Waiting here used to surface ``camoufox_pool_shutdown_pending``
        # and caused the next task to race into an empty/disconnected pool.
        with host._POOL_LOCK:
            current = host._POOLS.get(key)
            if current is not None and not bool(getattr(current, "_closed", False)):
                return current
            if current is not None and host._POOLS.get(key) is current:
                host._POOLS.pop(key, None)
            for old_key, old_pool in list(host._POOLS.items()):
                if old_key != key and bool(getattr(old_pool, "_closed", False)):
                    host._POOLS.pop(old_key, None)
            replacement = host.CamoufoxBrowserPool(config)
            host._POOLS[key] = replacement
            return replacement


def _shutdown_camoufox_pools_locked(host, *, force: bool = False) -> dict[str, int]:
    """Shutdown idle Camoufox pools, preserving opted-in debug sessions.

    ``force=True`` is reserved for process exit. The default keeps active
    tasks and retained debug windows alive during batch completion.
    """
    with host._POOL_LOCK:
        pools = list(host._POOLS.items())
    closed = 0
    retained = 0
    for key, pool in pools:
        has_debug = bool(getattr(pool, "has_debug_sessions", lambda: False)())
        has_active = bool(getattr(pool, "has_active_contexts", lambda: False)())
        if not force and (has_debug or has_active):
            retained += 1
            continue
        try:
            try:
                result = pool.shutdown(force=force)
            except TypeError:
                # Keep lightweight test doubles and older integration adapters
                # compatible with the no-argument shutdown contract.
                result = pool.shutdown()
            if result is not False:
                closed += 1
                with host._POOL_LOCK:
                    if host._POOLS.get(key) is pool:
                        host._POOLS.pop(key, None)
            else:
                retained += 1
        except Exception:
            retained += 1
    with host._POOL_LOCK:
        retained = max(retained, len(host._POOLS))
    return {"closed_pools": closed, "retained_pools": retained}


def shutdown_camoufox_pools(host, *, force: bool = False) -> dict[str, int]:
    """Shutdown pools under the same barrier used by pool lookup."""
    with host._POOL_LIFECYCLE_LOCK:
        return host._shutdown_camoufox_pools_locked(force=force)


def _force_close_idle_camoufox_pools(host) -> dict[str, int]:
    """Retry shutdown for pools that are provably idle after debug close.

    The regular non-forced shutdown preserves active registrations and open
    inspection windows.  A pool can still refuse that first shutdown while its
    event-loop thread is finishing a previous cleanup.  Once the close request
    has released every debug hold, retry only pools with no active contexts or
    debug sessions so the browser process cannot be left behind; active work
    remains protected by the same checks as the normal path.
    """
    with host._POOL_LIFECYCLE_LOCK:
        with host._POOL_LOCK:
            pools = list(host._POOLS.items())
        closed = 0
        retained = 0
        for key, pool in pools:
            try:
                if bool(getattr(pool, "has_debug_sessions", lambda: False)()):
                    retained += 1
                    continue
                if bool(getattr(pool, "has_active_contexts", lambda: False)()):
                    retained += 1
                    continue
                try:
                    result = pool.shutdown(force=True)
                except TypeError:
                    result = pool.shutdown()
                if result is not False:
                    closed += 1
                    with host._POOL_LOCK:
                        if host._POOLS.get(key) is pool:
                            host._POOLS.pop(key, None)
                else:
                    retained += 1
            except Exception:
                retained += 1
        with host._POOL_LOCK:
            retained = max(retained, len(host._POOLS))
        return {"closed_pools": closed, "retained_pools": retained}


def camoufox_debug_state(host, config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a secret-free aggregate of retained headed debug contexts.

    Before the first browser pool is created there is no slot object from
    which to derive capacity.  Use the normalized config in that case so the
    public state still reflects the configured debug/headless mode and pool
    capacity instead of briefly reporting a misleading disabled/zero state.
    """
    nested_config = config.get("camoufox") if isinstance(config, Mapping) else None
    # Accept both the public Free config shape and the low-level nested
    # Camoufox mapping used by direct pool callers.  A flat mapping without a
    # ``camoufox`` key must not silently fall back to the default debug mode.
    browser_config = (
        nested_config if isinstance(nested_config, Mapping)
        else (config if isinstance(config, Mapping) else {})
    )
    current_key: tuple[Any, ...] | None = None
    if browser_config:
        try:
            current_key = host._camoufox_pool_key(browser_config)
        except (TypeError, ValueError, OverflowError):
            current_key = None
    # Settings can change while no new batch is running. Reap obsolete idle
    # pools during the next state read, while retaining old pools that still
    # own a visible debug window or an active task.
    if current_key is not None:
        host._retire_idle_camoufox_pools(current_key=current_key)
    with host._POOL_LOCK:
        pool_items = list(host._POOLS.items())
    snapshots: list[tuple[tuple[Any, ...], Mapping[str, Any]]] = []
    for key, pool in pool_items:
        getter = getattr(pool, "debug_state", None)
        if not callable(getter):
            continue
        try:
            snapshot = getter()
        except Exception:
            continue
        if isinstance(snapshot, Mapping):
            snapshots.append((key, snapshot))
    snapshot_values = [snapshot for _key, snapshot in snapshots]
    sessions = [item for snapshot in snapshot_values for item in snapshot.get("sessions", [])]
    closing_sessions = sorted({
        str(session_id)
        for snapshot in snapshot_values
        for session_id in (snapshot.get("closing_sessions") or [])
        if str(session_id or "").strip()
    })
    closing_contexts = sum(
        max(0, int(snapshot.get("closing_contexts") or 0))
        for snapshot in snapshot_values
    )
    browser_count = sum(
        max(0, int(snapshot.get("browser_count") or 0))
        for snapshot in snapshot_values
    )
    capacity = sum(max(0, int(snapshot.get("capacity") or 0)) for snapshot in snapshot_values)
    used = sum(max(0, int(snapshot.get("used") or snapshot.get("open_contexts") or 0)) for snapshot in snapshot_values)
    current_snapshot = next(
        (snapshot for key, snapshot in snapshots if current_key is not None and key == current_key),
        None,
    )
    if current_snapshot is not None:
        # ``enabled`` and ``headless`` describe the current settings identity;
        # legacy pools may intentionally have the opposite window mode while
        # their retained pages remain visible to the operator.
        enabled = bool(current_snapshot.get("enabled"))
        headless = bool(current_snapshot.get("headless", True))
    elif snapshot_values:
        # No current pool has been created yet. Use the persisted config for
        # mode flags and keep the legacy pool capacity/occupancy in the totals.
        enabled, headless = host._effective_camoufox_headless(browser_config)
    else:
        enabled, headless = host._effective_camoufox_headless(browser_config)
        try:
            pool_size = max(1, int(browser_config.get("pool_size") or 2))
            max_contexts = max(1, int(browser_config.get("max_contexts_per_browser") or 3))
            capacity = pool_size * max_contexts
            browser_count = pool_size
        except (TypeError, ValueError):
            capacity = 0
            browser_count = 0
    return {
        "enabled": enabled,
        "headless": headless,
        "capacity": capacity,
        "used": used,
        "available": max(0, capacity - used),
        "open_contexts": len(sessions),
        "closing_contexts": closing_contexts,
        "closing_sessions": closing_sessions,
        "browser_count": browser_count,
        "pool_count": len(snapshots),
        "sessions": sessions,
    }


def annotate_camoufox_debug_session(host, session_id: str, incident_id: str) -> bool:
    """Best-effort incident association for a retained page."""
    normalized_session = str(session_id or "").strip()
    if not normalized_session:
        return False
    with host._POOL_LOCK:
        pools = list(host._POOLS.values())
    for pool in pools:
        annotator = getattr(pool, "annotate_debug_session", None)
        if callable(annotator):
            try:
                if annotator(normalized_session, incident_id):
                    return True
            except Exception:
                continue
    return False


def close_camoufox_debug_browsers(
    host,
    session_id: str = "",
    *,
    config: Mapping[str, Any] | None = None,
) -> dict[str, int]:
    """Close one/all retained contexts, then safely reap idle pools.

    ``config`` keeps the aggregate state accurate after the last pool is
    removed.  The manager passes the current normalized settings; direct
    compatibility callers can omit it and retain the historical defaults.
    """
    normalized = str(session_id or "").strip()
    with host._POOL_LOCK:
        pools = list(host._POOLS.values())
    requested = 0
    closed_contexts = 0
    for pool in pools:
        has_debug = bool(getattr(pool, "has_debug_sessions", lambda: False)())
        if has_debug:
            requested += 1
        closer = getattr(pool, "close_debug_sessions", None)
        if callable(closer):
            try:
                closed_contexts += int(closer(normalized))
            except Exception:
                continue
    result = host.shutdown_camoufox_pools(force=False)
    # A normal close may race a pool thread that is finishing an earlier
    # teardown and return without closing its manager. Retry only idle pools;
    # never force-close a pool with active work or another retained window.
    idle_retry = host._force_close_idle_camoufox_pools()
    result["forced_idle_pools"] = int(idle_retry.get("closed_pools") or 0)
    result["closed_pools"] = int(result.get("closed_pools") or 0) + result["forced_idle_pools"]
    result["retained_pools"] = int(idle_retry.get("retained_pools") or 0)
    result["closed_contexts"] = closed_contexts
    remaining = host.camoufox_debug_state(config)
    result["retained_contexts"] = int(remaining.get("open_contexts") or 0)
    result["remaining_contexts"] = int(remaining.get("open_contexts") or 0)
    result["remaining_sessions"] = int(remaining.get("open_contexts") or 0)
    result["requested_pools"] = requested
    return result




class CamoufoxRegistrationRunner:
    """Manager-compatible synchronous facade for the async browser pool."""

    def __init__(self, *, lifecycle_store_path: str = "", debug_artifact_dir: str = "") -> None:
        self.lifecycle_store_path = lifecycle_store_path
        self.debug_artifact_dir = debug_artifact_dir or (
            str(Path(lifecycle_store_path).expanduser().resolve().parent / "camoufox_debug")
            if lifecycle_store_path else ""
        )

    @staticmethod
    def preflight(config: Mapping[str, Any]) -> dict[str, Any]:
        _host_mod()._load_camoufox_api()
        runtime_version = _host_mod()._check_camoufox_runtime()
        browser = dict(config.get("camoufox") or {})
        debug_mode, effective_headless = _host_mod()._effective_camoufox_headless(browser)
        return {
            "driver": "camoufox",
            "dependency": "available",
            "runtime_version": runtime_version,
            "debug_mode": debug_mode,
            "headless": effective_headless,
            "pool_size": int(browser.get("pool_size") or 2),
            "max_contexts_per_browser": int(browser.get("max_contexts_per_browser") or 3),
        }

    def __call__(
        self,
        task: Mapping[str, Any],
        config: Mapping[str, Any],
        stop_event: Any,
        stage: Callable[[str, str], None],
        log: Callable[[str, str], None],
        *,
        twofa_retry: bool = False,
        password_retry: bool = False,
    ) -> Mapping[str, Any]:
        if twofa_retry and password_retry:
            raise _host_mod().FreeRegisterError(
                "free_retry", "重试 Free 任务",
                "2FA 重试和密码重试不能同时提交",
                retryable=False, error_code="free_retry_modes_conflict",
            )
        task_id = str(task.get("task_id") or "")
        private_result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
        saved_password_token = str(private_result.get("access_token") or "").strip()
        if password_retry:
            if not saved_password_token:
                raise _host_mod().FreeRegisterError(
                    "free_password_retry", "重试 Free 账号密码设置",
                    "原账号没有可用 access token", retryable=False,
                    error_code="free_password_retry_token_missing",
                )
            if not _host_mod().password_retry_allowed(private_result):
                raise _host_mod().FreeRegisterError(
                    "free_password_retry", "重试 Free 账号密码设置",
                    "该账号当前没有可补设的密码状态", retryable=False,
                    error_code="free_password_retry_not_pending",
                )
        existing_password = ""
        for candidate in (
            private_result.get("password"),
            task.get("password"),
            task.get("saved_password"),
        ):
            if str(candidate or "").strip():
                existing_password = str(candidate).strip()
                break
        if twofa_retry and not existing_password:
            # Passwordless accounts never save a credential. Falling back to
            # the mailbox verification-code login inside the browser flow is
            # the supported continuation, so do not reject here anymore.
            log(
                "已有账号未保存密码，将尝试邮箱验证码登录", "warn",
            )
        browser_config = dict(config.get("camoufox") or {})
        if self.debug_artifact_dir:
            browser_config["_debug_artifact_dir"] = self.debug_artifact_dir
        deadline_controller = RegistrationDeadline(
            float(browser_config.get("registration_timeout_seconds") or 600)
        )
        task_deadline_controller = deadline_controller
        provider_kwargs: dict[str, Any] = {"log_fn": log, "task_id": task_id, "stage_fn": stage, **({"batch_id": str(task.get("batch_id") or "")} if task.get("batch_id") else {})}
        if str(task.get("mailbox_source") or "url").strip().lower() == "remail":
            provider_kwargs.update({"mailbox_source": "remail", "mailbox_email": str(task.get("email") or ""), "service_token": str(task.get("service_token") or "")})
        otp = _host_mod().build_free_mailbox_otp_provider(str(task.get("mailbox_url") or ""), str(task.get("proxy") or ""), config, **provider_kwargs)
        # Keep the builder's historical config identity intact.  The
        # deadline is task-local runtime state, so attach it to the provider
        # instance instead of adding a private key to the caller's mapping.
        try:
            setattr(otp, "deadline_controller", deadline_controller)
        except Exception as exc:
            # Controller attachment is optional scheduling telemetry.
            self._note_quiet("deadline_controller_attach", exc)
        try:
            stage(task_id, "free_password_enroll" if password_retry else "free_camoufox_signup")
            if stop_event.is_set():
                raise _host_mod().FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在启动 Camoufox 前已停止", retryable=False)
            def callback(
                stage_code: str = "free_email_otp_wait",
                *,
                stop_requested: Callable[[], bool] | None = None,
                deadline_monotonic: float | None = None,
                deadline_controller: Any | None = None,
            ) -> str:
                active_controller = deadline_controller or task_deadline_controller
                if active_controller is not getattr(otp, "deadline_controller", None):
                    otp.deadline_controller = active_controller
                def combined_stop() -> bool:
                    return stop_event.is_set() or (
                        callable(stop_requested) and bool(stop_requested())
                    )

                return otp.wait_code(
                    str(task.get("email") or ""),
                    stage_code=stage_code,
                    stop_requested=combined_stop,
                    deadline_monotonic=deadline_monotonic,
                )
            result = _host_mod()._pool_for(browser_config).register(
                email=str(task.get("email") or ""),
                # Existing-login and password-continuation adapters retain the
                # historical empty argument shape; _host_mod()._browser_flow resolves the
                # configured value before submitting a signup/password page.
                password="" if (twofa_retry or password_retry) else _host_mod().configured_free_password(config),
                proxy=str(task.get("proxy") or ""), otp_callback=callback,
                otp_prepare=otp.prepare, otp_mark_sent=otp.mark_sent,
                config={
                    **config, **browser_config, "task_id": task_id,
                    "device_id": str(task.get("device_id") or ""),
                    "incident_id": str(task.get("incident_id") or ""),
                    "proxy_fingerprint": str(task.get("proxy_fingerprint") or ""),
                    "_host_mod()._stop_requested": stop_event.is_set,
                    "_deadline_controller": task_deadline_controller,
                }, log=log,
                stage_fn=stage,
                timing_fn=config.get("_timing_substep"),
                force_existing_login=twofa_retry,
                existing_password=existing_password,
                password_retry=password_retry,
                password_retry_token=saved_password_token,
                deadline_controller=task_deadline_controller,
            )
            result = dict(result)
            if password_retry:
                # The browser continuation returns only password fields. Fill
                # missing account evidence from the saved result so a successful
                # password operation cannot erase an existing TOTP/plan/token.
                result = _host_mod().merge_account_result_fields(private_result, result)
            result["registration_ip"] = str(task.get("expected_exit_ip") or task.get("exit_ip") or "")
            result["expected_exit_ip"] = str(task.get("expected_exit_ip") or task.get("exit_ip") or "")
            result["profile_summary"] = "Camoufox shared pool"
            return _host_mod().finalize_registration_result(result, driver="camoufox", email=str(task.get("email") or ""))
        finally:
            close = getattr(otp, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    log("Camoufox 邮箱 OTP 客户端清理失败，不覆盖原任务结果", "warn")


__all__ = [
    "CamoufoxBrowserPool",
    "shutdown_camoufox_pools",
    "camoufox_debug_state",
    "annotate_camoufox_debug_session",
    "close_camoufox_debug_browsers",
    "CamoufoxRegistrationRunner",
]
