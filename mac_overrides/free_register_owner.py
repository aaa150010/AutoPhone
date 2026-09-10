"""Process owner fencing for the Free register manager.

Split out of ``free_register_runtime``; the manager keeps initializing the
``_manager_owner_*`` state while this mixin owns the acquire / verify /
release protocol against the isolated Free SQLite store.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

try:
    from .free_register_common import FreeRegisterError
except ImportError:  # pragma: no cover - top-level recovery import
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]

try:
    from .free_storage import ManagerOwnerConflict
except ImportError:  # pragma: no cover - top-level recovery import
    from free_storage import ManagerOwnerConflict  # type: ignore[no-redef]


class FreeRegisterOwnerMixin:
    """Fence Free database writes to one live manager process.

    Required host attributes: ``storage`` (exposing ``acquire_manager_owner``,
    ``manager_owner_status``, ``manager_owner_is_current`` and
    ``release_manager_owner``), the ``_manager_owner_*`` state initialized by
    the manager, plus ``_log`` and ``_note_quiet`` for telemetry.
    """

    def _owner_storage(self) -> Any | None:
        storage = getattr(self, "storage", None)
        if storage is None or not callable(getattr(storage, "acquire_manager_owner", None)):
            return None
        return storage

    def _runtime_owner_is_live(self) -> bool:
        """Return whether another manager currently fences this database."""
        storage = self._owner_storage()
        if storage is None:
            return False
        try:
            status = storage.manager_owner_status()
        except Exception:
            # An unavailable metadata read must not make a fresh process
            # overwrite active task rows. Treat the runtime as fenced until a
            # later explicit start can establish ownership atomically.
            return True
        return bool(isinstance(status, Mapping) and status.get("active"))

    def _acquire_runtime_owner(self) -> None:
        """Claim the isolated Free database before reserving any resources."""
        storage = self._owner_storage()
        if storage is None:
            return
        if self._manager_owner_acquired:
            if self._owner_current():
                return
            self._runtime_fenced = True
            raise FreeRegisterError(
                "free_process_owner",
                "Free 进程所有权",
                "当前 Free 进程已失去数据库所有权，拒绝继续写入",
                retryable=True,
                error_code="free_manager_epoch_mismatch",
                action_hint="停止当前服务并等待旧任务退出后重新启动",
            )
        try:
            owner = storage.acquire_manager_owner(
                self._manager_owner_id,
                pid=os.getpid(),
            )
        except ManagerOwnerConflict as exc:
            self._runtime_fenced = True
            raise FreeRegisterError(
                "free_process_owner",
                "Free 进程所有权",
                "已有 Free 注册进程正在运行，请先等待上一批任务停止",
                retryable=True,
                error_code="free_manager_already_running",
                action_hint="调用停止并等待任务完成，或确认旧进程已退出后重试",
                provider_code=str(exc.owner.get("pid") or ""),
            ) from exc
        except Exception as exc:
            raise FreeRegisterError(
                "free_process_owner",
                "Free 进程所有权",
                "Free 进程所有权暂时无法建立",
                retryable=True,
                error_code="free_manager_owner_store_failed",
                action_hint="检查 Free SQLite 数据库权限和锁状态后重试",
                provider_code=type(exc).__name__,
            ) from exc
        self._manager_owner_epoch = int(owner.get("epoch") or 0)
        self._manager_owner_acquired = True
        self._runtime_fenced = False
        self._manager_owner_fence_reported = False

    def _ensure_runtime_owner(self) -> None:
        """Require a valid owner for retry/continuation writes."""
        self._acquire_runtime_owner()

    def _owner_current(self) -> bool:
        storage = self._owner_storage()
        if storage is None or not self._manager_owner_acquired:
            return True
        try:
            return bool(
                storage.manager_owner_is_current(
                    self._manager_owner_id,
                    self._manager_owner_epoch,
                )
            )
        except Exception:
            return False

    def _record_owner_fenced(self, *, task_id: str = "") -> None:
        """Emit one credential-free event when a stale worker is fenced."""
        if self._manager_owner_fence_reported:
            return
        self._manager_owner_fence_reported = True
        try:
            self._log(
                f"[{task_id or 'free'}/Free 进程所有权/free_process_owner] "
                "旧 worker 写入被拒绝，数据库已由新进程接管",
                "warn",
                task_id=task_id,
                node_code="free_process_owner",
                node_label="Free 进程所有权",
                outcome="stale_writer_rejected",
                error_code="free_manager_epoch_mismatch",
                workflow="lifecycle",
            )
        except Exception as exc:
            # Lifecycle telemetry must not break manager shutdown.
            self._note_quiet("lifecycle_telemetry", exc)

    def _release_runtime_owner(self) -> None:
        storage = self._owner_storage()
        if storage is None or not self._manager_owner_acquired:
            return
        owner_id = self._manager_owner_id
        epoch = self._manager_owner_epoch
        self._manager_owner_acquired = False
        try:
            storage.release_manager_owner(owner_id, epoch)
        except Exception as exc:
            # Process exit/cleanup is best effort; a dead PID and TTL let the
            # next manager reclaim the fence even if this write fails.
            self._note_quiet("manager_owner_release", exc)


__all__ = ["FreeRegisterOwnerMixin"]
