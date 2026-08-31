"""Composition root for the Free compatibility manager."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from ..diagnostic_writer import DiagnosticEventWriter, LogContext
    from ..free_log_migration import cleanup_legacy_logs
    from ..free_storage import FreeSQLiteStore
except ImportError:  # pragma: no cover
    from diagnostic_writer import DiagnosticEventWriter, LogContext  # type: ignore[no-redef]
    from free_log_migration import cleanup_legacy_logs  # type: ignore[no-redef]
    from free_storage import FreeSQLiteStore  # type: ignore[no-redef]

from .task_repository import FreeTaskRepository


@dataclass(frozen=True, slots=True)
class FreeManagerComponents:
    data_dir: Path
    storage: FreeSQLiteStore
    tasks: FreeTaskRepository
    diagnostic_writer: DiagnosticEventWriter | None
    log_cleanup: Any


def build_manager_components(
    data_dir: str | Path,
    *,
    diagnostic_store: Any = None,
) -> FreeManagerComponents:
    """Build isolated persistence and diagnostics before worker startup."""

    # Keep the lexical path for legacy-log maintenance.  Resolving a symlink
    # before calling the cleanup helper would bypass its root guard; the
    # SQLite store still receives the resolved path for normal persistence.
    input_root = Path(data_dir).expanduser()
    root = input_root.resolve()
    storage = FreeSQLiteStore(root)
    tasks = FreeTaskRepository(root, storage=storage)
    writer = None
    if diagnostic_store is not None:
        writer = DiagnosticEventWriter(
            diagnostic_store,
            context=LogContext(chain="free", workflow="register", driver="free"),
        )
    try:
        # The cleanup helper intentionally rejects broad/non-Free roots.  The
        # composition API is also used by legacy integrations with arbitrary
        # temporary directories, so skip startup cleanup there rather than
        # turning a compatibility path check into a diagnostic incident.
        cleanup = (
            cleanup_legacy_logs(input_root, diagnostic_store=diagnostic_store)
            if root.name == "free_register"
            else {"deleted": 0, "skipped": 0, "already_done": False, "failed": False}
        )
    except Exception as exc:
        # Maintenance is deliberately non-blocking for task startup. Keep a
        # small health-shaped result and attach a structured event when the
        # helper rejects the path or encounters an unexpected error.
        cleanup = {
            "failed": True,
            "error_type": type(exc).__name__,
            "deleted": 0,
            "skipped": 0,
        }
        if writer is not None:
            writer.record({
                "level": "error",
                "outcome": "cleanup_failed",
                "workflow": "maintenance",
                "node_code": "free_log_cleanup",
                "node_label": "清理 Free 旧日志",
                "message": "旧日志清理未完成",
                "failure": {
                    "error_code": "free_log_cleanup_failed",
                    "technical_summary": "旧日志清理未完成",
                    "retryable": True,
                    "transport_error_code": type(exc).__name__,
                    "action_hint": "检查 Free 数据目录权限后重试维护命令。",
                },
            })
    return FreeManagerComponents(root, storage, tasks, writer, cleanup)


def legacy_manager_class() -> Any:
    """Resolve the compatibility class lazily to avoid an import cycle."""

    try:
        from ..free_register_runtime import FreeRegisterManager
    except ImportError:  # pragma: no cover
        from free_register_runtime import FreeRegisterManager  # type: ignore[no-redef]
    return FreeRegisterManager


def create_manager(data_dir: str | Path, **kwargs: Any) -> Any:
    return legacy_manager_class()(data_dir, **kwargs)


def __getattr__(name: str) -> Any:
    if name == "FreeRegisterManager":
        return legacy_manager_class()
    raise AttributeError(name)


__all__ = [
    "FreeManagerComponents",
    "FreeRegisterManager",
    "build_manager_components",
    "create_manager",
    "legacy_manager_class",
]
