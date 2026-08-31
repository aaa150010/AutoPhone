"""One-shot maintenance helpers for obsolete Free JSON log files.

Free diagnostics are now stored in ``diagnostics.sqlite3``.  The old global
``logs.json`` and per-task ``task_logs/*.json`` files are intentionally not
imported: they may contain stale, unstructured data and are not an authoritative
source anymore.  This module provides a narrow, idempotent cleanup command for
installations that still have those files.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any, Iterable


MIGRATION_KEY = "free_legacy_json_logs_cleanup"
MIGRATION_VERSION = "1"


@dataclass(frozen=True, slots=True)
class CleanupResult:
    """Result of one cleanup attempt, safe to expose in a health response."""

    data_dir: str
    deleted: int = 0
    skipped: int = 0
    already_done: bool = False
    failed: bool = False
    error_type: str = ""
    marker_written: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "data_dir": self.data_dir,
            "deleted": self.deleted,
            "skipped": self.skipped,
            "already_done": self.already_done,
            "failed": self.failed,
            "error_type": self.error_type,
            "marker_written": self.marker_written,
        }


def _root(data_dir: str | Path) -> Path:
    # Resolve only after rejecting a symlink at the deletion root.  Calling
    # ``resolve`` first would silently turn ``.../free_register`` into an
    # operator-unexpected external directory and make the narrow cleanup
    # scope ineffective.
    candidate = Path(data_dir).expanduser()
    if candidate.is_symlink():
        raise ValueError("data_dir must not be a symlink")
    root = candidate.resolve()
    # The helper must never receive the broad application root.  A Free data
    # directory is either explicitly named ``free_register`` or contains the
    # Free pool marker; reject obvious parent paths to keep deletion narrow.
    if root.name != "free_register":
        raise ValueError("data_dir must be the isolated free_register directory")
    return root


def _marker_path(root: Path) -> Path:
    # The marker lives in the Free-owned database used by the other storage
    # services.  Creating only this tiny metadata table is safe when the main
    # database has not been initialized yet, and avoids a second state store.
    return root / "free_register.sqlite3"


def _read_marker(root: Path) -> bool:
    path = _marker_path(root)
    if not path.is_file():
        return False
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=0.2)
        connection.execute("PRAGMA busy_timeout=200")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS storage_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        row = connection.execute(
            "SELECT value FROM storage_meta WHERE key=?", (MIGRATION_KEY,)
        ).fetchone()
        connection.commit()
        return bool(row and str(row[0]) == MIGRATION_VERSION)
    except sqlite3.Error:
        # A corrupt marker must not be treated as completed; the caller can
        # retry cleanup and receive a structured failure instead.
        raise
    finally:
        if connection is not None:
            connection.close()


def _write_marker(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    path = _marker_path(root)
    connection = sqlite3.connect(path, timeout=1.0)
    try:
        connection.execute("PRAGMA busy_timeout=1000")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS storage_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO storage_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (MIGRATION_KEY, MIGRATION_VERSION),
        )
        connection.commit()
    finally:
        connection.close()


def _targets(root: Path) -> Iterable[Path]:
    """Yield only the two explicitly supported legacy file shapes."""
    yield root / "logs.json"
    task_dir = root / "task_logs"
    # ``Path.iterdir`` follows a directory symlink.  Refuse the directory
    # itself before walking it, otherwise a malicious/stale link could make a
    # cleanup intended for this Free directory unlink JSON files elsewhere.
    if task_dir.is_symlink():
        # Yield the link itself so the caller reports one skipped target;
        # the deletion loop has an explicit no-symlink rule.
        yield task_dir
        return
    if not task_dir.is_dir():
        return
    # Inspection failures must reach ``cleanup_legacy_logs``. Silently
    # treating an unreadable directory as empty would write a completed marker
    # while obsolete logs may still be present.
    children = sorted(task_dir.iterdir())
    for child in children:
        # Do not recurse and do not remove arbitrary files from task_logs.
        if child.suffix.lower() != ".json":
            continue
        # Yield a JSON-shaped symlink even when its target is missing. The
        # deletion loop records it as skipped and deliberately withholds the
        # completion marker for an operator-visible retry.
        if child.is_symlink() or child.is_file():
            yield child


def cleanup_legacy_logs(
    data_dir: str | Path,
    *,
    dry_run: bool = False,
    force: bool = False,
    diagnostic_store: Any = None,
) -> CleanupResult:
    """Delete obsolete Free JSON log files exactly once.

    The operation is idempotent and never follows symlinks.  By default a
    completed ``storage_meta`` marker avoids touching the filesystem again;
    ``force`` is intended for an operator explicitly repairing a partial
    installation.  No task, result, mailbox, proxy, or diagnostic database is
    included in the target set.
    """
    root = _root(data_dir)

    def failure_result(
        *, deleted: int = 0, skipped: int = 0, error_type: str,
    ) -> CleanupResult:
        result = CleanupResult(
            str(root), deleted=deleted, skipped=skipped, failed=True,
            error_type=error_type,
        )
        # Cleanup diagnostics are deliberately best-effort. Never let a
        # broken diagnostic index turn a maintenance failure into an app
        # startup failure, and never include filesystem paths or exception
        # messages in the event payload.
        if diagnostic_store is not None:
            try:
                from .diagnostic_writer import DiagnosticEventWriter
            except ImportError:  # pragma: no cover
                from diagnostic_writer import DiagnosticEventWriter  # type: ignore[no-redef]
            try:
                DiagnosticEventWriter(diagnostic_store).record({
                    "chain": "free",
                    "workflow": "maintenance",
                    "driver": "free",
                    "node_code": "free_log_cleanup",
                    "node_label": "清理 Free 旧日志",
                    "outcome": "failed",
                    "level": "error",
                    "failure": {
                        "error_code": "free_log_cleanup_failed",
                        "retryable": True,
                        "technical_summary": "旧日志清理未完成",
                    },
                })
            except Exception:
                pass
        return result

    try:
        if not force and _read_marker(root):
            return CleanupResult(str(root), already_done=True)
        deleted = 0
        skipped = 0
        blocked_by_symlink = False
        for target in _targets(root):
            try:
                # A symlink is never followed or unlinked: leave it for an
                # operator to inspect rather than widening the deletion scope.
                if target.is_symlink():
                    blocked_by_symlink = True
                    skipped += 1
                    continue
                if not target.is_file():
                    continue
                if dry_run:
                    skipped += 1
                    continue
                target.unlink()
                deleted += 1
            except FileNotFoundError:
                continue
            except OSError as exc:
                return failure_result(
                    deleted=deleted, skipped=skipped, error_type=type(exc).__name__,
                )
        if dry_run:
            return CleanupResult(str(root), deleted=0, skipped=skipped)
        # A skipped symlink means the target set was not fully inspected.  Do
        # not claim one-shot completion: an operator may replace the link
        # with a regular legacy file and retry cleanup later.  Keep this a
        # non-failure for compatibility with the existing health/API shape.
        if blocked_by_symlink:
            return CleanupResult(str(root), deleted=deleted, skipped=skipped)
        try:
            _write_marker(root)
        except (OSError, sqlite3.Error) as exc:
            return failure_result(
                deleted=deleted, skipped=skipped, error_type=type(exc).__name__,
            )
        return CleanupResult(str(root), deleted=deleted, skipped=skipped, marker_written=True)
    except (OSError, sqlite3.Error, ValueError) as exc:
        return failure_result(error_type=type(exc).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Remove obsolete Free JSON logs")
    parser.add_argument("--data-dir", required=True, help="isolated .../free_register directory")
    parser.add_argument("--dry-run", action="store_true", help="report targets without deleting")
    parser.add_argument("--force", action="store_true", help="run even when the marker is complete")
    args = parser.parse_args(argv)
    result = cleanup_legacy_logs(args.data_dir, dry_run=args.dry_run, force=args.force)
    # Keep CLI output machine-readable and credential-free.
    import json

    print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
    return 1 if result.failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "CleanupResult",
    "MIGRATION_KEY",
    "MIGRATION_VERSION",
    "cleanup_legacy_logs",
    "main",
]
