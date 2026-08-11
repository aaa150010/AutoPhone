"""Incremental historical SMS cost aggregation for dashboard snapshots.

Set ``GPTPHONE_SMS_COST_INCREMENTAL=0`` and restart when any documented
``ROLLBACK_CONDITIONS`` occurs; snapshots then synchronously reconcile disk.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import threading
import time
from typing import Any, Mapping

try:
    from .result_persistence_runtime import resolve_results_dir, result_json_path
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from result_persistence_runtime import resolve_results_dir, result_json_path


INCREMENTAL_ENVIRONMENT_VARIABLE = "GPTPHONE_SMS_COST_INCREMENTAL"
ROLLBACK_CONDITIONS = {
    "snapshot_mismatch": "A forced disk reconciliation disagrees with the incremental snapshot.",
    "persist_visibility_delay": "A persisted result is absent after one public-state refresh cycle.",
    "reconcile_failures": "The background reconciliation worker fails three consecutive times.",
    "invalid_aggregate": "The account count or total cost becomes negative or non-finite.",
}
_FALSE_ENVIRONMENT_VALUES = frozenset({"0", "false", "no", "off"})


def _incremental_enabled_from_environment() -> bool:
    value = os.environ.get(INCREMENTAL_ENVIRONMENT_VARIABLE, "1")
    return value.strip().lower() not in _FALSE_ENVIRONMENT_VALUES


@dataclass(frozen=True)
class _ResultCost:
    signature: tuple[int, int]
    task_id: str
    cost_cny: float | None
    rank: tuple[float, int, str]


def _valid_cost(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        cost = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return cost if math.isfinite(cost) and cost >= 0 else None


def _result_timestamp(document: Mapping[str, Any]) -> float:
    timing = document.get("timing") if isinstance(document.get("timing"), Mapping) else {}
    for value in (
        document.get("created_at"),
        timing.get("finished_at"),
        document.get("batch_started_at"),
    ):
        try:
            parsed = float(value or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        if math.isfinite(parsed) and parsed > 0:
            return parsed
    return 0.0


def _document_cost(document: Mapping[str, Any]) -> float | None:
    result = document.get("result") if isinstance(document.get("result"), Mapping) else {}
    value = (
        result.get("sms_cost_cny")
        if "sms_cost_cny" in result
        else document.get("sms_cost_cny")
    )
    return _valid_cost(value)


class SmsCostHistoryIndex:
    """Cache numeric contributions while tracking result-file changes."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        reconcile_seconds: float = 30.0,
        incremental_enabled: bool | None = None,
    ) -> None:
        self.data_dir = Path(data_dir).resolve(strict=False)
        self.reconcile_seconds = max(0.0, float(reconcile_seconds))
        self.incremental_enabled = (
            _incremental_enabled_from_environment()
            if incremental_enabled is None
            else bool(incremental_enabled)
        )
        self.lock = threading.RLock()
        self._reconcile_lock = threading.Lock()
        self._results_dir: Path | None = None
        self._directory_signature: tuple[int, int] | None = None
        self._generation = 0
        self._initialized = False
        self._signatures: dict[Path, tuple[int, int]] = {}
        self._files: dict[Path, _ResultCost] = {}
        self._task_paths: dict[str, set[Path]] = {}
        self._latest: dict[str, _ResultCost] = {}
        self._account_count = 0
        self._total_cny = 0.0
        self._snapshot = self._empty_snapshot()
        self._worker_started = False
        self._reconcile_count = 0
        self._changed_files = 0
        self._last_reconcile_seconds = 0.0
        self._consecutive_reconcile_failures = 0

    @staticmethod
    def _empty_snapshot() -> dict[str, Any]:
        return {"account_count": 0, "total_cny": 0.0, "average_cny": 0.0}

    def _settings(self) -> dict[str, Any]:
        path = self.data_dir / "settings.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        return dict(value) if isinstance(value, Mapping) else {}

    def _configured_results_dir(self) -> Path:
        return resolve_results_dir(self._settings(), self.data_dir)

    @staticmethod
    def _dir_signature(root: Path) -> tuple[int, int] | None:
        try:
            stat = root.stat()
        except OSError:
            return None
        return stat.st_mtime_ns, stat.st_ctime_ns

    @staticmethod
    def _file_signature(path: Path) -> tuple[int, int] | None:
        try:
            stat = path.stat()
        except OSError:
            return None
        return stat.st_mtime_ns, stat.st_size

    @staticmethod
    def _read_result(path: Path, signature: tuple[int, int]) -> _ResultCost | None:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        if not isinstance(document, Mapping):
            return None
        task_id = str(document.get("task_id") or "").strip() or f"path:{path.name}"
        return _ResultCost(
            signature=signature,
            task_id=task_id,
            cost_cny=_document_cost(document),
            rank=(_result_timestamp(document), signature[0], path.name),
        )

    def _publish_snapshot(self) -> None:
        total = round(self._total_cny, 4)
        self._snapshot = {
            "account_count": self._account_count,
            "total_cny": total,
            "average_cny": round(total / self._account_count, 4) if self._account_count else 0.0,
        }

    def _refresh_task(self, task_id: str) -> None:
        previous = self._latest.get(task_id)
        if previous is not None and previous.cost_cny is not None:
            self._account_count -= 1
            self._total_cny -= previous.cost_cny
        candidates = (
            self._files[path]
            for path in self._task_paths.get(task_id, ())
            if path in self._files
        )
        current = max(candidates, key=lambda item: item.rank, default=None)
        if current is None:
            self._latest.pop(task_id, None)
        else:
            self._latest[task_id] = current
            if current.cost_cny is not None:
                self._account_count += 1
                self._total_cny += current.cost_cny

    def _replace_file(self, path: Path, contribution: _ResultCost | None) -> None:
        previous = self._files.pop(path, None)
        affected: set[str] = set()
        if previous is not None:
            affected.add(previous.task_id)
            paths = self._task_paths.get(previous.task_id)
            if paths is not None:
                paths.discard(path)
                if not paths:
                    self._task_paths.pop(previous.task_id, None)
        if contribution is not None:
            self._files[path] = contribution
            self._task_paths.setdefault(contribution.task_id, set()).add(path)
            affected.add(contribution.task_id)
        for task_id in affected:
            self._refresh_task(task_id)

    def _clear(self, root: Path) -> None:
        self._results_dir = root
        self._directory_signature = None
        self._generation += 1
        self._initialized = False
        self._signatures.clear()
        self._files.clear()
        self._task_paths.clear()
        self._latest.clear()
        self._account_count = 0
        self._total_cny = 0.0
        self._snapshot = self._empty_snapshot()

    def reconcile(self) -> None:
        """Reconcile disk changes without holding the public snapshot lock during I/O."""
        started = time.monotonic()
        try:
            with self._reconcile_lock:
                changed_files = self._reconcile()
        except Exception:
            with self.lock:
                self._last_reconcile_seconds = round(time.monotonic() - started, 6)
                self._consecutive_reconcile_failures += 1
            raise
        with self.lock:
            self._reconcile_count += 1
            self._changed_files += changed_files
            self._last_reconcile_seconds = round(time.monotonic() - started, 6)
            self._consecutive_reconcile_failures = 0

    def _reconcile(self) -> int:
        root = self._configured_results_dir()
        with self.lock:
            if root != self._results_dir:
                self._clear(root)
            generation = self._generation
            baseline = dict(self._signatures)
        try:
            paths = [path for path in root.iterdir() if path.is_file() and path.suffix == ".json"]
        except OSError:
            paths = []
        scanned: dict[Path, tuple[int, int]] = {}
        changed: dict[Path, _ResultCost | None] = {}
        for path in paths:
            signature = self._file_signature(path)
            if signature is None:
                continue
            scanned[path] = signature
            if baseline.get(path) != signature:
                changed[path] = self._read_result(path, signature)
        directory_signature = self._dir_signature(root)
        applied_changes = 0
        with self.lock:
            if generation != self._generation or root != self._results_dir:
                return 0
            for path, contribution in changed.items():
                current_signature = self._signatures.get(path)
                if current_signature is None or current_signature == baseline.get(path):
                    self._replace_file(path, contribution)
                    self._signatures[path] = scanned[path]
                    applied_changes += 1
            for path, signature in baseline.items():
                if path not in scanned and self._signatures.get(path) == signature:
                    self._replace_file(path, None)
                    self._signatures.pop(path, None)
                    applied_changes += 1
            self._directory_signature = directory_signature
            self._initialized = True
            self._publish_snapshot()
        return applied_changes

    def record_path(self, path: str | Path) -> None:
        """Apply one successfully persisted result without scanning the directory."""
        if not self.incremental_enabled:
            self.reconcile()
            return
        target = Path(path).resolve(strict=False)
        with self.lock:
            if target.parent != self._results_dir:
                return
        signature = self._file_signature(target)
        contribution = self._read_result(target, signature) if signature is not None else None
        directory_signature = self._dir_signature(target.parent)
        with self.lock:
            if target.parent != self._results_dir:
                return
            self._replace_file(target, contribution)
            if signature is None:
                self._signatures.pop(target, None)
            else:
                self._signatures[target] = signature
            self._directory_signature = directory_signature
            self._publish_snapshot()

    def _start_worker(self) -> None:
        with self.lock:
            if (
                self._worker_started
                or not self.incremental_enabled
                or self.reconcile_seconds <= 0
            ):
                return
            self._worker_started = True

        def run() -> None:
            wake = threading.Event()
            while True:
                wake.wait(self.reconcile_seconds)
                try:
                    self.reconcile()
                except Exception:
                    continue

        threading.Thread(target=run, name="sms-cost-history", daemon=True).start()

    def snapshot(self) -> dict[str, Any]:
        root = self._configured_results_dir()
        with self.lock:
            needs_initial = not self._initialized or root != self._results_dir
        if needs_initial or not self.incremental_enabled:
            self.reconcile()
        self._start_worker()
        with self.lock:
            return dict(self._snapshot)

    def metrics(self) -> dict[str, Any]:
        """Return credential-free health metrics for rollback decisions."""
        with self.lock:
            return {
                "incremental_enabled": self.incremental_enabled,
                "initialized": self._initialized,
                "tracked_files": len(self._signatures),
                "tracked_tasks": len(self._latest),
                "account_count": self._account_count,
                "reconcile_count": self._reconcile_count,
                "changed_files": self._changed_files,
                "last_reconcile_seconds": self._last_reconcile_seconds,
                "consecutive_reconcile_failures": self._consecutive_reconcile_failures,
                "rollback_reason": "" if self.incremental_enabled else "environment_disabled",
            }


def attach_task_sms_cost(
    result: dict[str, Any],
    task_id: Any,
    ledger: Any,
    exchange: Any,
) -> None:
    """Preserve the existing task-cost attachment policy outside web_gui."""

    cost_summary = ledger.summary(str(task_id), exchange)
    if cost_summary.get("sms_order_outcomes") or "sms_cost_usd" not in result:
        result.update(cost_summary)


_INDEXES_LOCK = threading.Lock()
_INDEXES: dict[Path, SmsCostHistoryIndex] = {}


def historical_sms_cost(data_dir: str | Path) -> dict[str, Any]:
    root = Path(data_dir).resolve(strict=False)
    with _INDEXES_LOCK:
        index = _INDEXES.setdefault(root, SmsCostHistoryIndex(root))
    return index.snapshot()


def note_persisted_result(
    data_dir: str | Path,
    settings: Mapping[str, Any] | None,
    task_id: Any,
    email: Any,
) -> None:
    try:
        root = Path(data_dir).resolve(strict=False)
        with _INDEXES_LOCK:
            index = _INDEXES.setdefault(root, SmsCostHistoryIndex(root))
        index.record_path(result_json_path(settings, root, task_id, email))
    except Exception:
        return


def with_historical_sms_cost(
    summary: Mapping[str, Any] | None,
    data_dir: str | Path,
) -> dict[str, Any]:
    value = dict(summary or {})
    value["sms_cost_history"] = historical_sms_cost(data_dir)
    return value


__all__ = [
    "INCREMENTAL_ENVIRONMENT_VARIABLE",
    "ROLLBACK_CONDITIONS",
    "SmsCostHistoryIndex",
    "attach_task_sms_cost",
    "historical_sms_cost",
    "note_persisted_result",
    "with_historical_sms_cost",
]
