"""Durable, credential-free manifests for one-click runtime batches."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any
import uuid


MANIFEST_VERSION = 1
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_STATUSES = frozenset(
    {
        "success",
        "failed",
        "stopped",
        "stopped_before_start",
        "retryable_infra",
        "retryable_email",
        "repair_pending",
        "email_damaged",
        "account_banned",
        "cancelled",
        "canceled",
    }
)
_STOPPED_STATUSES = frozenset(
    {"stopped", "stopped_before_start", "cancelled", "canceled"}
)


def _clean(value: Any, maximum: int = 256) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()[:maximum]


def _safe_id(value: Any) -> str:
    text = _clean(value, 128)
    return text if _SAFE_ID_RE.fullmatch(text) else ""


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _row_fingerprint(value: Any) -> str:
    text = str(value or "").strip()
    lowered = text.lower()
    if _SHA256_RE.fullmatch(lowered):
        return lowered
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _accepts_keyword(callback: Callable[..., Any], name: str) -> bool:
    try:
        parameters = inspect.signature(callback).parameters
    except (TypeError, ValueError):
        return False
    parameter = parameters.get(name)
    return bool(
        parameter
        and parameter.kind
        in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
    ) or any(item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values())


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def reconciliation_failure(code: str, cause: str) -> dict[str, Any]:
    label = "运行批次对账"
    message = f"{label} [{label}/{code}]：{cause}"
    return {
        "node_code": code,
        "node_label": label,
        "error_code": code,
        "public_message": message,
        "technical_summary": message,
        "retryable": True,
        "http_status": None,
    }


_failure = reconciliation_failure


class RunBatchManifestStore:
    """Persist batch membership before workers can start and reconcile every member."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        manifest_path: str | Path | None = None,
        now: Callable[[], float] = time.time,
        recover_pending: bool = True,
        log_fn: Callable[[str, str], None] | None = None,
        lease_releaser: Callable[..., Any] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.manifest_path = (
            Path(manifest_path).expanduser().resolve()
            if manifest_path
            else self.data_dir / "run_batch_manifests.json"
        )
        self.now = now
        self.log_fn = log_fn
        self.lease_releaser = lease_releaser
        self._lock = threading.RLock()
        self._store = self._load()
        self._task_index: dict[str, str] = {}
        self._rebuild_task_index_locked()
        if recover_pending:
            self.recover()

    def _load(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {"version": MANIFEST_VERSION, "batches": []}
        batches = raw.get("batches") if isinstance(raw, Mapping) else None
        return {
            "version": MANIFEST_VERSION,
            "batches": [
                copy.deepcopy(item)
                for item in batches or []
                if isinstance(item, Mapping) and _safe_id(item.get("batch_id"))
            ],
        }

    def _save_locked(self) -> None:
        _atomic_write_json(self.manifest_path, self._store)

    def _emit(self, message: str, level: str = "info") -> None:
        if not callable(self.log_fn):
            return
        try:
            self.log_fn(_clean(message, 500), level)
        except Exception:
            pass

    def _rebuild_task_index_locked(self) -> None:
        self._task_index.clear()
        for batch in self._store["batches"]:
            batch_id = _safe_id(batch.get("batch_id"))
            for member in batch.get("members") or []:
                if isinstance(member, Mapping):
                    task_id = _safe_id(member.get("task_id"))
                    if task_id:
                        self._task_index[task_id] = batch_id

    def _batch_locked(self, batch_id: Any) -> dict[str, Any]:
        identifier = _safe_id(batch_id)
        for batch in self._store["batches"]:
            if batch.get("batch_id") == identifier:
                return batch
        raise KeyError(identifier)

    @staticmethod
    def _member_locked(batch: Mapping[str, Any], task_id: Any) -> dict[str, Any]:
        identifier = _safe_id(task_id)
        for member in batch.get("members") or []:
            if isinstance(member, dict) and member.get("task_id") == identifier:
                return member
        raise KeyError(identifier)

    def _batch_for_task_locked(self, task_id: Any) -> dict[str, Any]:
        identifier = _safe_id(task_id)
        batch_id = self._task_index.get(identifier)
        if not batch_id:
            raise KeyError(identifier)
        return self._batch_locked(batch_id)

    def _stored_local_path(
        self,
        settings: Mapping[str, Any],
        key: str,
        default_name: str,
    ) -> str:
        raw = _clean(settings.get(key), 2048)
        path = Path(raw) if raw else self.data_dir / default_name
        if not path.is_absolute():
            path = self.data_dir / path
        resolved = path.expanduser().resolve()
        try:
            return resolved.relative_to(self.data_dir).as_posix()
        except ValueError:
            # This is a local mode-0600 recovery pointer, never returned publicly.
            return str(resolved)

    def _stored_results_dir(self, settings: Mapping[str, Any]) -> str:
        return self._stored_local_path(settings, "results_dir", "results")

    def _local_path(self, batch: Mapping[str, Any], key: str, default_name: str) -> Path:
        raw = _clean(batch.get(key), 2048)
        path = Path(raw) if raw else self.data_dir / default_name
        return (path if path.is_absolute() else self.data_dir / path).resolve()

    def _results_dir(self, batch: Mapping[str, Any]) -> Path:
        return self._local_path(batch, "results_dir", "results")

    @staticmethod
    def _refresh_counts_locked(batch: dict[str, Any]) -> None:
        members = [item for item in batch.get("members") or [] if isinstance(item, Mapping)]
        terminal = [item for item in members if item.get("terminal_at")]
        statuses = [str(item.get("status") or "").strip().lower() for item in terminal]
        batch["counts"] = {
            "target": max(_safe_int(batch.get("target")), len(members)),
            "reserved": sum(1 for item in members if item.get("reserved_at")),
            "started": sum(1 for item in members if item.get("started_at")),
            "terminal": len(terminal),
            "persisted": sum(1 for item in members if item.get("persisted_at")),
            "success": sum(1 for value in statuses if value == "success"),
            "failed": sum(1 for value in statuses if value not in _STOPPED_STATUSES and value != "success"),
            "stopped": sum(1 for value in statuses if value in _STOPPED_STATUSES),
            "missing": sum(1 for item in members if item.get("reconciled_missing")),
        }

    def begin(
        self,
        settings: Mapping[str, Any],
        *,
        target: int,
        members: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        return self._create(settings, target=target, members=members, status="active")

    def prepare(
        self,
        settings: Mapping[str, Any],
        *,
        target: int,
        members: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Persist immutable membership before the mailbox lease transaction commits."""
        return self._create(settings, target=target, members=members, status="preparing")

    def _create(
        self,
        settings: Mapping[str, Any],
        *,
        target: int,
        members: Iterable[Mapping[str, Any]],
        status: str,
    ) -> dict[str, Any]:
        batch_id = _safe_id(settings.get("batch_id"))
        if not batch_id:
            raise ValueError("运行批次缺少有效 batch_id")
        member_rows: list[dict[str, Any]] = []
        seen_tasks: set[str] = set()
        seen_ordinals: set[int] = set()
        for raw in members:
            task_id = _safe_id(raw.get("task_id"))
            ordinal = _safe_int(raw.get("ordinal"))
            if not task_id or ordinal <= 0 or task_id in seen_tasks or ordinal in seen_ordinals:
                raise ValueError("运行批次成员标识无效或重复")
            seen_tasks.add(task_id)
            seen_ordinals.add(ordinal)
            member_rows.append(
                {
                    "task_id": task_id,
                    "ordinal": ordinal,
                    "row_id": _row_fingerprint(raw.get("row_id")),
                    "line_no": max(_safe_int(raw.get("line_no")), 0),
                    "status": "planned",
                    "reserved_at": 0,
                    "started_at": 0,
                    "terminal_at": 0,
                    "persisted_at": 0,
                    "reconciled_missing": False,
                }
            )
        requested = max(_safe_int(target), 0)
        if requested <= 0 or len(member_rows) != requested:
            raise ValueError("运行批次成员数量与目标数量不一致")
        now = int(self.now())
        with self._lock:
            try:
                existing = self._batch_locked(batch_id)
            except KeyError:
                existing = None
            if existing is not None:
                if _safe_int(existing.get("target")) != requested:
                    raise ValueError("运行批次 ID 已存在且目标数量不一致")
                return self._public(existing, include_members=True)
            batch = {
                "batch_id": batch_id,
                "batch_started_at": (
                    _safe_int(settings.get("batch_started_at"))
                    if _safe_int(settings.get("batch_started_at")) > 0
                    else now
                ),
                "mode": _clean(settings.get("run_mode"), 32).lower() or "register",
                "target": requested,
                "results_dir": self._stored_results_dir(settings),
                "pool_path": self._stored_local_path(
                    settings,
                    "pool_path",
                    "mailbox_pool.txt",
                ),
                "state_path": self._stored_local_path(
                    settings,
                    "state_path",
                    "mailbox_pool_state.json",
                ),
                "status": status,
                "members": member_rows,
                "counts": {},
                "created_at": now,
                "updated_at": now,
                "completed_at": 0,
            }
            self._refresh_counts_locked(batch)
            self._store["batches"].append(batch)
            for task_id in seen_tasks:
                self._task_index[task_id] = batch_id
            try:
                self._save_locked()
            except Exception:
                self._store["batches"].remove(batch)
                self._rebuild_task_index_locked()
                raise
            return self._public(batch, include_members=True)

    def commit_prepared(self, batch_id: Any) -> dict[str, Any]:
        now = int(self.now())
        with self._lock:
            batch = self._batch_locked(batch_id)
            status = _clean(batch.get("status"), 32).lower()
            if status == "active":
                return self._public(batch, include_members=True)
            if status != "preparing":
                raise ValueError("运行批次不处于可提交状态")
            prior_updated_at = batch.get("updated_at")
            batch["status"] = "active"
            batch["updated_at"] = now
            try:
                self._save_locked()
            except Exception:
                batch["status"] = "preparing"
                batch["updated_at"] = prior_updated_at
                raise
            return self._public(batch, include_members=True)

    def rollback_prepared(self, batch_id: Any) -> bool:
        identifier = _safe_id(batch_id)
        with self._lock:
            batch = self._batch_locked(identifier)
            if _clean(batch.get("status"), 32).lower() != "preparing":
                return False
            index = self._store["batches"].index(batch)
            self._store["batches"].pop(index)
            self._rebuild_task_index_locked()
            try:
                self._save_locked()
            except Exception:
                self._store["batches"].insert(index, batch)
                self._rebuild_task_index_locked()
                raise
            return True

    def reserve(
        self,
        batch_id: Any,
        task_id: Any,
        *,
        row_identity: Any = "",
        line_no: Any = 0,
    ) -> None:
        now = int(self.now())
        with self._lock:
            batch = self._batch_locked(batch_id)
            member = self._member_locked(batch, task_id)
            member["reserved_at"] = member.get("reserved_at") or now
            member["status"] = "queued"
            fingerprint = _row_fingerprint(row_identity)
            if fingerprint:
                member["row_id"] = fingerprint
            if _safe_int(line_no) > 0:
                member["line_no"] = _safe_int(line_no)
            batch["updated_at"] = now
            self._refresh_counts_locked(batch)
            self._save_locked()

    def mark_started(self, task_id: Any) -> None:
        now = int(self.now())
        with self._lock:
            batch = self._batch_for_task_locked(task_id)
            member = self._member_locked(batch, task_id)
            member["started_at"] = member.get("started_at") or now
            if not member.get("terminal_at"):
                member["status"] = "running"
            batch["updated_at"] = now
            self._refresh_counts_locked(batch)
            self._save_locked()

    def observe_task(self, task_id: Any, status: Any) -> None:
        normalized = _clean(status, 64).lower()
        if not normalized:
            return
        now = int(self.now())
        with self._lock:
            batch = self._batch_for_task_locked(task_id)
            member = self._member_locked(batch, task_id)
            member["status"] = normalized
            if normalized not in {"planned", "queued"}:
                member["started_at"] = member.get("started_at") or now
            if normalized in _TERMINAL_STATUSES:
                member["terminal_at"] = member.get("terminal_at") or now
            batch["updated_at"] = now
            self._refresh_counts_locked(batch)
            self._save_locked()

    def mark_persisted(self, batch_id: Any, task_id: Any, status: Any) -> None:
        normalized = _clean(status, 64).lower() or "failed"
        now = int(self.now())
        with self._lock:
            batch = self._batch_locked(batch_id)
            member = self._member_locked(batch, task_id)
            member["status"] = normalized
            member["terminal_at"] = member.get("terminal_at") or now
            member["persisted_at"] = member.get("persisted_at") or now
            batch["updated_at"] = now
            self._refresh_counts_locked(batch)
            self._save_locked()

    @staticmethod
    def _document_identity(raw: Mapping[str, Any]) -> tuple[str, str, str]:
        wrapped = raw.get("result") if isinstance(raw.get("result"), Mapping) else {}
        return (
            _safe_id(raw.get("batch_id") or wrapped.get("batch_id")),
            _safe_id(raw.get("task_id") or wrapped.get("task_id")),
            _clean(raw.get("status") or wrapped.get("status"), 64).lower(),
        )

    def _discover_results_locked(self, batch: dict[str, Any]) -> None:
        results_dir = self._results_dir(batch)
        if not results_dir.exists():
            return
        batch_id = batch["batch_id"]
        now = int(self.now())
        for path in results_dir.glob("*.json"):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(raw, Mapping):
                continue
            found_batch, task_id, status = self._document_identity(raw)
            if found_batch != batch_id or not task_id:
                continue
            try:
                member = self._member_locked(batch, task_id)
            except KeyError:
                continue
            member["status"] = status or str(member.get("status") or "failed")
            member["terminal_at"] = member.get("terminal_at") or now
            member["persisted_at"] = member.get("persisted_at") or now

    def _write_synthetic_result_locked(
        self,
        batch: Mapping[str, Any],
        member: dict[str, Any],
        *,
        reason: str,
    ) -> None:
        results_dir = self._results_dir(batch)
        task_id = member["task_id"]
        prior_status = _clean(member.get("status"), 64).lower()
        unresolved = prior_status not in _TERMINAL_STATUSES
        if unresolved or prior_status == "success":
            status = "failed"
            code = "batch_member_missing_terminal" if unresolved else "batch_result_missing"
            cause = (
                "任务未产生终态，已由批次清单补记失败"
                if unresolved
                else "任务报告成功但结果文件缺失，已由批次清单补记失败"
            )
            failure = _failure(code, cause)
            error = failure["public_message"]
        elif prior_status in _STOPPED_STATUSES:
            status = "stopped"
            failure = None
            error = "任务已停止，批次清单已补写终态"
        else:
            status = prior_status or "failed"
            failure = _failure("batch_result_missing", "任务终态存在但结果文件缺失，已补写脱敏记录")
            error = failure["public_message"]
        payload: dict[str, Any] = {
            "task_id": task_id,
            "ordinal": max(_safe_int(member.get("ordinal")), 0),
            "batch_id": batch["batch_id"],
            "batch_started_at": max(_safe_int(batch.get("batch_started_at")), 0),
            "run_mode": _clean(batch.get("mode"), 32) or "register",
            "status": status,
            "error": error,
            "result": {
                "task_id": task_id,
                "batch_id": batch["batch_id"],
                "batch_started_at": max(_safe_int(batch.get("batch_started_at")), 0),
                "reconciled_by_batch_manifest": True,
                "reconcile_reason": _clean(reason, 80) or "batch_finished",
            },
        }
        if failure is not None:
            payload["failure"] = failure
            payload["technical_error"] = failure["technical_summary"]
            payload["result"]["failure"] = failure
        _atomic_write_json(results_dir / f"{task_id}_batch_recovery.json", payload)
        now = int(self.now())
        member["status"] = status
        member["terminal_at"] = member.get("terminal_at") or now
        member["persisted_at"] = now
        member["reconciled_missing"] = True

    def finalize(
        self,
        batch_id: Any,
        *,
        tasks: Mapping[str, Any] | Iterable[Mapping[str, Any]] | None = None,
        reason: str = "batch_finished",
    ) -> dict[str, Any]:
        now = int(self.now())
        with self._lock:
            batch = self._batch_locked(batch_id)
            if _clean(batch.get("status"), 32).lower() == "complete":
                return self._public(batch, include_members=True)
            if isinstance(tasks, Mapping):
                rows = [
                    {**dict(value), "task_id": task_id}
                    for task_id, value in tasks.items()
                    if isinstance(value, Mapping)
                ]
            else:
                rows = [dict(value) for value in tasks or [] if isinstance(value, Mapping)]
            for row in rows:
                task_id = _safe_id(row.get("task_id"))
                status = _clean(row.get("status"), 64).lower()
                if not task_id or not status:
                    continue
                try:
                    member = self._member_locked(batch, task_id)
                except KeyError:
                    continue
                member["status"] = status
                if status not in {"planned", "queued"}:
                    member["started_at"] = member.get("started_at") or now
                if status in _TERMINAL_STATUSES:
                    member["terminal_at"] = member.get("terminal_at") or now
            self._discover_results_locked(batch)
            for member in batch.get("members") or []:
                if isinstance(member, dict) and not member.get("persisted_at"):
                    self._write_synthetic_result_locked(batch, member, reason=reason)
            batch["status"] = "complete"
            batch["completed_at"] = batch.get("completed_at") or now
            batch["updated_at"] = now
            self._refresh_counts_locked(batch)
            self._save_locked()
            public = self._public(batch, include_members=True)
        missing = public["counts"]["missing"]
        level = "warn" if missing else "success"
        self._emit(
            f"[运行批次对账/run_batch_manifest] 批次 {public['batch_id']} "
            f"已对账 {public['counts']['persisted']}/{public['counts']['target']}，"
            f"补写缺失 {missing} 项",
            level,
        )
        return public

    def recover(self) -> None:
        with self._lock:
            pending = [
                (
                    batch["batch_id"],
                    _clean(batch.get("mode"), 32).lower(),
                    _clean(batch.get("status"), 32).lower(),
                    copy.deepcopy(batch.get("members") or []),
                    str(self._local_path(batch, "pool_path", "mailbox_pool.txt")),
                    str(self._local_path(batch, "state_path", "mailbox_pool_state.json")),
                )
                for batch in self._store["batches"]
                if _clean(batch.get("status"), 32).lower() != "complete"
            ]
        for batch_id, mode, status, members, pool_path, state_path in pending:
            try:
                if mode != "relogin" and callable(self.lease_releaser):
                    release_options = {}
                    if _accepts_keyword(self.lease_releaser, "pool_path"):
                        release_options["pool_path"] = pool_path
                    if _accepts_keyword(self.lease_releaser, "state_path"):
                        release_options["state_path"] = state_path
                    released = self.lease_releaser(batch_id, members, **release_options)
                    if isinstance(released, Mapping):
                        released_count = max(_safe_int(released.get("released")), 0)
                        mismatch_count = max(
                            _safe_int(released.get("ownership_mismatch")),
                            0,
                        )
                        self._emit(
                            f"[运行批次对账/run_batch_manifest] 批次 {batch_id} "
                            f"重启归还租约 {released_count} 项，所有权已变化 {mismatch_count} 项",
                            "warn" if mismatch_count else "info",
                        )
                if status == "preparing":
                    self.rollback_prepared(batch_id)
                else:
                    self.finalize(batch_id, reason="process_restart")
            except Exception as exc:
                self._emit(
                    f"[运行批次对账/run_batch_manifest] 批次 {batch_id} 重启恢复失败："
                    f"{type(exc).__name__}",
                    "error",
                )

    @staticmethod
    def _public(batch: Mapping[str, Any], *, include_members: bool) -> dict[str, Any]:
        result = {
            "batch_id": _safe_id(batch.get("batch_id")),
            "batch_started_at": max(_safe_int(batch.get("batch_started_at")), 0),
            "run_mode": _clean(batch.get("mode"), 32) or "register",
            "target": max(_safe_int(batch.get("target")), 0),
            "status": _clean(batch.get("status"), 32) or "active",
            "counts": copy.deepcopy(batch.get("counts") or {}),
            "created_at": max(_safe_int(batch.get("created_at")), 0),
            "updated_at": max(_safe_int(batch.get("updated_at")), 0),
            "completed_at": max(_safe_int(batch.get("completed_at")), 0),
        }
        if include_members:
            result["members"] = [
                {
                    "task_id": _safe_id(member.get("task_id")),
                    "ordinal": max(_safe_int(member.get("ordinal")), 0),
                    "status": _clean(member.get("status"), 64),
                    "reserved": bool(member.get("reserved_at")),
                    "started": bool(member.get("started_at")),
                    "terminal": bool(member.get("terminal_at")),
                    "persisted": bool(member.get("persisted_at")),
                    "reconciled_missing": bool(member.get("reconciled_missing")),
                }
                for member in batch.get("members") or []
                if isinstance(member, Mapping)
            ]
        return result

    def get(self, batch_id: Any, *, include_members: bool = True) -> dict[str, Any]:
        with self._lock:
            return self._public(self._batch_locked(batch_id), include_members=include_members)

    def records(self, *, limit: int = 100, include_members: bool = False) -> list[dict[str, Any]]:
        maximum = min(max(_safe_int(limit, 100), 1), 500)
        with self._lock:
            batches = sorted(
                self._store["batches"],
                key=lambda value: (
                    _safe_int(value.get("batch_started_at")),
                    _safe_int(value.get("created_at")),
                ),
                reverse=True,
            )[:maximum]
            return [self._public(batch, include_members=include_members) for batch in batches]

    def latest_row_bindings(self, *, failed_only: bool = False) -> list[dict[str, Any]]:
        """Return private stable row bindings for mailbox batch filters."""
        with self._lock:
            eligible = [
                batch
                for batch in self._store["batches"]
                if _clean(batch.get("status"), 32).lower() != "preparing"
            ]
            if not eligible:
                return []
            batch = max(
                eligible,
                key=lambda value: (
                    _safe_int(value.get("batch_started_at")),
                    _safe_int(value.get("created_at")),
                ),
            )
            rows = []
            for member in batch.get("members") or []:
                if not isinstance(member, Mapping):
                    continue
                status = _clean(member.get("status"), 64).lower()
                if failed_only and (status == "success" or status in _STOPPED_STATUSES):
                    continue
                row_id = _row_fingerprint(member.get("row_id"))
                if row_id:
                    rows.append(
                        {
                            "row_id": row_id,
                            "line_no": max(_safe_int(member.get("line_no")), 0),
                            "task_id": _safe_id(member.get("task_id")),
                            "status": status,
                            "batch_id": _safe_id(batch.get("batch_id")),
                            "batch_started_at": max(
                                _safe_int(batch.get("batch_started_at")),
                                0,
                            ),
                        }
                    )
            return rows


__all__ = ["RunBatchManifestStore", "reconciliation_failure"]
