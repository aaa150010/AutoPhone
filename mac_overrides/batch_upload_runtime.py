"""Durable end-of-run upload coordination for optional Pixel and NV targets."""

from __future__ import annotations

from collections.abc import Callable, Mapping
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
_QUEUE_ACCEPTED_STATUSES = frozenset(
    {"accepted", "pending", "queued", "queueing", "processing"}
)
_QUEUE_SKIPPED_STATUSES = frozenset({
    "complete",
    "completed",
    "disabled",
    "duplicate",
    "empty",
    "exists",
    "skipped",
    "success",
})


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _nonnegative_int(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _safe_id(value: Any) -> str:
    text = _clean(value)
    if _SAFE_ID_RE.fullmatch(text):
        return text
    if not text:
        return ""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _safe_error(value: Any) -> str:
    text = str(value or "")[:2048]
    text = re.sub(
        r"(?i)(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|authorization|"
        r"api[_ -]?key|sms[_ -]?key|password|passwd|secret|cookie|session)"
        r"(?:\\?[\"'])?\s*[:=]\s*(?:\\?[\"'])?[^\s,;}\]\"']+",
        lambda match: f"{match.group(1)}=********",
        text,
    )
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer ********", text)
    text = re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1********@", text)
    text = re.sub(r"(?i)(https?://[^?\s,;]+)\?[^\s,;]+", r"\1?[redacted]", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", r"***@\1", text)
    text = re.sub(r"(?<![A-Za-z0-9])\+?\d{10,15}(?![A-Za-z0-9])", "********", text)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:500]


def _accepts_keyword(callable_value: Callable[..., Any], keyword: str) -> bool:
    try:
        parameters = inspect.signature(callable_value).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == keyword or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _queue_record_source_count(record: Mapping[str, Any]) -> int:
    count = _nonnegative_int(record.get("source_count"))
    for key in ("task_ids", "result_files"):
        values = record.get(key)
        if isinstance(values, (list, tuple)):
            count = max(count, len(values))
    if not count and any(_clean(record.get(key)) for key in ("task_id", "result_file")):
        count = 1
    return count


def _queue_counts(result: Any, source_count: int) -> tuple[int, int, int]:
    total = _nonnegative_int(source_count)
    if isinstance(result, Mapping) and any(
        key in result for key in ("accepted", "skipped", "failed")
    ):
        failed = min(_nonnegative_int(result.get("failed")), total)
        skipped = min(_nonnegative_int(result.get("skipped")), total - failed)
        accepted = min(_nonnegative_int(result.get("accepted")), total - failed - skipped)
        failed += total - accepted - skipped - failed
        return accepted, skipped, failed
    if isinstance(result, list):
        structured = any(
            isinstance(record, Mapping)
            and any(key in record for key in ("status", "source_count", "task_ids", "result_files"))
            for record in result
        )
        if structured:
            raw_accepted = 0
            raw_skipped = 0
            raw_failed = 0
            for record in result:
                if not isinstance(record, Mapping):
                    continue
                count = _queue_record_source_count(record)
                status = _clean(record.get("status")).lower()
                if status in _QUEUE_ACCEPTED_STATUSES:
                    raw_accepted += count
                elif status in _QUEUE_SKIPPED_STATUSES:
                    raw_skipped += count
                elif status == "partial":
                    partial_accepted = min(_nonnegative_int(record.get("accepted")), count)
                    raw_accepted += partial_accepted
                    raw_failed += count - partial_accepted
                else:
                    raw_failed += count
            failed = min(raw_failed, total)
            skipped = min(raw_skipped, total - failed)
            accepted = min(raw_accepted, total - failed - skipped)
            failed += total - accepted - skipped - failed
            return accepted, skipped, failed
    if result:
        return total, 0, 0
    return 0, total, 0


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


class BatchUploadCoordinator:
    def __init__(
        self,
        data_dir: str | Path,
        *,
        pixel_queue: Any = None,
        nv_queue: Any = None,
        manifest_path: str | Path | None = None,
        now: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
        log_fn: Callable[[str, str], None] | None = None,
        recover_pending: bool = True,
    ) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.manifest_path = Path(manifest_path).resolve() if manifest_path else self.data_dir / "batch_upload_manifests.json"
        self.pixel_queue = pixel_queue
        self.nv_queue = nv_queue
        self.now = now
        self.sleeper = sleeper
        self.log_fn = log_fn
        self._lock = threading.RLock()
        self._watchers: dict[str, threading.Thread] = {}
        self._store = self._load()
        if recover_pending:
            self.recover()

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {"version": MANIFEST_VERSION, "batches": []}
        batches = value.get("batches") if isinstance(value, Mapping) else None
        return {
            "version": MANIFEST_VERSION,
            "batches": [copy.deepcopy(item) for item in batches or [] if isinstance(item, Mapping)],
        }

    def _save_locked(self) -> None:
        _atomic_write_json(self.manifest_path, self._store)

    def _manifest_locked(self, batch_id: str) -> dict[str, Any]:
        for item in self._store["batches"]:
            if item.get("batch_id") == batch_id:
                return item
        raise KeyError(batch_id)

    def _emit(self, message: str, level: str = "info") -> None:
        if self.log_fn is None:
            return
        try:
            self.log_fn(_safe_error(message), level)
        except Exception:
            pass

    def _results_dir(self, value: Any) -> Path:
        raw = _clean(value)
        path = Path(raw) if raw else self.data_dir / "results"
        if not path.is_absolute():
            path = self.data_dir / path
        resolved = path.resolve()
        try:
            resolved.relative_to(self.data_dir)
        except ValueError:
            raise ValueError("批次结果目录必须位于本地 data 目录") from None
        return resolved

    def begin(self, importer: Any, settings: Mapping[str, Any]) -> dict[str, Any] | None:
        targets = settings.get("_gptphone_upload_targets")
        targets = targets if isinstance(targets, Mapping) else {}
        selected = {"pixel": bool(targets.get("pixel")), "nv": bool(targets.get("nv"))}
        if _clean(settings.get("run_mode")).lower() == "relogin" or not any(selected.values()):
            return None
        batch_id = _safe_id(settings.get("batch_id"))
        if not batch_id:
            raise ValueError("批次上传缺少批次 ID")
        now = int(self.now())
        with self._lock:
            try:
                manifest = self._manifest_locked(batch_id)
            except KeyError:
                manifest = {
                    "batch_id": batch_id,
                    "batch_started_at": max(int(settings.get("batch_started_at") or 0), 0),
                    "results_dir": self._results_dir(settings.get("results_dir")).relative_to(self.data_dir).as_posix(),
                    "targets": selected,
                    "platforms": {
                        name: {
                            "status": "waiting" if enabled else "disabled",
                            "error": "",
                            "upload_attempt_id": "",
                            "accepted": 0,
                            "skipped": 0,
                            "failed": 0,
                            "attempt_history": [],
                        }
                        for name, enabled in selected.items()
                    },
                    "status": "waiting",
                    "source_count": 0,
                    "task_ids": [],
                    "result_files": [],
                    "created_at": now,
                    "updated_at": now,
                }
                self._store["batches"].append(manifest)
                self._save_locked()
            public = self._public(manifest)
            existing = self._watchers.get(batch_id)
            if existing is None or not existing.is_alive():
                watcher = threading.Thread(
                    target=self._watch,
                    args=(batch_id, importer, dict(settings)),
                    name=f"batch-upload-{batch_id[:24]}",
                    daemon=True,
                )
                self._watchers[batch_id] = watcher
                watcher.start()
        return public

    def _watch(self, batch_id: str, importer: Any, settings: Mapping[str, Any]) -> None:
        try:
            while True:
                try:
                    snapshot = importer.status(dict(settings))
                except Exception:
                    self.sleeper(1.0)
                    continue
                running = snapshot.get("running") if isinstance(snapshot, Mapping) else None
                if running is False:
                    break
                self.sleeper(1.0)
            self.finalize(batch_id)
        finally:
            with self._lock:
                self._watchers.pop(batch_id, None)

    def _discover(self, manifest: Mapping[str, Any]) -> list[dict[str, str]]:
        results_dir = self._results_dir(manifest.get("results_dir"))
        batch_id = _clean(manifest.get("batch_id"))
        sources: list[dict[str, str]] = []
        if not results_dir.exists():
            return sources
        for path in sorted(results_dir.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(raw, Mapping):
                continue
            wrapped = raw.get("result") if isinstance(raw.get("result"), Mapping) else {}
            if _clean(raw.get("batch_id") or wrapped.get("batch_id")) != batch_id:
                continue
            if _clean(raw.get("status")).lower() != "success":
                continue
            task_id = _safe_id(raw.get("task_id") or wrapped.get("task_id"))
            if not task_id:
                continue
            try:
                relative = path.resolve().relative_to(self.data_dir).as_posix()
            except ValueError:
                continue
            sources.append({"task_id": task_id, "result_file": relative})
        return sources

    def finalize(self, batch_id: Any) -> dict[str, Any]:
        identifier = _safe_id(batch_id)
        with self._lock:
            manifest = self._manifest_locked(identifier)
            sources = self._discover(manifest)
            manifest["task_ids"] = [item["task_id"] for item in sources]
            manifest["result_files"] = [item["result_file"] for item in sources]
            manifest["source_count"] = len(sources)
            manifest["status"] = "collected"
            manifest["updated_at"] = int(self.now())
            self._save_locked()
        if not sources:
            with self._lock:
                manifest = self._manifest_locked(identifier)
                for name, selected in manifest.get("targets", {}).items():
                    if selected:
                        manifest["platforms"][name].update(status="empty", error="")
                manifest["status"] = "complete"
                manifest["updated_at"] = int(self.now())
                self._save_locked()
                return self._public(manifest)

        self._queue_platform(identifier, "pixel", sources, attempt_kind="initial")
        self._queue_platform(identifier, "nv", sources, attempt_kind="initial")
        with self._lock:
            manifest = self._manifest_locked(identifier)
            selected_states = [
                value.get("status")
                for name, value in manifest.get("platforms", {}).items()
                if manifest.get("targets", {}).get(name)
            ]
            manifest["status"] = "complete" if all(state in {"queued", "empty"} for state in selected_states) else "queue_failed"
            manifest["updated_at"] = int(self.now())
            self._save_locked()
            return self._public(manifest)

    def _queue_platform(
        self,
        batch_id: str,
        platform: str,
        sources: list[dict[str, str]],
        *,
        attempt_kind: str,
    ) -> None:
        upload_attempt_id = f"upload-{uuid.uuid4().hex}"
        attempted_at = int(self.now())
        with self._lock:
            manifest = self._manifest_locked(batch_id)
            if not manifest.get("targets", {}).get(platform):
                return
            state = manifest.get("platforms", {}).get(platform, {})
            if state.get("status") in {"queued", "empty", "queueing"}:
                return
            history = state.setdefault("attempt_history", [])
            if not isinstance(history, list):
                history = []
                state["attempt_history"] = history
            history.append({
                "upload_attempt_id": upload_attempt_id,
                "kind": "retry" if attempt_kind == "retry" else "initial",
                "status": "queueing",
                "accepted": 0,
                "skipped": 0,
                "failed": 0,
                "error": "",
                "started_at": attempted_at,
                "completed_at": 0,
            })
            state.update(
                status="queueing",
                error="",
                upload_attempt_id=upload_attempt_id,
                accepted=0,
                skipped=0,
                failed=0,
            )
            manifest["updated_at"] = attempted_at
            self._save_locked()
            started_at = manifest.get("batch_started_at")
        queue_service = self.pixel_queue if platform == "pixel" else self.nv_queue
        try:
            if queue_service is None:
                raise RuntimeError(f"{platform.upper()} 上传服务未启用")
            enqueue_batch = queue_service.enqueue_batch
            kwargs: dict[str, Any] = {}
            if platform == "nv":
                kwargs["batch_started_at"] = started_at
            if _accepts_keyword(enqueue_batch, "upload_attempt_id"):
                kwargs["upload_attempt_id"] = upload_attempt_id
            records = enqueue_batch(batch_id, sources, **kwargs)
            accepted, skipped, failed = _queue_counts(records, len(sources))
            status = "queue_failed" if failed else "queued" if accepted else "empty"
            error = ""
            level = "error" if failed else "info"
        except Exception as exc:
            status = "queue_failed"
            error = _safe_error(exc) or f"{platform.upper()} 上传入队失败：未返回错误详情"
            accepted, skipped, failed = 0, 0, len(sources)
            level = "error"
        completed_at = int(self.now())
        with self._lock:
            manifest = self._manifest_locked(batch_id)
            state = manifest["platforms"].setdefault(platform, {})
            state.update(
                status=status,
                error=error,
                upload_attempt_id=upload_attempt_id,
                accepted=accepted,
                skipped=skipped,
                failed=failed,
            )
            history = state.setdefault("attempt_history", [])
            for attempt in reversed(history if isinstance(history, list) else []):
                if attempt.get("upload_attempt_id") == upload_attempt_id:
                    attempt.update(
                        status=status,
                        accepted=accepted,
                        skipped=skipped,
                        failed=failed,
                        error=error,
                        completed_at=completed_at,
                    )
                    break
            manifest["updated_at"] = completed_at
            self._save_locked()
        message = (
            "[批次上传入队/batch_upload_enqueued] "
            f"批次 {batch_id}，{platform.upper()} 上传尝试 {upload_attempt_id}："
            f"本地队列 accepted={accepted}，skipped={skipped}，failed={failed}"
        )
        if error:
            message += f"；{error}；注册结果不受影响"
        elif accepted:
            message += "；仅表示已入队，远端结果尚未确认"
        self._emit(message, level)

    @staticmethod
    def _stored_sources(manifest: Mapping[str, Any]) -> list[dict[str, str]]:
        task_ids = manifest.get("task_ids")
        result_files = manifest.get("result_files")
        if not isinstance(task_ids, list) or not isinstance(result_files, list):
            raise ValueError("批次上传清单缺少已持久化的成功账号来源")
        if not task_ids or len(task_ids) != len(result_files):
            raise ValueError("批次上传清单中的成功账号来源不完整")
        sources = []
        for task_id, result_file in zip(task_ids, result_files, strict=True):
            safe_task_id = _safe_id(task_id)
            safe_result_file = _clean(result_file)
            if not safe_task_id or not safe_result_file:
                raise ValueError("批次上传清单中的成功账号来源无效")
            sources.append({"task_id": safe_task_id, "result_file": safe_result_file})
        return sources

    def retry(self, batch_id: Any, platform: Any) -> dict[str, Any]:
        """Retry one failed platform from the manifest's persisted source list."""
        identifier = _safe_id(batch_id)
        target = _clean(platform).lower()
        if target not in {"pixel", "nv"}:
            raise ValueError("批次上传重试平台必须是 Pixel 或 NV")
        with self._lock:
            manifest = self._manifest_locked(identifier)
            if not manifest.get("targets", {}).get(target):
                raise ValueError(f"该批次未选择 {target.upper()} 上传")
            state = manifest.get("platforms", {}).get(target, {})
            if state.get("status") != "queue_failed":
                raise ValueError(f"该批次的 {target.upper()} 上传当前不可重试")
            sources = self._stored_sources(manifest)
            state.update(status="waiting", error="")
            manifest["status"] = "collected"
            manifest["updated_at"] = int(self.now())
            self._save_locked()
        self._queue_platform(identifier, target, sources, attempt_kind="retry")
        with self._lock:
            manifest = self._manifest_locked(identifier)
            selected_states = [
                value.get("status")
                for name, value in manifest.get("platforms", {}).items()
                if manifest.get("targets", {}).get(name)
            ]
            manifest["status"] = (
                "complete"
                if all(state in {"queued", "empty"} for state in selected_states)
                else "queue_failed"
                if any(state == "queue_failed" for state in selected_states)
                else "collected"
            )
            manifest["updated_at"] = int(self.now())
            self._save_locked()
            return self._public(manifest)

    def recover(self) -> None:
        with self._lock:
            changed = False
            for item in self._store["batches"]:
                for state in (item.get("platforms") or {}).values():
                    if isinstance(state, dict) and state.get("status") == "queueing":
                        attempt_id = _safe_id(state.get("upload_attempt_id"))
                        history = state.get("attempt_history")
                        if isinstance(history, list):
                            for attempt in reversed(history):
                                if (
                                    isinstance(attempt, dict)
                                    and _safe_id(attempt.get("upload_attempt_id")) == attempt_id
                                    and attempt.get("status") == "queueing"
                                ):
                                    attempt.update(
                                        status="interrupted",
                                        error="进程中断，未确认本次入队结果",
                                        completed_at=int(self.now()),
                                    )
                                    break
                        state["status"] = "waiting"
                        changed = True
            if changed:
                self._save_locked()
            pending = [
                _clean(item.get("batch_id"))
                for item in self._store["batches"]
                if _clean(item.get("status")) not in {"complete"}
            ]
        for batch_id in pending:
            try:
                self.finalize(batch_id)
            except Exception as exc:
                self._emit(f"批次 {batch_id} 上传清单恢复失败：{_safe_error(exc) or '未返回错误详情'}", "error")

    @staticmethod
    def _public(manifest: Mapping[str, Any]) -> dict[str, Any]:
        platforms = {}
        for name, value in (manifest.get("platforms") or {}).items():
            if not isinstance(value, Mapping):
                continue
            platforms[name] = {
                "status": _clean(value.get("status")) or "waiting",
                "error": _safe_error(value.get("error")),
                "upload_attempt_id": _safe_id(value.get("upload_attempt_id")),
                "accepted": _nonnegative_int(value.get("accepted")),
                "skipped": _nonnegative_int(value.get("skipped")),
                "failed": _nonnegative_int(value.get("failed")),
                "attempt_history": [
                    {
                        "upload_attempt_id": _safe_id(attempt.get("upload_attempt_id")),
                        "kind": "retry" if attempt.get("kind") == "retry" else "initial",
                        "status": _clean(attempt.get("status")) or "waiting",
                        "accepted": _nonnegative_int(attempt.get("accepted")),
                        "skipped": _nonnegative_int(attempt.get("skipped")),
                        "failed": _nonnegative_int(attempt.get("failed")),
                        "error": _safe_error(attempt.get("error")),
                        "started_at": _nonnegative_int(attempt.get("started_at")),
                        "completed_at": _nonnegative_int(attempt.get("completed_at")),
                    }
                    for attempt in value.get("attempt_history") or []
                    if isinstance(attempt, Mapping)
                ],
            }
        return {
            "batch_id": _safe_id(manifest.get("batch_id")),
            "batch_started_at": _nonnegative_int(manifest.get("batch_started_at")),
            "targets": {
                "pixel": bool((manifest.get("targets") or {}).get("pixel")),
                "nv": bool((manifest.get("targets") or {}).get("nv")),
            },
            "platforms": platforms,
            "status": _clean(manifest.get("status")) or "waiting",
            "source_count": _nonnegative_int(manifest.get("source_count")),
            "created_at": _nonnegative_int(manifest.get("created_at")),
            "updated_at": _nonnegative_int(manifest.get("updated_at")),
        }

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public(item) for item in reversed(self._store["batches"])]


__all__ = ["BatchUploadCoordinator"]
