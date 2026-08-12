"""Incremental, credential-private index for persisted mailbox results."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from threading import RLock
import time
from typing import Any, Mapping

try:
    from .mailbox_row_formats import email_from_row
    from .mailbox_sub2_results import sub2_account_id_from_result
    from .openai_quota_runtime import OpenAIQuotaError, credentials_from_result
except ImportError:  # Loaded as top-level runtime overrides by the Mac launcher.
    from mailbox_row_formats import email_from_row
    from mailbox_sub2_results import sub2_account_id_from_result
    from openai_quota_runtime import OpenAIQuotaError, credentials_from_result


RESULT_INDEX_ROLLBACK_SECONDS = 5 * 60


@dataclass(frozen=True)
class MailboxResultSnapshot:
    latest_results: dict[str, dict[str, Any]]
    latest_sub2_accounts: dict[str, dict[str, Any]]
    metrics: dict[str, Any]


@dataclass(frozen=True)
class _CachedResult:
    signature: tuple[int, int, int, int]
    document: dict[str, Any]


def _read_document(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _created_at(document: Mapping[str, Any], fallback: float) -> int:
    try:
        return int(document.get("created_at") or document.get("updated_at") or fallback)
    except (TypeError, ValueError):
        return int(fallback)


def _build_indexes(entries: Mapping[Path, _CachedResult]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    latest_results: dict[str, dict[str, Any]] = {}
    latest_sub2: dict[str, dict[str, Any]] = {}
    for path in sorted(entries):
        cached = entries[path]
        data = dict(cached.document)
        email = email_from_row(data.get("email") or data.get("source_row") or "")
        if not email:
            continue
        created = _created_at(data, cached.signature[0] / 1_000_000_000)
        previous = latest_results.get(email)
        if previous is None or created >= int(previous.get("_created") or 0):
            data["_created"] = created
            data["_result_file"] = str(path.resolve())
            latest_results[email] = data

        if str(data.get("status") or "").lower() not in {"success", "ok", "uploaded"}:
            continue
        account_id = sub2_account_id_from_result(data)
        if not account_id:
            continue
        previous_account = latest_sub2.get(email)
        if previous_account is not None and created < int(previous_account.get("created_at") or 0):
            continue
        try:
            openai_account_id = credentials_from_result(data).account_id
        except OpenAIQuotaError:
            openai_account_id = ""
        latest_sub2[email] = {
            "account_id": account_id,
            "openai_account_id": openai_account_id,
            "created_at": created,
            "result_file": str(path.resolve()),
        }
    return latest_results, latest_sub2


class MailboxResultIndex:
    """Reuse unchanged JSON documents while rebuilding public indexes each read."""

    def __init__(self, *, now_fn=time.time, rollback_seconds: float = RESULT_INDEX_ROLLBACK_SECONDS) -> None:
        self.now_fn = now_fn
        self.rollback_seconds = max(1.0, float(rollback_seconds))
        self._lock = RLock()
        self._root: Path | None = None
        self._entries: dict[Path, _CachedResult] = {}
        self._rollback_until = 0.0
        self._rollback_reason = ""

    @staticmethod
    def _signature(path: Path) -> tuple[int, int, int, int]:
        stat = path.stat()
        return (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino)

    def _full_scan(self, root: Path) -> tuple[dict[Path, _CachedResult], int]:
        entries: dict[Path, _CachedResult] = {}
        reads = 0
        if not root.exists():
            return entries, reads
        for path in sorted(root.glob("*.json")):
            try:
                signature = self._signature(path)
            except OSError:
                continue
            entries[path] = _CachedResult(signature, _read_document(path))
            reads += 1
        return entries, reads

    def snapshot(self, results_dir: str | Path, *, enabled: bool = True) -> MailboxResultSnapshot:
        root = Path(results_dir).resolve()
        started = time.monotonic()
        with self._lock:
            now = float(self.now_fn())
            rollback_active = now < self._rollback_until
            cache_enabled = bool(enabled) and not rollback_active
            hits = 0
            reads = 0
            scanned = 0
            if not cache_enabled:
                entries, reads = self._full_scan(root)
                scanned = len(entries)
            else:
                try:
                    paths = sorted(root.glob("*.json")) if root.exists() else []
                    scanned = len(paths)
                    entries = {}
                    if self._root != root:
                        self._entries = {}
                        self._root = root
                    for path in paths:
                        signature = self._signature(path)
                        cached = self._entries.get(path)
                        if cached is not None and cached.signature == signature:
                            entries[path] = cached
                            hits += 1
                        else:
                            entries[path] = _CachedResult(signature, _read_document(path))
                            reads += 1
                    self._entries = entries
                    self._rollback_reason = ""
                except (OSError, RuntimeError):
                    self._rollback_until = now + self.rollback_seconds
                    self._rollback_reason = "result_directory_scan_failed"
                    rollback_active = True
                    entries, reads = self._full_scan(root)
                    scanned = len(entries)
                    hits = 0
            latest_results, latest_sub2 = _build_indexes(entries)
            metrics = {
                "enabled": bool(enabled),
                "cache_active": cache_enabled and not rollback_active,
                "rollback_active": rollback_active,
                "rollback_reason": self._rollback_reason if rollback_active else "",
                "files_scanned": scanned,
                "cache_hits": hits,
                "files_read": reads,
                "elapsed_ms": round(max(0.0, time.monotonic() - started) * 1000, 3),
            }
            return MailboxResultSnapshot(latest_results, latest_sub2, metrics)


__all__ = ["MailboxResultIndex", "MailboxResultSnapshot", "RESULT_INDEX_ROLLBACK_SECONDS"]
