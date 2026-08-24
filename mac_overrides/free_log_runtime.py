"""Persistent, credential-redacted logs for the isolated Free runtime."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import re
from typing import Any, Mapping

try:
    from .free_failure_runtime import sanitize_failure_text, sanitize_log_message, sanitize_safe_page
    from .free_register_common import FREE_STAGE_LABELS, atomic_write, fingerprint, safe_log_message
except ImportError:
    from free_failure_runtime import sanitize_failure_text, sanitize_log_message, sanitize_safe_page  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FREE_STAGE_LABELS,
        atomic_write,
        fingerprint,
        safe_log_message,
    )


class FreeLogStore:
    """Persist one stable, credential-safe shape for every Free log row.

    The log file predates the structured diagnostics fields, so reads also
    normalize and migrate legacy rows.  This keeps the public API predictable
    after an upgrade without exposing arbitrary legacy keys that may contain
    credentials.
    """

    REQUIRED_FIELDS = (
        "time", "level", "task_id", "node_code", "node_label", "attempt",
        "duration_ms", "page_type", "safe_page", "http_status", "provider_code",
        "outcome", "diagnostic", "action_hint", "result",
    )
    _KNOWN_FIELDS = frozenset({
        "time", "level", "message", "task_id", "stage", "stage_label",
        "node_code", "node_label", "error_code", "provider_code", "page",
        "safe_page", "page_type", "content_type", "session_rebuilds",
        "http_status", "attempt", "duration_ms", "outcome", "diagnostic",
        "technical_summary", "action_hint", "retryable", "result",
    })

    def __init__(self, data_dir: str | Path, *, limit: int = 5000, task_limit: int = 5000) -> None:
        self.path = Path(data_dir).expanduser().resolve() / "logs.json"
        self.task_dir = self.path.parent / "task_logs"
        self.limit = max(50, int(limit))
        self.task_limit = max(100, int(task_limit))
        self._lock = threading.RLock()

    @staticmethod
    def _number(value: Any, *, maximum: int = 1_000_000) -> int | None:
        if isinstance(value, bool) or value in (None, ""):
            return None
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            return None
        return max(0, min(maximum, number))

    @staticmethod
    def _safe_time(value: Any) -> str:
        text = str(value or "").strip()
        if re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
            text,
        ):
            return text
        return ""

    @classmethod
    def _normalize_row(cls, value: Mapping[str, Any]) -> dict[str, Any]:
        raw = dict(value)
        message = sanitize_log_message(raw.get("message"), 800)
        level = sanitize_failure_text(raw.get("level"), 32) or "info"
        # Generated task IDs intentionally contain numeric shards.  Keep the
        # identifier joinable while allowing only identifier characters, so a
        # malicious legacy value cannot carry a URL or credential.
        task_id = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(raw.get("task_id") or "")).strip("_.:-")[:160]
        if task_id and not task_id.startswith("free-"):
            task_id = ""
        node_code = sanitize_failure_text(raw.get("node_code") or raw.get("stage"), 160)
        node_label = sanitize_failure_text(raw.get("node_label") or raw.get("stage_label"), 160)
        if node_code and not node_label:
            node_label = sanitize_failure_text(FREE_STAGE_LABELS.get(node_code, node_code), 160)
        safe_page = sanitize_safe_page(raw.get("safe_page") or raw.get("page"))
        technical_summary = sanitize_failure_text(raw.get("technical_summary"), 800)
        diagnostic = sanitize_failure_text(raw.get("diagnostic") or technical_summary, 800)
        row: dict[str, Any] = {
            "time": cls._safe_time(raw.get("time")),
            "level": level,
            "message": message,
            "task_id": task_id,
            "stage": sanitize_failure_text(raw.get("stage") or node_code, 160),
            "stage_label": sanitize_failure_text(raw.get("stage_label") or node_label, 160),
            "node_code": node_code,
            "node_label": node_label,
            "error_code": sanitize_failure_text(raw.get("error_code"), 160),
            "provider_code": sanitize_failure_text(raw.get("provider_code"), 160),
            "page": safe_page,
            "safe_page": safe_page,
            "page_type": sanitize_failure_text(raw.get("page_type"), 120),
            "content_type": sanitize_failure_text(raw.get("content_type"), 160),
            "session_rebuilds": cls._number(raw.get("session_rebuilds"), maximum=100),
            "http_status": cls._number(raw.get("http_status"), maximum=999),
            "attempt": cls._number(raw.get("attempt"), maximum=100_000),
            "duration_ms": cls._number(raw.get("duration_ms"), maximum=86_400_000),
            "outcome": sanitize_failure_text(raw.get("outcome"), 80),
            "diagnostic": diagnostic,
            "technical_summary": technical_summary,
            "action_hint": sanitize_failure_text(raw.get("action_hint"), 400),
            "result": sanitize_failure_text(raw.get("result"), 800),
        }
        retryable = raw.get("retryable")
        if isinstance(retryable, bool):
            row["retryable"] = retryable
        elif isinstance(retryable, str) and retryable.strip().lower() in {"true", "false"}:
            row["retryable"] = retryable.strip().lower() == "true"
        # Keep only known, redacted fields.  In particular, do not carry an
        # unknown legacy ``token``/``cookie`` key into the public API.
        return {key: item for key, item in row.items() if key in cls._KNOWN_FIELDS}

    @classmethod
    def _load(cls, path: Path) -> list[dict[str, Any]]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return []
        if not isinstance(value, list):
            return []
        rows = [cls._normalize_row(item) for item in value if isinstance(item, dict)]
        # Migrate old rows on read so the persisted file and the API have the
        # same complete shape.  A failed best-effort migration must not make
        # log viewing fail.
        if rows != [item for item in value if isinstance(item, dict)]:
            try:
                atomic_write(path, rows)
            except OSError:
                pass
        return rows

    def _task_path(self, task_id: str) -> Path:
        return self.task_dir / f"{fingerprint(task_id)}.json"

    def add(self, message: Any, level: str = "info", **fields: Any) -> None:
        with self._lock:
            rows = self._load(self.path)
            source_text = safe_log_message(message)
            text = sanitize_log_message(source_text)
            match = re.search(r"\[([^\]/]{1,160})/([^\]/]{1,160})(?:/([^\]]{1,160}))?\]", source_text)
            task_id = str(fields.get("task_id") or "")
            if not task_id:
                task_id = match.group(1) if match and match.group(1).startswith("free-") else ""
            # Runtime callbacks historically accepted only (message, level).
            # Accept optional safe metadata as well, so newer account logs can
            # expose timing/page/HTTP summaries without changing that contract.
            metadata = {}
            for key in (
                "stage", "stage_label", "node_code", "node_label", "error_code",
                "provider_code", "page", "safe_page", "http_status", "attempt",
                "outcome", "duration_ms", "result", "diagnostic", "technical_summary",
                "action_hint", "retryable", "page_type", "content_type", "session_rebuilds",
            ):
                value = fields.get(key)
                if value not in (None, ""):
                    # Metadata can arrive from recovered exceptions as well as
                    # hand-written stage logs. Apply the same redactor as the
                    # message so a diagnostic field cannot bypass log safety.
                    if key == "session_rebuilds":
                        try:
                            metadata[key] = max(0, min(100, int(value)))
                        except (TypeError, ValueError):
                            continue
                    elif isinstance(value, bool) or isinstance(value, (int, float)):
                        metadata[key] = value
                    elif key in {"page", "safe_page"}:
                        metadata[key] = sanitize_safe_page(value)
                    else:
                        metadata[key] = sanitize_failure_text(value)
            for key, value in re.findall(
                r"(?:^|\s)(page|safe_page|page_type|content_type|session_rebuilds|http_status|attempt|outcome|duration_ms|result|diagnostic|action_hint|provider_code)=([^\s]+)",
                source_text,
            ):
                if key not in metadata:
                    if key in {"page", "safe_page"}:
                        metadata[key] = sanitize_safe_page(value)
                    elif key in {"session_rebuilds", "http_status", "attempt", "duration_ms"}:
                        try:
                            metadata[key] = max(0, int(value))
                        except (TypeError, ValueError):
                            continue
                    else:
                        metadata[key] = sanitize_failure_text(value)
            page_match = re.search(r"(?:页面|位置)[= 为：]+(https?://[^\s，）]+|页面地址未知)", source_text)
            http_match = re.search(r"\bHTTP\s+(\d{3})\b", source_text, re.IGNORECASE)
            attempt_match = re.search(r"第\s*(\d+)\s*次", source_text)
            duration_match = re.search(r"耗时[=：]\s*(\d+)\s*ms", source_text, re.IGNORECASE)
            if page_match and "page" not in metadata:
                metadata["page"] = sanitize_safe_page(page_match.group(1))
            if http_match and "http_status" not in metadata:
                metadata["http_status"] = int(http_match.group(1))
            if attempt_match and "attempt" not in metadata:
                metadata["attempt"] = int(attempt_match.group(1))
            if duration_match and "duration_ms" not in metadata:
                metadata["duration_ms"] = int(duration_match.group(1))
            if "outcome" not in metadata and str(level or "info") in {"success", "warn", "error"}:
                metadata["outcome"] = str(level or "info")
            prefix_task = bool(match and match.group(1).startswith("free-"))
            node_code = str(metadata.get("node_code") or (match.group(3) if match else "") or (match.group(2) if match and not match.group(3) else ""))
            node_label = str(
                metadata.get("node_label")
                or (match.group(2) if match and match.group(3) else "")
                or (match.group(1) if match and not prefix_task else "")
            )
            row = self._normalize_row({
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "level": str(level or "info"),
                "message": text,
                "task_id": task_id,
                "stage": str(metadata.get("stage") or node_code),
                "stage_label": str(metadata.get("stage_label") or node_label),
                "node_code": node_code,
                "node_label": node_label,
                **metadata,
            })
            rows.append(row)
            atomic_write(self.path, rows[-self.limit:])
            if task_id:
                task_path = self._task_path(task_id)
                task_rows = self._load(task_path)
                task_rows.append(row)
                atomic_write(task_path, task_rows[-self.task_limit:])

    def snapshot(self, task_id: str = "") -> list[dict[str, Any]]:
        with self._lock:
            normalized = str(task_id or "").strip()
            if normalized:
                rows = self._load(self._task_path(normalized))
                if rows:
                    return rows[-self.task_limit:]
                return [row for row in self._load(self.path) if row.get("task_id") == normalized][-self.task_limit:]
            return self._load(self.path)[-self.limit:]

    def delete_tasks(self, task_ids: list[str]) -> int:
        normalized = {str(task_id or "").strip() for task_id in task_ids}
        normalized.discard("")
        if not normalized:
            return 0
        with self._lock:
            rows = [row for row in self._load(self.path) if str(row.get("task_id") or "") not in normalized]
            atomic_write(self.path, rows[-self.limit:])
            deleted = 0
            for task_id in normalized:
                path = self._task_path(task_id)
                try:
                    path.unlink()
                    deleted += 1
                except FileNotFoundError:
                    continue
        return deleted

    def clear(self) -> None:
        with self._lock:
            atomic_write(self.path, [])
            for task_path in self.task_dir.glob("*.json"):
                try:
                    task_path.unlink()
                except FileNotFoundError:
                    continue


__all__ = ["FreeLogStore"]
