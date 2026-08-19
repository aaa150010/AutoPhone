"""Persistent, credential-redacted logs for the isolated Free runtime."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import re
from typing import Any

try:
    from .free_register_common import atomic_write, fingerprint, safe_log_message
except ImportError:
    from free_register_common import atomic_write, fingerprint, safe_log_message  # type: ignore[no-redef]


class FreeLogStore:
    def __init__(self, data_dir: str | Path, *, limit: int = 500, task_limit: int = 500) -> None:
        self.path = Path(data_dir).expanduser().resolve() / "logs.json"
        self.task_dir = self.path.parent / "task_logs"
        self.limit = max(50, int(limit))
        self.task_limit = max(100, int(task_limit))
        self._lock = threading.RLock()

    @staticmethod
    def _load(path: Path) -> list[dict[str, Any]]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return []
        return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def _task_path(self, task_id: str) -> Path:
        return self.task_dir / f"{fingerprint(task_id)}.json"

    def add(self, message: Any, level: str = "info") -> None:
        with self._lock:
            rows = self._load(self.path)
            text = safe_log_message(message)
            match = re.search(r"\[([^\]/]{1,160})/([^\]/]{1,160})(?:/([^\]]{1,160}))?\]", text)
            task_id = match.group(1) if match and match.group(1).startswith("free-") else ""
            row = {
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "level": str(level or "info"),
                "message": text,
                "task_id": task_id,
                "stage": match.group(3) or (match.group(2) if match else ""),
                "stage_label": match.group(2) if match and match.group(3) else "",
            }
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

    def clear(self) -> None:
        with self._lock:
            atomic_write(self.path, [])


__all__ = ["FreeLogStore"]
