"""Private target-mailbox storage for Free account email rebinds.

The rebind mailbox pool is deliberately separate from the registration pool.
It has its own files, lifecycle states and result records so importing a target
address can never make it available to a new-account registration task.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import threading
from typing import Any, Mapping, Sequence

try:
    from .free_failure_runtime import canonical_failure
    from .free_register_common import FreeMailbox, FreeRegisterError, atomic_write, fingerprint, parse_mailbox_line
except ImportError:  # pragma: no cover - top-level runtime loading
    from free_failure_runtime import canonical_failure  # type: ignore[no-redef]
    from free_register_common import FreeMailbox, FreeRegisterError, atomic_write, fingerprint, parse_mailbox_line  # type: ignore[no-redef]


ACTIVE_REBIND_POOL_STATUSES = frozenset({"reserved", "running"})


class RebindMailboxPool:
    """A mailbox pool used only as the destination of an email rebind."""

    def __init__(self, data_dir: str | Path) -> None:
        root = Path(data_dir).expanduser().resolve()
        self.data_dir = root / "rebind"
        self.pool_path = self.data_dir / "mailbox_pool.txt"
        self.state_path = self.data_dir / "mailbox_state.json"
        self.results_dir = self.data_dir / "results"
        self._lock = threading.RLock()

    def _state(self) -> dict[str, Any]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            value = {}
        rows = value.get("rows") if isinstance(value, Mapping) else {}
        return {"version": 1, "rows": dict(rows) if isinstance(rows, Mapping) else {}}

    @staticmethod
    def _parse_content(content: str) -> list[FreeMailbox]:
        result: list[FreeMailbox] = []
        seen: set[str] = set()
        for line_no, raw in enumerate(str(content or "").splitlines(), 1):
            parsed = parse_mailbox_line(raw)
            if parsed is None:
                continue
            email, mailbox_url = parsed
            row_id = fingerprint(f"{email}|{mailbox_url}")
            if row_id in seen:
                continue
            seen.add(row_id)
            result.append(FreeMailbox(row_id, line_no, email, mailbox_url))
        return result

    def entries(self) -> list[FreeMailbox]:
        try:
            return self._parse_content(self.pool_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError):
            return []

    def entry(self, row_id: str) -> FreeMailbox | None:
        target = str(row_id or "").strip().lower()
        return next((row for row in self.entries() if row.row_id == target), None)

    def _write_entries(self, rows: Sequence[FreeMailbox]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.pool_path.write_text(
            "".join(f"{row.email}----{row.mailbox_url}\n" for row in rows),
            encoding="utf-8",
        )
        self.pool_path.chmod(0o600)

    def import_text_with_stats(self, content: str) -> tuple[int, int]:
        incoming = self._parse_content(content)
        if not incoming:
            raise FreeRegisterError(
                "free_rebind_pool", "换绑邮箱池", "换绑邮箱池没有有效的邮箱-取码 URL", retryable=False
            )
        with self._lock:
            existing = self.entries()
            existing_ids = {row.row_id for row in existing}
            combined: list[FreeMailbox] = []
            seen: set[str] = set()
            for row in (*existing, *incoming):
                if row.row_id not in seen:
                    seen.add(row.row_id)
                    combined.append(row)
            added = sum(row.row_id not in existing_ids for row in incoming)
            self._write_entries(combined)
            state = self._state()
            for row in combined:
                state["rows"].setdefault(
                    row.row_id,
                    {"email": row.email, "mailbox_url": row.mailbox_url, "status": "available"},
                )
            atomic_write(self.state_path, state)
            return added, max(0, len(incoming) - added)

    def import_text(self, content: str) -> int:
        return self.import_text_with_stats(content)[0]

    def reveal_mailbox_url(self, row_id: str) -> str:
        row = self.entry(row_id)
        if row is None:
            raise FreeRegisterError("free_rebind_mailbox_url", "读取换绑取件地址", "换绑邮箱行不存在", retryable=False)
        return row.mailbox_url

    def update(self, row_id: str, **values: Any) -> None:
        with self._lock:
            state = self._state()
            row = state["rows"].setdefault(str(row_id), {})
            row.update({key: value for key, value in values.items() if value is not None})
            if "failure" in values:
                normalized = canonical_failure(values.get("failure"))
                if normalized is None:
                    row.pop("failure", None)
                else:
                    row["failure"] = normalized
            atomic_write(self.state_path, state)

    def reserve(self, row_id: str, task_id: str) -> None:
        with self._lock:
            state = self._state()
            row = state["rows"].setdefault(str(row_id), {})
            status = str(row.get("status") or "available")
            if status not in {"available", "failed", "pending_rerun"}:
                raise FreeRegisterError("free_rebind_pool_reserve", "预留换绑邮箱", "换绑邮箱已被其他任务占用", retryable=False)
            row.update({"status": "reserved", "task_id": task_id, "error": ""})
            row.pop("failure", None)
            atomic_write(self.state_path, state)

    def set_status(self, row_ids: Sequence[str], status: str) -> int:
        allowed = {"available", "unavailable"}
        if status not in allowed:
            raise FreeRegisterError("free_rebind_pool_status", "更新换绑邮箱状态", "换绑邮箱状态无效", retryable=False)
        requested = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        with self._lock:
            state = self._state()
            existing = {row.row_id for row in self.entries()}
            targets = requested & existing
            if any(str(state["rows"].get(row_id, {}).get("status") or "available") in ACTIVE_REBIND_POOL_STATUSES for row_id in targets):
                raise FreeRegisterError("free_rebind_pool_status", "更新换绑邮箱状态", "运行中的换绑邮箱不能修改状态", retryable=False)
            for row_id in targets:
                state["rows"].setdefault(row_id, {})["status"] = status
            atomic_write(self.state_path, state)
            return len(targets)

    def delete(self, row_ids: Sequence[str]) -> int:
        requested = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        if not requested:
            return 0
        with self._lock:
            rows = self.entries()
            state = self._state()
            targets = {row.row_id for row in rows if row.row_id in requested}
            if any(str(state["rows"].get(row_id, {}).get("status") or "available") in ACTIVE_REBIND_POOL_STATUSES for row_id in targets):
                raise FreeRegisterError("free_rebind_pool_delete", "删除换绑邮箱", "运行中的换绑邮箱不能删除", retryable=False)
            self._write_entries([row for row in rows if row.row_id not in targets])
            for row_id in targets:
                state["rows"].pop(row_id, None)
            atomic_write(self.state_path, state)
            return len(targets)

    def public_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            state = self._state()["rows"]
            rows: list[dict[str, Any]] = []
            for row in self.entries():
                current = state.get(row.row_id, {})
                failure = canonical_failure(current.get("failure") if isinstance(current.get("failure"), Mapping) else None)
                rows.append({
                    "row_id": row.row_id,
                    "line_no": row.line_no,
                    "email": row.email,
                    "status": str(current.get("status") or "available"),
                    "task_id": str(current.get("task_id") or ""),
                    "error": str(current.get("error") or (failure or {}).get("public_message") or "")[:300],
                    "failure": failure,
                })
            return rows


__all__ = ["ACTIVE_REBIND_POOL_STATUSES", "RebindMailboxPool"]
