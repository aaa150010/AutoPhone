"""Private target-mailbox storage for Free account email rebinds.

The rebind mailbox pool is deliberately separate from the registration pool.
It has its own files, lifecycle states and result records so importing a target
address can never make it available to a new-account registration task.
"""

from __future__ import annotations

from pathlib import Path
import threading
from typing import Any, Sequence

try:
    from .free_register_common import FreeMailbox, FreeRegisterError, fingerprint, parse_mailbox_line
    from .free_rebind_storage import RebindSQLiteStore, RebindStorageError
except ImportError:  # pragma: no cover - top-level runtime loading
    from free_register_common import FreeMailbox, FreeRegisterError, fingerprint, parse_mailbox_line  # type: ignore[no-redef]
    from free_rebind_storage import RebindSQLiteStore, RebindStorageError  # type: ignore[no-redef]


ACTIVE_REBIND_POOL_STATUSES = frozenset({"reserved", "running"})


class RebindMailboxPool:
    """A mailbox pool used only as the destination of an email rebind."""

    def __init__(self, data_dir: str | Path) -> None:
        root = Path(data_dir).expanduser().resolve()
        # Accept either the Free root or an already-normalized ``rebind``
        # directory.  This keeps direct maintenance/API callers from creating
        # an accidental ``rebind/rebind`` hierarchy.
        self.data_dir = root if root.name == "rebind" else root / "rebind"
        self.pool_path = self.data_dir / "mailbox_pool.txt"
        self.state_path = self.data_dir / "mailbox_state.json"
        self.results_dir = self.data_dir / "results"
        self._lock = threading.RLock()
        # SQLite is the rebind source of truth.  The path/text attributes are
        # retained only for compatibility with older callers and maintenance
        # tooling; normal operations never write them.
        self.storage = RebindSQLiteStore(self.data_dir)

    def _state(self) -> dict[str, Any]:
        rows: dict[str, Any] = {}
        for item in self.storage.list_mailboxes():
            row_id = str(item.get("row_id") or "")
            if not row_id:
                continue
            payload = dict(item)
            payload.pop("row_id", None)
            rows[row_id] = payload
        return {"version": 1, "rows": rows}

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
        result: list[FreeMailbox] = []
        for index, row in enumerate(self.storage.list_mailboxes(), 1):
            row_id = str(row.get("row_id") or "").strip().lower()
            email = str(row.get("email") or "").strip()
            mailbox_url = str(row.get("mailbox_url") or "").strip()
            if not row_id or not email or not mailbox_url:
                continue
            try:
                line_no = int(row.get("line_no") or index)
            except (TypeError, ValueError):
                line_no = index
            result.append(FreeMailbox(row_id, max(1, line_no), email, mailbox_url))
        return result

    def entry(self, row_id: str) -> FreeMailbox | None:
        target = str(row_id or "").strip().lower()
        return next((row for row in self.entries() if row.row_id == target), None)

    def _write_entries(self, rows: Sequence[FreeMailbox]) -> None:
        for row in rows:
            self.storage.upsert_mailbox(
                email=row.email,
                mailbox_url=row.mailbox_url,
                row_id=row.row_id,
                payload={"line_no": row.line_no},
            )

    def import_text_with_stats(self, content: str) -> tuple[int, int]:
        incoming = self._parse_content(content)
        if not incoming:
            raise FreeRegisterError(
                "free_rebind_pool", "换绑邮箱池", "换绑邮箱池没有有效的邮箱-取码 URL", retryable=False
            )
        with self._lock:
            existing = self.entries()
            existing_ids = {row.row_id for row in existing}
            # Upserts are idempotent and preserve active reservations in the
            # SQLite store.  Existing rows are not rewritten to legacy files.
            for row in incoming:
                self.storage.upsert_mailbox(
                    email=row.email,
                    mailbox_url=row.mailbox_url,
                    row_id=row.row_id,
                    payload={"line_no": row.line_no},
                )
            added = sum(row.row_id not in existing_ids for row in incoming)
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
            self.storage.update_mailbox(str(row_id), values=values)

    def reserve(self, row_id: str, task_id: str) -> None:
        with self._lock:
            row = self.storage.reserve_mailbox(str(row_id), str(task_id))
            if row is None:
                raise FreeRegisterError("free_rebind_pool_reserve", "预留换绑邮箱", "换绑邮箱已被其他任务占用", retryable=False)

    def set_status(self, row_ids: Sequence[str], status: str) -> int:
        allowed = {"available", "unavailable"}
        if status not in allowed:
            raise FreeRegisterError("free_rebind_pool_status", "更新换绑邮箱状态", "换绑邮箱状态无效", retryable=False)
        requested = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        with self._lock:
            try:
                return self.storage.set_mailbox_status(sorted(requested), status)
            except RebindStorageError as exc:
                raise FreeRegisterError("free_rebind_pool_status", "更新换绑邮箱状态", "运行中的换绑邮箱不能修改状态", retryable=False)

    def delete(self, row_ids: Sequence[str]) -> int:
        requested = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        if not requested:
            return 0
        with self._lock:
            try:
                return self.storage.delete_mailboxes(sorted(requested))
            except RebindStorageError as exc:
                raise FreeRegisterError("free_rebind_pool_delete", "删除换绑邮箱", "运行中的换绑邮箱不能删除", retryable=False)

    def public_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            return self.storage.public_mailboxes()


__all__ = ["ACTIVE_REBIND_POOL_STATUSES", "RebindMailboxPool"]
