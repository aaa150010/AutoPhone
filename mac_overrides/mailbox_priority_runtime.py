"""Persistent FIFO priority for mailboxes imported during an active run."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any
import uuid


STORE_VERSION = 1
LEASE_OWNER_FIELD = "lease_owner_batch_id"
_SAFE_BATCH_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _fingerprint(value: Any) -> str:
    text = str(value or "").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_batch_id(value: Any) -> str:
    text = str(value or "").strip()
    return text if _SAFE_BATCH_ID.fullmatch(text) else ""


def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
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


class MailboxNextBatchPriorityStore:
    """Track only row fingerprints and FIFO order; never persist mailbox content."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        path: str | Path | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = (
            Path(path).expanduser().resolve()
            if path
            else self.data_dir / "mailbox_next_batch_priority.json"
        )
        self.now = now
        self._lock = threading.RLock()
        self._state = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {"version": STORE_VERSION, "next_sequence": 0, "entries": {}}
        entries = raw.get("entries") if isinstance(raw, Mapping) else None
        cleaned: dict[str, dict[str, int]] = {}
        if isinstance(entries, Mapping):
            for row_id, item in entries.items():
                identifier = str(row_id or "").strip().lower()
                if len(identifier) != 64 or not isinstance(item, Mapping):
                    continue
                sequence = max(_safe_int(item.get("sequence")), 0)
                if sequence <= 0:
                    continue
                cleaned[identifier] = {
                    "sequence": sequence,
                    "imported_at": max(_safe_int(item.get("imported_at")), 0),
                }
        next_sequence = max(
            max((_safe_int(item.get("sequence")) for item in cleaned.values()), default=0),
            max(_safe_int(raw.get("next_sequence")) if isinstance(raw, Mapping) else 0, 0),
        )
        return {
            "version": STORE_VERSION,
            "next_sequence": next_sequence,
            "entries": cleaned,
        }

    def _save_locked(self) -> None:
        _atomic_write(self.path, self._state)

    def mark_imported(self, source_rows: Iterable[Any]) -> int:
        row_ids = []
        seen: set[str] = set()
        for row in source_rows:
            row_id = _fingerprint(row)
            if row_id and row_id not in seen:
                seen.add(row_id)
                row_ids.append(row_id)
        if not row_ids:
            return 0
        now = int(self.now())
        added = 0
        with self._lock:
            for row_id in row_ids:
                if row_id in self._state["entries"]:
                    continue
                self._state["next_sequence"] += 1
                self._state["entries"][row_id] = {
                    "sequence": self._state["next_sequence"],
                    "imported_at": now,
                }
                added += 1
            if added:
                self._save_locked()
        return added

    def prioritize(self, entries: Sequence[Any]) -> list[Any]:
        """Return priority rows first without changing order inside either group."""
        rows = list(entries)
        with self._lock:
            priorities = {
                row_id: _safe_int(item.get("sequence"))
                for row_id, item in self._state["entries"].items()
                if isinstance(item, Mapping)
            }
        indexed = list(enumerate(rows))
        indexed.sort(
            key=lambda pair: (
                0
                if _fingerprint(getattr(pair[1], "source_row", "")) in priorities
                else 1,
                priorities.get(_fingerprint(getattr(pair[1], "source_row", "")), pair[0]),
                pair[0],
            )
        )
        return [entry for _index, entry in indexed]

    def consume(self, source_row: Any) -> bool:
        row_id = _fingerprint(source_row)
        if not row_id:
            return False
        with self._lock:
            removed = self._state["entries"].pop(row_id, None) is not None
            if removed:
                self._save_locked()
            return removed

    def prune(self, source_rows: Iterable[Any]) -> int:
        current = {_fingerprint(row) for row in source_rows}
        current.discard("")
        with self._lock:
            stale = [row_id for row_id in self._state["entries"] if row_id not in current]
            for row_id in stale:
                self._state["entries"].pop(row_id, None)
            if stale:
                self._save_locked()
            return len(stale)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            ordered = sorted(
                self._state["entries"].items(),
                key=lambda item: _safe_int(item[1].get("sequence")),
            )
            return {
                "pending": len(ordered),
                "row_ids": [row_id for row_id, _item in ordered],
                "sequences": [_safe_int(item.get("sequence")) for _row_id, item in ordered],
            }


def reserve_available_batch(
    pool: Any,
    target: Any,
    *,
    lease_seconds: Any = 3600,
    before_reserve: Callable[[Sequence[Any]], Any] | None = None,
    after_reserve: Callable[[Sequence[Any]], Any] | None = None,
    on_reserve_failed: Callable[[Sequence[Any], Exception], Any] | None = None,
    mailbox_error_type: type[Exception] = RuntimeError,
    lease_owner_batch_id: Any = "",
) -> list[Any]:
    """Select and lease one immutable batch in the recovered pool's file lock."""
    count = max(_safe_int(target), 0)
    seconds = max(60, min(_safe_int(lease_seconds, 3600), 86400))
    lease_owner = _safe_batch_id(lease_owner_batch_id)
    if count <= 0:
        return []

    prepared: list[Any] = []

    def allocate(state: dict[str, Any], entries: list[Any]) -> list[Any] | None:
        now = float(time.time())
        selected: list[tuple[Any, dict[str, Any]]] = []
        for entry in entries:
            item = pool._item(state, entry)
            status = str(item.get("status") or "").strip().lower()
            try:
                lease_until = float(item.get("lease_until") or 0)
            except (TypeError, ValueError):
                lease_until = 0.0
            if status in {"consumed", "damaged"}:
                continue
            if status == "leased" and lease_until > now:
                continue
            selected.append((entry, item))
            if len(selected) == count:
                break
        if len(selected) != count:
            return None
        chosen = [entry for entry, _item in selected]
        prepared[:] = chosen
        if callable(before_reserve):
            before_reserve(chosen)
        updated_at = int(now)
        for _entry, item in selected:
            item.update(
                status="leased",
                lease_until=now + seconds,
                **{LEASE_OWNER_FIELD: lease_owner},
                updated_at=updated_at,
            )
            pool._history(item, "leased")
        return chosen

    try:
        selected = pool._update(allocate)
    except Exception as exc:
        if prepared and callable(on_reserve_failed):
            try:
                on_reserve_failed(tuple(prepared), exc)
            except Exception:
                pass
        raise
    if not isinstance(selected, list) or len(selected) != count:
        if prepared and callable(on_reserve_failed):
            try:
                on_reserve_failed(
                    tuple(prepared),
                    mailbox_error_type("mailbox_pool_empty: no available mailbox"),
                )
            except Exception:
                pass
        raise mailbox_error_type("mailbox_pool_empty: no available mailbox")
    if callable(after_reserve):
        try:
            after_reserve(tuple(selected))
        except Exception as exc:
            rollback_complete = False
            if lease_owner:
                bindings = [
                    {
                        "row_id": _fingerprint(getattr(entry, "source_row", "")),
                        "line_no": _safe_int(getattr(entry, "line_no", 0)),
                    }
                    for entry in selected
                ]
                try:
                    released = release_owned_batch_leases(
                        pool,
                        lease_owner,
                        bindings,
                        reason="batch_manifest_commit_failed",
                    )
                except Exception:
                    released = None
                if released is not None:
                    rollback_complete = (
                        released["requested"] == len(selected)
                        and released["released"] + released["not_leased"]
                        + released["ownership_mismatch"] == released["requested"]
                    )
            if rollback_complete and callable(on_reserve_failed):
                try:
                    on_reserve_failed(tuple(selected), exc)
                except Exception:
                    pass
            raise
    return selected


def reserve_specific_available(
    pool: Any,
    row_ids: Iterable[Any],
    *,
    lease_seconds: Any = 3600,
    lease_owner_batch_id: Any = "",
    mailbox_error_type: type[Exception] = RuntimeError,
) -> list[Any]:
    """Lease only the requested row fingerprints, preserving requested order."""
    wanted = [str(value or "").strip().lower() for value in row_ids]
    wanted = list(dict.fromkeys(value for value in wanted if len(value) == 64))
    if not wanted:
        return []
    seconds = max(60, min(_safe_int(lease_seconds, 3600), 86400))
    owner = _safe_batch_id(lease_owner_batch_id)

    def allocate(state: dict[str, Any], entries: list[Any]) -> list[Any] | None:
        by_id = {_fingerprint(getattr(entry, "source_row", "")): entry for entry in entries}
        selected = []
        now = float(time.time())
        for row_id in wanted:
            entry = by_id.get(row_id)
            if entry is None:
                return None
            item = pool._item(state, entry)
            status = str(item.get("status") or "").strip().lower()
            try:
                lease_until = float(item.get("lease_until") or 0)
            except (TypeError, ValueError):
                lease_until = 0.0
            if status in {"consumed", "damaged"} or (status == "leased" and lease_until > now):
                return None
            selected.append((entry, item))
        updated_at = int(now)
        for _entry, item in selected:
            item.update(
                status="leased",
                lease_until=now + seconds,
                **{LEASE_OWNER_FIELD: owner},
                updated_at=updated_at,
            )
            pool._history(item, "leased")
        return [entry for entry, _item in selected]

    selected = pool._update(allocate)
    if not isinstance(selected, list) or len(selected) != len(wanted):
        raise mailbox_error_type("追加邮箱已变化或不再可用")
    return selected


def release_owned_batch_leases(
    pool: Any,
    batch_id: Any,
    members: Iterable[Mapping[str, Any]],
    *,
    reason: str = "process_restart",
    now: Callable[[], float] = time.time,
) -> dict[str, int]:
    """Release exact rows only while their lease is still owned by this batch."""
    owner = _safe_batch_id(batch_id)
    wanted = {
        (str(member.get("row_id") or "").strip().lower(), _safe_int(member.get("line_no")))
        for member in members
        if isinstance(member, Mapping)
    }
    wanted = {
        binding
        for binding in wanted
        if len(binding[0]) == 64
        and all(character in "0123456789abcdef" for character in binding[0])
        and binding[1] > 0
    }
    counts = {
        "requested": len(wanted),
        "matched": 0,
        "released": 0,
        "ownership_mismatch": 0,
        "not_leased": 0,
        "missing": 0,
    }
    if not owner or not wanted:
        counts["missing"] = len(wanted)
        return counts

    safe_reason = str(reason or "process_restart").strip()[:80] or "process_restart"

    def release(state: dict[str, Any], entries: list[Any]) -> dict[str, int]:
        found: set[tuple[str, int]] = set()
        updated_at = int(now())
        for entry in entries:
            binding = (
                _fingerprint(getattr(entry, "source_row", "")),
                _safe_int(getattr(entry, "line_no", 0)),
            )
            if binding not in wanted:
                continue
            found.add(binding)
            counts["matched"] += 1
            item = pool._item(state, entry)
            if str(item.get("status") or "").strip().lower() != "leased":
                counts["not_leased"] += 1
                continue
            if not _same_owner(item.get(LEASE_OWNER_FIELD), owner):
                counts["ownership_mismatch"] += 1
                continue
            item.update(
                status="available",
                lease_until=0,
                reason=safe_reason,
                updated_at=updated_at,
                **{LEASE_OWNER_FIELD: ""},
            )
            pool._history(item, "released")
            counts["released"] += 1
        counts["missing"] = len(wanted - found)
        return dict(counts)

    result = pool._update(release)
    return dict(result) if isinstance(result, Mapping) else dict(counts)


def _same_owner(value: Any, expected: str) -> bool:
    candidate = _safe_batch_id(value)
    return bool(candidate and candidate == expected)


__all__ = [
    "LEASE_OWNER_FIELD",
    "MailboxNextBatchPriorityStore",
    "release_owned_batch_leases",
    "reserve_available_batch",
]
