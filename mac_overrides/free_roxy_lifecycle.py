"""Persistent ownership and cleanup coordination for Free Roxy profiles.

The Roxy API creates profiles asynchronously.  A request can therefore time
out after the server has already allocated a window, and a close/delete call
can return before the connection has disappeared.  This module keeps a small
redacted ownership journal and provides a confirmation-based cleanup helper.
It deliberately never scans or removes unowned Roxy profiles.
"""

from __future__ import annotations

from dataclasses import dataclass
import copy
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Mapping


MANAGED_WINDOW_PREFIX = "FreeRegister "
MANAGED_WINDOW_REMARK = "FreeRegister temporary profile"
STORE_VERSION = 2


def _safe_text(value: Any, limit: int = 200) -> str:
    return str(value or "").replace("\x00", "").strip()[:limit]


def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(temp, 0o600)
    except OSError:
        pass
    os.replace(temp, path)


@dataclass(frozen=True, slots=True)
class RoxyCleanupRecord:
    profile_id: str
    workspace_id: str = ""
    batch_id: str = ""
    task_id: str = ""
    window_name: str = ""
    window_remark: str = MANAGED_WINDOW_REMARK
    state: str = "created"
    attempts: int = 0
    last_error: str = ""
    updated_at: int = 0


@dataclass(frozen=True, slots=True)
class RoxyCreationIntent:
    intent_id: str
    workspace_id: str = ""
    batch_id: str = ""
    task_id: str = ""
    window_name: str = ""
    window_remark: str = MANAGED_WINDOW_REMARK
    updated_at: int = 0


class RoxyCleanupStore:
    """Thread-safe JSON journal for profiles owned by this Free runtime."""

    _locks: dict[str, threading.RLock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        key = str(self.path)
        with self._locks_guard:
            self._lock = self._locks.setdefault(key, threading.RLock())

    def _read(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            payload = {}
        records = payload.get("records") if isinstance(payload, Mapping) else {}
        intents = payload.get("intents") if isinstance(payload, Mapping) else {}
        return {
            "version": STORE_VERSION,
            "records": dict(records) if isinstance(records, Mapping) else {},
            "intents": dict(intents) if isinstance(intents, Mapping) else {},
        }

    def _write(self, payload: Mapping[str, Any]) -> None:
        _atomic_write(self.path, payload)

    @staticmethod
    def _key(profile_id: Any) -> str:
        return _safe_text(profile_id, 200)

    @staticmethod
    def _intent_key(value: Any) -> str:
        return _safe_text(value, 200)

    def reserve_intent(
        self,
        intent_id: str,
        *,
        workspace_id: Any = "",
        batch_id: Any = "",
        task_id: Any = "",
        window_name: Any = "",
        window_remark: Any = MANAGED_WINDOW_REMARK,
    ) -> RoxyCreationIntent:
        key = self._intent_key(intent_id)
        if not key:
            raise ValueError("intent_id is required")
        intent = {
            "intent_id": key,
            "workspace_id": _safe_text(workspace_id),
            "batch_id": _safe_text(batch_id),
            "task_id": _safe_text(task_id),
            "window_name": _safe_text(window_name),
            "window_remark": _safe_text(window_remark) or MANAGED_WINDOW_REMARK,
            "updated_at": int(time.time()),
        }
        with self._lock:
            payload = self._read()
            payload["intents"][key] = intent
            self._write(payload)
        return RoxyCreationIntent(**intent)

    def clear_intent(self, intent_id: str) -> bool:
        key = self._intent_key(intent_id)
        if not key:
            return False
        with self._lock:
            payload = self._read()
            existed = key in payload["intents"]
            payload["intents"].pop(key, None)
            if existed:
                self._write(payload)
            return existed

    def intents(self) -> list[RoxyCreationIntent]:
        with self._lock:
            payload = self._read()
            result: list[RoxyCreationIntent] = []
            for raw in payload["intents"].values():
                if not isinstance(raw, Mapping):
                    continue
                try:
                    intent = RoxyCreationIntent(
                        intent_id=_safe_text(raw.get("intent_id")),
                        workspace_id=_safe_text(raw.get("workspace_id")),
                        batch_id=_safe_text(raw.get("batch_id")),
                        task_id=_safe_text(raw.get("task_id")),
                        window_name=_safe_text(raw.get("window_name")),
                        window_remark=_safe_text(raw.get("window_remark")) or MANAGED_WINDOW_REMARK,
                        updated_at=max(0, int(raw.get("updated_at") or 0)),
                    )
                except (TypeError, ValueError):
                    continue
                if intent.intent_id:
                    result.append(intent)
            return result

    def upsert(
        self,
        profile_id: str,
        *,
        workspace_id: Any = "",
        batch_id: Any = "",
        task_id: Any = "",
        window_name: Any = "",
        window_remark: Any = MANAGED_WINDOW_REMARK,
        state: str = "created",
    ) -> RoxyCleanupRecord:
        key = self._key(profile_id)
        if not key:
            raise ValueError("profile_id is required")
        with self._lock:
            payload = self._read()
            old = payload["records"].get(key)
            prior = dict(old) if isinstance(old, Mapping) else {}
            record = {
                "profile_id": key,
                "workspace_id": _safe_text(workspace_id),
                "batch_id": _safe_text(batch_id),
                "task_id": _safe_text(task_id),
                "window_name": _safe_text(window_name),
                "window_remark": _safe_text(window_remark) or MANAGED_WINDOW_REMARK,
                "state": _safe_text(state) or "created",
                "attempts": max(0, int(prior.get("attempts") or 0)),
                "last_error": _safe_text(prior.get("last_error")),
                "updated_at": int(time.time()),
            }
            payload["records"][key] = record
            self._write(payload)
            return RoxyCleanupRecord(**record)

    def update(self, profile_id: str, *, state: str | None = None, error: Any = None) -> RoxyCleanupRecord | None:
        key = self._key(profile_id)
        if not key:
            return None
        with self._lock:
            payload = self._read()
            raw = payload["records"].get(key)
            if not isinstance(raw, Mapping):
                return None
            record = dict(raw)
            if state is not None:
                record["state"] = _safe_text(state) or record.get("state") or "created"
            if error is not None:
                record["last_error"] = _safe_text(error)
            record["attempts"] = max(0, int(record.get("attempts") or 0))
            record["updated_at"] = int(time.time())
            payload["records"][key] = record
            self._write(payload)
            return RoxyCleanupRecord(**record)

    def mark_pending(self, profile_id: str, error: Any = "") -> RoxyCleanupRecord | None:
        key = self._key(profile_id)
        with self._lock:
            payload = self._read()
            raw = payload["records"].get(key)
            if not isinstance(raw, Mapping):
                return None
            record = dict(raw)
            record["state"] = "cleanup_pending"
            record["attempts"] = max(0, int(record.get("attempts") or 0)) + 1
            record["last_error"] = _safe_text(error)
            record["updated_at"] = int(time.time())
            payload["records"][key] = record
            self._write(payload)
            return RoxyCleanupRecord(**record)

    def remove(self, profile_id: str) -> bool:
        key = self._key(profile_id)
        if not key:
            return False
        with self._lock:
            payload = self._read()
            existed = key in payload["records"]
            payload["records"].pop(key, None)
            if existed:
                self._write(payload)
            return existed

    def records(self, *, states: set[str] | None = None) -> list[RoxyCleanupRecord]:
        with self._lock:
            payload = self._read()
            result: list[RoxyCleanupRecord] = []
            for raw in payload["records"].values():
                if not isinstance(raw, Mapping):
                    continue
                try:
                    record = RoxyCleanupRecord(
                        profile_id=_safe_text(raw.get("profile_id")),
                        workspace_id=_safe_text(raw.get("workspace_id")),
                        batch_id=_safe_text(raw.get("batch_id")),
                        task_id=_safe_text(raw.get("task_id")),
                        window_name=_safe_text(raw.get("window_name")),
                        window_remark=_safe_text(raw.get("window_remark")) or MANAGED_WINDOW_REMARK,
                        state=_safe_text(raw.get("state")) or "created",
                        attempts=max(0, int(raw.get("attempts") or 0)),
                        last_error=_safe_text(raw.get("last_error")),
                        updated_at=max(0, int(raw.get("updated_at") or 0)),
                    )
                except (TypeError, ValueError):
                    continue
                if record.profile_id and (states is None or record.state in states):
                    result.append(record)
            return result

    def pending(self) -> list[RoxyCleanupRecord]:
        return self.records(states={"created", "opening", "opened", "cleanup_pending", "orphaned"})


class RoxyLifecycle:
    """Confirmation-based close/delete operations for one Roxy API client."""

    def __init__(
        self,
        client: Any,
        store: RoxyCleanupStore,
        *,
        log_fn: Callable[[str, str], None] | None = None,
        verify_timeout: float = 8.0,
        verify_interval: float = 0.25,
        retries: int = 3,
    ) -> None:
        self.client = client
        self.store = store
        self.log_fn = log_fn
        self.verify_timeout = max(0.5, float(verify_timeout))
        self.verify_interval = max(0.05, float(verify_interval))
        self.retries = max(1, int(retries))

    def _log(self, message: str, level: str = "info") -> None:
        if callable(self.log_fn):
            self.log_fn(str(message), level)

    def _connection_gone(self, profile_id: str, workspace_id: str = "") -> bool:
        """Return False on API failure; absence is not inferred from errors."""
        try:
            return self._profile_call("connection_info", profile_id, workspace_id) is None
        except Exception as exc:
            # Roxy versions differ on whether a closed/missing window is
            # represented as an empty 200 response or a 404/410.  Both are a
            # positive gone result; transport and other server errors are not.
            status = getattr(exc, "provider_status", None)
            try:
                status = int(status) if status is not None else None
            except (TypeError, ValueError):
                status = None
            if status in {404, 410}:
                return True
            text = str(exc or "").casefold()
            if any(marker in text for marker in ("not found", "no such window", "window not exist", "窗口不存在")):
                return True
            self._log(f"Roxy connection_info 确认失败（{type(exc).__name__}）", "warn")
            return False

    def _profile_gone(self, profile_id: str, workspace_id: str) -> bool:
        list_profiles = getattr(self.client, "list_profiles", None)
        if not callable(list_profiles):
            return True
        try:
            rows = list_profiles(workspace_id)
        except Exception as exc:
            self._log(f"Roxy Profile 列表确认失败（{type(exc).__name__}）", "warn")
            return False
        return not any(str(row.get("profile_id") or row.get("dirId") or row.get("id") or "") == str(profile_id) for row in rows if isinstance(row, Mapping))

    def _wait_connection_gone(self, profile_id: str, workspace_id: str = "") -> bool:
        deadline = time.monotonic() + self.verify_timeout
        while time.monotonic() < deadline:
            if self._connection_gone(profile_id, workspace_id):
                return True
            time.sleep(self.verify_interval)
        return self._connection_gone(profile_id, workspace_id)

    def cleanup(
        self,
        record: RoxyCleanupRecord | Mapping[str, Any] | None,
        *,
        delete_profile: bool = True,
    ) -> bool:
        if record is None:
            return True
        if isinstance(record, RoxyCleanupRecord):
            profile_id = record.profile_id
            workspace_id = record.workspace_id
        else:
            profile_id = _safe_text(record.get("profile_id") or record.get("profileId") or record.get("dirId"))
            workspace_id = _safe_text(record.get("workspace_id") or record.get("workspaceId"))
        if not profile_id:
            return True
        self.store.update(profile_id, state="cleanup_running")
        close_ok = False
        for _attempt in range(self.retries):
            try:
                self._profile_call("close_profile", profile_id, workspace_id)
                close_ok = True
                break
            except Exception as exc:
                self._log(f"Roxy Profile 关闭失败（{type(exc).__name__}）", "warn")
        connection_ok = self._wait_connection_gone(profile_id, workspace_id) if close_ok else False
        delete_ok = not delete_profile
        if delete_profile:
            # A ghost connection may already have lost its Profile row.  In
            # that case deletion is already satisfied; attempting /delete
            # would turn a harmless 404 into an endless cleanup queue.
            profile_already_gone = self._profile_gone(profile_id, workspace_id)
            if profile_already_gone:
                delete_ok = True
            else:
                for _attempt in range(self.retries):
                    try:
                        self._profile_call("delete_profile", profile_id, workspace_id)
                        delete_ok = True
                        break
                    except Exception as exc:
                        status = getattr(exc, "provider_status", None)
                        if status in {404, 410}:
                            delete_ok = True
                            break
                        self._log(f"Roxy Profile 删除失败（{type(exc).__name__}）", "warn")
        # Delete is asynchronous on some Roxy versions.  Confirm both the
        # connection and the profile list before removing the ownership record.
        final_connection_ok = self._wait_connection_gone(profile_id, workspace_id) if delete_ok else False
        profile_ok = self._profile_gone(profile_id, workspace_id) if delete_profile and delete_ok else True
        # Once deletion has been accepted and both independent read-backs show
        # that the profile is gone, a timed-out close request cannot keep an
        # already released profile in the queue forever. When deletion is
        # disabled, the close and connection checks remain mandatory.
        complete = (
            bool(delete_ok and final_connection_ok and profile_ok)
            if delete_profile
            else bool(close_ok and connection_ok)
        )
        if complete:
            self.store.remove(profile_id)
            self._log(f"Roxy Profile 已关闭、删除并确认释放：{profile_id}", "success")
        else:
            self.store.mark_pending(profile_id, "关闭/连接确认/删除/最终确认未全部完成")
        return complete

    def _profile_call(self, method_name: str, profile_id: str, workspace_id: str) -> Any:
        """Call profile lifecycle methods with the journaled workspace.

        Older fake clients and injected compatibility clients accept only the
        profile id. Retry those call signatures without weakening the
        workspace-aware path used by the real Roxy client.
        """
        method = getattr(self.client, method_name)
        try:
            return method(profile_id, workspace_id=workspace_id or None)
        except TypeError as exc:
            if "unexpected keyword argument" not in str(exc):
                raise
            return method(profile_id)

    def recover_pending(self, *, limit: int = 20) -> dict[str, int]:
        records = self.store.pending()[:max(0, int(limit))]
        recovered = 0
        failed = 0
        for record in records:
            if self.cleanup(record):
                recovered += 1
            else:
                failed += 1
        return {"examined": len(records), "recovered": recovered, "failed": failed}

    def recover_creation_intents(self, *, limit: int = 20) -> dict[str, int]:
        """Reconcile create requests whose HTTP response was lost.

        Only an exact ownership remark and window name match is eligible. An
        unmarked or ambiguous Roxy window is deliberately left untouched.
        """
        intents = self.store.intents()[:max(0, int(limit))]
        examined = recovered = failed = 0
        list_profiles = getattr(self.client, "list_profiles", None)
        list_connections = getattr(self.client, "list_connections", None)
        if not callable(list_profiles) and not callable(list_connections):
            return {"examined": len(intents), "recovered": 0, "failed": len(intents)}
        for intent in intents:
            examined += 1
            rows: list[Mapping[str, Any]] = []
            try:
                if callable(list_connections):
                    # Scan connections first: a create timeout can produce a
                    # ghost that is not yet (or no longer) present in the
                    # Profile list but still consumes a Roxy window slot.
                    rows.extend(list_connections(intent.workspace_id))
            except Exception as exc:
                self._log(f"Roxy 创建意图连接对账失败（{type(exc).__name__}）", "warn")
            try:
                if callable(list_profiles):
                    rows.extend(list_profiles(intent.workspace_id))
            except Exception as exc:
                self._log(f"Roxy 创建意图 Profile 对账失败（{type(exc).__name__}）", "warn")
            matched_by_id: dict[str, Mapping[str, Any]] = {}
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                if str(row.get("window_remark") or "") != intent.window_remark:
                    continue
                if str(row.get("window_name") or "") != intent.window_name:
                    continue
                profile_id = _safe_text(row.get("profile_id") or row.get("profileId") or row.get("dirId") or row.get("id"))
                if profile_id:
                    matched_by_id.setdefault(profile_id, row)
            matches = list(matched_by_id.values())
            if not matches:
                # The create may still be in flight. Keep the intent for the
                # next startup rather than guessing or deleting another user.
                failed += 1
                continue
            intent_ok = True
            for row in matches:
                profile_id = _safe_text(row.get("profile_id") or row.get("dirId") or row.get("id"))
                if not profile_id:
                    intent_ok = False
                    continue
                record = self.store.upsert(
                    profile_id,
                    workspace_id=row.get("workspace_id") or intent.workspace_id,
                    batch_id=intent.batch_id,
                    task_id=intent.task_id,
                    window_name=intent.window_name,
                    window_remark=intent.window_remark,
                    state="orphaned",
                )
                if not self.cleanup(record):
                    intent_ok = False
            if intent_ok:
                self.store.clear_intent(intent.intent_id)
                recovered += 1
            else:
                failed += 1
        return {"examined": examined, "recovered": recovered, "failed": failed}


__all__ = [
    "MANAGED_WINDOW_PREFIX", "MANAGED_WINDOW_REMARK", "RoxyCleanupRecord",
    "RoxyCreationIntent",
    "RoxyCleanupStore", "RoxyLifecycle", "STORE_VERSION",
]
