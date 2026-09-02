"""Private mailbox, proxy, result and task stores for Free registration."""

from __future__ import annotations

import copy
import json
import math
import os
from pathlib import Path
import re
import threading
import time
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

try:
    from .free_failure_runtime import (
        canonical_failure,
        merge_account_result_fields,
        normalize_password_result,
        sanitize_failure_text,
        sanitize_public_bool,
        sanitize_public_email,
        sanitize_public_http_status,
        sanitize_public_identifier,
        sanitize_public_number,
        sanitize_public_progress,
        sanitize_public_scheme,
        sanitize_public_status,
        sanitize_public_timestamp,
    )
    from .free_register_common import (
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeMailbox,
        FreeRegisterError,
        ProxyBinding,
        TERMINAL_STATUSES,
        atomic_write,
        fingerprint,
        mask_email,
        mask_proxy,
        normalize_proxy_value,
        parse_mailbox_line,
        proxy_error_detail,
    )
    from .free_proxy_store import FreeProxyPool as StructuredFreeProxyPool
except ImportError:
    from free_failure_runtime import (  # type: ignore[no-redef]
        canonical_failure,
        merge_account_result_fields,
        normalize_password_result,
        sanitize_failure_text,
        sanitize_public_bool,
        sanitize_public_email,
        sanitize_public_http_status,
        sanitize_public_identifier,
        sanitize_public_number,
        sanitize_public_progress,
        sanitize_public_scheme,
        sanitize_public_status,
        sanitize_public_timestamp,
    )
    from free_register_common import (  # type: ignore[no-redef]
        DEFAULT_FREE_PROXY_SCHEME,
        FREE_PROXY_SCHEMES,
        FreeMailbox,
        FreeRegisterError,
        ProxyBinding,
        TERMINAL_STATUSES,
        atomic_write,
        fingerprint,
        mask_email,
        mask_proxy,
        normalize_proxy_value,
        parse_mailbox_line,
        proxy_error_detail,
    )
    from free_proxy_store import FreeProxyPool as StructuredFreeProxyPool  # type: ignore[no-redef]


def _timestamp_number(value: Any, default: float = 0.0) -> float:
    try:
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value or "").strip()
        if text:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        pass
    return float(default)


ACTIVE_POOL_STATUSES = frozenset({"reserved", "queued", "running"})
FREE_EMAIL_429_COOLDOWN_SECONDS = 300


def _account_material_line(
    email: str,
    mailbox_url: str,
    result: Mapping[str, Any],
    *,
    include_password: bool = True,
) -> str:
    """Build the credential shape consumed by the ordinary mailbox flow.

    Password and URL are intentionally mutually exclusive in the first two
    fields.  A password-backed account is consumed as ``email----password``
    (or ``email----password----totp``); a passwordless account needs its
    private mailbox URL to fetch the next code (``email----url`` or
    ``email----url----totp``).  The URL is read from the selected private pool
    row at request time and never copied into a public task snapshot.
    """
    if not isinstance(result, Mapping):
        result = {}
    password = str(result.get("password") or "").strip()
    totp_secret = str(result.get("totp_secret") or "").strip()
    email_value = str(email or "").strip()
    mailbox_value = str(mailbox_url or "").strip()
    if include_password and password:
        fields = [email_value, password]
    else:
        fields = [email_value, mailbox_value]
    if totp_secret:
        fields.append(totp_secret)
    # A malformed historical row must not produce a dangling delimiter or
    # accidentally expose a password as a URL-only row.
    return "----".join(fields) if all(fields) else ""


def _cooldown_timestamp(value: Any) -> float:
    try:
        return max(0.0, float(value or 0))
    except (TypeError, ValueError):
        return 0.0


class FreeMailboxPool:
    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.pool_path = self.data_dir / "free_mailbox_pool.txt"
        self.state_path = self.data_dir / "free_mailbox_state.json"
        self.results_dir = self.data_dir / "free_register_results"
        self._lock = threading.RLock()

    def _state(self) -> dict[str, Any]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            value = {}
        rows = value.get("rows") if isinstance(value, dict) else {}
        return {"version": 2, "rows": rows if isinstance(rows, dict) else {}}

    def import_text(self, content: str) -> int:
        added, _skipped = self.import_text_with_stats(content)
        return added

    def import_text_with_stats(self, content: str) -> tuple[int, int]:
        incoming = self._parse_content(content)
        if not incoming:
            raise FreeRegisterError("free_pool", "Free 邮箱池", "Free 邮箱池没有有效的邮箱-取码 URL")
        with self._lock:
            existing = self.entries()
            existing_ids = {entry.row_id for entry in existing}
            combined: list[FreeMailbox] = []
            seen: set[str] = set()
            # Only genuinely new rows move to the top. Re-importing an old
            # row must preserve its existing position and state association.
            for entry in [
                *(item for item in incoming if item.row_id not in existing_ids),
                *existing,
            ]:
                if entry.row_id not in seen:
                    seen.add(entry.row_id)
                    combined.append(entry)
            added = sum(entry.row_id not in existing_ids for entry in incoming)
            self._write_entries(combined)
            state = self._state()
            fresh = [entry for entry in incoming if entry.row_id not in existing_ids]
            now = time.time()
            for index, entry in enumerate(fresh):
                row_state = state["rows"].setdefault(entry.row_id, {"email": entry.email, "mailbox_url": entry.mailbox_url, "status": "available"})
                row_state.setdefault("created_at", now + (len(fresh) - index) / 1_000_000)
            for entry in combined:
                state["rows"].setdefault(entry.row_id, {"email": entry.email, "mailbox_url": entry.mailbox_url, "status": "available", "created_at": now})
            atomic_write(self.state_path, state)
        return added, max(0, len(incoming) - added)

    def mark_next_batch_priority(self, row_ids: Sequence[str]) -> int:
        """Mark rows imported during an active run for the next dispatch.

        The marker is deliberately separate from ``import_text`` so a normal
        initial pool load keeps its historical file order.
        """
        requested = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        if not requested:
            return 0
        with self._lock:
            state = self._state()
            existing = {row.row_id for row in self.entries()}
            priorities: list[int] = []
            for row_state in state["rows"].values():
                if isinstance(row_state, Mapping):
                    try:
                        priorities.append(int(row_state.get("next_batch_priority") or 0))
                    except (TypeError, ValueError):
                        continue
            next_priority = max(priorities, default=0)
            marked = 0
            for row_id in requested:
                if row_id not in existing:
                    continue
                row = state["rows"].setdefault(row_id, {})
                if row.get("next_batch_priority"):
                    continue
                next_priority += 1
                row["next_batch_priority"] = next_priority
                marked += 1
            if marked:
                atomic_write(self.state_path, state)
            return marked

    def _write_entries(self, entries: Sequence[FreeMailbox]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.pool_path.write_text(
            "".join(f"{entry.email}----{entry.mailbox_url}\n" for entry in entries),
            encoding="utf-8",
        )
        os.chmod(self.pool_path, 0o600)

    def _parse_content(self, content: str) -> list[FreeMailbox]:
        entries: list[FreeMailbox] = []
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
            entries.append(FreeMailbox(row_id, line_no, email, mailbox_url))
        return entries

    def entries(self) -> list[FreeMailbox]:
        try:
            return self._parse_content(self.pool_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError):
            return []

    def _row_state(self, row_id: str) -> dict[str, Any]:
        return self._state()["rows"].get(row_id, {})

    def entry(self, row_id: str) -> FreeMailbox | None:
        target = str(row_id or "").strip().lower()
        return next((row for row in self.entries() if row.row_id == target), None)

    def available(self, count: int) -> list[FreeMailbox]:
        with self._lock:
            state = self._state()["rows"]
            now = time.time()
            available = [
                row for row in self.entries()
                if str(state.get(row.row_id, {}).get("status") or "available") == "available"
                and _cooldown_timestamp(state.get(row.row_id, {}).get("cooldown_until")) <= now
            ]
            if any(state.get(row.row_id, {}).get("next_batch_priority") for row in available):
                original_order = {row.row_id: index for index, row in enumerate(available)}
                def priority(row: FreeMailbox) -> int:
                    try:
                        return int(state.get(row.row_id, {}).get("next_batch_priority") or 0)
                    except (TypeError, ValueError):
                        return 0
                available.sort(key=lambda row: (
                    0 if state.get(row.row_id, {}).get("next_batch_priority") else 1,
                    priority(row),
                    original_order[row.row_id],
                ))
            return available[:max(0, int(count))]

    def reserve(self, rows: Sequence[FreeMailbox], batch_id: str) -> None:
        with self._lock:
            state = self._state()
            for row in rows:
                current = state["rows"].setdefault(row.row_id, {})
                if current.get("status") not in (None, "available") or _cooldown_timestamp(current.get("cooldown_until")) > time.time():
                    raise FreeRegisterError(
                        "free_pool_reserve", "预留 Free 邮箱", "Free 邮箱已被其他任务预留"
                    )
                current.update({
                    "email": row.email,
                    "mailbox_url": row.mailbox_url,
                    "status": "reserved",
                    "batch_id": batch_id,
                    "error": "",
                })
                current.pop("next_batch_priority", None)
                current.pop("failure", None)
            atomic_write(self.state_path, state)

    def update(self, row_id: str, **values: Any) -> None:
        with self._lock:
            state = self._state()
            row = state["rows"].setdefault(str(row_id), {})
            updates = {key: value for key, value in values.items() if value is not None}
            if "failure" in values:
                failure = canonical_failure(values.get("failure"))
                if failure is None:
                    row.pop("failure", None)
                else:
                    updates["failure"] = failure
            row.update(updates)
            atomic_write(self.state_path, state)

    def recover_reserved(self) -> int:
        """Release rows reserved before a process could create their tasks."""
        with self._lock:
            state = self._state()
            changed = 0
            for row in state["rows"].values():
                if not isinstance(row, Mapping) or row.get("status") != "reserved":
                    continue
                row.update({"status": "available", "batch_id": "", "stage": ""})
                row.pop("cooldown_until", None)
                changed += 1
            if changed:
                atomic_write(self.state_path, state)
            return changed

    def recover_interrupted(self, row_id: str, *, reusable: bool, failure: Mapping[str, Any] | None = None) -> None:
        """Persist a deterministic state for a task interrupted by restart."""
        with self._lock:
            state = self._state()
            row = state["rows"].setdefault(str(row_id), {})
            normalized = canonical_failure(failure)
            if reusable:
                row.update({
                    "status": "available", "batch_id": "", "stage": "", "error": "",
                    "driver": "", "proxy": "", "proxy_masked": "", "proxy_fingerprint": "",
                    "proxy_id": "", "proxy_scheme": "", "proxy_country": "", "proxy_group": "",
                    "expected_exit_ip": "", "registration_ip": "", "exit_ip": "",
                })
                if normalized is not None:
                    row.update({"error": normalized["public_message"], "failure": normalized})
            else:
                row.update({"status": "failed", "stage": "free_process_recovery", "error": "Free 进程重启，中断任务未完成"})
                if normalized is not None:
                    row.update({"error": normalized["public_message"], "failure": normalized})
            atomic_write(self.state_path, state)

    def save_result(self, row_id: str, result: Mapping[str, Any]) -> None:
        with self._lock:
            # A registration failure can arrive after a previous attempt has
            # already produced an account/token.  Keep the latest status and
            # diagnostic fields, but fill missing credential fields from the
            # durable record so a late failure cannot erase the account.
            try:
                existing = json.loads(
                    (self.results_dir / f"{fingerprint(row_id)}.json").read_text(encoding="utf-8")
                )
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                existing = {}
            payload = merge_account_result_fields(
                existing if isinstance(existing, Mapping) else {},
                result,
            )
            for key in ("failure", "plan_failure", "twofa_failure", "live_check_failure"):
                if key in payload:
                    normalized = canonical_failure(payload.get(key) if isinstance(payload.get(key), Mapping) else None)
                    if normalized is None:
                        payload.pop(key, None)
                    else:
                        payload[key] = normalized
            atomic_write(self.results_dir / f"{fingerprint(row_id)}.json", payload)

    def result(self, row_id: str) -> dict[str, Any]:
        payload, readable = self.result_with_status(row_id)
        return payload if readable else {}

    def result_with_status(self, row_id: str) -> tuple[dict[str, Any], bool]:
        """Read one private result and distinguish absence from corruption."""
        try:
            current = json.loads(
                (self.results_dir / f"{fingerprint(row_id)}.json").read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            return {}, True
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}, False
        if not isinstance(current, dict):
            return {}, False
        return dict(current), True

    def reveal_mailbox_url(self, row_id: str) -> str:
        row = self.entry(row_id)
        if row is None:
            raise FreeRegisterError(
                "free_mailbox_url", "读取 Free 取件地址", "Free 邮箱行不存在或已变化", retryable=False
            )
        return row.mailbox_url

    def delete(self, row_ids: Sequence[str]) -> int:
        requested = list(dict.fromkeys(str(value or "").strip().lower() for value in row_ids if str(value or "").strip()))
        if not requested:
            return 0
        with self._lock:
            entries = self.entries()
            by_id = {entry.row_id: entry for entry in entries}
            targets = [by_id[row_id] for row_id in requested if row_id in by_id]
            state = self._state()
            if any(str(state["rows"].get(row.row_id, {}).get("status") or "available") in ACTIVE_POOL_STATUSES for row in targets):
                raise FreeRegisterError(
                    "free_pool_delete",
                    "删除 Free 邮箱",
                    "选中的 Free 邮箱仍在排队或运行中，请等待任务结束后再删除",
                    retryable=False,
                )
            target_ids = {entry.row_id for entry in targets}
            self._write_entries([entry for entry in entries if entry.row_id not in target_ids])
            for row_id in target_ids:
                state["rows"].pop(row_id, None)
            atomic_write(self.state_path, state)
            return len(target_ids)

    def set_status(self, row_ids: Sequence[str], status: str) -> int:
        allowed = {"available", "unavailable", "draft", "pending_rerun"}
        if status not in allowed:
            raise FreeRegisterError("free_pool_status", "更新 Free 邮箱状态", "Free 邮箱状态无效", retryable=False)
        requested = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        with self._lock:
            existing = {entry.row_id for entry in self.entries()}
            state = self._state()
            targets = requested & existing
            if any(str(state["rows"].get(row_id, {}).get("status") or "available") in ACTIVE_POOL_STATUSES for row_id in targets):
                raise FreeRegisterError(
                    "free_pool_status", "更新 Free 邮箱状态", "运行中的 Free 邮箱不能修改状态", retryable=False
                )
            for row_id in targets:
                row = state["rows"].setdefault(row_id, {})
                row["status"] = status
                if status == "available":
                    row.pop("cooldown_until", None)
            atomic_write(self.state_path, state)
            return len(targets)

    def counts(self) -> dict[str, int]:
        rows = self.public_rows()
        counts = {"total": len(rows), "available": 0, "running": 0, "success": 0, "partial_success": 0, "failed": 0, "pending_rerun": 0, "draft": 0, "unavailable": 0, "twofa_pending": 0}
        for row in rows:
            status = str(row.get("status") or "available")
            if status in ACTIVE_POOL_STATUSES:
                counts["running"] += 1
            elif status in counts:
                counts[status] += 1
        return counts

    def public_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            state_doc = self._state()
            state = state_doc["rows"]
            output = []
            entries = self.entries()
            for position, row in enumerate(entries):
                current = state.get(row.row_id, {})
                if not isinstance(current, Mapping):
                    current = {}
                if not current.get("created_at"):
                    current = dict(current)
                    current["created_at"] = time.time() - position
                    state[row.row_id] = current
                result = self.result(row.row_id)
                current_status = sanitize_public_status(current.get("status"), default="available")
                if result:
                    result = normalize_password_result(result)
                if current_status in ACTIVE_POOL_STATUSES:
                    failure_source = current.get("failure")
                else:
                    failure_source = result.get("failure") if isinstance(result.get("failure"), Mapping) else current.get("failure")
                failure = canonical_failure(failure_source if isinstance(failure_source, Mapping) else None)
                plan_failure = canonical_failure(
                    result.get("plan_failure") if isinstance(result.get("plan_failure"), Mapping) else None,
                    default_node_code="free_plan_check",
                    default_node_label="查询 Free 套餐资格",
                )
                live_failure = canonical_failure(result.get("live_check_failure") if isinstance(result.get("live_check_failure"), Mapping) else None)
                has_password = bool(result.get("password"))
                has_totp = bool(result.get("totp_secret"))
                # A passwordless TOTP account still has a usable complete
                # material line: its mailbox URL is supplied on demand from
                # the private source row.  Do not require a persisted
                # ``credential_line`` (which deliberately omits that URL).
                has_credential = bool(result.get("credential_line")) or has_totp or has_password
                email_masked = sanitize_public_email(row.email)
                public_row_id = sanitize_public_identifier(row.row_id)
                public_line_no = sanitize_public_number(row.line_no, integer=True, minimum=1, default=0)
                public_stage = sanitize_public_identifier(current.get("stage"), limit=120)
                public_batch_id = sanitize_public_identifier(current.get("batch_id"), limit=160)
                public_driver = sanitize_public_identifier(
                    result.get("driver") or current.get("driver"), limit=40
                )
                public_proxy_fingerprint = sanitize_public_identifier(
                    current.get("proxy_fingerprint"), limit=160
                )
                public_proxy_id = sanitize_public_identifier(current.get("proxy_id"), limit=160)
                public_proxy_scheme = sanitize_public_scheme(current.get("proxy_scheme"))
                public_plan_status = sanitize_public_status(result.get("plan_check_status"))
                public_plan_task_id = sanitize_public_identifier(result.get("plan_check_task_id"), limit=160)
                public_plan_checked_at = sanitize_public_timestamp(result.get("plan_checked_at"), default="")
                public_plan_retry_until = sanitize_public_timestamp(result.get("plan_retry_after_until"), default=None)
                public_plan_http_status = sanitize_public_http_status(result.get("plan_http_status"), default=None)
                public_live_status = sanitize_public_status(result.get("live_check_status"))
                public_live_mode = sanitize_public_status(result.get("live_check_mode"))
                public_live_task_id = sanitize_public_identifier(result.get("live_check_task_id"), limit=160)
                public_live_checked_at = sanitize_public_timestamp(result.get("live_checked_at"), default="")
                public_live_http_status = sanitize_public_http_status(result.get("live_check_http_status"), default=None)
                public_twofa_status = sanitize_public_status(result.get("twofa_status"))
                public_source = sanitize_public_identifier(current.get("source"), limit=30)
                output.append({
                    "row_id": public_row_id,
                    "line_no": public_line_no,
                    "created_at": _timestamp_number(current.get("created_at"), time.time() - position),
                    # ``email`` is retained as a UI-compatible alias, but it
                    # is never the raw mailbox address in a public row.
                    "email": email_masked,
                    "email_masked": email_masked,
                    "subject_ref_fingerprint": fingerprint(row.email),
                    "status": current_status,
                    "cooldown_until": _cooldown_timestamp(current.get("cooldown_until")) or None,
                    "cooldown_remaining": max(0, int(_cooldown_timestamp(current.get("cooldown_until")) - time.time())),
                    "stage": public_stage,
                    "batch_id": public_batch_id,
                    "driver": public_driver,
                    "source": public_source,
                    "proxy_masked": sanitize_failure_text(current.get("proxy_masked", ""), 300),
                    "proxy_fingerprint": public_proxy_fingerprint,
                    "proxy_id": public_proxy_id,
                    "proxy_scheme": public_proxy_scheme,
                    # The Free allocator is a single healthy_random pool;
                    # retired country/group dimensions are never projected.
                    "proxy_country": "",
                    "proxy_group": "",
                    "profile_summary": sanitize_failure_text(result.get("profile_summary", ""), 300),
                    "account_flow": sanitize_failure_text(result.get("account_flow", ""), 120),
                    "plan_type": sanitize_failure_text(result.get("plan_type", ""), 120),
                    "subscription_plan": sanitize_failure_text(result.get("subscription_plan", ""), 120),
                    "has_active_subscription": sanitize_public_bool(result.get("has_active_subscription", False)),
                    "plus_trial_eligible": sanitize_public_bool(result.get("plus_trial_eligible", False)),
                    "eligible_campaign_id": sanitize_public_identifier(result.get("eligible_campaign_id", ""), limit=160),
                    "plan_check_status": public_plan_status,
                    "plan_check_task_id": public_plan_task_id,
                    "plan_source": sanitize_failure_text(result.get("plan_source", ""), 80),
                    "plan_checked_at": public_plan_checked_at,
                    "plan_retry_after_until": public_plan_retry_until,
                    "plan_error_code": sanitize_public_identifier(result.get("plan_error_code", ""), limit=160),
                    "plan_http_status": public_plan_http_status,
                    "plan_failure": plan_failure,
                    "live_check_status": public_live_status,
                    "live_check_mode": public_live_mode,
                    "live_check_task_id": public_live_task_id,
                    "live_checked_at": public_live_checked_at,
                    "live_check_token_refreshed": sanitize_public_bool(result.get("live_check_token_refreshed", False)),
                    "live_check_http_status": public_live_http_status,
                    "live_check_failure": live_failure,
                    "twofa_status": public_twofa_status,
                    "twofa_error": sanitize_failure_text(result.get("twofa_error", ""), 300),
                    "has_access_token": bool(result.get("access_token")),
                    "has_password": has_password,
                    "has_totp": has_totp,
                    "has_credential": has_credential,
                    "rebind_email": sanitize_public_email(result.get("rebind_email", "")),
                    "rebind_email_masked": sanitize_public_email(result.get("rebind_email", "")),
                    "rebind_task_id": sanitize_public_identifier(result.get("rebind_task_id", ""), limit=160),
                    "rebind_status": sanitize_public_status(result.get("rebind_status", "")),
                    "rebind_plan_type": sanitize_public_identifier(result.get("rebind_plan_type", ""), limit=120),
                    "rebind_plus_trial_eligible": sanitize_public_bool(result.get("rebind_plus_trial_eligible", False)),
                    "has_mailbox_url": True,
                    "task_id": sanitize_public_identifier(result.get("task_id", ""), limit=160),
                    "error": failure.get("public_message", "") if failure else sanitize_failure_text(current.get("error", "")),
                    "failure": failure,
                    # State rows can contain snapshots written by older
                    # workers. Keep the progress shape compatible while
                    # projecting nested timing through the shared public
                    # allowlist; private credentials must never ride along
                    # in a mailbox-list response.
                    "progress": sanitize_public_progress(current.get("progress")) if isinstance(current.get("progress"), Mapping) else None,
                })
            output.sort(key=lambda item: (_timestamp_number(item.get("created_at"), 0), str(item.get("row_id") or "")), reverse=True)
            for index, item in enumerate(output, 1):
                item["display_index"] = index
            atomic_write(self.state_path, state_doc)
            return output

    def export_success(self, row_ids: Sequence[str] = ()) -> str:
        selected = {str(value or "").strip().lower() for value in row_ids if str(value or "").strip()}
        values: list[str] = []
        for row in self.entries():
            if selected and row.row_id not in selected:
                continue
            result = self.result(row.row_id)
            if result.get("status") not in (None, "", "success") and not result.get("access_token"):
                continue
            credential = _account_material_line(row.email, row.mailbox_url, result)
            token = str(result.get("access_token") or "").strip()
            if credential or token:
                values.append(credential or f"{row.email}----{token}")
        return "\n".join(values)

    def build_transfer_content(
        self,
        row_ids: Sequence[str] = (),
        *,
        include_password: bool = True,
    ) -> dict[str, Any]:
        """Build ordinary mailbox-pool rows from explicitly selected Free rows."""
        requested = list(dict.fromkeys(
            str(value or "").strip().lower()
            for value in row_ids
            if str(value or "").strip()
        ))
        if not requested:
            return {
                "content": "",
                "selected": 0,
                "prepared": 0,
                "skipped": 1,
                "skipped_items": [{
                    "row_id": "",
                    "email": "",
                    "email_masked": "",
                    "reason": "没有提供有效的 Free 邮箱选择",
                }],
            }
        selected = set(requested)
        lines: list[str] = []
        skipped: list[dict[str, str]] = []
        state = self._state()["rows"]
        for row in self.entries():
            if selected and row.row_id not in selected:
                continue
            current = state.get(row.row_id, {}) if isinstance(state, Mapping) else {}
            status = str(current.get("status") or "available").strip().lower()
            if status in ACTIVE_POOL_STATUSES:
                skipped.append({"row_id": row.row_id, "email": mask_email(row.email), "email_masked": mask_email(row.email), "subject_ref_fingerprint": fingerprint(row.email), "reason": "该 Free 邮箱仍在注册或测活任务中"})
                continue
            result = self.result(row.row_id)
            live_status = str(result.get("live_check_status") or "").strip().lower()
            if live_status in {"queued", "running"}:
                skipped.append({"row_id": row.row_id, "email": mask_email(row.email), "email_masked": mask_email(row.email), "subject_ref_fingerprint": fingerprint(row.email), "reason": "该 Free 邮箱仍在测活中"})
                continue
            if not result:
                skipped.append({"row_id": row.row_id, "email": mask_email(row.email), "email_masked": mask_email(row.email), "subject_ref_fingerprint": fingerprint(row.email), "reason": "该 Free 邮箱没有注册结果，暂不可传输"})
                continue
            line = _account_material_line(
                row.email,
                row.mailbox_url,
                result,
                include_password=include_password,
            )
            if line:
                lines.append(line)
            else:
                skipped.append({"row_id": row.row_id, "email": mask_email(row.email), "email_masked": mask_email(row.email), "subject_ref_fingerprint": fingerprint(row.email), "reason": "该 Free 邮箱缺少可用账号凭据"})
        requested_missing = selected - {row.row_id for row in self.entries()}
        skipped.extend({"row_id": row_id, "email": "", "email_masked": "", "reason": "Free 邮箱行不存在或已变化"} for row_id in sorted(requested_missing))
        return {
            "content": "\n".join(lines),
            "selected": len(requested) if requested else len(lines),
            "prepared": len(lines),
            "skipped": len(skipped),
            "skipped_items": skipped,
        }


class FreeProxyPool:
    def __init__(self, data_dir: str | Path, *, default_scheme: str = DEFAULT_FREE_PROXY_SCHEME) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = self.data_dir / "free_proxy_pool.txt"
        scheme = str(default_scheme or DEFAULT_FREE_PROXY_SCHEME).strip().lower()
        self.default_scheme = scheme if scheme in FREE_PROXY_SCHEMES else DEFAULT_FREE_PROXY_SCHEME

    def import_text(self, content: str) -> int:
        incoming = [normalized for row in str(content or "").splitlines() if (normalized := normalize_proxy_value(row, default_scheme=self.default_scheme))]
        if not incoming:
            raise FreeRegisterError("free_proxy_pool", "Free 代理池", "Free 代理池没有有效代理")
        existing = self.values()
        seen = set(existing)
        valid = list(existing)
        for value in incoming:
            if value in seen:
                continue
            seen.add(value)
            valid.append(value)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(valid) + "\n", encoding="utf-8")
        os.chmod(self.path, 0o600)
        return len(valid) - len(existing)

    def values(self, content: str = "") -> list[str]:
        if content.strip():
            rows = content.splitlines()
        else:
            try:
                rows = self.path.read_text(encoding="utf-8").splitlines()
            except (FileNotFoundError, OSError, UnicodeError):
                rows = []
        return [normalized for row in rows if (normalized := normalize_proxy_value(row, default_scheme=self.default_scheme))]

    def public(self) -> dict[str, Any]:
        values = self.values()
        return {"count": len(values), "rows": [{"index": index, "masked": mask_proxy(value), "fingerprint": fingerprint(value)} for index, value in enumerate(values, 1)]}

    @staticmethod
    def _probe(proxy: str, target: str) -> str:
        from curl_cffi import requests as curl_requests

        session = curl_requests.Session(impersonate="chrome", verify=False)
        session.proxies = {"http": proxy, "https": proxy}
        try:
            response = session.get(target, headers={"Accept": "text/plain", "Cache-Control": "no-cache"}, timeout=12)
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()
        status = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= status < 300:
            raise ValueError(f"代理探测请求返回 HTTP {status}")
        value = bytes(getattr(response, "content", b"") or b"")[:128].decode("utf-8", "ignore").strip()
        if not re.fullmatch(r"[0-9a-fA-F:.]{3,64}", value):
            raise ValueError("代理探测响应格式无效")
        return value

    def bind(self, count: int, *, content: str = "", probe: Callable[[str, str], str] | None = None, probe_url: str = "https://chatgpt.com/", perform_probe: bool = True) -> list[ProxyBinding]:
        values = self.values(content)
        if not values:
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "Free 代理池没有有效代理", retryable=False)
        selected = [values[index % len(values)] for index in range(max(0, int(count)))]
        fingerprints = [fingerprint(value) for value in selected]
        check = probe or self._probe
        exit_ips: list[str] = []
        for index, value in enumerate(selected, 1):
            if not perform_probe:
                exit_ips.append("")
                continue
            try:
                exit_ips.append(str(check(value, probe_url)).strip())
            except FreeRegisterError:
                raise
            except Exception as exc:
                raise FreeRegisterError(
                    "free_proxy_preflight", "Free 代理预检",
                    f"代理池第 {index} 条代理探测失败：{proxy_error_detail(exc)}",
                ) from exc
        return [ProxyBinding(value, fp, mask_proxy(value), ip) for value, fp, ip in zip(selected, fingerprints, exit_ips)]

    def verify(self, binding: ProxyBinding, *, probe: Callable[[str, str], str] | None = None, probe_url: str = "https://chatgpt.com/") -> str:
        try:
            current = str((probe or self._probe)(binding.proxy, probe_url)).strip()
        except Exception as exc:
            raise FreeRegisterError("proxy_connect_failed", "代理连接失败", f"代理连通性检查失败：{proxy_error_detail(exc)}") from exc
        return current


class FreeTaskStore:
    def __init__(self, data_dir: str | Path) -> None:
        self.path = Path(data_dir).expanduser().resolve() / "tasks.json"
        self._lock = threading.RLock()

    def load(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                return {}
            tasks = payload.get("tasks") if isinstance(payload, Mapping) else {}
            return {str(key): dict(value) for key, value in tasks.items() if isinstance(value, Mapping)} if isinstance(tasks, Mapping) else {}

    def save(self, tasks: Mapping[str, Mapping[str, Any]]) -> None:
        with self._lock:
            atomic_write(self.path, {"version": 1, "tasks": copy.deepcopy(dict(tasks))})

    @staticmethod
    def _timing_number(value: Any, *, integer: bool = False) -> float | int | None:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(parsed):
            return None
        if not parsed or parsed < 0:
            return 0 if integer else 0.0
        return int(parsed) if integer else parsed

    @classmethod
    def _merge_timing_stage(cls, current: Mapping[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
        """Merge two immutable stage samples without allowing duration rollback."""
        result = copy.deepcopy(dict(current))
        for key, value in incoming.items():
            if key not in result or result.get(key) in (None, ""):
                result[key] = copy.deepcopy(value)

        for key in ("duration_ms", "visits", "attempt", "proxy_attempts"):
            values = [
                cls._timing_number(current.get(key), integer=True),
                cls._timing_number(incoming.get(key), integer=True),
            ]
            numeric = [value for value in values if value is not None]
            if numeric:
                result[key] = max(numeric)
        for key in ("elapsed_seconds",):
            values = [
                cls._timing_number(current.get(key)),
                cls._timing_number(incoming.get(key)),
            ]
            numeric = [value for value in values if value is not None]
            if numeric:
                result[key] = max(numeric)

        for key in ("started_at", "entered_at"):
            values = [
                cls._timing_number(current.get(key), integer=True),
                cls._timing_number(incoming.get(key), integer=True),
            ]
            numeric = [value for value in values if value]
            if numeric:
                result[key] = min(numeric)
        for key in ("finished_at", "left_at"):
            values = [
                cls._timing_number(current.get(key), integer=True),
                cls._timing_number(incoming.get(key), integer=True),
            ]
            numeric = [value for value in values if value]
            if numeric:
                result[key] = max(numeric)
        # A later completed sample carries the authoritative outcome and
        # failure metadata.  When wall-clock timestamps tie, a larger visit
        # count is the only monotonic signal available to identify it.
        current_finished = cls._timing_number(current.get("finished_at"), integer=True) or 0
        incoming_finished = cls._timing_number(incoming.get("finished_at"), integer=True) or 0
        current_seen = cls._timing_number(current.get("last_recorded_at"), integer=True) or 0
        incoming_seen = cls._timing_number(incoming.get("last_recorded_at"), integer=True) or 0
        current_visits = cls._timing_number(current.get("visits"), integer=True) or 0
        incoming_visits = cls._timing_number(incoming.get("visits"), integer=True) or 0
        incoming_is_newer = incoming_finished > current_finished or (
            incoming_finished == current_finished
            and (incoming_seen > current_seen or incoming_visits > current_visits)
        )
        for key in ("outcome", "failure_code", "retryable"):
            if key not in incoming or incoming.get(key) in (None, ""):
                continue
            # The current row comes from disk and may have been written by a
            # newer stage/terminal save.  On a tie, preserve it; only fill a
            # missing value or accept an explicitly newer timestamp.
            if incoming_is_newer or result.get(key) in (None, ""):
                result[key] = copy.deepcopy(incoming[key])
        return result

    @classmethod
    def _merge_timing(cls, current: Mapping[str, Any] | None, incoming: Mapping[str, Any]) -> dict[str, Any]:
        """Monotonically merge a checkpoint with a newer on-disk snapshot.

        Checkpoints are written after releasing the runtime manager lock, so a
        stage/terminal save can win the race while the old snapshot is in
        flight.  This merge is intentionally limited to timing fields and
        never changes task status or any other task data.
        """
        base = copy.deepcopy(dict(current)) if isinstance(current, Mapping) else {}
        candidate = copy.deepcopy(dict(incoming))
        for key, value in candidate.items():
            if key not in base or base.get(key) in (None, ""):
                base[key] = copy.deepcopy(value)

        for key in ("elapsed_ms", "queue_elapsed_seconds", "execution_elapsed_seconds"):
            values = [cls._timing_number(base.get(key)), cls._timing_number(candidate.get(key))]
            numeric = [value for value in values if value is not None]
            if numeric:
                base[key] = max(numeric)
        if "elapsed_seconds" in base or "elapsed_seconds" in candidate:
            values = [cls._timing_number(base.get("elapsed_seconds")), cls._timing_number(candidate.get("elapsed_seconds"))]
            numeric = [value for value in values if value is not None]
            if numeric:
                base["elapsed_seconds"] = max(numeric)
        for key in ("started_at", "queued_at", "execution_started_at"):
            values = [
                cls._timing_number(base.get(key), integer=True),
                cls._timing_number(candidate.get(key), integer=True),
            ]
            numeric = [value for value in values if value]
            if numeric:
                base[key] = min(numeric)
        finished_values = [
            cls._timing_number(base.get("finished_at"), integer=True),
            cls._timing_number(candidate.get("finished_at"), integer=True),
        ]
        finished_numeric = [value for value in finished_values if value]
        if finished_numeric:
            base["finished_at"] = max(finished_numeric)

        current_stages = base.get("stages") if isinstance(base.get("stages"), list) else []
        incoming_stages = candidate.get("stages") if isinstance(candidate.get("stages"), list) else []
        stage_rows: dict[tuple[str, int, int], dict[str, Any]] = {}
        stage_order: list[tuple[str, int, int]] = []
        for row in [*current_stages, *incoming_stages]:
            if not isinstance(row, Mapping):
                continue
            code = str(row.get("code") or "")
            try:
                attempt = int(row.get("attempt") or 0)
            except (TypeError, ValueError):
                attempt = 0
            try:
                started = int(row.get("started_at") or row.get("entered_at") or 0)
            except (TypeError, ValueError):
                started = 0
            identity = (code, attempt, started)
            if identity not in stage_rows:
                stage_order.append(identity)
                stage_rows[identity] = copy.deepcopy(dict(row))
            else:
                stage_rows[identity] = cls._merge_timing_stage(stage_rows[identity], row)
        order_index = {identity: index for index, identity in enumerate(stage_order)}
        stage_order.sort(key=lambda identity: (identity[2] or 2**63 - 1, order_index[identity]))
        if stage_rows:
            base["stages"] = [stage_rows[identity] for identity in stage_order][-200:]

        current_substeps = base.get("substeps") if isinstance(base.get("substeps"), list) else []
        incoming_substeps = candidate.get("substeps") if isinstance(candidate.get("substeps"), list) else []
        substep_rows: dict[str, dict[str, Any]] = {}
        substep_order: list[str] = []
        for row in [*current_substeps, *incoming_substeps]:
            if not isinstance(row, Mapping):
                continue
            identity = str(row.get("key") or f"{row.get('stage_code') or ''}:{row.get('code') or ''}")
            if not identity:
                continue
            if identity not in substep_rows:
                substep_order.append(identity)
                substep_rows[identity] = copy.deepcopy(dict(row))
                continue
            existing = substep_rows[identity]
            merged = cls._merge_timing_stage(existing, row)
            for key in ("first_duration_ms",):
                first_values = [
                    cls._timing_number(existing.get(key), integer=True),
                    cls._timing_number(row.get(key), integer=True),
                ]
                numeric = [value for value in first_values if value is not None]
                if numeric:
                    merged[key] = min(numeric)
            for key in ("max_duration_ms",):
                max_values = [
                    cls._timing_number(existing.get(key), integer=True),
                    cls._timing_number(row.get(key), integer=True),
                ]
                numeric = [value for value in max_values if value is not None]
                if numeric:
                    merged[key] = max(numeric)
            existing_seen = cls._timing_number(existing.get("last_recorded_at"), integer=True) or 0
            incoming_seen = cls._timing_number(row.get("last_recorded_at"), integer=True) or 0
            existing_visits = cls._timing_number(existing.get("visits"), integer=True) or 0
            incoming_visits = cls._timing_number(row.get("visits"), integer=True) or 0
            if incoming_seen > existing_seen or (
                incoming_seen == existing_seen and incoming_visits > existing_visits
            ):
                for key in ("last_duration_ms", "last_recorded_at", "outcome"):
                    if key in row and row.get(key) not in (None, ""):
                        merged[key] = copy.deepcopy(row[key])
            substep_rows[identity] = merged
        if substep_rows:
            base["substeps"] = [substep_rows[identity] for identity in substep_order]

        candidates = [base.get("slowest_node"), candidate.get("slowest_node")]
        slowest = [row for row in candidates if isinstance(row, Mapping)]
        if slowest:
            base["slowest_node"] = copy.deepcopy(max(slowest, key=lambda row: int(cls._timing_number(row.get("duration_ms"), integer=True) or 0)))
        return base

    def save_timing(
        self,
        task_id: str,
        timing: Mapping[str, Any],
        *,
        skip_terminal: bool = True,
    ) -> bool:
        """Merge one diagnostic timing snapshot without rewriting task state.

        Adapter callbacks are frequent and can run concurrently with a task
        completion callback.  A normal ``save(tasks)`` from a callback would
        serialize the whole in-memory task table while the manager lock is
        held, and could also overwrite a newer status written by another
        worker.  This narrow read/modify/write keeps every non-timing field
        from the current on-disk snapshot and refuses to apply a stale
        checkpoint after a task reaches a terminal state.

        The return value is false when the task is absent or terminal and the
        checkpoint was intentionally skipped.  Storage errors still propagate
        so callers can report a diagnostic-only warning without changing the
        registration outcome.
        """
        normalized_id = str(task_id or "").strip()
        if not normalized_id or not isinstance(timing, Mapping):
            return False
        with self._lock:
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
                return False
            if not isinstance(payload, Mapping):
                return False
            raw_tasks = payload.get("tasks")
            if not isinstance(raw_tasks, Mapping):
                return False
            current = raw_tasks.get(normalized_id)
            if not isinstance(current, Mapping):
                return False
            status = str(current.get("status") or "").strip().lower()
            if skip_terminal and status in TERMINAL_STATUSES:
                return False
            tasks = {
                str(key): dict(value)
                for key, value in raw_tasks.items()
                if isinstance(value, Mapping)
            }
            merged = tasks.get(normalized_id)
            if merged is None:
                return False
            merged["timing"] = self._merge_timing(merged.get("timing"), timing)
            tasks[normalized_id] = merged
            version = payload.get("version")
            try:
                version_value = int(version) if version is not None else 1
            except (TypeError, ValueError):
                version_value = 1
            atomic_write(self.path, {"version": version_value, "tasks": tasks})
            return True


# Keep the historical import path while moving all runtime calls to the
# structured Free-only resource store.
FreeProxyPool = StructuredFreeProxyPool

__all__ = [
    "FreeMailboxPool",
    "FreeProxyPool",
    "FreeTaskStore",
    "merge_account_result_fields",
]
