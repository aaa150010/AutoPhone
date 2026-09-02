"""Compatibility adapters that move Free runtime stores onto SQLite.

The restored Free manager still speaks to the historical ``FreeMailboxPool``,
``FreeProxyPool`` and ``FreeTaskStore`` APIs.  This module keeps those APIs
stable while making SQLite the only mutable source of truth.  The adapters are
deliberately thin: mailbox/task result projection and the mature proxy
selection/health policy continue to come from the existing compatibility
classes, while their ``_load``/``_save`` boundaries are redirected to the
transactional :class:`~mac_overrides.free_storage.FreeSQLiteStore`.

No legacy JSON/TXT file is written by these classes.  ``FreeSQLiteStore``
performs the one-shot, read-only import when it is constructed.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
import copy
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import unquote, urlsplit

try:
    from .free_failure_runtime import canonical_failure, merge_account_result_fields, normalize_password_result
    from .free_register_common import (
        FreeMailbox,
        FreeRegisterError,
        ProxyBinding,
        TERMINAL_STATUSES,
        fingerprint,
        mask_email,
        mask_proxy,
        parse_mailbox_line,
        safe_log_message,
    )
    from .free_register_store import FreeMailboxPool as _LegacyMailboxPool
    from .free_register_store import FreeTaskStore as _LegacyTaskStore, _account_material_line
    from .free_proxy_store import FreeProxyPool as _LegacyProxyPool
    from .free_storage import FreeSQLiteStore, RevisionConflict, _partition_json, _stored_bool
    from .remail_api import remail_order_expired, remail_pickup_url
except ImportError:  # pragma: no cover - recovery imports
    from free_failure_runtime import canonical_failure, merge_account_result_fields, normalize_password_result  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FreeMailbox,
        FreeRegisterError,
        ProxyBinding,
        TERMINAL_STATUSES,
        fingerprint,
        mask_email,
        mask_proxy,
        parse_mailbox_line,
        safe_log_message,
    )
    from free_register_store import FreeMailboxPool as _LegacyMailboxPool  # type: ignore[no-redef]
    from free_register_store import FreeTaskStore as _LegacyTaskStore, _account_material_line  # type: ignore[no-redef]
    from free_proxy_store import FreeProxyPool as _LegacyProxyPool  # type: ignore[no-redef]
    from free_storage import FreeSQLiteStore, RevisionConflict, _partition_json, _stored_bool  # type: ignore[no-redef]
    from remail_api import remail_order_expired, remail_pickup_url  # type: ignore[no-redef]


_ACTIVE_MAILBOX_STATUSES = frozenset({"reserved", "queued", "running"})
_TERMINAL_TASK_STATUSES = frozenset(TERMINAL_STATUSES)
_MAILBOX_TRANSIENT_KEYS = frozenset({
    "lease_confirmed",
    "lease_confirmed_at",
    "task_id",
    "batch_id",
    "driver",
})


def _json_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return {}


def _compat_timestamp(value: Any, default: int = 0) -> int:
    """Normalize SQLite ISO timestamps to the legacy manager's epoch shape."""
    if isinstance(value, bool):
        return int(value)
    try:
        return int(float(value))
    except (TypeError, ValueError):
        pass
    text = str(value or "").strip()
    if text:
        try:
            return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
        except (TypeError, ValueError, OverflowError):
            pass
    return int(default)


def _row_payload(row: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(row, Mapping):
        return {}
    payload = _json_payload(row.get("payload"))
    for key in (
        "row_id",
        "email",
        "mailbox_url",
        "status",
        "batch_id",
        "lease_owner",
        "lease_until",
        "revision",
        "created_at",
        "updated_at",
    ):
        if key in row:
            payload[key] = copy.deepcopy(row.get(key))
    return payload


class SQLiteFreeMailboxPool(_LegacyMailboxPool):
    """SQLite-backed implementation of the historical mailbox pool API."""

    def __init__(self, data_dir: str | Path, *, storage: FreeSQLiteStore | None = None) -> None:
        # The parent constructor only establishes paths/locks; it does not
        # read files.  Keep its public attributes for older callers, but every
        # overridden mutator below writes through ``storage``.
        super().__init__(data_dir)
        self.storage = storage or FreeSQLiteStore(self.data_dir)
        self.path = self.storage.path

    def _state(self) -> dict[str, Any]:
        rows: dict[str, dict[str, Any]] = {}
        for item in self.storage.list_mailboxes(limit=10_000):
            row_id = str(item.get("row_id") or "")
            if not row_id:
                continue
            rows[row_id] = _row_payload(item)
        return {"version": 3, "rows": rows}

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

    @staticmethod
    def _pool_order(row: Mapping[str, Any], fallback: int) -> tuple[int, int]:
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
        try:
            # New imports carry an order marker so the historical "new rows
            # first" projection survives restarts and same-millisecond writes.
            return (0, int(payload.get("_pool_order")))
        except (TypeError, ValueError):
            return (1, int(fallback))

    def _ordered_rows(self) -> list[dict[str, Any]]:
        rows = self.storage.list_mailboxes(limit=10_000)
        return [
            row
            for _index, row in sorted(
                enumerate(rows),
                key=lambda item: self._pool_order(item[1], item[0]),
            )
        ]

    def entries(self) -> list[FreeMailbox]:
        rows = self._ordered_rows()
        entries: list[FreeMailbox] = []
        for index, row in enumerate(rows, 1):
            entries.append(
                FreeMailbox(
                    str(row.get("row_id") or ""),
                    index,
                    str(row.get("email") or ""),
                    str(row.get("mailbox_url") or ""),
                )
            )
        return entries

    def _row_state(self, row_id: str) -> dict[str, Any]:
        row = self.storage.get_mailbox(str(row_id or "").strip())
        return _row_payload(row)

    def entry(self, row_id: str) -> FreeMailbox | None:
        target = str(row_id or "").strip()
        return next((item for item in self.entries() if item.row_id == target), None)

    def import_text_with_stats(self, content: str) -> tuple[int, int]:
        incoming = self._parse_content(content)
        if not incoming:
            raise FreeRegisterError(
                "free_pool", "Free 邮箱池", "Free 邮箱池没有有效的邮箱-取码 URL"
            )
        added = 0
        skipped = 0
        with self._lock:
            existing_orders: list[int] = []
            for row in self.storage.list_mailboxes(limit=10_000):
                payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
                try:
                    existing_orders.append(int(payload.get("_pool_order")))
                except (TypeError, ValueError):
                    continue
            # Leave room before the current first row for this import batch;
            # the input order is preserved within the batch.
            next_order = min(existing_orders, default=0) - len(incoming)
            for entry in incoming:
                existing = self.storage.get_mailbox(entry.row_id)
                if existing is not None:
                    skipped += 1
                    continue
                self.storage.upsert_mailbox(
                    row_id=entry.row_id,
                    email=entry.email,
                    mailbox_url=entry.mailbox_url,
                    status="available",
                    payload={
                        "line_no": entry.line_no,
                        "_pool_order": next_order + added,
                    },
                )
                added += 1
        return added, skipped

    def import_text(self, content: str) -> int:
        return self.import_text_with_stats(content)[0]

    def import_remail_order(self, order: Mapping[str, Any]) -> dict[str, Any]:
        """Insert one long-lived Remail order as a Free mailbox resource."""
        order_no = str(order.get("orderNo") or order.get("order_no") or "").strip()
        email = str(order.get("deliveryEmail") or order.get("delivery_email") or "").strip().lower()
        payload = order.get("payload") if isinstance(order.get("payload"), Mapping) else {}
        token = str(order.get("serviceToken") or order.get("service_token") or payload.get("serviceToken") or payload.get("service_token") or "").strip()
        if not order_no or not email or not token:
            raise FreeRegisterError("remail_order_credentials", "导入 Remail 订单", "订单缺少交付邮箱或服务凭证", retryable=False)
        row_id = fingerprint(f"remail:{order_no}")
        payload = {**dict(payload), **dict(order)}
        payload.update({"source": "remail", "order_no": order_no, "service_token": token, "remail_order_no": order_no, "email": email})
        self.storage.upsert_remail_order(payload)
        row = self.storage.upsert_mailbox(
            row_id=row_id,
            email=email,
            mailbox_url="https://remail.aishop6.com/v1/pickup",
            status="available",
            payload=payload,
        )
        self.storage.mark_remail_order_imported(order_no, row_id)
        return row

    def mark_next_batch_priority(self, row_ids: Sequence[str]) -> int:
        requested = {
            str(value or "").strip() for value in row_ids if str(value or "").strip()
        }
        if not requested:
            return 0
        current_rows = self._ordered_rows()
        priorities = []
        for row in current_rows:
            payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
            try:
                priorities.append(int(payload.get("next_batch_priority") or 0))
            except (TypeError, ValueError):
                pass
        next_priority = max(priorities, default=0)
        marked = 0
        for row_id in requested:
            row = self.storage.get_mailbox(row_id)
            if row is None:
                continue
            payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
            if payload.get("next_batch_priority"):
                continue
            next_priority += 1
            self.storage.update_mailbox(
                row_id,
                payload_patch={"next_batch_priority": next_priority},
            )
            marked += 1
        return marked

    def available(self, count: int) -> list[FreeMailbox]:
        rows = []
        for row in self._ordered_rows():
            payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
            if str(payload.get("source") or "").strip().lower() == "remail" and remail_order_expired(payload):
                if str(row.get("status") or "available") not in _ACTIVE_MAILBOX_STATUSES:
                    self.storage.update_mailbox(
                        str(row.get("row_id") or ""),
                        status="unavailable",
                        payload_patch={"remail_expired": True, "error": "Remail 订单已过期"},
                    )
                continue
            rows.append(row)
        rows = [
            row for row in rows
            if str(row.get("status") or "available") == "available"
            # A stale/manual status reset must not turn an already-submitted
            # mailbox back into a fresh-registration candidate.  Explicit
            # rerun goes through ``reserve_mailboxes`` which clears this marker
            # at its intentional reset boundary.
            and not _stored_bool(
                (row.get("payload") or {}).get("lease_confirmed")
                if isinstance(row.get("payload"), Mapping)
                else False
            )
        ][:10_000]
        now = time.time()
        selected: list[tuple[int, int, FreeMailbox]] = []
        for index, row in enumerate(rows):
            payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
            try:
                cooldown = float(payload.get("cooldown_until") or 0)
            except (TypeError, ValueError):
                cooldown = 0
            if cooldown > now:
                continue
            try:
                priority = int(payload.get("next_batch_priority") or 0)
            except (TypeError, ValueError):
                priority = 0
            selected.append(
                (
                    0 if priority else 1,
                    priority or index,
                    FreeMailbox(
                        str(row.get("row_id") or ""),
                        index + 1,
                        str(row.get("email") or ""),
                        str(row.get("mailbox_url") or ""),
                    ),
                )
            )
        selected.sort(key=lambda item: (item[0], item[1], item[2].line_no, item[2].row_id))
        return [item[2] for item in selected[: max(0, int(count))]]

    def reserve(self, rows: Sequence[FreeMailbox], batch_id: str) -> None:
        # Validate and update the complete selection in one SQLite
        # transaction.  The old row-by-row implementation could leave the
        # first mailboxes reserved when a later row lost a race.
        for mailbox in rows:
            state = self._row_state(mailbox.row_id)
            if str(state.get("source") or "").strip().lower() == "remail" and remail_order_expired(state):
                self.storage.update_mailbox(
                    mailbox.row_id,
                    status="unavailable",
                    payload_patch={"remail_expired": True, "error": "Remail 订单已过期"},
                )
                raise FreeRegisterError(
                    "free_pool_reserve", "预留 Free 邮箱", "Remail 订单已过期，不能继续分配", retryable=False,
                )
        reserved = self.storage.reserve_mailboxes(
            [
                {
                    "row_id": mailbox.row_id,
                    "email": mailbox.email,
                    "mailbox_url": mailbox.mailbox_url,
                }
                for mailbox in rows
            ],
            batch_id=str(batch_id or ""),
        )
        if not reserved:
            raise FreeRegisterError(
                "free_pool_reserve", "预留 Free 邮箱", "Free 邮箱已被其他任务预留"
            )

    def update(self, row_id: str, **values: Any) -> None:
        target = str(row_id or "").strip()
        if not target:
            return
        scalar_status = values.pop("status", None)
        scalar_batch = values.pop("batch_id", None)
        if "failure" in values:
            failure = canonical_failure(values.get("failure"))
            values["failure"] = failure
        # ``None`` means clear a field for the historical API.  The storage
        # patch accepts it as JSON null; lifecycle fields are guarded while a
        # live lease is present.
        self.storage.update_mailbox(
            target,
            status=str(scalar_status) if scalar_status is not None else None,
            batch_id=str(scalar_batch) if scalar_batch is not None else None,
            payload_patch=values,
            # A worker's terminal transition is authoritative even while its
            # lease is still held; non-terminal progress updates remain
            # lifecycle-protected until the coordinator releases the claim.
            allow_active_status=str(scalar_status or "").strip().lower()
            in {"success", "partial_success", "failed", "stopped", "twofa_pending", "pending_rerun"},
        )

    def recover_reserved(self) -> int:
        changed = 0
        for row in self.storage.list_mailboxes(status="reserved", limit=10_000):
            payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
            # A confirmed row may have lost its lease sidecar during a crash.
            # Keep it non-dispatchable; only an explicit reserve/rerun path may
            # clear the durable confirmation marker.
            if _stored_bool(payload.get("lease_confirmed")):
                continue
            if self.storage.update_mailbox(row["row_id"], status="available", batch_id="", payload_patch={"stage": ""}):
                changed += 1
        return changed

    def recover_interrupted(self, row_id: str, *, reusable: bool, failure: Mapping[str, Any] | None = None) -> None:
        current = self.storage.get_mailbox(str(row_id or "").strip())
        current_payload = current.get("payload") if isinstance(current, Mapping) and isinstance(current.get("payload"), Mapping) else {}
        if _stored_bool(current_payload.get("lease_confirmed")):
            # The process-recovery path does not have enough task identity to
            # prove that a confirmed marker is safe to clear. Preserve it and
            # let the explicit pending-rerun flow handle the row.
            return
        normalized = canonical_failure(failure)
        target_status = "available" if reusable else "failed"
        patch: dict[str, Any] = {
            "stage": "" if reusable else "free_process_recovery",
            "error": "" if reusable else "Free 进程重启，中断任务未完成",
        }
        if normalized is not None:
            patch.update({"error": normalized["public_message"], "failure": normalized})
        if reusable:
            patch.update({key: "" for key in ("driver", "proxy", "proxy_masked", "proxy_fingerprint", "proxy_id", "proxy_scheme", "proxy_country", "proxy_group", "expected_exit_ip", "registration_ip", "exit_ip")})
        self.storage.update_mailbox(str(row_id), status=target_status, batch_id="", payload_patch=patch)

    def save_result(self, row_id: str, result: Mapping[str, Any]) -> None:
        target = str(row_id or "").strip()
        if not target:
            return
        existing_row = self.storage.get_result(target)
        existing = existing_row.get("payload") if isinstance(existing_row, Mapping) else {}
        merged = merge_account_result_fields(
            existing if isinstance(existing, Mapping) else {}, result
        )
        for key in ("failure", "plan_failure", "twofa_failure", "live_check_failure"):
            if key in merged:
                normalized = canonical_failure(
                    merged.get(key) if isinstance(merged.get(key), Mapping) else None
                )
                if normalized is None:
                    merged.pop(key, None)
                else:
                    merged[key] = normalized
        self.storage.save_result(target, merged)

    def result(self, row_id: str) -> dict[str, Any]:
        row = self.storage.get_result(str(row_id or ""))
        payload = row.get("payload") if isinstance(row, Mapping) else {}
        return copy.deepcopy(dict(payload)) if isinstance(payload, Mapping) else {}

    def result_with_status(self, row_id: str) -> tuple[dict[str, Any], bool]:
        row = self.storage.get_result(str(row_id or ""))
        if row is None:
            return {}, True
        payload = row.get("payload")
        return (copy.deepcopy(dict(payload)), True) if isinstance(payload, Mapping) else ({}, False)

    def reveal_mailbox_url(self, row_id: str) -> str:
        row = self.storage.get_mailbox(str(row_id or "").strip())
        if row is None:
            raise FreeRegisterError(
                "free_mailbox_url", "读取 Free 取件地址", "Free 邮箱行不存在或已变化", retryable=False
            )
        mailbox_url = str(row.get("mailbox_url") or "").strip()
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
        if str(payload.get("source") or "").strip().lower() == "remail":
            token = str(payload.get("service_token") or payload.get("serviceToken") or "").strip()
            try:
                return remail_pickup_url(mailbox_url, str(row.get("email") or ""), token)
            except ValueError as exc:
                raise FreeRegisterError(
                    "free_mailbox_url", "读取 Free 取件地址", "Remail 订单缺少有效取件凭证", retryable=False,
                ) from exc
        return mailbox_url

    def release(self, row_id: str, *, owner: str = "", reusable: bool = True) -> bool:
        """Compatibility release helper used by adapters and maintenance code."""
        target = str(row_id or "").strip()
        owner_value = str(owner or "").strip()
        if owner_value:
            released = self.storage.release_mailbox_lease(
                target, owner=owner_value, reusable=reusable
            )
            if released:
                return True
            # A failed owner-bound release must never fall through to the
            # legacy unowned cleanup path while another worker still owns the
            # row.  That race would clear a live reservation (or a confirmed
            # hand-off) and make the mailbox available to a second task.
            current = self.storage.get_mailbox(target)
            if current is None:
                return False
            payload = current.get("payload") if isinstance(current.get("payload"), Mapping) else {}
            current_owner = str(current.get("lease_owner") or "").strip()
            try:
                lease_until = float(current.get("lease_until") or 0)
            except (TypeError, ValueError):
                lease_until = 0.0
            bound_task = str(payload.get("task_id") or "").strip()
            confirmed = bool(payload.get("lease_confirmed"))
            # Keep an active lease or an explicitly confirmed task owner
            # immutable for callers that do not own it.  An expired lease with
            # no confirmed task can still use the historical cleanup fallback
            # to recover a crashed worker's row.
            if (current_owner and lease_until > time.time() and current_owner != owner_value) or (
                confirmed and bound_task and bound_task != owner_value
            ):
                return False
        row = self.storage.get_mailbox(target)
        if row is None:
            return False
        confirmed = bool((row.get("payload") or {}).get("lease_confirmed"))
        if confirmed:
            return bool(
                self.storage.update_mailbox(target, status="pending_rerun", batch_id="")
            )
        if reusable:
            return bool(
                self.storage.update_mailbox(
                    target,
                    status="available",
                    batch_id="",
                    payload_patch={key: None for key in _MAILBOX_TRANSIENT_KEYS},
                )
            )
        return bool(self.storage.update_mailbox(target, status="failed"))

    def delete(self, row_ids: Sequence[str]) -> int:
        requested = list(dict.fromkeys(str(value or "").strip() for value in row_ids if str(value or "").strip()))
        if not requested:
            return 0
        placeholders = ",".join("?" for _ in requested)
        with self.storage._transaction():  # noqa: SLF001 - adapter boundary
            with self.storage._connection() as db:  # noqa: SLF001
                db.execute("BEGIN IMMEDIATE")
                try:
                    rows = db.execute(
                        f"SELECT row_id,status FROM mailboxes WHERE row_id IN ({placeholders})",
                        requested,
                    ).fetchall()
                    if any(str(row["status"] or "") in _ACTIVE_MAILBOX_STATUSES for row in rows):
                        raise FreeRegisterError(
                            "free_pool_delete", "删除 Free 邮箱",
                            "选中的 Free 邮箱仍在排队或运行中，请等待任务结束后再删除",
                            retryable=False,
                        )
                    ids = [str(row["row_id"]) for row in rows]
                    if ids:
                        marks = ",".join("?" for _ in ids)
                        db.execute(
                            f"DELETE FROM resource_leases WHERE resource_type='mailbox' AND resource_id IN ({marks})",
                            ids,
                        )
                        deleted = db.execute(
                            f"DELETE FROM mailboxes WHERE row_id IN ({marks})", ids
                        ).rowcount
                    else:
                        deleted = 0
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return int(deleted or 0)

    def set_status(self, row_ids: Sequence[str], status: str) -> int:
        allowed = {"available", "unavailable", "draft", "pending_rerun"}
        if status not in allowed:
            raise FreeRegisterError("free_pool_status", "更新 Free 邮箱状态", "Free 邮箱状态无效", retryable=False)
        changed = 0
        requested = {
            str(value or "").strip()
            for value in row_ids
            if str(value or "").strip()
        }
        # Validate the complete selection before writing any row.  A durable
        # confirmation marker means the address crossed the upstream submit
        # boundary; changing only its scalar status to ``available`` would
        # leave a misleading UI row that ``available()`` and ``claim_mailbox``
        # correctly refuse to dispatch.  Explicit rerun is the sole reset
        # boundary and goes through ``reserve_mailboxes`` instead.
        existing_rows: dict[str, dict[str, Any]] = {}
        for row_id in requested:
            row = self.storage.get_mailbox(row_id)
            if row is None:
                continue
            existing_rows[row_id] = row
            if str(row.get("status") or "") in _ACTIVE_MAILBOX_STATUSES:
                raise FreeRegisterError("free_pool_status", "更新 Free 邮箱状态", "运行中的 Free 邮箱不能修改状态", retryable=False)
        if status == "available":
            confirmed = [
                row_id
                for row_id, row in existing_rows.items()
                if _stored_bool(
                    (row.get("payload") or {}).get("lease_confirmed")
                    if isinstance(row.get("payload"), Mapping)
                    else False
                )
            ]
            if confirmed:
                raise FreeRegisterError(
                    "free_pool_status",
                    "更新 Free 邮箱状态",
                    "已确认提交的 Free 邮箱不能手动恢复为可用，请使用显式重跑",
                    retryable=False,
                    error_code="free_pool_confirmed_requires_rerun",
                    action_hint="使用显式重跑入口，由系统通过预留操作清除确认标记",
                )
        for row_id in existing_rows:
            row = existing_rows[row_id]
            if self.storage.update_mailbox(row_id, status=status):
                changed += 1
        return changed

    def counts(self) -> dict[str, int]:
        counts = {
            "total": 0,
            "available": 0,
            "running": 0,
            "success": 0,
            "partial_success": 0,
            "failed": 0,
            "pending_rerun": 0,
            "draft": 0,
            "unavailable": 0,
            "twofa_pending": 0,
        }
        for row in self.storage.list_mailboxes(limit=10_000):
            counts["total"] += 1
            status = str(row.get("status") or "available")
            key = "running" if status in _ACTIVE_MAILBOX_STATUSES else status
            if key in counts:
                counts[key] += 1
        return counts

    def public_rows(self) -> list[dict[str, Any]]:
        # Reuse the established result/status projection, then enforce the
        # SQLite public boundary for mailbox identity and URL fields.
        rows = super().public_rows()
        for row in rows:
            # The legacy projection already applies the canonical Free email
            # mask.  Re-masking that display value here would progressively
            # distort short local parts (for example ``ab@`` -> ``a****@``),
            # so only normalize when an injected parent projection omitted
            # the explicit ``email_masked`` field.
            display = str(row.get("email_masked") or row.get("email") or "")
            if not row.get("email_masked"):
                display = mask_email(display)
            row["email"] = display
            row["email_masked"] = display
            row["mailbox_url"] = "********" if row.get("has_mailbox_url") else ""
        return rows

    def export_success(self, row_ids: Sequence[str] = ()) -> str:
        selected = {
            str(value or "").strip().lower()
            for value in row_ids
            if str(value or "").strip()
        }
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
        """Build ordinary mailbox-pool rows from selected Free accounts."""
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
        rows = self.entries()
        known = {row.row_id for row in rows}
        lines: list[str] = []
        skipped: list[dict[str, str]] = []
        for row in rows:
            if row.row_id not in selected:
                continue
            state = self._row_state(row.row_id)
            status = str(state.get("status") or "available").strip().lower()
            if status in _ACTIVE_MAILBOX_STATUSES:
                skipped.append({
                    "row_id": row.row_id,
                    "email": mask_email(row.email),
                    "email_masked": mask_email(row.email),
                    "subject_ref_fingerprint": fingerprint(row.email),
                    "reason": "该 Free 邮箱仍在注册或测活任务中",
                })
                continue
            result = self.result(row.row_id)
            live_status = str(result.get("live_check_status") or "").strip().lower()
            if live_status in {"queued", "running"}:
                skipped.append({
                    "row_id": row.row_id,
                    "email": mask_email(row.email),
                    "email_masked": mask_email(row.email),
                    "subject_ref_fingerprint": fingerprint(row.email),
                    "reason": "该 Free 邮箱仍在测活中",
                })
                continue
            if not result:
                skipped.append({
                    "row_id": row.row_id,
                    "email": mask_email(row.email),
                    "email_masked": mask_email(row.email),
                    "subject_ref_fingerprint": fingerprint(row.email),
                    "reason": "该 Free 邮箱没有注册结果，暂不可传输",
                })
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
                skipped.append({
                    "row_id": row.row_id,
                    "email": mask_email(row.email),
                    "email_masked": mask_email(row.email),
                    "subject_ref_fingerprint": fingerprint(row.email),
                    "reason": "该 Free 邮箱缺少可用账号凭据",
                })
        skipped.extend(
            {
                "row_id": row_id,
                "email": "",
                "email_masked": "",
                "reason": "Free 邮箱行不存在或已变化",
            }
            for row_id in sorted(selected - known)
        )
        return {
            "content": "\n".join(lines),
            "selected": len(requested),
            "prepared": len(lines),
            "skipped": len(skipped),
            "skipped_items": skipped,
        }


class SQLiteFreeTaskStore(_LegacyTaskStore):
    """SQLite-backed implementation of the historical task-store API."""

    def __init__(self, data_dir: str | Path, *, storage: FreeSQLiteStore | None = None) -> None:
        super().__init__(data_dir)
        self.storage = storage or FreeSQLiteStore(self.path.parent)
        self.path = self.storage.path
        # ``save`` historically accepted a complete JSON snapshot and pruned
        # terminal rows that disappeared from it.  SQLite is shared by
        # multiple workers/processes, so only rows observed by this adapter's
        # last ``load`` (and still at the same revision) are safe to prune.
        # Rows created by another process after that snapshot are retained.
        self._known_task_revisions: dict[str, int] = {}

    @staticmethod
    def _task_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
        payload = _json_payload(row.get("payload"))
        payload.update({
            "task_id": str(row.get("task_id") or payload.get("task_id") or ""),
            "status": str(row.get("status") or payload.get("status") or "queued"),
            "revision": int(row.get("revision") or payload.get("revision") or 0),
            "created_at": _compat_timestamp(
                payload.get("created_at", row.get("created_at")),
                _compat_timestamp(row.get("created_at")),
            ),
            "updated_at": _compat_timestamp(
                payload.get("updated_at", row.get("updated_at")),
                _compat_timestamp(row.get("updated_at")),
            ),
        })
        if row.get("lease_owner"):
            payload["lease_owner"] = row.get("lease_owner")
            payload["lease_until"] = row.get("lease_until")
        return payload

    def load(self) -> dict[str, dict[str, Any]]:
        rows = self.storage.list_tasks(limit=10_000)
        loaded = {
            str(row.get("task_id")): self._task_from_row(row)
            for row in rows
            if str(row.get("task_id") or "")
        }
        self._known_task_revisions = {
            task_id: int(value.get("revision") or 0)
            for task_id, value in loaded.items()
            if isinstance(value, Mapping)
        }
        return loaded

    def _remember_revision(self, task_id: str, row: Mapping[str, Any]) -> None:
        try:
            self._known_task_revisions[str(task_id)] = int(row.get("revision") or 0)
        except (TypeError, ValueError):
            pass

    @staticmethod
    def _sync_saved_value(value: Mapping[str, Any], row: Mapping[str, Any]) -> None:
        """Return SQLite CAS metadata to the manager's mutable snapshot."""
        if not isinstance(value, MutableMapping):
            return
        value["revision"] = int(row.get("revision") or 0)
        if row.get("status") is not None:
            value["status"] = str(row.get("status") or "queued")
        if row.get("created_at") is not None:
            value["created_at"] = _compat_timestamp(row.get("created_at"))
        if row.get("updated_at") is not None:
            value["updated_at"] = _compat_timestamp(row.get("updated_at"))

    def _save_one(self, task_id: str, value: Mapping[str, Any]) -> None:
        """Save one legacy snapshot with a bounded CAS refresh.

        The compatibility manager owns a full in-memory task map and does not
        perform repository transitions yet.  Timing checkpoints can advance a
        row revision between two full saves, so one stale revision is refreshed
        from the durable row and retried.  A durable terminal task always wins
        over a late active snapshot.
        """
        prefer_latest_revision = False
        for attempt in range(3):
            current = self.storage.get_task(task_id)
            if current is None:
                created = self.storage.create_task(
                    task_id,
                    value,
                    status=str(value.get("status") or "queued"),
                )
                self._sync_saved_value(value, created)
                self._remember_revision(task_id, created)
                return
            current_status = str(current.get("status") or "queued")
            incoming_status = str(value.get("status") or current_status or "queued")
            if current_status in _TERMINAL_TASK_STATUSES and incoming_status != current_status:
                self._sync_saved_value(value, current)
                self._remember_revision(task_id, current)
                return
            current_payload = current.get("payload")
            merged = _json_payload(current_payload)
            merged.update(copy.deepcopy(dict(value)))
            raw_expected = value.get("revision")
            if prefer_latest_revision or raw_expected is None:
                expected_revision = int(current.get("revision") or 0)
            else:
                try:
                    expected_revision = int(raw_expected)
                except (TypeError, ValueError):
                    expected_revision = int(current.get("revision") or 0)
            try:
                saved = self.storage.save_task(
                    task_id,
                    merged,
                    expected_revision=expected_revision,
                    status=incoming_status,
                )
            except RevisionConflict:
                if attempt >= 2:
                    raise
                prefer_latest_revision = True
                continue
            self._sync_saved_value(value, saved)
            self._remember_revision(task_id, saved)
            return

    def save(self, tasks: Mapping[str, Mapping[str, Any]]) -> None:
        known_before = dict(self._known_task_revisions)
        incoming_ids: set[str] = set()
        for key, value in tasks.items():
            if not isinstance(value, Mapping):
                continue
            task_id = str(value.get("task_id") or key or "").strip()
            if not task_id:
                continue
            incoming_ids.add(task_id)
            self._save_one(task_id, value)
        # Preserve the legacy explicit-delete behavior for rows this adapter
        # actually observed, while preventing a stale snapshot from deleting
        # terminal rows created or advanced by another process.
        stale_revisions = {
            task_id: revision
            for task_id, revision in known_before.items()
            if task_id not in incoming_ids
        }
        if stale_revisions:
            self.storage.delete_tasks(
                tuple(stale_revisions),
                terminal_only=True,
                expected_revisions=stale_revisions,
            )

    def save_timing(self, task_id: str, timing: Mapping[str, Any], *, skip_terminal: bool = True) -> bool:
        target = str(task_id or "").strip()
        if not target or not isinstance(timing, Mapping):
            return False
        current = self.storage.get_task(target)
        if current is None:
            return False
        status = str(current.get("status") or "").strip().lower()
        if skip_terminal and status in _TERMINAL_TASK_STATUSES:
            return False
        payload = current.get("payload") if isinstance(current.get("payload"), Mapping) else {}
        merged = copy.deepcopy(dict(payload))
        # Use the parent class's pure monotonic timing merge; it performs no
        # filesystem access and keeps stage/substep history from rolling back.
        merged["timing"] = self._merge_timing(merged.get("timing"), timing)
        try:
            self.storage.save_task(
                target,
                merged,
                expected_revision=int(current.get("revision") or 0),
                status=status or "queued",
            )
        except Exception:
            return False
        return True


class SQLiteFreeProxyPool(_LegacyProxyPool):
    """SQLite-backed proxy pool preserving the mature policy implementation.

    The parent class contains the transport/probe/quarantine policy and only
    calls ``_load``/``_save`` for persistence.  Redirecting those two methods
    keeps behavior aligned with the reference implementation without creating
    a second proxy state machine.
    """

    def __init__(self, data_dir: str | Path, *, storage: FreeSQLiteStore | None = None, **kwargs: Any) -> None:
        super().__init__(data_dir, **kwargs)
        self.storage = storage or FreeSQLiteStore(self.data_dir)
        self.path = self.storage.path

    @staticmethod
    def _proxy_url_from_row(row: Mapping[str, Any]) -> str:
        value = str(row.get("proxy") or "").strip()
        if value:
            return value
        return ""

    def _load(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        with self.storage._connection() as db:  # noqa: SLF001 - adapter boundary
            rows = db.execute("SELECT * FROM proxies ORDER BY updated_at DESC,proxy_id ASC").fetchall()
            for row in rows:
                try:
                    payload = self.storage._row_payload(row)  # noqa: SLF001 - adapter boundary
                except (TypeError, ValueError, json.JSONDecodeError):
                    # A single damaged payload must not hide the rest of the
                    # shared proxy pool; retain scalar identity/health fields
                    # and let the next successful probe repair metadata.
                    payload = {}
                proxy = str(row["proxy"] or "")
                parsed = urlsplit(proxy)
                lease_metadata = {
                    str(item.get("owner") or ""): item
                    for item in (payload.get("leases") or [])
                    if isinstance(item, Mapping) and str(item.get("owner") or "").strip()
                }
                leases = [
                    {
                        "owner": str(item["owner"]),
                        "until": float(item["lease_until"]),
                        "batch_id": str(
                            lease_metadata.get(str(item["owner"]), {}).get("batch_id")
                            or payload.get("lease_batch_id")
                            or ""
                        ),
                        "task_id": str(
                            lease_metadata.get(str(item["owner"]), {}).get("task_id")
                            or payload.get("lease_task_id")
                            or ""
                        ),
                    }
                    for item in db.execute(
                        "SELECT owner,lease_until FROM resource_leases "
                        "WHERE resource_type='proxy' AND resource_id=? AND lease_until>?",
                        (str(row["proxy_id"]), time.time()),
                    ).fetchall()
                ]
                status = str(row["status"] or "unknown")
                if status == "healthy":
                    status = "available"
                if status not in {"unknown", "available", "quarantined"}:
                    status = "unknown"
                record = {
                    **payload,
                    "proxy_id": str(row["proxy_id"]),
                    "proxy": proxy,
                    "host": str(parsed.hostname or payload.get("host") or ""),
                    "port": int(parsed.port or payload.get("port") or 0),
                    "username": unquote(str(parsed.username or payload.get("username") or "")),
                    "password": unquote(str(parsed.password or payload.get("password") or "")),
                    "scheme": str(row["scheme"] or parsed.scheme or self.default_scheme).lower(),
                    "effective_scheme": str(payload.get("effective_scheme") or row["scheme"] or parsed.scheme or self.default_scheme).lower(),
                    "country": "",
                    "group": "",
                    "enabled": bool(row["enabled"]),
                    "status": status,
                    "leases": leases,
                    "lease_owner": str(row["lease_owner"] or ""),
                    "lease_until": row["lease_until"],
                    # Keep a private snapshot of the owners observed in this
                    # read.  ``_save`` uses it to distinguish an intentional
                    # release from a lease acquired concurrently by another
                    # process; the marker is never persisted in payloads.
                    "_lease_snapshot_owners": tuple(
                        sorted(
                            str(item.get("owner") or "").strip()
                            for item in leases
                            if str(item.get("owner") or "").strip()
                        )
                    ),
                    "_lease_snapshot_until": {
                        str(item.get("owner") or "").strip(): float(item.get("until") or 0)
                        for item in leases
                        if str(item.get("owner") or "").strip()
                    },
                    "_normalized": proxy,
                }
                record["_storage_revision"] = int(row["revision"] or 0)
                identity = f"{record['host']}\x00{record['port']}\x00{record['username']}\x00{record['password']}"
                record["_identity"] = identity
                output.append(record)
        return output

    def _save(self, rows: Iterable[Mapping[str, Any]]) -> None:
        values = [dict(row) for row in rows if isinstance(row, Mapping)]
        now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        now_epoch = time.time()
        with self.storage._transaction():  # noqa: SLF001 - adapter boundary
            with self.storage._connection() as db:  # noqa: SLF001
                db.execute("BEGIN IMMEDIATE")
                try:
                    for row in values:
                        proxy = str(row.get("_normalized") or row.get("proxy") or "").strip()
                        if not proxy:
                            continue
                        parsed = urlsplit(proxy)
                        proxy_id = str(row.get("proxy_id") or fingerprint(proxy))
                        current_row = db.execute(
                            "SELECT * FROM proxies WHERE proxy_id=?", (proxy_id,)
                        ).fetchone()
                        current_payload: dict[str, Any] = {}
                        if current_row is not None:
                            try:
                                decoded = json.loads(str(current_row["payload"] or "{}"))
                            except (TypeError, ValueError, json.JSONDecodeError):
                                decoded = {}
                            if isinstance(decoded, Mapping):
                                current_payload = copy.deepcopy(dict(decoded))

                        # A legacy caller hands this adapter a complete
                        # in-memory snapshot.  Only owners present in that
                        # snapshot may be removed: an owner acquired after the
                        # snapshot was read is unknown and must survive this
                        # write.  This makes stale health/config writes safe
                        # across processes while preserving explicit release
                        # (the releasing call loads a fresh owner snapshot).
                        raw_snapshot_owners = row.get("_lease_snapshot_owners")
                        if isinstance(raw_snapshot_owners, (list, tuple, set, frozenset)):
                            snapshot_owners = {
                                str(owner or "").strip()
                                for owner in raw_snapshot_owners
                                if str(owner or "").strip()
                            }
                        else:
                            snapshot_owners = set()
                        raw_snapshot_until = row.get("_lease_snapshot_until")
                        snapshot_until: dict[str, float] = {}
                        if isinstance(raw_snapshot_until, Mapping):
                            for owner, value in raw_snapshot_until.items():
                                owner_text = str(owner or "").strip()
                                try:
                                    until = float(value or 0)
                                except (TypeError, ValueError):
                                    until = 0.0
                                if owner_text and until > 0:
                                    snapshot_until[owner_text] = until
                        raw_snapshot_revision = row.get("_storage_revision")
                        try:
                            snapshot_revision = int(raw_snapshot_revision)
                        except (TypeError, ValueError):
                            snapshot_revision = None
                        current_revision = (
                            int(current_row["revision"] or 0)
                            if current_row is not None
                            else None
                        )
                        revision_changed = (
                            snapshot_revision is not None
                            and current_revision is not None
                            and current_revision != snapshot_revision
                        )
                        current_lease_metadata: dict[str, dict[str, Any]] = {}
                        raw_current_leases = current_payload.get("leases")
                        if isinstance(raw_current_leases, list):
                            for item in raw_current_leases:
                                if not isinstance(item, Mapping):
                                    continue
                                owner = str(item.get("owner") or "").strip()
                                if owner:
                                    current_lease_metadata[owner] = dict(item)

                        existing_leases = db.execute(
                            "SELECT owner,lease_until FROM resource_leases "
                            "WHERE resource_type='proxy' AND resource_id=?",
                            (proxy_id,),
                        ).fetchall()
                        existing_owners = {
                            str(item["owner"] or "").strip()
                            for item in existing_leases
                            if str(item["owner"] or "").strip()
                        }

                        desired = row.get("leases") if isinstance(row.get("leases"), list) else []
                        desired_by_owner: dict[str, dict[str, Any]] = {}
                        for item in desired:
                            if not isinstance(item, Mapping):
                                continue
                            owner = str(item.get("owner") or "").strip()
                            try:
                                until = float(item.get("until") or 0)
                            except (TypeError, ValueError):
                                until = 0
                            # If this owner existed in the loaded snapshot but
                            # disappeared while another writer advanced the
                            # row, it was explicitly released (or expired) in
                            # the meantime.  Do not recreate it from the stale
                            # health/config snapshot.  Fresh lease/heartbeat
                            # calls have an unchanged revision and therefore
                            # continue to renew their owner normally.
                            if (
                                owner
                                and until > now_epoch
                                and not (
                                    revision_changed
                                    and owner in snapshot_owners
                                    and owner not in existing_owners
                                )
                            ):
                                desired_by_owner[owner] = {
                                    "owner": owner,
                                    "until": until,
                                    "batch_id": str(item.get("batch_id") or ""),
                                    "task_id": str(item.get("task_id") or ""),
                                }

                        # Remove expired rows and owners explicitly removed
                        # from the snapshot.  Concurrently added owners are
                        # absent from ``snapshot_owners`` and are retained.
                        remove_owners = {
                            owner
                            for owner in existing_owners
                            if owner not in desired_by_owner
                            and (
                                (
                                    owner in snapshot_owners
                                    and next(
                                        (
                                            float(item["lease_until"] or 0)
                                            for item in existing_leases
                                            if str(item["owner"] or "").strip() == owner
                                        ),
                                        0.0,
                                    ) <= snapshot_until.get(owner, 0.0)
                                )
                                or next(
                                    (
                                        float(item["lease_until"] or 0)
                                        for item in existing_leases
                                        if str(item["owner"] or "").strip() == owner
                                    ),
                                    0,
                                ) <= now_epoch
                            )
                        }
                        for owner in remove_owners:
                            db.execute(
                                "DELETE FROM resource_leases WHERE resource_type='proxy' "
                                "AND resource_id=? AND owner=?",
                                (proxy_id, owner),
                            )

                        # Refresh desired owners and add new owners.  Existing
                        # unknown owners are intentionally left untouched.
                        for owner, item in desired_by_owner.items():
                            db.execute(
                                "INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                                "VALUES('proxy',?,?,?,?,?) "
                                "ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET "
                                # Never shorten a lease renewed by another
                                # worker after this snapshot was read.
                                "lease_until=MAX(resource_leases.lease_until,excluded.lease_until),updated_at=excluded.updated_at",
                                (proxy_id, owner, item["until"], now, now),
                            )

                        final_lease_rows = db.execute(
                            "SELECT owner,lease_until FROM resource_leases "
                            "WHERE resource_type='proxy' AND resource_id=? AND lease_until>? "
                            "ORDER BY owner ASC",
                            (proxy_id, now_epoch),
                        ).fetchall()
                        final_leases: list[dict[str, Any]] = []
                        for item in final_lease_rows:
                            owner = str(item["owner"] or "").strip()
                            if not owner:
                                continue
                            metadata = desired_by_owner.get(owner) or current_lease_metadata.get(owner) or {}
                            final_leases.append(
                                {
                                    "owner": owner,
                                    "until": float(item["lease_until"]),
                                    "batch_id": str(metadata.get("batch_id") or ""),
                                    "task_id": str(metadata.get("task_id") or ""),
                                }
                            )
                        latest = max(final_leases, key=lambda item: float(item["until"]), default=None)
                        payload = {
                            str(key): copy.deepcopy(value)
                            for key, value in row.items()
                            if str(key) not in {
                                "_identity",
                                "_normalized",
                                "_storage_revision",
                                "_lease_snapshot_owners",
                                "_lease_snapshot_until",
                                "proxy",
                                "proxy_id",
                                "scheme",
                                "status",
                                "enabled",
                                "lease_owner",
                                "lease_until",
                            }
                        }
                        payload["proxy"] = proxy
                        payload["proxy_id"] = proxy_id
                        payload["leases"] = final_leases
                        payload["lease_owner"] = str(latest["owner"]) if latest else ""
                        payload["lease_until"] = float(latest["until"]) if latest else None
                        payload["lease_batch_id"] = str(latest.get("batch_id") or "") if latest else ""
                        payload["lease_task_id"] = str(latest.get("task_id") or "") if latest else ""
                        scheme = str(row.get("scheme") or parsed.scheme or self.default_scheme).lower()
                        status = str(row.get("status") or "unknown")
                        if status == "healthy":
                            status = "available"
                        public_payload, private_payload = _partition_json(payload)
                        db.execute(
                            "INSERT INTO proxies(proxy_id,proxy,scheme,status,enabled,lease_owner,lease_until,revision,created_at,updated_at,payload,private_payload) "
                            "VALUES(?,?,?,?,?,?,?,0,?,?,?,?) "
                            "ON CONFLICT(proxy_id) DO UPDATE SET proxy=excluded.proxy,scheme=excluded.scheme,status=excluded.status,"
                            "enabled=excluded.enabled,lease_owner=excluded.lease_owner,lease_until=excluded.lease_until,"
                            "revision=proxies.revision+1,updated_at=excluded.updated_at,payload=excluded.payload,private_payload=excluded.private_payload",
                            (
                                proxy_id,
                                proxy,
                                scheme,
                                status,
                                int(bool(row.get("enabled", True))),
                                str(latest["owner"]) if latest else "",
                                float(latest["until"]) if latest else None,
                                now,
                                now,
                                json.dumps(public_payload, ensure_ascii=False, sort_keys=True),
                                json.dumps(private_payload, ensure_ascii=False, sort_keys=True),
                            ),
                        )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def public(self) -> dict[str, Any]:
        """Return the legacy proxy projection plus a stable ``proxies`` alias.

        Older UI callers use ``rows`` while the SQLite adapter contract uses
        ``proxies``.  Both keys point to independently copied rows so callers
        cannot mutate the adapter's in-memory projection through either view.
        """

        projection = dict(super().public())
        rows = projection.get("rows")
        if not isinstance(rows, list):
            rows = []
        normalized_rows: list[Any] = []
        for item in rows:
            if not isinstance(item, Mapping):
                normalized_rows.append(item)
                continue
            row = dict(item)
            # ``proxy`` is the historical public field name; its value is
            # always the credential-free masked representation.
            row.setdefault("proxy", row.get("masked", ""))
            normalized_rows.append(row)
        projection["rows"] = normalized_rows
        projection["proxies"] = [dict(item) if isinstance(item, Mapping) else item for item in projection["rows"]]
        return projection

    def release_owner(self, owner: str) -> int:
        """Release all proxy leases held by an interrupted task owner."""
        releaser = getattr(self.storage, "release_proxy_leases", None)
        if not callable(releaser):
            return 0
        result = releaser(str(owner or "").strip())
        try:
            return int(result or 0)
        except (TypeError, ValueError):
            return 0

    # Keep the operation discoverable under the storage-oriented name too.
    release_leases_for_owner = release_owner


@dataclass(frozen=True, slots=True)
class SQLiteFreeStorageAdapters:
    data_dir: Path
    storage: FreeSQLiteStore
    mailboxes: SQLiteFreeMailboxPool
    proxies: SQLiteFreeProxyPool
    tasks: SQLiteFreeTaskStore

    # Names mirror the manager's historical attributes for straightforward
    # dependency injection.
    @property
    def pool(self) -> SQLiteFreeMailboxPool:
        return self.mailboxes

    @property
    def task_store(self) -> SQLiteFreeTaskStore:
        return self.tasks

    @property
    def task_repository(self) -> Any:
        """Return the narrow revisioned repository facade for new callers."""
        try:
            from .free_register.task_repository import FreeTaskRepository
        except ImportError:  # pragma: no cover
            from free_register.task_repository import FreeTaskRepository  # type: ignore[no-redef]
        return FreeTaskRepository(self.data_dir, storage=self.storage)


def build_free_storage_adapters(
    data_dir: str | Path,
    *,
    storage: FreeSQLiteStore | None = None,
    proxy_options: Mapping[str, Any] | None = None,
) -> SQLiteFreeStorageAdapters:
    root = Path(data_dir).expanduser().resolve()
    shared = storage or FreeSQLiteStore(root)
    options = dict(proxy_options or {})
    mailboxes = SQLiteFreeMailboxPool(root, storage=shared)
    proxies = SQLiteFreeProxyPool(root, storage=shared, **options)
    tasks = SQLiteFreeTaskStore(root, storage=shared)
    return SQLiteFreeStorageAdapters(root, shared, mailboxes, proxies, tasks)


# Explicit aliases make the migration seam discoverable without forcing a
# future caller to remember the internal naming convention.
FreeSQLiteMailboxPool = SQLiteFreeMailboxPool
FreeSQLiteProxyPool = SQLiteFreeProxyPool
FreeSQLiteTaskStore = SQLiteFreeTaskStore
FreeStorageAdapters = SQLiteFreeStorageAdapters


__all__ = [
    "SQLiteFreeMailboxPool",
    "SQLiteFreeProxyPool",
    "SQLiteFreeTaskStore",
    "SQLiteFreeStorageAdapters",
    "FreeSQLiteMailboxPool",
    "FreeSQLiteProxyPool",
    "FreeSQLiteTaskStore",
    "FreeStorageAdapters",
    "build_free_storage_adapters",
]
