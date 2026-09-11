"""SQLite-backed adapter for the historical Free mailbox pool API."""

from __future__ import annotations

import copy
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from .free_failure_runtime import canonical_failure, merge_account_result_fields
    from .free_register_common import (
        FreeMailbox,
        FreeRegisterError,
        fingerprint,
        mask_email,
        parse_mailbox_line,
    )
    from .free_register_store import FreeMailboxPool as _LegacyMailboxPool
    from .free_register_store import _account_material_line
    from .free_storage import FreeSQLiteStore, _stored_bool
    from .free_storage_adapter_common import (
        _ACTIVE_MAILBOX_STATUSES,
        _ACTIVE_STATUS_OVERRIDE,
        _MAILBOX_TRANSIENT_KEYS,
        _json_payload,
    )
    from .remail_api import remail_order_expired, remail_pickup_url
except ImportError:  # pragma: no cover - recovery imports
    from free_failure_runtime import canonical_failure, merge_account_result_fields  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FreeMailbox,
        FreeRegisterError,
        fingerprint,
        mask_email,
        parse_mailbox_line,
    )
    from free_register_store import FreeMailboxPool as _LegacyMailboxPool  # type: ignore[no-redef]
    from free_register_store import _account_material_line  # type: ignore[no-redef]
    from free_storage import FreeSQLiteStore, _stored_bool  # type: ignore[no-redef]
    from free_storage_adapter_common import (  # type: ignore[no-redef]
        _ACTIVE_MAILBOX_STATUSES,
        _ACTIVE_STATUS_OVERRIDE,
        _MAILBOX_TRANSIENT_KEYS,
        _json_payload,
    )
    from remail_api import remail_order_expired, remail_pickup_url  # type: ignore[no-redef]


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
        if not target:
            return None
        # Primary-key lookup instead of rebuilding the whole ordered pool for
        # one row.  ``index`` is only meaningful on the ordered ``entries()``
        # view; no caller resolves a single entry's display position.
        row = self.storage.get_mailbox(target)
        if row is None:
            return None
        payload = _row_payload(row)
        return FreeMailbox(
            str(payload.get("row_id") or target),
            0,
            str(payload.get("email") or ""),
            str(payload.get("mailbox_url") or ""),
        )

    def mailbox_index(self) -> dict[str, FreeMailbox]:
        """Return every pool entry keyed by ``row_id`` in one storage read.

        ``entry`` rebuilds the whole ordered pool per call, so state
        projections that previously resolved mailboxes one-by-one paid a full
        pool scan per task.  This bulk variant keeps a single scan.
        """
        return {item.row_id: item for item in self.entries()}

    def results_bulk(self, row_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        """Return durable account results for ``row_ids`` in one query."""
        unique: list[str] = []
        seen: set[str] = set()
        for row_id in row_ids:
            target = str(row_id or "").strip()
            if target and target not in seen:
                seen.add(target)
                unique.append(target)
        if not unique:
            return {}
        placeholders = ",".join("?" for _ in unique)
        with self.storage._connection() as db:
            rows = db.execute(
                f"SELECT row_id,payload,private_payload FROM results WHERE row_id IN ({placeholders})",
                unique,
            ).fetchall()
        bulk: dict[str, dict[str, Any]] = {}
        for row in rows:
            # ``result`` returns the merged public/private payload; keep the
            # bulk reader byte-identical so capability markers survive.
            try:
                payload = dict(json.loads(str(row["payload"] or "{}")))
            except (TypeError, ValueError):
                payload = {}
            try:
                payload.update(json.loads(str(row["private_payload"] or "{}")))
            except (TypeError, ValueError):
                pass
            if payload:
                bulk[str(row["row_id"] or "")] = copy.deepcopy(payload)
        return bulk

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
            existing_ids: set[str] = set()
            for row in self.storage.list_mailboxes(limit=10_000):
                existing_ids.add(str(row.get("row_id") or ""))
                payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
                try:
                    existing_orders.append(int(payload.get("_pool_order")))
                except (TypeError, ValueError):
                    continue
            # Leave room before the current first row for this import batch;
            # the input order is preserved within the batch.
            next_order = min(existing_orders, default=0) - len(incoming)
            for entry in incoming:
                if entry.row_id in existing_ids:
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

    def available_count(self) -> int:
        """Count dispatchable rows without materializing or sorting entries.

        ``state`` polls only need this number; ``available(10_000)`` would
        additionally build and sort a full entry list per request.
        Expiry handling matches ``available``: an expired Remail row that is
        still marked active is flipped to unavailable (without scanning it
        into the count).
        """
        now = time.time()
        expired_batch: list[tuple[str, dict[str, Any]]] = []
        total = 0
        for row in self.storage.list_mailboxes(limit=10_000):
            payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
            if str(payload.get("source") or "").strip().lower() == "remail" and remail_order_expired(payload, now=now):
                if str(row.get("status") or "available") in _ACTIVE_MAILBOX_STATUSES:
                    expired_batch.append((str(row.get("row_id") or ""), {"remail_expired": True, "error": "Remail 订单已过期"}))
                continue
            if str(row.get("status") or "available") != "available":
                continue
            if _stored_bool(payload.get("lease_confirmed")):
                continue
            try:
                cooldown = float(payload.get("cooldown_until") or 0)
            except (TypeError, ValueError):
                cooldown = 0
            if cooldown > now:
                continue
            total += 1
        for row_id, patch in expired_batch:
            self.storage.update_mailbox(row_id, status="unavailable", payload_patch=patch)
        return total

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
            in _ACTIVE_STATUS_OVERRIDE,
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
        # The status column always wins over the payload JSON in the row
        # projection, so the aggregation can run in SQLite instead of
        # materializing and decoding every row in Python.
        grouped: dict[str, int] = {}
        with self.storage._connection() as db:  # noqa: SLF001 - adapter boundary
            for row in db.execute("SELECT status, COUNT(*) FROM mailboxes GROUP BY status").fetchall():
                grouped[str(row[0] or "available")] = int(row[1])
        for status, total in grouped.items():
            counts["total"] += total
            key = "running" if status in _ACTIVE_MAILBOX_STATUSES else status
            if key in counts:
                counts[key] += total
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
        pool_rows = self.entries()
        bulk_results = self.results_bulk([row.row_id for row in pool_rows])
        for row in pool_rows:
            if selected and row.row_id not in selected:
                continue
            result = bulk_results.get(row.row_id) or {}
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
        bulk_results = self.results_bulk([row.row_id for row in rows])
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
            result = bulk_results.get(row.row_id) or {}
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


__all__ = ["SQLiteFreeMailboxPool"]
