"""Mailbox pool-state policy and stable manual availability mutations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
import hashlib
import hmac
import re
import time
from typing import Any


MANUAL_DRAFT_REASON = "manual_draft"
MANUAL_UNAVAILABLE_REASON = "manual_unavailable"
MANUAL_SMS_CONSUMED_REASON = "manual_sms_consumed"
_INTERNAL_MAILBOX_REASONS = frozenset(
    {
        MANUAL_DRAFT_REASON,
        "manual_reimport_retry",
        "manual_restore",
        MANUAL_UNAVAILABLE_REASON,
        MANUAL_SMS_CONSUMED_REASON,
        "sub2_uploaded",
    }
)
_EMAIL_RE = re.compile(
    r"(?i)\b[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"
)
_ROW_ID_RE = re.compile(r"^[0-9a-f]{64}$")


@contextmanager
def _locked_pool_config(mailbox_admin: Any):
    callback = getattr(mailbox_admin, "_locked_pool_config", None)
    if callable(callback):
        with callback() as config:
            yield config
        return
    with mailbox_admin._lock:
        yield mailbox_admin._config()


def selected_line_numbers(payload: Any) -> list[int]:
    value = payload if isinstance(payload, Mapping) else {}
    result = []
    for item in value.get("line_nos") or []:
        try:
            number = int(item)
        except (TypeError, ValueError):
            continue
        if number > 0:
            result.append(number)
    return sorted(set(result))


def pool_count_status(state_item: Any, now: float | int | None = None) -> str:
    item = state_item if isinstance(state_item, Mapping) else {}
    status = str(item.get("status") or "").lower()
    if status == "damaged" and str(item.get("reason") or "").strip().lower() == MANUAL_DRAFT_REASON:
        return "draft"
    if status in {"damaged", "consumed"}:
        return status
    if status == "leased":
        try:
            lease_until = float(item.get("lease_until") or 0)
        except (TypeError, ValueError):
            lease_until = 0
        if lease_until > (time.time() if now is None else now):
            return "running"
    return "available"


def human_mailbox_status(state_item: Any, now: float | int | None = None) -> tuple[str, str]:
    item = state_item if isinstance(state_item, Mapping) else {}
    status = pool_count_status(item, now)
    if status == "running":
        return "running", "运行中"
    if status == "consumed":
        return "consumed", "已使用"
    if status == "draft":
        return "draft", "草稿"
    if status == "damaged":
        label = "不可用" if str(item.get("reason") or "") == MANUAL_UNAVAILABLE_REASON else "失败"
        return "failed", label
    return "available", "可用"


def public_mailbox_reason(reason: Any) -> str:
    value = str(reason or "")
    return "" if value.strip().lower() in _INTERNAL_MAILBOX_REASONS else value


def manual_sms_received(state_item: Any) -> bool:
    """Return whether an operator marked this exact row as manually used."""
    return (
        isinstance(state_item, Mapping)
        and str(state_item.get("reason") or "").strip().lower()
        == MANUAL_SMS_CONSUMED_REASON
    )


def public_batch_metadata(
    live_task: Mapping[str, Any],
    batch_member: Mapping[str, Any],
    result: Mapping[str, Any],
    result_payload: Mapping[str, Any],
    state_item: Mapping[str, Any],
) -> tuple[str, int, int]:
    """Build safe batch identity and timestamps for one public mailbox row."""
    batch_id = str(
        live_task.get("batch_id")
        or batch_member.get("batch_id")
        or result.get("batch_id")
        or result_payload.get("batch_id")
        or ""
    )
    try:
        batch_started_at = int(
            live_task.get("batch_started_at")
            or batch_member.get("batch_started_at")
            or result.get("batch_started_at")
            or result_payload.get("batch_started_at")
            or 0
        )
    except (TypeError, ValueError):
        batch_started_at = 0
    try:
        updated_at = max(
            int(live_task.get("updated_at") or 0),
            int(result.get("created_at") or result.get("updated_at") or 0),
            int(state_item.get("updated_at") or 0),
        )
    except (TypeError, ValueError):
        updated_at = 0
    return batch_id, batch_started_at, updated_at


def friendly_mailbox_error(error: Any) -> str:
    value = public_mailbox_reason(error)
    status_messages = {
        "stopped": "任务已停止",
        "stopped_before_start": "任务开始前已停止",
    }
    if value in status_messages:
        return status_messages[value]
    if "deleted or deactivated" in value or "You do not have an account" in value:
        return "邮箱对应的 OpenAI 账号不可用（已删除或停用）"
    if "email_otp_failed" in value:
        return "邮箱验证码提交后被 OpenAI 拒绝，请确认该邮箱对应的 OpenAI 账号是否可用"
    return value


def latest_batch_members_by_row(callback: Any) -> dict[str, Mapping[str, Any]]:
    if not callable(callback):
        return {}
    try:
        members = callback(failed_only=False) or []
    except Exception:
        return {}
    return {
        str(item.get("row_id") or "").strip().lower(): item
        for item in members
        if isinstance(item, Mapping) and item.get("row_id")
    }


def index_mailbox_states(
    items: Any,
) -> tuple[
    dict[int, Mapping[str, Any]],
    dict[tuple[str, int], Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
]:
    by_line: dict[int, Mapping[str, Any]] = {}
    by_email_line: dict[tuple[str, int], Mapping[str, Any]] = {}
    by_row_id: dict[str, Mapping[str, Any]] = {}
    source = items if isinstance(items, Mapping) else {}
    for state_key, item in source.items():
        if not isinstance(item, Mapping):
            continue
        normalized_key = str(state_key or "").strip().lower()
        if _ROW_ID_RE.fullmatch(normalized_key):
            by_row_id[normalized_key] = item
        email = _email_from_source(str(item.get("email") or ""))
        try:
            line_no = int(item.get("line_no") or 0)
        except (TypeError, ValueError):
            line_no = 0
        if line_no > 0 and not email:
            by_line[line_no] = item
        if email and line_no > 0:
            by_email_line[(email, line_no)] = item
    return by_line, by_email_line, by_row_id


def indexed_mailbox_state(
    by_line: Mapping[int, Mapping[str, Any]],
    by_email_line: Mapping[tuple[str, int], Mapping[str, Any]],
    by_row_id: Mapping[str, Mapping[str, Any]],
    *,
    row_id: str,
    email: str,
    line_no: int,
) -> Mapping[str, Any]:
    """Resolve state without borrowing another source row's same-email state."""
    exact = by_row_id.get(str(row_id or "").strip().lower())
    if isinstance(exact, Mapping):
        return exact
    email_match = by_email_line.get((str(email or "").strip().lower(), line_no))
    if isinstance(email_match, Mapping):
        return email_match
    legacy_line = by_line.get(line_no)
    return legacy_line if isinstance(legacy_line, Mapping) else {}


def _email_from_source(row: str) -> str:
    match = _EMAIL_RE.search(str(row or ""))
    return match.group(0).lower() if match else ""


def _row_id_from_source(row: str) -> str:
    return hashlib.sha256(str(row or "").encode("utf-8")).hexdigest()


def _state_line_no(item: Any) -> int:
    try:
        return int(item.get("line_no") or 0) if isinstance(item, Mapping) else 0
    except (TypeError, ValueError):
        return 0


def _matching_state_keys(
    items: Mapping[str, Any],
    row_id: str,
    email: str,
    line_no: int,
    *,
    known_row_ids: set[str] | None = None,
) -> list[str]:
    """Return every state candidate for one stable source row, exact key first."""
    matches = [
        str(key)
        for key, raw_item in items.items()
        if str(key).strip().lower() == row_id and isinstance(raw_item, Mapping)
    ]
    for key, raw_item in items.items():
        normalized_key = str(key)
        normalized_row_key = normalized_key.strip().lower()
        if (
            normalized_key not in matches
            and (not known_row_ids or normalized_row_key not in known_row_ids)
            and isinstance(raw_item, Mapping)
            and _email_from_source(str(raw_item.get("email") or "")) == email
            and _state_line_no(raw_item) == line_no
        ):
            matches.append(normalized_key)
    for key, raw_item in items.items():
        normalized_key = str(key)
        normalized_row_key = normalized_key.strip().lower()
        if (
            normalized_key in matches
            or (known_row_ids and normalized_row_key in known_row_ids)
            or not isinstance(raw_item, Mapping)
        ):
            continue
        if _email_from_source(str(raw_item.get("email") or "")):
            continue
        if _state_line_no(raw_item) == line_no:
            matches.append(normalized_key)
    return matches


def rewrite_state_after_delete(
    mailbox_admin: Any,
    kept_lines: Sequence[str],
    deleted_line_nos: set[int],
    deleted_rows: Any,
    config: Mapping[str, Any],
) -> None:
    """Drop selected state and renumber only state proven to belong to a kept row."""
    deleted_by_line: dict[int, tuple[str, str]] = {}
    legacy_deleted_emails: set[str] = set()
    if isinstance(deleted_rows, Mapping):
        for raw_line_no, raw_binding in deleted_rows.items():
            try:
                line_no = int(raw_line_no)
            except (TypeError, ValueError):
                continue
            if isinstance(raw_binding, Mapping):
                row_id = str(raw_binding.get("row_id") or "").strip().lower()
                email = _email_from_source(str(raw_binding.get("email") or ""))
            elif isinstance(raw_binding, Sequence) and not isinstance(raw_binding, (str, bytes)):
                row_id = str(raw_binding[0] if raw_binding else "").strip().lower()
                email = _email_from_source(str(raw_binding[1] if len(raw_binding) > 1 else ""))
            else:
                continue
            if line_no > 0:
                deleted_by_line[line_no] = (row_id, email)
    else:
        legacy_deleted_emails = {
            email
            for value in (deleted_rows or ())
            if (email := _email_from_source(str(value or "")))
        }

    kept_by_id: dict[str, tuple[int, str]] = {}
    kept_by_old_line: dict[int, tuple[int, str]] = {}
    old_line_no = 1
    for new_line_no, source in enumerate(kept_lines, start=1):
        while old_line_no in deleted_line_nos:
            old_line_no += 1
        email = _email_from_source(source)
        kept_by_id[_row_id_from_source(source)] = (new_line_no, email)
        kept_by_old_line[old_line_no] = (new_line_no, email)
        old_line_no += 1

    deleted_row_ids = {row_id for row_id, _email in deleted_by_line.values() if row_id}
    state_path = mailbox_admin._path(config, "state_path")
    state = mailbox_admin._read_json_file(state_path)
    items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
    new_items: dict[str, Any] = {}
    for key, raw_item in items.items():
        if not isinstance(raw_item, Mapping):
            continue
        normalized_key = str(key).strip().lower()
        if normalized_key in deleted_row_ids:
            continue
        item = dict(raw_item)
        if normalized_key in kept_by_id:
            item["line_no"] = kept_by_id[normalized_key][0]
            new_items[key] = item
            continue

        item_line_no = _state_line_no(item)
        item_email = _email_from_source(str(item.get("email") or ""))
        deleted_binding = deleted_by_line.get(item_line_no)
        if deleted_binding is not None and (
            (item_email and item_email == deleted_binding[1]) or not item_email
        ):
            continue
        if item_line_no in deleted_line_nos and item_email in legacy_deleted_emails:
            continue
        kept_binding = kept_by_old_line.get(item_line_no)
        if kept_binding is not None and (
            (item_email and item_email == kept_binding[1]) or not item_email
        ):
            item["line_no"] = kept_binding[0]
        new_items[key] = item
    state["items"] = new_items
    state["updated_at"] = int(mailbox_admin.now_fn())
    mailbox_admin._write_json_file(state_path, state)


def restore_mailbox_rows(mailbox_admin: Any, payload: Any) -> dict[str, Any]:
    """Restore exact selected rows while retaining the legacy line-only API."""
    selected = selected_line_numbers(payload)
    if not selected:
        return {"ok": False, "error": "请先勾选要放回可领取的邮箱"}

    value = payload if isinstance(payload, Mapping) else {}
    requested = value.get("rows")
    bindings: dict[int, str] = {}
    if requested is not None:
        if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)):
            return {"ok": False, "code": "mailbox_rows_invalid", "error": "放回参数无效"}
        for raw_binding in requested:
            if not isinstance(raw_binding, Mapping):
                return {"ok": False, "code": "mailbox_rows_invalid", "error": "放回参数无效"}
            row_id = str(raw_binding.get("row_id") or "").strip().lower()
            line_no = _state_line_no(raw_binding)
            if line_no <= 0 or not _ROW_ID_RE.fullmatch(row_id) or line_no in bindings:
                return {"ok": False, "code": "mailbox_rows_invalid", "error": "放回参数无效"}
            bindings[line_no] = row_id
        if not bindings or set(bindings) != set(selected):
            return {"ok": False, "code": "mailbox_rows_invalid", "error": "放回参数无效"}

    # Validate before taking the source lock; the recovered validator opens the
    # same lock again while reading pool entries and its flock is not reentrant.
    mailbox_admin._validate_pool()
    with _locked_pool_config(mailbox_admin) as config:
        lines = mailbox_admin._read_pool_lines(config)
        known_row_ids = {_row_id_from_source(source) for source in lines}
        resolved: list[tuple[int, str, str]] = []
        for line_no in selected:
            if line_no > len(lines):
                return {"ok": False, "error": "选中的邮箱不存在"}
            source = lines[line_no - 1]
            row_id = _row_id_from_source(source)
            expected_row_id = bindings.get(line_no)
            if expected_row_id and not hmac.compare_digest(expected_row_id, row_id):
                return {
                    "ok": False,
                    "code": "mailbox_rows_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            email = _email_from_source(source)
            if email:
                resolved.append((line_no, row_id, email))
        if not resolved:
            return {"ok": False, "error": "选中的邮箱不存在"}

        state_path = mailbox_admin._path(config, "state_path")
        state = mailbox_admin._read_json_file(state_path)
        items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
        items = dict(items)
        now = int(mailbox_admin.now_fn())
        restored = 0
        for line_no, row_id, email in resolved:
            matching_keys = _matching_state_keys(
                items,
                row_id,
                email,
                line_no,
                known_row_ids=known_row_ids,
            ) or [row_id]
            for state_key in matching_keys:
                raw_item = items.get(state_key)
                item = dict(raw_item) if isinstance(raw_item, Mapping) else {}
                history = list(item.get("history")) if isinstance(item.get("history"), list) else []
                history.append({"event": "restored", "reason": "manual_restore", "at": now})
                item.update(
                    email=email,
                    line_no=line_no,
                    status="available",
                    lease_until=0,
                    reason="manual_restore",
                    updated_at=now,
                    history=history,
                )
                items[state_key] = item
                restored += 1
        state["items"] = items
        state["updated_at"] = now
        mailbox_admin._write_json_file(state_path, state)

    mailbox_admin._log(f"邮箱管理放回可领取: {restored} 条", "success")
    return {"ok": True, "restored": restored}


def _stable_bindings(
    payload: Any,
    *,
    required_error: str = "请先勾选要设置为不可用的邮箱",
    invalid_error: str = "设置不可用参数无效",
) -> tuple[list[tuple[int, str]], dict[str, Any] | None]:
    value = payload if isinstance(payload, Mapping) else {}
    requested = value.get("rows")
    if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)) or not requested:
        return [], {
            "ok": False,
            "code": "mailbox_rows_required",
            "error": required_error,
        }
    bindings: list[tuple[int, str]] = []
    seen_lines: set[int] = set()
    seen_row_ids: set[str] = set()
    for item in requested:
        if not isinstance(item, Mapping):
            return [], {"ok": False, "code": "mailbox_rows_invalid", "error": invalid_error}
        row_id = str(item.get("row_id") or "").strip().lower()
        try:
            line_no = int(item.get("line_no") or 0)
        except (TypeError, ValueError):
            line_no = 0
        if (
            line_no <= 0
            or not _ROW_ID_RE.fullmatch(row_id)
            or line_no in seen_lines
            or row_id in seen_row_ids
        ):
            return [], {"ok": False, "code": "mailbox_rows_invalid", "error": invalid_error}
        seen_lines.add(line_no)
        seen_row_ids.add(row_id)
        bindings.append((line_no, row_id))
    if value.get("line_nos") is not None:
        raw_lines = value.get("line_nos")
        if not isinstance(raw_lines, Sequence) or isinstance(raw_lines, (str, bytes)):
            return [], {"ok": False, "code": "mailbox_rows_invalid", "error": invalid_error}
        supplied_lines = selected_line_numbers(value)
        if len(raw_lines) != len(bindings) or set(supplied_lines) != seen_lines:
            return [], {"ok": False, "code": "mailbox_rows_invalid", "error": invalid_error}
    return bindings, None


def _mutate_draft_rows(
    mailbox_admin: Any,
    payload: Any,
    *,
    restore: bool,
) -> dict[str, Any]:
    action = "放回可用" if restore else "放入草稿箱"
    bindings, error = _stable_bindings(
        payload,
        required_error=f"请先勾选要{action}的邮箱",
        invalid_error=f"邮箱{action}参数无效",
    )
    if error is not None:
        return error

    mailbox_admin._validate_pool()
    with _locked_pool_config(mailbox_admin) as config:
        lines = mailbox_admin._read_pool_lines(config)
        known_row_ids = {_row_id_from_source(source) for source in lines}
        selected: list[tuple[int, str, str]] = []
        for line_no, expected_row_id in bindings:
            if line_no > len(lines):
                return {
                    "ok": False,
                    "code": "mailbox_rows_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            source = lines[line_no - 1]
            if not hmac.compare_digest(expected_row_id, _row_id_from_source(source)):
                return {
                    "ok": False,
                    "code": "mailbox_rows_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            email = _email_from_source(source)
            if not email:
                return {
                    "ok": False,
                    "code": "mailbox_row_invalid",
                    "error": "选中的邮箱行无法识别",
                }
            selected.append((line_no, expected_row_id, email))

        state_path = mailbox_admin._path(config, "state_path")
        state = mailbox_admin._read_json_file(state_path)
        raw_items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
        items: dict[str, Any] = dict(raw_items)
        now = int(mailbox_admin.now_fn())
        resolved: list[tuple[int, str, list[str]]] = []
        for line_no, row_id, email in selected:
            matching_keys = _matching_state_keys(
                items,
                row_id,
                email,
                line_no,
                known_row_ids=known_row_ids,
            )
            exact_item = items.get(row_id)
            if isinstance(exact_item, Mapping):
                # The current source row is authoritative. Older identity or
                # line-based aliases can describe a previous lifecycle and
                # must not make a valid draft look stale.
                matching_keys = [row_id]
            if restore:
                is_draft = bool(matching_keys) and all(
                    isinstance(items.get(state_key), Mapping)
                    and str(items[state_key].get("status") or "").strip().lower() == "damaged"
                    and str(items[state_key].get("reason") or "").strip().lower() == MANUAL_DRAFT_REASON
                    for state_key in matching_keys
                )
                if not is_draft:
                    return {
                        "ok": False,
                        "code": "mailbox_rows_not_draft",
                        "error": "选中的邮箱已不在草稿箱，请刷新后重试",
                    }
            else:
                for state_key in matching_keys:
                    current_status = pool_count_status(items.get(state_key), now)
                    if current_status == "running":
                        return {
                            "ok": False,
                            "code": "mailbox_rows_running",
                            "error": "选中的邮箱仍在运行中，请等待任务结束后重试",
                        }
                    if current_status != "available":
                        return {
                            "ok": False,
                            "code": "mailbox_rows_not_available",
                            "error": "只能将当前可用的邮箱放入草稿箱，请刷新后重试",
                        }
                matching_keys = matching_keys or [row_id]
            resolved.append((line_no, email, matching_keys))

        target_status = "available" if restore else "damaged"
        target_reason = "manual_restore" if restore else MANUAL_DRAFT_REASON
        event = "restored" if restore else "drafted"
        for line_no, email, matching_keys in resolved:
            for state_key in matching_keys:
                raw_item = items.get(state_key)
                item = dict(raw_item) if isinstance(raw_item, Mapping) else {}
                history = list(item.get("history")) if isinstance(item.get("history"), list) else []
                history.append({"event": event, "reason": target_reason, "at": now})
                item.update(
                    email=email,
                    line_no=line_no,
                    status=target_status,
                    lease_until=0,
                    reason=target_reason,
                    updated_at=now,
                    history=history,
                )
                items[state_key] = item
        state["items"] = items
        state["updated_at"] = now
        mailbox_admin._write_json_file(state_path, state)

    count = len(selected)
    if restore:
        mailbox_admin._log(f"邮箱管理草稿放回可用: {count} 条", "success")
        return {"ok": True, "restored": count}
    mailbox_admin._log(f"邮箱管理放入草稿箱: {count} 条", "info")
    return {"ok": True, "drafted": count}


def mark_mailboxes_draft(mailbox_admin: Any, payload: Any) -> dict[str, Any]:
    """Move exact currently available rows out of the recovered lease pool."""
    return _mutate_draft_rows(mailbox_admin, payload, restore=False)


def restore_draft_mailboxes(mailbox_admin: Any, payload: Any) -> dict[str, Any]:
    """Restore only rows that still carry the dedicated manual draft marker."""
    return _mutate_draft_rows(mailbox_admin, payload, restore=True)


def _mutate_manual_used_rows(
    mailbox_admin: Any,
    payload: Any,
    *,
    restore: bool,
) -> dict[str, Any]:
    """Toggle the operator's manual SMS receipt marker for exact source rows."""
    action = "标记未用" if restore else "标记已手动接码"
    bindings, error = _stable_bindings(
        payload,
        required_error=f"请先勾选要{action}的邮箱",
        invalid_error=f"邮箱{action}参数无效",
    )
    if error is not None:
        return error

    mailbox_admin._validate_pool()
    with _locked_pool_config(mailbox_admin) as config:
        lines = mailbox_admin._read_pool_lines(config)
        known_row_ids = {_row_id_from_source(source) for source in lines}
        selected: list[tuple[int, str, str]] = []
        for line_no, expected_row_id in bindings:
            if line_no > len(lines):
                return {
                    "ok": False,
                    "code": "mailbox_rows_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            source = lines[line_no - 1]
            if not hmac.compare_digest(expected_row_id, _row_id_from_source(source)):
                return {
                    "ok": False,
                    "code": "mailbox_rows_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            email = _email_from_source(source)
            if not email:
                return {
                    "ok": False,
                    "code": "mailbox_row_invalid",
                    "error": "选中的邮箱行无法识别",
                }
            selected.append((line_no, expected_row_id, email))

        state_path = mailbox_admin._path(config, "state_path")
        state = mailbox_admin._read_json_file(state_path)
        raw_items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
        items: dict[str, Any] = dict(raw_items)
        now = int(mailbox_admin.now_fn())
        resolved: list[tuple[int, str, list[str]]] = []
        for line_no, row_id, email in selected:
            matching_keys = _matching_state_keys(
                items,
                row_id,
                email,
                line_no,
                known_row_ids=known_row_ids,
            )
            if restore:
                is_manual_used = bool(matching_keys) and all(
                    isinstance(items.get(state_key), Mapping)
                    and str(items[state_key].get("status") or "").strip().lower() == "consumed"
                    and str(items[state_key].get("reason") or "").strip().lower()
                    == MANUAL_SMS_CONSUMED_REASON
                    for state_key in matching_keys
                )
                if not is_manual_used:
                    return {
                        "ok": False,
                        "code": "mailbox_rows_not_manual_used",
                        "error": "选中的邮箱不是手动接码标记，请刷新后重试",
                    }
            else:
                for state_key in matching_keys:
                    if pool_count_status(items.get(state_key), now) == "running":
                        return {
                            "ok": False,
                            "code": "mailbox_rows_running",
                            "error": "选中的邮箱仍在运行中，请等待任务结束后重试",
                        }
                    if pool_count_status(items.get(state_key), now) != "available":
                        return {
                            "ok": False,
                            "code": "mailbox_rows_not_available",
                            "error": "只能将当前可用的邮箱标记为已手动接码，请刷新后重试",
                        }
                matching_keys = matching_keys or [row_id]
            resolved.append((line_no, email, matching_keys))

        target_status = "available" if restore else "consumed"
        target_reason = "manual_restore" if restore else MANUAL_SMS_CONSUMED_REASON
        event = "manual_unused" if restore else "manual_sms_received"
        for line_no, email, matching_keys in resolved:
            for state_key in matching_keys:
                raw_item = items.get(state_key)
                item = dict(raw_item) if isinstance(raw_item, Mapping) else {}
                history = list(item.get("history")) if isinstance(item.get("history"), list) else []
                history.append({"event": event, "reason": target_reason, "at": now})
                item.update(
                    email=email,
                    line_no=line_no,
                    status=target_status,
                    lease_until=0,
                    reason=target_reason,
                    updated_at=now,
                    history=history,
                )
                items[state_key] = item
        state["items"] = items
        state["updated_at"] = now
        mailbox_admin._write_json_file(state_path, state)

    count = len(selected)
    if restore:
        mailbox_admin._log(f"邮箱管理标记未用并放回可用: {count} 条", "success")
        return {"ok": True, "restored": count}
    mailbox_admin._log(f"邮箱管理标记已手动接码: {count} 条", "info")
    return {"ok": True, "used": count}


def mark_mailboxes_manual_used(mailbox_admin: Any, payload: Any) -> dict[str, Any]:
    """Mark currently available rows as consumed by manual phone verification."""
    return _mutate_manual_used_rows(mailbox_admin, payload, restore=False)


def restore_manual_used_mailboxes(mailbox_admin: Any, payload: Any) -> dict[str, Any]:
    """Undo only the dedicated manual phone-verification marker."""
    return _mutate_manual_used_rows(mailbox_admin, payload, restore=True)


def mark_mailboxes_unavailable(mailbox_admin: Any, payload: Any) -> dict[str, Any]:
    """Persist ``damaged`` for an all-or-nothing stable mailbox selection."""
    bindings, error = _stable_bindings(payload)
    if error is not None:
        return error

    # See restore_mailbox_rows: validation must not run while this source lock
    # is held because the recovered pool validator acquires it once more.
    mailbox_admin._validate_pool()
    with _locked_pool_config(mailbox_admin) as config:
        lines = mailbox_admin._read_pool_lines(config)
        known_row_ids = {_row_id_from_source(source) for source in lines}
        selected: list[tuple[int, str, str]] = []
        for line_no, expected_row_id in bindings:
            if line_no > len(lines):
                return {
                    "ok": False,
                    "code": "mailbox_rows_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            source = lines[line_no - 1]
            if not hmac.compare_digest(expected_row_id, _row_id_from_source(source)):
                return {
                    "ok": False,
                    "code": "mailbox_rows_stale",
                    "error": "邮箱列表已变化，请刷新后重试",
                }
            email = _email_from_source(source)
            if not email:
                return {
                    "ok": False,
                    "code": "mailbox_row_invalid",
                    "error": "选中的邮箱行无法识别",
                }
            selected.append((line_no, expected_row_id, email))

        state_path = mailbox_admin._path(config, "state_path")
        state = mailbox_admin._read_json_file(state_path)
        raw_items = state.get("items") if isinstance(state.get("items"), Mapping) else {}
        items: dict[str, Any] = dict(raw_items)
        now = int(mailbox_admin.now_fn())
        resolved: list[tuple[int, str, str, list[str]]] = []
        for line_no, row_id, email in selected:
            matching_keys = _matching_state_keys(
                items,
                row_id,
                email,
                line_no,
                known_row_ids=known_row_ids,
            )
            for matching_key in matching_keys:
                raw_item = items.get(matching_key)
                if not isinstance(raw_item, Mapping):
                    continue
                status = str(raw_item.get("status") or "").strip().lower()
                try:
                    lease_until = float(raw_item.get("lease_until") or 0)
                except (TypeError, ValueError):
                    lease_until = 0
                if status == "leased" and lease_until > now:
                    return {
                        "ok": False,
                        "code": "mailbox_rows_running",
                        "error": "选中的邮箱仍在运行中，请等待任务结束后重试",
                    }
            resolved.append((line_no, row_id, email, matching_keys or [row_id]))

        for line_no, _row_id, email, matching_keys in resolved:
            for state_key in matching_keys:
                raw_item = items.get(state_key)
                item = dict(raw_item) if isinstance(raw_item, Mapping) else {}
                history = list(item.get("history")) if isinstance(item.get("history"), list) else []
                history.append({"event": "damaged", "reason": MANUAL_UNAVAILABLE_REASON, "at": now})
                item.update(
                    email=email,
                    line_no=line_no,
                    status="damaged",
                    lease_until=0,
                    reason=MANUAL_UNAVAILABLE_REASON,
                    updated_at=now,
                    history=history,
                )
                items[state_key] = item
        state["items"] = items
        state["updated_at"] = now
        mailbox_admin._write_json_file(state_path, state)

    mailbox_admin._log(f"邮箱管理设置不可用: {len(selected)} 条", "warn")
    return {"ok": True, "unavailable": len(selected)}


__all__ = [
    "MANUAL_DRAFT_REASON",
    "MANUAL_SMS_CONSUMED_REASON",
    "MANUAL_UNAVAILABLE_REASON",
    "friendly_mailbox_error",
    "human_mailbox_status",
    "indexed_mailbox_state",
    "index_mailbox_states",
    "latest_batch_members_by_row",
    "manual_sms_received",
    "mark_mailboxes_draft",
    "mark_mailboxes_manual_used",
    "mark_mailboxes_unavailable",
    "pool_count_status",
    "public_batch_metadata",
    "public_mailbox_reason",
    "restore_draft_mailboxes",
    "restore_manual_used_mailboxes",
    "restore_mailbox_rows",
    "rewrite_state_after_delete",
    "selected_line_numbers",
]
