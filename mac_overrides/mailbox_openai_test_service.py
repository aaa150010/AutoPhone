"""Resolve local OpenAI tests and remove only confirmed deactivated workspaces."""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from threading import Lock
from typing import Any

try:
    from .mailbox_quota_service import delete_deactivated_mailboxes
    from .mailbox_row_formats import email_from_row, row_id_from_source
    from .mailbox_state_runtime import indexed_mailbox_state, index_mailbox_states
    from .openai_direct_test_runtime import DEACTIVATED_WORKSPACE_KIND
    from .openai_quota_runtime import OpenAIQuotaError, credentials_from_result
except ImportError:  # Loaded as top-level runtime overrides by the Mac launcher.
    from mailbox_quota_service import delete_deactivated_mailboxes
    from mailbox_row_formats import email_from_row, row_id_from_source
    from mailbox_state_runtime import indexed_mailbox_state, index_mailbox_states
    from openai_direct_test_runtime import DEACTIVATED_WORKSPACE_KIND
    from openai_quota_runtime import OpenAIQuotaError, credentials_from_result


def _confirmed_deactivated_rows(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    confirmed: list[dict[str, Any]] = []
    for item in result.get("results") or ():
        if not isinstance(item, Mapping):
            continue
        status = item.get("sub2_status")
        if not isinstance(status, Mapping):
            continue
        try:
            status_code = int(status.get("status_code") or 0)
            line_no = int(item.get("line_no") or 0)
        except (TypeError, ValueError):
            continue
        row_id = str(item.get("row_id") or "").strip().lower()
        if (
            status_code == 402
            and str(status.get("kind") or "").strip() == DEACTIVATED_WORKSPACE_KIND
            and row_id
            and line_no > 0
        ):
            confirmed.append({"row_id": row_id, "line_no": line_no})
    return confirmed


def test_openai_mailboxes(mailbox_admin: Any, payload: Any) -> dict[str, Any]:
    value = payload if isinstance(payload, Mapping) else {}
    row_completed = value.get("_on_row_completed")
    internal_batch = callable(row_completed)
    if not internal_batch:
        row_completed = None
    immediate_deleted: set[str] = set()
    immediate_deleted_count = 0
    delete_lock = Lock()

    def publish_completed(update: Any) -> None:
        nonlocal immediate_deleted_count
        if internal_batch and isinstance(update, Mapping):
            confirmed = _confirmed_deactivated_rows({"results": [update]})
            if confirmed:
                row_id = str(confirmed[0].get("row_id") or "").strip().lower()
                with delete_lock:
                    if row_id and row_id not in immediate_deleted:
                        deleted = delete_deactivated_mailboxes(mailbox_admin, confirmed)
                        if deleted.get("ok") and int(deleted.get("deactivated_deleted") or 0) > 0:
                            immediate_deleted.add(row_id)
                            immediate_deleted_count += int(deleted["deactivated_deleted"])
        if row_completed is not None:
            try:
                row_completed(update)
            except Exception:
                pass
    requested = value.get("rows")
    if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)) or not requested:
        return {"ok": False, "code": "openai_test_rows_required", "error": "请先勾选要测试的邮箱"}
    bindings: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for item in requested:
        if not isinstance(item, Mapping):
            return {"ok": False, "code": "openai_test_rows_invalid", "error": "批量测试参数无效"}
        try:
            line_no = int(item.get("line_no") or 0)
        except (TypeError, ValueError):
            line_no = 0
        row_id = str(item.get("row_id") or "").strip()
        binding = (line_no, row_id)
        if line_no <= 0 or not row_id or binding in seen:
            return {"ok": False, "code": "openai_test_rows_invalid", "error": "批量测试参数无效"}
        seen.add(binding)
        bindings.append(binding)

    with mailbox_admin._lock:
        config = mailbox_admin._config()
        lines = mailbox_admin._read_pool_lines(config)
        latest = mailbox_admin._latest_results_by_email(mailbox_admin._path(config, "results_dir"))
        state = mailbox_admin._read_json_file(mailbox_admin._path(config, "state_path"))
        state_by_line, state_by_email, state_by_row_id = index_mailbox_states(state.get("items"))
        resolved: list[dict[str, Any]] = []
        for original_line_no, expected_row_id in bindings:
            line_no = original_line_no
            if internal_batch:
                rebound = next(
                    (
                        (current_line, source_row)
                        for current_line, source_row in enumerate(lines, start=1)
                        if hmac.compare_digest(expected_row_id, row_id_from_source(source_row))
                    ),
                    None,
                )
                if rebound is None:
                    return {"ok": False, "code": "mailbox_rows_stale", "error": "邮箱列表已变化，请刷新后重试"}
                line_no, row = rebound
            else:
                if line_no > len(lines):
                    return {"ok": False, "code": "mailbox_rows_stale", "error": "邮箱列表已变化，请刷新后重试"}
                row = lines[line_no - 1]
                if not hmac.compare_digest(expected_row_id, row_id_from_source(row)):
                    return {"ok": False, "code": "mailbox_rows_stale", "error": "邮箱列表已变化，请刷新后重试"}
            email = email_from_row(row)
            document = latest.get(email) or {}
            result_status = str(document.get("status") or "").strip().lower()
            state_item = indexed_mailbox_state(
                state_by_line,
                state_by_email,
                state_by_row_id,
                row_id=expected_row_id,
                email=email,
                line_no=line_no,
            )
            if (
                str(state_item.get("status") or "").lower() == "available"
                and str(state_item.get("reason") or "") == "manual_restore"
            ):
                document = {}
                result_status = ""
            if result_status not in {"success", "ok", "uploaded"}:
                document = {}
            try:
                openai_status_id = credentials_from_result(document).account_id if document else ""
            except OpenAIQuotaError:
                openai_status_id = ""
            resolved.append({
                "row_id": expected_row_id,
                "line_no": original_line_no,
                "email": email,
                "openai_status_id": openai_status_id,
                "document": document,
            })
            if row_completed is not None:
                resolved[-1]["_on_row_completed"] = publish_completed

    if mailbox_admin.openai_direct_batch_tester is None:
        return {
            "ok": False,
            "code": "openai_test_not_configured",
            "error": "本机 OpenAI 连接测试尚未配置",
        }
    try:
        tested = mailbox_admin.openai_direct_batch_tester(
            resolved,
            str(config.get("proxy") or "").strip(),
        )
    except Exception:
        return {
            "ok": False,
            "code": "openai_test_batch_failed",
            "error": "本机 OpenAI 批量连接测试失败",
        }
    if not isinstance(tested, Mapping):
        return {
            "ok": False,
            "code": "openai_test_batch_failed",
            "error": "本机 OpenAI 批量连接测试失败",
        }

    result = dict(tested)
    if not result.get("ok"):
        return result
    current_deactivated_rows = _confirmed_deactivated_rows(result)
    deactivated_rows = current_deactivated_rows
    result["deactivated_rows"] = deactivated_rows
    result["deactivated_detected"] = len(current_deactivated_rows)
    if immediate_deleted_count:
        result["deactivated_deleted"] = immediate_deleted_count
    pending_delete = [
        item for item in deactivated_rows
        if str(item.get("row_id") or "").strip().lower() not in immediate_deleted
    ]
    if pending_delete:
        cleanup = delete_deactivated_mailboxes(mailbox_admin, pending_delete)
        if not cleanup.get("ok"):
            result.update(cleanup)
        else:
            result["deactivated_deleted"] = int(
                result.get("deactivated_deleted") or 0
            ) + int(cleanup.get("deactivated_deleted") or 0)
            result["deactivated_missing"] = int(cleanup.get("deactivated_missing") or 0)
    return result


__all__ = ["test_openai_mailboxes"]
