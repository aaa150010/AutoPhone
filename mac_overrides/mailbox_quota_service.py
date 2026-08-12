"""OpenAI quota batch queries and local cleanup for deactivated workspaces."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Mapping, Sequence
from typing import Any

try:
    from .mailbox_row_formats import row_id_from_source
    from .openai_quota_runtime import OpenAIQuotaError, credentials_from_result, public_quota_snapshot
    from .openai_row_status import persist_quota_row_status
except ImportError:  # Loaded as top-level runtime overrides by the Mac launcher.
    from mailbox_row_formats import row_id_from_source
    from openai_quota_runtime import OpenAIQuotaError, credentials_from_result, public_quota_snapshot
    from openai_row_status import persist_quota_row_status


DEACTIVATED_WORKSPACE_CODE = "openai_quota_deactivated_workspace"


def _is_deactivated_workspace(value: Mapping[str, Any]) -> bool:
    try:
        http_status = int(value.get("http_status") or 0)
    except (TypeError, ValueError):
        http_status = 0
    return (
        http_status == 402
        and str(value.get("code") or "").strip() == DEACTIVATED_WORKSPACE_CODE
    )


def delete_deactivated_mailboxes(mailbox_admin: Any, rows: Any) -> dict[str, Any]:
    wanted = {
        str(item.get("row_id") or "").strip().lower()
        for item in (rows or ())
        if isinstance(item, Mapping)
    }
    wanted = {
        value for value in wanted
        if len(value) == 64 and all(character in "0123456789abcdef" for character in value)
    }
    if not wanted:
        return {"ok": True, "deactivated_deleted": 0, "deactivated_missing": 0}

    with mailbox_admin._locked_pool_config() as config:
        lines = mailbox_admin._read_pool_lines(config)
        bindings = [
            {"row_id": row_id_from_source(line), "line_no": index}
            for index, line in enumerate(lines, start=1)
            if row_id_from_source(line) in wanted
        ]
    if not bindings:
        return {
            "ok": True,
            "deactivated_deleted": 0,
            "deactivated_missing": len(wanted),
        }

    result = mailbox_admin.delete_mailboxes({
        "line_nos": [item["line_no"] for item in bindings],
        "rows": bindings,
    })
    deleted = int(result.get("deleted") or 0) if isinstance(result, Mapping) else 0
    if not isinstance(result, Mapping) or not result.get("ok"):
        return {
            "ok": False,
            "code": "deactivated_workspace_local_delete_failed",
            "error": "清理已停用 OpenAI 工作空间的本地邮箱失败，请刷新后重试",
            "deactivated_deleted": 0,
            "deactivated_missing": len(wanted),
        }
    mailbox_admin._log(f"OpenAI 工作空间已停用，自动删除本地邮箱: {deleted} 条", "warn")
    return {
        "ok": True,
        "deactivated_deleted": deleted,
        "deactivated_missing": max(0, len(wanted) - deleted),
    }


def query_openai_quotas(mailbox_admin: Any, payload: Any) -> dict[str, Any]:
    value = payload if isinstance(payload, Mapping) else {}
    requested = value.get("rows")
    if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)) or not requested:
        return {"ok": False, "code": "mailbox_rows_required", "error": "请先勾选要查询额度的邮箱"}
    if len(requested) > 20:
        return {
            "ok": False,
            "code": "mailbox_quota_batch_too_large",
            "error": "单批最多查询 20 个邮箱额度",
        }
    row_completed = value.get("_on_row_completed")
    internal_batch = callable(row_completed)
    if not internal_batch:
        row_completed = None
    selected = mailbox_admin.selected_success_results({"rows": requested, "_include_skipped": True})
    if not selected.get("ok"):
        return selected
    if not callable(mailbox_admin.openai_quota_query):
        return {
            "ok": False,
            "code": "openai_quota_not_configured",
            "error": "OpenAI 额度查询尚未配置",
        }
    proxy = str(mailbox_admin._config().get("proxy") or "")

    def publish_completed(item: Mapping[str, Any]) -> None:
        if row_completed is None:
            return
        try:
            row_completed(dict(item))
        except Exception:
            pass

    def persist(public_item: Mapping[str, Any], quota_account_id: str, quota: Mapping[str, Any]) -> dict[str, Any]:
        public_quota = public_quota_snapshot(quota, queried_at=int(mailbox_admin.now_fn()))
        public_quota = persist_quota_row_status(
            mailbox_admin.openai_quota_status_store,
            account_id=quota_account_id,
            row_id=public_item["row_id"],
            value=public_quota,
        )
        if not public_quota:
            public_quota = {
                "status": "error",
                "node_code": "openai_quota",
                "node_label": "查询 OpenAI 额度",
                "code": "openai_quota_failed",
                "error": "查询 OpenAI 额度失败：额度状态持久化未返回结果",
            }
        completed = {**public_item, **public_quota}
        publish_completed(completed)
        return completed

    def query_one(item: Mapping[str, Any]) -> dict[str, Any]:
        public_item = {
            "row_id": str(item.get("row_id") or ""),
            "line_no": int(item.get("line_no") or 0),
        }
        try:
            quota_account_id = credentials_from_result(item["document"]).account_id
        except OpenAIQuotaError as exc:
            quota_account_id = ""
            quota: Mapping[str, Any] = exc.public()
        else:
            try:
                queried = mailbox_admin.openai_quota_query(item["document"], proxy)
                if not isinstance(queried, Mapping):
                    raise OpenAIQuotaError("openai_quota_invalid_result", "额度查询未返回有效结果")
                quota = queried
            except OpenAIQuotaError as exc:
                quota = exc.public()
            except Exception as exc:
                quota = {
                    "status": "error",
                    "node_code": "openai_quota",
                    "node_label": "查询 OpenAI 额度",
                    "code": "openai_quota_failed",
                    "error": f"查询 OpenAI 额度失败：未处理异常（{type(exc).__name__}）",
                }
        return persist(public_item, quota_account_id, quota)

    finished: list[dict[str, Any]] = []
    for item in selected.get("skipped_items") or []:
        public_item = {
            "row_id": str(item.get("row_id") or ""),
            "line_no": int(item.get("line_no") or 0),
        }
        finished.append(persist(public_item, "", {
            "status": "error",
            "node_code": "openai_quota",
            "node_label": "查询 OpenAI 额度",
            "code": "openai_quota_result_missing",
            "error": "查询 OpenAI 额度失败：本地成功结果缺失或不可读取，请重新登录后重试",
            "queried_at": int(mailbox_admin.now_fn()),
        }))

    selected_items = selected.get("items") or []
    results: list[dict[str, Any] | None] = [None] * len(selected_items)
    if selected_items:
        with ThreadPoolExecutor(max_workers=min(3, len(selected_items)), thread_name_prefix="openai-quota") as executor:
            futures = {executor.submit(query_one, item): index for index, item in enumerate(selected_items)}
            for future in as_completed(futures):
                results[futures[future]] = future.result()
    finished.extend(item for item in results if isinstance(item, dict))
    requested_order = {
        (str(item.get("row_id") or ""), int(item.get("line_no") or 0)): index
        for index, item in enumerate(requested)
        if isinstance(item, Mapping)
    }
    finished.sort(key=lambda item: requested_order.get((item["row_id"], item["line_no"]), len(requested)))
    current_deactivated_rows = [
        {"row_id": item["row_id"], "line_no": item["line_no"]}
        for item in finished
        if _is_deactivated_workspace(item)
    ]
    pending_deactivated_rows = [
        {"row_id": str(item.get("row_id") or ""), "line_no": int(item.get("line_no") or 0)}
        for item in ((value.get("_pending_deactivated_rows") or ()) if internal_batch else ())
        if isinstance(item, Mapping)
    ]
    deactivated_rows = list({
        item["row_id"]: item
        for item in [*pending_deactivated_rows, *current_deactivated_rows]
        if item["row_id"]
    }.values())
    result = {
        "ok": True,
        "results": finished,
        "queried": sum(item.get("status") == "ok" for item in finished),
        "failed": sum(item.get("status") == "error" for item in finished),
        "skipped": int(selected.get("skipped") or 0),
        "deactivated_rows": deactivated_rows,
        "deactivated_detected": len(current_deactivated_rows),
    }
    defer_delete = internal_batch and value.get("_defer_deactivated_delete") is True
    if deactivated_rows and not defer_delete:
        result.update(delete_deactivated_mailboxes(mailbox_admin, deactivated_rows))
    return result


__all__ = ["DEACTIVATED_WORKSPACE_CODE", "delete_deactivated_mailboxes", "query_openai_quotas"]
