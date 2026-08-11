"""Stable mailbox-row selection without exposing source credentials."""

from __future__ import annotations

import hmac
from collections.abc import Callable, Mapping, Sequence
from typing import Any


def resolve_source_rows(
    payload: Any,
    source_lines: Sequence[str],
    row_id_from_source: Callable[[str], str],
) -> dict[str, Any]:
    """Resolve an all-or-nothing row-id/line-number selection."""

    value = payload if isinstance(payload, Mapping) else {}
    requested = value.get("rows")
    if not isinstance(requested, Sequence) or isinstance(requested, (str, bytes)) or not requested:
        return {
            "ok": False,
            "code": "mailbox_rows_required",
            "error": "请先勾选要处理的邮箱",
        }

    bindings: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for item in requested:
        if not isinstance(item, Mapping):
            return _invalid_rows()
        try:
            line_no = int(item.get("line_no") or 0)
        except (TypeError, ValueError):
            line_no = 0
        row_id = str(item.get("row_id") or "").strip()
        binding = (line_no, row_id)
        if line_no <= 0 or not row_id or binding in seen:
            return _invalid_rows()
        seen.add(binding)
        bindings.append(binding)

    rows: list[dict[str, Any]] = []
    for line_no, expected_row_id in bindings:
        if line_no > len(source_lines):
            return _stale_rows()
        source_row = source_lines[line_no - 1]
        if not hmac.compare_digest(expected_row_id, row_id_from_source(source_row)):
            return _stale_rows()
        rows.append({
            "row_id": expected_row_id,
            "line_no": line_no,
            "source_row": source_row,
        })
    return {"ok": True, "rows": rows}


def _invalid_rows() -> dict[str, Any]:
    return {"ok": False, "code": "mailbox_rows_invalid", "error": "批量操作参数无效"}


def _stale_rows() -> dict[str, Any]:
    return {
        "ok": False,
        "code": "mailbox_rows_stale",
        "error": "邮箱列表已变化，请刷新后重试",
    }


__all__ = ["resolve_source_rows"]
