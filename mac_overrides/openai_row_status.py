"""Stable, credential-free snapshot keys and public OpenAI row status policy."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

try:
    from .openai_quota_runtime import (
        persist_quota_snapshot,
        public_quota_snapshot,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from openai_quota_runtime import (
        persist_quota_snapshot,
        public_quota_snapshot,
    )


_OPENAI_STATUS_FIELDS = (
    "kind",
    "status_code",
    "label",
    "summary",
    "tested_at",
    "is_error",
    "is_abnormal",
    "is_test_failure",
    "needs_rerun",
)


def row_status_key(row_id: Any) -> str:
    """Return a namespaced stable key without exposing mailbox credentials."""

    value = str(row_id or "").strip().lower()
    return f"mailbox-row:{value}" if value else ""


def _status_flags(kind: Any, status_code: int | None) -> tuple[bool, bool, bool]:
    normalized_kind = str(kind or "").strip().lower()
    is_abnormal = status_code == 401 or normalized_kind == "unauthorized"
    is_rate_limited = status_code == 429 or normalized_kind == "rate_limited"
    is_test_failure = (
        not is_abnormal
        and not is_rate_limited
        and normalized_kind not in {"healthy", "unlinked", "not_linked", "not_ready", "untested"}
    )
    return is_abnormal or is_test_failure, is_abnormal, is_test_failure


def _needs_rerun(kind: Any, status_code: int | None) -> bool:
    normalized_kind = str(kind or "").strip().lower()
    return status_code in {401, 404} or normalized_kind in {"unauthorized", "not_found"}


def public_openai_status(
    value: Any,
    *,
    linked: bool,
    unuploaded: bool = False,
) -> dict[str, Any]:
    if not linked:
        return {
            "kind": "not_ready" if unuploaded else "unlinked",
            "status_code": None,
            "label": "缺少本地 OAuth 凭据" if unuploaded else "未关联",
            "summary": (
                "该邮箱没有可用于本机直连测试的 OpenAI OAuth 成功结果"
                if unuploaded
                else ""
            ),
            "tested_at": None,
            "is_error": False,
            "is_abnormal": False,
            "is_test_failure": False,
            "needs_rerun": False,
        }
    item = value if isinstance(value, Mapping) else {}
    if not item:
        return {
            "kind": "untested",
            "status_code": None,
            "label": "未测试",
            "summary": "",
            "tested_at": None,
            "is_error": False,
            "is_abnormal": False,
            "is_test_failure": False,
            "needs_rerun": False,
        }
    result = {field: item.get(field) for field in _OPENAI_STATUS_FIELDS}
    result["kind"] = str(result.get("kind") or "untested")[:40]
    result["label"] = str(result.get("label") or "未测试")[:80]
    result["summary"] = str(result.get("summary") or "")[:240]
    try:
        result["status_code"] = int(result["status_code"]) if result.get("status_code") is not None else None
    except (TypeError, ValueError):
        result["status_code"] = None
    try:
        result["tested_at"] = int(result["tested_at"]) if result.get("tested_at") is not None else None
    except (TypeError, ValueError):
        result["tested_at"] = None
    is_error, is_abnormal, is_test_failure = _status_flags(
        result["kind"],
        result["status_code"],
    )
    result["is_error"] = is_error
    result["is_abnormal"] = is_abnormal
    result["is_test_failure"] = is_test_failure
    result["needs_rerun"] = _needs_rerun(result["kind"], result["status_code"])
    return result


def _lookup(
    status_lookup: Callable[[str], Mapping[str, Any] | None] | None,
    identifier: str,
) -> dict[str, Any]:
    if not identifier or not callable(status_lookup):
        return {}
    try:
        value = status_lookup(identifier)
    except Exception:
        return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _meaningful_openai_status(value: Mapping[str, Any]) -> bool:
    return str(value.get("kind") or "").strip().lower() not in {"", "untested"}


def resolve_openai_status(
    status_lookup: Callable[[str], Mapping[str, Any] | None] | None,
    *,
    openai_account_id: Any = "",
    sub2_account_id: Any = "",
    row_id: Any = "",
    allow_row_fallback: bool = False,
) -> dict[str, Any]:
    """Prefer account-bound state, then a completed row-bound fallback."""

    account_ids = []
    for candidate in (openai_account_id, sub2_account_id):
        identifier = str(candidate or "").strip()
        if identifier and identifier not in account_ids:
            account_ids.append(identifier)

    first_account_status: dict[str, Any] = {}
    for identifier in account_ids:
        status = _lookup(status_lookup, identifier)
        if status and not first_account_status:
            first_account_status = status
        if _meaningful_openai_status(status):
            return public_openai_status(status, linked=True)

    if allow_row_fallback and not account_ids:
        status = _lookup(status_lookup, row_status_key(row_id))
        if _meaningful_openai_status(status):
            return public_openai_status(status, linked=True)

    if account_ids:
        return public_openai_status(first_account_status, linked=True)
    return public_openai_status(None, linked=False, unuploaded=True)


def resolve_quota_status(
    status_lookup: Callable[[str], Mapping[str, Any] | None] | None,
    *,
    account_id: Any = "",
    row_id: Any = "",
    allow_row_fallback: bool = False,
) -> dict[str, Any]:
    account_key = str(account_id or "").strip()
    identifiers = [account_key]
    if allow_row_fallback and not account_key:
        identifiers.append(row_status_key(row_id))
    for identifier in identifiers:
        snapshot = public_quota_snapshot(_lookup(status_lookup, identifier))
        if snapshot:
            return snapshot
    return {}


def persist_quota_row_status(
    status_store: Callable[[str, Mapping[str, Any]], Mapping[str, Any] | None] | None,
    *,
    account_id: Any,
    row_id: Any,
    value: Any,
) -> dict[str, Any]:
    identifier = str(account_id or "").strip() or row_status_key(row_id)
    return persist_quota_snapshot(status_store, identifier, value)


# Compatibility name retained for existing imports and tests.
public_sub2_status = public_openai_status


__all__ = [
    "persist_quota_row_status",
    "public_openai_status",
    "public_sub2_status",
    "resolve_openai_status",
    "resolve_quota_status",
    "row_status_key",
]
