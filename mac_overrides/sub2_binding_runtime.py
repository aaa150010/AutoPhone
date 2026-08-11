"""Pure decisions for updating an existing SUB2 account binding."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
from typing import Any


_RERUN_CODES = frozenset({401, 404})
_RERUN_KINDS = frozenset({"unauthorized", "not_found"})


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _status_code(status: Mapping[str, Any]) -> int | None:
    try:
        return int(status.get("status_code"))
    except (TypeError, ValueError):
        return None


def status_requires_existing_update(value: Any) -> bool:
    status = value if isinstance(value, Mapping) else {}
    return bool(
        _status_code(status) in _RERUN_CODES
        or _clean(status.get("kind")).lower() in _RERUN_KINDS
    )


def historical_openai_account_id(historical: Any, remote_account_id: Any) -> str:
    value = historical if isinstance(historical, Mapping) else {}
    remote_id = _clean(remote_account_id)
    if not remote_id or _clean(value.get("account_id")) != remote_id:
        return ""
    return _clean(value.get("openai_account_id"))


def resolve_existing_update_binding(
    historical: Any,
    *,
    direct_status_lookup: Callable[[str], Any] | None = None,
    sub2_status_lookup: Callable[[str], Any] | None = None,
) -> dict[str, Any] | None:
    """Return the historical remote binding when either status requires a rerun."""

    value = historical if isinstance(historical, Mapping) else {}
    remote_id = _clean(value.get("account_id"))
    if not remote_id:
        return None
    openai_id = historical_openai_account_id(value, remote_id)
    probes = (
        ("openai_direct", direct_status_lookup, openai_id),
        ("sub2", sub2_status_lookup, remote_id),
    )
    for source, lookup, lookup_id in probes:
        if not callable(lookup) or not lookup_id:
            continue
        try:
            raw_status = lookup(lookup_id)
        except Exception:
            continue
        status = raw_status if isinstance(raw_status, Mapping) else {}
        if not status_requires_existing_update(status):
            continue
        return {
            "account_id": remote_id,
            "openai_account_id": openai_id,
            "status_code": _status_code(status),
            "status_kind": _clean(status.get("kind")).lower(),
            "status_source": source,
        }
    return None


def successful_update_status_targets(binding: Any, result: Any) -> tuple[str, str]:
    binding_value = binding if isinstance(binding, Mapping) else {}
    result_value = result if isinstance(result, Mapping) else {}
    remote_id = _clean(
        binding_value.get("account_id") or result_value.get("sub2api_account_id")
    )
    openai_id = _clean(
        binding_value.get("openai_account_id")
        or result_value.get("chatgpt_account_id")
        or result_value.get("account_id")
    )
    return remote_id, openai_id


def clear_successful_update_statuses(
    binding: Any,
    result: Any,
    *,
    sub2_runtime: Any = None,
    direct_runtime: Any = None,
) -> tuple[str, str]:
    """Clear each cache with its own identifier after a verified update."""

    value = result if isinstance(result, Mapping) else {}
    if not value.get("ok"):
        return "", ""
    targets = successful_update_status_targets(binding, value)
    remote_id, openai_id = targets

    clear_sub2_status = getattr(sub2_runtime, "clear_status", None)
    if remote_id and callable(clear_sub2_status):
        try:
            clear_sub2_status(remote_id)
        except Exception:
            pass

    clear_direct_status = getattr(direct_runtime, "clear_status", None)
    if callable(clear_direct_status):
        for account_id in dict.fromkeys((openai_id, remote_id)):
            if not account_id:
                continue
            try:
                clear_direct_status(account_id)
            except Exception:
                pass
    mark_refreshed = getattr(direct_runtime, "mark_credentials_refreshed", None)
    if openai_id and callable(mark_refreshed):
        try:
            mark_refreshed(openai_id)
        except Exception:
            pass
    return targets


def confirmed_upload_log(result: Any) -> str:
    """Return a credential-free log only after every remote check passed."""

    value = result if isinstance(result, Mapping) else {}
    verified = all(
        value.get(key) is True
        for key in (
            "ok",
            "sub2_remote_verified",
            "sub2_group_verified",
            "sub2_chatgpt_account_id_verified",
        )
    )
    remote_id = _clean(value.get("sub2api_account_id"))
    if not verified or not remote_id:
        return ""
    fingerprint = hashlib.sha256(remote_id.encode("utf-8")).hexdigest()[:12]
    return (
        "  [SUB2 上传确认/sub2_upload_confirmed] 远端账号已回查并确认，"
        f"远端标识 sha256:{fingerprint}，保留远端当前分组且 OpenAI 身份一致"
    )


__all__ = [
    "clear_successful_update_statuses",
    "confirmed_upload_log",
    "historical_openai_account_id",
    "resolve_existing_update_binding",
    "status_requires_existing_update",
    "successful_update_status_targets",
]
