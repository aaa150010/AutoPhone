"""SUB2 account lineage extracted from persisted registration results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

try:
    from .mailbox_row_formats import email_from_row
    from .openai_quota_runtime import OpenAIQuotaError, credentials_from_result
except ImportError:  # Loaded as top-level override modules by the Mac launcher.
    from mailbox_row_formats import email_from_row
    from openai_quota_runtime import OpenAIQuotaError, credentials_from_result


def sub2_account_id_from_result(result: Any) -> str:
    value = result if isinstance(result, Mapping) else {}
    payload = value.get("result") if isinstance(value.get("result"), Mapping) else {}
    return str(payload.get("sub2api_account_id") or value.get("sub2api_account_id") or "").strip()


def latest_sub2_accounts_by_email(results_dir: str | Path) -> dict[str, dict[str, Any]]:
    """Index the latest successful SUB2 account binding for each mailbox."""

    root = Path(results_dir)
    latest: dict[str, dict[str, Any]] = {}
    if not root.exists():
        return latest
    for path in sorted(root.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        data = value if isinstance(value, dict) else {}
        if str(data.get("status") or "").lower() not in {"success", "ok", "uploaded"}:
            continue
        account_id = sub2_account_id_from_result(data)
        email = email_from_row(data.get("email") or data.get("source_row") or "")
        if not email or not account_id:
            continue
        try:
            fallback_created = path.stat().st_mtime
        except OSError:
            fallback_created = 0
        try:
            created = int(data.get("created_at") or data.get("updated_at") or fallback_created)
        except (TypeError, ValueError):
            created = int(fallback_created)
        previous = latest.get(email)
        if previous is None or created >= int(previous.get("created_at") or 0):
            try:
                openai_account_id = credentials_from_result(data).account_id
            except OpenAIQuotaError:
                openai_account_id = ""
            latest[email] = {
                "account_id": account_id,
                "openai_account_id": openai_account_id,
                "created_at": created,
                "result_file": str(path.resolve()),
            }
    return latest


__all__ = ["latest_sub2_accounts_by_email", "sub2_account_id_from_result"]
