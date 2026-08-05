"""Mailbox source-row retention policies for terminal task outcomes."""

from __future__ import annotations

import time
from typing import Any, Callable


def preserve_consumed_entry(pool: Any, entry: Any, *, reason: str = "sub2_uploaded") -> bool:
    """Match one exact source entry and mark it consumed without deleting its pool row."""
    wanted_key = str(getattr(entry, "key", "") or "").strip()
    safe_reason = str(reason or "")[:180]
    if not wanted_key:
        return False

    def consume_item(state: dict[str, Any], entries: list[Any]) -> bool:
        matched = next(
            (
                candidate
                for candidate in entries
                if str(getattr(candidate, "key", "") or "").strip() == wanted_key
            ),
            None,
        )
        if matched is None:
            return False
        item = pool._item(state, matched)
        item.update(
            status="consumed",
            lease_until=0,
            reason=safe_reason,
            updated_at=int(time.time()),
        )
        pool._history(item, "consumed", safe_reason)
        return True

    return bool(pool._update(consume_item))


def remove_banned_entry(
    pool: Any,
    entry: Any,
    remove_fn: Callable[..., Any],
    *,
    reason: str = "account_banned",
) -> bool:
    """Remove one confirmed-banned source row and refresh remaining line bindings."""
    wanted_key = str(getattr(entry, "key", "") or "").strip()
    if not wanted_key:
        return False
    if not bool(remove_fn(pool, entry, reason=str(reason or "account_banned")[:180])):
        return False

    def refresh_line_bindings(state: dict[str, Any], entries: list[Any]) -> bool:
        items = state.get("items") if isinstance(state.get("items"), dict) else {}
        current = {
            str(getattr(candidate, "key", "") or "").strip(): candidate
            for candidate in entries
            if str(getattr(candidate, "key", "") or "").strip()
        }
        items.pop(wanted_key, None)
        for key, item in items.items():
            candidate = current.get(str(key))
            if candidate is None or not isinstance(item, dict):
                continue
            item["line_no"] = int(getattr(candidate, "line_no", 0) or 0)
            email = str(getattr(candidate, "email", "") or "").strip().lower()
            if email:
                item["email"] = email
        state["items"] = items
        return True

    return bool(pool._update(refresh_line_bindings))


__all__ = ["preserve_consumed_entry", "remove_banned_entry"]
