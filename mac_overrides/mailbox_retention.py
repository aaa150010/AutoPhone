"""Keep successful mailbox source rows while retiring them from future runs."""

from __future__ import annotations

import time
from typing import Any


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


__all__ = ["preserve_consumed_entry"]
