"""Persistent account-level risk markers for phone verification retries."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
from threading import RLock
import time
from typing import Any, Callable, Mapping


_SAFE_CODE_RE = re.compile(r"[^a-z0-9_.-]+")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_CODES = frozenset(
    {
        "oauth_session_invalid",
        "auth_session_invalid",
        "phone_flow_mfa_regressed",
        "phone_flow_login_regressed",
        "auth_context_page_mismatch",
        "auth_context_cookies_missing",
        "auth_context_task_mismatch",
        "auth_context_generation_mismatch",
    }
)
_STAGES = frozenset({"phone_submitting", "sms_verifying"})


def account_fingerprint(email: Any) -> str:
    normalized = str(email or "").strip().lower()
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()


def _safe_code(value: Any, fallback: str) -> str:
    normalized = _SAFE_CODE_RE.sub("_", str(value or "").strip().lower()).strip("_")
    return (normalized or fallback)[:80]


def _safe_reason_code(value: Any) -> str:
    normalized = _safe_code(value, "auth_session_invalid")
    return normalized if normalized in _REASON_CODES else "auth_session_invalid"


def _safe_stage(value: Any) -> str:
    normalized = _safe_code(value, "phone_submitting")
    return normalized if normalized in _STAGES else "phone_submitting"


def _safe_count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _safe_timestamp(value: Any) -> float:
    try:
        timestamp = float(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return timestamp if math.isfinite(timestamp) and timestamp >= 0 else 0.0


def _stored_row(value: Any) -> dict[str, Any]:
    row = value if isinstance(value, Mapping) else {}
    return {
        "active": row.get("active") is True,
        "reason_code": _safe_reason_code(row.get("reason_code")),
        "count": _safe_count(row.get("count")),
        "first_at": _safe_timestamp(row.get("first_at")),
        "last_at": _safe_timestamp(row.get("last_at")),
        "stage": _safe_stage(row.get("stage")),
        "cleared_at": _safe_timestamp(row.get("cleared_at")),
    }


class PhoneRiskStore:
    """Store retry markers without persisting account or credential material."""

    def __init__(
        self,
        path: str | Path,
        *,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.now_fn = now_fn
        self._lock = RLock()

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            value = {}
        if not isinstance(value, Mapping):
            value = {}
        items = value.get("items") if isinstance(value.get("items"), Mapping) else {}
        sanitized = {
            str(key): _stored_row(row)
            for key, row in items.items()
            if _FINGERPRINT_RE.fullmatch(str(key)) and isinstance(row, Mapping)
        }
        return {"version": 1, "items": sanitized}

    def _write_unlocked(self, value: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(dict(value), ensure_ascii=True, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    @staticmethod
    def _public_row(value: Any) -> dict[str, Any]:
        return _stored_row(value)

    def mark(
        self,
        email: Any,
        *,
        reason_code: Any = "oauth_session_invalid",
        stage: Any = "phone_submitting",
    ) -> dict[str, Any]:
        key = account_fingerprint(email)
        if not key:
            return {}
        with self._lock:
            value = self._read_unlocked()
            items = value["items"]
            previous = items.get(key) if isinstance(items.get(key), Mapping) else {}
            now = _safe_timestamp(self.now_fn())
            first_at = _safe_timestamp(previous.get("first_at")) or now
            row = {
                "active": True,
                "reason_code": _safe_reason_code(reason_code),
                "count": _safe_count(previous.get("count")) + 1,
                "first_at": first_at,
                "last_at": now,
                "stage": _safe_stage(stage),
            }
            items[key] = row
            self._write_unlocked(value)
            return self._public_row(row)

    def clear(self, email: Any) -> dict[str, Any]:
        key = account_fingerprint(email)
        if not key:
            return {}
        with self._lock:
            value = self._read_unlocked()
            items = value["items"]
            previous = items.get(key)
            if not isinstance(previous, Mapping):
                return {}
            row = _stored_row(previous)
            row["active"] = False
            row["cleared_at"] = _safe_timestamp(self.now_fn())
            items[key] = row
            self._write_unlocked(value)
            return self._public_row(row)

    def status(self, email: Any) -> dict[str, Any]:
        key = account_fingerprint(email)
        if not key:
            return {}
        with self._lock:
            row = self._read_unlocked()["items"].get(key)
            return self._public_row(row) if isinstance(row, Mapping) else {}

    def is_active(self, email: Any) -> bool:
        return bool(self.status(email).get("active"))


__all__ = ["PhoneRiskStore", "account_fingerprint"]
