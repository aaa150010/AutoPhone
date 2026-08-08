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

# A session invalidation at the phone stage is expensive: the next attempt
# can allocate a paid SMS activation before discovering that the account is
# still unusable.  Keep the policy conservative by default, while allowing
# the launcher/tests to tune it without changing the persisted schema.
DEFAULT_QUARANTINE_THRESHOLD = 3
DEFAULT_QUARANTINE_SECONDS = 6 * 60 * 60
DEFAULT_ISOLATION_THRESHOLD = 6
_MAX_QUARANTINE_SECONDS = 30 * 24 * 60 * 60
_MAX_POLICY_COUNT = 10_000


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


def _safe_policy_count(value: Any, default: int) -> int:
    """Normalize a policy count without allowing malformed config to disable it."""

    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        parsed = default
    return max(0, min(_MAX_POLICY_COUNT, parsed))


def _safe_policy_seconds(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        parsed = default
    if not math.isfinite(parsed):
        parsed = default
    return max(0.0, min(float(_MAX_QUARANTINE_SECONDS), parsed))


def _stored_row(value: Any) -> dict[str, Any]:
    row = value if isinstance(value, Mapping) else {}
    sanitized = {
        "active": row.get("active") is True,
        "reason_code": _safe_reason_code(row.get("reason_code")),
        "count": _safe_count(row.get("count")),
        "first_at": _safe_timestamp(row.get("first_at")),
        "last_at": _safe_timestamp(row.get("last_at")),
        "stage": _safe_stage(row.get("stage")),
        "cleared_at": _safe_timestamp(row.get("cleared_at")),
    }
    # These fields were added after version 1.  Keep them optional so that
    # writing a legacy marker does not create needless schema churn.
    if "blocked_until" in row:
        sanitized["blocked_until"] = _safe_timestamp(row.get("blocked_until"))
    if "isolated" in row:
        sanitized["isolated"] = row.get("isolated") is True
    return sanitized


class PhoneRiskStore:
    """Store retry markers without persisting account or credential material."""

    def __init__(
        self,
        path: str | Path,
        *,
        now_fn: Callable[[], float] = time.time,
        quarantine_threshold: int = DEFAULT_QUARANTINE_THRESHOLD,
        quarantine_seconds: float = DEFAULT_QUARANTINE_SECONDS,
        isolation_threshold: int = DEFAULT_ISOLATION_THRESHOLD,
    ) -> None:
        self.path = Path(path)
        self.now_fn = now_fn
        self.quarantine_threshold = _safe_policy_count(
            quarantine_threshold,
            DEFAULT_QUARANTINE_THRESHOLD,
        ) or DEFAULT_QUARANTINE_THRESHOLD
        self.quarantine_seconds = _safe_policy_seconds(
            quarantine_seconds,
            DEFAULT_QUARANTINE_SECONDS,
        )
        # A value of zero explicitly disables permanent isolation.  Otherwise
        # the hard threshold is always at or above the quarantine threshold.
        parsed_isolation = _safe_policy_count(
            isolation_threshold,
            DEFAULT_ISOLATION_THRESHOLD,
        )
        self.isolation_threshold = (
            max(self.quarantine_threshold, parsed_isolation)
            if parsed_isolation
            else 0
        )
        self._lock = RLock()

    def _now(self) -> float:
        try:
            return _safe_timestamp(self.now_fn())
        except Exception:
            return _safe_timestamp(time.time())

    def _policy_snapshot(self, value: Any, *, now: float | None = None) -> dict[str, Any]:
        """Return a public row plus the effective SMS admission decision.

        ``blocked_until`` is derived for old rows that only contain ``count``
        and ``last_at``.  This makes a count accumulated by an older runtime
        immediately protect the account after an upgrade.
        """

        row = _stored_row(value)
        current = self._now() if now is None else _safe_timestamp(now)
        count = row["count"]
        isolated = bool(row["active"]) and (
            bool(row.get("isolated"))
            or (
                bool(self.isolation_threshold)
                and count >= self.isolation_threshold
            )
        )
        blocked_until = _safe_timestamp(row.get("blocked_until"))
        if (
            row["active"]
            and not isolated
            and count >= self.quarantine_threshold
            and blocked_until <= 0
        ):
            # Legacy rows have no explicit deadline.  Their latest marker is
            # the safest point from which to start the first cooldown.
            blocked_until = _safe_timestamp(row.get("last_at")) + self.quarantine_seconds
            if blocked_until <= 0 and self.quarantine_seconds > 0:
                blocked_until = current + self.quarantine_seconds
        quarantined = bool(
            row["active"]
            and not isolated
            and count >= self.quarantine_threshold
            and current < blocked_until
        )
        blocked = bool(row["active"] and (isolated or quarantined))
        snapshot = dict(row)
        snapshot.update(
            {
                "blocked": blocked,
                "quarantined": quarantined,
                "isolated": isolated,
                "blocked_until": blocked_until,
                "cooldown_remaining": max(
                    0,
                    int(math.ceil(blocked_until - current))
                    if blocked_until > current and not isolated
                    else 0,
                ),
                "sms_allowed": not blocked,
            }
        )
        return snapshot

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
            previous_row = _stored_row(previous)
            now = self._now()
            first_at = _safe_timestamp(previous.get("first_at")) or now
            count = _safe_count(previous_row.get("count")) + 1
            row = {
                "active": True,
                "reason_code": _safe_reason_code(reason_code),
                "count": count,
                "first_at": first_at,
                "last_at": now,
                "stage": _safe_stage(stage),
            }
            inherited_isolation = bool(previous_row.get("isolated"))
            if self.isolation_threshold and count >= self.isolation_threshold:
                inherited_isolation = True
            if inherited_isolation:
                # Permanent isolation is intentionally represented without a
                # timestamp: it remains in force until a successful clear.
                row["isolated"] = True
            elif count >= self.quarantine_threshold:
                row["blocked_until"] = now + self.quarantine_seconds
            items[key] = row
            self._write_unlocked(value)
            return self._policy_snapshot(row, now=now)

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
            row["cleared_at"] = self._now()
            # A successful phone OTP is an explicit recovery signal.  Remove
            # the current quarantine/isolation state while retaining count and
            # timestamps for diagnosis.
            row.pop("blocked_until", None)
            row.pop("isolated", None)
            items[key] = row
            self._write_unlocked(value)
            return self._policy_snapshot(row, now=row["cleared_at"])

    def status(self, email: Any) -> dict[str, Any]:
        key = account_fingerprint(email)
        if not key:
            return {}
        with self._lock:
            row = self._read_unlocked()["items"].get(key)
            return self._policy_snapshot(row) if isinstance(row, Mapping) else {}

    def is_active(self, email: Any) -> bool:
        return bool(self.status(email).get("active"))

    def decision(self, email: Any) -> dict[str, Any]:
        """Return the safe, current decision used before allocating an SMS.

        An empty result means the account has no marker and is admissible.
        Callers should treat ``blocked`` (or ``sms_allowed`` being false) as a
        hard stop before invoking any provider API.
        """

        return self.status(email)

    def should_skip_sms(self, email: Any) -> bool:
        """Whether a retry must be isolated before paid SMS allocation."""

        return bool(self.decision(email).get("blocked"))

    def is_quarantined(self, email: Any) -> bool:
        return bool(self.decision(email).get("quarantined"))

    def is_isolated(self, email: Any) -> bool:
        return bool(self.decision(email).get("isolated"))


__all__ = [
    "DEFAULT_ISOLATION_THRESHOLD",
    "DEFAULT_QUARANTINE_SECONDS",
    "DEFAULT_QUARANTINE_THRESHOLD",
    "PhoneRiskStore",
    "account_fingerprint",
]
