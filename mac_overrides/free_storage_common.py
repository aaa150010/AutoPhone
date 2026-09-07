"""Shared constants, errors and pure payload helpers for Free storage.

Split out of ``free_storage.py``; the original module re-exports every name
(including private ones referenced by adapters and tests) for compatibility.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import quote, unquote, urlsplit, urlunsplit


SCHEMA_VERSION = 1
MIGRATION_KEY = "legacy_migration_v1"
MANAGER_OWNER_KEY = "free_manager_owner_v1"
# A manager heartbeat is deliberately shorter than the lease TTL used by
# mailbox/proxy rows.  This gives a replacement process a bounded takeover
# window after a hard crash while still rejecting a live old worker during a
# normal restart.
MANAGER_OWNER_TTL_SECONDS = 90
# A small follow-up marker lets an upgraded runtime repair installations that
# were migrated by an earlier build before host/port proxy rows were
# supported.  It is deliberately separate from ``MIGRATION_KEY`` so the main
# import remains one-shot and operators can see that the repair ran.
PROXY_REPAIR_KEY = "legacy_proxy_repair_v1"
SECRET_MASK = "********"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAILBOX_SPLIT_RE = re.compile(r"---+|\|", re.ASCII)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|cookie|authorization|auth[_-]?code|"
    r"refresh|access[_-]?token|id[_-]?token|otp|verification[_-]?code|"
    r"mailbox[_-]?url|code[_-]?url|api[_-]?key|private[_-]?key|"
    r"proxy(?:_used)?$|proxy_password|proxy_username)",
    re.IGNORECASE,
)
_PRIVATE_KEYS = {
    "password",
    "registration_password",
    "account_password",
    "totp_secret",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "cookie",
    "cookies",
    "authorization",
    "auth_code",
    "mailbox_url",
    "code_url",
    "proxy",
    "proxy_used",
    "proxy_username",
    "proxy_password",
    "username",
    "credential_line",
}

# These fields describe capability/state and are safe to keep in the normal
# JSON projection.  The broad sensitive-key expression intentionally matches
# ``password``/``token`` substrings, so exclude the status/boolean variants
# before partitioning payloads.
_NON_SECRET_METADATA_KEYS = frozenset({
    "password_status",
    "password_set_after_registration",
    "has_password",
    "twofa_status",
    "has_totp",
    "has_access_token",
    "token_status",
    "token_type",
    "proxy_status",
    "proxy_scheme",
    "proxy_effective_scheme",
    "proxy_id",
    "proxy_fingerprint",
    "proxy_masked",
})
_NON_SECRET_METADATA_KEY_TOKENS = frozenset(
    re.sub(r"[^a-z0-9]", "", key.lower())
    for key in _NON_SECRET_METADATA_KEYS
)
_MISSING = object()

# Country/group labels belonged to the retired multi-pool allocator.  They are
# intentionally normalized away at the storage boundary so a legacy snapshot
# cannot reintroduce those dimensions through a task/mailbox public payload.
_LEGACY_PROXY_DIMENSION_KEYS = frozenset({"proxy_country", "proxy_group"})
_LEGACY_PLAIN_DIMENSION_KEYS = frozenset({"country", "group"})

# Keep the terminal set in one place.  A terminal task may receive an
# idempotent same-status update, but must never be moved back into an active
# state by a late worker callback.
TERMINAL_TASK_STATUSES = frozenset({
    "success",
    "partial_success",
    "failed",
    "stopped",
    "twofa_pending",
})


class FreeStorageError(RuntimeError):
    """Base error for the standalone Free SQLite store."""


class RevisionConflict(FreeStorageError):
    """Raised when a task update was based on an old revision."""

    def __init__(self, task_id: str, expected: int | None, actual: int | None) -> None:
        self.task_id = str(task_id)
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"任务 revision 冲突: task_id={self.task_id}, "
            f"expected={expected}, actual={actual}"
        )


class LeaseConflict(FreeStorageError):
    """Raised when a non-shareable resource is leased by another owner."""


class ManagerOwnerConflict(FreeStorageError):
    """Raised when another live Free manager owns the SQLite runtime."""

    def __init__(self, owner: Mapping[str, Any] | None = None) -> None:
        self.owner = dict(owner or {})
        super().__init__("Free manager 已被另一个活动进程占用")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(str(value or "").strip().encode("utf-8")).hexdigest()[:16]


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return json.dumps({}, ensure_ascii=False)


def _valid_migration_marker(value: Any, *, version: int = SCHEMA_VERSION) -> bool:
    """Validate a structured legacy-migration marker.

    A non-empty value is not sufficient: interrupted/hand-edited markers must
    be retried, while a marker from a newer schema must never be treated as a
    successful import by an older runtime.
    """
    try:
        parsed = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(parsed, Mapping):
        return False
    # Newer markers can explicitly record an incomplete source read.  Keep
    # older markers (which predate ``complete``) valid for compatibility, but
    # never let an incomplete marker suppress the retry on restart.
    if parsed.get("complete") is False:
        return False
    try:
        return int(parsed.get("version")) == int(version)
    except (TypeError, ValueError):
        return False


def _migration_marker_version(value: Any) -> int | None:
    """Extract a structured marker version, if one is present."""
    try:
        parsed = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, Mapping):
        return None
    try:
        return int(parsed.get("version"))
    except (TypeError, ValueError):
        return None


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return {}


def _clear_legacy_pool_dimensions(
    value: Any, *, include_plain: bool = False, _depth: int = 0
) -> Any:
    """Clear retired proxy dimensions recursively without mutating input.

    ``group`` is also a legitimate progress field (``progress.group=free``),
    so plain country/group keys are scrubbed only for proxy rows.  Task and
    mailbox payloads always clear the explicit ``proxy_*`` aliases.
    """
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            normalized = key.strip().lower()
            if normalized in _LEGACY_PROXY_DIMENSION_KEYS or (
                include_plain
                and _depth == 0
                and normalized in _LEGACY_PLAIN_DIMENSION_KEYS
            ):
                result[key] = ""
            else:
                result[key] = _clear_legacy_pool_dimensions(
                    raw_value, include_plain=include_plain, _depth=_depth + 1
                )
        return result
    if isinstance(value, list):
        return [
            _clear_legacy_pool_dimensions(
                item, include_plain=include_plain, _depth=_depth + 1
            )
            for item in value
        ]
    if isinstance(value, tuple):
        return [
            _clear_legacy_pool_dimensions(
                item, include_plain=include_plain, _depth=_depth + 1
            )
            for item in value
        ]
    return copy.deepcopy(value)


def _safe_float(value: Any, default: float | None = None) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        return default
    return parsed


def _stored_bool(value: Any, default: bool = False) -> bool:
    """Parse lifecycle booleans from JSON without treating ``'false'`` true."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            if float(value) in {0.0, 1.0}:
                return bool(int(value))
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled", ""}:
            return False
    return default


def _mask_email(value: Any) -> str:
    return str(value or "").strip()


def _mask_proxy(value: Any) -> str:
    """Return scheme/host/port only; credentials and query are discarded."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
        if not parsed.scheme or not parsed.hostname:
            return ""
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = ""
        try:
            if parsed.port:
                port = f":{parsed.port}"
        except ValueError:
            pass
        return urlunsplit((parsed.scheme.lower(), host + port, "", "", ""))
    except (TypeError, ValueError):
        return ""


def _redact(value: Any, *, key: str = "") -> Any:
    """Recursively redact values destined for a public/UI projection."""
    lowered = str(key or "").strip().lower()
    # Capability/state fields intentionally contain words such as
    # ``password`` or ``token`` but do not contain the credential itself.
    # Keep them visible so public task/account projections remain useful.
    if re.sub(r"[^a-z0-9]", "", lowered) in _NON_SECRET_METADATA_KEY_TOKENS:
        return copy.deepcopy(value)
    if lowered in {"email", "mailbox_email"} or lowered.endswith("_email"):
        return _mask_email(value)
    if lowered in {"proxy", "proxy_used", "proxy_url"}:
        return _mask_proxy(value)
    if lowered in _PRIVATE_KEYS or _SENSITIVE_KEY_RE.search(lowered):
        if value in (None, "", [], {}):
            return value
        return SECRET_MASK
    if isinstance(value, Mapping):
        return {str(k): _redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, key=key) for item in value]
    if isinstance(value, tuple):
        return [_redact(item, key=key) for item in value]
    return copy.deepcopy(value)


def _parse_mailbox_line(raw: Any) -> tuple[str, str] | None:
    text = str(raw or "").strip()
    if not text or text.startswith("#"):
        return None
    parts = _MAILBOX_SPLIT_RE.split(text, maxsplit=2)
    email = str(parts[0] or "").strip().lower()
    mailbox_url = str(parts[1] or "").strip() if len(parts) > 1 else ""
    try:
        parsed = urlsplit(mailbox_url)
    except ValueError:
        return None
    if not _EMAIL_RE.fullmatch(email) or parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return email, urlunsplit(parsed)


def _normalize_proxy(raw: Any, default_scheme: str = "socks5") -> str:
    value = str(raw or "").strip().strip('"').strip("'")
    if not value:
        return ""
    value = " ".join(value.replace("\t", " ").replace(",", " ").split())
    if "://" not in value:
        parts = value.split()
        if len(parts) >= 2:
            host, port = parts[:2]
            user = parts[2] if len(parts) > 2 else ""
            password = parts[3] if len(parts) > 3 else ""
            auth = f"{quote(user, safe='')}:{quote(password, safe='')}@" if user or password else ""
            value = f"{default_scheme}://{auth}{host}:{port}"
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h", "socks4"} or not parsed.hostname:
            return ""
        # Accessing .port validates malformed ports before persisting them.
        _ = parsed.port
        return urlunsplit(parsed)
    except (TypeError, ValueError):
        return ""


def _legacy_proxy_url(raw: Mapping[str, Any], default_scheme: str = "socks5") -> str:
    """Normalize both historical proxy record shapes.

    Older Free snapshots stored only ``host``, ``port``, ``username`` and
    ``password`` while newer snapshots store a complete URL.  Migration must
    understand both forms without changing the source JSON.  The returned
    value is used only inside the private SQLite payload; public projections
    still mask credentials.
    """
    if not isinstance(raw, Mapping):
        return ""
    direct = (
        raw.get("proxy")
        or raw.get("url")
        or raw.get("address")
        or raw.get("proxy_url")
    )
    normalized = _normalize_proxy(direct, default_scheme=default_scheme)
    if normalized:
        return normalized

    host = str(
        raw.get("host")
        or raw.get("hostname")
        or raw.get("server")
        or ""
    ).strip().strip("[]")
    if not host:
        return ""
    try:
        port = int(str(raw.get("port") or raw.get("proxy_port") or "0").strip())
    except (TypeError, ValueError):
        return ""
    if port < 1 or port > 65535:
        return ""
    scheme = str(
        raw.get("scheme")
        or raw.get("protocol")
        or raw.get("effective_scheme")
        or default_scheme
    ).strip().lower()
    if scheme not in {"http", "https", "socks4", "socks5", "socks5h"}:
        scheme = str(default_scheme or "socks5").strip().lower()
    if scheme not in {"http", "https", "socks4", "socks5", "socks5h"}:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    username = str(
        raw.get("username")
        or raw.get("user")
        or raw.get("proxy_username")
        or ""
    )
    password = str(
        raw.get("password")
        or raw.get("pass")
        or raw.get("proxy_password")
        or ""
    )
    auth = ""
    if username or password:
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return _normalize_proxy(
        urlunsplit((scheme, f"{auth}{host}:{port}", "", "", "")),
        default_scheme=scheme,
    )


def _payload_with_fields(payload: Mapping[str, Any] | None, **fields: Any) -> dict[str, Any]:
    result = _json_object(payload)
    for key, value in fields.items():
        if value is not None:
            result[key] = copy.deepcopy(value)
    return result


def _is_private_key(key: Any) -> bool:
    """Return whether a payload key belongs in the private sidecar.

    SQLite's scalar identity columns remain private as before.  This helper
    only governs the free-form JSON payload and deliberately leaves status
    metadata available to indexed/public callers.
    """
    lowered = str(key or "").strip().lower()
    if not lowered or re.sub(r"[^a-z0-9]", "", lowered) in _NON_SECRET_METADATA_KEY_TOKENS:
        return False
    return lowered in _PRIVATE_KEYS or bool(_SENSITIVE_KEY_RE.search(lowered))


def _split_private_payload(value: Any) -> tuple[Any, Any]:
    """Split a payload into public JSON and a private sidecar JSON value.

    Sensitive leaves are removed from the regular payload before it is stored.
    The sidecar preserves enough shape for private worker reads to reconstruct
    the historical mapping.  Lists containing a sensitive descendant are
    represented by an index map; a sensitive list under a sensitive key is
    kept intact.
    """
    if isinstance(value, Mapping):
        public: dict[str, Any] = {}
        private: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if _is_private_key(key):
                private[key] = copy.deepcopy(raw_value)
                continue
            public_value, private_value = _split_private_payload(raw_value)
            if public_value is not _MISSING:
                public[key] = public_value
            if private_value is not _MISSING:
                private[key] = private_value
        return public, private if private else _MISSING
    if isinstance(value, list):
        public_items: list[Any] = []
        private_items: dict[str, Any] = {}
        for index, raw_value in enumerate(value):
            public_value, private_value = _split_private_payload(raw_value)
            public_items.append(public_value if public_value is not _MISSING else {})
            if private_value is not _MISSING:
                private_items[str(index)] = private_value
        if private_items:
            return public_items, {"__list_private__": private_items}
        return public_items, _MISSING
    if isinstance(value, tuple):
        return _split_private_payload(list(value))
    return copy.deepcopy(value), _MISSING


def _merge_private_payload(public_value: Any, private_value: Any) -> Any:
    """Reconstruct a private worker payload from its public + sidecar JSON."""
    if private_value is _MISSING or private_value is None:
        return copy.deepcopy(public_value)
    if isinstance(private_value, Mapping) and "__list_private__" in private_value:
        result = list(public_value) if isinstance(public_value, list) else []
        entries = private_value.get("__list_private__")
        if isinstance(entries, Mapping):
            for raw_index, item in entries.items():
                try:
                    index = int(raw_index)
                except (TypeError, ValueError):
                    continue
                while len(result) <= index:
                    result.append({})
                result[index] = _merge_private_payload(result[index], item)
        return result
    if isinstance(private_value, Mapping):
        result = dict(public_value) if isinstance(public_value, Mapping) else {}
        for key, item in private_value.items():
            result[str(key)] = _merge_private_payload(result.get(str(key)), item)
        return result
    return copy.deepcopy(private_value)


def _partition_json(value: Mapping[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    # Apply the shared-pool invariant to every write, including updates from
    # compatibility adapters.  This prevents a stale task snapshot from
    # restoring retired country/group selectors after the one-time migration.
    cleaned = _clear_legacy_pool_dimensions(_json_object(value))
    public_value, private_value = _split_private_payload(cleaned)
    return (
        _json_object(public_value),
        _json_object(private_value) if private_value is not _MISSING else {},
    )
