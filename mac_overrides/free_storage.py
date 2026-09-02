"""SQLite persistence primitives for the Free registration subsystem.

This module is deliberately independent from the current runtime facade.  It
provides a small, transactional store that can be wired into the runtime in a
later change without changing the on-disk JSON/TXT files in place.  Legacy
files are read once, recorded in ``storage_meta``, and never removed.

The database contains private payloads for workers and redacted projections
for UI callers.  Claims and leases are performed inside ``BEGIN IMMEDIATE``
transactions so two processes cannot claim the same mailbox accidentally.
Proxy leases are shareable by default because the Free policy permits several
tasks to use one healthy proxy concurrently.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
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
    text = str(value or "").strip()
    if "@" not in text:
        return ""
    local, domain = text.split("@", 1)
    if len(local) <= 1:
        masked = "*"
    elif len(local) == 2:
        masked = local[0] + "*"
    else:
        masked = local[0] + "***" + local[-1]
    return f"{masked}@{domain}"


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


class FreeSQLiteStore:
    """Thread/process-safe SQLite store for Free private resources.

    ``data_dir`` is expected to be the Free data directory (normally
    ``${GPTPHONE_DATA_DIR}/free_register``).  Methods returning a row expose
    private values by default for workers; ``public=True`` or the ``public_*``
    helpers return redacted projections suitable for UI responses.
    """

    def __init__(
        self,
        data_dir: str | Path,
        *,
        busy_timeout_ms: int = 30_000,
        auto_migrate: bool = True,
    ) -> None:
        self.root = Path(data_dir).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "free_register.sqlite3"
        self.busy_timeout_ms = max(100, int(busy_timeout_ms))
        self._lock = threading.RLock()
        # Read failures are kept separate from malformed individual rows.
        # The latter are stable data-quality diagnostics; the former mean a
        # legacy source may not have been seen at all and must keep migration
        # retryable on the next process start.
        self._legacy_read_errors: list[str] = []
        self._initialize()
        if auto_migrate:
            self.migrate_legacy()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000.0,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self, *, immediate: bool = True) -> Iterator[None]:
        """Serialize a multi-step operation within this process.

        Callers open their own connection inside this context so each SQL
        mutation can use an explicit ``BEGIN IMMEDIATE``.  ``immediate`` is
        retained for compatibility with early callers of this private helper.
        """
        del immediate
        with self._lock:
            yield None

    @staticmethod
    def _decode_json_value(value: Any) -> Any:
        try:
            return json.loads(str(value or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}

    def _migrate_payload_sidecars(self, db: sqlite3.Connection) -> None:
        """Move sensitive leaves out of pre-sidecar payload columns once.

        This is intentionally an in-place schema hygiene migration.  It does
        not alter timestamps, revisions, or lifecycle state, and is safe to
        rerun after an interrupted process because the partition operation is
        deterministic.
        """
        identity_columns = {
            "mailboxes": "row_id",
            "proxies": "proxy_id",
            "tasks": "task_id",
            "results": "row_id",
        }
        for table, identity in identity_columns.items():
            rows = db.execute(
                f"SELECT {identity},payload,private_payload FROM {table}"
            ).fetchall()
            for row in rows:
                combined = _merge_private_payload(
                    self._decode_json_value(row[1]),
                    self._decode_json_value(row[2]),
                )
                combined = _clear_legacy_pool_dimensions(
                    combined, include_plain=table == "proxies"
                )
                public_value, private_value = _partition_json(
                    combined if isinstance(combined, Mapping) else {}
                )
                public_json = _safe_json(public_value)
                private_json = _safe_json(private_value)
                if str(row[1] or "") == public_json and str(row[2] or "") == private_json:
                    continue
                db.execute(
                    f"UPDATE {table} SET payload=?,private_payload=? WHERE {identity}=?",
                    (public_json, private_json, str(row[0])),
                )

    def _initialize(self) -> None:
        with self._transaction():
            # Payload columns preserve forward compatibility while the scalar
            # fields make claims, status counts and pagination indexable.
            with self._connection() as db:
                try:
                    db.executescript(
                        """
                        CREATE TABLE IF NOT EXISTS storage_meta (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS mailboxes (
                            row_id TEXT PRIMARY KEY,
                            email TEXT NOT NULL,
                            mailbox_url TEXT NOT NULL,
                            status TEXT NOT NULL DEFAULT 'available',
                            batch_id TEXT NOT NULL DEFAULT '',
                            lease_owner TEXT NOT NULL DEFAULT '',
                            lease_until REAL,
                            revision INTEGER NOT NULL DEFAULT 0,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS proxies (
                            proxy_id TEXT PRIMARY KEY,
                            proxy TEXT NOT NULL,
                            scheme TEXT NOT NULL DEFAULT '',
                            status TEXT NOT NULL DEFAULT 'unknown',
                            enabled INTEGER NOT NULL DEFAULT 1,
                            lease_owner TEXT NOT NULL DEFAULT '',
                            lease_until REAL,
                            revision INTEGER NOT NULL DEFAULT 0,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS tasks (
                            task_id TEXT PRIMARY KEY,
                            status TEXT NOT NULL DEFAULT 'queued',
                            revision INTEGER NOT NULL DEFAULT 0,
                            lease_owner TEXT NOT NULL DEFAULT '',
                            lease_until REAL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS results (
                            row_id TEXT PRIMARY KEY,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS remail_orders (
                            order_no TEXT PRIMARY KEY,
                            status TEXT NOT NULL DEFAULT '',
                            delivery_email TEXT NOT NULL DEFAULT '',
                            imported INTEGER NOT NULL DEFAULT 0,
                            pool_row_id TEXT NOT NULL DEFAULT '',
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            payload TEXT NOT NULL DEFAULT '{}',
                            private_payload TEXT NOT NULL DEFAULT '{}'
                        );
                        CREATE TABLE IF NOT EXISTS resource_leases (
                            resource_type TEXT NOT NULL,
                            resource_id TEXT NOT NULL,
                            owner TEXT NOT NULL,
                            lease_until REAL NOT NULL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            PRIMARY KEY(resource_type, resource_id, owner)
                        );
                        CREATE INDEX IF NOT EXISTS idx_mailboxes_status ON mailboxes(status, row_id);
                        CREATE INDEX IF NOT EXISTS idx_mailboxes_lease ON mailboxes(lease_until);
                        CREATE INDEX IF NOT EXISTS idx_mailboxes_updated ON mailboxes(updated_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status, enabled, proxy_id);
                        CREATE INDEX IF NOT EXISTS idx_proxies_lease ON proxies(lease_until);
                        CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, updated_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_tasks_updated ON tasks(updated_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_leases_expiry ON resource_leases(resource_type, lease_until);
                        -- Compatibility names for callers that prefer an
                        -- explicit Free prefix.  Views avoid duplicating data
                        -- or creating a second source of truth.
                        CREATE VIEW IF NOT EXISTS free_storage_meta AS SELECT * FROM storage_meta;
                        CREATE VIEW IF NOT EXISTS free_mailboxes AS SELECT * FROM mailboxes;
                        CREATE VIEW IF NOT EXISTS free_proxies AS SELECT * FROM proxies;
                        CREATE VIEW IF NOT EXISTS free_tasks AS SELECT * FROM tasks;
                        CREATE VIEW IF NOT EXISTS free_results AS SELECT * FROM results;
                        CREATE VIEW IF NOT EXISTS free_remail_orders AS SELECT * FROM remail_orders;
                        CREATE VIEW IF NOT EXISTS free_resource_leases AS SELECT * FROM resource_leases;
                        """
                    )
                    # Existing installations may already have the v1 tables.
                    # Add the sidecar columns in place and normalize any
                    # malformed/null values without touching business rows.
                    existing_schema_row = db.execute(
                        "SELECT value FROM storage_meta WHERE key='schema_version'"
                    ).fetchone()
                    try:
                        existing_schema = int(existing_schema_row[0]) if existing_schema_row else 0
                    except (TypeError, ValueError):
                        existing_schema = 0
                    if existing_schema > SCHEMA_VERSION:
                        raise FreeStorageError(
                            f"SQLite schema 版本 {existing_schema} 高于当前运行时 {SCHEMA_VERSION}"
                        )
                    for table in ("mailboxes", "proxies", "tasks", "results", "remail_orders"):
                        columns = {
                            str(item[1])
                            for item in db.execute(f"PRAGMA table_info({table})").fetchall()
                        }
                        if "private_payload" not in columns:
                            db.execute(
                                f"ALTER TABLE {table} ADD COLUMN private_payload TEXT NOT NULL DEFAULT '{{}}'"
                            )
                        db.execute(
                            f"UPDATE {table} SET private_payload='{{}}' WHERE private_payload IS NULL"
                        )
                    self._migrate_payload_sidecars(db)
                    # ``executescript`` manages DDL in autocommit mode when
                    # isolation_level=None; use a short explicit transaction
                    # for the metadata write instead of committing a vanished
                    # DDL transaction.
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES('schema_version',?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (str(SCHEMA_VERSION),),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def _meta(self, key: str) -> str | None:
        with self._connection() as db:
            row = db.execute("SELECT value FROM storage_meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row is not None else None

    # ------------------------------------------------------------------
    # Process owner fencing
    # ------------------------------------------------------------------
    @staticmethod
    def _decode_manager_owner(value: Any) -> dict[str, Any]:
        try:
            parsed = json.loads(str(value or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return dict(parsed) if isinstance(parsed, Mapping) else {}

    @staticmethod
    def _pid_is_alive(pid: Any) -> bool:
        """Return whether a recorded process still exists on this host.

        ``os.kill(pid, 0)`` does not terminate anything.  A permission error
        still means that the process exists, so it is treated as live.  A
        malformed/absent PID is intentionally not considered a proof of life;
        the heartbeat timestamp remains the fallback for old metadata.
        """
        try:
            value = int(pid)
        except (TypeError, ValueError, OverflowError):
            return False
        if value <= 0:
            return False
        try:
            os.kill(value, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    @classmethod
    def _manager_owner_live(
        cls,
        owner: Mapping[str, Any],
        *,
        now: float,
        ttl_seconds: float,
    ) -> bool:
        try:
            heartbeat = float(owner.get("heartbeat_at"))
        except (TypeError, ValueError):
            return False
        # A clock adjustment must not make a recently written owner appear
        # stale.  The upper bound is the only expiry condition.
        if now - heartbeat > max(1.0, float(ttl_seconds)):
            return False
        pid = owner.get("pid")
        if pid not in (None, "", 0):
            return cls._pid_is_alive(pid)
        # Metadata written by an older build may not contain a PID.  Keep it
        # fenced while its heartbeat is fresh rather than allowing a second
        # manager to race the unknown process.
        return True

    def acquire_manager_owner(
        self,
        owner_id: str,
        *,
        pid: int | None = None,
        now: float | None = None,
        ttl_seconds: int = MANAGER_OWNER_TTL_SECONDS,
    ) -> dict[str, Any]:
        """Atomically claim the Free manager runtime.

        The claim lives in ``storage_meta`` so it is shared by every process
        using the isolated Free database.  A live owner causes
        :class:`ManagerOwnerConflict`; an expired/dead owner is replaced with
        a monotonically increasing epoch.  Callers must renew the returned
        ``owner_id``/``epoch`` pair and use that pair as a write fence.
        """
        normalized = str(owner_id or "").strip()
        if not normalized:
            raise ValueError("owner_id 不能为空")
        current_time = float(time.time() if now is None else now)
        process_id = int(os.getpid() if pid is None else pid)
        ttl = max(1, int(ttl_seconds))
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT value FROM storage_meta WHERE key=?",
                        (MANAGER_OWNER_KEY,),
                    ).fetchone()
                    existing = self._decode_manager_owner(row[0] if row else None)
                    existing_id = str(existing.get("owner_id") or "").strip()
                    if (
                        existing_id
                        and existing_id != normalized
                        and self._manager_owner_live(
                            existing, now=current_time, ttl_seconds=ttl
                        )
                    ):
                        db.execute("ROLLBACK")
                        raise ManagerOwnerConflict(existing)
                    try:
                        previous_epoch = max(0, int(existing.get("epoch") or 0))
                    except (TypeError, ValueError, OverflowError):
                        previous_epoch = 0
                    # Re-acquiring the same token is idempotent (useful for a
                    # controlled application reload); a new token advances the
                    # fence so stale workers cannot write afterwards.
                    epoch = previous_epoch if existing_id == normalized else previous_epoch + 1
                    record = {
                        "owner_id": normalized,
                        "pid": process_id,
                        "epoch": epoch,
                        "started_at": current_time,
                        "heartbeat_at": current_time,
                        "ttl_seconds": ttl,
                    }
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (MANAGER_OWNER_KEY, _safe_json(record)),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return record

    def renew_manager_owner(
        self,
        owner_id: str,
        epoch: int,
        *,
        pid: int | None = None,
        now: float | None = None,
        ttl_seconds: int = MANAGER_OWNER_TTL_SECONDS,
    ) -> bool:
        """Refresh a manager claim only when its owner/epoch still match."""
        normalized = str(owner_id or "").strip()
        if not normalized:
            return False
        current_time = float(time.time() if now is None else now)
        process_id = int(os.getpid() if pid is None else pid)
        ttl = max(1, int(ttl_seconds))
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT value FROM storage_meta WHERE key=?",
                        (MANAGER_OWNER_KEY,),
                    ).fetchone()
                    existing = self._decode_manager_owner(row[0] if row else None)
                    if (
                        str(existing.get("owner_id") or "").strip() != normalized
                        or int(existing.get("epoch") or -1) != int(epoch)
                    ):
                        db.execute("COMMIT")
                        return False
                    existing.update({
                        "pid": process_id,
                        "heartbeat_at": current_time,
                        "ttl_seconds": ttl,
                    })
                    db.execute(
                        "UPDATE storage_meta SET value=? WHERE key=?",
                        (_safe_json(existing), MANAGER_OWNER_KEY),
                    )
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def manager_owner_is_current(self, owner_id: str, epoch: int) -> bool:
        """Check the exact owner/epoch pair without extending its lease."""
        normalized = str(owner_id or "").strip()
        if not normalized:
            return False
        with self._connection() as db:
            row = db.execute(
                "SELECT value FROM storage_meta WHERE key=?",
                (MANAGER_OWNER_KEY,),
            ).fetchone()
        owner = self._decode_manager_owner(row[0] if row else None)
        try:
            owner_epoch = int(owner.get("epoch"))
        except (TypeError, ValueError, OverflowError):
            return False
        return (
            str(owner.get("owner_id") or "").strip() == normalized
            and owner_epoch == int(epoch)
        )

    def release_manager_owner(self, owner_id: str, epoch: int) -> bool:
        """Delete a claim only if the caller still owns its fence."""
        normalized = str(owner_id or "").strip()
        if not normalized:
            return False
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT value FROM storage_meta WHERE key=?",
                        (MANAGER_OWNER_KEY,),
                    ).fetchone()
                    owner = self._decode_manager_owner(row[0] if row else None)
                    try:
                        matches = (
                            str(owner.get("owner_id") or "").strip() == normalized
                            and int(owner.get("epoch")) == int(epoch)
                        )
                    except (TypeError, ValueError, OverflowError):
                        matches = False
                    if not matches:
                        db.execute("COMMIT")
                        return False
                    deleted = db.execute(
                        "DELETE FROM storage_meta WHERE key=?",
                        (MANAGER_OWNER_KEY,),
                    ).rowcount == 1
                    db.execute("COMMIT")
                    return deleted
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def manager_owner_status(self) -> dict[str, Any]:
        """Return a credential-free owner health snapshot for diagnostics."""
        raw = self._meta(MANAGER_OWNER_KEY)
        owner = self._decode_manager_owner(raw)
        try:
            heartbeat = float(owner.get("heartbeat_at"))
        except (TypeError, ValueError):
            heartbeat = 0.0
        try:
            ttl = max(1, int(owner.get("ttl_seconds") or MANAGER_OWNER_TTL_SECONDS))
        except (TypeError, ValueError, OverflowError):
            ttl = MANAGER_OWNER_TTL_SECONDS
        age = max(0.0, time.time() - heartbeat) if heartbeat else None
        return {
            "present": bool(owner.get("owner_id")),
            "active": bool(owner.get("owner_id")) and self._manager_owner_live(
                owner, now=time.time(), ttl_seconds=ttl
            ),
            "epoch": int(owner.get("epoch") or 0),
            "pid": int(owner.get("pid") or 0),
            "heartbeat_age_seconds": round(age, 3) if age is not None else None,
            "ttl_seconds": ttl,
        }

    # ------------------------------------------------------------------
    # Legacy migration
    # ------------------------------------------------------------------
    def _record_legacy_read_error(self, path: Path, kind: str) -> None:
        """Record a credential-free, stable source-read diagnostic."""
        source_names = {
            "free_mailbox_pool.txt": "mailbox_pool",
            "free_mailbox_state.json": "mailbox_state",
            "free_proxy_pool.json": "proxy_state",
            "free_proxy_pool.txt": "proxy_pool",
            "tasks.json": "task_state",
        }
        # Result filenames came from legacy integrations and are not a safe
        # diagnostic identifier: some installations used an email address or
        # credential-derived value as the stem. Collapse them to a fixed
        # source code. Unknown sources use only a short hash, never the name.
        if path.parent.name == "free_register_results":
            source = "result"
        else:
            source = source_names.get(path.name)
        if not source:
            source = f"source_{hashlib.sha256(path.name.encode('utf-8')).hexdigest()[:8]}"
        marker = f"legacy_{str(kind or 'read').strip().lower()}_{source}"
        if marker not in self._legacy_read_errors:
            self._legacy_read_errors.append(marker)

    def _read_json_file(self, path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default
        except json.JSONDecodeError:
            self._record_legacy_read_error(path, "invalid")
            return default
        except (OSError, UnicodeError):
            self._record_legacy_read_error(path, "read")
            return default

    def _legacy_mailboxes(self) -> tuple[list[dict[str, Any]], list[str]]:
        errors: list[str] = []
        pool_path = self.root / "free_mailbox_pool.txt"
        state_path = self.root / "free_mailbox_state.json"
        try:
            lines = pool_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            lines = []
        except (OSError, UnicodeError):
            self._record_legacy_read_error(pool_path, "read")
            lines = []
        state_payload = self._read_json_file(state_path, {})
        state_rows = state_payload.get("rows") if isinstance(state_payload, Mapping) else {}
        if not isinstance(state_rows, Mapping):
            state_rows = {}
        rows: list[dict[str, Any]] = []
        for line_no, raw in enumerate(lines, 1):
            parsed = _parse_mailbox_line(raw)
            if parsed is None:
                if str(raw or "").strip() and not str(raw).lstrip().startswith("#"):
                    errors.append(f"mailbox_line_{line_no}")
                continue
            email, mailbox_url = parsed
            row_id = _fingerprint(f"{email}|{mailbox_url}")
            state = state_rows.get(row_id) if isinstance(state_rows, Mapping) else None
            state = dict(state) if isinstance(state, Mapping) else {}
            payload = _payload_with_fields(
                _clear_legacy_pool_dimensions(state),
                email=email,
                mailbox_url=mailbox_url,
                row_id=row_id,
            )
            rows.append({
                "row_id": row_id,
                "email": email,
                "mailbox_url": mailbox_url,
                "status": str(state.get("status") or "available"),
                "batch_id": str(state.get("batch_id") or ""),
                "lease_owner": str(state.get("lease_owner") or ""),
                "lease_until": _safe_float(state.get("lease_until")),
                "revision": max(0, int(state.get("revision") or 0)) if str(state.get("revision") or "0").lstrip("-").isdigit() else 0,
                "created_at": str(state.get("created_at") or _now()),
                "updated_at": str(state.get("updated_at") or _now()),
                "payload": payload,
            })
        return rows, errors

    def _legacy_proxies(self) -> tuple[list[dict[str, Any]], list[str]]:
        errors: list[str] = []
        path = self.root / "free_proxy_pool.json"
        payload = self._read_json_file(path, None)
        raw_rows = payload.get("proxies") if isinstance(payload, Mapping) else None
        if not isinstance(raw_rows, list):
            raw_rows = []
        if not raw_rows:
            legacy_path = self.root / "free_proxy_pool.txt"
            try:
                raw_lines = legacy_path.read_text(encoding="utf-8").splitlines()
            except FileNotFoundError:
                raw_lines = []
            except (OSError, UnicodeError):
                self._record_legacy_read_error(legacy_path, "read")
                raw_lines = []
            raw_rows = [{"proxy": line} for line in raw_lines]
        rows: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_rows, 1):
            if not isinstance(raw, Mapping):
                errors.append(f"proxy_row_{index}")
                continue
            # v1-v3 snapshots used host/port/auth scalar fields and did not
            # include a ``proxy`` URL.  Accept that shape as well as the
            # complete URL used by v4+ snapshots.
            proxy = _legacy_proxy_url(raw)
            if not proxy:
                errors.append(f"proxy_row_{index}")
                continue
            parsed = urlsplit(proxy)
            proxy_id = str(raw.get("proxy_id") or _fingerprint(proxy))
            now = _now()
            row_payload = _clear_legacy_pool_dimensions(raw, include_plain=True)
            row_payload.setdefault("proxy", proxy)
            rows.append({
                "proxy_id": proxy_id,
                "proxy": proxy,
                "scheme": str(raw.get("scheme") or parsed.scheme).lower(),
                "status": str(raw.get("status") or "unknown"),
                "enabled": 0 if raw.get("enabled") is False else 1,
                "lease_owner": str(raw.get("lease_owner") or ""),
                "lease_until": _safe_float(raw.get("lease_until")),
                "revision": max(0, int(raw.get("revision") or 0)) if str(raw.get("revision") or "0").lstrip("-").isdigit() else 0,
                "created_at": str(raw.get("created_at") or raw.get("imported_at") or now),
                "updated_at": str(raw.get("updated_at") or now),
                "payload": row_payload,
            })
        # Some installations contain a partially written/old JSON snapshot
        # alongside the authoritative text pool.  If no JSON row could be
        # normalized, use the text rows as a read-only fallback instead of
        # silently creating an empty SQLite proxy pool.
        if not rows:
            legacy_path = self.root / "free_proxy_pool.txt"
            try:
                raw_lines = legacy_path.read_text(encoding="utf-8").splitlines()
            except FileNotFoundError:
                raw_lines = []
            except (OSError, UnicodeError):
                self._record_legacy_read_error(legacy_path, "read")
                raw_lines = []
            for line_no, raw_line in enumerate(raw_lines, 1):
                proxy = _normalize_proxy(raw_line)
                if not proxy:
                    if str(raw_line or "").strip():
                        errors.append(f"proxy_line_{line_no}")
                    continue
                parsed = urlsplit(proxy)
                proxy_id = _fingerprint(proxy)
                now = _now()
                rows.append({
                    "proxy_id": proxy_id,
                    "proxy": proxy,
                    "scheme": str(parsed.scheme or "socks5").lower(),
                    "status": "unknown",
                    "enabled": 1,
                    "lease_owner": "",
                    "lease_until": None,
                    "revision": 0,
                    "created_at": now,
                    "updated_at": now,
                    "payload": {
                        "proxy": proxy,
                        "proxy_id": proxy_id,
                        "line_no": line_no,
                    },
                })
        return rows, errors

    def _legacy_tasks(self) -> tuple[list[dict[str, Any]], list[str]]:
        errors: list[str] = []
        payload = self._read_json_file(self.root / "tasks.json", {})
        raw_tasks = payload.get("tasks") if isinstance(payload, Mapping) else {}
        if not isinstance(raw_tasks, Mapping):
            return [], errors
        rows: list[dict[str, Any]] = []
        for task_id, raw in raw_tasks.items():
            if not isinstance(raw, Mapping):
                # Legacy task keys are operator-controlled and some old
                # integrations used an email address (or another secret) as
                # the dictionary key.  Migration diagnostics must remain
                # credential-free, so expose only a stable shape code.
                errors.append("task_row_invalid")
                continue
            item = _clear_legacy_pool_dimensions(raw)
            normalized_id = str(item.get("task_id") or task_id).strip()
            if not normalized_id:
                errors.append("task_empty_id")
                continue
            value = item.get("revision")
            try:
                revision = max(0, int(value or 0))
            except (TypeError, ValueError):
                revision = 0
            now = _now()
            rows.append({
                "task_id": normalized_id,
                "status": str(item.get("status") or "queued"),
                "revision": revision,
                "lease_owner": str(item.get("lease_owner") or ""),
                "lease_until": _safe_float(item.get("lease_until")),
                "created_at": str(item.get("created_at") or item.get("queued_at") or now),
                "updated_at": str(item.get("updated_at") or now),
                "payload": item,
            })
        return rows, errors

    def _legacy_results(self) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
        directory = self.root / "free_register_results"
        if not directory.is_dir():
            return [], []
        rows: list[tuple[str, dict[str, Any]]] = []
        errors: list[str] = []
        for path in sorted(directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                continue
            except json.JSONDecodeError:
                self._record_legacy_read_error(path, "invalid")
                errors.append("result_invalid")
                continue
            except (OSError, UnicodeError):
                self._record_legacy_read_error(path, "read")
                errors.append("result_unreadable")
                continue
            if not isinstance(payload, Mapping):
                errors.append("result_invalid_shape")
                continue
            row_id = str(payload.get("row_id") or path.stem).strip()
            if row_id:
                rows.append((row_id, _clear_legacy_pool_dimensions(payload)))
        return rows, errors

    def _repair_legacy_proxies(self) -> dict[str, Any]:
        """Serialize a complete legacy proxy repair within this process."""
        with self._lock:
            return self._repair_legacy_proxies_locked()

    def _repair_legacy_proxies_locked(self) -> dict[str, Any]:
        """Backfill proxy rows for databases created by an older runtime.

        The first SQLite migration shipped before the legacy host/port record
        shape was understood.  Its completion marker is still valid for
        mailboxes/tasks/results, so changing that marker would cause an
        unnecessary full import.  This narrow, separately marked repair only
        inserts missing proxy rows and is safe to run more than once.
        """
        self._legacy_read_errors = []
        repair_marker = self._meta(PROXY_REPAIR_KEY)
        repair_version = _migration_marker_version(repair_marker)
        if repair_version is not None and repair_version > SCHEMA_VERSION:
            raise FreeStorageError(
                f"SQLite 代理迁移标记版本 {repair_version} 高于当前运行时 {SCHEMA_VERSION}"
            )
        if _valid_migration_marker(repair_marker):
            return {"migrated": False, "reason": "already_repaired"}
        proxies, errors = self._legacy_proxies()
        blocking_errors = list(self._legacy_read_errors)
        counts = 0
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    for row in proxies:
                        public_payload, private_payload = _partition_json(row["payload"])
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO proxies(proxy_id,proxy,scheme,status,enabled,lease_owner,lease_until,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                row["proxy_id"], row["proxy"], row["scheme"], row["status"],
                                row["enabled"], row["lease_owner"], row["lease_until"],
                                row["revision"], row["created_at"], row["updated_at"],
                                _safe_json(public_payload), _safe_json(private_payload),
                            ),
                        )
                        counts += int(cursor.rowcount > 0)
                    # A source read failure means the repair did not inspect
                    # the complete legacy pool. Store an explicit incomplete
                    # marker so a later startup retries it; malformed rows
                    # alone remain informational and do not block completion.
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (PROXY_REPAIR_KEY, _safe_json({
                            "version": SCHEMA_VERSION,
                            "complete": not bool(blocking_errors),
                            "completed_at": now if not blocking_errors else None,
                            "proxies": counts,
                            "errors": (blocking_errors + errors)[:100],
                        })),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return {
            "migrated": True,
            "proxies": counts,
            "errors": (blocking_errors + errors)[:100],
            "recovery_required": bool(blocking_errors),
        }

    def migrate_legacy(self, *, force: bool = False) -> dict[str, Any]:
        """Serialize legacy source reads, marker writes and imports."""
        with self._lock:
            return self._migrate_legacy_locked(force=force)

    def _migrate_legacy_locked(self, *, force: bool = False) -> dict[str, Any]:
        """Import legacy files once, without deleting or rewriting them.

        ``force`` is intended for an operator explicitly requesting a second
        read.  Inserts remain ``OR IGNORE`` so repeated calls are idempotent.
        """
        self._legacy_read_errors = []
        marker = self._meta(MIGRATION_KEY)
        marker_version = _migration_marker_version(marker)
        if marker_version is not None and marker_version > SCHEMA_VERSION:
            raise FreeStorageError(
                f"SQLite 迁移标记版本 {marker_version} 高于当前运行时 {SCHEMA_VERSION}"
            )
        if not force and _valid_migration_marker(marker):
            # Complete the narrow compatibility repair before returning the
            # usual idempotent result.  Existing callers still receive the
            # historical ``already_migrated`` reason.
            self._repair_legacy_proxies()
            return {"migrated": False, "reason": "already_migrated", "version": SCHEMA_VERSION}
        mailboxes, mailbox_errors = self._legacy_mailboxes()
        proxies, proxy_errors = self._legacy_proxies()
        tasks, task_errors = self._legacy_tasks()
        results, result_errors = self._legacy_results()
        blocking_errors = list(self._legacy_read_errors)
        errors = blocking_errors + mailbox_errors + proxy_errors + task_errors + result_errors
        counts = {"mailboxes": 0, "proxies": 0, "tasks": 0, "results": 0}
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    for row in mailboxes:
                        public_payload, private_payload = _partition_json(row["payload"])
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO mailboxes(row_id,email,mailbox_url,status,batch_id,lease_owner,lease_until,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (row["row_id"], row["email"], row["mailbox_url"], row["status"], row["batch_id"], row["lease_owner"], row["lease_until"], row["revision"], row["created_at"], row["updated_at"], _safe_json(public_payload), _safe_json(private_payload)),
                        )
                        counts["mailboxes"] += int(cursor.rowcount > 0)
                        # Preserve an active legacy owner in the normalized
                        # lease table.  The scalar lease columns remain for
                        # compatibility, but recovery/renewal operates on
                        # ``resource_leases`` exclusively.
                        try:
                            mailbox_until = float(row.get("lease_until") or 0)
                        except (TypeError, ValueError):
                            mailbox_until = 0.0
                        mailbox_owner = str(row.get("lease_owner") or "").strip()
                        if mailbox_owner and mailbox_until > time.time():
                            db.execute(
                                "INSERT OR IGNORE INTO resource_leases "
                                "(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                                "VALUES('mailbox',?,?,?,?,?)",
                                (row["row_id"], mailbox_owner, mailbox_until, now, now),
                            )
                    for row in proxies:
                        public_payload, private_payload = _partition_json(row["payload"])
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO proxies(proxy_id,proxy,scheme,status,enabled,lease_owner,lease_until,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (row["proxy_id"], row["proxy"], row["scheme"], row["status"], row["enabled"], row["lease_owner"], row["lease_until"], row["revision"], row["created_at"], row["updated_at"], _safe_json(public_payload), _safe_json(private_payload)),
                        )
                        counts["proxies"] += int(cursor.rowcount > 0)
                        try:
                            proxy_until = float(row.get("lease_until") or 0)
                        except (TypeError, ValueError):
                            proxy_until = 0.0
                        proxy_owner = str(row.get("lease_owner") or "").strip()
                        if proxy_owner and proxy_until > time.time():
                            db.execute(
                                "INSERT OR IGNORE INTO resource_leases "
                                "(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                                "VALUES('proxy',?,?,?,?,?)",
                                (row["proxy_id"], proxy_owner, proxy_until, now, now),
                            )
                    for row in tasks:
                        public_payload, private_payload = _partition_json(row["payload"])
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO tasks(task_id,status,revision,lease_owner,lease_until,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?)",
                            (row["task_id"], row["status"], row["revision"], row["lease_owner"], row["lease_until"], row["created_at"], row["updated_at"], _safe_json(public_payload), _safe_json(private_payload)),
                        )
                        counts["tasks"] += int(cursor.rowcount > 0)
                        try:
                            task_until = float(row.get("lease_until") or 0)
                        except (TypeError, ValueError):
                            task_until = 0.0
                        task_owner = str(row.get("lease_owner") or "").strip()
                        if task_owner and task_until > time.time():
                            db.execute(
                                "INSERT OR IGNORE INTO resource_leases "
                                "(resource_type,resource_id,owner,lease_until,created_at,updated_at) "
                                "VALUES('task',?,?,?,?,?)",
                                (row["task_id"], task_owner, task_until, now, now),
                            )
                    for row_id, payload in results:
                        public_payload, private_payload = _partition_json(payload)
                        cursor = db.execute(
                            "INSERT OR IGNORE INTO results(row_id,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?)",
                            (row_id, now, now, _safe_json(public_payload), _safe_json(private_payload)),
                        )
                        counts["results"] += int(cursor.rowcount > 0)
                    summary = {
                        "version": SCHEMA_VERSION,
                        "complete": not bool(blocking_errors),
                        "completed_at": now if not blocking_errors else None,
                        "counts": counts,
                        "errors": errors[:100],
                    }
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (MIGRATION_KEY, _safe_json(summary)),
                    )
                    db.execute(
                        "INSERT INTO storage_meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (PROXY_REPAIR_KEY, _safe_json({
                            "version": SCHEMA_VERSION,
                            "complete": not bool(blocking_errors),
                            "completed_at": now if not blocking_errors else None,
                            "proxies": counts["proxies"],
                            "errors": (blocking_errors + proxy_errors)[:100],
                        })),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return {
            "migrated": True,
            **counts,
            "errors": errors[:100],
            "version": SCHEMA_VERSION,
            "recovery_required": bool(blocking_errors),
        }

    def migration_status(self) -> dict[str, Any]:
        """Return a safe, version-aware view of the legacy import marker."""
        raw = self._meta(MIGRATION_KEY)
        detail: dict[str, Any] = {}
        try:
            parsed = json.loads(str(raw or ""))
            if isinstance(parsed, Mapping):
                detail = dict(parsed)
        except (TypeError, ValueError, json.JSONDecodeError):
            detail = {}
        return {
            "key": MIGRATION_KEY,
            "completed": _valid_migration_marker(raw),
            "version": SCHEMA_VERSION,
            **detail,
        }

    # ------------------------------------------------------------------
    # Generic row helpers and public projections
    # ------------------------------------------------------------------
    @staticmethod
    def _row_payload(row: sqlite3.Row, *, include_private: bool = True) -> dict[str, Any]:
        try:
            payload = _json_object(json.loads(str(row["payload"] or "{}")))
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        if include_private:
            try:
                private_payload = _json_object(
                    json.loads(str(row["private_payload"] or "{}"))
                ) if "private_payload" in row.keys() else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                private_payload = {}
            merged = _merge_private_payload(payload, private_payload)
            return _json_object(merged)
        return _redact(payload)

    @staticmethod
    def _mailbox_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeSQLiteStore._row_payload(row, include_private=not public)
        if public:
            payload = _redact(payload)
        result = {
            "row_id": str(row["row_id"]),
            "email": str(row["email"]) if not public else _mask_email(row["email"]),
            "status": str(row["status"]),
            "batch_id": str(row["batch_id"]),
            "revision": int(row["revision"] or 0),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "lease_owner": str(row["lease_owner"]) if not public else (SECRET_MASK if row["lease_owner"] else ""),
            "lease_until": row["lease_until"],
            "payload": payload,
        }
        if public:
            result.update({
                "email_masked": _mask_email(row["email"]),
                "subject_ref_fingerprint": _fingerprint(row["email"]),
                "has_mailbox_url": bool(row["mailbox_url"]),
                "mailbox_url": SECRET_MASK if row["mailbox_url"] else "",
            })
        else:
            result["mailbox_url"] = str(row["mailbox_url"])
        return result

    @staticmethod
    def _proxy_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeSQLiteStore._row_payload(row, include_private=not public)
        result = {
            "proxy_id": str(row["proxy_id"]),
            "scheme": str(row["scheme"]),
            "status": str(row["status"]),
            "enabled": bool(row["enabled"]),
            "revision": int(row["revision"] or 0),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "lease_owner": str(row["lease_owner"]) if not public else (SECRET_MASK if row["lease_owner"] else ""),
            "lease_until": row["lease_until"],
            "payload": _redact(payload) if public else payload,
        }
        result["proxy"] = _mask_proxy(row["proxy"]) if public else str(row["proxy"])
        return result

    @staticmethod
    def _task_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeSQLiteStore._row_payload(row, include_private=not public)
        result = {
            "task_id": str(row["task_id"]),
            "status": str(row["status"]),
            "revision": int(row["revision"] or 0),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "lease_owner": str(row["lease_owner"]) if not public else (SECRET_MASK if row["lease_owner"] else ""),
            "lease_until": row["lease_until"],
            "payload": _redact(payload) if public else payload,
        }
        return result

    @staticmethod
    def _result_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeSQLiteStore._row_payload(row, include_private=not public)
        return {
            "row_id": str(row["row_id"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "payload": _redact(payload) if public else payload,
        }

    @staticmethod
    def _remail_order_dict(row: sqlite3.Row, *, public: bool = False) -> dict[str, Any]:
        payload = FreeSQLiteStore._row_payload(row, include_private=not public)
        if public:
            payload = _redact(payload)
        return {
            "order_no": str(row["order_no"]),
            "status": str(row["status"]),
            "delivery_email": str(row["delivery_email"]) if not public else _mask_email(row["delivery_email"]),
            "delivery_email_masked": _mask_email(row["delivery_email"]),
            "imported": bool(row["imported"]),
            "pool_row_id": str(row["pool_row_id"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "payload": payload,
        }

    def _page(
        self,
        table: str,
        *,
        status: str | None,
        limit: int,
        offset: int,
        public: bool,
    ) -> dict[str, Any]:
        converters = {
            "mailboxes": self._mailbox_dict,
            "proxies": self._proxy_dict,
            "tasks": self._task_dict,
        }
        converter = converters.get(table)
        if converter is None:
            raise ValueError("不支持的 Free 分页资源")
        page_limit = max(1, min(5_000, int(limit)))
        page_offset = max(0, int(offset))
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        where = " AND ".join(clauses)
        with self._connection() as db:
            summary = db.execute(
                f"SELECT COUNT(*) AS total,COALESCE(MAX(updated_at),'') AS latest FROM {table} WHERE {where}",
                params,
            ).fetchone()
            rows = db.execute(
                f"SELECT * FROM {table} WHERE {where} ORDER BY updated_at DESC,rowid DESC LIMIT ? OFFSET ?",
                [*params, page_limit, page_offset],
            ).fetchall()
        total = int(summary["total"] or 0) if summary is not None else 0
        latest = str(summary["latest"] or "") if summary is not None else ""
        return {
            "items": [converter(row, public=public) for row in rows],
            "total": total,
            "offset": page_offset,
            "limit": page_limit,
            "revision": f"{total}:{latest}",
        }

    # ------------------------------------------------------------------
    # Mailboxes
    # ------------------------------------------------------------------
    def upsert_mailbox(
        self,
        *,
        row_id: str | None = None,
        email: str,
        mailbox_url: str,
        status: str = "available",
        batch_id: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        email_value = str(email or "").strip().lower()
        url_value = str(mailbox_url or "").strip()
        parsed = urlsplit(url_value)
        if not _EMAIL_RE.fullmatch(email_value) or parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("邮箱或 mailbox_url 无效")
        rid = str(row_id or _fingerprint(f"{email_value}|{url_value}")).strip()
        now = _now()
        values = _payload_with_fields(payload, row_id=rid, email=email_value, mailbox_url=url_value)
        public_values, private_values = _partition_json(values)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    existing = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (rid,)
                    ).fetchone()
                    if existing is None:
                        db.execute(
                            "INSERT INTO mailboxes(row_id,email,mailbox_url,status,batch_id,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,0,?,?,?,?)",
                            (
                                rid,
                                email_value,
                                url_value,
                                str(status or "available"),
                                str(batch_id or ""),
                                now,
                                now,
                                _safe_json(public_values),
                                _safe_json(private_values),
                            ),
                        )
                    else:
                        # A pool refresh must not turn a row with an active
                        # lease back into ``available`` or erase the worker's
                        # confirmation metadata.  The check is performed in
                        # the same immediate transaction as the update.
                        active_lease = db.execute(
                            "SELECT 1 FROM resource_leases "
                            "WHERE resource_type='mailbox' AND resource_id=? "
                            "AND lease_until>? LIMIT 1",
                            (rid, time.time()),
                        ).fetchone()
                        row_lease_until = _safe_float(existing["lease_until"])
                        row_is_active = row_lease_until is not None and row_lease_until > time.time()
                        current_payload = self._row_payload(existing)
                        if active_lease is not None or row_is_active:
                            merged_payload = current_payload
                            # Pool refreshes may carry stale lifecycle fields
                            # from an old JSON snapshot.  Never let those
                            # fields clear a worker's confirmed hand-off or
                            # change its task ownership while a lease is live.
                            protected_fields = {
                                "row_id",
                                "email",
                                "mailbox_url",
                                "lease_confirmed",
                                "lease_confirmed_at",
                                "task_id",
                                "batch_id",
                                "driver",
                            }
                            merged_payload.update(
                                {
                                    key: value
                                    for key, value in values.items()
                                    if key not in protected_fields
                                }
                            )
                            merged_public, merged_private = _partition_json(merged_payload)
                            db.execute(
                                # Metadata refreshes must not invalidate the
                                # revision captured by a worker between claim
                                # and email submission.  Lifecycle mutations
                                # (claim/confirm/release) remain the only
                                # operations that advance this CAS revision.
                                "UPDATE mailboxes SET updated_at=?,payload=?,private_payload=? "
                                "WHERE row_id=? AND revision=?",
                                (
                                    now,
                                    _safe_json(merged_public),
                                    _safe_json(merged_private),
                                    rid,
                                    int(existing["revision"] or 0),
                                ),
                            )
                        else:
                            db.execute(
                                "UPDATE mailboxes SET email=?,mailbox_url=?,status=?,batch_id=?,"
                                "updated_at=?,revision=revision+1,payload=?,private_payload=? "
                                "WHERE row_id=? AND revision=?",
                                (
                                    email_value,
                                    url_value,
                                    str(status or "available"),
                                    str(batch_id or ""),
                                    now,
                                    _safe_json(public_values),
                                    _safe_json(private_values),
                                    rid,
                                    int(existing["revision"] or 0),
                                ),
                            )
                    row = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (rid,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._mailbox_dict(row)

    def get_mailbox(self, row_id: str, *, public: bool = False) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (str(row_id),)).fetchone()
        return self._mailbox_dict(row, public=public) if row is not None else None

    def is_mailbox_confirmed_for_task(self, row_id: str, task_id: str) -> bool:
        """Return the durable confirmation marker for one task/mailbox pair.

        This deliberately does not inspect ``resource_leases`` or the scalar
        lease expiry.  The lease sidecar is only a temporary ownership guard;
        once the email-submit boundary has been crossed, the payload marker is
        the durable evidence needed by cleanup and retry classification.  The
        task identity check prevents a stale marker from being attributed to a
        different worker.
        """
        normalized_row = str(row_id or "").strip()
        normalized_task = str(task_id or "").strip()
        if not normalized_row or not normalized_task:
            return False
        with self._connection() as db:
            row = db.execute(
                "SELECT payload,private_payload FROM mailboxes WHERE row_id=?",
                (normalized_row,),
            ).fetchone()
        if row is None:
            return False
        payload = self._row_payload(row)
        return bool(
            _stored_bool(payload.get("lease_confirmed"))
            and str(payload.get("task_id") or "").strip() == normalized_task
        )

    # Explicitly named alias for callers that model this as a durable
    # confirmation lookup rather than a boolean mailbox helper.
    mailbox_confirmed_for_task = is_mailbox_confirmed_for_task

    def list_mailboxes(
        self,
        *,
        status: str | None = None,
        limit: int = 500,
        offset: int = 0,
        public: bool = False,
    ) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        params.extend([max(1, int(limit)), max(0, int(offset))])
        with self._connection() as db:
            rows = db.execute(
                f"SELECT * FROM mailboxes WHERE {' AND '.join(clauses)} ORDER BY created_at ASC, row_id ASC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._mailbox_dict(row, public=public) for row in rows]

    def list_mailboxes_page(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        public: bool = False,
    ) -> dict[str, Any]:
        return self._page(
            "mailboxes", status=status, limit=limit, offset=offset, public=public
        )

    def claim_mailbox(
        self,
        *,
        owner: str,
        lease_seconds: int = 180,
        row_id: str | None = None,
        claimed_status: str = "reserved",
    ) -> dict[str, Any] | None:
        owner_value = str(owner or "").strip()
        if not owner_value:
            raise ValueError("owner 不能为空")
        until = time.time() + max(1, int(lease_seconds))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    # Explicit row IDs still have to be available.  A caller
                    # must use ``lease_mailbox`` to renew its own reservation;
                    # this prevents accidentally stealing a failed/running
                    # row during a retry race.
                    where = "row_id=? AND status='available'" if row_id else "status='available'"
                    params: list[Any] = [str(row_id)] if row_id else []
                    claim_now = time.time()
                    candidates = db.execute(
                        f"SELECT * FROM mailboxes WHERE {where} "
                        "AND (lease_until IS NULL OR lease_until<=?) "
                        "AND NOT EXISTS ("
                        "SELECT 1 FROM resource_leases rl "
                        "WHERE rl.resource_type='mailbox' AND rl.resource_id=mailboxes.row_id "
                        "AND rl.lease_until>?"
                        ") ORDER BY created_at ASC,row_id ASC",
                        [*params, claim_now, claim_now],
                    ).fetchall()
                    # JSON payloads are intentionally kept portable (some
                    # supported SQLite builds do not expose JSON1).  Filter
                    # the durable confirmation marker in Python while the
                    # surrounding IMMEDIATE transaction still holds the claim
                    # admission lock.
                    row = next(
                        (
                            candidate
                            for candidate in candidates
                            if not _stored_bool(
                                self._row_payload(candidate).get("lease_confirmed")
                            )
                        ),
                        None,
                    )
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    updated = db.execute(
                        "UPDATE mailboxes SET status=?,lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE row_id=? AND (lease_until IS NULL OR lease_until<=?)",
                        (str(claimed_status), owner_value, until, now, row["row_id"], claim_now),
                    )
                    if updated.rowcount != 1:
                        db.execute("COMMIT")
                        return None
                    current = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (row["row_id"],)).fetchone()
                    db.execute(
                        "INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) VALUES('mailbox',?,?,?,?,?) ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET lease_until=excluded.lease_until,updated_at=excluded.updated_at",
                        (row["row_id"], owner_value, until, now, now),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return self._mailbox_dict(current) if current is not None else None

    def reserve_mailboxes(
        self,
        rows: Sequence[Mapping[str, Any]],
        *,
        batch_id: str = "",
    ) -> bool:
        """Reserve a mailbox batch atomically.

        The compatibility pool historically updated one row at a time.  That
        leaves a partially reserved batch when a later row is claimed by
        another process.  Validate every row and apply every update inside a
        single ``BEGIN IMMEDIATE`` transaction so callers see an all-or-none
        result and can safely retry the complete selection.
        """
        normalized: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for item in rows or ():
            if not isinstance(item, Mapping):
                return False
            row_id = str(item.get("row_id") or "").strip()
            if not row_id or row_id in seen:
                return False
            seen.add(row_id)
            normalized.append(
                (
                    row_id,
                    str(item.get("email") or "").strip(),
                    str(item.get("mailbox_url") or "").strip(),
                )
            )
        if not normalized:
            return True
        now_epoch = time.time()
        stamp = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current_rows: list[tuple[tuple[str, str, str], sqlite3.Row]] = []
                    for item in normalized:
                        row = db.execute(
                            "SELECT * FROM mailboxes WHERE row_id=? "
                            "AND status='available' "
                            "AND (lease_until IS NULL OR lease_until<=?) "
                            "AND NOT EXISTS ("
                            "SELECT 1 FROM resource_leases rl "
                            "WHERE rl.resource_type='mailbox' "
                            "AND rl.resource_id=mailboxes.row_id "
                            "AND rl.lease_until>?"
                            ")",
                            (item[0], now_epoch, now_epoch),
                        ).fetchone()
                        if row is None:
                            db.execute("ROLLBACK")
                            return False
                        current_rows.append((item, row))
                    for (row_id, email, mailbox_url), row in current_rows:
                        payload = self._row_payload(row)
                        # A row may have been manually restored from an older
                        # snapshot. Clear stale two-phase markers before a new
                        # reservation is handed to a worker.
                        for key in (
                            "lease_confirmed",
                            "lease_confirmed_at",
                            "task_id",
                            "batch_id",
                            "driver",
                        ):
                            payload.pop(key, None)
                        payload.update({
                            "email": email or str(row["email"] or ""),
                            "mailbox_url": mailbox_url or str(row["mailbox_url"] or ""),
                            "error": "",
                            "next_batch_priority": None,
                            "failure": None,
                        })
                        public_payload, private_payload = _partition_json(payload)
                        updated = db.execute(
                            "UPDATE mailboxes SET status='reserved',batch_id=?,"
                            "lease_owner='',lease_until=NULL,updated_at=?,"
                            "revision=revision+1,payload=?,private_payload=? "
                            "WHERE row_id=? AND status='available'",
                            (
                                str(batch_id or ""),
                                stamp,
                                _safe_json(public_payload),
                                _safe_json(private_payload),
                                row_id,
                            ),
                        )
                        if updated.rowcount != 1:
                            db.execute("ROLLBACK")
                            return False
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise

    def lease_mailbox(
        self,
        row_id: str,
        *,
        owner: str,
        lease_seconds: int = 180,
        expected_revision: int | None = None,
    ) -> bool:
        return self._lease_single("mailbox", str(row_id), str(owner), lease_seconds, expected_revision)

    def confirm_mailbox_lease(
        self,
        row_id: str,
        *,
        owner: str,
        task_id: str,
        batch_id: str = "",
        driver: str = "protocol",
        expected_revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Confirm a mailbox lease at the point the page submits the email.

        Claiming a row only protects it during transport setup.  This second
        conditional update records the irreversible hand-off and is the sole
        place where a worker may mark a mailbox as consumed by a task.
        """
        normalized_row = str(row_id or "").strip()
        normalized_owner = str(owner or "").strip()
        normalized_task = str(task_id or "").strip()
        if not normalized_row or not normalized_owner or not normalized_task:
            return None
        now_epoch = time.time()
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    lease = db.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND owner=? AND lease_until>?",
                        (normalized_row, normalized_owner, now_epoch),
                    ).fetchone()
                    if lease is None or str(row["status"] or "") not in {"reserved", "running"}:
                        db.execute("COMMIT")
                        return None
                    payload = self._row_payload(row)
                    # Confirmation is deliberately idempotent for the same
                    # task, while a second task can never consume the same
                    # mailbox lease. Check this before the revision guard so
                    # a retried callback with an older snapshot can succeed
                    # without incrementing the revision again.
                    if payload.get("lease_confirmed"):
                        if str(payload.get("task_id") or "") == normalized_task:
                            db.execute("COMMIT")
                            return self._mailbox_dict(row)
                        db.execute("COMMIT")
                        return None
                    actual_revision = int(row["revision"] or 0)
                    if expected_revision is not None and actual_revision != int(expected_revision):
                        db.execute("COMMIT")
                        return None
                    payload.update({
                        "task_id": normalized_task,
                        "batch_id": str(batch_id or ""),
                        "driver": str(driver or "protocol"),
                        "lease_confirmed": True,
                        "lease_confirmed_at": now_epoch,
                    })
                    public_payload, private_payload = _partition_json(payload)
                    updated = db.execute(
                        "UPDATE mailboxes SET status='running',batch_id=?,updated_at=?,"
                        "revision=revision+1,payload=?,private_payload=? WHERE row_id=? AND revision=?",
                        (
                            str(batch_id or ""), now, _safe_json(public_payload),
                            _safe_json(private_payload),
                            normalized_row, actual_revision,
                        ),
                    )
                    if updated.rowcount != 1:
                        db.execute("ROLLBACK")
                        return None
                    current = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return self._mailbox_dict(current) if current is not None else None

    # Explicit alias used by callers that model the two-phase lifecycle as a
    # lease object rather than a mailbox row update.
    confirm_lease = confirm_mailbox_lease

    def abort_mailbox_confirmation(
        self,
        row_id: str,
        *,
        owner: str,
        task_id: str,
        submission_definitely_not_started: bool = False,
        expected_revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Roll back a pre-submit confirmation while retaining the lease.

        Confirmation is conservative: callers set it immediately before a
        side-effecting submit.  A transport may roll it back only when it can
        prove that the submit primitive was never entered.  Once the request,
        click, or Enter action may have started, normal release semantics keep
        the row in ``pending_rerun``.
        """
        normalized_row = str(row_id or "").strip()
        normalized_owner = str(owner or "").strip()
        normalized_task = str(task_id or "").strip()
        if (
            not normalized_row
            or not normalized_owner
            or not normalized_task
            or submission_definitely_not_started is not True
        ):
            return None
        now_epoch = time.time()
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    lease = db.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND owner=? AND lease_until>?",
                        (normalized_row, normalized_owner, now_epoch),
                    ).fetchone()
                    payload = self._row_payload(row)
                    if (
                        lease is None
                        or str(row["lease_owner"] or "") != normalized_owner
                        or str(row["status"] or "") != "running"
                        or not _stored_bool(payload.get("lease_confirmed"))
                        or str(payload.get("task_id") or "") != normalized_task
                    ):
                        db.execute("COMMIT")
                        return None
                    actual_revision = int(row["revision"] or 0)
                    if (
                        expected_revision is not None
                        and actual_revision != int(expected_revision)
                    ):
                        db.execute("COMMIT")
                        return None
                    for key in (
                        "lease_confirmed",
                        "lease_confirmed_at",
                        "task_id",
                        "batch_id",
                        "driver",
                    ):
                        payload.pop(key, None)
                    public_payload, private_payload = _partition_json(payload)
                    updated = db.execute(
                        "UPDATE mailboxes SET status='reserved',updated_at=?,"
                        "revision=revision+1,payload=?,private_payload=? "
                        "WHERE row_id=? AND revision=? AND lease_owner=?",
                        (
                            now,
                            _safe_json(public_payload),
                            _safe_json(private_payload),
                            normalized_row,
                            actual_revision,
                            normalized_owner,
                        ),
                    )
                    if updated.rowcount != 1:
                        db.execute("ROLLBACK")
                        return None
                    current = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return self._mailbox_dict(current) if current is not None else None

    abort_lease_confirmation = abort_mailbox_confirmation

    def release_mailbox_lease(
        self,
        row_id: str,
        *,
        owner: str,
        reusable: bool = True,
    ) -> bool:
        """Release an unconfirmed lease, or consume a confirmed one."""
        normalized_row = str(row_id or "").strip()
        normalized_owner = str(owner or "").strip()
        if not normalized_row or not normalized_owner:
            return False
        now_epoch = time.time()
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT * FROM mailboxes WHERE row_id=?", (normalized_row,)
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return False
                    lease = db.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND owner=?",
                        (normalized_row, normalized_owner),
                    ).fetchone()
                    if lease is None:
                        db.execute("COMMIT")
                        return False
                    payload = self._row_payload(row)
                    confirmed = _stored_bool(payload.get("lease_confirmed"))
                    # Once the email was submitted, the mailbox is never made
                    # immediately available again.  It is explicitly marked
                    # for a later rerun/cleanup instead.
                    # Once a worker has explicitly written a terminal mailbox
                    # result (success/partial/twofa/failure), cleanup must not
                    # overwrite that durable status with ``pending_rerun``.
                    # Only an active confirmed claim needs the pending marker.
                    current_status = str(row["status"] or "")
                    if confirmed:
                        target_status = (
                            "pending_rerun"
                            if current_status in {"reserved", "queued", "running"}
                            else current_status or "pending_rerun"
                        )
                    else:
                        target_status = "available" if reusable else "failed"

                    db.execute(
                        "DELETE FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND owner=?",
                        (normalized_row, normalized_owner),
                    )
                    remaining = db.execute(
                        "SELECT owner,lease_until FROM resource_leases "
                        "WHERE resource_type='mailbox' AND resource_id=? "
                        "AND lease_until>? ORDER BY lease_until DESC LIMIT 1",
                        (normalized_row, now_epoch),
                    ).fetchone()
                    if remaining is not None:
                        # A stale owner may release after its lease was
                        # replaced. Preserve the new owner's state and payload
                        # instead of changing it underneath that worker.
                        db.execute(
                            "UPDATE mailboxes SET lease_owner=?,lease_until=?,"
                            "updated_at=?,revision=revision+1 WHERE row_id=?",
                            (
                                str(remaining["owner"]),
                                float(remaining["lease_until"]),
                                now,
                                normalized_row,
                            ),
                        )
                    else:
                        if not confirmed and reusable:
                            for key in (
                                "lease_confirmed",
                                "lease_confirmed_at",
                                "task_id",
                                "batch_id",
                                "driver",
                            ):
                                payload.pop(key, None)
                        public_payload, private_payload = _partition_json(payload)
                        db.execute(
                            "UPDATE mailboxes SET status=?,lease_owner='',lease_until=NULL,"
                            "updated_at=?,revision=revision+1,payload=?,private_payload=? WHERE row_id=?",
                            (
                                target_status,
                                now,
                                _safe_json(public_payload),
                                _safe_json(private_payload),
                                normalized_row,
                            ),
                        )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return True

    # ------------------------------------------------------------------
    # Proxies
    # ------------------------------------------------------------------
    def upsert_proxy(
        self,
        *,
        proxy: str,
        proxy_id: str | None = None,
        scheme: str | None = None,
        status: str = "healthy",
        enabled: bool = True,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized = _normalize_proxy(proxy, default_scheme=str(scheme or "socks5"))
        if not normalized:
            raise ValueError("proxy 无效")
        parsed = urlsplit(normalized)
        pid = str(proxy_id or _fingerprint(normalized)).strip()
        now = _now()
        values = _payload_with_fields(
            _clear_legacy_pool_dimensions(payload, include_plain=True),
            proxy=normalized,
            proxy_id=pid,
            scheme=str(scheme or parsed.scheme).lower(),
        )
        public_values, private_values = _partition_json(values)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    existing = db.execute(
                        "SELECT * FROM proxies WHERE proxy_id=?", (pid,)
                    ).fetchone()
                    active_lease = None
                    if existing is not None:
                        active_lease = db.execute(
                            "SELECT 1 FROM resource_leases WHERE resource_type='proxy' "
                            "AND resource_id=? AND lease_until>? LIMIT 1",
                            (pid, time.time()),
                        ).fetchone()
                        if active_lease is not None or (
                            _safe_float(existing["lease_until"]) or 0
                        ) > time.time():
                            # A pool refresh must not erase a worker's shared
                            # lease or reset a quarantined/healthy state
                            # underneath it. Merge non-lifecycle metadata and
                            # leave the CAS revision stable while a lease is
                            # active; lease/heartbeat methods own those
                            # fields and update them conditionally.
                            current_payload = self._row_payload(existing)
                            protected = {
                                "proxy_id", "proxy", "scheme", "status", "enabled",
                                "lease_owner", "lease_until", "leases",
                            }
                            merged_payload = current_payload
                            merged_payload.update({
                                key: value
                                for key, value in values.items()
                                if key not in protected
                            })
                            merged_public, merged_private = _partition_json(merged_payload)
                            db.execute(
                                "UPDATE proxies SET proxy=?,scheme=?,updated_at=?,payload=?,private_payload=? "
                                "WHERE proxy_id=? AND revision=?",
                                (
                                    normalized,
                                    str(scheme or parsed.scheme).lower(),
                                    now,
                                    _safe_json(merged_public),
                                    _safe_json(merged_private),
                                    pid,
                                    int(existing["revision"] or 0),
                                ),
                            )
                        else:
                            db.execute(
                                "UPDATE proxies SET proxy=?,scheme=?,status=?,enabled=?,updated_at=?,revision=revision+1,payload=?,private_payload=? "
                                "WHERE proxy_id=? AND revision=?",
                                (
                                    normalized,
                                    str(scheme or parsed.scheme).lower(),
                                    str(status or "healthy"),
                                    int(bool(enabled)),
                                    now,
                                    _safe_json(public_values),
                                    _safe_json(private_values),
                                    pid,
                                    int(existing["revision"] or 0),
                                ),
                            )
                    else:
                        db.execute(
                            "INSERT INTO proxies(proxy_id,proxy,scheme,status,enabled,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,0,?,?,?,?)",
                            (
                                pid,
                                normalized,
                                str(scheme or parsed.scheme).lower(),
                                str(status or "healthy"),
                                int(bool(enabled)),
                                now,
                                now,
                                _safe_json(public_values),
                                _safe_json(private_values),
                            ),
                        )
                    row = db.execute("SELECT * FROM proxies WHERE proxy_id=?", (pid,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._proxy_dict(row)

    def get_proxy(self, proxy_id: str, *, public: bool = False) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM proxies WHERE proxy_id=?", (str(proxy_id),)).fetchone()
        return self._proxy_dict(row, public=public) if row is not None else None

    def list_proxies(self, *, status: str | None = None, limit: int = 500, offset: int = 0, public: bool = False) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        params.extend([max(1, int(limit)), max(0, int(offset))])
        with self._connection() as db:
            rows = db.execute(
                f"SELECT * FROM proxies WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC,proxy_id ASC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._proxy_dict(row, public=public) for row in rows]

    def list_proxies_page(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        public: bool = False,
    ) -> dict[str, Any]:
        return self._page(
            "proxies", status=status, limit=limit, offset=offset, public=public
        )

    def claim_proxy(
        self,
        *,
        owner: str,
        lease_seconds: int = 180,
        proxy_id: str | None = None,
        shared: bool = True,
    ) -> dict[str, Any] | None:
        owner_value = str(owner or "").strip()
        if not owner_value:
            raise ValueError("owner 不能为空")
        until = time.time() + max(1, int(lease_seconds))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    where = (
                        "proxy_id=? AND enabled=1 AND status IN ('healthy','unknown','available')"
                        if proxy_id
                        else "enabled=1 AND status IN ('healthy','unknown','available')"
                    )
                    params: list[Any] = [str(proxy_id)] if proxy_id else []
                    row = db.execute(
                        f"SELECT * FROM proxies WHERE {where} ORDER BY updated_at DESC,proxy_id ASC LIMIT 1",
                        params,
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    if not shared:
                        active = db.execute(
                            "SELECT 1 FROM resource_leases WHERE resource_type='proxy' AND resource_id=? AND owner<>? AND lease_until>? LIMIT 1",
                            (row["proxy_id"], owner_value, time.time()),
                        ).fetchone()
                        if active is not None:
                            db.execute("COMMIT")
                            return None
                    db.execute(
                        "INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) VALUES('proxy',?,?,?,?,?) ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET lease_until=excluded.lease_until,updated_at=excluded.updated_at",
                        (row["proxy_id"], owner_value, until, now, now),
                    )
                    db.execute("UPDATE proxies SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE proxy_id=?", (owner_value, until, now, row["proxy_id"]));
                    current = db.execute("SELECT * FROM proxies WHERE proxy_id=?", (row["proxy_id"],)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return self._proxy_dict(current) if current is not None else None

    def lease_proxy(self, proxy_id: str, *, owner: str, lease_seconds: int = 180, shared: bool = True) -> bool:
        return self._lease_single("proxy", str(proxy_id), str(owner), lease_seconds, None, shared=shared)

    def release_lease(self, resource_type: str, resource_id: str, *, owner: str, status: str | None = None) -> bool:
        resource_type = str(resource_type or "").strip().lower()
        resource_id = str(resource_id or "").strip()
        owner = str(owner or "").strip()
        if resource_type not in {"mailbox", "proxy", "task"} or not resource_id or not owner:
            return False
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    table, key = {"mailbox": ("mailboxes", "row_id"), "proxy": ("proxies", "proxy_id"), "task": ("tasks", "task_id")}[
                        resource_type
                    ]
                    # Check the parent row in the same transaction.  Without
                    # this guard an orphan lease could report success and
                    # make cleanup callers believe a resource was released.
                    parent = db.execute(
                        f"SELECT 1 FROM {table} WHERE {key}=?", (resource_id,)
                    ).fetchone()
                    if parent is None:
                        db.execute("COMMIT")
                        return False
                    parent_payload: dict[str, Any] = {}
                    parent_status = ""
                    if resource_type == "mailbox":
                        parent_row = db.execute(
                            "SELECT payload,private_payload,status FROM mailboxes WHERE row_id=?",
                            (resource_id,),
                        ).fetchone()
                        if parent_row is not None:
                            parent_status = str(parent_row["status"] or "")
                            parent_payload = self._row_payload(parent_row)
                    deleted = db.execute(
                        "DELETE FROM resource_leases WHERE resource_type=? AND resource_id=? AND owner=?",
                        (resource_type, resource_id, owner),
                    )
                    if deleted.rowcount != 1:
                        db.execute("COMMIT")
                        return False
                    # Clear denormalized owner only when it still points at this owner;
                    # another shared proxy lease must remain represented by its owner.
                    # Recompute the denormalized owner from any remaining
                    # shared leases instead of blanking a proxy while another
                    # worker still owns it.
                    remaining = db.execute(
                        "SELECT owner,lease_until FROM resource_leases "
                        "WHERE resource_type=? AND resource_id=? AND lease_until>? "
                        "ORDER BY lease_until DESC LIMIT 1",
                        (resource_type, resource_id, time.time()),
                    ).fetchone()
                    next_owner = str(remaining["owner"]) if remaining is not None else ""
                    next_until = float(remaining["lease_until"]) if remaining is not None else None
                    # If another owner has already acquired the resource,
                    # preserve its status.  This matters when a stale worker
                    # releases after its lease expired and was replaced.
                    update_status = status if remaining is None else None
                    if (
                        remaining is None
                        and resource_type == "mailbox"
                        and parent_payload.get("lease_confirmed")
                        and parent_status in {"reserved", "queued", "running"}
                        and (update_status is None or str(update_status) in {"available", "reserved", "queued", "running"})
                    ):
                        # The repository facade releases through this generic
                        # method. Preserve the two-phase mailbox invariant
                        # even when it does not pass an explicit status.
                        update_status = "pending_rerun"
                    if (
                        remaining is None
                        and resource_type == "mailbox"
                        and not parent_payload.get("lease_confirmed")
                    ):
                        # Generic repository callers use this method for both
                        # task/proxy leases and mailbox cleanup.  A mailbox
                        # claim is only a reservation until confirmation, so
                        # release must discard all owner/task metadata from a
                        # previous attempt before the row can be claimed
                        # again.  Keep confirmed metadata intact: once the
                        # address was submitted, the row is deliberately
                        # retained as ``pending_rerun`` for audit/retry.
                        for key_name in (
                            "lease_confirmed",
                            "lease_confirmed_at",
                            "task_id",
                            "batch_id",
                            "driver",
                        ):
                            parent_payload.pop(key_name, None)
                        public_payload, private_payload = _partition_json(parent_payload)
                        db.execute(
                            "UPDATE mailboxes SET payload=?,private_payload=? WHERE row_id=?",
                            (
                                _safe_json(public_payload),
                                _safe_json(private_payload),
                                resource_id,
                            ),
                        )
                    if update_status is not None:
                        db.execute(
                            f"UPDATE {table} SET status=? WHERE {key}=?",
                            (str(update_status), resource_id),
                        )
                    db.execute(
                        f"UPDATE {table} SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE {key}=?",
                        (next_owner, next_until, now, resource_id),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return True

    def release_proxy_leases(self, owner: str) -> int:
        """Release every shared proxy lease owned by one interrupted worker.

        A worker normally releases a proxy in its ``finally`` block.  If the
        process exits first, the lease can remain live until its TTL expires
        and unnecessarily reduces the shared pool's capacity.  Recovery uses
        this owner-scoped operation so it cannot touch leases belonging to
        another task.  The denormalized proxy owner is recomputed in the same
        transaction, preserving any remaining shared leases.
        """
        owner_value = str(owner or "").strip()
        if not owner_value:
            return 0
        now_epoch = time.time()
        now = _now()
        released = 0
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    lease_rows = db.execute(
                        "SELECT resource_id FROM resource_leases "
                        "WHERE resource_type='proxy' AND owner=?",
                        (owner_value,),
                    ).fetchall()
                    for lease_row in lease_rows:
                        proxy_id = str(lease_row["resource_id"] or "").strip()
                        deleted = db.execute(
                            "DELETE FROM resource_leases "
                            "WHERE resource_type='proxy' AND resource_id=? AND owner=?",
                            (proxy_id, owner_value),
                        )
                        if deleted.rowcount != 1:
                            continue
                        remaining = db.execute(
                            "SELECT owner,lease_until FROM resource_leases "
                            "WHERE resource_type='proxy' AND resource_id=? "
                            "AND lease_until>? ORDER BY lease_until DESC LIMIT 1",
                            (proxy_id, now_epoch),
                        ).fetchone()
                        next_owner = str(remaining["owner"]) if remaining is not None else ""
                        next_until = (
                            float(remaining["lease_until"])
                            if remaining is not None
                            else None
                        )
                        db.execute(
                            "UPDATE proxies SET lease_owner=?,lease_until=?,"
                            "updated_at=?,revision=revision+1 WHERE proxy_id=?",
                            (next_owner, next_until, now, proxy_id),
                        )
                        released += 1
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return released

    # Explicit alias for adapters/callers that use the more general wording.
    release_leases_for_owner = release_proxy_leases

    def renew_lease(
        self,
        resource_type: str,
        resource_id: str,
        *,
        owner: str,
        lease_seconds: int = 180,
        expected_revision: int | None = None,
    ) -> bool:
        """Extend an unexpired lease owned by ``owner`` using revision CAS."""
        resource_type = str(resource_type or "").strip().lower()
        resource_id = str(resource_id or "").strip()
        owner = str(owner or "").strip()
        mapping = {
            "mailbox": ("mailboxes", "row_id"),
            "proxy": ("proxies", "proxy_id"),
            "task": ("tasks", "task_id"),
        }
        if resource_type not in mapping or not resource_id or not owner:
            return False
        table, key = mapping[resource_type]
        current_time = time.time()
        until = current_time + max(1, int(lease_seconds))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        f"SELECT revision FROM {table} WHERE {key}=?", (resource_id,)
                    ).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return False
                    actual = int(row["revision"] or 0)
                    if expected_revision is not None and actual != int(expected_revision):
                        db.execute("COMMIT")
                        return False
                    renewed = db.execute(
                        "UPDATE resource_leases SET lease_until=?,updated_at=? "
                        "WHERE resource_type=? AND resource_id=? AND owner=? AND lease_until>?",
                        (until, now, resource_type, resource_id, owner, current_time),
                    )
                    if renewed.rowcount != 1:
                        db.execute("COMMIT")
                        return False
                    updated = db.execute(
                        f"UPDATE {table} SET "
                        "lease_owner=CASE WHEN lease_owner='' OR lease_owner=? THEN ? ELSE lease_owner END,"
                        "lease_until=CASE WHEN lease_owner='' OR lease_owner=? THEN ? ELSE lease_until END,"
                        "updated_at=?,revision=revision+1 "
                        f"WHERE {key}=? AND revision=?",
                        (owner, owner, owner, until, now, resource_id, actual),
                    )
                    if updated.rowcount != 1:
                        db.execute("ROLLBACK")
                        return False
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

    def recover_expired_leases(
        self,
        *,
        now: float | None = None,
        resource_type: str | None = None,
    ) -> dict[str, int]:
        """Recover stale mailbox/task ownership and preserve active proxy shares.

        Mailboxes left ``reserved`` become ``available`` when their last lease
        expires.  Interrupted ``running``/``stopping`` tasks return to
        ``queued``.  Proxy health is never changed by lease recovery.
        """
        current_time = time.time() if now is None else float(now)
        selected_type = str(resource_type or "").strip().lower()
        if selected_type and selected_type not in {"mailbox", "proxy", "task"}:
            raise ValueError("resource_type 无效")
        params: tuple[Any, ...]
        where = "lease_until<=?"
        params = (current_time,)
        if selected_type:
            where += " AND resource_type=?"
            params = (current_time, selected_type)
        recovered = {"mailbox": 0, "proxy": 0, "task": 0, "total": 0}
        mapping = {
            "mailbox": ("mailboxes", "row_id"),
            "proxy": ("proxies", "proxy_id"),
            "task": ("tasks", "task_id"),
        }
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    expired = db.execute(
                        f"SELECT resource_type,resource_id,owner FROM resource_leases WHERE {where}",
                        params,
                    ).fetchall()
                    db.execute(f"DELETE FROM resource_leases WHERE {where}", params)
                    resources = {
                        (str(row["resource_type"]), str(row["resource_id"]))
                        for row in expired
                    }
                    stamp = _now()
                    for kind, resource_id in resources:
                        table, key = mapping[kind]
                        active = db.execute(
                            "SELECT owner,lease_until FROM resource_leases "
                            "WHERE resource_type=? AND resource_id=? AND lease_until>? "
                            "ORDER BY lease_until DESC LIMIT 1",
                            (kind, resource_id, current_time),
                        ).fetchone()
                        if active is not None:
                            db.execute(
                                f"UPDATE {table} SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE {key}=?",
                                (str(active["owner"]), float(active["lease_until"]), stamp, resource_id),
                            )
                        elif kind == "mailbox":
                            mailbox_row = db.execute(
                                "SELECT payload,private_payload,status FROM mailboxes WHERE row_id=?",
                                (resource_id,),
                            ).fetchone()
                            if mailbox_row is not None:
                                mailbox_payload = self._row_payload(mailbox_row)
                            else:
                                mailbox_payload = {}
                            confirmed = _stored_bool(mailbox_payload.get("lease_confirmed"))
                            if not confirmed:
                                # An unconfirmed lease never submitted the
                                # address.  Clear all task/driver markers and
                                # return every transient mailbox state to the
                                # dispatchable pool after expiry.
                                for key_name in (
                                    "lease_confirmed",
                                    "lease_confirmed_at",
                                    "task_id",
                                    "batch_id",
                                    "driver",
                                    "lease_owner",
                                    "lease_until",
                                    "stage",
                                ):
                                    mailbox_payload.pop(key_name, None)
                                public_payload, private_payload = _partition_json(mailbox_payload)
                                db.execute(
                                    "UPDATE mailboxes SET lease_owner='',lease_until=NULL,"
                                    "batch_id='',status=CASE WHEN status IN ('reserved','queued','running') "
                                    "THEN 'available' ELSE status END,updated_at=?,revision=revision+1,"
                                    "payload=?,private_payload=? WHERE row_id=?",
                                    (
                                        stamp,
                                        _safe_json(public_payload),
                                        _safe_json(private_payload),
                                        resource_id,
                                    ),
                                )
                            else:
                                db.execute(
                                    "UPDATE mailboxes SET lease_owner='',lease_until=NULL,"
                                    "status=CASE WHEN status IN ('reserved','queued','running') THEN 'pending_rerun' "
                                    "ELSE status END,updated_at=?,revision=revision+1 WHERE row_id=?",
                                    (stamp, resource_id),
                                )
                        elif kind == "task":
                            db.execute(
                                "UPDATE tasks SET lease_owner='',lease_until=NULL,"
                                "status=CASE WHEN status IN ('running','stopping') THEN 'queued' ELSE status END,"
                                "updated_at=?,revision=revision+1 WHERE task_id=?",
                                (stamp, resource_id),
                            )
                        else:
                            db.execute(
                                "UPDATE proxies SET lease_owner='',lease_until=NULL,updated_at=?,revision=revision+1 WHERE proxy_id=?",
                                (stamp, resource_id),
                            )
                        recovered[kind] += 1
                    recovered["total"] = len(resources)
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return recovered

    def recover_orphaned_mailboxes(self, *, now: float | None = None) -> int:
        """Release ``reserved`` mailboxes that have no live normalized lease.

        A process can terminate after the legacy pool row is marked
        ``reserved`` but before the corresponding task/lease transaction is
        committed.  Such a row is not covered by
        :meth:`recover_expired_leases` because there is no row in
        ``resource_leases`` to expire.  Recover only the unconfirmed form of
        this state; a confirmed mailbox remains non-reusable even when a
        malformed/old database lost its lease row.

        The complete scan and conditional updates run under one immediate
        transaction.  This prevents a concurrent claimant from acquiring a
        row between the orphan check and the reset.
        """
        current_time = time.time() if now is None else float(now)
        stamp = _now()
        transient_keys = (
            "lease_confirmed",
            "lease_confirmed_at",
            "task_id",
            "batch_id",
            "driver",
            "lease_owner",
            "lease_until",
            "stage",
        )
        changed = 0
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    rows = db.execute(
                        "SELECT row_id,payload,private_payload FROM mailboxes "
                        "WHERE status='reserved' AND NOT EXISTS ("
                        "SELECT 1 FROM resource_leases rl "
                        "WHERE rl.resource_type='mailbox' "
                        "AND rl.resource_id=mailboxes.row_id "
                        "AND rl.lease_until>?"
                        ")",
                        (current_time,),
                    ).fetchall()
                    for row in rows:
                        payload = _merge_private_payload(
                            self._decode_json_value(row["payload"]),
                            self._decode_json_value(row["private_payload"]),
                        )
                        if not isinstance(payload, Mapping):
                            payload = {}
                        # Confirmed means the address was submitted to the
                        # upstream service. Never make that mailbox available
                        # merely because its lease sidecar is missing.
                        if _stored_bool(payload.get("lease_confirmed")):
                            continue
                        normalized = copy.deepcopy(dict(payload))
                        for key in transient_keys:
                            normalized.pop(key, None)
                        public_payload, private_payload = _partition_json(normalized)
                        updated = db.execute(
                            "UPDATE mailboxes SET status='available',batch_id='',"
                            "lease_owner='',lease_until=NULL,updated_at=?,"
                            "revision=revision+1,payload=?,private_payload=? "
                            "WHERE row_id=? AND status='reserved' AND NOT EXISTS ("
                            "SELECT 1 FROM resource_leases rl "
                            "WHERE rl.resource_type='mailbox' "
                            "AND rl.resource_id=mailboxes.row_id "
                            "AND rl.lease_until>?"
                            ")",
                            (
                                stamp,
                                _safe_json(public_payload),
                                _safe_json(private_payload),
                                str(row["row_id"]),
                                current_time,
                            ),
                        )
                        changed += int(updated.rowcount or 0)
                        if updated.rowcount:
                            # Expired sidecar rows are not authoritative and
                            # can otherwise make a later claim look stale.
                            db.execute(
                                "DELETE FROM resource_leases WHERE "
                                "resource_type='mailbox' AND resource_id=? "
                                "AND lease_until<=?",
                                (str(row["row_id"]), current_time),
                            )
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return changed

    # ------------------------------------------------------------------
    # Tasks and revisioned snapshots
    # ------------------------------------------------------------------
    def create_task(self, task_id: str, payload: Mapping[str, Any] | None = None, *, status: str = "queued") -> dict[str, Any]:
        task = str(task_id or "").strip()
        if not task:
            raise ValueError("task_id 不能为空")
        now = _now()
        values = _payload_with_fields(payload, task_id=task, status=str(status or "queued"), revision=0)
        public_values, private_values = _partition_json(values)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("INSERT OR IGNORE INTO tasks(task_id,status,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?)", (task, str(status or "queued"), 0, now, now, _safe_json(public_values), _safe_json(private_values)))
                    row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._task_dict(row)

    def get_task(self, task_id: str, *, public: bool = False) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (str(task_id),)).fetchone()
        return self._task_dict(row, public=public) if row is not None else None

    def list_tasks(self, *, status: str | None = None, limit: int = 500, offset: int = 0, public: bool = False) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        params.extend([max(1, int(limit)), max(0, int(offset))])
        with self._connection() as db:
            rows = db.execute(f"SELECT * FROM tasks WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC,task_id ASC LIMIT ? OFFSET ?", params).fetchall()
        return [self._task_dict(row, public=public) for row in rows]

    def list_tasks_page(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        public: bool = False,
    ) -> dict[str, Any]:
        return self._page(
            "tasks", status=status, limit=limit, offset=offset, public=public
        )

    def save_task(
        self,
        task_id: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: int | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        task = str(task_id or "").strip()
        if not task:
            raise ValueError("task_id 不能为空")
        incoming = _json_object(payload)
        public_incoming, private_incoming = _partition_json(incoming)
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    if current is None:
                        if expected_revision not in (None, 0):
                            raise RevisionConflict(task, expected_revision, None)
                        next_revision = 0
                        task_status = str(status or incoming.get("status") or "queued")
                        incoming.setdefault("task_id", task)
                        incoming["revision"] = next_revision
                        db.execute("INSERT INTO tasks(task_id,status,revision,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?)", (task, task_status, next_revision, now, now, _safe_json(public_incoming), _safe_json(private_incoming)))
                    else:
                        actual = int(current["revision"] or 0)
                        if expected_revision is not None and actual != int(expected_revision):
                            raise RevisionConflict(task, expected_revision, actual)
                        requested_status = str(
                            status
                            or incoming.get("status")
                            or current["status"]
                            or "queued"
                        )
                        if (
                            str(current["status"] or "") in TERMINAL_TASK_STATUSES
                            and requested_status != str(current["status"] or "")
                        ):
                            # Treat a late callback that attempts to revive a
                            # completed task as a compare-and-set conflict.
                            # Callers already handle RevisionConflict as a
                            # benign stale-writer outcome.
                            raise RevisionConflict(task, expected_revision, actual)
                        next_revision = actual + 1
                        task_status = requested_status
                        incoming.setdefault("task_id", task)
                        incoming["revision"] = next_revision
                        public_incoming, private_incoming = _partition_json(incoming)
                        updated = db.execute("UPDATE tasks SET status=?,revision=?,updated_at=?,payload=?,private_payload=? WHERE task_id=? AND revision=?", (task_status, next_revision, now, _safe_json(public_incoming), _safe_json(private_incoming), task, actual))
                        if updated.rowcount != 1:
                            raise RevisionConflict(task, expected_revision, actual)
                    row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._task_dict(row)

    update_task = save_task

    def transition_task(
        self,
        task_id: str,
        from_status: str | Sequence[str],
        to_status: str,
        *,
        payload_patch: Mapping[str, Any] | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Apply one explicit task state transition with compare-and-set.

        ``None`` means the current state is not in ``from_status``.  A stale
        revision raises :class:`RevisionConflict`, allowing callers to
        distinguish a concurrent writer from an invalid state transition.
        """
        task = str(task_id or "").strip()
        if not task:
            raise ValueError("task_id 不能为空")
        allowed = (
            {str(item) for item in from_status}
            if not isinstance(from_status, str)
            else {from_status}
        )
        target_status = str(to_status or "").strip()
        if not target_status or not allowed:
            raise ValueError("任务状态不能为空")
        patch = _json_object(payload_patch)
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    if current is None:
                        db.execute("COMMIT")
                        return None
                    actual = int(current["revision"] or 0)
                    if expected_revision is not None and actual != int(expected_revision):
                        raise RevisionConflict(task, expected_revision, actual)
                    current_status = str(current["status"] or "")
                    if current_status not in allowed:
                        db.execute("COMMIT")
                        return None
                    # A terminal task is immutable unless the caller repeats
                    # the same status as an idempotent write.
                    if current_status in TERMINAL_TASK_STATUSES and target_status != current_status:
                        db.execute("COMMIT")
                        return None
                    payload = self._row_payload(current)
                    payload.update(patch)
                    payload.update({"task_id": task, "status": target_status, "revision": actual + 1})
                    public_payload, private_payload = _partition_json(payload)
                    updated = db.execute(
                        "UPDATE tasks SET status=?,revision=?,updated_at=?,payload=?,private_payload=? "
                        "WHERE task_id=? AND status IN (" + ",".join("?" for _ in allowed) + ") AND revision=?",
                        [target_status, actual + 1, now, _safe_json(public_payload), _safe_json(private_payload), task, *sorted(allowed), actual],
                    )
                    if updated.rowcount != 1:
                        raise RevisionConflict(task, expected_revision, actual)
                    row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return self._task_dict(row) if row is not None else None

    def claim_task(self, task_id: str, *, owner: str, lease_seconds: int = 180, statuses: Sequence[str] = ("queued", "pending")) -> dict[str, Any] | None:
        task = str(task_id or "").strip()
        owner = str(owner or "").strip()
        if not task or not owner:
            return None
        until = time.time() + max(1, int(lease_seconds))
        now = _now()
        placeholders = ",".join("?" for _ in statuses) or "?"
        status_values = tuple(str(value) for value in statuses) or ("queued",)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(f"SELECT * FROM tasks WHERE task_id=? AND status IN ({placeholders}) AND (lease_until IS NULL OR lease_until<=?)", (*((task, *status_values)), time.time())).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return None
                    updated = db.execute("UPDATE tasks SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE task_id=? AND revision=? AND (lease_until IS NULL OR lease_until<=?)", (owner, until, now, task, int(row["revision"]), time.time()))
                    if updated.rowcount != 1:
                        db.execute("COMMIT")
                        return None
                    db.execute("INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) VALUES('task',?,?,?,?,?) ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET lease_until=excluded.lease_until,updated_at=excluded.updated_at", (task, owner, until, now, now))
                    current = db.execute("SELECT * FROM tasks WHERE task_id=?", (task,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return self._task_dict(current) if current is not None else None

    def _lease_single(self, resource_type: str, resource_id: str, owner: str, lease_seconds: int, expected_revision: int | None, *, shared: bool = False) -> bool:
        if not resource_id or not owner:
            return False
        table, key = {"mailbox": ("mailboxes", "row_id"), "proxy": ("proxies", "proxy_id"), "task": ("tasks", "task_id")}[resource_type]
        until = time.time() + max(1, int(lease_seconds))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(f"SELECT * FROM {table} WHERE {key}=?", (resource_id,)).fetchone()
                    if row is None:
                        db.execute("COMMIT")
                        return False
                    if expected_revision is not None and int(row["revision"] or 0) != int(expected_revision):
                        db.execute("COMMIT")
                        return False
                    if not shared:
                        active = db.execute("SELECT 1 FROM resource_leases WHERE resource_type=? AND resource_id=? AND owner<>? AND lease_until>? LIMIT 1", (resource_type, resource_id, owner, time.time())).fetchone()
                        if active is not None:
                            db.execute("COMMIT")
                            return False
                    revision = int(row["revision"] or 0)
                    updated = db.execute(f"UPDATE {table} SET lease_owner=?,lease_until=?,updated_at=?,revision=revision+1 WHERE {key}=? AND revision=?", (owner, until, now, resource_id, revision))
                    if updated.rowcount != 1:
                        db.execute("COMMIT")
                        return False
                    db.execute("INSERT INTO resource_leases(resource_type,resource_id,owner,lease_until,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(resource_type,resource_id,owner) DO UPDATE SET lease_until=excluded.lease_until,updated_at=excluded.updated_at", (resource_type, resource_id, owner, until, now, now))
                    db.execute("COMMIT")
                    return True
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

    # ------------------------------------------------------------------
    # Results and health helpers
    # ------------------------------------------------------------------
    def save_result(self, row_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        rid = str(row_id or "").strip()
        if not rid:
            raise ValueError("row_id 不能为空")
        now = _now()
        value = _json_object(payload)
        public_value, private_value = _partition_json(value)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("INSERT INTO results(row_id,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?) ON CONFLICT(row_id) DO UPDATE SET updated_at=excluded.updated_at,payload=excluded.payload,private_payload=excluded.private_payload", (rid, now, now, _safe_json(public_value), _safe_json(private_value)))
                    row = db.execute("SELECT * FROM results WHERE row_id=?", (rid,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._result_dict(row)

    def upsert_remail_order(self, order: Mapping[str, Any]) -> dict[str, Any]:
        """Persist an order, keeping service_token in the private sidecar."""
        order_no = str(order.get("orderNo") or order.get("order_no") or "").strip()
        if not order_no:
            raise ValueError("Remail orderNo 不能为空")
        email = str(order.get("deliveryEmail") or order.get("delivery_email") or "").strip().lower()
        status = str(order.get("status") or "").strip().lower()
        public, private = _partition_json(dict(order))
        now = _now()
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current = db.execute("SELECT imported,pool_row_id,created_at FROM remail_orders WHERE order_no=?", (order_no,)).fetchone()
                    imported = int(current[0]) if current is not None else int(bool(order.get("imported")))
                    pool_row_id = str(current[1]) if current is not None else str(order.get("pool_row_id") or "")
                    created_at = str(current[2]) if current is not None else now
                    db.execute(
                        "INSERT INTO remail_orders(order_no,status,delivery_email,imported,pool_row_id,created_at,updated_at,payload,private_payload) VALUES(?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(order_no) DO UPDATE SET status=excluded.status,delivery_email=excluded.delivery_email,updated_at=excluded.updated_at,payload=excluded.payload,private_payload=excluded.private_payload",
                        (order_no, status, email, imported, pool_row_id, created_at, now, _safe_json(public), _safe_json(private)),
                    )
                    row = db.execute("SELECT * FROM remail_orders WHERE order_no=?", (order_no,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        assert row is not None
        return self._remail_order_dict(row)

    def list_remail_orders(self, *, status: str | None = None, imported: bool | None = None, public: bool = False, limit: int = 500) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(str(status))
        if imported is not None:
            clauses.append("imported=?")
            params.append(int(bool(imported)))
        params.append(max(1, min(5000, int(limit))))
        with self._connection() as db:
            rows = db.execute(f"SELECT * FROM remail_orders WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC, order_no DESC LIMIT ?", params).fetchall()
        return [self._remail_order_dict(row, public=public) for row in rows]

    def mark_remail_order_imported(self, order_no: str, pool_row_id: str) -> dict[str, Any] | None:
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("UPDATE remail_orders SET imported=1,pool_row_id=?,updated_at=? WHERE order_no=?", (str(pool_row_id), _now(), str(order_no).strip()))
                    row = db.execute("SELECT * FROM remail_orders WHERE order_no=?", (str(order_no).strip(),)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return self._remail_order_dict(row) if row is not None else None

    def update_mailbox(
        self,
        row_id: str,
        *,
        status: str | None = None,
        batch_id: str | None = None,
        payload_patch: Mapping[str, Any] | None = None,
        allow_active_status: bool = False,
    ) -> dict[str, Any] | None:
        """Apply a narrow mailbox update without replacing private fields."""
        rid = str(row_id or "").strip()
        if not rid:
            return None
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    current = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (rid,)).fetchone()
                    if current is None:
                        db.execute("COMMIT")
                        return None
                    payload = self._row_payload(current)
                    now_epoch = time.time()
                    active_lease = db.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_type='mailbox' "
                        "AND resource_id=? AND lease_until>? LIMIT 1",
                        (rid, now_epoch),
                    ).fetchone()
                    if isinstance(payload_patch, Mapping):
                        patch_values = copy.deepcopy(dict(payload_patch))
                        if active_lease is not None:
                            # Lifecycle fields have dedicated atomic methods;
                            # accepting them from a generic progress callback
                            # would let a stale snapshot clear confirmation.
                            for key in (
                                "row_id",
                                "email",
                                "mailbox_url",
                                "status",
                                "lease_owner",
                                "lease_until",
                                "lease_confirmed",
                                "lease_confirmed_at",
                                "task_id",
                                "batch_id",
                                "driver",
                            ):
                                patch_values.pop(key, None)
                        payload.update(patch_values)
                    revision_clause = "revision=revision+1"
                    if active_lease is not None:
                        # Non-lifecycle metadata must not invalidate the
                        # worker's claim-to-confirm CAS revision.
                        revision_clause = "revision=revision"
                    public_payload, private_payload = _partition_json(payload)
                    updates: list[str] = []
                    params: list[Any] = []
                    if status is not None and (active_lease is None or allow_active_status):
                        updates.append("status=?")
                        params.append(str(status))
                    if batch_id is not None and (active_lease is None or allow_active_status):
                        updates.append("batch_id=?")
                        params.append(str(batch_id))
                    updates.extend([
                        "updated_at=?",
                        revision_clause,
                        "payload=?",
                        "private_payload=?",
                    ])
                    params.extend([
                        _now(),
                        _safe_json(public_payload),
                        _safe_json(private_payload),
                        rid,
                    ])
                    db.execute(
                        f"UPDATE mailboxes SET {','.join(updates)} WHERE row_id=?",
                        params,
                    )
                    row = db.execute("SELECT * FROM mailboxes WHERE row_id=?", (rid,)).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return self._mailbox_dict(row) if row is not None else None

    def delete_tasks(
        self,
        task_ids: Sequence[str],
        *,
        terminal_only: bool = True,
        expected_revisions: Mapping[str, int] | None = None,
    ) -> int:
        """Delete task history with optional revision compare-and-set.

        ``expected_revisions`` is used by compatibility snapshot writers.  A
        task may be absent from one process' in-memory map because another
        process created it after the map was read; requiring a known revision
        prevents that stale writer from deleting the newer history.  The
        check and delete run in one ``BEGIN IMMEDIATE`` transaction, so a
        matching row cannot change between the predicate and the delete.
        """
        values = [str(value or "").strip() for value in task_ids if str(value or "").strip()]
        if not values:
            return 0
        revisions: dict[str, int] = {}
        if expected_revisions is not None:
            for task_id in values:
                if task_id not in expected_revisions:
                    continue
                try:
                    revisions[task_id] = int(expected_revisions[task_id])
                except (TypeError, ValueError):
                    continue
            # A CAS deletion is intentionally conservative: unknown rows are
            # never eligible for removal from a stale full snapshot.
            values = [task_id for task_id in values if task_id in revisions]
            if not values:
                return 0
        placeholders = ",".join("?" for _ in values)
        terminal = tuple(TERMINAL_TASK_STATUSES)
        with self._transaction():
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    clauses: list[str] = []
                    params: list[Any] = []
                    if revisions:
                        revision_clauses = []
                        for task_id in values:
                            revision_clauses.append("(task_id=? AND revision=?)")
                            params.extend((task_id, revisions[task_id]))
                        clauses.append("(" + " OR ".join(revision_clauses) + ")")
                    else:
                        clauses.append(f"task_id IN ({placeholders})")
                        params.extend(values)
                    if terminal_only:
                        terminal_placeholders = ",".join("?" for _ in terminal)
                        clauses.append(f"status IN ({terminal_placeholders})")
                        params.extend(terminal)
                    # Never delete a row while a live worker lease exists.
                    # The worker may still persist a terminal result after a
                    # UI cleanup request; deleting here would allow that late
                    # callback to recreate inconsistent history.
                    clauses.append(
                        "NOT EXISTS (SELECT 1 FROM resource_leases rl "
                        "WHERE rl.resource_type='task' AND rl.resource_id=tasks.task_id "
                        "AND rl.lease_until>?)"
                    )
                    params.append(time.time())
                    rows = db.execute(
                        f"SELECT task_id FROM tasks WHERE {' AND '.join(clauses)}", params
                    ).fetchall()
                    ids = [str(row[0]) for row in rows]
                    if ids:
                        id_placeholders = ",".join("?" for _ in ids)
                        db.execute(
                            f"DELETE FROM resource_leases WHERE resource_type='task' AND resource_id IN ({id_placeholders})",
                            ids,
                        )
                        deleted = db.execute(
                            f"DELETE FROM tasks WHERE task_id IN ({id_placeholders})", ids
                        ).rowcount
                    else:
                        deleted = 0
                    db.execute("COMMIT")
                except BaseException:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                    raise
        return int(deleted or 0)

    def get_result(self, row_id: str, *, public: bool = False) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute("SELECT * FROM results WHERE row_id=?", (str(row_id),)).fetchone()
        return self._result_dict(row, public=public) if row is not None else None

    def public_mailboxes(self, **kwargs: Any) -> list[dict[str, Any]]:
        kwargs["public"] = True
        return self.list_mailboxes(**kwargs)

    def public_proxies(self, **kwargs: Any) -> list[dict[str, Any]]:
        kwargs["public"] = True
        return self.list_proxies(**kwargs)

    def public_tasks(self, **kwargs: Any) -> list[dict[str, Any]]:
        kwargs["public"] = True
        return self.list_tasks(**kwargs)

    def health(self) -> dict[str, Any]:
        with self._connection() as db:
            tables = {}
            for table in ("mailboxes", "proxies", "tasks", "results"):
                tables[table] = int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            journal = str(db.execute("PRAGMA journal_mode").fetchone()[0] or "").lower()
            busy = int(db.execute("PRAGMA busy_timeout").fetchone()[0] or 0)
        owner_status = self.manager_owner_status()
        return {
            "ok": journal == "wal" and busy >= self.busy_timeout_ms,
            "path": str(self.path),
            "journal_mode": journal,
            "busy_timeout_ms": busy,
            "schema_version": int(self._meta("schema_version") or 0),
            "migration": self._meta(MIGRATION_KEY),
            "counts": tables,
            "manager_owner": owner_status,
        }


# Names kept intentionally broad so the future runtime wiring can choose a
# descriptive import without another compatibility module.
FreeStorage = FreeSQLiteStore
FreeRegisterSQLiteStore = FreeSQLiteStore


__all__ = [
    "FreeSQLiteStore",
    "FreeStorage",
    "FreeRegisterSQLiteStore",
    "FreeStorageError",
    "RevisionConflict",
    "LeaseConflict",
    "ManagerOwnerConflict",
    "SCHEMA_VERSION",
    "MIGRATION_KEY",
    "MANAGER_OWNER_KEY",
    "MANAGER_OWNER_TTL_SECONDS",
    "PROXY_REPAIR_KEY",
    "_valid_migration_marker",
]
