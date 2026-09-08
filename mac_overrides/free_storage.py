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


try:
    from .free_storage_common import (
    MANAGER_OWNER_KEY,
    MANAGER_OWNER_TTL_SECONDS,
    MIGRATION_KEY,
    PROXY_REPAIR_KEY,
    SCHEMA_VERSION,
    SECRET_MASK,
    TERMINAL_TASK_STATUSES,
    FreeStorageError,
    LeaseConflict,
    ManagerOwnerConflict,
    RevisionConflict,
    _EMAIL_RE,
    _LEGACY_PLAIN_DIMENSION_KEYS,
    _LEGACY_PROXY_DIMENSION_KEYS,
    _MAILBOX_SPLIT_RE,
    _MISSING,
    _NON_SECRET_METADATA_KEYS,
    _NON_SECRET_METADATA_KEY_TOKENS,
    _PRIVATE_KEYS,
    _SENSITIVE_KEY_RE,
    _clear_legacy_pool_dimensions,
    _fingerprint,
    _is_private_key,
    _json_object,
    _legacy_proxy_url,
    _mask_email,
    _mask_proxy,
    _merge_private_payload,
    _migration_marker_version,
    _normalize_proxy,
    _now,
    _parse_mailbox_line,
    _partition_json,
    _payload_with_fields,
    _redact,
    _safe_float,
    _safe_json,
    _split_private_payload,
    _stored_bool,
    _valid_migration_marker,
    )
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_storage_common import (  # type: ignore[no-redef]
            MANAGER_OWNER_KEY,
        MANAGER_OWNER_TTL_SECONDS,
        MIGRATION_KEY,
        PROXY_REPAIR_KEY,
        SCHEMA_VERSION,
        SECRET_MASK,
        TERMINAL_TASK_STATUSES,
        FreeStorageError,
        LeaseConflict,
        ManagerOwnerConflict,
        RevisionConflict,
        _EMAIL_RE,
        _LEGACY_PLAIN_DIMENSION_KEYS,
        _LEGACY_PROXY_DIMENSION_KEYS,
        _MAILBOX_SPLIT_RE,
        _MISSING,
        _NON_SECRET_METADATA_KEYS,
        _NON_SECRET_METADATA_KEY_TOKENS,
        _PRIVATE_KEYS,
        _SENSITIVE_KEY_RE,
        _clear_legacy_pool_dimensions,
        _fingerprint,
        _is_private_key,
        _json_object,
        _legacy_proxy_url,
        _mask_email,
        _mask_proxy,
        _merge_private_payload,
        _migration_marker_version,
        _normalize_proxy,
        _now,
        _parse_mailbox_line,
        _partition_json,
        _payload_with_fields,
        _redact,
        _safe_float,
        _safe_json,
        _split_private_payload,
        _stored_bool,
        _valid_migration_marker,
    )

try:
    from .free_storage_schema import FreeStorageSchemaMixin
    from .free_storage_migration import FreeStorageMigrationMixin
    from .free_storage_rows import FreeStorageRowMixin
    from .free_storage_mailbox import FreeStorageMailboxMixin
    from .free_storage_proxy import FreeStorageProxyMixin
    from .free_storage_tasks import FreeStorageTaskMixin
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_storage_schema import FreeStorageSchemaMixin  # type: ignore[no-redef]
    from free_storage_migration import FreeStorageMigrationMixin  # type: ignore[no-redef]
    from free_storage_rows import FreeStorageRowMixin  # type: ignore[no-redef]
    from free_storage_mailbox import FreeStorageMailboxMixin  # type: ignore[no-redef]
    from free_storage_proxy import FreeStorageProxyMixin  # type: ignore[no-redef]
    from free_storage_tasks import FreeStorageTaskMixin  # type: ignore[no-redef]

class FreeSQLiteStore(
    FreeStorageSchemaMixin,
    FreeStorageMigrationMixin,
    FreeStorageRowMixin,
    FreeStorageMailboxMixin,
    FreeStorageProxyMixin,
    FreeStorageTaskMixin,
):
    """Thread/process-safe SQLite store for Free private resources.

    ``data_dir`` is expected to be the Free data directory (normally
    ``${GPTPHONE_DATA_DIR}/free_register``).  Methods returning a row expose
    private values by default for workers; ``public=True`` or the ``public_*``
    helpers return redacted projections suitable for UI responses.
    """

    # Aliases kept for callers that model these operations under their
    # more general wording; they resolve through the domain mixins above.
    mailbox_confirmed_for_task = FreeStorageMailboxMixin.is_mailbox_confirmed_for_task
    confirm_lease = FreeStorageMailboxMixin.confirm_mailbox_lease
    abort_lease_confirmation = FreeStorageMailboxMixin.abort_mailbox_confirmation
    release_leases_for_owner = FreeStorageProxyMixin.release_proxy_leases
    update_task = FreeStorageTaskMixin.save_task

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
