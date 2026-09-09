"""Compatibility re-export layer for the Free SQLite storage adapters.

The adapter implementations live in ``free_storage_adapter_common.py``,
``free_storage_adapter_mailbox.py``, ``free_storage_adapter_task.py`` and
``free_storage_adapter_proxy.py``.  This module keeps the historical import
path (``free_storage_adapters``) and its public names stable for the Free
manager, ``web_gui`` and existing tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

try:
    from .free_storage import FreeSQLiteStore
    from .free_storage_adapter_mailbox import SQLiteFreeMailboxPool
    from .free_storage_adapter_proxy import SQLiteFreeProxyPool
    from .free_storage_adapter_task import SQLiteFreeTaskStore
except ImportError:  # pragma: no cover - recovery imports
    from free_storage import FreeSQLiteStore  # type: ignore[no-redef]
    from free_storage_adapter_mailbox import SQLiteFreeMailboxPool  # type: ignore[no-redef]
    from free_storage_adapter_proxy import SQLiteFreeProxyPool  # type: ignore[no-redef]
    from free_storage_adapter_task import SQLiteFreeTaskStore  # type: ignore[no-redef]


@dataclass(frozen=True, slots=True)
class SQLiteFreeStorageAdapters:
    data_dir: Path
    storage: FreeSQLiteStore
    mailboxes: SQLiteFreeMailboxPool
    proxies: SQLiteFreeProxyPool
    tasks: SQLiteFreeTaskStore

    # Names mirror the manager's historical attributes for straightforward
    # dependency injection.
    @property
    def pool(self) -> SQLiteFreeMailboxPool:
        return self.mailboxes

    @property
    def task_store(self) -> SQLiteFreeTaskStore:
        return self.tasks

    @property
    def task_repository(self) -> Any:
        """Return the narrow revisioned repository facade for new callers."""
        try:
            from .free_register.task_repository import FreeTaskRepository
        except ImportError:  # pragma: no cover
            from free_register.task_repository import FreeTaskRepository  # type: ignore[no-redef]
        return FreeTaskRepository(self.data_dir, storage=self.storage)


def build_free_storage_adapters(
    data_dir: str | Path,
    *,
    storage: FreeSQLiteStore | None = None,
    proxy_options: Mapping[str, Any] | None = None,
) -> SQLiteFreeStorageAdapters:
    root = Path(data_dir).expanduser().resolve()
    shared = storage or FreeSQLiteStore(root)
    options = dict(proxy_options or {})
    mailboxes = SQLiteFreeMailboxPool(root, storage=shared)
    proxies = SQLiteFreeProxyPool(root, storage=shared, **options)
    tasks = SQLiteFreeTaskStore(root, storage=shared)
    return SQLiteFreeStorageAdapters(root, shared, mailboxes, proxies, tasks)


# Explicit aliases make the migration seam discoverable without forcing a
# future caller to remember the internal naming convention.
FreeSQLiteMailboxPool = SQLiteFreeMailboxPool
FreeSQLiteProxyPool = SQLiteFreeProxyPool
FreeSQLiteTaskStore = SQLiteFreeTaskStore
FreeStorageAdapters = SQLiteFreeStorageAdapters


__all__ = [
    "SQLiteFreeMailboxPool",
    "SQLiteFreeProxyPool",
    "SQLiteFreeTaskStore",
    "SQLiteFreeStorageAdapters",
    "FreeSQLiteMailboxPool",
    "FreeSQLiteProxyPool",
    "FreeSQLiteTaskStore",
    "FreeStorageAdapters",
    "build_free_storage_adapters",
]
