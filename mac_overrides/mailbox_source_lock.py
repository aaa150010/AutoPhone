"""Shared source-pool locking for mailbox administration."""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
import hashlib
from typing import Any, Mapping

try:
    from file_safety import named_file_lock as _named_file_lock
except ImportError:  # Unit tests do not load recovered runtime dependencies.
    _named_file_lock = None


class MailboxSourceLockMixin:
    """Provide stable source locking and recovered-pool validation adapters."""

    def _pool_source_lock(self, config: Mapping[str, Any]):
        if _named_file_lock is None:
            return nullcontext()
        pool_path = self._path(config, "pool_path").resolve()
        digest = hashlib.sha256(str(pool_path).encode("utf-8")).hexdigest()[:16]
        return _named_file_lock(f"self_mailbox_source_{digest}.lock")

    @contextmanager
    def _locked_pool_config(self):
        with self._lock:
            config = self._config()
            with self._pool_source_lock(config):
                yield config

    def _validate_pool(self) -> Any:
        return self.validate_pool(self._config())


__all__ = ["MailboxSourceLockMixin"]
