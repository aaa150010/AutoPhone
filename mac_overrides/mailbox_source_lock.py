"""Shared source-pool locking for mailbox administration.

The recovered ``file_safety.named_file_lock`` uses a blocking ``flock``.  A
stale helper process or a second dashboard request could therefore hold the
service ``RLock`` forever while waiting for the file lock.  This module keeps
the recovered lock name and process lock registry, but uses a bounded,
non-blocking poll for the source lock used by mailbox mutations.
"""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
import errno
import hashlib
import math
import os
from pathlib import Path
import threading
import time
from typing import Any, Iterator, Mapping

try:
    import fcntl
except ImportError:  # pragma: no cover - the shipped runtime targets macOS.
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover - exercised only on Windows.
    msvcrt = None

try:
    from file_safety import named_file_lock as _named_file_lock
except ImportError:  # Unit tests do not load recovered runtime dependencies.
    _named_file_lock = None

try:
    from runtime_paths import runtime_path as _runtime_path
except ImportError:  # Unit tests do not load recovered runtime dependencies.
    _runtime_path = None


DEFAULT_SOURCE_LOCK_TIMEOUT_SECONDS = 5.0
SOURCE_LOCK_POLL_SECONDS = 0.05
_MAX_SOURCE_LOCK_TIMEOUT_SECONDS = 30.0


class MailboxSourceLockTimeout(TimeoutError):
    """Raised when another process keeps the mailbox source lock too long."""

    code = "mailbox_source_lock_timeout"
    node_code = "mailbox_source_lock"
    node_label = "邮箱池源文件锁"
    status_code = 409

    def __init__(self, lock_name: str, timeout_seconds: float) -> None:
        self.lock_name = str(lock_name or "lock")
        self.timeout_seconds = float(timeout_seconds)
        self.public_message = (
            "邮箱池锁等待超时 [邮箱池锁/mailbox_source_lock_timeout]："
            f"等待 {self.timeout_seconds:.1f} 秒后仍未释放，请稍后重试"
        )
        self.error_code = self.code
        super().__init__(self.public_message)


_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_PROCESS_LOCKS: dict[str, threading.RLock] = {}


def _safe_lock_name(name: Any) -> str:
    raw_name = str(name or "lock")
    safe_name = "".join(
        character if character.isalnum() or character in ".-_" else "_"
        for character in raw_name
    )
    if len(safe_name) > 120:
        digest = hashlib.sha256(raw_name.encode("utf-8", errors="ignore")).hexdigest()[:16]
        safe_name = f"{safe_name[:96]}_{digest}"
    return safe_name


def _timeout_seconds(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = DEFAULT_SOURCE_LOCK_TIMEOUT_SECONDS
    if not math.isfinite(parsed):
        parsed = DEFAULT_SOURCE_LOCK_TIMEOUT_SECONDS
    return max(0.0, min(parsed, _MAX_SOURCE_LOCK_TIMEOUT_SECONDS))


def _recovered_file_safety_globals() -> Mapping[str, Any]:
    """Return recovered lock globals when the real function is installed."""

    function = getattr(_named_file_lock, "__wrapped__", None)
    if not callable(function):
        return {}
    if getattr(_named_file_lock, "__module__", "") != "file_safety":
        return {}
    if getattr(_named_file_lock, "__name__", "") != "named_file_lock":
        return {}
    value = getattr(function, "__globals__", {})
    return value if isinstance(value, Mapping) else {}


def _process_lock_for(safe_name: str) -> threading.RLock:
    """Reuse file_safety's per-process lock to stay compatible with callers."""

    recovered = _recovered_file_safety_globals()
    guard = recovered.get("_LOCKS_GUARD")
    locks = recovered.get("_PROCESS_LOCKS")
    if guard is not None and isinstance(locks, dict):
        with guard:
            lock = locks.get(safe_name)
            if lock is None:
                lock = threading.RLock()
                locks[safe_name] = lock
            return lock
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_PROCESS_LOCKS.setdefault(safe_name, threading.RLock())


def _lock_directory() -> Path:
    if callable(_runtime_path):
        try:
            return Path(_runtime_path("data", "locks"))
        except Exception:
            pass
    app_root = str(os.environ.get("CHATGPT_AR_APP_ROOT") or "").strip()
    return Path(app_root or Path.cwd()) / "data" / "locks"


def _try_lock_file(handle: Any) -> None:
    if fcntl is not None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return
    if msvcrt is not None:  # pragma: no cover - Windows compatibility path.
        handle.seek(0)
        mode = getattr(msvcrt, "LK_NBLCK", getattr(msvcrt, "LK_LOCK"))
        msvcrt.locking(handle.fileno(), mode, 1)
        return
    raise OSError("no supported file locking primitive")


def _unlock_file(handle: Any) -> None:
    if fcntl is not None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    elif msvcrt is not None:  # pragma: no cover - Windows compatibility path.
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def _direct_timed_file_lock(name: str, timeout_seconds: float) -> Iterator[None]:
    """Acquire the recovered lock file without an unbounded ``flock`` call."""

    safe_name = _safe_lock_name(name)
    timeout = _timeout_seconds(timeout_seconds)
    process_lock = _process_lock_for(safe_name)
    started = time.monotonic()
    deadline = started + timeout
    acquired_process = False
    handle = None
    locked = False
    try:
        remaining = max(0.0, deadline - time.monotonic())
        if remaining > 0:
            acquired_process = process_lock.acquire(timeout=remaining)
        else:
            acquired_process = process_lock.acquire(blocking=False)
        if not acquired_process:
            raise MailboxSourceLockTimeout(safe_name, timeout)

        lock_directory = _lock_directory()
        lock_directory.mkdir(parents=True, exist_ok=True)
        handle = (lock_directory / safe_name).open("a+b")
        while True:
            try:
                _try_lock_file(handle)
                locked = True
                break
            except OSError as exc:
                if exc.errno not in {
                    errno.EACCES,
                    errno.EAGAIN,
                    getattr(errno, "EWOULDBLOCK", errno.EAGAIN),
                }:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MailboxSourceLockTimeout(safe_name, timeout) from exc
                time.sleep(min(SOURCE_LOCK_POLL_SECONDS, remaining))
        yield
    finally:
        if locked and handle is not None:
            try:
                _unlock_file(handle)
            except OSError:
                pass
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        if acquired_process:
            process_lock.release()


@contextmanager
def _timed_source_file_lock(name: str, timeout_seconds: float) -> Iterator[None]:
    """Use a test-injected factory verbatim, otherwise use the bounded lock."""

    if _named_file_lock is None:
        yield
        return
    if _recovered_file_safety_globals():
        with _direct_timed_file_lock(name, timeout_seconds):
            yield
        return

    # Unit tests and embedding callers may replace the recovered factory with
    # an in-memory/context-manager implementation. Preserve that contract.
    with _named_file_lock(name):
        yield


class MailboxSourceLockMixin:
    """Provide stable source locking and recovered-pool validation adapters."""

    def _source_lock_timeout(self, config: Mapping[str, Any] | None = None) -> float:
        value = (config or {}).get("mailbox_source_lock_timeout_seconds") if config else None
        return _timeout_seconds(value)

    def _pool_source_lock(
        self,
        config: Mapping[str, Any],
        *,
        timeout_seconds: float | None = None,
    ):
        if _named_file_lock is None:
            return nullcontext()
        pool_path = self._path(config, "pool_path").resolve()
        digest = hashlib.sha256(str(pool_path).encode("utf-8")).hexdigest()[:16]
        timeout = self._source_lock_timeout(config) if timeout_seconds is None else timeout_seconds
        return _timed_source_file_lock(
            f"self_mailbox_source_{digest}.lock",
            timeout,
        )

    @contextmanager
    def _locked_pool_config(self):
        # Keep the config snapshot and source lock paired.  The service lock
        # is bounded too, so a blocked cross-process flock cannot leave every
        # reader waiting forever, while a config change cannot redirect a
        # write to a pool path protected by a different lock.
        initial_config = self._config()
        timeout = self._source_lock_timeout(initial_config)
        started = time.monotonic()
        if timeout > 0:
            acquired = self._lock.acquire(timeout=timeout)
        else:
            acquired = self._lock.acquire(blocking=False)
        if not acquired:
            raise MailboxSourceLockTimeout("mailbox_admin", timeout)
        try:
            config = self._config()
            remaining = max(0.0, timeout - (time.monotonic() - started))
            with self._pool_source_lock(config, timeout_seconds=remaining):
                yield config
        finally:
            self._lock.release()

    def _validate_pool(self) -> Any:
        return self.validate_pool(self._config())


__all__ = [
    "DEFAULT_SOURCE_LOCK_TIMEOUT_SECONDS",
    "MailboxSourceLockMixin",
    "MailboxSourceLockTimeout",
]
