"""Task-scoped transport cleanup and process resource observations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import resource
import stat
import subprocess
import threading
import time
from typing import Any, Callable


_CLOSE_LOCK = threading.RLock()
_SESSION_ATTRIBUTES = (
    "session",
    "auth_session",
    "_auth_session",
    "curl_session",
    "_curl_session",
)
_NODE_PROCESS_ATTRIBUTES = (
    "node_process",
    "_node_process",
    "node_proc",
    "_node_proc",
    "node_subprocess",
    "_node_subprocess",
    "child_process",
)
_GENERIC_PROCESS_ATTRIBUTES = ("process", "proc")
_PIPE_ATTRIBUTES = (
    "node_stdin",
    "node_stdout",
    "node_stderr",
    "stdin",
    "stdout",
    "stderr",
)
_OWNED_NODE_BINDINGS_ATTRIBUTE = "_gptphone_owned_node_bindings"
_CLOSED_RESOURCE_IDS_ATTRIBUTE = "_gptphone_closed_resource_ids"
_CLEANUP_PENDING_ATTRIBUTE = "_gptphone_transport_cleanup_pending"


def _task_key(value: Any) -> str:
    return str(value or "").strip()


def _close_once(
    resource: Any,
    attempted: set[int],
    completed: set[int],
) -> tuple[bool, bool]:
    if resource is None or id(resource) in completed:
        return False, True
    if id(resource) in attempted:
        return False, True
    close = getattr(resource, "close", None)
    if not callable(close):
        return False, True
    attempted.add(id(resource))
    try:
        close()
        completed.add(id(resource))
        return True, True
    except Exception:
        return False, False


def _process_command(process: Any) -> str:
    args = getattr(process, "args", "")
    if isinstance(args, (list, tuple)):
        return " ".join(str(value) for value in args[:2])
    return str(args or "")


def _is_node_process(process: Any) -> bool:
    command = _process_command(process).strip()
    if not command:
        return False
    executable = command.split(maxsplit=1)[0]
    return Path(executable).name.lower() in {"node", "nodejs"}


def _direct_child_ppid(pid: int) -> int | None:
    proc_stat = Path(f"/proc/{pid}/stat")
    try:
        text = proc_stat.read_text(encoding="utf-8", errors="replace")
        tail = text.rsplit(")", 1)[1].strip().split()
        return int(tail[1])
    except (IndexError, OSError, TypeError, ValueError):
        pass
    try:
        result = subprocess.run(
            ["ps", "-o", "ppid=", "-p", str(pid)],
            capture_output=True,
            check=False,
            text=True,
            timeout=1.0,
        )
        return int(result.stdout.strip()) if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return None


def _cached_owned_node_process(transport: Any, process: Any) -> bool:
    bindings = getattr(transport, _OWNED_NODE_BINDINGS_ATTRIBUTE, None)
    if not isinstance(bindings, dict):
        return False
    binding = bindings.get(id(process))
    if not isinstance(binding, tuple) or len(binding) != 3:
        return False
    bound_process, bound_pid, owner_pid = binding
    return (
        bound_process is process
        and owner_pid == os.getpid()
        and bound_pid == getattr(process, "pid", None)
    )


def _node_process_ownership(
    process: Any,
    *,
    explicit_node_attribute: bool,
    transport: Any = None,
) -> bool | None:
    if process is None:
        return False
    if transport is not None and _cached_owned_node_process(transport, process):
        return True
    if not explicit_node_attribute and not _is_node_process(process):
        return False
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        # Test doubles and not-yet-started Popen-like objects are owned only
        # when the transport used a node-specific attribute.
        return explicit_node_attribute
    if not _is_node_process(process):
        return False
    try:
        parent_pid = _direct_child_ppid(pid)
    except Exception:
        parent_pid = None
    if parent_pid is None:
        poll = getattr(process, "poll", None)
        try:
            if callable(poll) and poll() is not None:
                return True
        except Exception:
            pass
        return None
    return parent_pid == os.getpid()


def _owned_node_process(
    process: Any,
    *,
    explicit_node_attribute: bool,
    transport: Any = None,
) -> bool:
    return (
        _node_process_ownership(
            process,
            explicit_node_attribute=explicit_node_attribute,
            transport=transport,
        )
        is True
    )


def _process_owners(transport: Any) -> tuple[Any, ...]:
    owners = [transport]
    sentinel = getattr(transport, "sentinel_provider", None)
    if sentinel is not None:
        owners.append(sentinel)
    return tuple(owners)


def _remember_owned_node_processes(transport: Any) -> None:
    """Cache verified child bindings while descriptor pressure is still low."""

    bindings = getattr(transport, _OWNED_NODE_BINDINGS_ATTRIBUTE, None)
    bindings = dict(bindings) if isinstance(bindings, dict) else {}
    changed = False
    for owner in _process_owners(transport):
        for name in _NODE_PROCESS_ATTRIBUTES + _GENERIC_PROCESS_ATTRIBUTES:
            process = getattr(owner, name, None)
            if process is None or id(process) in bindings:
                continue
            explicit = name in _NODE_PROCESS_ATTRIBUTES
            if _owned_node_process(
                process,
                explicit_node_attribute=explicit,
            ):
                bindings[id(process)] = (
                    process,
                    getattr(process, "pid", None),
                    os.getpid(),
                )
                changed = True
    if changed:
        try:
            setattr(transport, _OWNED_NODE_BINDINGS_ATTRIBUTE, bindings)
        except Exception:
            pass


def _close_process_pipes(
    process: Any,
    attempted: set[int],
    completed: set[int],
) -> tuple[bool, bool]:
    changed = False
    succeeded = True
    for name in _PIPE_ATTRIBUTES:
        resource_changed, resource_succeeded = _close_once(
            getattr(process, name, None), attempted, completed
        )
        changed = resource_changed or changed
        succeeded = resource_succeeded and succeeded
    return changed, succeeded


def _stop_node_process(
    process: Any,
    attempted: set[int],
    completed: set[int],
) -> tuple[bool, bool]:
    if process is None or id(process) in completed:
        return False, True
    if id(process) in attempted:
        return False, True
    attempted.add(id(process))
    changed, pipes_succeeded = _close_process_pipes(process, attempted, completed)
    poll = getattr(process, "poll", None)
    try:
        running = not callable(poll) or poll() is None
    except Exception:
        running = True
    if not running:
        if pipes_succeeded:
            completed.add(id(process))
        return changed, pipes_succeeded
    terminate = getattr(process, "terminate", None)
    wait = getattr(process, "wait", None)
    stopped = False
    try:
        if callable(terminate):
            terminate()
            changed = True
        if callable(wait):
            wait(timeout=0.5)
        stopped = callable(terminate) or callable(wait)
    except Exception:
        stopped = False
    if not stopped:
        kill = getattr(process, "kill", None)
        try:
            if callable(kill):
                kill()
                changed = True
            if callable(wait):
                wait(timeout=0.5)
            stopped = callable(kill) or callable(wait)
        except Exception:
            stopped = False
    succeeded = pipes_succeeded and stopped
    if succeeded:
        completed.add(id(process))
    return changed, succeeded


def close_transport(transport: Any) -> bool:
    """Best-effort close of resources explicitly owned by one transport."""
    if transport is None:
        return False
    with _CLOSE_LOCK:
        if bool(getattr(transport, "_gptphone_transport_closed", False)):
            return False

        changed = False
        succeeded = True
        attempted: set[int] = set()
        completed_value = getattr(transport, _CLOSED_RESOURCE_IDS_ATTRIBUTE, None)
        completed = set(completed_value) if isinstance(completed_value, set) else set()
        for name in _SESSION_ATTRIBUTES:
            resource_changed, resource_succeeded = _close_once(
                getattr(transport, name, None), attempted, completed
            )
            changed = resource_changed or changed
            succeeded = resource_succeeded and succeeded
        for name in _PIPE_ATTRIBUTES:
            resource_changed, resource_succeeded = _close_once(
                getattr(transport, name, None), attempted, completed
            )
            changed = resource_changed or changed
            succeeded = resource_succeeded and succeeded

        for owner in _process_owners(transport):
            for name in _NODE_PROCESS_ATTRIBUTES + _GENERIC_PROCESS_ATTRIBUTES:
                process = getattr(owner, name, None)
                explicit = name in _NODE_PROCESS_ATTRIBUTES
                ownership = _node_process_ownership(
                    process,
                    explicit_node_attribute=explicit,
                    transport=transport,
                )
                if ownership is True:
                    process_changed, process_succeeded = _stop_node_process(
                        process, attempted, completed
                    )
                    changed = process_changed or changed
                    succeeded = process_succeeded and succeeded
                elif ownership is None:
                    succeeded = False
        try:
            setattr(transport, _CLOSED_RESOURCE_IDS_ATTRIBUTE, completed)
            setattr(transport, _CLEANUP_PENDING_ATTRIBUTE, not succeeded)
            if succeeded:
                setattr(transport, "_gptphone_transport_closed", True)
        except Exception:
            pass
        return changed


class TaskTransportRegistry:
    """Own strong transport references only for the lifetime of one task."""

    def __init__(
        self,
        *,
        task_id_getter: Callable[[Any], str] | None = None,
        close_fn: Callable[[Any], bool] = close_transport,
    ) -> None:
        self._task_id_getter = task_id_getter
        self._close_fn = close_fn
        self._lock = threading.RLock()
        self._items: dict[str, Any] = {}
        self._pending: dict[str, list[Any]] = {}
        self._closed_count = 0

    @staticmethod
    def _cleanup_completed(transport: Any, changed: bool) -> bool:
        closed_marker = getattr(transport, "_gptphone_transport_closed", None)
        pending_marker = getattr(transport, _CLEANUP_PENDING_ATTRIBUTE, None)
        if closed_marker is not None or pending_marker is not None:
            return bool(closed_marker) and not bool(pending_marker)
        return changed

    def _remove_pending(self, key: str, transport: Any) -> None:
        with self._lock:
            pending = self._pending.get(key, [])
            remaining = [item for item in pending if item is not transport]
            if remaining:
                self._pending[key] = remaining
            else:
                self._pending.pop(key, None)

    def _retain_pending(self, key: str, transport: Any) -> None:
        with self._lock:
            pending = self._pending.setdefault(key, [])
            if not any(item is transport for item in pending):
                pending.append(transport)

    def _attempt_cleanup(self, key: str, transport: Any) -> tuple[bool, bool]:
        try:
            changed = bool(self._close_fn(transport))
        except Exception:
            changed = False
        completed = self._cleanup_completed(transport, changed)
        if completed:
            self._remove_pending(key, transport)
            with self._lock:
                self._closed_count += 1
        else:
            self._retain_pending(key, transport)
        return changed, completed

    def _transport_task_id(self, transport: Any) -> str:
        if callable(self._task_id_getter):
            try:
                return _task_key(self._task_id_getter(transport))
            except Exception:
                return ""
        config = getattr(transport, "config", None)
        if not isinstance(config, dict):
            return ""
        return _task_key(config.get("sms_task_id") or config.get("run_id"))

    def register(self, task_id: Any, transport: Any) -> None:
        key = _task_key(task_id)
        if not key or transport is None:
            return
        _remember_owned_node_processes(transport)
        displaced: list[Any] = []
        with self._lock:
            for old_key, old_transport in tuple(self._items.items()):
                if old_transport is transport and old_key != key:
                    self._items.pop(old_key, None)
            previous = self._items.get(key)
            if previous is not None and previous is not transport:
                displaced.append(previous)
            self._items[key] = transport
        for previous in displaced:
            self._attempt_cleanup(key, previous)
        try:
            setattr(transport, "_gptphone_registered_task_id", key)
        except Exception:
            pass

    def get(self, task_id: Any) -> Any:
        key = _task_key(task_id)
        if not key:
            return None
        stale = None
        with self._lock:
            transport = self._items.get(key)
            if transport is not None and self._transport_task_id(transport) != key:
                self._items.pop(key, None)
                stale = transport
                transport = None
        if stale is not None:
            self._attempt_cleanup(key, stale)
        return transport

    def unregister(self, task_id: Any, transport: Any = None) -> Any:
        key = _task_key(task_id)
        if not key:
            return None
        with self._lock:
            current = self._items.get(key)
            if current is None or (transport is not None and current is not transport):
                return None
            self._items.pop(key, None)
        if getattr(current, "_gptphone_registered_task_id", "") == key:
            try:
                delattr(current, "_gptphone_registered_task_id")
            except (AttributeError, TypeError):
                pass
        return current

    def close_task(self, task_id: Any) -> bool:
        key = _task_key(task_id)
        if not key:
            return False
        with self._lock:
            current = self._items.pop(key, None)
            pending = self._pending.pop(key, [])
        transports = [item for item in (current, *pending) if item is not None]
        if not transports:
            return False
        if current is not None and getattr(
            current,
            "_gptphone_registered_task_id",
            "",
        ) == key:
            try:
                delattr(current, "_gptphone_registered_task_id")
            except (AttributeError, TypeError):
                pass
        all_completed = True
        seen: set[int] = set()
        for transport in transports:
            if id(transport) in seen:
                continue
            seen.add(id(transport))
            _changed, completed = self._attempt_cleanup(key, transport)
            all_completed = all_completed and completed
        with self._lock:
            cleanup_remaining = bool(self._pending.get(key))
            active_remaining = self._items.get(key) is not None
        return all_completed and not cleanup_remaining and not active_remaining

    def clear(self) -> int:
        with self._lock:
            items = list(self._items.items())
            self._items.clear()
            for key, pending in self._pending.items():
                items.extend((key, item) for item in pending)
            self._pending.clear()
        completed = 0
        seen: set[int] = set()
        for key, item in items:
            if id(item) in seen:
                continue
            seen.add(id(item))
            _changed, item_completed = self._attempt_cleanup(key, item)
            completed += int(item_completed)
        return completed

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "active_transports": len(self._items),
                "closed_transports": self._closed_count,
                "pending_cleanup": sum(len(items) for items in self._pending.values()),
            }


@dataclass(frozen=True)
class ProcessResourceSnapshot:
    open_fds: int | None
    soft_fd_limit: int | None
    fd_ratio: float | None
    pipe_fds: int | None = None
    socket_fds: int | None = None
    close_wait_sockets: int | None = None
    node_child_processes: int | None = None
    observed_at: float = 0.0

    def public(self) -> dict[str, Any]:
        value = asdict(self)
        if isinstance(value.get("fd_ratio"), float):
            value["fd_ratio"] = round(value["fd_ratio"], 4)
        return value


def _fd_directory() -> Path | None:
    for candidate in (Path("/proc/self/fd"), Path("/dev/fd")):
        if candidate.is_dir():
            return candidate
    return None


def _fd_counts(fd_dir: Path) -> tuple[int, int, int, set[int]]:
    open_fds = 0
    pipe_fds = 0
    socket_fds = 0
    socket_inodes: set[int] = set()
    for name in os.listdir(fd_dir):
        if not str(name).isdigit():
            continue
        fd = int(name)
        try:
            fd_stat = os.fstat(fd)
        except OSError:
            continue
        open_fds += 1
        if stat.S_ISFIFO(fd_stat.st_mode):
            pipe_fds += 1
        elif stat.S_ISSOCK(fd_stat.st_mode):
            socket_fds += 1
            if fd_stat.st_ino > 0:
                socket_inodes.add(int(fd_stat.st_ino))
    return open_fds, pipe_fds, socket_fds, socket_inodes


def _linux_close_wait_count(socket_inodes: set[int]) -> int | None:
    if not socket_inodes:
        return 0
    observed: set[int] = set()
    available = False
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = path.read_text(encoding="ascii", errors="replace").splitlines()[1:]
            available = True
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "08":
                continue
            try:
                inode = int(fields[9])
            except ValueError:
                continue
            if inode in socket_inodes:
                observed.add(inode)
    return len(observed) if available else None


def _darwin_close_wait_count() -> int | None:
    try:
        result = subprocess.run(
            [
                "lsof",
                "-nP",
                "-a",
                "-p",
                str(os.getpid()),
                "-iTCP",
                "-sTCP:CLOSE_WAIT",
                "-Ff",
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=1.0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode not in {0, 1}:
        return None
    descriptors: set[str] = set()
    for line in result.stdout.splitlines():
        if not line.startswith("f"):
            continue
        descriptor = ""
        for character in line[1:]:
            if not character.isdigit():
                break
            descriptor += character
        if descriptor:
            descriptors.add(descriptor)
    return len(descriptors)


def _close_wait_count(socket_inodes: set[int]) -> int | None:
    if Path("/proc/net/tcp").is_file():
        return _linux_close_wait_count(socket_inodes)
    return _darwin_close_wait_count()


def _soft_fd_limit() -> int | None:
    try:
        raw_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except (OSError, ValueError):
        return None
    if raw_limit <= 0 or raw_limit == resource.RLIM_INFINITY:
        return None
    return int(raw_limit)


def process_fd_ratio() -> float | None:
    """Return current FD pressure without spawning ps/lsof diagnostics."""

    fd_dir = _fd_directory()
    if fd_dir is None:
        return None
    try:
        open_fds, _pipe_fds, _socket_fds, _socket_inodes = _fd_counts(fd_dir)
    except OSError:
        return None
    soft_limit = _soft_fd_limit()
    if soft_limit is None or soft_limit <= 0:
        return None
    return float(open_fds) / float(soft_limit)


def _node_child_process_count() -> int | None:
    proc_root = Path("/proc")
    if proc_root.is_dir():
        count = 0
        try:
            entries = tuple(proc_root.iterdir())
        except OSError:
            return None
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                pid = int(entry.name)
                if _direct_child_ppid(pid) != os.getpid():
                    continue
                command = (entry / "cmdline").read_bytes().split(b"\0", 1)[0]
                if Path(os.fsdecode(command)).name.lower() in {"node", "nodejs"}:
                    count += 1
            except (OSError, ValueError):
                continue
        return count
    try:
        result = subprocess.run(
            ["ps", "-axo", "ppid=,comm="],
            capture_output=True,
            check=False,
            text=True,
            timeout=1.0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    count = 0
    for line in result.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            direct = int(fields[0]) == os.getpid()
        except ValueError:
            continue
        if direct and Path(fields[1]).name.lower() in {"node", "nodejs"}:
            count += 1
    return count


def process_resource_snapshot(*, now_fn: Callable[[], float] = time.time) -> ProcessResourceSnapshot:
    open_fds: int | None = None
    pipe_fds: int | None = None
    socket_fds: int | None = None
    close_wait_sockets: int | None = None
    fd_dir = _fd_directory()
    if fd_dir is not None:
        try:
            open_fds, pipe_fds, socket_fds, socket_inodes = _fd_counts(fd_dir)
            close_wait_sockets = _close_wait_count(socket_inodes)
        except OSError:
            open_fds = None
    soft_limit = _soft_fd_limit()
    ratio = (
        float(open_fds) / float(soft_limit)
        if open_fds is not None and soft_limit is not None and soft_limit > 0
        else None
    )
    return ProcessResourceSnapshot(
        open_fds=open_fds,
        soft_fd_limit=soft_limit,
        fd_ratio=ratio,
        pipe_fds=pipe_fds,
        socket_fds=socket_fds,
        close_wait_sockets=close_wait_sockets,
        node_child_processes=_node_child_process_count(),
        observed_at=float(now_fn()),
    )


def is_fd_exhaustion(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return "too many open files" in text or "errno 24" in text or "emfile" in text


__all__ = [
    "ProcessResourceSnapshot",
    "TaskTransportRegistry",
    "close_transport",
    "is_fd_exhaustion",
    "process_fd_ratio",
    "process_resource_snapshot",
]
