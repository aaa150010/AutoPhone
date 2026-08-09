"""Bounded, credential-safe access to the macOS generic-password Keychain."""

from __future__ import annotations

import base64
from collections.abc import Callable
import errno
import inspect
import os
import select
import secrets
import subprocess
import time
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - macOS and Linux provide fcntl.
    fcntl = None

try:
    import pty as _pty
    import termios as _termios
except ImportError:  # pragma: no cover - Windows is not a supported runtime.
    _pty = None
    _termios = None


KEY_SERVICE = "com.gptphone.phase1-checkpoint"
DEFAULT_KEYCHAIN_TIMEOUT_SECONDS = 15.0
_KEYCHAIN_POLL_SECONDS = 0.10


class CheckpointError(RuntimeError):
    """Base error for encrypted checkpoint operations."""


class CheckpointDisabled(CheckpointError):
    """Checkpoint support is unavailable for this process."""


class KeychainUnavailable(CheckpointDisabled):
    """The platform Keychain could not provide the encryption key."""


class KeychainOperationStopped(CheckpointDisabled):
    """The current task stopped while a Keychain helper was running."""


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


class SecurityKeyProvider:
    """Minimal macOS Keychain adapter with no shell interpolation."""

    def __init__(
        self,
        *,
        service: str = KEY_SERVICE,
        account: str = "local-installation",
        runner: Callable[..., Any] = subprocess.run,
        timeout_seconds: float = DEFAULT_KEYCHAIN_TIMEOUT_SECONDS,
    ) -> None:
        self.service = service
        self.account = account
        self.runner = runner
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError):
            timeout = DEFAULT_KEYCHAIN_TIMEOUT_SECONDS
        self.timeout_seconds = max(0.1, min(300.0, timeout))

    def get_or_create(
        self,
        *,
        stop_event: Any = None,
        timeout_seconds: float | None = None,
    ) -> bytes:
        """Return the installation key, creating it in Keychain if needed.

        ``security add-generic-password -w`` asks for the new value twice when
        the password is omitted from argv. The old implementation supplied
        only one line, leaving the helper waiting forever for confirmation.
        The default subprocess path is monitored in short intervals so a
        manual stop can terminate it immediately; the key is written only to
        the child's private pty and is never included in argv or diagnostics.
        """
        timeout = self._timeout(timeout_seconds, self.timeout_seconds)
        self._check_stop(stop_event)
        find = self._run(
            ["/usr/bin/security", "find-generic-password", "-a", self.account, "-s", self.service, "-w"],
            stop_event=stop_event,
            timeout_seconds=timeout,
        )
        if getattr(find, "returncode", 1) == 0:
            try:
                value = base64.urlsafe_b64decode(str(find.stdout or "").strip().encode("ascii"))
                if len(value) == 32:
                    return value
            except (ValueError, TypeError):
                pass
        self._check_stop(stop_event)
        key = secrets.token_bytes(32)
        encoded = _b64(key)
        # ``security`` prompts twice when -w has no argv value. Supplying both
        # responses through the pty avoids exposing the key in process listings.
        add = self._run(
            [
                "/usr/bin/security",
                "add-generic-password",
                "-U",
                "-a",
                self.account,
                "-s",
                self.service,
                "-w",
            ],
            input_text=f"{encoded}\n{encoded}\n",
            stop_event=stop_event,
            timeout_seconds=timeout,
        )
        if getattr(add, "returncode", 1) != 0:
            raise KeychainUnavailable("macOS Keychain 不可用，已禁用 OAuth checkpoint")
        return key

    @staticmethod
    def _stopped(stop_event: Any) -> bool:
        if stop_event is None:
            return False
        checker = getattr(stop_event, "is_set", None)
        try:
            if callable(checker):
                return bool(checker())
            return bool(stop_event()) if callable(stop_event) else bool(stop_event)
        except Exception:
            # A broken stop callback must not make a credential operation
            # retry indefinitely. Treat it as a stop request fail-closed.
            return True

    @staticmethod
    def _timeout(value: float | None, default: float = DEFAULT_KEYCHAIN_TIMEOUT_SECONDS) -> float:
        try:
            timeout = default if value is None else float(value)
        except (TypeError, ValueError):
            timeout = default
        return max(0.1, min(300.0, timeout))

    def _check_stop(self, stop_event: Any) -> None:
        if self._stopped(stop_event):
            raise KeychainOperationStopped("任务已停止，已中断 Keychain 操作")

    def _run(
        self,
        argv: list[str],
        *,
        input_text: str = "",
        stop_event: Any = None,
        timeout_seconds: float = DEFAULT_KEYCHAIN_TIMEOUT_SECONDS,
    ) -> Any:
        """Run one Keychain command with a bounded, cancellable wait."""
        self._check_stop(stop_event)
        if self.runner is subprocess.run:
            result = self._run_default_subprocess(
                argv,
                input_text=input_text,
                stop_event=stop_event,
                timeout_seconds=timeout_seconds,
            )
            self._check_stop(stop_event)
            return result

        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "check": False,
            "timeout": self._timeout(timeout_seconds),
        }
        if input_text:
            # Custom runners are retained for tests/embedders. Their input is
            # still supplied via stdin and never appended to argv.
            kwargs["input"] = input_text
        try:
            result = self._call_compatible_runner(argv, kwargs)
        except subprocess.TimeoutExpired as exc:
            raise KeychainUnavailable("Keychain 操作超时，已禁用 OAuth checkpoint") from exc
        except OSError as exc:
            raise KeychainUnavailable("macOS Keychain 不可用，已禁用 OAuth checkpoint") from exc
        self._check_stop(stop_event)
        return result

    def _call_compatible_runner(self, argv: list[str], kwargs: dict[str, Any]) -> Any:
        """Keep legacy injected runners working when they lack ``timeout``."""
        call_kwargs = dict(kwargs)
        try:
            signature = inspect.signature(self.runner)
        except (TypeError, ValueError):
            signature = None
        if signature is not None:
            parameters = signature.parameters.values()
            accepts_kwargs = any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters
            )
            if not accepts_kwargs:
                accepted = {
                    parameter.name
                    for parameter in signature.parameters.values()
                    if parameter.kind
                    in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
                }
                call_kwargs = {
                    name: value for name, value in call_kwargs.items() if name in accepted
                }
        return self.runner(argv, **call_kwargs)

    def _run_default_subprocess(
        self,
        argv: list[str],
        *,
        input_text: str,
        stop_event: Any,
        timeout_seconds: float,
    ) -> subprocess.CompletedProcess[str]:
        if input_text and _pty is not None and _termios is not None and fcntl is not None:
            return self._run_prompted_subprocess(
                argv,
                input_text=input_text,
                stop_event=stop_event,
                timeout_seconds=timeout_seconds,
            )

        stdin = subprocess.PIPE if input_text else subprocess.DEVNULL
        try:
            process = subprocess.Popen(
                argv,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            raise KeychainUnavailable("macOS Keychain 不可用，已禁用 OAuth checkpoint") from exc

        try:
            if input_text and process.stdin is not None:
                try:
                    process.stdin.write(input_text)
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    try:
                        process.stdin.close()
                    except OSError:
                        pass

            deadline = time.monotonic() + self._timeout(timeout_seconds)
            while True:
                self._check_stop_or_terminate(process, stop_event)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._terminate_process(process)
                    raise KeychainUnavailable("Keychain 操作超时，已禁用 OAuth checkpoint")
                try:
                    stdout, stderr = process.communicate(
                        timeout=min(remaining, _KEYCHAIN_POLL_SECONDS)
                    )
                    return subprocess.CompletedProcess(
                        argv,
                        process.returncode,
                        stdout,
                        stderr,
                    )
                except subprocess.TimeoutExpired:
                    continue
        finally:
            if process.poll() is None:
                self._terminate_process(process)
            for stream_name in ("stdout", "stderr", "stdin"):
                stream = getattr(process, stream_name, None)
                close = getattr(stream, "close", None)
                if callable(close):
                    try:
                        close()
                    except OSError:
                        pass

    def _run_prompted_subprocess(
        self,
        argv: list[str],
        *,
        input_text: str,
        stop_event: Any,
        timeout_seconds: float,
    ) -> subprocess.CompletedProcess[str]:
        """Answer ``security``'s /dev/tty password prompt without argv secrets."""
        master_fd, slave_fd = _pty.openpty()
        try:
            attrs = _termios.tcgetattr(slave_fd)
            attrs[3] &= ~(_termios.ECHO | _termios.ECHONL)
            _termios.tcsetattr(slave_fd, _termios.TCSANOW, attrs)
        except (OSError, _termios.error):
            pass

        def attach_terminal() -> None:
            os.setsid()
            fcntl.ioctl(slave_fd, _termios.TIOCSCTTY, 0)

        process = None
        streams: dict[int, str] = {master_fd: "tty"}
        output: dict[str, bytearray] = {
            "stdout": bytearray(),
            "stderr": bytearray(),
            "tty": bytearray(),
        }
        try:
            process = subprocess.Popen(
                argv,
                stdin=slave_fd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                close_fds=True,
                preexec_fn=attach_terminal,
            )
        except OSError as exc:
            raise KeychainUnavailable("macOS Keychain 不可用，已禁用 OAuth checkpoint") from exc
        finally:
            try:
                os.close(slave_fd)
            except OSError:
                pass

        pending = input_text.encode("utf-8", "replace")
        try:
            while pending:
                try:
                    written = os.write(master_fd, pending)
                except OSError as exc:
                    if exc.errno in (errno.EIO, errno.EBADF):
                        break
                    raise
                pending = pending[written:]

            for stream_name in ("stdout", "stderr"):
                stream = getattr(process, stream_name, None)
                if stream is not None:
                    streams[stream.fileno()] = stream_name
                    try:
                        os.set_blocking(stream.fileno(), False)
                    except (AttributeError, OSError):
                        pass
            try:
                os.set_blocking(master_fd, False)
            except (AttributeError, OSError):
                pass

            deadline = time.monotonic() + self._timeout(timeout_seconds)
            while streams:
                self._check_stop_or_terminate(process, stop_event)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._terminate_process(process)
                    raise KeychainUnavailable("Keychain 操作超时，已禁用 OAuth checkpoint")
                try:
                    ready, _, _ = select.select(
                        list(streams), [], [], min(remaining, _KEYCHAIN_POLL_SECONDS)
                    )
                except (OSError, ValueError):
                    ready = []
                for fd in ready:
                    stream_name = streams.get(fd)
                    if stream_name is None:
                        continue
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError as exc:
                        if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                            streams.pop(fd, None)
                        continue
                    if not chunk:
                        streams.pop(fd, None)
                        continue
                    bucket = output[stream_name]
                    if len(bucket) < 65536:
                        bucket.extend(chunk[: 65536 - len(bucket)])

            while process.poll() is None:
                self._check_stop_or_terminate(process, stop_event)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._terminate_process(process)
                    raise KeychainUnavailable("Keychain 操作超时，已禁用 OAuth checkpoint")
                time.sleep(min(remaining, _KEYCHAIN_POLL_SECONDS))
            return subprocess.CompletedProcess(
                argv,
                process.returncode,
                bytes(output["stdout"]).decode("utf-8", "replace"),
                bytes(output["stderr"]).decode("utf-8", "replace"),
            )
        finally:
            if process is not None and process.poll() is None:
                self._terminate_process(process)
            if process is not None:
                for stream_name in ("stdout", "stderr", "stdin"):
                    stream = getattr(process, stream_name, None)
                    close = getattr(stream, "close", None)
                    if callable(close):
                        try:
                            close()
                        except OSError:
                            pass
            for fd in tuple(streams):
                if fd != master_fd:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            try:
                os.close(master_fd)
            except OSError:
                pass

    def _check_stop_or_terminate(self, process: Any, stop_event: Any) -> None:
        if self._stopped(stop_event):
            self._terminate_process(process)
            raise KeychainOperationStopped("任务已停止，已中断 Keychain 操作")

    @staticmethod
    def _terminate_process(process: Any) -> None:
        """Terminate and reap a helper, escalating to kill if necessary."""
        try:
            if process.poll() is not None:
                return
        except Exception:
            pass
        try:
            process.terminate()
        except Exception:
            pass
        try:
            process.wait(timeout=0.5)
            return
        except Exception:
            pass
        try:
            process.kill()
        except Exception:
            pass
        try:
            process.wait(timeout=0.5)
        except Exception:
            pass


__all__ = [
    "CheckpointDisabled",
    "CheckpointError",
    "DEFAULT_KEYCHAIN_TIMEOUT_SECONDS",
    "KEY_SERVICE",
    "KeychainOperationStopped",
    "KeychainUnavailable",
    "SecurityKeyProvider",
]
