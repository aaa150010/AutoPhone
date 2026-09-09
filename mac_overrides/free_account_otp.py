"""Bounded account OTP callback execution for the Free browser flows.

Split out of ``free_account_service.py``; the original module re-exports
``_await_account_otp_callback`` (and its small helpers) for compatibility.
"""

from __future__ import annotations

import asyncio
import inspect
import math
import sys
import threading
import time
from typing import Any, Callable

try:
    from .free_register_common import FreeRegisterError, clean
except ImportError:  # pragma: no cover - top-level recovery import
    from free_register_common import FreeRegisterError, clean  # type: ignore[no-redef]


def _note_stderr(where: str, exc: BaseException) -> None:
    """Last-resort stderr note for swallowed best-effort OTP wait cleanup."""
    try:
        print(f"[free_account_otp/{where}] {type(exc).__name__}", file=sys.stderr)
    except Exception:
        return


def _otp_stop_requested(value: Any) -> bool:
    """Read an OTP stop signal without assuming an Event/callback shape."""
    if value is None:
        return False
    try:
        checker = getattr(value, "is_set", None)
        if callable(checker):
            return bool(checker())
        return bool(value()) if callable(value) else bool(value)
    except Exception:
        # A broken stop callback must not leave a blocking mailbox worker alive.
        return True


def _invoke_staged_otp_callback(
    callback: Callable[..., Any],
    stage_code: str,
    *,
    stop_requested: Callable[[], bool],
    deadline_monotonic: float | None,
    deadline_controller: Any | None,
) -> Any:
    """Invoke old and current OTP callback signatures exactly once."""
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        try:
            signature = inspect.signature(getattr(callback, "__call__"))
        except (AttributeError, TypeError, ValueError):
            # An opaque legacy adapter cannot be safely probed by trial calls:
            # a TypeError may come from its side effects rather than binding.
            # The historic positional stage form is the least surprising
            # one-shot fallback; daemon-worker cancellation remains bounded.
            return callback(stage_code)

    candidates = (
        ((stage_code,), {
            "stop_requested": stop_requested,
            "deadline_monotonic": deadline_monotonic,
            "deadline_controller": deadline_controller,
        }),
        ((stage_code,), {
            "stop_requested": stop_requested,
            "deadline_monotonic": deadline_monotonic,
        }),
        ((stage_code,), {"stop_requested": stop_requested}),
        ((stage_code,), {
            "deadline_monotonic": deadline_monotonic,
            "deadline_controller": deadline_controller,
        }),
        ((stage_code,), {"deadline_monotonic": deadline_monotonic}),
        ((stage_code,), {"deadline_controller": deadline_controller}),
        ((stage_code,), {}),
        ((), {
            "stop_requested": stop_requested,
            "deadline_monotonic": deadline_monotonic,
            "deadline_controller": deadline_controller,
        }),
        ((), {
            "stop_requested": stop_requested,
            "deadline_monotonic": deadline_monotonic,
        }),
        ((), {"stop_requested": stop_requested}),
        ((), {
            "deadline_monotonic": deadline_monotonic,
            "deadline_controller": deadline_controller,
        }),
        ((), {"deadline_monotonic": deadline_monotonic}),
        ((), {"deadline_controller": deadline_controller}),
        ((), {}),
    )
    for args, original_kwargs in candidates:
        kwargs = {
            key: value for key, value in original_kwargs.items()
            if value is not None
        }
        try:
            signature.bind(*args, **kwargs)
        except TypeError:
            continue
        return callback(*args, **kwargs)
    raise TypeError("unsupported OTP callback signature")


async def _await_account_otp_callback(
    callback: Callable[..., Any],
    stage_code: str,
    *,
    deadline_monotonic: float | None = None,
    deadline_controller: Any | None = None,
    stop_requested: Any = None,
) -> Any:
    """Run a blocking account OTP callback with bounded cancellation.

    ``asyncio.to_thread`` cannot stop its executor job when the surrounding
    page flow is cancelled.  A daemon worker plus a cooperative stop event
    keeps the event loop and browser-pool shutdown bounded while preserving
    the callback's legacy synchronous/async signatures.
    """
    loop = asyncio.get_running_loop()
    result: asyncio.Future[Any] = loop.create_future()
    worker_stop = threading.Event()
    end_lock = threading.Lock()
    wait_ended = False
    pending_async_task: asyncio.Task[Any] | None = None
    pending_raw_awaitable: Any = None
    awaitable_lock = threading.Lock()
    abandoned = False

    _MISSING = object()

    def controller_call(name: str, *args: Any, default: Any = _MISSING) -> Any:
        """Read an optional deadline hook without making it a failure node."""
        controller = deadline_controller
        if controller is None:
            return default
        try:
            method = getattr(controller, name, None)
            if not callable(method):
                return default
            return method(*args)
        except Exception:
            # Recovered integrations may expose only part of the controller,
            # or an old implementation may raise while being torn down. The
            # absolute deadline and worker stop path remain authoritative.
            return default

    def controller_bool(name: str) -> bool:
        value = controller_call(name, default=False)
        try:
            return bool(value)
        except Exception:
            return False

    controller_call("begin_otp_wait")

    def end_once() -> None:
        nonlocal wait_ended
        with end_lock:
            if wait_ended:
                return
            wait_ended = True
        controller_call("end_otp_wait")

    def requested() -> bool:
        return worker_stop.is_set() or _otp_stop_requested(stop_requested)

    def consume_exception(future: asyncio.Future[Any]) -> None:
        if not future.cancelled():
            try:
                # Consume the exception so asyncio does not log
                # "exception was never retrieved"; CancelledError included.
                future.exception()
            except BaseException:
                pass

    def discard_awaitable(value: Any) -> None:
        """Close/cancel an async callback result that the caller abandoned."""
        if not inspect.isawaitable(value):
            return
        close = getattr(value, "close", None)
        if callable(close):
            try:
                close()
                return
            except Exception as exc:
                # Best-effort cleanup of a closeable wait handle.
                _note_stderr("wait_handle_close", exc)
        cancel = getattr(value, "cancel", None)
        if callable(cancel):
            try:
                cancel()
            except Exception as exc:
                # Best-effort cancellation must not mask the stop request.
                _note_stderr("wait_handle_cancel", exc)

    result.add_done_callback(consume_exception)

    def publish(kind: str, value: Any) -> None:
        if abandoned or result.done():
            if kind == "result":
                discard_awaitable(value)
            return
        if kind == "error":
            result.set_exception(value)
        else:
            result.set_result(value)
        end_once()

    async def resolve_awaitable(value: Any) -> Any:
        current = value
        for _ in range(16):
            if not inspect.isawaitable(current):
                return current
            current = await current
        discard_awaitable(current)
        raise TypeError("OTP callback returned too many nested awaitables")

    def finish_async_task(task: asyncio.Task[Any], original: Any) -> None:
        nonlocal pending_async_task
        if pending_async_task is task:
            pending_async_task = None
        if task.cancelled():
            discard_awaitable(original)
            if not abandoned:
                publish("error", asyncio.CancelledError())
            return
        try:
            value = task.result()
        except BaseException as exc:
            publish("error", exc)
        else:
            publish("result", value)

    def take_raw_awaitable() -> Any:
        nonlocal pending_raw_awaitable
        with awaitable_lock:
            value = pending_raw_awaitable
            pending_raw_awaitable = None
        return value

    def start_awaitable() -> None:
        nonlocal pending_async_task
        value = take_raw_awaitable()
        if value is None:
            return
        if abandoned or result.done():
            discard_awaitable(value)
            return
        resolver = resolve_awaitable(value)
        try:
            task = loop.create_task(resolver)
        except BaseException as exc:
            discard_awaitable(resolver)
            discard_awaitable(value)
            publish("error", exc)
            return
        pending_async_task = task
        task.add_done_callback(
            lambda completed, original=value: finish_async_task(completed, original)
        )

    def worker() -> None:
        nonlocal pending_raw_awaitable
        try:
            value = _invoke_staged_otp_callback(
                callback,
                stage_code,
                stop_requested=requested,
                deadline_monotonic=deadline_monotonic,
                deadline_controller=deadline_controller,
            )
        except BaseException as exc:
            kind, value = "error", exc
        else:
            if inspect.isawaitable(value):
                with awaitable_lock:
                    pending_raw_awaitable = value
                try:
                    loop.call_soon_threadsafe(start_awaitable)
                except RuntimeError:
                    # The owning loop may be closing after cancellation. Close
                    # the coroutine here so it cannot be garbage-collected as
                    # an un-awaited result.
                    discard_awaitable(take_raw_awaitable())
                return
            kind = "result"
        try:
            loop.call_soon_threadsafe(publish, kind, value)
        except RuntimeError as exc:
            # The owning loop may be closing after cancellation. The daemon
            # worker has no useful result to deliver in that state.  Leave a
            # credential-free stderr trace because this thread has no store
            # or logger wiring.
            stage_label = clean(stage_code, 32) or "otp_wait"
            print(
                f"[Free账号OTP/free_account_otp_worker] 阶段 {stage_label} "
                f"结果回投失败，事件循环已关闭（{type(exc).__name__}）",
                file=sys.stderr,
            )

    threading.Thread(
        target=worker,
        name=f"free-account-otp-{clean(stage_code, 32) or 'wait'}",
        daemon=True,
    ).start()

    def budget_state() -> tuple[float | None, bool, bool, bool, bool]:
        """Return remaining budget and pause flags from the shared controller."""
        controller = deadline_controller
        paused = prompt = handoff = grace = False
        if controller is not None:
            paused = controller_bool("is_paused")
            prompt = controller_bool("manual_prompt_active")
            handoff = controller_bool("manual_handoff_active")
            grace = controller_bool("manual_submission_grace_active")
            remaining_value = controller_call("remaining")
            if remaining_value is not _MISSING:
                try:
                    numeric = float(remaining_value)
                    if math.isfinite(numeric):
                        return numeric, paused, prompt, handoff, grace
                except Exception as exc:
                    # A missing remaining-budget probe falls back to the coarse deadline.
                    _note_stderr("budget_probe", exc)
        if deadline_monotonic is None:
            return None, paused, prompt, handoff, grace
        try:
            fallback = float(deadline_monotonic) - time.monotonic()
        except (TypeError, ValueError, OverflowError):
            fallback = None
        return fallback, paused, prompt, handoff, grace

    async def await_cleanup(value: Any, timeout: float) -> None:
        """Drain a shielded child while tolerating repeated outer cancels."""
        if not isinstance(value, asyncio.Future):
            try:
                value = asyncio.ensure_future(value)
            except BaseException:
                return
        end = loop.time() + max(0.0, float(timeout))
        while not value.done():
            remaining = end - loop.time()
            if remaining <= 0:
                return
            try:
                await asyncio.wait_for(asyncio.shield(value), timeout=remaining)
            except asyncio.TimeoutError:
                return
            except asyncio.CancelledError:
                current = asyncio.current_task()
                uncancel = getattr(current, "uncancel", None)
                if callable(uncancel):
                    try:
                        while int(getattr(current, "cancelling", lambda: 0)() or 0) > 0:
                            uncancel()
                    except Exception as exc:
                        # Uncancel bookkeeping must not break the OTP wait loop.
                        _note_stderr("task_uncancel", exc)
                continue
            except BaseException:
                return

    async def stop_and_drain() -> None:
        nonlocal abandoned
        if abandoned:
            end_once()
            return
        abandoned = True
        worker_stop.set()
        discard_awaitable(take_raw_awaitable())
        async_task = pending_async_task
        if async_task is not None and not async_task.done():
            async_task.cancel()
        if async_task is not None:
            await await_cleanup(async_task, 0.5)
            if not async_task.done():
                # A coroutine may deliberately defer its first cancellation
                # while unwinding network cleanup. Give it one final bounded
                # cancellation before releasing the browser flow.
                async_task.cancel()
                await await_cleanup(async_task, 0.25)
        if result.done():
            try:
                discard_awaitable(result.result())
            except BaseException:
                # result.result() may raise CancelledError during teardown;
                # discard already closed what it could.
                pass
            end_once()
            return
        await await_cleanup(result, 1.5)
        # A worker can publish a coroutine during the drain window. It is no
        # longer useful after cancellation/timeout, so consume and close it.
        if result.done():
            try:
                discard_awaitable(result.result())
            except BaseException:
                pass
        end_once()

    handoff_started: float | None = None
    try:
        while True:
            if _otp_stop_requested(stop_requested):
                await stop_and_drain()
                raise FreeRegisterError(
                    "free_run_stop",
                    "停止 Free 注册",
                    "任务已请求停止，邮箱验证码轮询已中断",
                    retryable=False,
                    error_code="free_run_stop",
                )
            # A callback result published at the deadline still belongs to
            # this attempt and must be consumed before checking the clock.
            # An explicit stop signal takes precedence even if the cooperative
            # worker returned an empty value while it was being interrupted.
            if result.done():
                if _otp_stop_requested(stop_requested):
                    await stop_and_drain()
                    raise FreeRegisterError(
                        "free_run_stop",
                        "停止 Free 注册",
                        "任务已请求停止，邮箱验证码轮询已中断",
                        retryable=False,
                        error_code="free_run_stop",
                    )
                end_once()
                value = await asyncio.shield(result)
                if _otp_stop_requested(stop_requested):
                    await stop_and_drain()
                    raise FreeRegisterError(
                        "free_run_stop",
                        "停止 Free 注册",
                        "任务已请求停止，邮箱验证码轮询已中断",
                        retryable=False,
                        error_code="free_run_stop",
                    )
                return value

            remaining, paused, prompt, handoff, grace = budget_state()
            controller = deadline_controller
            if handoff and handoff_started is None:
                handoff_remaining = controller_call("manual_handoff_remaining")
                try:
                    handoff_remaining = float(handoff_remaining)
                    if not math.isfinite(handoff_remaining):
                        raise ValueError
                except (TypeError, ValueError, OverflowError):
                    handoff_remaining = 2.0
                handoff_started = time.monotonic() - max(0.0, 2.0 - handoff_remaining)
            if (
                remaining is not None
                and remaining <= 0
                and not (paused or prompt or handoff or grace)
            ):
                # Let a cooperative provider open its manual prompt during a
                # short scheduling handoff at the exact deadline.
                request_result = controller_call("request_manual_handoff")
                if request_result is not _MISSING and handoff_started is None:
                    handoff_started = time.monotonic()
                    paused = True
                    handoff = True
                else:
                    await stop_and_drain()
                    if paused:
                        controller_call("resume_manual", "timeout")
                    raise FreeRegisterError(
                        stage_code,
                        "等待邮箱验证码",
                        "邮箱验证码等待已达到调用方时间预算",
                        retryable=True,
                        error_code=f"{stage_code}_mailbox_code_timeout",
                    )
            if handoff_started is not None and not prompt and not grace:
                if time.monotonic() - handoff_started >= 2.0:
                    await stop_and_drain()
                    if paused:
                        controller_call("resume_manual", "timeout")
                    raise FreeRegisterError(
                        stage_code,
                        "等待邮箱验证码",
                        "邮箱验证码等待已达到调用方时间预算",
                        retryable=True,
                        error_code=f"{stage_code}_mailbox_code_timeout",
                    )
            wait_timeout = 0.25
            if remaining is not None and not (paused or prompt or handoff or grace):
                wait_timeout = min(wait_timeout, max(0.01, remaining))
            try:
                value = await asyncio.wait_for(asyncio.shield(result), timeout=wait_timeout)
                if _otp_stop_requested(stop_requested):
                    await stop_and_drain()
                    raise FreeRegisterError(
                        "free_run_stop",
                        "停止 Free 注册",
                        "任务已请求停止，邮箱验证码轮询已中断",
                        retryable=False,
                        error_code="free_run_stop",
                    )
                return value
            except asyncio.TimeoutError:
                continue
    except asyncio.CancelledError:
        await stop_and_drain()
        raise
    except BaseException:
        # Controller/query failures must not strand the daemon mailbox worker.
        await stop_and_drain()
        raise
    finally:
        end_once()


__all__ = ["_await_account_otp_callback", "_invoke_staged_otp_callback", "_otp_stop_requested"]
