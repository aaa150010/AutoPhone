"""Compatibility wrapper around the shared mailbox OTP service for Free runs."""

from __future__ import annotations

import time
import threading
import math
import inspect
from typing import Any, Callable, Mapping

# Keep the broker window in sync with the Camoufox deadline adapter without
# importing that module here (the two modules load each other).
MANUAL_OTP_WINDOW_SECONDS = 300
_DEADLINE_CONTROLLER_MISSING = object()


def _deadline_controller_call(
    controller: Any,
    name: str,
    *args: Any,
    default: Any = _DEADLINE_CONTROLLER_MISSING,
) -> Any:
    """Invoke optional deadline hooks without masking the mailbox result."""
    if controller is None:
        return default
    try:
        method = getattr(controller, name, None)
        if not callable(method):
            return default
        return method(*args)
    except Exception:
        return default


def _deadline_controller_bool(controller: Any, name: str) -> bool:
    value = _deadline_controller_call(controller, name, default=False)
    try:
        return bool(value)
    except Exception:
        return False


def _stop_signal(value: Any) -> bool:
    """Read Event, callback, or boolean stop inputs consistently."""
    if value is None:
        return False
    try:
        checker = getattr(value, "is_set", None)
        if callable(checker):
            return bool(checker())
        return bool(value()) if callable(value) else bool(value)
    except Exception:
        return True

try:
    from .free_register_common import FreeRegisterError
    from .mailbox_otp_service import (
        DEFAULT_FREE_MAILBOX_PROXY,
        MailboxOtpError,
        MailboxOtpService,
        normalize_network_policy,
    )
    from .free_timing import TimingCallback
    from .manual_verification_runtime import ManualVerificationBroker, ManualVerificationError, wait_with_manual_fallback
    from .mailbox_url_runtime import MailboxResponse
except ImportError:
    from free_register_common import FreeRegisterError  # type: ignore[no-redef]
    from mailbox_otp_service import (  # type: ignore[no-redef]
        DEFAULT_FREE_MAILBOX_PROXY,
        MailboxOtpError,
        MailboxOtpService,
        normalize_network_policy,
    )
    from free_timing import TimingCallback  # type: ignore[no-redef]
    from manual_verification_runtime import ManualVerificationBroker, ManualVerificationError, wait_with_manual_fallback  # type: ignore[no-redef]
    from mailbox_url_runtime import MailboxResponse  # type: ignore[no-redef]


class MailboxUrlOtpProvider:
    """Keep the historic provider signature while isolating mailbox networking."""

    def __init__(
        self,
        mailbox_url: str,
        proxy: str = "",
        *,
        timeout: int,
        log_fn: Callable[..., Any] | None = None,
        task_id: str = "",
        stage_fn: Callable[[str, str], None] | None = None,
        network_mode: str = "local_proxy",
        mailbox_proxy_url: str = DEFAULT_FREE_MAILBOX_PROXY,
        request_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
        poll_interval_seconds: float = 1.0,
        fetcher: Callable[[str], MailboxResponse] | None = None,
        session: Any | None = None,
        session_factory: Callable[..., Any] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        now_fn: Callable[[], float] = time.time,
        monotonic_fn: Callable[[], float] = time.monotonic,
        manual_broker: ManualVerificationBroker | None = None,
        manual_generation_getter: Callable[[str, str], int] | None = None,
        deadline_controller: Any | None = None,
        verification_state_fn: Callable[[str, Mapping[str, Any] | None], Any] | None = None,
        timing_fn: TimingCallback | None = None,
        sample_context: Mapping[str, Any] | None = None,
    ) -> None:
        # ``proxy`` is the former registration-proxy argument. It is retained
        # for callable compatibility and deliberately never used for mailbox IO.
        self.registration_proxy = str(proxy or "")
        self.network_policy = normalize_network_policy(
            mode=network_mode,
            proxy_url=mailbox_proxy_url,
            retries=request_retries,
            backoff_seconds=retry_backoff_seconds,
            request_timeout_seconds=min(15, max(3, int(timeout))),
        )
        self.service = MailboxOtpService(
            mailbox_url,
            timeout_seconds=timeout,
            poll_interval_seconds=poll_interval_seconds,
            network_policy=self.network_policy,
            log_fn=log_fn,
            task_id=task_id,
            stage_fn=stage_fn,
            fetcher=fetcher,
            session=session,
            session_factory=session_factory,
            sleep_fn=sleep_fn,
            now_fn=now_fn,
            monotonic_fn=monotonic_fn,
            timing_fn=timing_fn,
            sample_scope="free",
            sample_context=sample_context,
        )
        # Compatibility attributes used by focused tests and older helpers.
        self.client = self.service.client
        self.state = self.service.state
        self.timeout = self.service.timeout_seconds
        self.log_fn = log_fn
        self.now_fn = now_fn
        self.monotonic_fn = monotonic_fn
        self.task_id = str(task_id or "")
        self.stage_fn = stage_fn
        self.manual_broker = manual_broker
        self.manual_generation_getter = manual_generation_getter
        self.deadline_controller = deadline_controller
        self.verification_state_fn = verification_state_fn
        self.timing_fn = timing_fn
        # Task-scoped and memory-only. It is set only after the broker has
        # actually returned a manually submitted value to this provider.
        self._manual_takeover = False

    def _set_verification_state(
        self,
        stage_code: str,
        phase: str,
        opened_at: Any,
        deadline_at: Any,
    ) -> None:
        callback = self.verification_state_fn
        if not callable(callback):
            return
        try:
            payload = {
                "phase": str(phase or "")[:24],
                "stage": str(stage_code or "")[:100],
                "opened_at": max(0, int(opened_at or 0)),
                "deadline_at": max(0, int(deadline_at or 0)),
            }
            callback(self.task_id, payload)
        except Exception:
            pass

    def _clear_verification_state(self) -> None:
        callback = self.verification_state_fn
        if callable(callback):
            try:
                callback(self.task_id, None)
            except Exception:
                pass

    @staticmethod
    def _label(stage_code: str) -> str:
        if "twofa" in stage_code:
            return "等待 Free 账号 2FA 邮箱验证码"
        if "existing_login" in stage_code:
            return "等待已有 Free 账号登录验证码"
        if "live" in stage_code:
            return "等待 Free 深度测活邮箱验证码"
        return "等待 Free 邮箱验证码"

    def mark_sent(self, stage_code: str = "free_email_otp_wait") -> None:
        self.service.mark_sent(stage_code)

    def prepare(
        self,
        stage_code: str = "free_email_otp_wait",
        *,
        force_snapshot: bool = False,
        notify_stage: bool = True,
    ) -> None:
        """Capture the baseline before browser/protocol actions can send a code."""
        self.service.prepare(
            stage_code,
            force_snapshot=force_snapshot,
            notify_stage=notify_stage,
        )

    def wait_code(
        self,
        _email: str,
        stage_code: str = "free_email_otp_wait",
        *,
        resend_fn: Callable[[], None] | None = None,
        resend_after_seconds: float = 12.0,
        stop_requested: Callable[[], bool] | None = None,
        deadline_monotonic: float | None = None,
    ) -> str:
        manual_completed = threading.Event()
        manual_capable = bool(self.manual_broker is not None and self.task_id)
        manual_priority = bool(
            self._manual_takeover
            and str(stage_code or "").casefold() in {
                "free_password_otp_wait",
                "free_twofa_enroll",
            }
        )
        manual_outcome = "cleanup"
        timeout = max(1, int(self.timeout))
        requested_deadline: float | None = None
        if deadline_monotonic is not None:
            try:
                candidate_deadline = float(deadline_monotonic)
                if not math.isfinite(candidate_deadline):
                    raise ValueError
                requested_deadline = candidate_deadline
            except (TypeError, ValueError):
                requested_deadline = None
        if requested_deadline is not None:
            remaining = requested_deadline - self.monotonic_fn()
            if remaining <= 0:
                if not manual_capable:
                    raise FreeRegisterError(
                        stage_code,
                        self._label(stage_code),
                        "邮箱验证码等待已达到调用方时间预算",
                        retryable=True,
                        error_code=f"{stage_code}_mailbox_code_timeout",
                    )
                # A worker can start a few milliseconds after the browser
                # watchdog observes the deadline. Keep the task eligible for
                # its bounded manual fallback instead of losing the prompt in
                # that scheduling gap. ``manual_opened`` will make this pause
                # visible to the shared controller as soon as the broker opens.
                pause_result = _deadline_controller_call(
                    self.deadline_controller, "request_manual_handoff"
                )
                if pause_result is _DEADLINE_CONTROLLER_MISSING:
                    _deadline_controller_call(self.deadline_controller, "pause_manual")
                timeout = 1
            else:
                # Round up a fractional remainder for one final polling turn;
                # the absolute deadline predicate below still stops it exactly.
                timeout = max(1, min(timeout, int(math.ceil(remaining))))
        _deadline_controller_call(self.deadline_controller, "begin_otp_wait")
        automatic_opened_at = int(self.now_fn())
        automatic_deadline_at = automatic_opened_at + timeout
        self._set_verification_state(
            stage_code,
            "automatic",
            automatic_opened_at,
            automatic_deadline_at,
        )

        def automatic_stop_requested() -> bool:
            if manual_completed.is_set():
                return True
            if _stop_signal(stop_requested):
                return True
            controller = self.deadline_controller
            paused = _deadline_controller_bool(controller, "is_paused")
            if (
                requested_deadline is not None
                and self.monotonic_fn() >= requested_deadline
                and not paused
            ):
                if manual_capable:
                    # Stop only the automatic waiter. The manual fallback's
                    # own stop predicate remains false, so it can open and
                    # wait for the operator even when the active budget just
                    # reached zero.
                    pause_result = _deadline_controller_call(
                        controller, "request_manual_handoff"
                    )
                    if pause_result is _DEADLINE_CONTROLLER_MISSING:
                        _deadline_controller_call(controller, "pause_manual")
                    return False
                return True
            return False

        def manual_selected() -> None:
            nonlocal manual_outcome
            # Stop the automatic service before it reaches its own timeout;
            # a manual success must not create a parser-miss sample later.
            manual_completed.set()
            manual_outcome = "submitted"
            self._manual_takeover = True
            self._log_manual_selected(stage_code)

        def caller_stop_requested() -> bool:
            return _stop_signal(stop_requested)

        def manual_opened(prompt: Mapping[str, Any]) -> None:
            pause_result = _deadline_controller_call(
                self.deadline_controller, "manual_prompt_opened"
            )
            if pause_result is _DEADLINE_CONTROLLER_MISSING:
                _deadline_controller_call(self.deadline_controller, "pause_manual")
            self._set_verification_state(
                stage_code,
                "manual",
                prompt.get("opened_at"),
                prompt.get("deadline_at"),
            )

        def manual_finished(outcome: str) -> None:
            _deadline_controller_call(
                self.deadline_controller, "resume_manual", outcome
            )

        def deadline_reached() -> bool:
            # An explicit task stop takes precedence over the local deadline
            # so callers retain the stable ``free_run_stop`` node.
            externally_stopped = _stop_signal(stop_requested)
            controller = self.deadline_controller
            if _deadline_controller_bool(controller, "is_paused"):
                return False
            remaining = _deadline_controller_call(controller, "remaining")
            if remaining is not _DEADLINE_CONTROLLER_MISSING:
                try:
                    candidate_remaining = float(remaining)
                    if math.isfinite(candidate_remaining):
                        return not externally_stopped and candidate_remaining <= 0
                except (TypeError, ValueError, OverflowError):
                    pass
            return (
                requested_deadline is not None
                and self.monotonic_fn() >= requested_deadline
                and not externally_stopped
            )

        def automatic_wait() -> Any:
            waiter = getattr(self.service, "wait_code", None)
            if not callable(waiter):
                raise MailboxOtpError(
                    "mailbox_waiter_missing",
                    "邮箱取件服务缺少 wait_code 方法",
                    retryable=False,
                )
            kwargs = {
                "resend_fn": resend_fn,
                "resend_after_seconds": resend_after_seconds,
                "stop_requested": automatic_stop_requested,
                "deadline_monotonic": requested_deadline,
            }
            try:
                signature = inspect.signature(waiter)
            except (TypeError, ValueError):
                try:
                    signature = inspect.signature(getattr(waiter, "__call__"))
                except (AttributeError, TypeError, ValueError):
                    # Keep the one-shot positional legacy form when an
                    # adapter intentionally hides its signature.
                    return waiter(stage_code)
            accepts_var_kwargs = any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            )
            filtered_kwargs = kwargs if accepts_var_kwargs else {
                key: value for key, value in kwargs.items()
                if key in signature.parameters
            }
            # ``wait_code(email)`` is still used by a few legacy test and
            # integration adapters. Try each compatible call shape via
            # ``Signature.bind`` so keyword-only and opaque adapters work
            # without catching a TypeError raised inside provider code itself.
            candidates = (
                ((stage_code,), filtered_kwargs),
                ((), {"stage_code": stage_code, **filtered_kwargs}),
                ((), filtered_kwargs),
                ((stage_code,), {}),
                ((), {"stage_code": stage_code}),
                ((), {}),
            )
            for call_args, call_kwargs in candidates:
                try:
                    signature.bind(*call_args, **call_kwargs)
                except TypeError:
                    continue
                value = waiter(*call_args, **call_kwargs)
                break
            else:
                raise TypeError("unsupported mailbox waiter signature")
            if _stop_signal(stop_requested) and not manual_completed.is_set():
                raise MailboxOtpError(
                    "mailbox_wait_stopped",
                    "邮箱验证码等待已停止",
                    retryable=False,
                )
            return value
        try:
            if self.manual_broker is not None and self.task_id:
                try:
                    generation = int(
                        self.manual_generation_getter(self.task_id, stage_code)
                        if callable(self.manual_generation_getter)
                        else 0
                    )
                except (TypeError, ValueError):
                    generation = 0
                if manual_priority:
                    prompt = self.manual_broker.open(
                        self.task_id,
                        "email_otp",
                        generation,
                        window_seconds=MANUAL_OTP_WINDOW_SECONDS,
                    )
                    manual_opened(prompt)
                    outcome = "expired"
                    try:
                        value = self.manual_broker.wait(
                            self.task_id,
                            "email_otp",
                            generation,
                            stop_event=caller_stop_requested,
                            timeout_seconds=MANUAL_OTP_WINDOW_SECONDS,
                        )
                        outcome = "submitted"
                        manual_selected()
                        return str(value or "").strip()
                    finally:
                        manual_finished(outcome)
                manual_outcome = "expired"
                try:
                    return str(wait_with_manual_fallback(
                        automatic_wait,
                        broker=self.manual_broker,
                        task_id=self.task_id,
                        input_kind="email_otp",
                        generation=generation,
                        # Use the same combined predicate for both automatic
                        # and manual phases. Passing only the caller's stop
                        # event here used to leave the manual broker alive
                        # after the Camoufox registration deadline expired.
                        stop_event=automatic_stop_requested,
                        automatic_timeout_seconds=timeout,
                        # The manual window has its own bounded lifetime. A
                        # Camoufox deadline controller pauses the registration
                        # budget while this prompt is visible.
                        manual_timeout_seconds=MANUAL_OTP_WINDOW_SECONDS,
                        on_automatic_unmatched=lambda cause: self.service.record_parser_sample(
                            str(self.service.diagnostic().get("reason") or getattr(cause, "code", "") or "mailbox_code_timeout"),
                            self.service.diagnostic(),
                        ),
                        on_manual_opened=manual_opened,
                        on_manual_selected=manual_selected,
                    ) or "").strip()
                finally:
                    manual_finished(manual_outcome)
            return automatic_wait()
        except MailboxOtpError as exc:
            if exc.code == "mailbox_wait_stopped":
                if deadline_reached():
                    raise FreeRegisterError(
                        stage_code,
                        self._label(stage_code),
                        "邮箱验证码等待已达到调用方时间预算",
                        retryable=True,
                        error_code=f"{stage_code}_mailbox_code_timeout",
                    ) from exc
                raise FreeRegisterError(
                    "free_run_stop",
                    "停止 Free 注册",
                    "任务已请求停止，邮箱验证码轮询已中断",
                    retryable=False,
                    error_code="free_run_stop",
                ) from exc
            raise FreeRegisterError(
                stage_code,
                self._label(stage_code),
                str(exc),
                error_code=f"{stage_code}_{exc.code}",
                retryable=exc.retryable,
                provider_status=exc.status,
            ) from exc
        except ManualVerificationError as exc:
            if exc.code == "stopped" and deadline_reached():
                raise FreeRegisterError(
                    stage_code,
                    self._label(stage_code),
                    "邮箱验证码等待已达到调用方时间预算",
                    retryable=True,
                    error_code=f"{stage_code}_mailbox_code_timeout",
                ) from exc
            raise FreeRegisterError(
                stage_code,
                self._label(stage_code),
                str(exc),
                error_code=f"{stage_code}_manual_{exc.code}",
                retryable=exc.code in {"expired", "stopped"},
            ) from exc
        finally:
            manual_completed.set()
            manual_finished("cleanup")
            _deadline_controller_call(self.deadline_controller, "end_otp_wait")
            self._clear_verification_state()

    def _log_manual_selected(self, stage_code: str) -> None:
        if callable(self.log_fn):
            try:
                self.log_fn(
                    f"[人工邮箱验证码/{stage_code}] 已接收当前任务的人工验证码",
                    "info",
                    task_id=self.task_id,
                    node_code=stage_code,
                    outcome="manual_submitted",
                )
            except TypeError:
                try:
                    self.log_fn(f"[人工邮箱验证码/{stage_code}] 已接收当前任务的人工验证码", "info")
                except Exception:
                    pass
            except Exception:
                pass

    def diagnostic(self) -> dict[str, Any]:
        return self.service.diagnostic()

    def close(self) -> None:
        self.service.close()


def build_free_mailbox_otp_provider(
    mailbox_url: str,
    registration_proxy: str,
    config: Mapping[str, Any],
    *,
    log_fn: Callable[..., Any] | None = None,
    task_id: str = "",
    stage_fn: Callable[[str, str], None] | None = None,
    batch_id: str = "",
    workflow: str = "free_register",
    driver: str = "",
) -> MailboxUrlOtpProvider:
    """Create a Free provider without ever borrowing the registration proxy."""
    return MailboxUrlOtpProvider(
        mailbox_url,
        registration_proxy,
        timeout=int(config.get("email_code_timeout") or 90),
        log_fn=log_fn,
        task_id=task_id,
        stage_fn=stage_fn,
        network_mode=str(config.get("mailbox_network_mode") or "local_proxy"),
        mailbox_proxy_url=str(config.get("mailbox_proxy_url") or DEFAULT_FREE_MAILBOX_PROXY),
        request_retries=int(config.get("mailbox_request_retries", 3)),
        retry_backoff_seconds=float(config.get("mailbox_retry_backoff_seconds", 1.0)),
        manual_broker=config.get("_manual_verification_broker"),
        manual_generation_getter=config.get("_manual_generation_getter"),
        deadline_controller=config.get("_deadline_controller"),
        verification_state_fn=config.get("_mailbox_verification_state_fn"),
        timing_fn=config.get("_timing_substep"),
        sample_context={
            "task_id": task_id,
            "batch_id": batch_id,
            "workflow": workflow,
            "driver": driver or config.get("driver") or "unknown",
            "chain": "free_rebind" if workflow == "free_rebind" else "free",
        },
    )


__all__ = ["MailboxUrlOtpProvider", "build_free_mailbox_otp_provider"]
