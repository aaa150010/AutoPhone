"""Credential-free, task-scoped manual verification input broker."""

from __future__ import annotations

from dataclasses import dataclass
import re
import threading
import time
from typing import Any, Callable


INPUT_KINDS = frozenset({"email_otp", "sms_otp", "totp"})
_DIGITS = re.compile(r"^[0-9]+$")
DEFAULT_WINDOW_SECONDS = 300
MAX_WINDOW_SECONDS = 300
TOMBSTONE_RETENTION_SECONDS = 300


class ManualVerificationError(RuntimeError):
    """Stable error carrying an HTTP-like status without exposing a code."""

    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(message)
        self.code = str(code)
        self.status = int(status)


class ManualVerificationStopped(ManualVerificationError):
    def __init__(self) -> None:
        super().__init__("stopped", "任务已停止，人工验证码输入已取消", 410)


@dataclass
class _Prompt:
    task_id: str
    input_kind: str
    generation: int
    opened_at: float
    deadline_at: float
    submitted: str = ""
    consumed: bool = False
    cancelled: bool = False
    cancel_reason: str = ""


@dataclass(frozen=True)
class _PromptTombstone:
    """Short-lived context used to classify late submissions without a code."""

    input_kind: str
    generation: int
    reason: str
    expires_at: float


def normalize_input_kind(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in INPUT_KINDS else ""


def validate_code(input_kind: Any, code: Any) -> str:
    kind = normalize_input_kind(input_kind)
    value = str(code or "").strip()
    if not kind:
        raise ManualVerificationError("invalid_input_kind", "验证码类型不受支持", 400)
    if not _DIGITS.fullmatch(value):
        raise ManualVerificationError("invalid_code", "验证码必须是数字", 400)
    minimum, maximum = (6, 6) if kind == "totp" else (4, 10)
    if not minimum <= len(value) <= maximum:
        raise ManualVerificationError(
            "invalid_code",
            f"验证码长度必须为 {minimum} 至 {maximum} 位",
            400,
        )
    return value


def _generation(value: Any) -> int:
    """Normalize the opaque task generation without accepting lossy casts."""
    if isinstance(value, bool):
        return -1
    if isinstance(value, int):
        return value if value >= 0 else -1
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate or not re.fullmatch(r"[0-9]+", candidate):
            return -1
        try:
            return int(candidate)
        except (TypeError, ValueError):
            return -1
    return -1


def normalize_generation(value: Any) -> int:
    """Return a non-negative generation or ``-1`` for malformed input."""
    return _generation(value)


class ManualVerificationBroker:
    """Keep code values in memory only and consume each prompt once."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        default_window_seconds: int = DEFAULT_WINDOW_SECONDS,
        tombstone_retention_seconds: int = TOMBSTONE_RETENTION_SECONDS,
    ) -> None:
        self._clock = clock
        self._window = max(1, min(MAX_WINDOW_SECONDS, int(default_window_seconds)))
        self._tombstone_retention = max(
            1,
            min(MAX_WINDOW_SECONDS, int(tombstone_retention_seconds)),
        )
        self._condition = threading.Condition()
        self._prompts: dict[str, _Prompt] = {}
        self._tombstones: dict[str, _PromptTombstone] = {}

    def _now(self) -> float:
        return float(self._clock())

    def open(
        self,
        task_id: Any,
        input_kind: Any,
        generation: Any,
        *,
        window_seconds: int | None = None,
    ) -> dict[str, Any]:
        task = str(task_id or "").strip()
        kind = normalize_input_kind(input_kind)
        gen = _generation(generation)
        if not task or not kind or gen < 0:
            raise ManualVerificationError("invalid_prompt", "人工验证码上下文无效", 400)
        now = self._now()
        window = self._window if window_seconds is None else max(
            1, min(MAX_WINDOW_SECONDS, int(window_seconds))
        )
        with self._condition:
            self._prune(now)
            existing = self._prompts.get(task)
            if existing is not None and not self._expired(existing, now) and not existing.cancelled:
                if existing.input_kind == kind and existing.generation == gen:
                    return self._public(existing, now)
                self._retire(existing, "superseded", now)
            prompt = _Prompt(task, kind, gen, now, now + window)
            self._prompts[task] = prompt
            self._tombstones.pop(task, None)
            self._condition.notify_all()
            return self._public(prompt, now)

    def submit(
        self,
        task_id: Any,
        input_kind: Any,
        generation: Any,
        code: Any,
    ) -> dict[str, Any]:
        task = str(task_id or "").strip()
        kind = normalize_input_kind(input_kind)
        gen = _generation(generation)
        if not task or not kind or gen < 0:
            raise ManualVerificationError("invalid_prompt", "人工验证码上下文无效", 400)
        now = self._now()
        with self._condition:
            self._prune(now)
            prompt = self._prompts.get(task)
            if prompt is None:
                self._raise_for_missing(task, kind, gen, now)
            if prompt.input_kind != kind or prompt.generation != gen:
                raise ManualVerificationError("stale_generation", "验证码输入已过期，请使用当前任务提示", 409)
            if prompt.cancelled or self._expired(prompt, now):
                reason = prompt.cancel_reason or "expired"
                self._retire(prompt, reason, now)
                self._raise_for_tombstone(reason)
            if prompt.submitted or prompt.consumed:
                raise ManualVerificationError("already_submitted", "人工验证码已提交", 409)
            value = validate_code(kind, code)
            prompt.submitted = value
            self._condition.notify_all()
            return {"accepted": True, **self._public(prompt, now, include_remaining=False)}

    def wait(
        self,
        task_id: Any,
        input_kind: Any,
        generation: Any,
        *,
        stop_event: Any = None,
        timeout_seconds: int | None = None,
    ) -> str:
        task = str(task_id or "").strip()
        kind = normalize_input_kind(input_kind)
        gen = _generation(generation)
        if not task or not kind or gen < 0:
            raise ManualVerificationError("invalid_prompt", "人工验证码上下文无效", 400)
        deadline = self._now() + max(
            1,
            min(MAX_WINDOW_SECONDS, int(timeout_seconds or self._window)),
        )
        with self._condition:
            self._prune(self._now())
            prompt = self._prompts.get(task)
            if prompt is None:
                self._raise_for_missing(task, kind, gen, self._now())
            if prompt.input_kind != kind or prompt.generation != gen:
                raise ManualVerificationError("stale_generation", "验证码输入已过期，请使用当前任务提示", 409)
            while True:
                if _is_set(stop_event):
                    self._retire(prompt, "stopped", self._now())
                    self._condition.notify_all()
                    raise ManualVerificationStopped()
                now = self._now()
                if prompt.submitted and not prompt.consumed:
                    value = prompt.submitted
                    prompt.consumed = True
                    self._retire(prompt, "consumed", now)
                    return value
                if prompt.cancelled or self._expired(prompt, now) or now >= deadline:
                    reason = prompt.cancel_reason or "expired"
                    self._retire(prompt, reason, now)
                    self._raise_for_tombstone(reason)
                self._condition.wait(timeout=min(0.25, max(0.01, deadline - now)))

    def cancel_task(self, task_id: Any, *, reason: str = "stopped") -> None:
        task = str(task_id or "").strip()
        with self._condition:
            prompt = self._prompts.get(task)
            if prompt is not None:
                self._retire(prompt, reason, self._now())
            self._condition.notify_all()

    def cancel_all(self) -> None:
        with self._condition:
            now = self._now()
            for prompt in tuple(self._prompts.values()):
                self._retire(prompt, "stopped", now)
            self._condition.notify_all()

    def public(self, task_id: Any = "") -> dict[str, Any] | list[dict[str, Any]]:
        now = self._now()
        with self._condition:
            self._prune(now)
            if task_id:
                prompt = self._prompts.get(str(task_id).strip())
                return self._public(prompt, now) if prompt is not None else {}
            return [self._public(prompt, now) for prompt in self._prompts.values()]

    @staticmethod
    def _expired(prompt: _Prompt, now: float) -> bool:
        return now >= prompt.deadline_at

    def _prune(self, now: float) -> None:
        for task, prompt in tuple(self._prompts.items()):
            if prompt.cancelled:
                self._retire(prompt, prompt.cancel_reason or "stopped", now)
            elif self._expired(prompt, now):
                self._retire(prompt, "expired", now)
        for task, tombstone in tuple(self._tombstones.items()):
            if now >= tombstone.expires_at:
                self._tombstones.pop(task, None)

    def _retire(self, prompt: _Prompt, reason: str, now: float) -> None:
        """Remove a prompt while retaining only non-secret expiry context."""
        task = prompt.task_id
        prompt.cancel_reason = str(reason or "expired")
        if prompt.cancel_reason != "consumed":
            prompt.cancelled = True
        self._prompts.pop(task, None)
        self._tombstones[task] = _PromptTombstone(
            input_kind=prompt.input_kind,
            generation=prompt.generation,
            reason=prompt.cancel_reason,
            expires_at=now + self._tombstone_retention,
        )

    def _raise_for_missing(self, task: str, kind: str, generation: int, now: float) -> None:
        tombstone = self._tombstones.get(task)
        if tombstone is None or now >= tombstone.expires_at:
            self._tombstones.pop(task, None)
            raise ManualVerificationError("not_waiting", "当前任务没有等待人工验证码", 404)
        if tombstone.input_kind != kind or tombstone.generation != generation:
            raise ManualVerificationError("stale_generation", "验证码输入已过期，请使用当前任务提示", 409)
        self._raise_for_tombstone(tombstone.reason)

    @staticmethod
    def _raise_for_tombstone(reason: str) -> None:
        if reason == "consumed":
            raise ManualVerificationError("already_submitted", "人工验证码已提交", 409)
        if reason in {"superseded", "stage_changed", "generation_changed"}:
            raise ManualVerificationError(
                "stale_generation",
                "验证码输入已过期，请使用当前任务提示",
                409,
            )
        raise ManualVerificationError("expired", "人工验证码输入窗口已结束", 410)

    @staticmethod
    def _public(
        prompt: _Prompt | None,
        now: float,
        *,
        include_remaining: bool = True,
    ) -> dict[str, Any]:
        if prompt is None:
            return {}
        value = {
            "input_kind": prompt.input_kind,
            "generation": prompt.generation,
            "opened_at": int(prompt.opened_at),
            "deadline_at": int(prompt.deadline_at),
            "capabilities": ["submit"],
            "can_submit": (
                not prompt.cancelled
                and not prompt.submitted
                and not prompt.consumed
            ),
        }
        if include_remaining:
            value["remaining_seconds"] = max(0, int(prompt.deadline_at - now))
        return value


def _is_set(stop_event: Any) -> bool:
    if stop_event is None:
        return False
    checker = getattr(stop_event, "is_set", None)
    if callable(checker):
        return bool(checker())
    return bool(stop_event()) if callable(stop_event) else bool(stop_event)


def is_timeout_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return any(
        marker in text
        for marker in (
            "timeout",
            "timed out",
            "code_timeout",
            "no verification code",
            "未获取到",
            "等待验证码",
        )
    )


def _validated_automatic_code(input_kind: Any, value: Any) -> str:
    """Only numeric, correctly-sized provider values may win the code race."""
    try:
        return validate_code(input_kind, value)
    except ManualVerificationError:
        return ""


def wait_with_manual_fallback(
    automatic_wait: Callable[[], Any],
    *,
    broker: ManualVerificationBroker,
    task_id: Any,
    input_kind: Any,
    generation: Any,
    stop_event: Any = None,
    automatic_timeout_seconds: int = 90,
    manual_timeout_seconds: int = DEFAULT_WINDOW_SECONDS,
    on_manual_selected: Callable[[], Any] | None = None,
) -> Any:
    """Race a bounded automatic wait against an inline manual prompt."""

    result_queue: list[tuple[str, Any]] = []
    condition = threading.Condition()
    manual_open = threading.Event()
    automatic_submitted = threading.Event()

    def run_automatic() -> None:
        try:
            result = automatic_wait()
            normalized = _validated_automatic_code(input_kind, result)
            value = ("result", normalized)
        except BaseException as exc:  # delivered to the task thread below
            value = ("error", exc)

        # Once the manual prompt is visible, arbitrate an automatic value
        # through the broker before publishing it to the hand-off queue.  This
        # closes the common completion/POST interleave in which an automatic
        # code had already arrived but a manual request could otherwise win
        # while the worker was still enqueueing its result.
        if manual_open.is_set() and value[0] == "result" and value[1]:
            try:
                broker.submit(task_id, input_kind, generation, value[1])
            except ManualVerificationError:
                pass
            else:
                automatic_submitted.set()
        with condition:
            result_queue.append(value)
            condition.notify_all()

    worker = threading.Thread(target=run_automatic, name="manual-verification-auto", daemon=True)
    worker.start()
    deadline = time.monotonic() + max(1, int(automatic_timeout_seconds))
    while True:
        if _is_set(stop_event):
            broker.cancel_task(task_id)
            raise ManualVerificationStopped()
        with condition:
            if result_queue:
                kind, value = result_queue.pop(0)
                if kind == "result" and value:
                    broker.cancel_task(task_id)
                    return value
                if kind == "error" and not is_timeout_error(value):
                    raise value
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            condition.wait(timeout=min(0.25, remaining))

    broker.open(task_id, input_kind, generation, window_seconds=manual_timeout_seconds)
    manual_open.set()
    try:
        # The automatic worker can finish in the small hand-off window between
        # the timeout decision and opening the prompt.  Consume that result
        # first so the same-generation first-valid-result rule remains exact.
        with condition:
            pending_results = list(result_queue)
            result_queue.clear()
        for result_kind, result_value in pending_results:
            if result_kind == "result" and result_value:
                # Submit through the broker so a manual POST that won the
                # hand-off race cannot be overwritten by this late provider
                # value.  The waiter below consumes whichever submission won.
                try:
                    broker.submit(task_id, input_kind, generation, result_value)
                except ManualVerificationError:
                    pass
                else:
                    automatic_submitted.set()
            if result_kind == "error" and not is_timeout_error(result_value):
                raise result_value
        value = broker.wait(
            task_id,
            input_kind,
            generation,
            stop_event=stop_event,
            timeout_seconds=manual_timeout_seconds,
        )
        if on_manual_selected is not None and not automatic_submitted.is_set():
            try:
                on_manual_selected()
            except Exception:
                pass
        return value
    finally:
        manual_open.clear()


def wait_for_manual(
    *,
    broker: ManualVerificationBroker,
    task_id: Any,
    input_kind: Any,
    generation: Any,
    stop_event: Any = None,
    timeout_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> str:
    """Open an already-selected prompt and wait without starting automation."""
    broker.open(task_id, input_kind, generation, window_seconds=timeout_seconds)
    return broker.wait(
        task_id,
        input_kind,
        generation,
        stop_event=stop_event,
        timeout_seconds=timeout_seconds,
    )


__all__ = [
    "DEFAULT_WINDOW_SECONDS",
    "INPUT_KINDS",
    "ManualVerificationBroker",
    "ManualVerificationError",
    "ManualVerificationStopped",
    "is_timeout_error",
    "normalize_generation",
    "normalize_input_kind",
    "validate_code",
    "wait_for_manual",
    "wait_with_manual_fallback",
]
