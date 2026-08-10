"""Protocol pressure classification and per-proxy concurrency gating."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import re
import threading
import time
from typing import Any, Callable, Iterator

try:
    from .protocol_pressure_runtime import ProtocolPressurePolicy
except ImportError:  # Loaded as a top-level runtime override.
    from protocol_pressure_runtime import ProtocolPressurePolicy  # type: ignore[no-redef]

try:
    from .auth_session_runtime import is_session_invalid
except ImportError:  # Loaded as a top-level runtime override.
    from auth_session_runtime import is_session_invalid  # type: ignore[no-redef]


def _http_status(value: Any) -> int | None:
    status_candidates = [value, getattr(value, "response", None)]
    if isinstance(value, Mapping):
        status_candidates.extend(
            value.get(key)
            for key in ("error", "response")
            if isinstance(value.get(key), Mapping)
        )
    for candidate in status_candidates:
        if candidate is None:
            continue
        for key in ("_status", "status", "status_code", "http_status"):
            try:
                raw_status = (
                    candidate.get(key)
                    if isinstance(candidate, Mapping)
                    else getattr(candidate, key, None)
                )
                status = int(raw_status)
            except (TypeError, ValueError):
                continue
            if status == 429:
                return status
            if 100 <= status <= 599:
                return status
    text = f"{type(value).__name__}: {value or ''}".lower()
    match = re.search(
        r"\b(?:http(?:error|/\d+(?:\.\d+)?)?(?:\s+(?:status|response))?"
        r"|status(?:_code)?)\s*[:=]?\s*(\d{3})\b",
        text,
    )
    if match:
        status = int(match.group(1))
        if 100 <= status <= 599:
            return status
    return None


def is_http_429_error(value: Any) -> bool:
    status = _http_status(value)
    if status is not None:
        return status == 429

    type_name = "" if value is None else type(value).__name__
    text = f"{type_name}: {value or ''}".lower()
    if re.search(r"\b429\b", text) and any(
        marker in text
        for marker in ("http", "status", "too many requests", "rate limit")
    ):
        return True
    return any(
        marker in text
        for marker in (
            "status=429",
            "http 429",
            "too many requests",
            "rate limit",
            "rate_limited",
        )
    )


def is_protocol_pressure_error(value: Any) -> bool:
    status = _http_status(value)
    if status is not None:
        return status == 429
    if is_http_429_error(value):
        return True
    type_name = "" if value is None else type(value).__name__
    text = f"{type_name}: {value or ''}".lower()
    return any(
        marker in text
        for marker in (
            "ssleoferror",
            "sslerror",
            "unexpected_eof",
            "tls connect",
            "tls handshake",
            "ssl handshake",
            "handshake failure",
            "connection reset",
            "connection aborted",
            "connection closed",
            "remote end closed connection",
            "remote disconnected",
            "server disconnected",
            "proxyerror",
            "proxy error",
            "proxy_connect_failed",
            "unable to connect to proxy",
            "proxy connect aborted",
            "failed to connect",
            "connection refused",
            "curl: (7)",
            "curl: (35)",
            "curl: (56)",
        )
    )


@dataclass
class _ProxyProtocolState:
    active: int = 0
    waiting: int = 0
    limit: int = 3
    baseline: int = 3
    ceiling: int = 3
    last_started_at: float = 0.0
    success_streak: int = 0
    expansion_enabled: bool = True
    recovery_required: bool = False
    paused: bool = False
    pause_reason: str = ""
    pause_until: float = 0.0
    connectivity_paused: bool = False
    connectivity_pause_reason: str = ""
    sticky_baseline: bool = False
    connectivity_outages: int = 0


def _notify_observer(observer: Any, value: Any) -> None:
    if not callable(observer):
        return
    try:
        observer(value)
    except Exception:
        pass


class ProxyProtocolGate:
    """Limit full protocol sessions independently for each configured proxy."""

    def __init__(
        self,
        default_limit: int = 3,
        *,
        now_fn: Callable[[], float] = time.monotonic,
        pressure_window_seconds: float = 60.0,
        restore_successes: int = 6,
        launch_interval_seconds: float = 1.0,
    ) -> None:
        self.default_limit = max(1, int(default_limit))
        self.default_baseline = self.default_limit
        self.default_ceiling = self.default_limit
        self.now_fn = now_fn
        self.pressure_window_seconds = max(1.0, float(pressure_window_seconds))
        self.restore_successes = max(1, int(restore_successes))
        self.launch_interval_seconds = max(0.0, float(launch_interval_seconds))
        self.condition = threading.Condition()
        self.states: dict[str, _ProxyProtocolState] = {}
        self._follow_synchronized_capacity = True

    @staticmethod
    def key(proxy: Any) -> str:
        text = str(proxy or "").strip()
        if not text:
            return "direct"
        return f"proxy:{hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()[:16]}"

    def _state(self, key: str) -> _ProxyProtocolState:
        return self.states.setdefault(
            key,
            _ProxyProtocolState(
                limit=self.default_limit,
                baseline=self.default_baseline,
                ceiling=self.default_ceiling,
                expansion_enabled=self.default_ceiling > self.default_baseline,
            ),
        )

    def begin_run(self, limit: Any, *, healthy_ceiling: Any = None) -> int:
        baseline = max(1, int(limit))
        ceiling = baseline if healthy_ceiling is None else max(baseline, int(healthy_ceiling))
        with self.condition:
            self.default_limit = baseline
            self.default_baseline = baseline
            self.default_ceiling = ceiling
            self._follow_synchronized_capacity = healthy_ceiling is None
            for state in self.states.values():
                state.baseline = baseline
                state.ceiling = ceiling
                state.limit = baseline
                state.success_streak = 0
                state.expansion_enabled = ceiling > baseline
                state.recovery_required = False
                state.paused = False
                state.pause_reason = ""
                state.pause_until = 0.0
                state.connectivity_paused = False
                state.connectivity_pause_reason = ""
                state.sticky_baseline = False
                state.connectivity_outages = 0
                state.last_started_at = 0.0
            self.condition.notify_all()
        return baseline

    def synchronize_capacity(self, limit: Any) -> int:
        """Preserve the legacy capacity-following API outside managed runs."""
        target = max(1, int(limit))
        with self.condition:
            if not self._follow_synchronized_capacity:
                return target
            self.default_limit = target
            self.default_baseline = target
            self.default_ceiling = target
            for state in self.states.values():
                state.baseline = target
                state.ceiling = target
                state.limit = target
                state.success_streak = 0
                state.expansion_enabled = False
                state.recovery_required = False
            self.condition.notify_all()
        return target

    def _clear_expired_pause_locked(
        self, state: _ProxyProtocolState, now: float,
    ) -> bool:
        if state.pause_until <= 0 or now < state.pause_until:
            return False
        state.pause_until = 0.0
        state.paused = state.connectivity_paused
        state.pause_reason = (
            state.connectivity_pause_reason if state.connectivity_paused else ""
        )
        state.limit = state.baseline
        state.success_streak = 0
        self.condition.notify_all()
        return True

    def guard_expansion(
        self,
        proxy: Any,
        *,
        reason: str = "openai_connectivity_suspected",
    ) -> int:
        """Return to baseline after the first qualified connection failure."""
        key = self.key(proxy)
        with self.condition:
            state = self._state(key)
            state.limit = state.baseline
            state.success_streak = 0
            state.expansion_enabled = False
            state.recovery_required = not state.sticky_baseline
            if not state.paused:
                state.pause_reason = str(reason or "openai_connectivity_suspected")
            self.condition.notify_all()
            return state.limit

    def pause_connectivity(
        self,
        proxy: Any,
        *,
        reason: str = "openai_connectivity_outage",
        count_outage: bool = True,
    ) -> int:
        """Pause new protocol leases while allowing active requests to finish."""
        key = self.key(proxy)
        with self.condition:
            state = self._state(key)
            now = float(self.now_fn())
            self._clear_expired_pause_locked(state, now)
            if count_outage and not state.connectivity_paused:
                state.connectivity_outages += 1
            if state.connectivity_outages >= 2:
                state.sticky_baseline = True
            state.limit = state.baseline
            state.success_streak = 0
            state.expansion_enabled = False
            state.recovery_required = not state.sticky_baseline
            state.connectivity_paused = True
            state.connectivity_pause_reason = str(
                reason or "openai_connectivity_outage"
            )
            state.paused = True
            state.pause_reason = (
                "http_429"
                if state.pause_until > now
                else state.connectivity_pause_reason
            )
            self.condition.notify_all()
            return state.limit

    def resume_connectivity(self, proxy: Any) -> int:
        """Resume immediately at baseline after connectivity probes recover."""
        key = self.key(proxy)
        with self.condition:
            state = self._state(key)
            now = float(self.now_fn())
            self._clear_expired_pause_locked(state, now)
            state.connectivity_paused = False
            state.connectivity_pause_reason = ""
            rate_limit_active = state.pause_until > now
            state.paused = rate_limit_active
            state.pause_reason = (
                "http_429"
                if rate_limit_active
                else (
                    "sticky_baseline"
                    if state.sticky_baseline
                    else "openai_connectivity_recovering"
                )
            )
            if not rate_limit_active:
                state.pause_until = 0.0
            state.limit = state.baseline
            state.success_streak = 0
            state.expansion_enabled = False
            state.recovery_required = not state.sticky_baseline
            self.condition.notify_all()
            return state.limit

    def apply_http_429(self, proxy: Any, *, cooldown_seconds: float = 30.0) -> int:
        """Apply a timed baseline cooldown and disable expansion for this batch."""
        key = self.key(proxy)
        with self.condition:
            state = self._state(key)
            now = float(self.now_fn())
            state.limit = state.baseline
            state.success_streak = 0
            state.expansion_enabled = False
            state.recovery_required = False
            state.sticky_baseline = True
            state.paused = True
            state.pause_reason = "http_429"
            state.pause_until = max(
                state.pause_until,
                now + max(0.0, float(cooldown_seconds)),
            )
            self.condition.notify_all()
            return state.limit

    @staticmethod
    def _stopped(stop_event: Any) -> bool:
        if stop_event is None:
            return False
        checker = getattr(stop_event, "is_set", None)
        if callable(checker):
            return bool(checker())
        return bool(stop_event()) if callable(stop_event) else bool(stop_event)

    def wake_all(self) -> None:
        with self.condition:
            self.condition.notify_all()

    def wait_until_resumed(
        self, proxy: Any, *, stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
    ) -> str:
        """Wait out a pause without taking another capacity slot."""
        key = self.key(proxy)
        wait_started = float(self.now_fn())
        blocked = False
        try:
            with self.condition:
                state = self._state(key)
                state.waiting += 1
                try:
                    while True:
                        if self._stopped(stop_event):
                            raise RuntimeError("task_stopped")
                        self._clear_expired_pause_locked(state, float(self.now_fn()))
                        if not state.paused:
                            return key
                        blocked = True
                        self.condition.wait(timeout=0.25)
                finally:
                    state.waiting = max(0, state.waiting - 1)
        finally:
            if blocked:
                _notify_observer(on_wait, max(0.0, float(self.now_fn()) - wait_started))

    @contextmanager
    def acquire(
        self,
        proxy: Any,
        *,
        stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
    ) -> Iterator[str]:
        key = self.key(proxy)
        acquired = False
        wait_started = float(self.now_fn())
        wait_reported = False
        try:
            try:
                with self.condition:
                    state = self._state(key)
                    state.waiting += 1
                    try:
                        while True:
                            if self._stopped(stop_event):
                                raise RuntimeError("task_stopped")
                            now = float(self.now_fn())
                            self._clear_expired_pause_locked(state, now)
                            launch_wait = (
                                max(
                                    0.0,
                                    state.last_started_at
                                    + self.launch_interval_seconds
                                    - now,
                                )
                                if state.last_started_at > 0
                                else 0.0
                            )
                            if (
                                not state.paused
                                and state.active < state.limit
                                and launch_wait <= 0
                            ):
                                state.active += 1
                                state.last_started_at = now
                                acquired = True
                                break
                            self.condition.wait(
                                timeout=min(0.25, launch_wait) if launch_wait else 0.25
                            )
                    finally:
                        state.waiting = max(0, state.waiting - 1)
            finally:
                waited = max(0.0, float(self.now_fn()) - wait_started)
                _notify_observer(on_wait, waited)
                wait_reported = True
            yield key
        finally:
            if not wait_reported:
                waited = max(0.0, float(self.now_fn()) - wait_started)
                _notify_observer(on_wait, waited)
            if acquired:
                with self.condition:
                    state.active = max(0, state.active - 1)
                    self.condition.notify_all()

    def report(
        self,
        proxy: Any,
        value: Any = None,
        *,
        success: bool = False,
        on_limit_change: Callable[[dict[str, Any]], Any] | None = None,
    ) -> int:
        key = self.key(proxy)
        event: dict[str, Any] | None = None
        recovery_qualified = False
        with self.condition:
            state = self._state(key)
            now = float(self.now_fn())
            self._clear_expired_pause_locked(state, now)
            old_limit = state.limit
            if success:
                if not state.paused and not state.sticky_baseline:
                    state.success_streak += 1
                    if state.success_streak >= self.restore_successes:
                        if state.recovery_required:
                            state.recovery_required = False
                            state.expansion_enabled = state.ceiling > state.baseline
                            recovery_qualified = True
                        if state.expansion_enabled and state.limit < state.ceiling:
                            state.limit += 1
                        state.success_streak = 0
                        self.condition.notify_all()
            elif is_http_429_error(value):
                state.limit = state.baseline
                state.success_streak = 0
                state.expansion_enabled = False
                state.recovery_required = False
                state.sticky_baseline = True
                state.paused = True
                state.pause_reason = "http_429"
                state.pause_until = max(state.pause_until, now + 30.0)
                self.condition.notify_all()
            else:
                state.success_streak = 0
            new_limit = state.limit
            if new_limit != old_limit or recovery_qualified:
                event = {
                    "kind": (
                        "recovery_qualified"
                        if new_limit == old_limit
                        else "restored" if new_limit > old_limit else "baseline_reset"
                    ),
                    "old_limit": old_limit,
                    "new_limit": new_limit,
                    "ceiling": state.ceiling,
                    "baseline": state.baseline,
                    "recovery_qualified": recovery_qualified,
                    "proxy_key": key,
                }
        if event is not None:
            _notify_observer(on_limit_change, event)
        return new_limit

    def snapshot(self, proxy: Any) -> dict[str, Any]:
        key = self.key(proxy)
        with self.condition:
            state = self.states.get(key) or _ProxyProtocolState(
                limit=self.default_limit,
                baseline=self.default_baseline,
                ceiling=self.default_ceiling,
                expansion_enabled=self.default_ceiling > self.default_baseline,
            )
            now = float(self.now_fn())
            if key in self.states:
                self._clear_expired_pause_locked(state, now)
            remaining = (
                max(0.0, state.pause_until - now)
                if state.paused and state.pause_until > 0
                else 0.0
            )
            return {
                "active": state.active,
                "limit": state.limit,
                "ceiling": state.ceiling,
                "baseline": state.baseline,
                "healthy_ceiling": state.ceiling,
                "waiting": state.waiting,
                "paused": state.paused,
                "pause_reason": state.pause_reason,
                "pause_remaining_seconds": int(remaining + 0.999) if remaining else 0,
                "sticky_baseline": state.sticky_baseline,
                "recovery_required": state.recovery_required,
                "expansion_enabled": state.expansion_enabled,
            }


class TransportProtocolCoordinator:
    """Own short protocol leases and recoverable connectivity responses."""

    def __init__(
        self,
        *,
        gate: Any,
        inflight_pipeline: Any,
        success_fn: Callable[[Any], bool],
        task_id_getter: Callable[[Any], str],
        task_context_getter: Callable[[], str],
        main_chain_source: Callable[..., tuple[bool, dict[str, Any]]],
        rate_limited_failure: Callable[[Any], bool],
        report_task_pressure: Callable[..., Any],
        connectivity_getter: Callable[[], Any],
        inflight_gate_getter: Callable[[], Any],
        activity_observer: Callable[[], Any],
        segment_observer: Callable[[str, str, float], Any],
    ) -> None:
        self.gate = gate
        self.inflight_pipeline = inflight_pipeline
        self.success_fn = success_fn
        self.task_id_getter = task_id_getter
        self.task_context_getter = task_context_getter
        self.main_chain_source = main_chain_source
        self.rate_limited_failure = rate_limited_failure
        self.report_task_pressure = report_task_pressure
        self.connectivity_getter = connectivity_getter
        self.inflight_gate_getter = inflight_gate_getter
        self.activity_observer = activity_observer
        self.segment_observer = segment_observer

    def protocol_gate(self) -> ProxyProtocolGate:
        return self.gate() if callable(self.gate) else self.gate

    def staged(self, transport: Any) -> bool:
        config = getattr(transport, "config", None)
        if (
            not isinstance(config, dict)
            or str(config.get("run_mode") or "register").lower() == "relogin"
        ):
            return False
        return self.inflight_pipeline.optimization_active(self.inflight_gate_getter())

    @staticmethod
    def _proxy_fingerprint(proxy: Any) -> str:
        text = str(proxy or "").strip() or "direct"
        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
        return f"sha256:{digest}"

    def capture_connectivity_generation(
        self,
        proxy: Any,
    ) -> tuple[str, str, str] | None:
        """Bind one request to the active proxy and connectivity incident."""
        connectivity = self.connectivity_getter()
        snapshot = getattr(connectivity, "snapshot", None)
        if not callable(snapshot):
            return None
        try:
            state = snapshot()
        except Exception:
            return None
        if not isinstance(state, Mapping):
            return None
        fingerprint = str(state.get("proxy_fingerprint") or "")
        if not fingerprint:
            return None
        return (
            fingerprint,
            str(state.get("event_id") or state.get("incident_id") or ""),
            self._proxy_fingerprint(proxy),
        )

    def _generation_matches(
        self,
        connectivity: Any,
        expected: tuple[str, str, str] | None,
    ) -> bool:
        if expected is None:
            return True
        expected_fingerprint, expected_event_id, request_fingerprint = expected
        if expected_fingerprint != request_fingerprint:
            return False
        snapshot = getattr(connectivity, "snapshot", None)
        if not callable(snapshot):
            return False
        try:
            state = snapshot()
        except Exception:
            return False
        if not isinstance(state, Mapping):
            return False
        return (
            str(state.get("proxy_fingerprint") or "") == expected_fingerprint
            and str(state.get("event_id") or state.get("incident_id") or "")
            == expected_event_id
        )

    def _observe_generation_bound(
        self,
        connectivity: Any,
        origin: str,
        value: Any,
        *,
        succeeded: bool,
        generation: tuple[str, str, str] | None,
        on_current: Callable[[dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        def observe() -> dict[str, Any]:
            if not self._generation_matches(connectivity, generation):
                return {
                    "kind": "stale_connectivity_generation",
                    "action": "ignored",
                    "reason_code": "stale_connectivity_generation",
                }
            reporter = (
                getattr(connectivity, "report_success")
                if succeeded
                else getattr(connectivity, "report_failure")
            )
            decision = reporter(origin) if succeeded else reporter(origin, value)
            _notify_observer(on_current, decision)
            return decision

        callback_lock = getattr(connectivity, "_callback_lock", None)
        if hasattr(callback_lock, "__enter__") and hasattr(callback_lock, "__exit__"):
            # Match the runtime's callback-lock -> state-lock order.  snapshot()
            # and the report methods take the state lock reentrantly.
            with callback_lock:
                return observe()
        return observe()

    @staticmethod
    def _is_session_invalidation(value: Any, failure: Any = None) -> bool:
        candidates = [value, failure]
        if isinstance(failure, Mapping):
            candidates.extend(
                failure.get(key)
                for key in ("error", "error_code", "code", "message")
            )
        return any(is_session_invalid(candidate) for candidate in candidates)

    def _rollback_inflight_for_session_invalidation(
        self,
        value: Any,
        failure: Any = None,
    ) -> None:
        if not self._is_session_invalidation(value, failure):
            return
        gate = self.inflight_gate_getter()
        reporter = getattr(gate, "report_session_invalidation", None)
        if not callable(reporter):
            reporter = getattr(gate, "report_pressure", None)
            if callable(reporter):
                try:
                    reporter("oauth_session_invalid")
                except Exception:
                    pass
            return
        try:
            reporter()
        except Exception:
            pass

    @staticmethod
    def proxy(transport: Any) -> Any:
        config = getattr(transport, "config", None)
        if isinstance(config, dict) and config.get("proxy"):
            return config.get("proxy")
        return getattr(transport, "proxy", "")

    def _resume_inflight_if_ready(self, event: Any) -> None:
        if not isinstance(event, dict) or not event.get("recovery_qualified"):
            return
        gate = self.inflight_gate_getter()
        resume = getattr(gate, "resume", None)
        if callable(resume):
            try:
                resume()
            except Exception:
                pass

    def synchronize_connectivity_pause(
        self,
        proxy: Any,
        inflight_gate: Any,
        *,
        on_paused: Callable[[dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        """Apply the current persisted outage to newly-created batch gates."""
        connectivity = self.connectivity_getter()

        def synchronize() -> dict[str, Any]:
            snapshot = getattr(connectivity, "snapshot", lambda: {})()
            state = dict(snapshot) if isinstance(snapshot, Mapping) else {}
            if not state.get("paused"):
                return state
            self.protocol_gate().pause_connectivity(proxy, count_outage=False)
            suspend = getattr(inflight_gate, "suspend", None)
            if callable(suspend):
                suspend("openai_connectivity_outage")
            _notify_observer(on_paused, state)
            return state

        condition = getattr(connectivity, "condition", None)
        if hasattr(condition, "__enter__") and hasattr(condition, "__exit__"):
            with condition:
                return synchronize()
        return synchronize()

    def _apply_connectivity_decision(
        self,
        decision: Any,
        *,
        proxy: Any,
    ) -> bool:
        if not isinstance(decision, dict):
            return False
        action = str(decision.get("action") or "")
        if action == "cancel_expansion":
            self.protocol_gate().guard_expansion(proxy)
            inflight = self.inflight_gate_getter()
            suspend = getattr(inflight, "suspend", None)
            if callable(suspend):
                suspend("openai_connectivity_suspected")
        elif action == "pause":
            gate = self.protocol_gate()
            gate.pause_connectivity(proxy)
            inflight = self.inflight_gate_getter()
            suspend = getattr(inflight, "suspend", None)
            if callable(suspend):
                suspend("openai_connectivity_outage")
        else:
            return False
        return True

    def observe_connectivity_result(
        self,
        origin: str,
        value: Any = None,
        *,
        succeeded: bool = False,
        task_id: Any = "",
        proxy: Any = "",
        count_capacity: bool = True,
        generation: tuple[str, str, str] | None = None,
        session_failure: Any = None,
    ) -> dict[str, Any]:
        connectivity = self.connectivity_getter()
        identifier = str(task_id or self.task_context_getter() or "").strip()
        route = proxy
        if succeeded:
            decision = self._observe_generation_bound(
                connectivity,
                origin,
                value,
                succeeded=True,
                generation=generation,
            )
            if decision.get("kind") == "stale_connectivity_generation":
                return decision
            if count_capacity:
                self.protocol_gate().report(
                    route,
                    success=True,
                    on_limit_change=self._resume_inflight_if_ready,
                )
            return decision
        decision = self._observe_generation_bound(
            connectivity,
            origin,
            value,
            succeeded=False,
            generation=generation,
            on_current=lambda _decision: (
                self._rollback_inflight_for_session_invalidation(
                    value,
                    session_failure,
                )
            ),
        )
        if decision.get("action") == "ignored" and decision.get("kind") == "stale_connectivity_generation":
            return decision
        if decision.get("kind") == "rate_limited":
            self.report_task_pressure(
                identifier,
                value,
                node_code="http_429",
                immediate=True,
            )
            self.protocol_gate().report(route, value)
        elif self._apply_connectivity_decision(
            decision,
            proxy=route,
        ):
            self.protocol_gate().report(route, value)
        elif decision.get("reason_code") == "openai_http_response":
            self._observe_generation_bound(
                connectivity,
                origin,
                value,
                succeeded=True,
                generation=generation,
            )
        return decision

    def record_result(
        self,
        transport: Any,
        value: Any,
        succeeded: bool,
        *,
        generation: tuple[str, str, str] | None = None,
        proxy: Any = None,
    ) -> None:
        self.activity_observer()
        task_id = self.task_id_getter(transport) or self.task_context_getter()
        main_chain, failure = self.main_chain_source(task_id, value)
        if succeeded:
            self.observe_connectivity_result(
                "auth.openai.com",
                value,
                succeeded=True,
                task_id=task_id,
                proxy=self.proxy(transport) if proxy is None else proxy,
                generation=generation,
            )
            return
        if not main_chain:
            if self._is_session_invalidation(value, failure):
                self.observe_connectivity_result(
                    "auth.openai.com",
                    value,
                    task_id=task_id,
                    proxy=self.proxy(transport) if proxy is None else proxy,
                    generation=generation,
                    session_failure=failure,
                )
            return
        decision = self.observe_connectivity_result(
            "auth.openai.com",
            value,
            task_id=task_id,
            proxy=self.proxy(transport) if proxy is None else proxy,
            generation=generation,
            session_failure=failure,
        )
        if (
            decision.get("kind") not in {"connectivity_failure", "rate_limited"}
            and (
                self.rate_limited_failure(failure)
                or is_protocol_pressure_error(value)
            )
        ):
            self.report_task_pressure(
                task_id,
                value,
                node_code="protocol_pressure",
                immediate=True,
            )
            self.protocol_gate().report(
                self.proxy(transport) if proxy is None else proxy,
                value,
            )

    def observe_main_chain_outcome(
        self,
        value: Any,
        *,
        succeeded: bool,
        task_id: Any,
        proxy: Any,
        failure: Any = None,
        on_limit_change: Callable[[dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        def observe_limit(event: dict[str, Any]) -> None:
            self._resume_inflight_if_ready(event)
            _notify_observer(on_limit_change, event)

        if succeeded:
            decision = self.observe_connectivity_result(
                "auth.openai.com",
                value,
                succeeded=True,
                task_id=task_id,
                proxy=proxy,
                count_capacity=False,
            )
            event = self.protocol_gate().report(
                proxy,
                success=True,
                on_limit_change=observe_limit,
            )
            return {**decision, "limit": event}
        signal = failure if self.rate_limited_failure(failure) else value
        decision = self.observe_connectivity_result(
            "auth.openai.com",
            signal,
            task_id=task_id,
            proxy=proxy,
            session_failure=failure,
        )
        if decision.get("kind") not in {"connectivity_failure", "rate_limited"}:
            if is_protocol_pressure_error(signal):
                self.report_task_pressure(
                    task_id,
                    signal,
                    node_code="protocol_pressure",
                    immediate=True,
                )
            self.protocol_gate().report(
                proxy,
                signal,
                on_limit_change=observe_limit,
            )
        return decision

    def call(self, transport: Any, callback: Callable[[], Any]) -> Any:
        config = getattr(transport, "config", None)
        task_id = self.task_id_getter(transport) or self.task_context_getter()
        route = self.proxy(transport)

        def observed_callback() -> Any:
            generation = self.capture_connectivity_generation(route)
            try:
                value = callback()
            except Exception as exc:
                try:
                    self.record_result(
                        transport,
                        exc,
                        False,
                        generation=generation,
                        proxy=route,
                    )
                except Exception:
                    pass
                raise
            try:
                succeeded = bool(self.success_fn(value))
                self.record_result(
                    transport,
                    value,
                    succeeded,
                    generation=generation,
                    proxy=route,
                )
            except Exception:
                pass
            return value

        return self.inflight_pipeline.call_with_protocol_lease(
            observed_callback,
            staged=self.staged(transport),
            gate=self.protocol_gate(),
            proxy=route,
            stop_event=(config or {}).get("_stop_requested") if isinstance(config, dict) else None,
            on_wait=lambda elapsed: self.segment_observer(
                task_id,
                "protocol_slot_waiting",
                elapsed,
            ),
        )

    def call_origin(
        self,
        transport: Any,
        origin: str,
        callback: Callable[[], Any],
        *, success_fn: Callable[[Any], bool], count_capacity: bool = True,
    ) -> Any:
        """Run one non-Auth OpenAI request under the shared protocol gate."""
        config = getattr(transport, "config", None)
        task_id = self.task_id_getter(transport) or self.task_context_getter()
        route = self.proxy(transport)

        def observed_callback() -> Any:
            generation = self.capture_connectivity_generation(route)
            try:
                value = callback()
            except Exception as exc:
                try:
                    self.observe_connectivity_result(
                        origin,
                        exc,
                        task_id=task_id,
                        proxy=route,
                        count_capacity=count_capacity,
                        generation=generation,
                    )
                except Exception:
                    pass
                raise
            try:
                self.observe_connectivity_result(
                    origin,
                    value,
                    succeeded=bool(success_fn(value)),
                    task_id=task_id,
                    proxy=route,
                    count_capacity=count_capacity,
                    generation=generation,
                )
            except Exception:
                pass
            return value

        return self.inflight_pipeline.call_with_protocol_lease(
            observed_callback,
            staged=self.staged(transport),
            gate=self.protocol_gate(),
            proxy=route,
            stop_event=(config or {}).get("_stop_requested") if isinstance(config, dict) else None,
            on_wait=lambda elapsed: self.segment_observer(
                task_id,
                "protocol_slot_waiting",
                elapsed,
            ),
        )

__all__ = [
    "ProxyProtocolGate",
    "ProtocolPressurePolicy",
    "TransportProtocolCoordinator",
    "_ProxyProtocolState",
    "_notify_observer",
    "is_http_429_error",
    "is_protocol_pressure_error",
]
