"""Credential-safe connectivity guard for the OpenAI authorization origins."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit
import uuid

try:
    from .configuration_runtime import atomic_write_private_json
except ImportError:  # Loaded as a top-level runtime override.
    from configuration_runtime import atomic_write_private_json  # type: ignore[no-redef]


AUTH_ORIGIN = "auth.openai.com"
SENTINEL_ORIGIN = "sentinel.openai.com"
OPENAI_CONNECTIVITY_ORIGINS = (AUTH_ORIGIN, SENTINEL_ORIGIN)

STATUS_UNKNOWN = "unknown"
STATUS_HEALTHY = "healthy"
STATUS_OUTAGE = "outage"
STATUS_RECOVERING = "recovering"
_VALID_STATUSES = {STATUS_UNKNOWN, STATUS_HEALTHY, STATUS_OUTAGE, STATUS_RECOVERING}

KIND_CONNECTIVITY = "connectivity_failure"
KIND_RATE_LIMITED = "rate_limited"
KIND_OTHER = "other"

OUTAGE_REASON_CODE = "openai_auth_connectivity_outage"
OUTAGE_REASON_LABEL = "OpenAI 授权链路连接异常"
PAUSE_REASON = "openai_auth_connectivity_outage"
RUNTIME_EPOCH = int(time.time_ns() // 1_000_000)

_SAFE_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{16}$")
_SAFE_REASON = re.compile(r"^[a-z0-9_]{1,100}$")
_HTTP_STATUS_TEXT = re.compile(
    r"\b(?:http(?:/\d(?:\.\d)?|(?:status)?error)?|http\s+status|status(?:[ _]code)?)"
    r"\s*[:=]?\s*['\"]?([1-5]\d{2})\b",
    re.IGNORECASE,
)
_BUSINESS_MARKERS = (
    "account banned", "account deactivated", "invalid password", "incorrect password", "invalid_grant",
    "session invalid", "session expired", "unauthorized", "forbidden", "captcha",
)
_CONNECTIVITY_RULES = (
    (
        "openai_proxy_connection_failure", "OpenAI 显式代理连接失败",
        ("proxyerror", "proxy error", "proxy_connect_failed", "unable to connect to proxy", "proxy connect aborted", "proxy connection"),
    ),
    (
        "openai_tls_connection_failure", "OpenAI TLS 握手失败",
        ("ssleoferror", "sslerror", "tls connect", "tls handshake", "ssl handshake", "handshake failure", "certificate verify failed", "curl: (35)", "curl (35)"),
    ),
    (
        "openai_connection_timeout", "OpenAI 连接超时",
        ("connecttimeout", "connect timeout", "connection timeout", "connection timed out", "timed out while connecting", "curl: (28)", "curl (28)"),
    ),
    (
        "openai_remote_disconnect", "OpenAI 远端连接中断",
        ("unexpected_eof", "unexpected eof", "connection reset", "connection aborted", "connection closed", "remote end closed connection", "remote disconnected", "remotedisconnected", "server disconnected", "curl: (56)", "curl (56)"),
    ),
    (
        "openai_connection_failure", "OpenAI 连接建立失败",
        ("connectionerror", "failed to connect", "connection refused", "network is unreachable", "no route to host", "name resolution", "could not resolve host", "curl: (6)", "curl (6)", "curl: (7)", "curl (7)"),
    ),
)


@dataclass(frozen=True)
class ConnectivityClassification:
    """Stable, credential-free classification of one protocol outcome."""

    kind: str
    reason_code: str
    reason_label: str

    @property
    def eligible(self) -> bool:
        return self.kind == KIND_CONNECTIVITY


@dataclass(frozen=True)
class ProbeResult:
    """Safe result for one unauthenticated origin reachability probe."""

    origin: str
    reachable: bool
    status_code: int | None = None
    reason_code: str = ""

    def public(self) -> dict[str, Any]:
        return {"origin": self.origin, "reachable": self.reachable,
                "status_code": self.status_code, "reason_code": self.reason_code}


@dataclass(frozen=True)
class _PendingCallback:
    function: Callable[[dict[str, Any]], Any]
    payload: dict[str, Any]
    kind: str
    event_id: str
    revision: int
    proxy_fingerprint: str


def normalize_openai_origin(value: Any) -> str:
    """Return an allowed hostname without retaining paths or query strings."""

    text = str(value or "").strip().lower()
    if not text:
        return ""
    parsed = urlsplit(text if "://" in text else f"//{text}")
    hostname = str(parsed.hostname or "").lower().rstrip(".")
    return hostname if hostname in OPENAI_CONNECTIVITY_ORIGINS else ""


def proxy_fingerprint(proxy: Any) -> str:
    """Identify a proxy without publishing its URL or credentials."""

    text = str(proxy or "").strip() or "direct"
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    return f"sha256:{digest}"


def _status_code(value: Any) -> int | None:
    candidates = [value, getattr(value, "response", None)]
    if isinstance(value, Mapping):
        candidates.extend(value.get(key) for key in ("error", "response"))
    for candidate in candidates:
        if candidate is None:
            continue
        for key in ("_status", "status", "status_code", "http_status"):
            raw = (
                candidate.get(key)
                if isinstance(candidate, Mapping)
                else getattr(candidate, key, None)
            )
            try:
                status = int(raw)
            except (TypeError, ValueError):
                continue
            if 100 <= status <= 599:
                return status
    return None


def classify_openai_connectivity_failure(value: Any) -> ConnectivityClassification:
    """Separate transport failures from rate limits and business failures."""

    status = _status_code(value)
    if status == 429:
        return ConnectivityClassification(KIND_RATE_LIMITED, "openai_http_429", "OpenAI 请求触发限流")
    if status is not None:
        return ConnectivityClassification(KIND_OTHER, "openai_http_response", "OpenAI 服务已返回 HTTP 响应")

    type_name = "" if value is None else type(value).__name__
    text = f"{type_name}: {value or ''}".lower()
    text_status = _HTTP_STATUS_TEXT.search(text)
    if text_status and int(text_status.group(1)) == 429:
        return ConnectivityClassification(KIND_RATE_LIMITED, "openai_http_429", "OpenAI 请求触发限流")
    if text_status:
        return ConnectivityClassification(KIND_OTHER, "openai_http_response", "OpenAI 服务已返回 HTTP 响应")
    if re.search(r"\b429\b", text) and any(
        marker in text for marker in ("too many requests", "rate limit")
    ):
        return ConnectivityClassification(KIND_RATE_LIMITED, "openai_http_429", "OpenAI 请求触发限流")
    if any(marker in text for marker in _BUSINESS_MARKERS):
        return ConnectivityClassification(KIND_OTHER, "openai_business_error", "OpenAI 业务请求未完成")
    for code, label, markers in _CONNECTIVITY_RULES:
        if any(marker in text for marker in markers):
            return ConnectivityClassification(KIND_CONNECTIVITY, code, label)
    return ConnectivityClassification(KIND_OTHER, "openai_non_connectivity_error", "OpenAI 请求未完成，但不是连接故障")


def is_openai_connectivity_failure(value: Any) -> bool:
    return classify_openai_connectivity_failure(value).eligible


def _stopped(stop_event: Any) -> bool:
    if stop_event is None:
        return False
    checker = getattr(stop_event, "is_set", None)
    if callable(checker):
        return bool(checker())
    return bool(stop_event()) if callable(stop_event) else bool(stop_event)


class OpenAIAuthConnectivityRuntime:
    """Pause new Auth/Sentinel requests until both origins are reachable."""

    def __init__(
        self,
        *,
        state_path: Path | str | None = None,
        proxy: str | None = None,
        enabled: bool = True,
        failure_threshold: int = 2,
        failure_window_seconds: float = 60.0,
        probe_interval_seconds: float = 10.0,
        probe_timeout_seconds: float = 5.0,
        recovery_probe_rounds: int = 2,
        now_fn: Callable[[], float] = time.time,
        probe_fn: Callable[[str, str, float], Any] | None = None,
        session_factory: Callable[[], Any] | None = None,
        thread_factory: Callable[..., Any] = threading.Thread,
        id_factory: Callable[[], str] | None = None,
        on_outage: Callable[[dict[str, Any]], Any] | None = None,
        on_recovery: Callable[[dict[str, Any]], Any] | None = None,
        auto_start_worker: bool = True,
    ) -> None:
        self.state_path = Path(state_path) if state_path is not None else None
        self.enabled = bool(enabled)
        self.failure_threshold = max(2, int(failure_threshold))
        self.failure_window_seconds = max(1.0, float(failure_window_seconds))
        self.probe_interval_seconds = max(0.01, float(probe_interval_seconds))
        self.probe_timeout_seconds = max(0.01, float(probe_timeout_seconds))
        self.recovery_probe_rounds = max(1, int(recovery_probe_rounds))
        self.now_fn = now_fn
        self.probe_fn = probe_fn
        self.session_factory = session_factory
        self.thread_factory = thread_factory
        self.id_factory = id_factory or (lambda: uuid.uuid4().hex)
        self.on_outage = on_outage
        self.on_recovery = on_recovery
        self.auto_start_worker = bool(auto_start_worker)

        self.condition = threading.Condition(threading.RLock())
        self._callback_lock = threading.RLock()
        self._probe_round_lock = threading.Lock()
        self._worker_wake = threading.Event()
        self._probe_thread: Any = None
        self._closed = False
        self._proxy = str(proxy or "").strip()
        self._proxy_configured = proxy is not None
        self._proxy_fingerprint = proxy_fingerprint(self._proxy) if proxy is not None else ""

        self.status, self.paused = STATUS_UNKNOWN, False
        self.reason_code = self.reason_label = ""
        self.affected_origins: set[str] = set()
        self.event_id = ""
        self.revision = 0
        self.detected_at = self.recovered_at = 0.0
        self.next_probe_at = self.last_probe_at = 0.0
        self.successful_probe_rounds = 0
        self.failure_times = {origin: [] for origin in OPENAI_CONNECTIVITY_ORIGINS}
        self._outage_notified_event_id = self._recovery_notified_event_id = ""

        self._load_state()
        if self._proxy_configured:
            self._apply_proxy_locked(self._proxy, persist=False)
        if self.auto_start_worker and self.paused and self._proxy_configured:
            self.start_probe_worker()
    def _load_state(self) -> None:
        if self.state_path is None:
            return
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return
        if not isinstance(value, Mapping):
            return
        fingerprint = str(value.get("proxy_fingerprint") or "")
        if fingerprint and not _SAFE_FINGERPRINT.fullmatch(fingerprint):
            return
        status = str(value.get("status") or STATUS_UNKNOWN)
        if status not in _VALID_STATUSES:
            return
        reason_code = str(value.get("reason_code") or "")
        if reason_code and not _SAFE_REASON.fullmatch(reason_code):
            return
        event_id = str(value.get("event_id") or "")
        if event_id and (len(event_id) > 64 or not event_id.isalnum()):
            return

        self._proxy_fingerprint = fingerprint
        self.status = status
        self.paused = status in {STATUS_OUTAGE, STATUS_RECOVERING}
        self.reason_code = reason_code
        self.reason_label = OUTAGE_REASON_LABEL if self.paused and reason_code else ""
        self.event_id = event_id
        self.revision = self._safe_int(value.get("revision"), 0, 1_000_000_000)
        self.detected_at = self._safe_float(value.get("detected_at"))
        self.recovered_at = self._safe_float(value.get("recovered_at"))
        now = float(self.now_fn())
        loaded_next_probe_at = self._safe_float(value.get("next_probe_at"))
        self.next_probe_at = (
            min(loaded_next_probe_at or now, now + self.probe_interval_seconds)
            if self.paused
            else 0.0
        )
        self.last_probe_at = self._safe_float(value.get("last_probe_at"))
        self.successful_probe_rounds = self._safe_int(value.get("successful_probe_rounds"), 0, self.recovery_probe_rounds)
        self._outage_notified_event_id = self._safe_event_id(value.get("outage_notified_event_id"))
        self._recovery_notified_event_id = self._safe_event_id(value.get("recovery_notified_event_id"))

        raw_origins = value.get("affected_origins")
        if isinstance(raw_origins, list):
            self.affected_origins = {
                origin
                for origin in map(normalize_openai_origin, raw_origins)
                if origin
            }
        if not self.paused:
            self.affected_origins.clear()
        raw_times = value.get("failure_times")
        if isinstance(raw_times, Mapping):
            for origin in OPENAI_CONNECTIVITY_ORIGINS:
                rows = raw_times.get(origin)
                if not isinstance(rows, list):
                    continue
                self.failure_times[origin] = [
                    parsed
                    for parsed in (self._safe_float(row) for row in rows[-self.failure_threshold :])
                    if parsed > 0 and 0 <= now - parsed <= self.failure_window_seconds
                ]
    @staticmethod
    def _safe_float(value: Any) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return 0.0
        return parsed if 0 <= parsed <= 10_000_000_000 else 0.0
    @staticmethod
    def _safe_int(value: Any, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return minimum
        return max(minimum, min(maximum, parsed))
    @staticmethod
    def _safe_event_id(value: Any) -> str:
        text = str(value or "")
        return text if text.isalnum() and len(text) <= 64 else ""
    def _persist_payload_locked(self) -> dict[str, Any]:
        return {
            "version": 1,
            "status": self.status,
            "reason_code": self.reason_code,
            "affected_origins": sorted(self.affected_origins),
            "event_id": self.event_id,
            "revision": self.revision,
            "proxy_fingerprint": self._proxy_fingerprint,
            "detected_at": self.detected_at,
            "recovered_at": self.recovered_at,
            "last_probe_at": self.last_probe_at,
            "next_probe_at": self.next_probe_at,
            "successful_probe_rounds": self.successful_probe_rounds,
            "failure_times": {
                origin: list(self.failure_times[origin])
                for origin in OPENAI_CONNECTIVITY_ORIGINS
            },
            "outage_notified_event_id": self._outage_notified_event_id,
            "recovery_notified_event_id": self._recovery_notified_event_id,
        }
    def _persist_locked(self) -> None:
        if self.state_path is None:
            return
        try:
            atomic_write_private_json(self.state_path, self._persist_payload_locked())
        except OSError:
            pass
    def _bump_locked(self) -> None:
        self.revision += 1
        self._persist_locked()
    def _prune_failure_times_locked(self, now: float) -> None:
        for origin in OPENAI_CONNECTIVITY_ORIGINS:
            self.failure_times[origin] = [
                observed
                for observed in self.failure_times[origin]
                if 0 <= now - observed <= self.failure_window_seconds
            ]
        if not self.paused:
            self.affected_origins.intersection_update(
                origin
                for origin in OPENAI_CONNECTIVITY_ORIGINS
                if self.failure_times[origin]
            )
    def _apply_proxy_locked(self, proxy: str, *, persist: bool = True) -> bool:
        fingerprint = proxy_fingerprint(proxy)
        previous = self._proxy_fingerprint
        self._proxy = str(proxy or "").strip()
        self._proxy_configured = True
        if not previous:
            self._proxy_fingerprint = fingerprint
            if persist:
                self._bump_locked()
            return False
        if previous == fingerprint:
            return False

        self._proxy_fingerprint = fingerprint
        self.status = STATUS_UNKNOWN
        self.paused = False
        self.reason_code = ""
        self.reason_label = ""
        self.affected_origins.clear()
        self.event_id = ""
        self.detected_at = 0.0
        self.recovered_at = 0.0
        self.next_probe_at = 0.0
        self.last_probe_at = 0.0
        self.successful_probe_rounds = 0
        self.failure_times = {origin: [] for origin in OPENAI_CONNECTIVITY_ORIGINS}
        self._outage_notified_event_id = ""
        self._recovery_notified_event_id = ""
        if persist:
            self._bump_locked()
        self.condition.notify_all()
        self._worker_wake.set()
        return True
    def configure_proxy(self, proxy: str) -> bool:
        """Switch proxy identity, clearing an incident from a different route."""
        with self._callback_lock:
            with self.condition:
                changed = self._apply_proxy_locked(proxy)
                start_worker = self.auto_start_worker and self.paused
        if start_worker:
            self.start_probe_worker()
        return changed
    def begin_run(self, *, proxy: str, enabled: bool | None = None) -> dict[str, Any]:
        """Bind a batch to its explicit route while retaining a same-route outage."""
        if enabled is not None:
            self.set_enabled(enabled)
        self.configure_proxy(proxy)
        return self.snapshot()
    def set_enabled(self, enabled: bool) -> None:
        # The callback lock makes disabling a synchronous barrier: once this
        # method returns, no callback from the former generation can start.
        with self._callback_lock:
            with self.condition:
                desired = bool(enabled)
                if self.enabled == desired:
                    return
                self.enabled = desired
                if not desired:
                    self.status = STATUS_UNKNOWN
                    self.paused = False
                    self.reason_code = ""
                    self.reason_label = ""
                    self.affected_origins.clear()
                    self.next_probe_at = 0.0
                    self.successful_probe_rounds = 0
                    self.failure_times = {
                        origin: [] for origin in OPENAI_CONNECTIVITY_ORIGINS
                    }
                    self.condition.notify_all()
                    self._worker_wake.set()
                self._bump_locked()
    def observe_success(self, origin: Any) -> dict[str, Any]:
        normalized = normalize_openai_origin(origin)
        if not normalized:
            return {"kind": KIND_OTHER, "action": "ignored", "revision": self.revision}
        with self._callback_lock:
            with self.condition:
                if not self.enabled:
                    return {"kind": "success", "action": "ignored", "revision": self.revision}
                if self.paused:
                    return {
                        "kind": "success",
                        "action": "awaiting_probe_recovery",
                        "revision": self.revision,
                    }
                changed = bool(self.failure_times[normalized]) or self.status != STATUS_HEALTHY
                self.failure_times[normalized].clear()
                self.affected_origins.discard(normalized)
                if changed:
                    self.status = STATUS_HEALTHY
                    self.reason_code = ""
                    self.reason_label = ""
                    self._bump_locked()
                return {"kind": "success", "action": "healthy", "revision": self.revision}
    def observe_failure(self, origin: Any, value: Any) -> dict[str, Any]:
        normalized = normalize_openai_origin(origin)
        classification = classify_openai_connectivity_failure(value)
        decision = {
            "kind": classification.kind,
            "reason_code": classification.reason_code,
            "reason_label": classification.reason_label,
            "origin": normalized,
            "action": "ignored",
            "outage": False,
        }
        if not normalized or not classification.eligible:
            decision["revision"] = self.revision
            return decision

        callback: _PendingCallback | None = None
        start_worker = False
        with self._callback_lock:
            with self.condition:
                # Classification is deliberately outside the lock, so the
                # guard must be checked again at the state transition.
                if not self.enabled:
                    decision["revision"] = self.revision
                    return decision
                now = float(self.now_fn())
                self._prune_failure_times_locked(now)
                rows = self.failure_times[normalized]
                rows.append(now)
                self.failure_times[normalized] = rows[-self.failure_threshold :]
                self.affected_origins.add(normalized)
                if self.paused:
                    self.status = STATUS_OUTAGE
                    self.reason_code = classification.reason_code
                    self.reason_label = classification.reason_label
                    self.successful_probe_rounds = 0
                    self.next_probe_at = now + self.probe_interval_seconds
                    self._worker_wake.set()
                    decision["action"] = "already_paused"
                    decision["outage"] = True
                    self._bump_locked()
                    start_worker = self.auto_start_worker and self._proxy_configured
                elif len(rows) < self.failure_threshold:
                    decision["action"] = "cancel_expansion"
                    self._bump_locked()
                else:
                    self.status = STATUS_OUTAGE
                    self.paused = True
                    self.reason_code = classification.reason_code
                    self.reason_label = classification.reason_label
                    self.event_id = self._new_event_id()
                    self.detected_at = now
                    self.recovered_at = 0.0
                    self.last_probe_at = 0.0
                    self.next_probe_at = now + self.probe_interval_seconds
                    self.successful_probe_rounds = 0
                    self._recovery_notified_event_id = ""
                    self.revision += 1
                    callback = self._prepare_outage_callback_locked()
                    self._persist_locked()
                    decision["action"] = "pause"
                    decision["outage"] = True
                    start_worker = self.auto_start_worker and self._proxy_configured
                decision["event_id"] = self.event_id
                decision["revision"] = self.revision
            self._invoke(callback)
        if start_worker:
            self.start_probe_worker()
        return decision
    def _new_event_id(self) -> str:
        text = "".join(character for character in str(self.id_factory()) if character.isalnum())
        return text[:64] or uuid.uuid4().hex
    def _event_payload_locked(self, kind: str) -> dict[str, Any]:
        now = float(self.now_fn())
        return {
            "kind": kind,
            "event_id": self.event_id,
            "revision": self.revision,
            "node_code": OUTAGE_REASON_CODE,
            "node_label": "OpenAI 授权链路",
            "status": self.status,
            "reason_code": self.reason_code or OUTAGE_REASON_CODE,
            "reason_label": self.reason_label or OUTAGE_REASON_LABEL,
            "affected_origins": sorted(self.affected_origins),
            "detected_at": self.detected_at,
            "recovered_at": self.recovered_at,
            "duration_seconds": (
                max(0, int((self.recovered_at or now) - self.detected_at))
                if self.detected_at
                else 0
            ),
            "proxy_fingerprint": self._proxy_fingerprint,
        }
    def _prepare_outage_callback_locked(self) -> _PendingCallback | None:
        if not callable(self.on_outage) or self._outage_notified_event_id == self.event_id:
            return None
        self._outage_notified_event_id = self.event_id
        return _PendingCallback(
            self.on_outage,
            self._event_payload_locked("outage"),
            "outage",
            self.event_id,
            self.revision,
            self._proxy_fingerprint,
        )
    def _prepare_recovery_callback_locked(self, *, recovered_at: float) -> _PendingCallback | None:
        self.recovered_at = recovered_at
        if not callable(self.on_recovery) or self._recovery_notified_event_id == self.event_id:
            return None
        self._recovery_notified_event_id = self.event_id
        return _PendingCallback(
            self.on_recovery,
            self._event_payload_locked("recovery"),
            "recovery",
            self.event_id,
            self.revision,
            self._proxy_fingerprint,
        )
    def _invoke(
        self,
        callback: _PendingCallback | None,
    ) -> None:
        if callback is None:
            return
        with self._callback_lock:
            with self.condition:
                expected_state = (
                    self.paused
                    if callback.kind == "outage"
                    else self.status == STATUS_HEALTHY and not self.paused
                )
                valid = (
                    self.enabled
                    and not self._closed
                    and expected_state
                    and callback.event_id == self.event_id
                    and callback.revision == self.revision
                    and callback.proxy_fingerprint == self._proxy_fingerprint
                )
            if not valid:
                return
            try:
                callback.function(callback.payload)
            except Exception:
                pass
    def wait_until_available(
        self,
        *,
        stop_event: Any = None,
        timeout: float | None = None,
    ) -> bool:
        """Wait without treating a known outage as a request failure."""
        started = time.monotonic()
        with self.condition:
            while self.enabled and self.paused:
                if _stopped(stop_event):
                    return False
                if timeout is not None:
                    remaining = float(timeout) - (time.monotonic() - started)
                    if remaining <= 0:
                        return False
                    self.condition.wait(timeout=min(0.1, remaining))
                else:
                    self.condition.wait(timeout=0.1)
            return not _stopped(stop_event)

    def wake_waiters(self) -> None:
        with self.condition:
            self.condition.notify_all()
        self._worker_wake.set()
    def _default_session_factory(self) -> Any:
        from curl_cffi import requests

        return requests.Session(impersonate="chrome")

    @staticmethod
    def _reachable_status(status: Any) -> bool:
        try:
            parsed = int(status)
        except (TypeError, ValueError):
            return False
        return 200 <= parsed <= 499 and parsed != 429

    def _probe_endpoint(self, origin: str, proxy: str | None = None) -> ProbeResult:
        probe_proxy = self._proxy if proxy is None else proxy
        if self.probe_fn is not None:
            try:
                return self._coerce_probe_result(
                    origin,
                    self.probe_fn(origin, probe_proxy, self.probe_timeout_seconds),
                )
            except Exception:
                return ProbeResult(origin, False, reason_code="probe_transport_error")

        session = None
        try:
            session = (self.session_factory or self._default_session_factory)()
            if hasattr(session, "trust_env"):
                session.trust_env = False
            cookies = getattr(session, "cookies", None)
            clear_cookies = getattr(cookies, "clear", None)
            if callable(clear_cookies):
                clear_cookies()
            kwargs: dict[str, Any] = {
                "headers": {"Accept": "*/*"},
                "timeout": self.probe_timeout_seconds,
                "allow_redirects": False,
            }
            if probe_proxy:
                kwargs["proxies"] = {"http": probe_proxy, "https": probe_proxy}
            response = session.get(f"https://{origin}/", **kwargs)
            status = _status_code(response)
            return ProbeResult(
                origin,
                self._reachable_status(status),
                status_code=status,
                reason_code=("" if self._reachable_status(status) else "probe_http_unreachable"),
            )
        except Exception:
            return ProbeResult(origin, False, reason_code="probe_transport_error")
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

    def _coerce_probe_result(self, origin: str, value: Any) -> ProbeResult:
        if isinstance(value, ProbeResult):
            return ProbeResult(
                origin,
                bool(value.reachable),
                value.status_code,
                str(value.reason_code or "")[:100],
            )
        if isinstance(value, bool):
            return ProbeResult(origin, value, reason_code="" if value else "probe_failed")
        if isinstance(value, int):
            return ProbeResult(
                origin,
                self._reachable_status(value),
                value,
                "" if self._reachable_status(value) else "probe_http_unreachable",
            )
        status = _status_code(value)
        if isinstance(value, Mapping) and "reachable" in value:
            reachable = bool(value.get("reachable"))
        else:
            reachable = self._reachable_status(status)
        return ProbeResult(
            origin,
            reachable,
            status,
            "" if reachable else "probe_failed",
        )

    def run_probe_round(self) -> dict[str, Any]:
        """Run one parallel two-origin probe round, primarily for the worker/tests."""
        with self._probe_round_lock:
            with self.condition:
                if not self.enabled or not self.paused or not self._proxy_configured:
                    return {
                        "complete": False,
                        "recovered": False,
                        "status": self.status,
                        "revision": self.revision,
                        "results": [],
                    }
                probe_proxy = self._proxy
                probe_generation = (
                    self._proxy_fingerprint,
                    self.event_id,
                    self.revision,
                )
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="openai-probe") as pool:
                futures = {
                    origin: pool.submit(self._probe_endpoint, origin, probe_proxy)
                    for origin in OPENAI_CONNECTIVITY_ORIGINS
                }
                results = [futures[origin].result() for origin in OPENAI_CONNECTIVITY_ORIGINS]

            callback: _PendingCallback | None = None
            recovered = False
            with self._callback_lock:
                with self.condition:
                    current_generation = (
                        self._proxy_fingerprint,
                        self.event_id,
                        self.revision,
                    )
                    if not self.enabled or not self.paused or probe_generation != current_generation:
                        return {
                            "complete": False,
                            "recovered": False,
                            "status": self.status,
                            "revision": self.revision,
                            "results": [result.public() for result in results],
                        }
                    now = float(self.now_fn())
                    self.last_probe_at = now
                    complete_success = all(result.reachable for result in results)
                    if complete_success:
                        self.successful_probe_rounds += 1
                        if self.successful_probe_rounds >= self.recovery_probe_rounds:
                            self.status = STATUS_HEALTHY
                            self.paused = False
                            self.next_probe_at = 0.0
                            self.failure_times = {
                                origin: [] for origin in OPENAI_CONNECTIVITY_ORIGINS
                            }
                            recovered = True
                            self.revision += 1
                            callback = self._prepare_recovery_callback_locked(recovered_at=now)
                            self.affected_origins.clear()
                            self.reason_code = ""
                            self.reason_label = ""
                            self._persist_locked()
                            self.condition.notify_all()
                            self._worker_wake.set()
                        else:
                            self.status = STATUS_RECOVERING
                            self.next_probe_at = now + self.probe_interval_seconds
                            self._bump_locked()
                    else:
                        self.status = STATUS_OUTAGE
                        self.successful_probe_rounds = 0
                        self.next_probe_at = now + self.probe_interval_seconds
                        self.affected_origins.update(
                            result.origin for result in results if not result.reachable
                        )
                        self._bump_locked()
                    report = {
                        "complete": True,
                        "successful": complete_success,
                        "recovered": recovered,
                        "status": self.status,
                        "successful_rounds": self.successful_probe_rounds,
                        "required_rounds": self.recovery_probe_rounds,
                        "revision": self.revision,
                        "results": [result.public() for result in results],
                    }
                self._invoke(callback)
            return report

    def start_probe_worker(self) -> bool:
        with self.condition:
            if (
                self._closed
                or not self.enabled
                or not self.paused
                or not self._proxy_configured
            ):
                return False
            alive = getattr(self._probe_thread, "is_alive", None)
            if self._probe_thread is not None and (not callable(alive) or alive()):
                return False
            self._worker_wake.clear()
            self._probe_thread = self.thread_factory(
                target=self._probe_worker,
                name="openai-auth-connectivity-probe",
                daemon=True,
            )
            self._probe_thread.start()
            return True

    def _probe_worker(self) -> None:
        worker = threading.current_thread()
        try:
            while True:
                with self.condition:
                    if self._closed or not self.enabled or not self.paused:
                        return
                    delay = max(0.0, self.next_probe_at - float(self.now_fn()))
                if self._worker_wake.wait(timeout=delay):
                    self._worker_wake.clear()
                    continue
                self.run_probe_round()
        finally:
            self._finish_probe_worker(worker)

    def _finish_probe_worker(self, worker: Any) -> None:
        restart = False
        with self.condition:
            if self._probe_thread is worker:
                self._probe_thread = None
                restart = (
                    not self._closed
                    and self.enabled
                    and self.paused
                    and self._proxy_configured
                    and self.auto_start_worker
                )
        if restart:
            self.start_probe_worker()

    def close(self) -> None:
        with self._callback_lock:
            with self.condition:
                self._closed = True
                self.condition.notify_all()
            self._worker_wake.set()

    report_failure = observe_failure
    report_success = observe_success
    stop = close

    def snapshot(self) -> dict[str, Any]:
        with self.condition:
            now = float(self.now_fn())
            counts = {
                origin: sum(
                    1
                    for observed in self.failure_times[origin]
                    if 0 <= now - observed <= self.failure_window_seconds
                )
                for origin in OPENAI_CONNECTIVITY_ORIGINS
            }
            return {
                "status": self.status,
                "runtime_epoch": RUNTIME_EPOCH,
                "enabled": self.enabled,
                "paused": self.paused,
                "pause_reason": PAUSE_REASON if self.paused else "",
                "reason_code": self.reason_code,
                "reason_label": self.reason_label,
                "affected_origins": sorted(self.affected_origins),
                "event_id": self.event_id,
                "incident_id": self.event_id,
                "revision": self.revision,
                "proxy_fingerprint": self._proxy_fingerprint,
                "detected_at": self.detected_at,
                "recovered_at": self.recovered_at,
                "failure_counts": counts,
                "probe_successful_rounds": self.successful_probe_rounds,
                "probe_required_rounds": self.recovery_probe_rounds,
                "last_probe_at": self.last_probe_at,
                "next_probe_at": self.next_probe_at,
                "next_probe_in_seconds": (
                    max(0, int(self.next_probe_at - now)) if self.paused else 0
                ),
            }
