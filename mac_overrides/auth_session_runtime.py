"""Per-task authentication context tracking and safe session invalidation."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import threading
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit


SESSION_INVALID_MARKERS = (
    "oauth_session_invalid",
    "sign-in session is no longer valid",
    "session is no longer valid",
)


def is_session_invalid(value: Any) -> bool:
    if isinstance(value, Mapping):
        candidates = [value.get("error"), value.get("message"), value.get("code")]
    else:
        candidates = [value]
    text = " ".join(str(item or "") for item in candidates).lower()
    return any(marker in text for marker in SESSION_INVALID_MARKERS)


def _short_fingerprint(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]


def _safe_path(value: Any) -> str:
    try:
        parsed = urlsplit(str(value or ""))
    except (TypeError, ValueError):
        return ""
    if not parsed.path:
        return ""
    return parsed.path[:180]


def _response_status(response: Any) -> int | None:
    if not isinstance(response, Mapping):
        return None
    for key in ("_status", "status_code", "http_status", "status"):
        try:
            value = int(response.get(key))
        except (TypeError, ValueError):
            continue
        if 100 <= value <= 599:
            return value
    return None


def _response_page_type(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page")
    if isinstance(page, Mapping) and page.get("type"):
        return str(page.get("type"))[:80]
    return str(response.get("page_type") or "")[:80]


@dataclass
class AuthSessionContext:
    task_id: str
    email: str = ""
    generation: int = 0
    node_instance_id: str = ""
    transport_instance_id: str = ""
    current_stage: str = ""
    last_success_stage: str = ""
    latest_continue_path: str = ""
    invalid: bool = False
    invalid_code: str = ""
    fresh_oauth_required: bool = False
    request_count: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)

    def new_generation(self, *, node_instance_id: Any = "", transport_instance_id: Any = "") -> int:
        self.generation += 1
        self.node_instance_id = _short_fingerprint(node_instance_id) or self.node_instance_id
        self.transport_instance_id = _short_fingerprint(transport_instance_id) or self.transport_instance_id
        self.invalid = False
        self.invalid_code = ""
        self.fresh_oauth_required = False
        self.latest_continue_path = ""
        self.current_stage = ""
        return self.generation

    def observe_stage(self, stage: Any, *, continue_url: Any = "", success: bool = False) -> None:
        value = str(stage or "").strip()
        if value:
            self.current_stage = value
        path = _safe_path(continue_url)
        if path:
            self.latest_continue_path = path
        if success and value:
            self.last_success_stage = value

    def begin_request(
        self,
        *,
        endpoint: Any,
        stage: Any,
        response: Any = None,
        cookies_present: bool | None = None,
        csrf_present: bool | None = None,
        proxy: Any = "",
    ) -> dict[str, Any]:
        self.request_count += 1
        result = {
            "request_context_id": f"{self.task_id}:{self.generation}:{self.request_count}",
            "endpoint": str(endpoint or "")[:160],
            "stage": str(stage or self.current_stage or "")[:80],
            "session_generation": self.generation,
            "session_fingerprint": self.transport_instance_id,
            "continue_path": self.latest_continue_path,
            "cookies_present": cookies_present,
            "csrf_present": csrf_present,
            "proxy_fingerprint": _short_fingerprint(proxy),
        }
        if isinstance(response, Mapping):
            result["response_status"] = _response_status(response)
            result["page_type"] = _response_page_type(response)
            result["continue_path"] = _safe_path(response.get("continue_url")) or result["continue_path"]
        self.events.append(result)
        del self.events[:-30]
        return dict(result)

    def finish_request(
        self,
        request_context_id: Any,
        *,
        response: Any = None,
        continue_url: Any = "",
    ) -> dict[str, Any] | None:
        wanted = str(request_context_id or "").strip()
        if not wanted:
            return None
        for event in reversed(self.events):
            if event.get("request_context_id") != wanted:
                continue
            if isinstance(response, Mapping):
                event["response_status"] = _response_status(response)
                event["page_type"] = _response_page_type(response)
                event["continue_path"] = _safe_path(response.get("continue_url")) or event.get("continue_path", "")
            path = _safe_path(continue_url)
            if path:
                event["continue_path"] = path
                self.latest_continue_path = path
            return dict(event)
        return None

    def invalidate(self, value: Any = "") -> None:
        self.invalid = True
        self.fresh_oauth_required = True
        self.invalid_code = "oauth_session_invalid" if is_session_invalid(value) else "auth_session_invalid"
        self.latest_continue_path = ""
        self.node_instance_id = ""
        self.transport_instance_id = ""

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "current_stage": self.current_stage,
            "last_success_stage": self.last_success_stage,
            "generation": self.generation,
            "session_fingerprint": self.transport_instance_id,
            "invalid": self.invalid,
            "fresh_oauth_required": self.fresh_oauth_required,
            "invalid_code": self.invalid_code,
            "events": [dict(item) for item in self.events[-10:]],
        }


class AuthSessionRegistry:
    """Keep authentication state isolated by task without retaining credentials."""

    def __init__(self, *, cancel_sms: Callable[[str, str], Any] | None = None) -> None:
        self._lock = threading.RLock()
        self._items: dict[str, AuthSessionContext] = {}
        self._cancel_sms = cancel_sms

    def set_cancel_sms(self, callback: Callable[[str, str], Any] | None) -> None:
        with self._lock:
            self._cancel_sms = callback

    def get(self, task_id: Any, *, email: Any = "") -> AuthSessionContext:
        key = str(task_id or "").strip()
        if not key:
            return AuthSessionContext(task_id="")
        with self._lock:
            item = self._items.get(key)
            if item is None:
                item = AuthSessionContext(task_id=key, email=str(email or "").strip().lower())
                self._items[key] = item
            elif email and not item.email:
                item.email = str(email).strip().lower()
            return item

    def start_generation(self, task_id: Any, *, email: Any = "", node_instance_id: Any = "", transport_instance_id: Any = "") -> AuthSessionContext:
        item = self.get(task_id, email=email)
        with self._lock:
            item.new_generation(node_instance_id=node_instance_id, transport_instance_id=transport_instance_id)
            return item

    def observe(self, task_id: Any, stage: Any, *, email: Any = "", continue_url: Any = "", success: bool = False) -> AuthSessionContext:
        item = self.get(task_id, email=email)
        with self._lock:
            item.observe_stage(stage, continue_url=continue_url, success=success)
            return item

    def invalidate(self, task_id: Any, value: Any = "", *, stage: Any = "", email: Any = "") -> AuthSessionContext:
        item = self.get(task_id, email=email)
        with self._lock:
            if stage:
                item.current_stage = str(stage)
            item.invalidate(value)
        if callable(self._cancel_sms) and item.task_id:
            try:
                self._cancel_sms(item.task_id, "oauth_session_invalid")
            except Exception:
                pass
        return item

    def clear(self, task_id: Any) -> None:
        with self._lock:
            self._items.pop(str(task_id or "").strip(), None)

    def public_snapshot(self, task_id: Any = "") -> dict[str, Any] | list[dict[str, Any]]:
        with self._lock:
            if task_id:
                item = self._items.get(str(task_id).strip())
                return item.public_snapshot() if item is not None else {}
            return [item.public_snapshot() for item in self._items.values()]
