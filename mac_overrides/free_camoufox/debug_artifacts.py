"""Credential-safe debug artifact boundary for Camoufox pages.

The production implementation historically lived in the large runtime module.
This adapter exposes a narrow service API and delegates to that implementation
when available, while retaining a conservative local fallback for callers that
only need text sanitization or an event ring buffer.  No browser dependency is
imported at module import time.
"""

from __future__ import annotations

from collections import deque
import copy
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import threading
import tempfile
import time
from typing import Any, Mapping
from urllib.parse import urlsplit


def _legacy_runtime() -> Any | None:
    try:
        from .. import free_camoufox_runtime
        return free_camoufox_runtime
    except Exception:  # pragma: no cover - top-level recovery import
        try:
            import free_camoufox_runtime  # type: ignore
            return free_camoufox_runtime
        except Exception:
            return None


def sanitize_debug_text(value: Any, limit: int = 800, *, mask_bare_numeric: bool = True) -> str:
    """Use the hardened legacy sanitizer, with a fail-closed fallback."""

    runtime = _legacy_runtime()
    sanitizer = getattr(runtime, "_sanitize_debug_text", None) if runtime else None
    if callable(sanitizer):
        try:
            return _redact_fallback(
                str(sanitizer(value, limit, mask_bare_numeric=mask_bare_numeric) or ""),
                limit,
            )
        except TypeError:
            try:
                return _redact_fallback(str(sanitizer(value, limit) or ""), limit)
            except Exception:
                pass
        except Exception:
            pass
    return _redact_fallback(str(value or ""), limit)


def _redact_fallback(value: str, limit: int = 800) -> str:
    """Apply a final fail-closed pass even when the legacy sanitizer is used."""

    text = str(value or "")[: max(0, int(limit))]
    # A fallback must never claim to be complete redaction; mask the most
    # common secret-shaped values before returning anything to a caller.
    import re
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<邮箱>", text)
    text = re.sub(r"(?<!\d)\d{4,7}(?!\d)", "<验证码>", text)
    text = re.sub(r"(?i)\b(?:bearer|basic)\s+[^\s,;]+", "<授权头>", text)
    text = re.sub(
        r"(?i)\b(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|password|cookie|secret|authorization)\s*[:=]\s*[^\s,;]+",
        r"\1=<已隐藏>",
        text,
    )
    text = re.sub(r"(?i)(https?|socks5?h?)://[^\s<>\"']+", "<地址已隐藏>", text)
    return text[: max(0, int(limit))]


@dataclass(slots=True)
class DebugEventBuffer:
    """Thread-safe bounded event buffer with strict field sanitization."""

    limit: int = 100
    _events: deque[dict[str, Any]] = field(init=False, repr=False)
    _lock: threading.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Respect the caller's bound exactly.  A previous defensive minimum
        # of ten made ``limit=1`` retain ten events, which is surprising for
        # per-page traces and can multiply memory use across a browser pool.
        try:
            requested_limit = int(self.limit)
        except (TypeError, ValueError, OverflowError):
            requested_limit = 100
        self.limit = max(1, requested_limit)
        self._events = deque(maxlen=self.limit)
        self._lock = threading.Lock()

    def add(self, kind: str, **fields: Any) -> None:
        safe_kind = sanitize_debug_text(kind, 40, mask_bare_numeric=False) or "event"
        event: dict[str, Any] = {
            "kind": safe_kind,
            "at": round(time.time(), 3),
        }
        for key, value in fields.items():
            if value in (None, ""):
                continue
            normalized_key = sanitize_debug_text(key, 40, mask_bare_numeric=False)
            if not normalized_key:
                continue
            if _is_sensitive_key(normalized_key):
                event[normalized_key] = "<已隐藏>"
            elif normalized_key.casefold() in {"url", "safe_page", "href"}:
                event[normalized_key] = _safe_debug_url(value)
            else:
                event[normalized_key] = sanitize_debug_text(value, 300)
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            # Copy nested values as well so a diagnostic consumer cannot
            # mutate the retained trace while another thread is appending.
            return [copy.deepcopy(item) for item in self._events]


def _safe_debug_url(value: Any) -> str:
    """Return an origin/path projection for fallback trace events."""

    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.hostname:
            return ""
        host = parsed.hostname
        trusted = (
            host.casefold() == "chatgpt.com"
            or host.casefold().endswith(".chatgpt.com")
            or host.casefold() == "openai.com"
            or host.casefold().endswith(".openai.com")
        )
        path = parsed.path or "/"
        if not trusted:
            path = "/[路径已隐藏]"
        return f"{parsed.scheme.lower()}://{host}{path}"[:500]
    except Exception:
        return ""


class DebugArtifactService:
    """Facade for capturing and retaining a failed headed page."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root).expanduser() if root else None

    async def capture(
        self,
        *,
        page: Any,
        session_id: str,
        artifact_id: str,
        summary: Mapping[str, Any],
        trace: Any,
    ) -> dict[str, Any]:
        runtime = _legacy_runtime()
        capture = getattr(runtime, "_capture_debug_artifact", None) if runtime else None
        if callable(capture):
            try:
                result = await capture(
                    page=page,
                    artifact_root=self.root,
                    session_id=session_id,
                    artifact_id=artifact_id,
                    summary=summary,
                    trace=trace,
                )
                if isinstance(result, Mapping):
                    return _safe_capture_result(result, artifact_id=artifact_id, root=self.root)
                return {
                    "artifact_id": str(artifact_id),
                    "artifact_path": "",
                    "screenshot": "skipped",
                    "screenshot_reason": "现场实现返回格式无效",
                }
            except Exception as exc:
                return {
                    "artifact_id": str(artifact_id),
                    "artifact_path": "",
                    "screenshot": "skipped",
                    "screenshot_reason": f"现场采集失败（{type(exc).__name__}）",
                }
        return {
            "artifact_id": str(artifact_id),
            "artifact_path": "",
            "screenshot": "skipped",
            "screenshot_reason": "未配置现场目录或兼容实现不可用",
        }

    def trim(self, *, current_session: str = "") -> None:
        if self.root is None:
            return
        runtime = _legacy_runtime()
        trim = getattr(runtime, "_trim_debug_artifacts", None) if runtime else None
        if callable(trim):
            try:
                trim(self.root, current_session=current_session)
            except Exception:
                return


def page_debug_trace(page: Any) -> Any:
    """Attach/get the canonical trace object for a page."""

    runtime = _legacy_runtime()
    factory = getattr(runtime, "_page_debug_trace", None) if runtime else None
    if callable(factory):
        return factory(page)
    trace = getattr(page, "_gptphone_debug_trace", None)
    if isinstance(trace, DebugEventBuffer):
        return trace
    trace = DebugEventBuffer()
    try:
        setattr(page, "_gptphone_debug_trace", trace)
    except Exception:
        pass
    return trace


def write_json_atomic(path: str | Path, payload: Mapping[str, Any]) -> None:
    """Small safe JSON writer for independently generated test artifacts."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    safe_payload = _safe_artifact_mapping(payload)
    temporary_handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
        delete=False,
    )
    temporary = Path(temporary_handle.name)
    try:
        with temporary_handle:
            temporary_handle.write(json.dumps(safe_payload, ensure_ascii=False, indent=2))
            temporary_handle.flush()
            os.fsync(temporary_handle.fileno())
        temporary.replace(target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


_SENSITIVE_FIELD_KEYS = frozenset({
    "token", "access_token", "refresh_token", "id_token", "authorization",
    "password", "cookie", "secret", "code", "otp", "email", "phone",
    "proxy", "proxy_url", "mailbox_url", "credential", "csrf", "state", "nonce",
})


def _is_sensitive_key(value: Any) -> bool:
    key = str(value or "").strip().casefold().replace("-", "_")
    if key in _SENSITIVE_FIELD_KEYS:
        return True
    return any(marker in key for marker in (
        "token", "password", "cookie", "secret", "credential", "authorization",
        "mailbox_url", "proxy_url", "otp", "verification_code", "csrf", "nonce",
    ))


_SAFE_ARTIFACT_KEYS = frozenset({
    "artifact_id", "task_id", "incident_id", "node_code", "node_label",
    "error_code", "page_type", "safe_page", "proxy_fingerprint", "created_at",
    "artifact_path", "screenshot", "screenshot_reason", "dom_file", "events", "elements", "tag",
    "role", "type", "aria_label", "text", "href", "url", "kind", "at", "status",
    "message", "error", "failure", "method", "name", "timestamp",
})


def _safe_capture_result(
    value: Mapping[str, Any], *, artifact_id: str, root: Path | None,
) -> dict[str, Any]:
    """Project a legacy capture response before crossing the facade boundary."""
    projected = _safe_artifact_mapping(value)
    projected["artifact_id"] = sanitize_debug_text(artifact_id, 120, mask_bare_numeric=False)
    # A path returned by a compatibility implementation is accepted only
    # after it is proven to live under the configured artifact root.
    projected["artifact_path"] = ""
    raw_path = str(value.get("artifact_path") or "").strip()
    if raw_path and root is not None:
        try:
            candidate = Path(raw_path).expanduser().resolve()
            root_path = root.expanduser().resolve()
            if candidate == root_path or root_path in candidate.parents:
                projected["artifact_path"] = str(candidate)
        except (OSError, RuntimeError, ValueError):
            pass
    # Keep the stable response shape expected by existing callers even when a
    # legacy implementation returns extra/private fields.
    projected.setdefault("artifact_path", "")
    projected.setdefault("screenshot", "skipped")
    projected.setdefault("screenshot_reason", "")
    return projected


def _safe_artifact_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project arbitrary mappings into the debug artifact allow-list."""

    result: dict[str, Any] = {}
    for key, item in value.items():
        normalized = str(key or "").strip()
        if normalized not in _SAFE_ARTIFACT_KEYS:
            continue
        if normalized in {"safe_page", "href", "url"}:
            safe = _safe_debug_url(item)
            if safe:
                result[normalized] = safe
        elif normalized == "events" and isinstance(item, list):
            result[normalized] = [
                _safe_artifact_mapping(row) if isinstance(row, Mapping) else sanitize_debug_text(row, 240)
                for row in item[:100]
            ]
        elif isinstance(item, Mapping):
            result[normalized] = _safe_artifact_mapping(item)
        elif isinstance(item, (list, tuple)):
            result[normalized] = [sanitize_debug_text(row, 240) for row in item[:100]]
        elif normalized == "created_at":
            try:
                number = float(item)
                if 0 <= number <= 4_102_444_800:
                    result[normalized] = number
            except (TypeError, ValueError, OverflowError):
                continue
        else:
            safe = sanitize_debug_text(item, 500, mask_bare_numeric=False)
            if safe:
                result[normalized] = safe
    return result


def __getattr__(name: str) -> Any:
    """Expose the canonical trace type for older diagnostic integrations."""

    if name == "_DebugTrace":
        runtime = _legacy_runtime()
        value = getattr(runtime, name, None) if runtime else None
        if value is not None:
            return value
        return DebugEventBuffer
    if name in {
        "_safe_event_url", "_safe_incident_id", "_safe_debug_task_id",
        "_safe_proxy_fingerprint", "_safe_body_markers", "_capture_debug_dom",
        "_capture_debug_artifact", "_screenshot_safety_check", "_atomic_artifact_write",
        "_trim_debug_artifacts",
    }:
        runtime = _legacy_runtime()
        value = getattr(runtime, name, None) if runtime else None
        if value is not None:
            return value
        raise AttributeError(name)
    raise AttributeError(name)


__all__ = [
    "DebugArtifactService",
    "DebugEventBuffer",
    "_DebugTrace",
    "page_debug_trace",
    "sanitize_debug_text",
    "write_json_atomic",
]
