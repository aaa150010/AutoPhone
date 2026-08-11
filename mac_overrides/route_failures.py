"""Consistent structured failure payloads for dashboard API routes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

try:
    from .error_observability import classify_failure, sanitize_failure_detail
except ImportError:  # Loaded as a top-level runtime override.
    from error_observability import classify_failure, sanitize_failure_detail  # type: ignore[no-redef]


def failure_payload(
    error: Any,
    *,
    result: Any = None,
    progress: Any = None,
    state: Any = None,
    secrets: Sequence[Any] = (),
) -> dict[str, Any]:
    failure = classify_failure(result, error, progress, secrets=secrets)
    payload: dict[str, Any] = {
        "ok": False,
        "code": failure["error_code"],
        "node_code": failure["node_code"],
        "node_label": failure["node_label"],
        "error_code": failure["error_code"],
        "error": failure["public_message"],
        "failure": failure,
    }
    if state is not None:
        payload["state"] = state
    return payload


def explicit_failure_payload(
    *,
    node_code: str,
    node_label: str,
    error_code: str,
    cause: Any,
    state: Any = None,
    retryable: bool = False,
    http_status: int | None = None,
    action_hint: str = "",
    secrets: Sequence[Any] = (),
) -> dict[str, Any]:
    safe_cause = sanitize_failure_detail(cause, secrets=secrets, limit=500) or "服务端未返回错误详情"
    failure = {
        "node_code": sanitize_failure_detail(node_code, limit=80),
        "node_label": sanitize_failure_detail(node_label, limit=80),
        "error_code": sanitize_failure_detail(error_code, limit=80),
        "provider_code": "",
        "public_message": f"{node_label}失败：{safe_cause}",
        "technical_summary": safe_cause,
        "retryable": bool(retryable),
        "http_status": http_status if http_status is not None and 100 <= http_status <= 599 else None,
        "action_hint": sanitize_failure_detail(action_hint, limit=500),
        "diagnostic_action": "",
    }
    payload: dict[str, Any] = {
        "ok": False,
        "code": failure["error_code"],
        "node_code": failure["node_code"],
        "node_label": failure["node_label"],
        "error_code": failure["error_code"],
        "error": failure["public_message"],
        "failure": failure,
    }
    if state is not None:
        payload["state"] = state
    return payload


def with_failure(value: Mapping[str, Any], failure: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    payload["failure"] = dict(failure)
    payload["error"] = str(failure.get("public_message") or payload.get("error") or "")
    payload.setdefault("code", failure.get("error_code"))
    return payload


__all__ = ["explicit_failure_payload", "failure_payload", "with_failure"]
