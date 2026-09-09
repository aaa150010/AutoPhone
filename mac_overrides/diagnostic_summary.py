"""Redaction primitives and first-failure root-cause selection for the diagnostic store."""

from __future__ import annotations

import json
import math
import re
import string
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

try:
    from .error_observability import sanitize_failure_detail
    from .free_register_common import safe_log_message
except ImportError:  # pragma: no cover
    from error_observability import sanitize_failure_detail  # type: ignore[no-redef]
    from free_register_common import safe_log_message  # type: ignore[no-redef]


_SAFE_ID = set(string.ascii_letters + string.digits + "_.:-")
_SAFE_CHAIN = set(string.ascii_letters + string.digits + "_.:-")
_FAILURE_MAPPING_KEYS = (
    "node_code", "node_label", "error_code", "provider_code",
    "public_message", "technical_summary", "retryable", "http_status",
    "action_hint", "diagnostic_action", "diagnostic", "page_type",
    "safe_page", "content_type", "session_rebuilds", "retry_after_seconds",
    "declared_scheme", "transport_scheme", "target_domain", "request_stage",
    "retry_count", "transport_error_code",
    "debug_session_id", "debug_artifact_id", "artifact_id",
    # Mailbox parser diagnostics reference a separate redacted sample store.
    "sample_id", "reason",
)
_TRANSPORT_MAPPING_KEYS = (
    "failure_count", "total_count", "target_domain", "nodes",
    "http_statuses", "provider_statuses", "provider_codes",
    "declared_schemes", "effective_schemes", "proxy_fingerprints",
    "health_write_failures", "request_stage", "http_status", "content_type",
    "authorize_url_present", "final_host", "final_path",
)


def _safe_text(value: Any, limit: int = 500) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    return " ".join(text.split())[:limit]


def _safe_occurred_at(value: Any, fallback: str) -> str:
    """Keep event timestamps parseable so arbitrary input cannot be persisted."""
    text = _safe_text(value, 40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return fallback


def _safe_message(value: Any, limit: int = 500) -> str:
    text = _safe_text(value, limit)
    if not text:
        return ""
    try:
        redacted = sanitize_failure_detail(safe_log_message(text), limit=limit)
    except Exception:
        return "[已省略未通过脱敏校验的内容]"
    # The shared redactor intentionally keeps some transport context for the
    # ordinary log panel. The diagnostic index is stricter: no raw email,
    # bearer value, URL query credential, proxy credential, or phone number.
    redacted = re.sub(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}", "<credential>", redacted)
    redacted = re.sub(r"(?i)(authorization\s*=\s*\*+\s+)[^\s]+", r"\1<credential>", redacted)
    redacted = re.sub(
        r"(?i)([?&](?:code|state|token|access_token|refresh_token|id_token|authorization|client_secret|otp|email|phone)=[^&\s]+)",
        lambda match: f"{match.group(1).split('=', 1)[0]}=********",
        redacted,
    )
    redacted = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", redacted)
    redacted = re.sub(r"(?i)(https?://)([^\s/@:]+):([^\s/@]+)@", r"\1<credential>@", redacted)
    redacted = re.sub(r"(?i)\b(?:https?|socks[45h]?)://[^\s]+", "<url>", redacted)
    redacted = re.sub(r"(?<![A-Za-z0-9])\+?\d[\d ()-]{7,}\d(?![A-Za-z0-9])", "<phone>", redacted)
    return redacted[:limit]


def _safe_id(value: Any, limit: int = 180) -> str:
    # Store-side contract: character-level projection. Unlike the writer's
    # ``_safe_id`` (whole-string fullmatch, invalid input becomes ""), this
    # fallback also sanitizes legacy/untrusted field values read back from
    # the store, so a partially valid identifier keeps its readable part
    # instead of disappearing from denormalized summaries. Generated event
    # IDs (uuid4 hex) and incident IDs (``LOG-`` format) pass both sides
    # unchanged.
    text = _safe_text(value, limit)
    return "".join(char for char in text if char in _SAFE_ID)[:limit]


def _safe_mapping(value: Any, *, allowed_keys: Sequence[str]) -> dict[str, Any]:
    """Project an untrusted diagnostic map through a scalar allowlist.

    Diagnostic JSON is deliberately not a general-purpose metadata channel.
    Iterating the allowlist (rather than the input order) also prevents a set
    of unknown keys from crowding canonical fields out of the stored record.
    """
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in allowed_keys:
        if key not in value:
            continue
        raw_value = value.get(key)
        if isinstance(raw_value, bool) or isinstance(raw_value, int):
            result[key] = raw_value
            continue
        if isinstance(raw_value, float):
            if math.isfinite(raw_value):
                result[key] = raw_value
            continue
        if isinstance(raw_value, (list, tuple)):
            # Canonical transport summaries may use bounded arrays for node,
            # status or fingerprint sets. Preserve that shape while projecting
            # every member through the same scalar/redaction rules.
            items: list[Any] = []
            for item in list(raw_value)[:32]:
                if isinstance(item, bool) or isinstance(item, int):
                    items.append(item)
                elif isinstance(item, float):
                    if math.isfinite(item):
                        items.append(item)
                elif isinstance(item, str):
                    text = _safe_message(item, 120)
                    if text:
                        items.append(text)
            if items:
                result[key] = items
            continue
        if not isinstance(raw_value, str):
            # Unknown containers could contain response bodies, headers or
            # credentials. They are never serialized into the index.
            continue
        text = _safe_message(raw_value, 300)
        if text:
            result[key] = text
    return result


def _safe_failure_mapping(value: Any) -> dict[str, Any]:
    return _safe_mapping(value, allowed_keys=_FAILURE_MAPPING_KEYS)


def _safe_transport_mapping(value: Any) -> dict[str, Any]:
    return _safe_mapping(value, allowed_keys=_TRANSPORT_MAPPING_KEYS)


def _masked_subject(value: Any, kind: str = "") -> str:
    """Return a display-only subject mask; raw account identifiers never persist."""
    text = _safe_text(value, 160)
    if not text:
        return ""
    normalized_kind = str(kind or "").strip().lower()
    if normalized_kind in {"", "email", "account"} and re.fullmatch(
        r"[^@\s]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",
        text,
    ):
        # The local GUI renders full mailbox addresses; validated email
        # shapes are display-safe here.  Non-email shapes still fall through
        # to the redaction fallbacks below.
        return text
    if normalized_kind in {"phone", "phone_number"} or re.fullmatch(r"\d{8,15}", text):
        if not re.fullmatch(r"\+?\d{8,15}", text):
            return "已脱敏账号"
        return f"***{text[-4:]}"
    # Generic account IDs are allowed only as opaque identifier text. Reject
    # credential/URL-looking values rather than exposing a masked substring.
    if (
        len(text) > 160
        or not re.fullmatch(r"[A-Za-z0-9_.:-]+", text)
        or any(marker in text.lower() for marker in ("token", "secret", "password", "credential", "auth", "key"))
    ):
        return "已脱敏账号"
    if len(text) <= 8:
        return f"{text[:1]}***"
    return f"{text[:2]}***{text[-2:]}"


def _is_cleanup_node(value: Any) -> bool:
    code = str(value or "").strip().lower()
    return any(token in code for token in (
        "cleanup", "close", "shutdown", "recovery", "restore", "process_recover",
        # Startup/maintenance handlers use a neutral ``maintenance`` workflow
        # while still belonging to the task's existing diagnostic timeline.
        "maintenance",
        # Lease/health bookkeeping is emitted after the business result and
        # must remain an associated cleanup event, never a new root cause.
        "proxy_release", "lease_release", "mailbox_release", "task_release",
    ))


def _is_cleanup_event(event: Any) -> bool:
    """Classify cleanup/recovery events from their full diagnostic context.

    Cleanup writes are often emitted with a neutral node (for example a pool
    health write) and identify themselves through ``workflow`` or an outcome
    such as ``cleanup_failed``.  Root-cause selection must exclude those
    events even when the node code itself does not contain a cleanup marker.
    """
    if event is None:
        return False
    for key in ("node_code", "first_node_code", "workflow", "outcome"):
        if _is_cleanup_node(_event_value(event, key)):
            return True
    label = str(
        _event_value(event, "node_label")
        or _event_value(event, "first_node_label")
        or ""
    ).strip().lower()
    return any(token in label for token in ("清理", "关闭", "恢复", "释放", "回收"))


_FAILURE_OUTCOMES = frozenset({"error", "failed", "failure", "stopped"})
_SUCCESS_OUTCOMES = frozenset({"success", "succeeded", "complete", "completed"})
_PARTIAL_OUTCOMES = frozenset({"partial", "partial_success"})


def _is_failure_outcome(outcome: Any, level: Any = "") -> bool:
    return str(outcome or "").strip().lower() in _FAILURE_OUTCOMES or str(level or "").strip().lower() in {"error", "danger"}


def _event_value(event: Any, key: str, default: Any = "") -> Any:
    """Read both sqlite rows and ordinary mappings."""
    try:
        return event[key]
    except (KeyError, IndexError, TypeError):
        if isinstance(event, Mapping):
            return event.get(key, default)
        return default


def _is_business_failure_event(event: Any) -> bool:
    """Identify failure candidates without losing non-standard structured outcomes."""
    outcome = str(_event_value(event, "outcome") or "").strip().lower()
    if _is_failure_outcome(outcome, _event_value(event, "level")):
        return True
    if outcome in {"", "info", "started", "success", "succeeded", "complete", "completed", "partial", "partial_success", "retry"}:
        # A legacy writer may have persisted structured failure details while
        # leaving the lifecycle outcome at ``info``. Preserve those details
        # for startup root-cause reconstruction without treating ordinary
        # informational rows as failures.
        return bool(_parse_failure(_event_value(event, "failure_json")))
    return bool(_parse_failure(_event_value(event, "failure_json")))


def _parse_failure(value: Any) -> dict[str, Any]:
    """Read a persisted failure map without allowing malformed JSON to leak."""
    if isinstance(value, Mapping):
        return _safe_failure_mapping(value)
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return _safe_failure_mapping(parsed)


def _retryable_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0", ""}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _business_failure_events(events: Sequence[Any]) -> list[Any]:
    """Return business failure events in append order, excluding cleanup."""
    return [
        event for event in events
        if _is_business_failure_event(event)
        and not _is_cleanup_event(event)
    ]


def _failure_summary(event: Any, failure: Mapping[str, Any] | None = None) -> tuple[str, str, str, bool, dict[str, Any]]:
    """Build the denormalized summary tuple for one failure event."""
    normalized = dict(failure or _parse_failure(_event_value(event, "failure_json")))
    node_code = str(_event_value(event, "node_code") or "")
    node_label = str(_event_value(event, "node_label") or "")
    error_code = _safe_id(normalized.get("error_code"), 120)
    retryable = (
        _retryable_value(normalized.get("retryable"))
        if "retryable" in normalized
        else False
    )
    return node_code, node_label, error_code, retryable, normalized


def _merge_missing_failure_fields(
    base: Mapping[str, Any] | None,
    candidates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Enrich a failure map without replacing fields already selected.

    A later structured event can contain details that were unavailable when
    the first event was appended.  Merge only absent keys; in particular,
    ``False`` and numeric zero are valid values and must not be treated as
    missing.
    """
    merged = dict(base or {})
    for candidate in candidates:
        for key, value in candidate.items():
            if key not in merged:
                merged[key] = value
    return merged


def _same_node_failure_maps(events: Sequence[Any], node_code: str) -> list[dict[str, Any]]:
    """Return structured failures for one node in append order."""
    maps: list[dict[str, Any]] = []
    for event in events:
        if str(_event_value(event, "node_code") or "") != node_code:
            continue
        failure = _parse_failure(_event_value(event, "failure_json"))
        if failure:
            maps.append(failure)
    return maps


def _is_cleanup_root(existing: Any, events: Sequence[Any]) -> bool:
    """Detect a stale cleanup root even when the incident row lost context."""
    if _is_cleanup_event(existing):
        return True
    root_code = str(_event_value(existing, "first_node_code") or "")
    if not root_code:
        return False
    return any(
        str(_event_value(event, "node_code") or "") == root_code
        and _is_cleanup_event(event)
        for event in events
    )




def _status_for_outcome(outcome: str) -> str:
    normalized = str(outcome or "").strip().lower()
    if normalized in {"success", "succeeded", "complete", "completed"}:
        return "success"
    if normalized in {"partial", "partial_success"}:
        return "partial"
    if normalized in {"stopped", "cancelled", "canceled"}:
        return "stopped"
    if normalized in {"error", "failed", "failure"}:
        return "failed"
    return "open"


class DiagnosticSummaryMixin:
    """Mixin providing root-cause selection helpers used by ``DiagnosticStore``."""

    def _startup_failure_summary(self, events: Sequence[Any]) -> tuple[str, str, str, bool, dict[str, Any]] | None:
        """Rebuild a legacy incident using its earliest structured failure.

        Older releases could append a bare failure before the structured failure
        was available.  During startup migration we prefer the first event that
        contains structured failure details; only an incident with no structured
        failure falls back to its earliest bare business failure.
        """
        business_events = _business_failure_events(events)
        if not business_events:
            return None
        structured = next(
            (event for event in business_events if _parse_failure(_event_value(event, "failure_json"))),
            None,
        )
        selected = structured or business_events[0]
        node_code = str(_event_value(selected, "node_code") or "")
        selected_failure = _parse_failure(_event_value(selected, "failure_json"))
        merged_failure = _merge_missing_failure_fields(
            selected_failure,
            _same_node_failure_maps(business_events, node_code),
        )
        return _failure_summary(selected, merged_failure)

    def _realtime_failure_summary(
        self,
        existing: Any,
        events: Sequence[Any],
    ) -> tuple[str, str, str, bool, dict[str, Any]] | None:
        """Keep a live incident's chosen root cause stable while enriching it.

        Once an incident has a first node, later events cannot promote another
        node.  A structured failure may only fill a missing failure (or label) on
        that same node.  For a newly-created incident, append order determines the
        first event, intentionally differing from startup migration semantics.
        """
        existing_node = str(_event_value(existing, "first_node_code") or "") if existing is not None else ""
        business_events = _business_failure_events(events)
        if not business_events:
            # A legacy release could persist a cleanup-only event as the root.
            # Clear that invalid denormalized summary as soon as the incident is
            # touched, while leaving ordinary informational incidents untouched.
            if existing is not None and _is_cleanup_root(existing, events):
                return "", "", "", False, {}
            return None

        # A pre-migration incident may have selected a cleanup node as its root.
        # Cleanup is never a business cause; once a real failure is appended,
        # repair that legacy summary from the earliest business event.
        if existing is not None and _is_cleanup_root(existing, events):
            existing_node = ""
        if not existing_node:
            selected = business_events[0]
            node_code = str(_event_value(selected, "node_code") or "")
            selected_failure = _parse_failure(_event_value(selected, "failure_json"))
            merged_failure = _merge_missing_failure_fields(
                selected_failure,
                _same_node_failure_maps(business_events, node_code),
            )
            summary = _failure_summary(selected, merged_failure)
            if not summary[1]:
                for candidate in business_events:
                    if str(_event_value(candidate, "node_code") or "") == node_code:
                        summary = (summary[0], str(_event_value(candidate, "node_label") or ""), summary[2], summary[3], summary[4])
                        if summary[1]:
                            break
            return summary

        # An existing summary is authoritative. Read its persisted failure map
        # and only fill missing fields from a structured same-node event.
        first_node_label = str(_event_value(existing, "first_node_label") or "")
        existing_failure = _parse_failure(_event_value(existing, "failure_json"))
        first_failure = _merge_missing_failure_fields(
            existing_failure,
            _same_node_failure_maps(business_events, existing_node),
        )
        first_event = next(
            (event for event in business_events if str(_event_value(event, "node_code") or "") == existing_node),
            None,
        )
        if first_event is not None and not first_node_label:
            first_node_label = str(_event_value(first_event, "node_label") or "")
        if not first_node_label:
            for candidate in business_events:
                if str(_event_value(candidate, "node_code") or "") != existing_node:
                    continue
                candidate_label = str(_event_value(candidate, "node_label") or "")
                if candidate_label:
                    first_node_label = candidate_label
                    break
        existing_error_code = _safe_id(_event_value(existing, "first_error_code"), 120)
        first_error_code = existing_error_code or _safe_id(first_failure.get("error_code"), 120)
        if "retryable" in existing_failure:
            retryable = _retryable_value(existing_failure.get("retryable"))
        elif bool(_event_value(existing, "retryable")):
            retryable = True
        else:
            retryable = _retryable_value(first_failure.get("retryable")) if "retryable" in first_failure else False
        return existing_node, first_node_label, first_error_code, retryable, first_failure


__all__ = ["DiagnosticSummaryMixin"]
