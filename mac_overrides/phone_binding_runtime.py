"""Incremental browser-contract compatibility for OpenAI phone binding."""

from __future__ import annotations

from collections import Counter
import hashlib
import re
import threading
import time
from typing import Any, Callable, Mapping


try:
    from .performance_runtime import PHONE_BINDING_COMPATIBILITY
except ImportError:  # Loaded as a top-level runtime override.
    from performance_runtime import PHONE_BINDING_COMPATIBILITY  # type: ignore[no-redef]
_COMPATIBILITY_MARKERS = re.compile(
    r"channel|invalid_state|no longer valid|session(?:\s+is)?\s+(?:invalid|expired)",
    re.IGNORECASE,
)
_SECURITY_CHALLENGE_MARKERS = (
    "challenge-platform",
    "just a moment",
    "cf-chl",
    "cloudflare",
    "security check",
)


def _enabled(value: Any, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
        "unchecked",
        "disabled",
    }


def _status(response: Any) -> int:
    if not isinstance(response, Mapping):
        return 0
    try:
        return int(response.get("_status") or 0)
    except (TypeError, ValueError):
        return 0


def _page_type(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page")
    if isinstance(page, Mapping):
        return str(page.get("type") or "").strip().lower()
    return str(response.get("page_type") or "").strip().lower()


def _error_code(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    error = response.get("error")
    if isinstance(error, Mapping):
        value = error.get("code") or error.get("type")
    else:
        value = response.get("code")
    return re.sub(r"[^a-z0-9_.-]+", "_", str(value or "").strip().lower())[:80]


def _response_text(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    error = response.get("error")
    values: list[Any] = [response.get("code"), response.get("message")]
    if isinstance(error, Mapping):
        values.extend((error.get("code"), error.get("message"), error.get("type")))
    else:
        values.append(error)
    values.extend((response.get("_body_summary"), response.get("_body")))
    return " ".join(str(value or "")[:2000] for value in values).lower()


def _is_html_response(response: Any) -> bool:
    if not isinstance(response, Mapping):
        return False
    content_type = str(response.get("_content_type") or "").lower()
    body = str(response.get("_body") or response.get("_body_summary") or "").lstrip().lower()
    return "html" in content_type or body.startswith("<!doctype html") or body.startswith("<html")


def _is_security_challenge(response: Any) -> bool:
    if not _is_html_response(response):
        return False
    text = _response_text(response)
    return any(marker in text for marker in _SECURITY_CHALLENGE_MARKERS)


def _stop_requested(config: Any) -> bool:
    value = config.get("_stop_requested") if isinstance(config, Mapping) else None
    if callable(value):
        try:
            return bool(value())
        except Exception:
            return False
    is_set = getattr(value, "is_set", None)
    if callable(is_set):
        try:
            return bool(is_set())
        except Exception:
            return False
    return bool(value)


class PhoneBindingMetrics:
    """Process-local aggregate counters containing no request identifiers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()

    def increment(self, key: str) -> None:
        with self._lock:
            self._counts[str(key)] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()


class PhoneBindingRuntime:
    """Own the extracted phone send path while preserving its public signature."""

    def __init__(
        self,
        *,
        auth_origin: str,
        json_headers: Mapping[str, Any],
        phone_for_openai: Callable[[Any], str],
        json_response: Callable[[Any], Any],
        codex_error: type[Exception],
        auth_requests: Any,
        auth_sessions: Any,
        registry: Any,
        with_protocol_lease: Callable[[Any, Callable[[], Any]], Any],
        protocol_coordinator: Any,
        record_segment: Callable[[Any, str, float], None],
        task_id_for: Callable[[Any], str],
        current_task_id: Callable[[], Any],
        set_stage: Callable[[str], None],
        normalize_channel: Callable[[Any], str],
        reject_channel_mismatch: Callable[[Any, Any], dict[str, Any]],
        sanitize_error: Callable[..., str],
        metrics: PhoneBindingMetrics | None = None,
    ) -> None:
        self.auth_origin = auth_origin.rstrip("/")
        self.json_headers = dict(json_headers)
        self.phone_for_openai = phone_for_openai
        self.json_response = json_response
        self.codex_error = codex_error
        self.auth_requests = auth_requests
        self.auth_sessions = auth_sessions
        self.registry = registry
        self.with_protocol_lease = with_protocol_lease
        self.protocol_coordinator = protocol_coordinator
        self.record_segment = record_segment
        self.task_id_for = task_id_for
        self.current_task_id = current_task_id
        self.set_stage = set_stage
        self.normalize_channel = normalize_channel
        self.reject_channel_mismatch = reject_channel_mismatch
        self.sanitize_error = sanitize_error
        self.metrics = metrics or PhoneBindingMetrics()
        self._fallback_lock = threading.Lock()

    def compatibility_enabled(self, transport: Any) -> bool:
        config = getattr(transport, "config", None)
        value = config if isinstance(config, Mapping) else {}
        return _enabled(value.get(PHONE_BINDING_COMPATIBILITY), True)

    def prepare_phone_entry(self, transport: Any, *, expected_task_id: str) -> Any:
        if not self.compatibility_enabled(transport):
            self.metrics.increment("page_prepare_skipped")
            return self.auth_requests.recover_phone_entry_context(
                transport,
                self.registry,
                expected_task_id=expected_task_id,
            )

        try:
            context, outcome = self.auth_requests.prepare_phone_entry_context(
                transport,
                self.registry,
                expected_task_id=expected_task_id,
            )
        except self.auth_requests.AuthRequestContextError:
            self.metrics.increment("page_prepare_attempted")
            self.metrics.increment("page_prepare_failed")
            raise
        if outcome in {"prepared", "recovered"}:
            self.metrics.increment("page_prepare_attempted")
            self.metrics.increment("page_prepare_succeeded")
        elif outcome in {"already_prepared", "already_attempted", "missing_url", "visitor_missing"}:
            self.metrics.increment("page_prepare_skipped")
        else:
            self.metrics.increment("page_prepare_attempted")
            self.metrics.increment("page_prepare_failed")
        return context

    def _request_headers(self, transport: Any, referer: str) -> dict[str, str]:
        headers = {
            **self.json_headers,
            "referer": referer,
            "oai-device-id": str(getattr(transport, "device_id", "") or ""),
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "x-datadog-origin": "rum",
        }
        return self.auth_requests.request_headers(
            transport,
            headers,
            include_sentinel=False,
        )

    def _post_once(
        self,
        transport: Any,
        *,
        endpoint: str,
        referer: str,
        payload: dict[str, Any],
        segment: str,
    ) -> dict[str, Any]:
        request_context = self.auth_requests.begin_request(
            transport,
            self.registry,
            endpoint=endpoint,
            stage="phone_submitting",
        )
        headers = self._request_headers(transport, referer)
        started = time.monotonic()
        try:
            def post_phone_number() -> dict[str, Any]:
                raw_response = transport.session.post(
                    f"{self.auth_origin}{endpoint}",
                    json=payload,
                    headers=headers,
                    allow_redirects=False,
                    timeout=30,
                )
                if isinstance(raw_response, Mapping):
                    return dict(raw_response)
                parsed = dict(self.json_response(raw_response) or {})
                parsed.setdefault("_status", int(getattr(raw_response, "status_code", 0) or 0))
                return parsed

            response = self.with_protocol_lease(transport, post_phone_number)
        except Exception as exc:
            response = {
                "_status": 0,
                "error": self.sanitize_error(exc, limit=220)
                or "phone_send_request_failed",
            }
        finally:
            self.record_segment(
                self.task_id_for(transport) or self.current_task_id(),
                segment,
                time.monotonic() - started,
            )
        finished = self.auth_requests.finish_request(
            transport,
            self.registry,
            request_context,
            response,
        )
        transport._gptphone_last_request_context = finished
        return dict(response)

    def _should_retry_without_channel(
        self,
        transport: Any,
        response: Any,
        requested_channel: str,
    ) -> bool:
        if not requested_channel or not self.compatibility_enabled(transport):
            return False
        if _status(response) not in {400, 409} or _is_html_response(response):
            return False
        if _error_code(response) in {
            "phone_channel_mismatch",
            "phone_security_challenge_required",
        }:
            return False
        if _stop_requested(getattr(transport, "config", None)):
            return False
        if _page_type(response) or (isinstance(response, Mapping) and response.get("continue_url")):
            return False
        return bool(_COMPATIBILITY_MARKERS.search(_response_text(response)))

    def _claim_channel_fallback(self, transport: Any, phone_value: str) -> bool:
        context = self.auth_requests.ensure_transport_context(transport, self.registry)
        fingerprint = hashlib.sha256(
            str(phone_value or "").encode("utf-8", "replace")
        ).hexdigest()
        with self._fallback_lock:
            if fingerprint in context.phone_channel_fallback_keys:
                return False
            context.phone_channel_fallback_keys.add(fingerprint)
            return True

    @staticmethod
    def _identity(response: Any) -> dict[str, Any]:
        return {
            "status": _status(response),
            "error_code": _error_code(response),
        }

    @staticmethod
    def _security_challenge_response(response: Mapping[str, Any]) -> dict[str, Any]:
        safe = {
            key: value
            for key, value in response.items()
            if key not in {"_body", "_body_summary", "error", "message"}
        }
        safe["error"] = {
            "code": "phone_security_challenge_required",
            "message": "OpenAI 手机号提交返回浏览器安全验证页面",
        }
        return safe

    def _finish_response(
        self,
        transport: Any,
        response: dict[str, Any],
        *,
        requested_channel: str,
        channel_checked: bool = False,
    ) -> dict[str, Any]:
        if _is_security_challenge(response):
            response = self._security_challenge_response(response)
        if not channel_checked:
            response = self.reject_channel_mismatch(response, requested_channel)
        transport.last_response = response
        if self.auth_sessions.is_session_invalid(response):
            self.auth_requests.invalidate_auth_session(
                transport,
                self.registry,
                response,
                stage="phone_submitting",
            )
            return response
        status = _status(response)
        if not 200 <= status < 300:
            structured_error = response.get("error")
            if (
                isinstance(structured_error, Mapping)
                and str(structured_error.get("code") or "").strip().lower()
                in {"phone_channel_mismatch", "phone_security_challenge_required"}
            ):
                return response
            return {
                **response,
                "error": response.get("_body_summary")
                or response.get("_body")
                or response.get("error", ""),
            }

        self.auth_requests.mark_phone_otp_sent(transport, self.registry, response)
        started = time.monotonic()
        try:
            self.protocol_coordinator.call_origin(
                transport,
                "sentinel.openai.com",
                lambda: self.auth_requests.refresh_sentinel(
                    transport,
                    self.registry,
                    flow="authorize_continue",
                    referer=f"{self.auth_origin}/phone-verification",
                ),
                success_fn=lambda value: bool(
                    isinstance(value, Mapping)
                    and (value.get("token") or value.get("so_token"))
                ),
                count_capacity=False,
            )
        except self.auth_requests.AuthRequestContextError as exc:
            raise self.codex_error(f"{exc.code}: {exc}") from exc
        finally:
            self.record_segment(
                self.task_id_for(transport) or self.current_task_id(),
                "sentinel_refresh",
                time.monotonic() - started,
            )
        return response

    def send_phone_number_otp(
        self,
        transport: Any,
        phone: Any,
        channel: Any = "sms",
    ) -> dict[str, Any]:
        requested_channel = self.normalize_channel(channel)
        if not hasattr(transport, "session"):
            payload = {"phone_number": self.phone_for_openai(phone)}
            if requested_channel:
                payload["channel"] = requested_channel
            return transport._post_auth_json(
                "/api/accounts/add-phone/send",
                payload,
                flow="authorize_continue",
                referer=f"{self.auth_origin}/add-phone",
                timeout=30,
            )

        self.set_stage("phone_submitting")
        endpoint = "/api/accounts/add-phone/send"
        referer = f"{self.auth_origin}/add-phone"
        try:
            self.auth_requests.validate_phone_context(transport, self.registry)
        except self.auth_requests.AuthRequestContextError as exc:
            self.auth_requests.invalidate_auth_session(
                transport,
                self.registry,
                f"{exc.code}: {exc}",
                stage="phone_submitting",
            )
            raise self.codex_error(f"{exc.code}: {exc}") from exc

        phone_value = self.phone_for_openai(phone)
        primary_payload: dict[str, Any] = {"phone_number": phone_value}
        if requested_channel:
            primary_payload["channel"] = requested_channel
        primary = self._post_once(
            transport,
            endpoint=endpoint,
            referer=referer,
            payload=primary_payload,
            segment="phone_submit_http",
        )
        if not self._should_retry_without_channel(transport, primary, requested_channel):
            return self._finish_response(
                transport,
                primary,
                requested_channel=requested_channel,
            )
        if not self._claim_channel_fallback(transport, phone_value):
            return self._finish_response(
                transport,
                primary,
                requested_channel=requested_channel,
            )

        self.metrics.increment("channel_fallback_attempted")
        fallback = self._post_once(
            transport,
            endpoint=endpoint,
            referer=referer,
            payload={"phone_number": phone_value},
            segment="phone_submit_compat_http",
        )
        fallback_checked = self.reject_channel_mismatch(fallback, requested_channel)
        if 200 <= _status(fallback_checked) < 300:
            self.metrics.increment("channel_fallback_succeeded")
        else:
            self.metrics.increment("channel_fallback_failed")
            fallback_checked["_phone_binding_compatibility"] = {
                "fallback_attempted": True,
                "primary": self._identity(primary),
                "fallback": self._identity(fallback_checked),
            }
        return self._finish_response(
            transport,
            fallback_checked,
            requested_channel=requested_channel,
            channel_checked=True,
        )


__all__ = [
    "PHONE_BINDING_COMPATIBILITY",
    "PhoneBindingMetrics",
    "PhoneBindingRuntime",
]
