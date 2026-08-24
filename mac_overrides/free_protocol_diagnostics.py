"""Credential-safe response and OAuth callback diagnostics for Free protocol."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit, urlunsplit

try:
    from .free_register_common import safe_log_message
except ImportError:  # pragma: no cover - recovered runtime compatibility
    from free_register_common import safe_log_message  # type: ignore[no-redef]


EMAIL_OTP_PAGE_TYPES = frozenset({
    "email_otp",
    "email_otp_send",
    "email_otp_verification",
    "email_verification",
    "email_code_verification",
    "passwordless_email_otp",
})


def is_email_otp_response(
    page_type: Any,
    continue_url: Any,
    *,
    normalize_page_type: Callable[[Any], Any] | None = None,
) -> bool:
    """Recognize an email-code state without treating MFA/phone as email OTP."""
    try:
        normalized = normalize_page_type(page_type) if callable(normalize_page_type) else page_type
    except Exception:
        normalized = page_type
    normalized = str(normalized or "").strip().casefold().replace("-", "_")
    if normalized in EMAIL_OTP_PAGE_TYPES:
        return True
    try:
        path = urlsplit(str(continue_url or "")).path.casefold().rstrip("/")
    except (TypeError, ValueError):
        path = ""
    return (
        path in {
            "/email-verification",
            "/email-otp",
            "/api/accounts/email-otp/send",
            "/api/accounts/email-otp/resend",
        }
        or path.startswith("/email-verification/")
        or path.startswith("/email-otp/")
    )


def response_status(response: Any) -> int | None:
    if isinstance(response, Mapping):
        raw = response.get("_status") if "_status" in response else response.get("status_code")
    else:
        raw = getattr(response, "status_code", None)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def content_type(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    return str(response.get("_content_type") or response.get("content_type") or "").split(";", 1)[0].strip().lower()


def page_locations(response: Any) -> tuple[str, ...]:
    if not isinstance(response, Mapping):
        return ()
    values: list[str] = []
    page = response.get("page")
    sources = (page, response) if isinstance(page, Mapping) else (response,)
    for source in sources:
        for key in ("continue_url", "external_url", "redirect_url", "next_url", "location", "_location", "url", "_url"):
            value = str(source.get(key) or "").strip()
            if value and value not in values:
                values.append(value)
    return tuple(values)


def page_location(response: Any) -> str:
    locations = page_locations(response)
    return locations[0] if locations else ""


def next_url(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page")
    sources = (page, response) if isinstance(page, Mapping) else (response,)
    for source in sources:
        for key in ("continue_url", "external_url", "redirect_url", "next_url", "location", "_location"):
            value = str(source.get(key) or "").strip()
            if value:
                return value
    return ""


def page_type_value(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page")
    if isinstance(page, Mapping):
        value = str(page.get("type") or "").strip()
        if value:
            return value
    return str(response.get("page_type") or "").strip()


def page_is_html(response: Any) -> bool:
    response_content_type = content_type(response)
    if response_content_type:
        return "html" in response_content_type
    if not isinstance(response, Mapping):
        return False
    if response.get("_html_title"):
        return True
    body = str(response.get("_body") or response.get("_body_summary") or "").lstrip().casefold()
    return body.startswith(("<!doctype html", "<html", "<head", "<body"))


def response_search_text(response: Any) -> str:
    if not isinstance(response, Mapping):
        return str(response or "")
    body = str(response.get("_body") or "")[:4096]
    fields = " ".join(str(response.get(key) or "") for key in ("_body_summary", "_html_title", "error", "_url", "_location"))
    return f"{fields} {body}"


def response_detail(response: Any, error: str = "") -> str:
    status = response_status(response)
    page = page_type_value(response)[:64]
    parts: list[str] = []
    if status is not None:
        parts.append(f"HTTP {status}")
    if content_type(response):
        parts.append(f"Content-Type {content_type(response)}")
    if page:
        parts.append(f"页面 {page}")
    if error:
        parts.append(safe_log_message(error)[:180])
    return "，".join(parts) or "服务端未返回可用诊断详情"


def provider_code(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    error = response.get("error")
    sources = (error, response) if isinstance(error, Mapping) else (response,)
    for source in sources:
        for key in ("error_code", "code", "type", "reason"):
            value = str(source.get(key) or "").strip()
            if value:
                return safe_log_message(value)[:120]
    return ""


def safe_url(value: str) -> str:
    try:
        parsed = urlsplit(str(value or ""))
    except ValueError:
        return "invalid"
    host = str(parsed.hostname or "")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed.scheme, netloc, str(parsed.path or "/"), "", ""))


def response_metadata(response: Any, *, action_hint: str = "", diagnostic_error: str = "") -> dict[str, Any]:
    location = page_location(response)
    return {
        "provider_status": response_status(response),
        "provider_code": provider_code(response),
        "action_hint": action_hint,
        "diagnostic": response_detail(response, diagnostic_error),
        "page_type": page_type_value(response),
        "safe_page": safe_url(location) if location else "",
        "content_type": content_type(response),
    }


def callback_query(callback_url: str) -> dict[str, str]:
    try:
        values = parse_qs(urlsplit(str(callback_url or "")).query, keep_blank_values=True)
    except (TypeError, ValueError):
        return {}
    return {key: str((items or [""])[0]) for key, items in values.items()}


def callback_matches_redirect(callback_url: str, redirect_uri: str) -> bool:
    try:
        actual, expected = urlsplit(callback_url), urlsplit(redirect_uri)
    except (TypeError, ValueError):
        return False
    normalize = lambda value: (str(value or "/").rstrip("/") or "/")
    return bool(
        expected.scheme and expected.netloc
        and actual.scheme.casefold() == expected.scheme.casefold()
        and actual.netloc.casefold() == expected.netloc.casefold()
        and normalize(actual.path) == normalize(expected.path)
    )


__all__ = [
    "EMAIL_OTP_PAGE_TYPES", "callback_matches_redirect", "callback_query", "content_type", "is_email_otp_response", "next_url",
    "page_is_html", "page_location", "page_locations", "page_type_value",
    "provider_code", "response_detail", "response_metadata", "response_search_text",
    "response_status", "safe_url",
]
