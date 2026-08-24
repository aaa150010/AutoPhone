"""Credential-safe bounded waiting for Free protocol security pages.

The protocol driver can receive a Cloudflare/security HTML envelope from any
OAuth request, not only from the initial network preflight.  This module keeps
the recovery policy small and independent from the page state machine:

* it only polls the existing transport session (and therefore its existing
  proxy/cookies/device context);
* it never calls the operation that produced the challenge a second time; and
* an unresolved challenge is returned unchanged so the caller can retain the
  stable security failure node.

A transport may provide ``wait_for_security_challenge`` when it has a more
precise, same-session page poll.  The hook is deliberately a polling hook, not
an operation-replay hook.
"""

from __future__ import annotations

from collections.abc import Mapping
import inspect
import math
import time
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit


SECURITY_CHALLENGE_WAIT_SECONDS = 60.0
SECURITY_CHALLENGE_POLL_SECONDS = 2.0

_CHALLENGE_MARKERS = (
    "captcha",
    "cloudflare",
    "turnstile",
    "verify you are human",
    "checking your browser",
    "just a moment",
    "人机验证",
    "人間であることを確認",
    "security_challenge",
    "security-challenge",
    "security-check",
    "/cdn-cgi/challenge-platform/",
    "cf-chl-",
    "challenge-platform",
)
_MFA_TYPES = frozenset({"mfa_challenge", "mfa_otp", "mfa_otp_verification"})
SECURITY_CHALLENGE_MARKERS = _CHALLENGE_MARKERS
MFA_PAGE_TYPES = _MFA_TYPES
SECURITY_PAGE_MARKERS = (
    "security_challenge",
    "security-challenge",
    "security-check",
    "captcha",
    "cloudflare",
    "turnstile",
    "/cdn-cgi/challenge-platform/",
)
SECURITY_PAGE_TYPES = frozenset({
    "security_challenge", "security_verification", "human_verification", "captcha",
})
_TRUSTED_HOSTS = frozenset({"auth.openai.com", "auth0.openai.com", "chatgpt.com"})
_DEFAULT_POLL_URL = "https://auth.openai.com/log-in"


def _text(value: Any, limit: int = 32768) -> str:
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value[:limit]).decode("utf-8", "ignore")
    return str(value or "")[:limit]


def response_search_text(response: Any) -> str:
    """Return a bounded, non-secret search surface for challenge markers."""
    if isinstance(response, str):
        return response[:32768]
    if isinstance(response, Mapping):
        fields: list[str] = []
        for key in (
            "_body", "_body_summary", "_html_title", "error", "_url",
            "_location", "url", "location", "page_type",
        ):
            value = response.get(key)
            if value not in (None, ""):
                fields.append(_text(value, 4096))
        page = response.get("page")
        if isinstance(page, Mapping):
            for key in ("type", "continue_url", "external_url", "redirect_url", "url"):
                value = page.get(key)
                if value not in (None, ""):
                    fields.append(_text(value, 4096))
        return " ".join(fields)[:32768]
    body = getattr(response, "text", None)
    if body in (None, ""):
        body = getattr(response, "content", None)
    url = getattr(response, "url", None)
    return f"{_text(body, 32768)} {_text(url, 2048)}"[:32768]


def _page_type(response: Any) -> str:
    if not isinstance(response, Mapping):
        return ""
    page = response.get("page")
    if isinstance(page, Mapping):
        return str(page.get("type") or "").strip().casefold().replace("-", "_")
    return str(response.get("page_type") or "").strip().casefold().replace("-", "_")


def is_security_challenge(response: Any) -> bool:
    """Recognize Cloudflare/security pages without classifying MFA as risk."""
    page_type = _page_type(response)
    if page_type in _MFA_TYPES:
        return False
    if isinstance(response, Mapping) and page_type:
        if page_type in {"security_challenge", "security_verification", "human_verification", "captcha"}:
            return True
    lowered = response_search_text(response).casefold()
    return bool(lowered) and any(marker.casefold() in lowered for marker in _CHALLENGE_MARKERS)


def is_security_page(response: Any) -> bool:
    """Recognize a structured security page while excluding MFA pages."""
    if not isinstance(response, Mapping):
        return False
    page_type = _page_type(response)
    if page_type in _MFA_TYPES:
        return False
    locations = " ".join(_locations(response)).casefold()
    return (
        page_type in SECURITY_PAGE_TYPES
        or any(marker.casefold().replace("-", "_") in page_type for marker in SECURITY_CHALLENGE_MARKERS)
        or any(marker.casefold() in locations for marker in SECURITY_CHALLENGE_MARKERS)
    )


def challenge_wait_seconds(transport: Any, default: float = SECURITY_CHALLENGE_WAIT_SECONDS) -> float:
    """Read and clamp the per-task bounded wait setting."""
    value: Any = getattr(transport, "security_challenge_wait_seconds", None)
    config = getattr(transport, "config", None)
    if value in (None, "") and isinstance(config, Mapping):
        protocol = config.get("protocol")
        if isinstance(protocol, Mapping):
            value = protocol.get("security_challenge_wait_seconds")
    try:
        value = float(default if value in (None, "") else value)
    except (TypeError, ValueError):
        value = float(default)
    if not math.isfinite(value):
        value = float(default)
    return max(0.0, min(SECURITY_CHALLENGE_WAIT_SECONDS, value))


def _locations(response: Any) -> tuple[str, ...]:
    values: list[str] = []
    if isinstance(response, Mapping):
        page = response.get("page")
        sources = (page, response) if isinstance(page, Mapping) else (response,)
        for source in sources:
            for key in (
                "continue_url", "external_url", "redirect_url", "next_url",
                "location", "_location", "url", "_url",
            ):
                value = str(source.get(key) or "").strip()
                if value and value not in values:
                    values.append(value)
    else:
        value = str(getattr(response, "url", "") or "").strip()
        if value:
            values.append(value)
    return tuple(values)


def _poll_url(transport: Any, response: Any) -> str:
    candidates = list(_locations(response))
    for name in ("last_oauth_url", "oauth_url", "_gptphone_last_oauth_url"):
        value = str(getattr(transport, name, "") or "").strip()
        if value:
            candidates.append(value)
    for candidate in candidates:
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if not parsed.scheme or not parsed.netloc:
            candidate = urljoin(_DEFAULT_POLL_URL, candidate)
            try:
                parsed = urlsplit(candidate)
            except ValueError:
                continue
        host = str(parsed.hostname or "").casefold()
        if host not in _TRUSTED_HOSTS:
            continue
        path = str(parsed.path or "").casefold()
        # A challenge may be attached to an API POST envelope.  GETting that
        # endpoint is not a page poll and commonly returns 405; use the
        # trusted login document instead.
        if path.startswith(("/api/", "/backend-api/", "/backend-anon/")):
            continue
        # Keep the original query for an OAuth start URL internally, but never
        # include it in diagnostics.  Fragment state is not sent to a server.
        try:
            port = parsed.port
        except ValueError:
            port = None
        safe_host = host
        if ":" in safe_host and not safe_host.startswith("["):
            safe_host = f"[{safe_host}]"
        safe_netloc = f"{safe_host}:{port}" if port is not None else safe_host
        return urlunsplit((parsed.scheme, safe_netloc, parsed.path or "/", parsed.query, ""))
    return _DEFAULT_POLL_URL


def _headers(transport: Any, flow: str, referer: str) -> Mapping[str, Any]:
    builder = getattr(transport, "_headers", None)
    if not callable(builder):
        return {}
    for args in ((flow, referer), (flow, _DEFAULT_POLL_URL), (referer,), ()):
        try:
            value = builder(*args)
        except TypeError:
            continue
        except Exception:
            return {}
        if isinstance(value, Mapping):
            return dict(value)
        return {}
    return {}


def _log(log: Callable[..., Any] | None, message: str, level: str = "info") -> None:
    if not callable(log):
        return
    try:
        log(message, level)
    except TypeError:
        try:
            log(message)
        except TypeError:
            return


def _stop(stop_requested: Callable[[], bool] | None) -> bool:
    try:
        return bool(stop_requested and stop_requested())
    except Exception:
        return False


def _invoke_hook(
    hook: Callable[..., Any],
    response: Any,
    *,
    timeout: float,
    poll_interval: float,
    method: str,
    flow: str,
    stop_requested: Callable[[], bool] | None,
) -> Any:
    kwargs = {
        "timeout": timeout,
        "wait_seconds": timeout,
        "poll_interval": poll_interval,
        "method": method,
        "flow": flow,
        "stop_requested": stop_requested,
    }
    try:
        signature = inspect.signature(hook)
    except (TypeError, ValueError):
        return hook(response, timeout=timeout, poll_interval=poll_interval)
    parameters = signature.parameters
    accepts_var_kw = any(item.kind is inspect.Parameter.VAR_KEYWORD for item in parameters.values())
    selected = kwargs if accepts_var_kw else {key: value for key, value in kwargs.items() if key in parameters}
    try:
        signature.bind(response, **selected)
    except TypeError:
        # A hook with a positional-only timeout is still a valid small test or
        # transport adapter.  Keep fallback calls bounded and predictable.
        for args in ((response, timeout), (response,)):
            try:
                return hook(*args)
            except TypeError:
                continue
        return hook(response)
    return hook(response, **selected)


def _unwrap_hook_result(value: Any) -> Any:
    if isinstance(value, Mapping) and "response" in value:
        candidate = value.get("response")
        return candidate if candidate is not None else value
    if isinstance(value, tuple) and value:
        # Adapters sometimes return (response, cleared).  The response is the
        # only part that can be safely fed back to the state machine.
        return value[0]
    return value


def _normalize_polled_response(transport: Any, value: Any) -> Any:
    """Convert a raw Session response back to the transport envelope shape."""
    if value is None or isinstance(value, bool):
        # A boolean is only an acknowledgement from an adapter, not a page
        # envelope.  Treating ``True`` as a successful OAuth response would
        # let the state machine advance without page/state data.
        return None
    if isinstance(value, Mapping):
        return value
    # Only use a converter explicitly bound to this transport.  Importing a
    # process-global recovered helper here is unsafe: a test double (or a
    # future transport implementation) may return a response from a different
    # session contract, and an empty HTTP 200 could then be mistaken for a
    # cleared challenge.  The production Free transport binds the recovered
    # converter during construction; transports without that binding remain
    # fail-closed.
    converters: list[Callable[[Any], Any]] = []
    for name in ("_json_response", "_gptphone_json_response", "json_response"):
        converter = getattr(transport, name, None)
        if callable(converter) and converter not in converters:
            converters.append(converter)
    for converter in converters:
        try:
            converted = converter(value)
        except Exception:
            continue
        if isinstance(converted, Mapping):
            return converted
    # Without a converter there is no page envelope for the OAuth state
    # machine to consume.  Preserve the challenge and fail closed instead of
    # treating a bare HTTP 200/boolean as a successful state transition.
    return None


def wait_for_security_challenge(
    transport: Any,
    response: Any,
    *,
    method: str = "",
    flow: str = "",
    timeout: float | None = None,
    poll_interval: float = SECURITY_CHALLENGE_POLL_SECONDS,
    stop_requested: Callable[[], bool] | None = None,
    log: Callable[..., Any] | None = None,
) -> Any:
    """Wait for a challenge to clear while preserving the original request.

    ``response`` is returned unchanged when no same-session polling mechanism
    exists or when the challenge remains at the deadline.  This fail-closed
    behavior is important for POST/OTP responses: the email or code operation
    is never replayed automatically.
    """
    if not is_security_challenge(response):
        return response
    if timeout is None:
        budget = challenge_wait_seconds(transport)
    else:
        try:
            requested = float(timeout)
        except (TypeError, ValueError):
            requested = 0.0
        budget = requested if math.isfinite(requested) else 0.0
        budget = max(0.0, min(SECURITY_CHALLENGE_WAIT_SECONDS, budget))
    if budget <= 0:
        return response
    poll = max(0.1, min(float(poll_interval or SECURITY_CHALLENGE_POLL_SECONDS), budget))
    label = str(method or flow or "协议请求")[:80]
    _log(log, f"[协议/{label}] 检测到安全挑战，保持当前会话和代理等待最多 {int(budget)} 秒", "warn")

    hook = getattr(transport, "wait_for_security_challenge", None)
    if callable(hook) and hook is not wait_for_security_challenge:
        if _stop(stop_requested):
            return response
        try:
            raw_candidate = _unwrap_hook_result(
                _invoke_hook(
                    hook,
                    response,
                    timeout=budget,
                    poll_interval=poll,
                    method=method,
                    flow=flow,
                    stop_requested=stop_requested,
                )
            )
            candidate = _normalize_polled_response(transport, raw_candidate)
            if candidate is None:
                candidate = response
        except Exception as exc:
            _log(log, f"[协议/{label}] 安全挑战等待适配器异常：{type(exc).__name__}", "warn")
            return response
        if candidate is not None and not is_security_challenge(candidate):
            _log(log, f"[协议/{label}] 安全挑战已解除，沿用同一会话继续", "info")
            return candidate
        _log(log, f"[协议/{label}] 安全挑战仍未解除，停止当前节点", "warn")
        return response if candidate is None else candidate

    session = getattr(transport, "session", None)
    getter = getattr(session, "get", None)
    if not callable(getter):
        # A transport without a session cannot safely poll.  Do not sleep for
        # the whole budget because that would only delay the terminal error.
        _log(log, f"[协议/{label}] 当前 Transport 没有可复用的 Session，保留安全挑战节点", "warn")
        return response

    url = _poll_url(transport, response)
    referer = _DEFAULT_POLL_URL
    deadline = time.monotonic() + budget
    max_polls = max(1, int(math.ceil(budget / poll)))
    polls = 0
    current = response
    while polls < max_polls:
        if _stop(stop_requested):
            return current
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll, remaining))
        polls += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            kwargs = {
                "headers": _headers(transport, flow or "oauth_authorize", referer),
                "timeout": max(0.1, min(remaining, 30.0)),
                "allow_redirects": True,
            }
            try:
                polled = _normalize_polled_response(transport, getter(url, **kwargs))
            except TypeError:
                polled = _normalize_polled_response(transport, getter(url))
            if polled is not None:
                current = polled
        except Exception as exc:
            _log(log, f"[协议/{label}] 安全挑战轮询异常：{type(exc).__name__}", "warn")
            continue
        if not is_security_challenge(current):
            _log(log, f"[协议/{label}] 安全挑战已解除，沿用同一会话继续", "info")
            return current
    _log(log, f"[协议/{label}] 安全挑战等待超时，保留当前风控节点", "warn")
    return current


__all__ = [
    "MFA_PAGE_TYPES",
    "SECURITY_CHALLENGE_MARKERS",
    "SECURITY_CHALLENGE_POLL_SECONDS",
    "SECURITY_CHALLENGE_WAIT_SECONDS",
    "SECURITY_PAGE_MARKERS",
    "SECURITY_PAGE_TYPES",
    "challenge_wait_seconds",
    "is_security_challenge",
    "is_security_page",
    "response_search_text",
    "wait_for_security_challenge",
]
