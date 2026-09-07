"""Pure SMS networking and small caching primitives.

Split out of ``sms_runtime.py``; the original module re-exports every name
for compatibility.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
import threading
import time
from typing import Any, Callable
import urllib.parse

try:
    from .sms_provider_runtime import (
        SECRET_MASK,
        normalize_sms_keys,
    )
    from .sms_route_runtime import (
        _candidate_value as _route_candidate_value,
        candidate_route,
        route_stat as _route_stat_value,
    )
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from sms_provider_runtime import (  # type: ignore[no-redef]
        SECRET_MASK,
        normalize_sms_keys,
    )
    from sms_route_runtime import (  # type: ignore[no-redef]
        _candidate_value as _route_candidate_value,
        candidate_route,
        route_stat as _route_stat_value,
    )


SMS_PREFLIGHT_MAX_WORKERS = 8
SMS_NETWORK_ATTEMPTS = 3
SMS_FIRST_WAIT_SECONDS = 30
SMS_SECOND_WAIT_SECONDS = 30
SMS_POLL_INTERVAL_SECONDS = 3


def key_fingerprint(key: str) -> str:
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:10]


def redact_sms_secrets(value: Any, secrets: list[str]) -> str:
    text = str(value or "")
    candidates = [
        secret
        for secret in normalize_sms_keys(secrets)
        if not set(secret).issubset({"*"})
    ]
    for secret in sorted(candidates, key=len, reverse=True):
        variants = {
            secret,
            urllib.parse.quote(secret, safe=""),
            urllib.parse.quote_plus(secret, safe=""),
        }
        for variant in sorted(variants, key=len, reverse=True):
            text = text.replace(variant, SECRET_MASK)
    return text


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


class SingleFlightTtlCache:
    """Deduplicate concurrent loads and briefly cache empty results."""

    def __init__(self, *, now_fn: Callable[[], float] = time.monotonic) -> None:
        self.now_fn = now_fn
        self.condition = threading.Condition()
        self.values: dict[Any, tuple[float, Any]] = {}
        self.loading: set[Any] = set()

    def clear(self) -> None:
        with self.condition:
            self.values.clear()

    def get_or_load(
        self,
        key: Any,
        loader: Callable[[], Any],
        *,
        ttl_seconds: float,
        empty_ttl_seconds: float,
    ) -> Any:
        while True:
            with self.condition:
                now = self.now_fn()
                cached = self.values.get(key)
                if cached is not None and cached[0] > now:
                    return cached[1]
                if key not in self.loading:
                    self.loading.add(key)
                    break
                self.condition.wait()

        try:
            value = loader()
        except BaseException:
            with self.condition:
                self.loading.discard(key)
                self.condition.notify_all()
            raise

        ttl = ttl_seconds if value else empty_ttl_seconds
        with self.condition:
            now = self.now_fn()
            self.values[key] = (now + max(0.0, float(ttl)), value)
            self.loading.discard(key)
            self.condition.notify_all()
        return value


class _StaleSmsPreflight(RuntimeError):
    """Stop obsolete preflight work before it uses superseded credentials."""


def _candidate_route(candidate: Any) -> tuple[str, str]:
    return candidate_route(candidate)


def _candidate_value(candidate: Any, name: str, default: Any = None) -> Any:
    """Compatibility export retained for runtime monkeypatch consumers."""
    return _route_candidate_value(candidate, name, default)


def _route_stat(route_stats: Any, route: tuple[str, str]) -> dict[str, Any]:
    """Compatibility export retained for runtime monkeypatch consumers."""
    return _route_stat_value(route_stats, route)


def parse_sms_balance(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        for key in ("balance", "amount", "value"):
            if key in value:
                return parse_sms_balance(value[key])
    text = str(value or "").strip()
    if text.startswith("{"):
        try:
            return parse_sms_balance(json.loads(text))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    match = re.search(r"(?:ACCESS_BALANCE:)?\s*(-?\d+(?:\.\d+)?)", text, re.I)
    if not match:
        raise ValueError(f"无法解析 SMS 余额响应: {text[:120] or 'empty'}")
    return float(match.group(1))


def classify_key_error(error: Any) -> str:
    text = str(error or "").lower()
    if any(marker in text for marker in ("no_balance", "no balance", "insufficient balance", "余额不足")):
        return "insufficient_balance"
    if any(marker in text for marker in ("bad_key", "wrong_key", "invalid api key", "status=401", "status=403")):
        return "invalid"
    if any(marker in text for marker in ("status=429", "too many requests", "rate limit", "ratelimit")):
        return "rate_limited"
    if any(
        marker in text
        for marker in (
            "timed out",
            "timeout",
            "urlopen error",
            "connection",
            "network",
            "ssl",
            "temporary failure",
        )
    ):
        return "network_error"
    return "other"


def is_transient_sms_network_error(value: Any) -> bool:
    text = str(value or "").lower()
    return any(
        marker in text
        for marker in (
            "timed out",
            "timeout",
            "connection reset",
            "connection aborted",
            "connection refused",
            "remote disconnected",
            "proxyerror",
            "proxy error",
            "ssleoferror",
            "sslerror",
            "tls",
            "unexpected_eof",
            "temporary failure",
            "network is unreachable",
            "name resolution",
        )
    )


def call_sms_with_retries(
    function: Callable[[], Any],
    *,
    attempts: int = SMS_NETWORK_ATTEMPTS,
    sleep_fn: Callable[[float], None] = time.sleep,
    deadline: float | None = None,
    now_fn: Callable[[], float] = time.monotonic,
) -> Any:
    last_error: Exception | None = None
    for attempt in range(max(1, int(attempts))):
        try:
            return function()
        except Exception as exc:
            if not is_transient_sms_network_error(exc):
                raise
            last_error = exc
        if attempt + 1 >= max(1, int(attempts)):
            break
        delay = min(1.5, 0.25 * (2 ** attempt))
        if deadline is not None:
            remaining = float(deadline) - float(now_fn())
            if remaining <= 0:
                break
            delay = min(delay, remaining)
        if delay > 0:
            sleep_fn(delay)
    assert last_error is not None
    raise last_error


def isolated_sms_get(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    proxy: str = "",
    timeout: int = 30,
    as_json: bool = False,
    session_factory: Callable[[], Any] | None = None,
) -> Any:
    """Perform one SMS API GET without inheriting host proxy variables."""

    if session_factory is None:
        from curl_cffi import requests as curl_requests

        session_factory = lambda: curl_requests.Session(impersonate="chrome")
    session = session_factory()
    if hasattr(session, "trust_env"):
        session.trust_env = False
    request_kwargs: dict[str, Any] = {
        "params": dict(params or {}),
        "headers": dict(headers or {}),
        "timeout": max(1, int(timeout)),
    }
    if proxy:
        request_kwargs["proxy"] = str(proxy)
        request_kwargs["verify"] = False
    response = session.get(str(url), **request_kwargs)
    if as_json:
        return response.json()
    return str(getattr(response, "text", "") or "").strip()


def is_sms_route_infrastructure_error(value: Any) -> bool:
    """Return whether an SMS outcome says nothing about route quality."""
    if isinstance(value, Mapping):
        status_value = (
            value.get("_status")
            or value.get("status")
            or value.get("status_code")
        )
    else:
        status_value = (
            getattr(value, "status_code", None)
            or getattr(getattr(value, "response", None), "status_code", None)
        )
    if int(_as_float(status_value, 0)) == 429:
        return True

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
            "tls",
            "ssl",
            "unexpected_eof",
            "connection",
            "connecterror",
            "connect error",
            "failed to connect",
            "remote disconnected",
            "server disconnected",
            "proxy",
            "curl",
            "network is unreachable",
            "name resolution",
            "too many requests",
            "rate limit",
            "ratelimit",
        )
    )
