"""Thread-safe SMS key pooling, balance checks, and cost accounting."""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable, Iterator
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


SECRET_MASK = "********"
ECB_DAILY_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
SMS_PREFLIGHT_MAX_WORKERS = 8
SMS_PROVIDER_DEFAULT_SERVICES = {
    "smsbower": "dr",
    "herosms": "dr",
    "5sim": "openai",
}
SMS_PROVIDER_ALIASES = {
    "hero-sms": "herosms",
    "hero_sms": "herosms",
    "fivesim": "5sim",
    "five_sim": "5sim",
}
PERFORMANCE_POLICY_VERSION = 10
PHONE_MAX_ATTEMPTS_LIMIT = 45
PERFORMANCE_DEFAULTS = {
    "auto_email_login_concurrency": 5,
    "phone_max_attempts": PHONE_MAX_ATTEMPTS_LIMIT,
    "phone_attempts_per_provider": 15,
    "phone_session_cycle_seconds": 1800,
    "auth_session_retries": 1,
}
SMS_NETWORK_ATTEMPTS = 3
SMS_FIRST_WAIT_SECONDS = 30
SMS_SECOND_WAIT_SECONDS = 30
SMS_POLL_INTERVAL_SECONDS = 3
_CANCEL_RECEIPT_KEYS = frozenset(
    {"cancel_state", "provider_response", "provider_status", "refund_status"}
)


def normalize_sms_keys(value: Any = None, legacy: Any = "") -> list[str]:
    """Normalize the canonical key list without interpreting key punctuation."""
    if isinstance(value, (list, tuple)):
        candidates = value
    elif isinstance(value, str) and value.strip():
        candidates = [value]
    elif legacy is not None:
        candidates = [legacy]
    else:
        candidates = []

    result: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate or "").strip()
        if not key or key == SECRET_MASK or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def normalize_sms_provider_name(value: Any) -> str:
    name = str(value or "").strip().lower()
    return SMS_PROVIDER_ALIASES.get(name, name)


def _safe_provider_token(value: Any) -> str:
    if isinstance(value, dict):
        value = next(
            (
                value.get(key)
                for key in ("status", "response", "result", "message", "error", "title", "code")
                if value.get(key) not in (None, "")
            ),
            "",
        )
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    text = str(value or "").strip()
    if text.startswith("{") or "{" in text:
        candidate = text[text.find("{") :]
        try:
            parsed = json.loads(candidate)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, dict):
            return _safe_provider_token(parsed)
    text = text.upper()
    return re.sub(r"[^A-Z0-9_.:-]+", "_", text)[:80]


def _provider_exception_text(error: BaseException) -> str:
    parts = [str(error or "")]
    reader = getattr(error, "read", None)
    if callable(reader):
        try:
            body = reader()
            if isinstance(body, bytes):
                body = body.decode("utf-8", "replace")
            parts.append(str(body or ""))
        except Exception:
            pass
    return " ".join(part for part in parts if part)


def _herosms_min_cancel_seconds(value: Any, default: int = 120) -> int:
    if isinstance(value, dict):
        info = value.get("info")
        if isinstance(info, dict):
            value = info.get("minActivationTime") or info.get("min_activation_time")
        else:
            value = value.get("minActivationTime") or value.get("min_activation_time")
    try:
        return max(1, min(600, int(value)))
    except (TypeError, ValueError):
        return int(default)


class HeroSmsCancellationDeferred(RuntimeError):
    """Signal that provider cancellation must resume after its protection window."""

    def __init__(self, retry_after_seconds: float, minimum_seconds: int) -> None:
        self.retry_after_seconds = max(1.0, float(retry_after_seconds))
        self.minimum_seconds = max(1, int(minimum_seconds))
        super().__init__(
            f"herosms_cancel_deferred:retry_after={int(self.retry_after_seconds)}"
        )


def herosms_cancel_delay_seconds(
    leased_at: Any,
    minimum_seconds: Any = 120,
    *,
    now_fn: Callable[[], float] = time.time,
) -> float:
    try:
        started = float(leased_at)
    except (TypeError, ValueError):
        started = float(now_fn())
    minimum = _herosms_min_cancel_seconds(minimum_seconds)
    elapsed = max(0.0, float(now_fn()) - started)
    return max(1.0, float(minimum) - elapsed + 1.0)


def safe_cancel_receipt(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key in _CANCEL_RECEIPT_KEYS:
        token = _safe_provider_token(value.get(key))
        if token:
            result[key] = token.lower() if key in {"cancel_state", "refund_status"} else token
    return result


def confirm_herosms_cancellation(
    provider: Any,
    activation_id: Any,
    *,
    now_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
    on_wait: Callable[[float], None] | None = None,
    leased_at: float | None = None,
    defer_early: bool = False,
) -> dict[str, str]:
    """Cancel one HeroSMS activation using its documented refund contract."""
    api = getattr(provider, "_api", None)
    activation = str(activation_id or "").strip()
    if not callable(api) or not activation:
        raise RuntimeError("herosms_cancel_confirmation_unavailable")
    started = float(leased_at) if leased_at is not None else float(now_fn())
    response = ""
    minimum_seconds = 120
    for attempt in range(3):
        try:
            raw_response = api({"action": "setStatus", "status": "8", "id": activation})
            response = _safe_provider_token(raw_response)
            minimum_seconds = _herosms_min_cancel_seconds(raw_response, minimum_seconds)
        except Exception as exc:
            raw_response = _provider_exception_text(exc)
            response = _safe_provider_token(raw_response)
            if response != "EARLY_CANCEL_DENIED":
                raise RuntimeError(
                    f"herosms_cancel_request_failed:{type(exc).__name__}"
                ) from exc

        if response == "ACCESS_CANCEL":
            break
        if response != "EARLY_CANCEL_DENIED":
            raise RuntimeError(f"herosms_cancel_rejected:{response or 'EMPTY_RESPONSE'}")
        if attempt >= 2:
            raise RuntimeError("herosms_cancel_early_denied_after_retry")
        wait_seconds = herosms_cancel_delay_seconds(
            started,
            minimum_seconds,
            now_fn=now_fn,
        )
        if callable(on_wait):
            try:
                on_wait(wait_seconds)
            except Exception:
                pass
        if defer_early:
            raise HeroSmsCancellationDeferred(wait_seconds, minimum_seconds)
        sleep_fn(wait_seconds)

    # HeroSMS documents ACCESS_CANCEL from setStatus=8 as the successful
    # "cancel activation (return funds)" response. A follow-up getStatus is
    # useful for diagnosis, but it can race activation cleanup or fail after
    # the cancellation has already been accepted; it must not negate that
    # authoritative acknowledgement.
    try:
        provider_status = _safe_provider_token(
            api({"action": "getStatus", "id": activation})
        )
    except Exception:
        provider_status = "STATUS_CHECK_UNAVAILABLE"
    return {
        "cancel_state": "confirmed",
        "provider_response": response,
        "provider_status": provider_status or "STATUS_CHECK_EMPTY",
        "refund_status": "provider_refund_accepted",
    }


def normalize_sms_provider_pools(
    value: Any = None,
    *,
    legacy_provider: Any = "smsbower",
    legacy_keys: Any = None,
    legacy_key: Any = "",
) -> list[dict[str, Any]]:
    """Normalize platform pools while accepting the pre-pool SMS settings."""
    rows = value if isinstance(value, (list, tuple)) else []
    pools: list[dict[str, Any]] = []
    by_provider: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        provider = normalize_sms_provider_name(raw.get("provider"))
        if not provider:
            continue
        service = str(
            raw.get("service") or SMS_PROVIDER_DEFAULT_SERVICES.get(provider, "dr")
        ).strip() or SMS_PROVIDER_DEFAULT_SERVICES.get(provider, "dr")
        keys = normalize_sms_keys(raw.get("api_keys"))
        existing = by_provider.get(provider)
        if existing is not None:
            existing["enabled"] = bool(existing.get("enabled")) or bool(raw.get("enabled", True))
            existing["api_keys"] = normalize_sms_keys(
                [*(existing.get("api_keys") or []), *keys]
            )
            if not existing.get("service"):
                existing["service"] = service
            continue
        pool = {
            "provider": provider,
            "enabled": bool(raw.get("enabled", True)),
            "api_keys": keys,
            "service": service,
        }
        by_provider[provider] = pool
        pools.append(pool)
    if pools:
        return pools

    provider = normalize_sms_provider_name(legacy_provider) or "smsbower"
    service = SMS_PROVIDER_DEFAULT_SERVICES.get(provider, "dr")
    return [
        {
            "provider": provider,
            "enabled": True,
            "api_keys": normalize_sms_keys(legacy_keys, legacy_key),
            "service": service,
        }
    ]


def flatten_sms_provider_keys(pools: Any) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for pool in pools if isinstance(pools, (list, tuple)) else []:
        if not isinstance(pool, dict):
            continue
        for key in normalize_sms_keys(pool.get("api_keys")):
            if key not in seen:
                seen.add(key)
                result.append(key)
    return result


def legacy_sms_provider_keys(pools: Any, provider: Any = "") -> list[str]:
    """Return one platform's keys for recovered single-provider call sites."""

    rows = normalize_sms_provider_pools(pools)
    wanted = normalize_sms_provider_name(provider)
    if wanted:
        for row in rows:
            if str(row.get("provider") or "") == wanted:
                return normalize_sms_keys(row.get("api_keys"))
    for row in rows:
        keys = normalize_sms_keys(row.get("api_keys"))
        if bool(row.get("enabled", True)) and keys:
            return keys
    return normalize_sms_keys(rows[0].get("api_keys")) if rows else []


def migrate_performance_config(value: Any) -> tuple[dict[str, Any], bool]:
    """Apply the one-time performance defaults while preserving later user choices."""
    config = dict(value or {}) if isinstance(value, dict) else {}
    try:
        version = int(config.get("performance_policy_version") or 0)
    except (TypeError, ValueError):
        version = 0
    migrated = version < PERFORMANCE_POLICY_VERSION
    if migrated:
        for key, default in PERFORMANCE_DEFAULTS.items():
            try:
                current = int(config.get(key) or 0)
            except (TypeError, ValueError):
                current = 0
            if current <= 0 or (
                version < PERFORMANCE_POLICY_VERSION
                and (
                    (key == "auto_email_login_concurrency" and current == 1)
                    or
                    (key == "phone_max_attempts" and current in {9, 15})
                    or (key == "phone_session_cycle_seconds" and current == 480)
                )
            ):
                config[key] = default
        config["performance_policy_version"] = PERFORMANCE_POLICY_VERSION
    else:
        for key, default in PERFORMANCE_DEFAULTS.items():
            if key not in config:
                config[key] = default

    try:
        phone_max_attempts = int(config.get("phone_max_attempts") or 0)
    except (TypeError, ValueError):
        phone_max_attempts = 0
    if phone_max_attempts > PHONE_MAX_ATTEMPTS_LIMIT:
        config["phone_max_attempts"] = PHONE_MAX_ATTEMPTS_LIMIT

    try:
        task_concurrency = max(1, min(100, int(config.get("concurrency") or 5)))
    except (TypeError, ValueError):
        task_concurrency = 5
    try:
        email_concurrency = int(
            config.get("auto_email_login_concurrency")
            or PERFORMANCE_DEFAULTS["auto_email_login_concurrency"]
        )
    except (TypeError, ValueError):
        email_concurrency = PERFORMANCE_DEFAULTS["auto_email_login_concurrency"]
    config["auto_email_login_concurrency"] = max(
        1,
        min(task_concurrency, email_concurrency),
    )

    pools = normalize_sms_provider_pools(
        config.get("sms_provider_pools"),
        legacy_provider=config.get("sms_provider") or "smsbower",
        legacy_keys=config.get("sms_api_keys"),
        legacy_key=config.get("sms_api_key"),
    )
    config["sms_provider_pools"] = pools
    config["sms_provider"] = str(pools[0].get("provider") or "smsbower")
    keys = legacy_sms_provider_keys(pools, config["sms_provider"])
    config["sms_api_keys"] = keys
    config["sms_api_key"] = keys[0] if keys else ""
    return config, migrated


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


def _candidate_value(candidate: Any, name: str, default: Any = None) -> Any:
    if isinstance(candidate, dict):
        return candidate.get(name, default)
    return getattr(candidate, name, default)


def _candidate_route(candidate: Any) -> tuple[str, str]:
    """Return the recovered selector's persisted route identity.

    ``SmsCandidate.pool`` describes the selector quality bucket (for example
    ``main`` or ``explore``), not an SMS platform.  The recovered selector
    persists routes strictly as ``country::provider_id`` and shares their
    history across those transient buckets.
    """
    country = str(_candidate_value(candidate, "country", "") or "")
    provider_id = str(_candidate_value(candidate, "provider_id", "") or "")
    return country, provider_id


def _route_stat(route_stats: Any, route: tuple[str, str]) -> dict[str, Any]:
    if not isinstance(route_stats, dict):
        return {}
    value = route_stats.get(route)
    if not isinstance(value, dict):
        value = route_stats.get("::".join(route))
    return value if isinstance(value, dict) else {}


def rank_sms_candidates(
    candidates: list[Any],
    route_stats: Any,
    *,
    priority_routes: tuple[tuple[str, ...], ...] = (),
    priority_countries: tuple[str, ...] = (),
    minimum_proven_rate: float = 0.10,
    now: float | None = None,
    recent_success_window_seconds: float = 600.0,
    reliability_mode: bool = False,
) -> list[Any]:
    """Rank routes normally, or put mature delivery routes first for risk retries."""
    route_priority = {route: index for index, route in enumerate(priority_routes)}
    country_priority = {country: index for index, country in enumerate(priority_countries)}
    default_route_priority = len(route_priority)
    default_country_priority = len(country_priority)
    current = time.time() if now is None else float(now)
    recent_window = max(0.0, float(recent_success_window_seconds))

    def metrics(candidate: Any) -> dict[str, Any]:
        route = _candidate_route(candidate)
        legacy_route = route[-2:]
        stat = _route_stat(route_stats, route)
        if not stat and route != legacy_route:
            stat = _route_stat(route_stats, legacy_route)
        final_success = max(0, int(_as_float(stat.get("success"), 0)))
        otp_received = max(0, int(_as_float(stat.get("otp_received"), 0)))
        failures = max(0, int(_as_float(stat.get("fail"), 0)))
        no_numbers = max(0, int(_as_float(stat.get("no_numbers"), 0)))
        classified_failures = sum(
            max(0, int(_as_float(stat.get(name), 0)))
            for name in ("phone_rejected", "register_rejected", "invalid_auth_step", "timeout")
        )
        rejected = max(0, failures - no_numbers, classified_failures)
        acceptance_success = max(final_success, otp_received)
        observations = acceptance_success + rejected + no_numbers
        acceptance_rate = acceptance_success / observations if observations else 0.0
        final_attempts = final_success + rejected
        final_success_rate = final_success / final_attempts if final_attempts else 0.0
        delivery_failures = max(
            int(_as_float(stat.get("timeout"), 0)),
            int(_as_float(stat.get("otp_sent"), 0)),
        )
        delivery_attempts = otp_received + max(0, delivery_failures)
        delivery_rate = otp_received / delivery_attempts if delivery_attempts else 0.0
        last_success_at = max(
            _as_float(stat.get("last_success_at"), 0.0),
            _as_float(stat.get("last_delivery_at"), 0.0),
        )
        recently_successful = bool(
            last_success_at > 0
            and recent_window > 0
            and 0 <= current - last_success_at <= recent_window
        )
        preferred = route in route_priority or legacy_route in route_priority

        return {
            "route": route,
            "legacy_route": legacy_route,
            "final_success": final_success,
            "otp_received": otp_received,
            "observations": observations,
            "acceptance_rate": acceptance_rate,
            "final_success_rate": final_success_rate,
            "delivery_rate": delivery_rate,
            "last_success_at": last_success_at,
            "recently_successful": recently_successful,
            "preferred": preferred,
        }

    def normal_key(candidate: Any) -> tuple[Any, ...]:
        values = metrics(candidate)
        route = values["route"]
        legacy_route = values["legacy_route"]
        success = max(values["final_success"], values["otp_received"])
        observations = values["observations"]
        acceptance_rate = values["acceptance_rate"]

        if success > 0 and acceptance_rate >= minimum_proven_rate:
            tier = 0
        elif observations == 0 and values["preferred"]:
            tier = 1
        elif success > 0:
            tier = 2
        elif observations == 0:
            tier = 3
        else:
            tier = 4

        return (
            tier,
            not values["recently_successful"],
            -acceptance_rate,
            -success,
            route_priority.get(route, route_priority.get(legacy_route, default_route_priority)),
            country_priority.get(route[-2], default_country_priority),
            -_as_float(_candidate_value(candidate, "score", 0.0), 0.0),
            _as_float(_candidate_value(candidate, "price", 999.0), 999.0),
            -int(_as_float(_candidate_value(candidate, "count", 0), 0)),
        )

    if not reliability_mode:
        return sorted(candidates, key=normal_key)

    def reliability_key(candidate: Any) -> tuple[Any, ...]:
        values = metrics(candidate)
        qualified = (
            values["final_success"] > 0
            and values["final_success_rate"] >= minimum_proven_rate
        )
        if values["otp_received"] > 0 and qualified:
            tier = 0
        elif values["otp_received"] == 0 and qualified:
            tier = 1
        else:
            return (2, *normal_key(candidate))
        return (
            tier,
            not values["recently_successful"],
            -values["last_success_at"],
            -values["delivery_rate"],
            -values["final_success_rate"],
            -values["final_success"],
            _as_float(_candidate_value(candidate, "price", 999.0), 999.0),
            -int(_as_float(_candidate_value(candidate, "count", 0), 0)),
        )

    return sorted(candidates, key=reliability_key)


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


def is_protocol_pressure_error(value: Any) -> bool:
    text = str(value or "").lower()
    return any(
        marker in text
        for marker in (
            "ssleoferror",
            "sslerror",
            "unexpected_eof",
            "tls connect",
            "connection reset",
            "connection aborted",
            "connection closed",
            "remote end closed connection",
            "remote disconnected",
            "server disconnected",
            "curl: (56)",
            "status=429",
            "http 429",
            "too many requests",
            "rate limit",
        )
    )


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


@dataclass
class _ProxyProtocolState:
    active: int = 0
    waiting: int = 0
    limit: int = 3
    ceiling: int = 3
    last_started_at: float = 0.0
    pressure_events: list[float] = field(default_factory=list)
    success_streak: int = 0


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
        self.now_fn = now_fn
        self.pressure_window_seconds = max(1.0, float(pressure_window_seconds))
        self.restore_successes = max(1, int(restore_successes))
        self.launch_interval_seconds = max(0.0, float(launch_interval_seconds))
        self.condition = threading.Condition()
        self.states: dict[str, _ProxyProtocolState] = {}

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
                ceiling=self.default_limit,
            ),
        )

    def begin_run(self, limit: Any) -> int:
        ceiling = max(1, int(limit))
        with self.condition:
            self.default_limit = ceiling
            for state in self.states.values():
                state.ceiling = ceiling
                state.limit = min(ceiling, max(1, state.limit)) if state.active else ceiling
                state.pressure_events.clear()
                state.success_streak = 0
                state.last_started_at = 0.0
            self.condition.notify_all()
        return ceiling

    @staticmethod
    def _stopped(stop_event: Any) -> bool:
        if stop_event is None:
            return False
        checker = getattr(stop_event, "is_set", None)
        if callable(checker):
            return bool(checker())
        return bool(stop_event()) if callable(stop_event) else bool(stop_event)

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
                            if state.active < state.limit and launch_wait <= 0:
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
        with self.condition:
            state = self._state(key)
            now = float(self.now_fn())
            old_limit = state.limit
            if success:
                state.pressure_events = [
                    observed
                    for observed in state.pressure_events
                    if 0 <= now - observed <= self.pressure_window_seconds
                ]
                state.success_streak += 1
                if state.limit < state.ceiling and state.success_streak >= self.restore_successes:
                    state.limit += 1
                    state.success_streak = 0
                    self.condition.notify_all()
            elif not is_protocol_pressure_error(value):
                state.success_streak = 0
            else:
                state.success_streak = 0
                state.pressure_events = [
                    observed
                    for observed in state.pressure_events
                    if 0 <= now - observed <= self.pressure_window_seconds
                ]
                state.pressure_events.append(now)
                if len(state.pressure_events) >= 2 and state.limit > 1:
                    state.limit -= 1
                    state.pressure_events.clear()
            new_limit = state.limit
            if new_limit != old_limit:
                event = {
                    "kind": "restored" if new_limit > old_limit else "degraded",
                    "old_limit": old_limit,
                    "new_limit": new_limit,
                    "ceiling": state.ceiling,
                    "proxy_key": key,
                }
        if event is not None:
            _notify_observer(on_limit_change, event)
        return new_limit

    def snapshot(self, proxy: Any) -> dict[str, int]:
        key = self.key(proxy)
        with self.condition:
            state = self.states.get(key) or _ProxyProtocolState(
                limit=self.default_limit,
                ceiling=self.default_limit,
            )
            return {
                "active": state.active,
                "limit": state.limit,
                "ceiling": state.ceiling,
                "waiting": state.waiting,
            }


@dataclass
class SmsKeyHealth:
    key: str = field(repr=False)
    index: int = 0
    fingerprint: str = ""
    status: str = "unchecked"
    balance_usd: float | None = None
    message: str = ""
    in_flight: int = 0
    cooldown_until: float = 0.0
    last_checked_at: float = 0.0
    health_revision: int = 0

    def public(self, now: float | None = None) -> dict[str, Any]:
        current = time.time() if now is None else now
        return {
            "index": self.index,
            "fingerprint": self.fingerprint,
            "status": self.status,
            "balance_usd": None if self.balance_usd is None else round(self.balance_usd, 4),
            "message": self.message,
            "in_flight": self.in_flight,
            "retry_after_seconds": max(0, int(self.cooldown_until - current)),
            "last_checked_at": int(self.last_checked_at or 0),
        }


@dataclass(frozen=True)
class _SmsKeyReservation:
    state: SmsKeyHealth
    health_revision: int


class SmsKeyPool:
    """Selects a healthy SMSBower account and binds each activation to it."""

    def __init__(
        self,
        provider_factory: Callable[..., Any],
        *,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.provider_factory = provider_factory
        self.now_fn = now_fn
        self.lock = threading.RLock()
        self.price_floor_cache = SingleFlightTtlCache(now_fn=now_fn)
        self.states: list[SmsKeyHealth] = []
        self.cursor = 0
        self.preflight_generation = 0
        self.service = "dr"
        self.min_price = 0.01
        self.max_price = 0.15
        self.logger: Callable[[str, str], None] | None = None
        self.alert_fn: Callable[[dict[str, Any]], None] | None = None
        self.exhausted_fn: Callable[[], None] | None = None
        self.alerted: set[tuple[str, str]] = set()
        self.exhaustion_reported = False

    def configure(
        self,
        keys: list[str],
        *,
        service: str = "dr",
        min_price: float = 0.01,
        max_price: float = 0.15,
        logger: Callable[[str, str], None] | None = None,
        alert_fn: Callable[[dict[str, Any]], None] | None = None,
        exhausted_fn: Callable[[], None] | None = None,
    ) -> None:
        normalized = normalize_sms_keys(keys)
        fingerprints = [key_fingerprint(key) for key in normalized]
        with self.lock:
            self.preflight_generation += 1
            existing = {state.fingerprint: state for state in self.states}
            if fingerprints != [state.fingerprint for state in self.states]:
                self.states = [
                    SmsKeyHealth(
                        key=key,
                        index=index,
                        fingerprint=fingerprint,
                        status=existing.get(fingerprint, SmsKeyHealth(key)).status,
                        balance_usd=existing.get(fingerprint, SmsKeyHealth(key)).balance_usd,
                        message=existing.get(fingerprint, SmsKeyHealth(key)).message,
                        cooldown_until=existing.get(fingerprint, SmsKeyHealth(key)).cooldown_until,
                        last_checked_at=existing.get(fingerprint, SmsKeyHealth(key)).last_checked_at,
                        health_revision=existing.get(fingerprint, SmsKeyHealth(key)).health_revision,
                    )
                    for index, (key, fingerprint) in enumerate(zip(normalized, fingerprints), start=1)
                ]
                self.cursor = 0
                self.alerted.clear()
                self.exhaustion_reported = False
            self.service = str(service or "dr").strip() or "dr"
            self.min_price = max(0.0, _as_float(min_price, 0.01))
            self.max_price = max(self.min_price, _as_float(max_price, 0.15))
            if logger is not None:
                self.logger = logger
            if alert_fn is not None:
                self.alert_fn = alert_fn
            if exhausted_fn is not None:
                self.exhausted_fn = exhausted_fn

    def begin_run(self) -> None:
        with self.lock:
            self.preflight_generation += 1
            for state in self.states:
                state.in_flight = 0
            self.alerted.clear()
            self.exhaustion_reported = False

    def has_keys(self) -> bool:
        with self.lock:
            return bool(self.states)

    def public_statuses(self) -> list[dict[str, Any]]:
        with self.lock:
            now = self.now_fn()
            return [state.public(now) for state in self.states]

    def safe_error(self, error: Any, extra_secrets: Any = None) -> str:
        with self.lock:
            secrets = [state.key for state in self.states]
        secrets.extend(normalize_sms_keys(extra_secrets))
        return redact_sms_secrets(error, secrets)

    def usable_count(self) -> int:
        with self.lock:
            return sum(1 for state in self.states if state.status == "usable")

    def unusable_count(self) -> int:
        with self.lock:
            return sum(1 for state in self.states if state.status != "usable")

    def all_balance_insufficient(self) -> bool:
        with self.lock:
            return bool(self.states) and all(state.status == "insufficient_balance" for state in self.states)

    def is_exhausted(self) -> bool:
        with self.lock:
            return self._hard_exhausted_locked()

    def _hard_exhausted_locked(self) -> bool:
        return bool(self.states) and all(state.status in {"insufficient_balance", "invalid"} for state in self.states)

    def _log(self, message: str, level: str = "info") -> None:
        if callable(self.logger):
            try:
                self.logger(message, level)
            except Exception:
                pass

    def _emit_alert_locked(self, state: SmsKeyHealth, kind: str, message: str) -> None:
        alert_key = (state.fingerprint, kind)
        if alert_key in self.alerted:
            return
        self.alerted.add(alert_key)
        payload = {
            "kind": kind,
            "index": state.index,
            "fingerprint": state.fingerprint,
            "message": message,
        }
        if callable(self.alert_fn):
            try:
                self.alert_fn(payload)
            except Exception:
                pass

    def _mark_error(
        self,
        state: SmsKeyHealth,
        error: Any,
        *,
        runtime: bool,
        expected_revision: int | None = None,
        expected_generation: int | None = None,
    ) -> str:
        kind = classify_key_error(error)
        now = self.now_fn()
        text = self.safe_error(error, [state.key])
        with self.lock:
            if expected_generation is not None and self.preflight_generation != expected_generation:
                return kind
            if expected_revision is not None and state.health_revision != expected_revision:
                return kind
            state.health_revision += 1
            state.last_checked_at = now
            if kind == "insufficient_balance":
                state.status = kind
                state.balance_usd = 0.0
                state.message = "余额不足"
                state.cooldown_until = 0.0
            elif kind == "invalid":
                state.status = kind
                state.message = "API Key 无效"
                state.cooldown_until = 0.0
            elif kind == "rate_limited":
                state.status = kind
                state.message = "请求限流，稍后重试"
                state.cooldown_until = now + 60
            elif kind == "network_error":
                state.status = kind
                state.message = "网络请求失败，稍后重试"
                state.cooldown_until = now + 30
            elif runtime:
                state.status = "usable"
                state.message = "可用"
                state.cooldown_until = 0.0
            else:
                state.status = "error"
                state.message = text[:160] or "余额查询失败"
                state.cooldown_until = 0.0
            if runtime and kind in {"insufficient_balance", "invalid", "rate_limited", "network_error"}:
                label = {
                    "insufficient_balance": "余额不足",
                    "invalid": "API Key 无效",
                    "rate_limited": "请求被限流",
                    "network_error": "网络异常",
                }[kind]
                message = f"SMS Key {state.index}（{state.fingerprint}）{label}，已切换其他 Key"
                self._emit_alert_locked(state, kind, message)
                self._log(message, "warn")
        return kind

    def report_error(self, state: SmsKeyHealth | None, error: Any, *, runtime: bool = True) -> str:
        if state is None:
            return classify_key_error(error)
        return self._mark_error(state, error, runtime=runtime)

    def _query_price_floor(
        self,
        proxy: str,
        states: list[SmsKeyHealth],
        *,
        expected_generation: int,
    ) -> float:
        with self.lock:
            service = self.service
            min_price = self.min_price
            max_price = self.max_price
        preferred = sorted(
            states,
            key=lambda state: (state.status != "usable", state.index),
        )[:2]
        cache_key = (
            tuple(state.fingerprint for state in preferred),
            service,
            min_price,
            max_price,
            key_fingerprint(proxy) if proxy else "direct",
        )

        def ensure_current() -> None:
            with self.lock:
                if self.preflight_generation != expected_generation:
                    raise _StaleSmsPreflight

        def load_price_floor() -> float | None:
            for state in preferred:
                ensure_current()
                try:
                    provider = self.provider_factory(state.key, proxy=proxy)
                    rows = provider.get_price_candidates(service=service)
                except Exception:
                    continue
                prices = []
                for row in rows or []:
                    if not isinstance(row, dict):
                        continue
                    price = _as_float(row.get("price"), -1)
                    count = int(_as_float(row.get("count"), 0))
                    if count > 0 and min_price <= price <= max_price:
                        prices.append(price)
                if prices:
                    return min(prices)
            return None

        if not preferred:
            return min_price
        ensure_current()
        value = self.price_floor_cache.get_or_load(
            cache_key,
            load_price_floor,
            ttl_seconds=60,
            empty_ttl_seconds=5,
        )
        return min_price if value is None else float(value)

    def query_balances(self, *, proxy: str = "") -> list[dict[str, Any]]:
        """Query configured keys without performing inventory discovery."""
        with self.lock:
            states = list(self.states)
            self.preflight_generation += 1
            generation = self.preflight_generation
            revisions = {
                id(state): state.health_revision
                for state in states
            }
            minimum_balance = self.min_price
        if not states:
            return []

        def check_balance(
            state: SmsKeyHealth,
        ) -> tuple[SmsKeyHealth, int, float, float | None, Exception | None]:
            revision = revisions[id(state)]
            now = self.now_fn()
            try:
                provider = self.provider_factory(state.key, proxy=proxy)
                balance = parse_sms_balance(provider.balance())
            except Exception as exc:
                return state, revision, now, None, exc
            return state, revision, now, balance, None

        workers = min(SMS_PREFLIGHT_MAX_WORKERS, len(states))
        if workers == 1:
            results = [check_balance(states[0])]
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sms-balance") as executor:
                results = list(executor.map(check_balance, states))

        for state, revision, now, balance, error in results:
            if error is not None:
                self._mark_error(
                    state,
                    error,
                    runtime=False,
                    expected_revision=revision,
                    expected_generation=generation,
                )
                continue
            with self.lock:
                if self.preflight_generation != generation:
                    continue
                if state.health_revision != revision:
                    continue
                assert balance is not None
                state.health_revision += 1
                state.balance_usd = balance
                state.last_checked_at = now
                state.cooldown_until = 0.0
                if balance + 1e-9 < minimum_balance:
                    state.status = "insufficient_balance"
                    state.message = f"余额低于配置最低价格 ${minimum_balance:.4f}"
                else:
                    state.status = "usable"
                    state.message = "余额查询成功"
        return self.public_statuses()

    def preflight(self, *, proxy: str = "") -> list[dict[str, Any]]:
        with self.lock:
            states = list(self.states)
            self.preflight_generation += 1
            generation = self.preflight_generation
            revisions = {
                id(state): state.health_revision
                for state in states
            }
        if not states:
            return []

        def check_balance(
            state: SmsKeyHealth,
        ) -> tuple[SmsKeyHealth, int, float, float | None, Exception | None]:
            revision = revisions[id(state)]
            now = self.now_fn()
            try:
                provider = self.provider_factory(state.key, proxy=proxy)
                balance = parse_sms_balance(provider.balance())
            except Exception as exc:
                return state, revision, now, None, exc
            return state, revision, now, balance, None

        workers = min(SMS_PREFLIGHT_MAX_WORKERS, len(states))
        if workers == 1:
            results = [check_balance(states[0])]
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sms-preflight") as executor:
                results = list(executor.map(check_balance, states))

        try:
            price_floor = self._query_price_floor(
                proxy,
                [state for state, _revision, _now, balance, error in results if error is None and balance is not None],
                expected_generation=generation,
            )
        except _StaleSmsPreflight:
            return self.public_statuses()

        for state, revision, now, balance, error in results:
            if error is not None:
                self._mark_error(
                    state,
                    error,
                    runtime=False,
                    expected_revision=revision,
                    expected_generation=generation,
                )
                continue
            with self.lock:
                if self.preflight_generation != generation:
                    continue
                if state.health_revision != revision:
                    continue
                assert balance is not None
                state.health_revision += 1
                state.balance_usd = balance
                state.last_checked_at = now
                state.cooldown_until = 0.0
                if balance + 1e-9 < price_floor:
                    state.status = "insufficient_balance"
                    state.message = f"余额不足，最低可用报价 ${price_floor:.4f}"
                else:
                    state.status = "usable"
                    state.message = "可用"
        return self.public_statuses()

    def _state_selectable_locked(self, state: SmsKeyHealth, now: float) -> bool:
        if state.status in {"usable", "unchecked"}:
            return True
        if state.status in {"rate_limited", "network_error"} and state.cooldown_until <= now:
            return True
        return False

    def _reserve_state(self, excluded: set[str]) -> _SmsKeyReservation | None:
        with self.lock:
            now = self.now_fn()
            selectable = [
                state
                for state in self.states
                if state.fingerprint not in excluded and self._state_selectable_locked(state, now)
            ]
            if not selectable:
                return None
            count = max(1, len(self.states))
            state = min(
                selectable,
                key=lambda item: (item.in_flight, (item.index - 1 - self.cursor) % count),
            )
            state.in_flight += 1
            self.cursor = state.index % count
            return _SmsKeyReservation(state, state.health_revision)

    def _mark_success(self, reservation: _SmsKeyReservation) -> bool:
        with self.lock:
            state = reservation.state
            if state.health_revision != reservation.health_revision:
                return False
            state.health_revision += 1
            state.status = "usable"
            state.message = "可用"
            state.cooldown_until = 0.0
            return True

    def _release_state(self, state: SmsKeyHealth | None) -> None:
        callback = None
        with self.lock:
            if state is not None:
                state.in_flight = max(0, state.in_flight - 1)
            if self._hard_exhausted_locked() and not self.exhaustion_reported:
                self.exhaustion_reported = True
                callback = self.exhausted_fn
        if callable(callback):
            try:
                callback()
            except Exception:
                pass

    def query(self, method: str, *, proxy: str = "", **kwargs: Any) -> Any:
        excluded: set[str] = set()
        while True:
            reservation = self._reserve_state(excluded)
            if reservation is None:
                raise RuntimeError(self.unavailable_error())
            state = reservation.state
            try:
                provider = self.provider_factory(state.key, proxy=proxy)
                result = getattr(provider, method)(**kwargs)
            except Exception as exc:
                kind = self._mark_error(state, exc, runtime=True)
                self._release_state(state)
                if kind in {"insufficient_balance", "invalid", "rate_limited", "network_error"}:
                    excluded.add(state.fingerprint)
                    continue
                raise RuntimeError(self.safe_error(exc, [state.key])) from exc
            self._release_state(state)
            self._mark_success(reservation)
            return result

    def activate(
        self,
        method: str,
        *,
        proxy: str = "",
        price_usd: float | None = None,
        **kwargs: Any,
    ) -> tuple[Any, SmsKeyHealth, tuple[str, str]]:
        excluded: set[str] = set()
        while True:
            reservation = self._reserve_state(excluded)
            if reservation is None:
                raise RuntimeError(self.unavailable_error())
            state = reservation.state
            try:
                provider = self.provider_factory(state.key, proxy=proxy)
                activation = getattr(provider, method)(**kwargs)
            except Exception as exc:
                kind = self._mark_error(state, exc, runtime=True)
                self._release_state(state)
                if kind in {"insufficient_balance", "invalid", "rate_limited", "network_error"}:
                    excluded.add(state.fingerprint)
                    continue
                raise RuntimeError(self.safe_error(exc, [state.key])) from exc
            self._mark_success(reservation)
            return provider, state, activation

    def release(self, state: SmsKeyHealth | None) -> None:
        self._release_state(state)

    def unavailable_error(self) -> str:
        with self.lock:
            if self._hard_exhausted_locked():
                if any(state.status == "insufficient_balance" for state in self.states):
                    return "sms_balance_insufficient: 所有可用 SMS Key 余额不足"
                return "sms_key_pool_unavailable: 所有 SMS Key 均不可用"
            if self.states:
                return "sms_key_pool_temporarily_unavailable: SMS Key 暂时不可用"
            return "sms_key_missing: 请至少填写一个 SMS API Key"


class PooledSmsBowerProvider:
    """Provider-compatible facade that keeps an activation on its selected key."""

    SMART_ANY_PROVIDER_FALLBACK = True
    SMART_COUNTRY_SCOPE_FILTER = True
    SMART_FIXED_COUNTRY_FALLBACK = False

    def __init__(self, pool: SmsKeyPool, *, proxy: str = "") -> None:
        self.pool = pool
        self.proxy = proxy
        self.api_key = ""
        self.activation_id: str | None = None
        self.phone: str | None = None
        self._provider: Any = None
        self._state: SmsKeyHealth | None = None
        self._released = True
        self.current_order_meta: dict[str, Any] = {}

    def balance(self) -> str:
        statuses = self.pool.public_statuses()
        total = sum(float(item.get("balance_usd") or 0) for item in statuses if item.get("status") == "usable")
        return f"ACCESS_BALANCE:{total:.4f}"

    def get_price_candidates(self, service: str = "dr", countries: list[str] | None = None) -> list[dict[str, Any]]:
        return self.pool.query(
            "get_price_candidates",
            proxy=self.proxy,
            service=service,
            countries=countries,
        )

    def get_available_countries(self, service: str = "dr") -> Any:
        return self.pool.query("get_available_countries", proxy=self.proxy, service=service)

    def _activate(self, method: str, price_usd: float | None = None, **kwargs: Any) -> tuple[str, str]:
        if not self._released:
            raise RuntimeError("SMS provider already has an active activation")
        provider, state, activation = self.pool.activate(
            method,
            proxy=self.proxy,
            price_usd=price_usd,
            **kwargs,
        )
        try:
            activation_id, phone = activation
            activation_text = str(activation_id).strip()
            phone_text = str(phone).strip()
            if not activation_text or not phone_text:
                raise ValueError("empty activation")
            order_meta = {
                "key_index": state.index,
                "key_fingerprint": state.fingerprint,
                "balance_usd": state.balance_usd,
                "price_usd": None if price_usd is None else float(price_usd),
                "leased_at": time.time(),
            }
        except Exception:
            try:
                if hasattr(provider, "cancel"):
                    provider.cancel()
            except Exception as cleanup_error:
                self.pool.report_error(state, cleanup_error, runtime=True)
            finally:
                self.pool.release(state)
            raise RuntimeError("sms_activation_invalid_response") from None

        self._provider = provider
        self._state = state
        self._released = False
        self.activation_id = activation_text
        self.phone = phone_text
        self.current_order_meta = order_meta
        return self.activation_id, self.phone

    def get_number(
        self,
        service: str = "dr",
        country: str = "151",
        provider_ids: str = "",
        max_price: str = "",
    ) -> tuple[str, str]:
        return self._activate(
            "get_number",
            service=service,
            country=country,
            provider_ids=provider_ids,
            max_price=max_price,
        )

    def get_number_from_candidate(
        self,
        service: str,
        country: str,
        provider_ids: str,
        max_price: str,
        candidate_price: float,
    ) -> tuple[str, str]:
        return self._activate(
            "get_number_from_candidate",
            price_usd=candidate_price,
            service=service,
            country=country,
            provider_ids=provider_ids,
            max_price=max_price,
            candidate_price=candidate_price,
        )

    def wait_code(self, timeout: int = 300, interval: int = 3) -> str | None:
        if self._provider is None:
            raise RuntimeError("No active activation")
        try:
            try:
                return self._provider.wait_code(timeout=timeout, interval=interval)
            except TypeError:
                return self._provider.wait_code(timeout=timeout)
        except Exception as exc:
            self.pool.report_error(self._state, exc, runtime=True)
            self._release()
            key = self._state.key if self._state is not None else ""
            raise RuntimeError(self.pool.safe_error(exc, [key])) from exc

    def set_ready(self) -> None:
        if self._provider is not None and hasattr(self._provider, "set_ready"):
            try:
                self._provider.set_ready()
            except Exception as exc:
                self.pool.report_error(self._state, exc, runtime=True)
                self._release()
                key = self._state.key if self._state is not None else ""
                raise RuntimeError(self.pool.safe_error(exc, [key])) from exc

    def _finish(self, method: str) -> None:
        if self._provider is not None and hasattr(self._provider, method):
            try:
                getattr(self._provider, method)()
            except Exception as exc:
                self.pool.report_error(self._state, exc, runtime=True)
                key = self._state.key if self._state is not None else ""
                raise RuntimeError(self.pool.safe_error(exc, [key])) from exc
            finally:
                self._release()
        else:
            self._release()

    def _release(self) -> None:
        if self._released:
            return
        self._released = True
        self.pool.release(self._state)

    def complete(self) -> None:
        self._finish("complete")

    def cancel(self) -> None:
        self._finish("cancel")


def _sms_timeout_error(value: Any) -> bool:
    text = str(value or "").lower()
    return any(
        marker in text
        for marker in (
            "timeout",
            "timed out",
            "no code",
            "no sms",
            "verification code",
            "未收到验证码",
        )
    )


class SmsProviderRegistry:
    """Own one key pool per SMS platform and expose one aggregate provider."""

    def __init__(
        self,
        provider_factory: Callable[..., Any],
        *,
        legacy_pool: SmsKeyPool | None = None,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.provider_factory = provider_factory
        self.legacy_pool = legacy_pool
        self.now_fn = now_fn
        self.lock = threading.RLock()
        self.pools: dict[str, SmsKeyPool] = {}
        self.specs: list[dict[str, Any]] = []
        self.candidates: list[dict[str, Any]] = []
        self._task_attempt_counts: dict[str, dict[str, int]] = {}
        self.inventory: dict[str, list[dict[str, Any]]] = {}
        self.cursor = 0
        self.logger: Callable[[str, str], None] | None = None
        self.alert_fn: Callable[[dict[str, Any]], None] | None = None
        self.exhausted_fn: Callable[[], None] | None = None

    def task_attempt_counts(self, task_id: Any) -> dict[str, int]:
        key = str(task_id or "").strip()
        if not key:
            return {}
        with self.lock:
            return self._task_attempt_counts.setdefault(key, {})

    def clear_task_attempt_counts(self, task_id: Any) -> None:
        key = str(task_id or "").strip()
        if not key:
            return
        with self.lock:
            self._task_attempt_counts.pop(key, None)

    def snapshot_task_attempt_counts(self, task_id: Any) -> dict[str, int]:
        key = str(task_id or "").strip()
        if not key:
            return {}
        with self.lock:
            return {
                str(platform): max(0, int(count))
                for platform, count in self._task_attempt_counts.get(key, {}).items()
            }

    def _pool_for(self, provider: str) -> SmsKeyPool:
        current = self.pools.get(provider)
        if current is not None:
            return current
        if provider == "smsbower" and self.legacy_pool is not None:
            current = self.legacy_pool
        else:
            current = SmsKeyPool(
                lambda key, proxy="", _provider=provider: self.provider_factory(
                    _provider,
                    key,
                    proxy=proxy,
                ),
                now_fn=self.now_fn,
            )
        self.pools[provider] = current
        return current

    def configure(
        self,
        config: Any,
        *,
        min_price: float = 0.01,
        max_price: float = 0.15,
        logger: Callable[[str, str], None] | None = None,
        alert_fn: Callable[[dict[str, Any]], None] | None = None,
        exhausted_fn: Callable[[], None] | None = None,
    ) -> None:
        value = dict(config or {}) if isinstance(config, dict) else {}
        specs = normalize_sms_provider_pools(
            value.get("sms_provider_pools"),
            legacy_provider=value.get("sms_provider") or "smsbower",
            legacy_keys=value.get("sms_api_keys"),
            legacy_key=value.get("sms_api_key"),
        )
        with self.lock:
            self.specs = specs
            self.logger = logger
            self.alert_fn = alert_fn
            self.exhausted_fn = exhausted_fn
            self.candidates = []
            self.inventory = {}
            for spec in specs:
                provider = str(spec["provider"])
                pool = self._pool_for(provider)
                pool.configure(
                    list(spec.get("api_keys") or []),
                    service=str(spec.get("service") or SMS_PROVIDER_DEFAULT_SERVICES.get(provider, "dr")),
                    min_price=min_price,
                    max_price=max_price,
                    logger=logger,
                    alert_fn=lambda payload, _provider=provider: self._platform_alert(
                        _provider,
                        payload,
                    ),
                    exhausted_fn=lambda _provider=provider: self._platform_exhausted(_provider),
                )

    def _platform_alert(self, provider: str, payload: Any) -> None:
        value = dict(payload or {})
        value["provider"] = provider
        if callable(self.alert_fn):
            try:
                self.alert_fn(value)
            except Exception:
                pass

    def _platform_exhausted(self, _provider: str) -> None:
        if self.is_exhausted() and callable(self.exhausted_fn):
            try:
                self.exhausted_fn()
            except Exception:
                pass

    def begin_run(self) -> None:
        with self.lock:
            pools = list(self.pools.values())
            self.candidates = []
            self.inventory = {}
            self._task_attempt_counts.clear()
        for pool in pools:
            pool.begin_run()

    def has_keys(self) -> bool:
        with self.lock:
            return any(
                bool(spec.get("enabled", True))
                and self.pools.get(str(spec.get("provider"))) is not None
                and self.pools[str(spec.get("provider"))].has_keys()
                for spec in self.specs
            )

    def public_statuses(self) -> list[dict[str, Any]]:
        with self.lock:
            specs = [dict(spec) for spec in self.specs]
            pools = dict(self.pools)
            inventory = {name: list(rows) for name, rows in self.inventory.items()}
        result: list[dict[str, Any]] = []
        for spec in specs:
            provider = str(spec.get("provider") or "")
            pool = pools.get(provider)
            if pool is None:
                continue
            inventory_rows = inventory.get(provider, [])
            inventory_count = sum(
                max(0, int(row.get("count") or 0)) for row in inventory_rows
            )
            prices = [
                float(row.get("price") or 0)
                for row in inventory_rows
                if float(row.get("price") or 0) > 0
            ]
            for row in pool.public_statuses():
                result.append(
                    {
                        **row,
                        "provider": provider,
                        "platform": provider,
                        "service": str(spec.get("service") or "dr"),
                        "enabled": bool(spec.get("enabled", True)),
                        "inventory_count": inventory_count,
                        "minimum_price": min(prices) if prices else None,
                    }
                )
        return result

    def safe_error(self, error: Any, extra_secrets: Any = None) -> str:
        with self.lock:
            pools = list(self.pools.values())
        text = str(error or "")
        for pool in pools:
            text = pool.safe_error(text, extra_secrets)
        return redact_sms_secrets(text, normalize_sms_keys(extra_secrets))

    def is_exhausted(self) -> bool:
        with self.lock:
            active = [
                self.pools.get(str(spec.get("provider")))
                for spec in self.specs
                if bool(spec.get("enabled", True))
            ]
        pools = [pool for pool in active if pool is not None and pool.has_keys()]
        return bool(pools) and all(pool.is_exhausted() for pool in pools)

    def all_balance_insufficient(self) -> bool:
        with self.lock:
            active = [
                self.pools.get(str(spec.get("provider")))
                for spec in self.specs
                if bool(spec.get("enabled", True))
            ]
        pools = [pool for pool in active if pool is not None and pool.has_keys()]
        return bool(pools) and all(pool.all_balance_insufficient() for pool in pools)

    def _active_specs(self) -> list[dict[str, Any]]:
        with self.lock:
            return [
                dict(spec)
                for spec in self.specs
                if bool(spec.get("enabled", True))
                and self.pools.get(str(spec.get("provider"))) is not None
                and self.pools[str(spec.get("provider"))].has_keys()
            ]

    @staticmethod
    def _row_match(
        row: Any,
        *,
        country: str,
        provider_ids: str,
        price: float,
    ) -> bool:
        row_country = str(row.get("country") or "")
        row_provider = str(row.get("provider_id") or row.get("operator") or "")
        if country and row_country and row_country != country:
            return False
        if provider_ids and row_provider and row_provider != provider_ids:
            return False
        row_price = _as_float(row.get("price"), -1)
        return row_price < 0 or abs(row_price - price) <= 0.000001

    def query_balances(self, *, proxy: str = "") -> list[dict[str, Any]]:
        with self.lock:
            specs = [
                dict(spec)
                for spec in self.specs
                if self.pools.get(str(spec.get("provider"))) is not None
                and self.pools[str(spec.get("provider"))].has_keys()
            ]
        if not specs:
            return []

        def check(spec: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            provider = str(spec.get("provider") or "")
            return spec, self.pools[provider].query_balances(proxy=proxy)

        workers = min(SMS_PREFLIGHT_MAX_WORKERS, len(specs))
        if workers == 1:
            results = [check(specs[0])]
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sms-platform-balance") as executor:
                results = list(executor.map(check, specs))

        rows: list[dict[str, Any]] = []
        for spec, statuses in results:
            provider = str(spec.get("provider") or "")
            for status in statuses:
                rows.append(
                    {
                        **status,
                        "provider": provider,
                        "platform": provider,
                        "service": str(spec.get("service") or "dr"),
                        "enabled": bool(spec.get("enabled", True)),
                    }
                )
        return rows

    def preflight(self, *, proxy: str = "") -> list[dict[str, Any]]:
        specs = self._active_specs()
        if not specs:
            return []

        def check(spec: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
            provider = str(spec.get("provider") or "")
            pool = self.pools[provider]
            statuses = pool.preflight(proxy=proxy)
            inventory = self._price_rows_for(spec, None, proxy=proxy)
            return provider, statuses, inventory

        workers = min(SMS_PREFLIGHT_MAX_WORKERS, len(specs))
        if workers == 1:
            results = [check(specs[0])]
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sms-platform-preflight") as executor:
                results = list(executor.map(check, specs))

        rows: list[dict[str, Any]] = []
        inventory_by_provider: dict[str, list[dict[str, Any]]] = {}
        for provider, statuses, inventory in results:
            inventory_by_provider[provider] = inventory
            total_inventory = sum(max(0, int(row.get("count") or 0)) for row in inventory)
            prices = [float(row.get("price") or 0) for row in inventory if float(row.get("price") or 0) > 0]
            for status in statuses:
                rows.append(
                    {
                        **status,
                        "provider": provider,
                        "platform": provider,
                        "inventory_count": total_inventory,
                        "minimum_price": min(prices) if prices else None,
                    }
                )
        with self.lock:
            self.inventory = inventory_by_provider
            self.candidates = [row for inventory in inventory_by_provider.values() for row in inventory]
        return rows

    def _price_rows_for(
        self,
        spec: dict[str, Any],
        countries: list[str] | None,
        *,
        proxy: str = "",
    ) -> list[dict[str, Any]]:
        provider_name = str(spec.get("provider") or "")
        pool = self.pools.get(provider_name)
        if pool is None:
            return []
        service = str(spec.get("service") or SMS_PROVIDER_DEFAULT_SERVICES.get(provider_name, "dr"))
        try:
            rows = pool.query(
                "get_price_candidates",
                proxy=proxy,
                service=service,
                countries=countries,
            )
        except Exception as exc:
            if callable(self.logger):
                try:
                    self.logger(
                        f"SMS 平台 {provider_name} 库存查询失败：{pool.safe_error(exc)}",
                        "warn",
                    )
                except Exception:
                    pass
            return []
        normalized: list[dict[str, Any]] = []
        for raw in rows or []:
            if not isinstance(raw, dict):
                continue
            row = dict(raw)
            row["platform"] = provider_name
            row["pool"] = provider_name
            row.setdefault("service", service)
            row["country"] = str(row.get("country") or "")
            row["provider_id"] = str(row.get("provider_id") or row.get("operator") or "")
            row["price"] = _as_float(row.get("price"), 0.0)
            row["count"] = max(0, int(_as_float(row.get("count"), 0)))
            if row["country"] and row["price"] >= 0:
                normalized.append(row)
        return normalized

    def get_price_candidates(
        self,
        service: str = "dr",
        countries: list[str] | None = None,
        *,
        proxy: str = "",
    ) -> list[dict[str, Any]]:
        del service
        specs = self._active_specs()
        rows: list[dict[str, Any]] = []
        for spec in specs:
            rows.extend(self._price_rows_for(spec, countries, proxy=proxy))
        with self.lock:
            self.candidates = list(rows)
        return rows

    def get_available_countries(self, service: str = "dr", *, proxy: str = "") -> list[str]:
        values: set[str] = set()
        for row in self.get_price_candidates(service=service, proxy=proxy):
            country = str(row.get("country") or "")
            if country:
                values.add(country)
        return sorted(values)

    def _candidate_specs(
        self,
        *,
        country: str,
        provider_ids: str,
        price: float,
        platform: str = "",
    ) -> list[dict[str, Any]]:
        specs = self._active_specs()
        with self.lock:
            candidates = list(self.candidates)
        matched: list[str] = []
        for row in candidates:
            row_platform = str(row.get("platform") or row.get("pool") or "")
            if platform and row_platform != platform:
                continue
            if self._row_match(row, country=country, provider_ids=provider_ids, price=price):
                if row_platform and row_platform not in matched:
                    matched.append(row_platform)
        active_names = [str(spec.get("provider") or "") for spec in specs]
        preferred = list(matched)
        if platform and platform in active_names and platform not in preferred:
            preferred.append(platform)
        names = preferred + [name for name in active_names if name not in preferred]
        # Inventory-capable platforms still supply the route, but the starting
        # platform rotates so a valid provider with an empty inventory response
        # is not permanently starved.
        if len(names) > 1:
            with self.lock:
                offset = self.cursor % len(names)
                self.cursor += 1
            names = names[offset:] + names[:offset]
        ordered = [spec for name in names for spec in specs if spec.get("provider") == name]
        ordered.extend(spec for spec in specs if spec not in ordered)
        return ordered

    def activate(
        self,
        method: str,
        *,
        proxy: str = "",
        price_usd: float | None = None,
        platform: str = "",
        attempt_counts: dict[str, int] | None = None,
        max_attempts_per_platform: int = 0,
        **kwargs: Any,
    ) -> tuple[Any, SmsKeyPool, SmsKeyHealth, Any, dict[str, Any]]:
        country = str(kwargs.get("country") or "")
        provider_ids = str(kwargs.get("provider_ids") or "")
        candidate_price = _as_float(price_usd, -1)
        specs = self._candidate_specs(
            country=country,
            provider_ids=provider_ids,
            price=candidate_price,
            platform=platform,
        )
        if not specs:
            raise RuntimeError("sms_provider_pool_unavailable: 所有启用 SMS 平台均不可用")
        errors: list[str] = []
        for spec in specs:
            provider_name = str(spec.get("provider") or "")
            if (
                attempt_counts is not None
                and max_attempts_per_platform > 0
                and int(attempt_counts.get(provider_name) or 0) >= max_attempts_per_platform
            ):
                continue
            pool = self.pools.get(provider_name)
            if pool is None:
                continue
            if attempt_counts is not None:
                attempt_counts[provider_name] = int(attempt_counts.get(provider_name) or 0) + 1
            service = str(spec.get("service") or SMS_PROVIDER_DEFAULT_SERVICES.get(provider_name, "dr"))
            call_kwargs = dict(kwargs)
            call_kwargs["service"] = service
            try:
                provider, state, activation = pool.activate(
                    method,
                    proxy=proxy,
                    price_usd=price_usd,
                    **call_kwargs,
                )
                meta = {
                    "platform": provider_name,
                    "provider": provider_name,
                    "service": service,
                    "key_index": state.index,
                    "key_fingerprint": state.fingerprint,
                    "balance_usd": state.balance_usd,
                    "country": country,
                    "provider_id": provider_ids,
                    "price_usd": None if price_usd is None else float(price_usd),
                }
                return provider, pool, state, activation, meta
            except Exception as exc:
                errors.append(self.safe_error(f"{provider_name}: {exc}"))
                continue
        detail = "; ".join(errors) or "所有启用 SMS 平台均已达到单平台尝试上限"
        raise RuntimeError(f"sms_provider_pool_unavailable: {detail}")


class PooledSmsProvider:
    """Provider-compatible facade for an order selected from any platform."""

    SMART_ANY_PROVIDER_FALLBACK = True
    SMART_COUNTRY_SCOPE_FILTER = True
    SMART_FIXED_COUNTRY_FALLBACK = False

    def __init__(self, registry: SmsProviderRegistry, *, proxy: str = "") -> None:
        self.registry = registry
        self.proxy = proxy
        self.api_key = ""
        self.activation_id: str | None = None
        self.phone: str | None = None
        self._provider: Any = None
        self._pool: SmsKeyPool | None = None
        self._state: SmsKeyHealth | None = None
        self._released = True
        self._resend_attempted = False
        self._reject_requested = False
        self._poll_lock = threading.Lock()
        self._poll_generation = 0
        self._cancel_attempted = False
        self.max_attempts_per_platform = 15
        self._platform_attempts: dict[str, int] = {}
        self._task_id = ""
        self.current_order_meta: dict[str, Any] = {}
        self.last_finish_receipt: dict[str, str] = {}

    def bind_task(self, task_id: Any) -> None:
        key = str(task_id or "").strip()
        if not key or key == self._task_id:
            return
        self._task_id = key
        self._platform_attempts = self.registry.task_attempt_counts(key)

    def balance(self) -> str:
        total = sum(
            float(row.get("balance_usd") or 0)
            for row in self.registry.public_statuses()
            if row.get("status") == "usable"
        )
        return f"ACCESS_BALANCE:{total:.4f}"

    def get_price_candidates(self, service: str = "dr", countries: list[str] | None = None) -> list[dict[str, Any]]:
        return self.registry.get_price_candidates(
            service=service,
            countries=countries,
            proxy=self.proxy,
        )

    def get_available_countries(self, service: str = "dr") -> list[str]:
        return self.registry.get_available_countries(service=service, proxy=self.proxy)

    def _activate(self, method: str, price_usd: float | None = None, **kwargs: Any) -> tuple[str, str]:
        if not self._released:
            raise RuntimeError("SMS provider already has an active activation")
        provider, pool, state, activation, meta = self.registry.activate(
            method,
            proxy=self.proxy,
            price_usd=price_usd,
            attempt_counts=self._platform_attempts,
            max_attempts_per_platform=self.max_attempts_per_platform,
            **kwargs,
        )
        try:
            activation_id, phone = activation
            activation_text = str(activation_id).strip()
            phone_text = str(phone).strip()
            if not activation_text or not phone_text:
                raise ValueError("empty activation")
        except Exception:
            try:
                if hasattr(provider, "cancel"):
                    provider.cancel()
            except Exception as cleanup_error:
                pool.report_error(state, cleanup_error, runtime=True)
            finally:
                pool.release(state)
            raise RuntimeError("sms_activation_invalid_response") from None
        self._provider = provider
        self._pool = pool
        self._state = state
        self._released = False
        self._resend_attempted = False
        self._reject_requested = False
        self._cancel_attempted = False
        self.last_finish_receipt = {}
        self.activation_id = activation_text
        self.phone = phone_text
        self.current_order_meta = {
            **meta,
            "leased_at": time.time(),
            "order_state": "leased",
        }
        return activation_text, phone_text

    def get_number(self, service: str = "dr", country: str = "151", provider_ids: str = "", max_price: str = "") -> tuple[str, str]:
        return self._activate(
            "get_number",
            service=service,
            country=country,
            provider_ids=provider_ids,
            max_price=max_price,
        )

    def get_number_from_candidate(
        self,
        service: str,
        country: str,
        provider_ids: str,
        max_price: str,
        candidate_price: float,
        platform: str = "",
    ) -> tuple[str, str]:
        return self._activate(
            "get_number_from_candidate",
            price_usd=candidate_price,
            service=service,
            country=country,
            provider_ids=provider_ids,
            max_price=max_price,
            candidate_price=candidate_price,
            platform=platform,
        )

    def _wait_once(self, timeout: int, interval: int) -> str | None:
        try:
            return self._provider.wait_code(timeout=timeout, interval=interval)
        except TypeError:
            return self._provider.wait_code(timeout=timeout)

    def _resend(self) -> None:
        platform = normalize_sms_provider_name(
            self.current_order_meta.get("platform")
            or self.current_order_meta.get("provider")
        )
        if platform == "5sim":
            return
        method = getattr(self._provider, "set_ready", None)
        if callable(method):
            method()

    def _ensure_activation(self, activation_id: str, generation: int) -> None:
        if (
            generation != self._poll_generation
            or str(self.activation_id or "") != activation_id
            or self._released
        ):
            raise RuntimeError(
                "sms_activation_replaced: 短信轮询结果所属订单已被替换"
            )

    def _wait_round(
        self,
        activation_id: str,
        generation: int,
        *,
        timeout: int,
        interval: int,
    ) -> str | None:
        deadline = time.monotonic() + max(1, int(timeout))

        def poll() -> str | None:
            self._ensure_activation(activation_id, generation)
            remaining = max(1, math.ceil(deadline - time.monotonic()))
            code = self._wait_once(remaining, interval)
            self._ensure_activation(activation_id, generation)
            return code

        try:
            return call_sms_with_retries(poll, deadline=deadline)
        except Exception as exc:
            if "sms_activation_replaced" in str(exc):
                raise
            if self._pool is not None:
                self._pool.report_error(self._state, exc, runtime=True)
            detail = self.registry.safe_error(exc)
            raise RuntimeError(
                f"sms_provider_poll_failed: {detail or type(exc).__name__}"
            ) from exc

    def wait_code(self, timeout: int = 300, interval: int = 3) -> str | None:
        if self._provider is None:
            raise RuntimeError("No active activation")
        if not self._poll_lock.acquire(blocking=False):
            raise RuntimeError(
                "sms_poll_already_active: 当前短信订单已有轮询线程"
            )
        self._poll_generation += 1
        generation = self._poll_generation
        activation_id = str(self.activation_id or "")
        round_timeout = min(SMS_FIRST_WAIT_SECONDS, max(1, int(timeout)))
        del interval
        poll_interval = SMS_POLL_INTERVAL_SECONDS
        self.current_order_meta["order_state"] = "waiting"
        try:
            code = self._wait_round(
                activation_id,
                generation,
                timeout=round_timeout,
                interval=poll_interval,
            )
            if code:
                self.current_order_meta["order_state"] = "code_received"
                return code
            self._resend_attempted = True
            platform = normalize_sms_provider_name(
                self.current_order_meta.get("platform")
                or self.current_order_meta.get("provider")
            )
            if platform != "5sim":
                try:
                    call_sms_with_retries(self._resend)
                except Exception as exc:
                    if self._pool is not None:
                        self._pool.report_error(self._state, exc, runtime=True)
                    detail = self.registry.safe_error(exc)
                    raise RuntimeError(
                        f"sms_provider_ready_failed: {detail or type(exc).__name__}"
                    ) from exc
            code = self._wait_round(
                activation_id,
                generation,
                timeout=min(SMS_SECOND_WAIT_SECONDS, max(1, int(timeout))),
                interval=poll_interval,
            )
            if code:
                self.current_order_meta["order_state"] = "code_received"
                return code
            raise RuntimeError(
                "sms_timeout: 两轮短信等待结束后仍未收到验证码"
            )
        finally:
            self._poll_lock.release()

    def set_ready(self) -> None:
        method = getattr(self._provider, "set_ready", None)
        if not callable(method):
            return
        try:
            call_sms_with_retries(method)
            self.current_order_meta["order_state"] = "ready"
        except Exception as exc:
            if self._pool is not None:
                self._pool.report_error(self._state, exc, runtime=True)
            detail = self.registry.safe_error(exc)
            raise RuntimeError(
                f"sms_provider_ready_failed: {detail or type(exc).__name__}"
            ) from exc

    def _release(self) -> None:
        if self._released:
            return
        self._released = True
        if self._pool is not None:
            self._pool.release(self._state)

    def _cancel_provider(self, platform: str) -> dict[str, str]:
        provider = self._provider
        if platform == "herosms" and callable(getattr(provider, "_api", None)):
            return confirm_herosms_cancellation(
                provider,
                self.activation_id,
                leased_at=self.current_order_meta.get("leased_at"),
                defer_early=True,
                on_wait=lambda seconds: self.registry._log(
                    f"HeroSMS 订单处于前置取消保护期，已安排约 {int(seconds)} 秒后后台取消并核对返款",
                    "warn",
                ),
            )
        callback = getattr(provider, "cancel", None)
        result = callback() if callable(callback) else None
        receipt = safe_cancel_receipt(result)
        return receipt or {
            "cancel_state": "confirmed",
            "refund_status": "provider_cancel_accepted",
        }

    def _reject_provider(self) -> dict[str, str]:
        provider = self._provider
        platform = normalize_sms_provider_name(
            self.current_order_meta.get("platform")
            or self.current_order_meta.get("provider")
        )
        if platform != "5sim":
            return self._cancel_provider(platform)

        reject_error: Exception | None = None
        for name in ("ban", "reject"):
            callback = getattr(provider, name, None)
            if not callable(callback):
                continue
            try:
                callback()
                return {
                    "cancel_state": "confirmed",
                    "refund_status": "provider_rejection_confirmed",
                }
            except Exception as exc:
                reject_error = exc
                break

        if reject_error is None:
            rest_get = getattr(provider, "_rest_get", None)
            activation_id = str(self.activation_id or "").strip()
            if callable(rest_get) and activation_id:
                try:
                    safe_id = urllib.parse.quote(activation_id, safe="")
                    rest_get(f"/user/ban/{safe_id}")
                    return {
                        "cancel_state": "confirmed",
                        "refund_status": "provider_rejection_confirmed",
                    }
                except Exception as exc:
                    reject_error = exc

        cancel = getattr(provider, "cancel", None)
        if callable(cancel):
            try:
                cancel()
                return {
                    "cancel_state": "unconfirmed",
                    "refund_status": "provider_cancel_unverified",
                }
            except Exception as cancel_error:
                if reject_error is None:
                    reject_error = cancel_error
        if reject_error is not None:
            raise reject_error
        return {
            "cancel_state": "unconfirmed",
            "refund_status": "provider_cancel_unverified",
        }

    def _finish(self, method: str) -> dict[str, str]:
        if method in {"cancel", "reject"} and self._cancel_attempted:
            return dict(self.last_finish_receipt)
        if method in {"cancel", "reject"}:
            self._cancel_attempted = True
        receipt: dict[str, str] = {}
        try:
            if method == "reject":
                receipt = self._reject_provider()
            elif method == "cancel":
                platform = normalize_sms_provider_name(
                    self.current_order_meta.get("platform")
                    or self.current_order_meta.get("provider")
                )
                receipt = self._cancel_provider(platform)
            else:
                callback = getattr(self._provider, method, None)
                if callable(callback):
                    result = callback()
                    receipt = safe_cancel_receipt(result)
            self.last_finish_receipt = safe_cancel_receipt(receipt)
            self.current_order_meta["order_state"] = (
                "cancelled" if method in {"cancel", "reject"} else "completed"
            )
            return dict(self.last_finish_receipt)
        except Exception as exc:
            if method in {"cancel", "reject"}:
                self.last_finish_receipt = {
                    "cancel_state": "error",
                    "refund_status": "provider_cancel_not_confirmed",
                }
                self.current_order_meta["order_state"] = "cancel_failed"
                platform = normalize_sms_provider_name(
                    self.current_order_meta.get("platform")
                    or self.current_order_meta.get("provider")
                )
                if platform == "herosms":
                    self._platform_attempts[platform] = self.max_attempts_per_platform
            if self._pool is not None:
                self._pool.report_error(self._state, exc, runtime=True)
                raise RuntimeError(self.registry.safe_error(exc)) from exc
            raise
        finally:
            self._release()

    def complete(self) -> dict[str, str]:
        return self._finish("complete")

    def mark_rejected(self) -> None:
        self._reject_requested = True

    def reject(self) -> dict[str, str]:
        self._reject_requested = False
        return self._finish("reject")

    def cancel(self) -> dict[str, str]:
        if self._reject_requested:
            return self.reject()
        return self._finish("cancel")


class PhoneSubmissionGate:
    def __init__(
        self,
        concurrency: int = 2,
        interval_seconds: float = 0.75,
        *,
        now_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.limit = max(1, int(concurrency))
        self.semaphore = threading.BoundedSemaphore(self.limit)
        self.interval_seconds = max(0.0, float(interval_seconds))
        self.now_fn = now_fn
        self.sleep_fn = sleep_fn
        self.spacing_lock = threading.Lock()
        self.status_lock = threading.Lock()
        self.active = 0
        self.waiting = 0
        self.last_started_at = 0.0
        self.not_before = 0.0
        self.transient_streak = 0

    def begin_run(self) -> None:
        with self.spacing_lock:
            self.last_started_at = 0.0
            self.not_before = 0.0
            self.transient_streak = 0

    def report_transient(self) -> float:
        with self.spacing_lock:
            self.transient_streak += 1
            delay = min(8.0, 2.0 ** self.transient_streak)
            self.not_before = max(self.not_before, self.now_fn() + delay)
            return delay

    def report_success(self) -> None:
        with self.spacing_lock:
            self.transient_streak = 0

    def status(self) -> dict[str, int]:
        with self.status_lock:
            return {
                "active": self.active,
                "limit": self.limit,
                "waiting": self.waiting,
            }

    @staticmethod
    def _stopped(stop_event: Any) -> bool:
        return ProxyProtocolGate._stopped(stop_event)

    def _acquire(self, stop_event: Any) -> None:
        with self.status_lock:
            self.waiting += 1
        try:
            while True:
                if self._stopped(stop_event):
                    raise RuntimeError("task_stopped")
                if self.semaphore.acquire(timeout=0.25):
                    with self.status_lock:
                        self.active += 1
                    return
        finally:
            with self.status_lock:
                self.waiting = max(0, self.waiting - 1)

    def _release(self) -> None:
        with self.status_lock:
            self.active = max(0, self.active - 1)
        self.semaphore.release()

    def _wait(self, seconds: float, stop_event: Any) -> None:
        remaining = max(0.0, float(seconds))
        if stop_event is None:
            self.sleep_fn(remaining)
            return
        while remaining > 0:
            if self._stopped(stop_event):
                raise RuntimeError("task_stopped")
            chunk = min(0.25, remaining)
            self.sleep_fn(chunk)
            remaining -= chunk

    def call(
        self,
        function: Callable[..., Any],
        *args: Any,
        stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        wait_started = float(self.now_fn())
        acquired = False
        wait_reported = False
        try:
            self._acquire(stop_event)
            acquired = True
            while True:
                with self.spacing_lock:
                    now = self.now_fn()
                    wait_for = max(
                        self.interval_seconds - (now - self.last_started_at),
                        self.not_before - now,
                    )
                    if wait_for <= 0:
                        self.last_started_at = now
                        break
                if wait_for > 0:
                    self._wait(wait_for, stop_event)
            _notify_observer(
                on_wait,
                max(0.0, float(self.now_fn()) - wait_started),
            )
            wait_reported = True
            return function(*args, **kwargs)
        finally:
            if not wait_reported:
                _notify_observer(
                    on_wait,
                    max(0.0, float(self.now_fn()) - wait_started),
                )
            if acquired:
                self._release()

    def call_with_retries(
        self,
        function: Callable[..., Any],
        *args: Any,
        is_transient: Callable[[Any], bool],
        max_attempts: int = 4,
        on_retry: Callable[[float, int], None] | None = None,
        stop_event: Any = None,
        on_wait: Callable[[float], Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        attempts = max(1, int(max_attempts))
        last_error: Any = None
        for attempt in range(1, attempts + 1):
            try:
                result = self.call(
                    function,
                    *args,
                    stop_event=stop_event,
                    on_wait=on_wait,
                    **kwargs,
                )
            except Exception as exc:
                if not is_transient(exc):
                    self.report_success()
                    raise
                last_error = exc
            else:
                if not is_transient(result):
                    self.report_success()
                    return result
                last_error = result

            delay = self.report_transient()
            if attempt < attempts and callable(on_retry):
                try:
                    on_retry(delay, attempt)
                except Exception:
                    pass

        if isinstance(last_error, Exception):
            raise last_error
        return last_error


def is_transient_openai_error(value: Any) -> bool:
    if isinstance(value, dict):
        error = value.get("error") or value.get("message") or ""
        if isinstance(error, dict):
            error = f"{error.get('code') or ''} {error.get('message') or ''}"
        status = int(_as_float(value.get("_status") or value.get("status"), 0))
        text = str(error).lower()
        if status in {500, 502, 503, 504}:
            return True
    else:
        text = str(value or "").lower()
    return any(
        marker in text
        for marker in (
            "the server had an error processing your request",
            "internal server error",
            "temporarily unavailable",
            "service unavailable",
            "upstream connect error",
        )
    )


class SmsRoutePolicy:
    """Keeps unavailable and non-delivering routes away from concurrent workers."""

    def __init__(
        self,
        *,
        now_fn: Callable[[], float] = time.time,
        streak_window_seconds: float = 1800.0,
    ) -> None:
        self.lock = threading.Lock()
        self.now_fn = now_fn
        self.streak_window_seconds = max(0.0, float(streak_window_seconds))
        # Kept for callers that introspect the pre-override policy.  Actual
        # streak state now lives in the persisted route row with timestamps.
        self.no_code_streaks: dict[tuple[str, ...], int] = {}

    @staticmethod
    def key(candidate: Any) -> tuple[str, ...]:
        return _candidate_route(candidate)

    @staticmethod
    def route_limit(stat: Any) -> int:
        row = stat if isinstance(stat, dict) else {}
        proven = any(
            int(_as_float(row.get(name), 0)) > 0
            for name in ("otp_received", "success")
        )
        return 2 if proven else 1

    def reset(self) -> None:
        with self.lock:
            self.no_code_streaks.clear()

    def update_stat_for_outcome(
        self,
        stat: Any,
        *,
        ok: bool,
        kind: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Persist bounded consecutive-failure state alongside recovered route stats."""
        row = dict(stat or {}) if isinstance(stat, dict) else {}
        current = self.now_fn() if now is None else float(now)
        if ok:
            for streak_name, timestamp_name in (
                ("no_numbers_streak", "last_no_numbers_at"),
                ("no_code_streak", "last_no_code_at"),
                ("generic_failure_streak", "last_generic_failure_at"),
            ):
                failure_at = _as_float(row.get(timestamp_name), 0.0)
                if timestamp_name not in row or failure_at <= current:
                    row.pop(streak_name, None)
                    row.pop(timestamp_name, None)
            return row

        latest_success_at = max(
            _as_float(row.get("last_success_at"), 0.0),
            _as_float(row.get("last_delivery_at"), 0.0),
        )
        if latest_success_at > current:
            return row

        def record_failure(streak_name: str, timestamp_name: str) -> dict[str, Any]:
            has_previous = timestamp_name in row
            previous_at = _as_float(row.get(timestamp_name), 0.0)
            delta = current - previous_at
            if has_previous and delta < -self.streak_window_seconds:
                return row
            within_window = bool(
                has_previous
                and self.streak_window_seconds > 0
                and abs(delta) <= self.streak_window_seconds
            )
            previous = max(0, int(_as_float(row.get(streak_name), 0)))
            row[streak_name] = previous + 1 if within_window else 1
            row[timestamp_name] = max(previous_at, current) if has_previous else current
            return row

        if kind == "no_numbers":
            return record_failure(
                "no_numbers_streak",
                "last_no_numbers_at",
            )
        if kind in {"timeout", "no_code"}:
            return record_failure(
                "no_code_streak",
                "last_no_code_at",
            )
        return record_failure(
            "generic_failure_streak",
            "last_generic_failure_at",
        )

    def record_delivery(self, stat: Any, *, now: float | None = None) -> dict[str, Any]:
        """Record one real SMS delivery and make that route immediately reusable."""
        current = self.now_fn() if now is None else float(now)
        row = self.update_stat_for_outcome(stat, ok=True, kind="success", now=current)
        row["otp_received"] = max(0, int(_as_float(row.get("otp_received"), 0))) + 1
        row["last_delivery_at"] = max(
            _as_float(row.get("last_delivery_at"), 0.0),
            current,
        )
        row["last_kind"] = "otp_received"
        row.pop("cooldown_until", None)
        return row

    def cooldown_for(
        self,
        candidate: Any,
        *,
        ok: bool,
        kind: str,
        error: Any = "",
        stat: Any = None,
    ) -> int:
        route = self.key(candidate)
        text = str(error or "").lower()
        if not all(route):
            return 0
        with self.lock:
            if ok:
                return 0
            if kind == "transient_server":
                return 0
            if kind == "no_numbers":
                row = stat if isinstance(stat, dict) else {}
                streak = max(1, int(_as_float(row.get("no_numbers_streak"), 1)))
                return 180 if streak >= 3 else 60
            if kind in {"timeout", "no_code"}:
                return 180
            if kind in {"invalid_auth_step", "auth_session", "auth_context"}:
                return 600
            if kind in {"unsupported", "unsupported_route"} or any(
                marker in text for marker in ("unsupported", "not supported")
            ):
                return 900
            if any(marker in text for marker in ("similar", "suspicious", "try another number", "too many accounts")):
                return 180
            if kind == "phone_rejected" or any(
                marker in text for marker in ("already been used", "number is already used", "used too many times")
            ):
                return 180
            row = stat if isinstance(stat, dict) else {}
            if int(_as_float(row.get("generic_failure_streak"), 0)) >= 3:
                return 180
            return 0


class RuntimeAlertBuffer:
    def __init__(self, limit: int = 100) -> None:
        self.limit = max(1, int(limit))
        self.lock = threading.Lock()
        self.items: list[dict[str, Any]] = []
        self.seen: set[str] = set()
        self.sequence = 0

    def begin_run(self) -> None:
        with self.lock:
            self.items.clear()
            self.seen.clear()

    def add(
        self,
        kind: str,
        message: str,
        *,
        level: str = "warning",
        dedupe_key: str = "",
        persistent: bool = True,
        **extra: Any,
    ) -> dict[str, Any] | None:
        key = dedupe_key or f"{kind}:{message}"
        with self.lock:
            if key in self.seen:
                return None
            self.seen.add(key)
            self.sequence += 1
            item = {
                "id": f"sms-alert-{self.sequence}",
                "kind": kind,
                "level": level,
                "message": str(message),
                "persistent": bool(persistent),
                "created_at": int(time.time()),
                **extra,
            }
            self.items.append(item)
            self.items = self.items[-self.limit :]
            return dict(item)

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(item) for item in self.items]


class SmsCleanupQueue:
    """Persist failed activation cancellations without exposing them publicly."""

    def __init__(
        self,
        path: Path,
        *,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.now_fn = now_fn
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.process_lock = threading.Lock()
        self.worker: threading.Thread | None = None
        self.worker_stop = threading.Event()
        self.worker_handler: Callable[[dict[str, Any]], bool] | None = None

    @staticmethod
    def _entry_id(platform: Any, activation_id: Any) -> str:
        value = f"{normalize_sms_provider_name(platform)}:{activation_id}"
        return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:20]

    def _read_payload_locked(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return [], []
        if isinstance(value, dict):
            rows = value.get("pending")
            if not isinstance(rows, list):
                rows = value.get("items")
            confirmed = value.get("confirmed")
        else:
            rows = value
            confirmed = []
        return (
            [dict(row) for row in rows or [] if isinstance(row, dict)],
            [dict(row) for row in confirmed or [] if isinstance(row, dict)],
        )

    def _read_locked(self) -> list[dict[str, Any]]:
        rows, _confirmed = self._read_payload_locked()
        return rows

    def _write_locked(
        self,
        rows: list[dict[str, Any]],
        confirmed: list[dict[str, Any]] | None = None,
    ) -> None:
        if confirmed is None:
            _pending, confirmed = self._read_payload_locked()
        confirmed = list(confirmed or [])[-500:]
        if not rows and not confirmed and not self.path.exists():
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "version": 3,
                    "items": rows,
                    "pending": rows,
                    "confirmed": confirmed,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def enqueue(
        self,
        *,
        platform: Any,
        key_fingerprint: Any,
        activation_id: Any,
        delay_seconds: float = 15.0,
        error_code: Any = "provider_cancel_failed",
        leased_at: Any = None,
        task_id: Any = "",
    ) -> str:
        platform_name = normalize_sms_provider_name(platform)
        activation = str(activation_id or "").strip()
        fingerprint = str(key_fingerprint or "").strip()[:20]
        if not platform_name or not activation or not fingerprint:
            return ""
        entry_id = self._entry_id(platform_name, activation)
        now = float(self.now_fn())
        with self.lock:
            rows, confirmed = self._read_payload_locked()
            if any(row.get("id") == entry_id for row in confirmed):
                return entry_id
            existing = next((row for row in rows if row.get("id") == entry_id), None)
            if existing is None:
                rows.append(
                    {
                        "id": entry_id,
                        "platform": platform_name,
                        "key_fingerprint": fingerprint,
                        "activation_id": activation,
                        "due_at": now + max(0.0, float(delay_seconds)),
                        "leased_at": float(leased_at or now),
                        "task_id": str(task_id or "").strip()[:80],
                        "attempts": 0,
                        "error_code": _safe_provider_token(error_code).lower(),
                    }
                )
            else:
                existing["due_at"] = min(
                    float(existing.get("due_at") or now),
                    now + max(0.0, float(delay_seconds)),
                )
                if not existing.get("task_id") and task_id:
                    existing["task_id"] = str(task_id).strip()[:80]
                if not existing.get("leased_at") and leased_at:
                    existing["leased_at"] = float(leased_at)
            self._write_locked(rows, confirmed)
            self.condition.notify_all()
        return entry_id

    def process(
        self,
        handler: Callable[[dict[str, Any]], bool],
        *,
        limit: int = 20,
    ) -> dict[str, int]:
        with self.process_lock:
            current = float(self.now_fn())
            with self.lock:
                rows = self._read_locked()
                due = [row for row in rows if float(row.get("due_at") or 0) <= current][
                    : max(1, int(limit))
                ]
            completed: set[str] = set()
            updates: dict[str, dict[str, Any]] = {}
            for row in due:
                entry_id = str(row.get("id") or "")
                try:
                    confirmed = bool(handler(dict(row)))
                except Exception as exc:
                    confirmed = False
                    error_code = type(exc).__name__.lower()
                    raw_retry_after = float(
                        getattr(exc, "retry_after_seconds", 0) or 0
                    )
                    retry_after = max(1.0, raw_retry_after) if raw_retry_after else 0.0
                else:
                    error_code = "provider_cancel_unconfirmed"
                    retry_after = 0.0
                if confirmed:
                    completed.add(entry_id)
                    continue
                attempt = max(0, int(row.get("attempts") or 0)) + 1
                retry_delay = retry_after or min(1800, 30 * (2 ** min(attempt, 5)))
                updates[entry_id] = {
                    "attempts": attempt,
                    "due_at": current + retry_delay,
                    "error_code": _safe_provider_token(error_code).lower(),
                }
            with self.lock:
                rows, confirmed_rows = self._read_payload_locked()
                confirmed_by_id = {
                    str(row.get("id") or ""): dict(row)
                    for row in confirmed_rows
                    if str(row.get("id") or "")
                }
                kept: list[dict[str, Any]] = []
                for row in rows:
                    entry_id = str(row.get("id") or "")
                    if entry_id in completed:
                        confirmed_by_id[entry_id] = {
                            "id": entry_id,
                            "platform": normalize_sms_provider_name(row.get("platform")),
                            "key_fingerprint": str(row.get("key_fingerprint") or "")[:20],
                            "task_id": str(row.get("task_id") or "")[:80],
                            "attempts": max(0, int(row.get("attempts") or 0)) + 1,
                            "confirmed_at": int(current),
                            "cancel_state": "confirmed",
                            "refund_status": "provider_refund_accepted",
                        }
                        continue
                    if entry_id in updates:
                        row.update(updates[entry_id])
                    kept.append(row)
                confirmed_rows = list(confirmed_by_id.values())[-500:]
                self._write_locked(kept, confirmed_rows)
                self.condition.notify_all()
        return {
            "processed": len(due),
            "completed": len(completed),
            "remaining": len(kept),
            "confirmed": len(confirmed_rows),
        }

    def start_worker(self, handler: Callable[[dict[str, Any]], bool]) -> None:
        with self.condition:
            self.worker_handler = handler
            if self.worker is not None and self.worker.is_alive():
                self.condition.notify_all()
                return
            self.worker_stop.clear()
            self.worker = threading.Thread(
                target=self._worker_loop,
                name="sms-cancel-cleanup",
                daemon=True,
            )
            self.worker.start()

    def _worker_loop(self) -> None:
        while not self.worker_stop.is_set():
            handler = self.worker_handler
            if callable(handler):
                try:
                    self.process(handler)
                except Exception:
                    pass
            with self.condition:
                if self.worker_stop.is_set():
                    return
                rows = self._read_locked()
                now = float(self.now_fn())
                due_times = [float(row.get("due_at") or now) for row in rows]
                wait_seconds = max(0.1, min(60.0, min(due_times) - now)) if due_times else 60.0
                self.condition.wait(timeout=wait_seconds)

    def stop_worker(self) -> None:
        self.worker_stop.set()
        with self.condition:
            self.condition.notify_all()


class ExchangeRateCache:
    def __init__(
        self,
        path: Path,
        *,
        fetcher: Callable[[], bytes] | None = None,
        now_fn: Callable[[], float] = time.time,
        ttl_seconds: int = 86400,
        fallback_rate: float = 7.20,
    ) -> None:
        self.path = Path(path)
        self.fetcher = fetcher or self._fetch_ecb
        self.now_fn = now_fn
        self.ttl_seconds = ttl_seconds
        self.fallback_rate = fallback_rate
        self.lock = threading.Lock()

    @staticmethod
    def _fetch_ecb() -> bytes:
        with urllib.request.urlopen(ECB_DAILY_URL, timeout=5) as response:
            return response.read(262144)

    @staticmethod
    def parse_ecb(payload: bytes) -> tuple[float, str]:
        root = ET.fromstring(payload)
        usd = None
        cny = None
        rate_date = ""
        for element in root.iter():
            if element.attrib.get("time"):
                rate_date = element.attrib["time"]
            currency = element.attrib.get("currency")
            if currency == "USD":
                usd = _as_float(element.attrib.get("rate"), 0)
            elif currency == "CNY":
                cny = _as_float(element.attrib.get("rate"), 0)
        if not usd or not cny:
            raise ValueError("ECB 汇率响应缺少 USD 或 CNY")
        return cny / usd, rate_date

    def _read(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def get_rate(self) -> dict[str, Any]:
        with self.lock:
            now = self.now_fn()
            cached = self._read()
            fetched_at = _as_float(cached.get("fetched_at"), 0)
            cached_rate = _as_float(cached.get("rate"), 0)
            if cached_rate > 0 and now - fetched_at < self.ttl_seconds:
                return {**cached, "source": "cache"}
            try:
                rate, rate_date = self.parse_ecb(self.fetcher())
                value = {
                    "rate": round(rate, 6),
                    "date": rate_date,
                    "fetched_at": int(now),
                    "source": "ecb",
                }
                self._write(value)
                return value
            except Exception:
                if cached_rate > 0:
                    return {**cached, "source": "stale_cache"}
                return {
                    "rate": self.fallback_rate,
                    "date": time.strftime("%Y-%m-%d", time.localtime(now)),
                    "fetched_at": int(now),
                    "source": "fallback",
                }


class SmsCostLedger:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.orders: dict[str, dict[str, dict[str, Any]]] = {}

    def clear(self) -> None:
        with self.lock:
            self.orders.clear()

    @staticmethod
    def _activation_key(activation_id: Any) -> str:
        return hashlib.sha256(str(activation_id or "").encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _candidate_value(candidate: Any, name: str, default: Any = None) -> Any:
        if isinstance(candidate, dict):
            return candidate.get(name, default)
        return getattr(candidate, name, default)

    def record_lease(self, task_id: str, lease: Any) -> None:
        meta = lease.meta if isinstance(getattr(lease, "meta", None), dict) else {}
        candidate = meta.get("candidate")
        price = meta.get("price_usd")
        if price is None:
            price = self._candidate_value(candidate, "price")
        activation_key = self._activation_key(getattr(lease, "activation_id", ""))
        order = {
            "activation": activation_key,
            "platform": meta.get("platform") or meta.get("provider") or self._candidate_value(candidate, "pool", ""),
            "key_index": meta.get("key_index"),
            "key_fingerprint": meta.get("key_fingerprint") or "",
            "country": self._candidate_value(candidate, "country", ""),
            "provider_id": self._candidate_value(candidate, "provider_id", ""),
            "price_usd": None if price is None else round(_as_float(price), 4),
            "status": "leased",
            "code_received": False,
            "leased_at": int(time.time()),
        }
        with self.lock:
            self.orders.setdefault(task_id, {})[activation_key] = order

    def mark_code_received(self, task_id: str, activation_id: Any) -> None:
        activation_key = self._activation_key(activation_id)
        with self.lock:
            order = self.orders.get(task_id, {}).get(activation_key)
            if order is not None:
                order["code_received"] = True
                order["status"] = "code_received"
                order["code_received_at"] = int(time.time())

    def mark_state(self, task_id: str, activation_id: Any, state: str) -> None:
        allowed = {
            "leased",
            "submitted",
            "ready",
            "waiting",
            "code_received",
            "completed",
            "cancel_pending",
            "cancelled",
            "cancel_failed",
        }
        value = str(state or "").strip()
        if value not in allowed:
            return
        activation_key = self._activation_key(activation_id)
        with self.lock:
            order = self.orders.get(task_id, {}).get(activation_key)
            if order is not None:
                order["status"] = value
                order[f"{value}_at"] = int(time.time())

    def mark_finished(
        self,
        task_id: str,
        activation_id: Any,
        status: str,
        reason: str = "",
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        activation_key = self._activation_key(activation_id)
        with self.lock:
            order = self.orders.get(task_id, {}).get(activation_key)
            if order is not None:
                order["status"] = status
                if reason:
                    order["reason"] = reason
                safe_details = safe_cancel_receipt(details)
                if safe_details:
                    order["cancel_receipt"] = safe_details
                order["finished_at"] = int(time.time())

    def summary(self, task_id: str, exchange: ExchangeRateCache, *, pop: bool = True) -> dict[str, Any]:
        with self.lock:
            task_orders = self.orders.pop(task_id, {}) if pop else dict(self.orders.get(task_id, {}))
            outcomes = [dict(order) for order in task_orders.values()]
        paid = [order for order in outcomes if order.get("code_received") and order.get("price_usd") is not None]
        if not paid:
            return {
                "sms_cost_usd": None,
                "sms_cost_cny": None,
                "sms_exchange_rate": None,
                "sms_exchange_date": "",
                "sms_order_outcomes": outcomes,
            }
        usd = round(sum(float(order["price_usd"]) for order in paid), 4)
        rate_info = exchange.get_rate()
        rate = float(rate_info["rate"])
        return {
            "sms_cost_usd": usd,
            "sms_cost_cny": round(usd * rate, 2),
            "sms_exchange_rate": round(rate, 6),
            "sms_exchange_date": str(rate_info.get("date") or ""),
            "sms_exchange_source": str(rate_info.get("source") or ""),
            "sms_order_outcomes": outcomes,
        }
