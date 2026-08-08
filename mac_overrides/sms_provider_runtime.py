"""Batch-scoped health state for aggregate SMS providers."""

from __future__ import annotations

from threading import RLock
from typing import Any


SECRET_MASK = "********"
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


def normalize_sms_keys(value: Any = None, legacy: Any = "") -> list[str]:
    """Normalize the canonical key list without interpreting punctuation."""
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


def normalize_sms_provider_pools(
    value: Any = None,
    *,
    legacy_provider: Any = "smsbower",
    legacy_keys: Any = None,
    legacy_key: Any = "",
) -> list[dict[str, Any]]:
    """Normalize platform pools while accepting pre-pool SMS settings."""
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
            existing["enabled"] = bool(existing.get("enabled")) or bool(
                raw.get("enabled", True)
            )
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
    return [
        {
            "provider": provider,
            "enabled": True,
            "api_keys": normalize_sms_keys(legacy_keys, legacy_key),
            "service": SMS_PROVIDER_DEFAULT_SERVICES.get(provider, "dr"),
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


class SmsProviderBatchHealth:
    """Skip platforms whose keys are all terminal for the current batch."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._exhausted: set[str] = set()

    def reset(self) -> None:
        with self._lock:
            self._exhausted.clear()

    def mark_exhausted(self, provider: Any) -> bool:
        name = str(provider or "").strip().lower()
        if not name:
            return False
        with self._lock:
            added = name not in self._exhausted
            self._exhausted.add(name)
            return added

    def mark_if_exhausted(self, provider: Any, pool: Any) -> bool:
        try:
            exhausted = bool(pool is not None and pool.has_keys() and pool.is_exhausted())
        except Exception:
            exhausted = False
        return self.mark_exhausted(provider) if exhausted else False

    def is_exhausted(self, provider: Any) -> bool:
        name = str(provider or "").strip().lower()
        with self._lock:
            return name in self._exhausted

    def snapshot(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._exhausted)
