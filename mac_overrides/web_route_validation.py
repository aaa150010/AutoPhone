"""Pure request validation helpers shared by dashboard routes."""

from __future__ import annotations

from collections.abc import Mapping
import ipaddress
from typing import Any
import urllib.parse


def normalize_upload_targets(value: Any) -> dict[str, bool] | None:
    if value is None:
        return {"pixel": False, "nv": False}
    if not isinstance(value, Mapping):
        return None
    return {
        "pixel": value.get("pixel") is True,
        "nv": value.get("nv") is True,
    }


def is_secure_nv_url(value: Any) -> bool:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    normalized_host = hostname.lower().rstrip(".")
    is_loopback = normalized_host == "localhost"
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(normalized_host).is_loopback
        except ValueError:
            is_loopback = False
    return parsed.scheme.lower() == "https" or is_loopback


__all__ = ["is_secure_nv_url", "normalize_upload_targets"]
