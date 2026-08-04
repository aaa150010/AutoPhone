"""Explicit-proxy policy shared by the recovered runtime overrides."""

from __future__ import annotations

import os
from typing import Any, MutableMapping


PROXY_ENV_NAMES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def clear_inherited_proxy_environment(
    environ: MutableMapping[str, str] | None = None,
) -> dict[str, str]:
    """Remove implicit proxy inheritance and return only the removed names."""
    target = os.environ if environ is None else environ
    removed: dict[str, str] = {}
    for name in PROXY_ENV_NAMES:
        value = target.pop(name, None)
        if value is not None:
            removed[name] = value
    return removed


def resolve_secret_input(value: Any, fallback: Any = "", *, present: bool = True, mask: str = "********") -> str:
    """Resolve a masked setting while allowing an explicit empty value to clear it."""
    if not present:
        return str(fallback or "")
    text = str(value or "")
    if text == mask:
        return str(fallback or "")
    return text
