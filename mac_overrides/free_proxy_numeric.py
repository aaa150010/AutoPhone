"""Bounded numeric normalization for persisted Free proxy state."""

from __future__ import annotations

import math
from typing import Any


def safe_int(
    value: Any,
    *,
    default: int | None = 0,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    try:
        if isinstance(value, float) and not math.isfinite(value):
            return default
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if minimum is not None and parsed < minimum:
        return default
    if maximum is not None and parsed > maximum:
        return default
    return parsed


def safe_float(
    value: Any,
    *,
    default: float | None = None,
    minimum: float | None = None,
) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(parsed) or (minimum is not None and parsed < minimum):
        return default
    return parsed


__all__ = ["safe_int", "safe_float"]
