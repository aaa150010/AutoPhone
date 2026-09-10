"""Shared integer coercion for config and request-input parsing.

Seven modules used to carry private ``_safe_int``/``_coerce_int``/
``_int_value`` variants that differed only in whether they clamped. One
implementation keeps the common contract: parse with ``int``, fall back to
``int(default)`` on ``TypeError``/``ValueError``, then optionally clamp.
"""

from __future__ import annotations

from typing import Any


def coerce_int(
    value: Any,
    default: int = 0,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Parse ``value`` as int, falling back to ``default`` and clamping.

    ``minimum`` is applied before ``maximum``; with contradictory bounds the
    maximum wins, matching the historical private variants.
    """
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    if minimum is not None:
        parsed = max(int(minimum), parsed)
    if maximum is not None:
        parsed = min(int(maximum), parsed)
    return parsed


__all__ = ["coerce_int"]
