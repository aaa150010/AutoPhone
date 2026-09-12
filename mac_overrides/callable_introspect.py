"""Shared callable signature introspection helpers."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

__all__ = ["accepts_keyword"]


def accepts_keyword(callback: Callable[..., Any], name: str) -> bool:
    """Whether ``callback`` can receive ``name`` as a keyword argument."""
    try:
        parameters = inspect.signature(callback).parameters
    except (TypeError, ValueError):
        return False
    parameter = parameters.get(name)
    return bool(
        parameter
        and parameter.kind
        in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
    ) or any(item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values())
