"""Single shared implementation for normalizing OpenAI auth page type aliases."""

from __future__ import annotations

import re
from typing import Any

__all__ = ["normalize_page_type"]


def normalize_page_type(value: Any) -> str:
    """Normalize provider page aliases without retaining arbitrary response text."""

    text = str(value or "").strip().lower().replace("-", "_")
    return re.sub(r"[^a-z0-9_]+", "_", text)[:80].strip("_")
