"""Shared atomic JSON file replacement with durable semantics.

Nine modules used to carry private ``_atomic_write``/``_write_json`` variants
that differed only in fsync usage, chmod ordering and key sorting.  One
implementation keeps the strongest common contract: write to a unique temp
file in the destination directory, fsync, chmod 0600, then ``os.replace``.
Callers that intentionally swallow ``OSError`` keep doing so at their call
site so the failure semantics stay local and visible.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any


def atomic_write_json(
    path: str | Path,
    value: Any,
    *,
    sort_keys: bool = False,
) -> None:
    """Replace ``path`` atomically with the JSON encoding of ``value``."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=sort_keys)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write_text(path: str | Path, text: str) -> None:
    """Replace ``path`` atomically with raw text (same durability contract)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


__all__ = ["atomic_write_json", "atomic_write_text"]
