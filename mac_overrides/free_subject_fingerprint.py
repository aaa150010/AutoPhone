"""Shared diagnostic-HMAC subject fingerprint for Free result records."""

from __future__ import annotations

import re
from typing import Any

try:
    from .free_register_common import fingerprint
except ImportError:  # pragma: no cover - top-level recovery import
    from free_register_common import fingerprint  # type: ignore[no-redef]
try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]


def subject_fingerprint(log_store: Any, email: Any) -> str:
    """Resolve the diagnostic HMAC for public correlation, else plain hash.

    ``log_store`` may be the historical FreeLogStore facade or a direct
    DiagnosticEventWriter; a malformed stored fingerprint falls back to
    hashing the value. Only the failure point label and the exception
    class name reach stderr.
    """
    value = str(email or "").strip()
    if not value:
        return ""
    store = getattr(log_store, "diagnostic_store", None)
    if store is None:
        # Accept direct DiagnosticEventWriter injection as well as the
        # historical FreeLogStore facade.
        store = getattr(log_store, "store", None)
    fingerprint_fn = getattr(store, "fingerprint", None)
    if callable(fingerprint_fn):
        try:
            candidate = str(fingerprint_fn(value) or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{32}", candidate):
                return candidate
        except Exception as exc:
            # A malformed stored fingerprint falls back to hashing the value.
            note_stderr("free_subject_fingerprint", "stored_fingerprint_probe", exc)
    return fingerprint(value)


__all__ = ["subject_fingerprint"]
