"""Last-resort stderr notes for swallowed best-effort cleanup paths.

Every module used to carry a byte-identical private ``_note_stderr`` that
printed only the failure point label and exception class name to stderr.  The
single shared implementation keeps that contract: no sensitive value is ever
formatted, and a failing stderr write is silently ignored because telemetry
must not mask the surrounding cleanup semantics.
"""

from __future__ import annotations

import sys


def note_stderr(scope: str, where: str, exc: BaseException) -> None:
    """Note one swallowed exception as ``[<scope>/<where>] <ExcClass>``."""
    try:
        print(f"[{scope}/{where}] {type(exc).__name__}", file=sys.stderr)
    except Exception:
        return


def make_note_stderr(scope: str):
    """Build the per-module ``_note_stderr(where, exc)`` shim."""
    def _note_stderr(where: str, exc: BaseException) -> None:
        note_stderr(scope, where, exc)
    return _note_stderr


def stderr_print(scope: str, message: str) -> None:
    """Best-effort stderr print that never raises (user-visible Chinese text)."""
    try:
        print(f"[{scope}] {message}", file=sys.stderr)
    except Exception:
        return


__all__ = ["make_note_stderr", "note_stderr", "stderr_print"]
