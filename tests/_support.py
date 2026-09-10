"""Shared test helpers for cross-file Free runtime tests."""

from __future__ import annotations


def drain_diagnostic_writer(owner) -> None:
    """Flush an owner's async diagnostic queue before store assertions.

    ``owner`` may be either a facade manager (``owner.log_store``) or a
    storage facade exposing ``diagnostic_writer`` directly; both shapes exist
    across the Free runtime tests.
    """
    store = getattr(owner, "log_store", owner)
    flush = getattr(getattr(store, "diagnostic_writer", None), "flush", None)
    if callable(flush):
        flush(2.0)


__all__ = ["drain_diagnostic_writer"]
