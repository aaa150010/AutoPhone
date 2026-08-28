"""Non-sensitive build markers exposed by the isolated Free runtime."""

from __future__ import annotations

FREE_RUNTIME_VERSION = "1.6.86"
try:
    from .mailbox_parser_sample_store import MAILBOX_PARSER_REVISION
except ImportError:  # pragma: no cover - top-level runtime loading
    from mailbox_parser_sample_store import MAILBOX_PARSER_REVISION  # type: ignore[no-redef]

FREE_OTP_PARSER_REVISION = MAILBOX_PARSER_REVISION


def runtime_info() -> dict[str, str]:
    return {
        "runtime_version": FREE_RUNTIME_VERSION,
        "otp_parser_revision": FREE_OTP_PARSER_REVISION,
    }


__all__ = ["FREE_OTP_PARSER_REVISION", "FREE_RUNTIME_VERSION", "runtime_info"]
