"""Non-sensitive build markers exposed by the isolated Free runtime."""

from __future__ import annotations

FREE_RUNTIME_VERSION = "1.6.82"
FREE_OTP_PARSER_REVISION = "pickup-dynamic-v5-manual-fallback-v1-timing-v1-proxy-recheck-v1"


def runtime_info() -> dict[str, str]:
    return {
        "runtime_version": FREE_RUNTIME_VERSION,
        "otp_parser_revision": FREE_OTP_PARSER_REVISION,
    }


__all__ = ["FREE_OTP_PARSER_REVISION", "FREE_RUNTIME_VERSION", "runtime_info"]
