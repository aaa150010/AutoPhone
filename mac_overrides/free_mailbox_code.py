"""Credential-safe one-shot lookup for Free mailbox quick-copy actions."""

from __future__ import annotations

from typing import Any

try:
    from .mailbox_url_runtime import MailboxUrlClient
    from .mailbox_parser_sample_store import MAILBOX_PARSER_REVISION, record_client_parser_failure
except ImportError:  # pragma: no cover - top-level runtime loading
    from mailbox_url_runtime import MailboxUrlClient  # type: ignore[no-redef]
    from mailbox_parser_sample_store import MAILBOX_PARSER_REVISION, record_client_parser_failure  # type: ignore[no-redef]


def fetch_latest_code(
    mailbox_url: str,
    *,
    timeout_seconds: int = 5,
    proxy: str = "",
    mailbox_source: str = "",
    mailbox_email: str = "",
    service_token: str = "",
) -> dict[str, Any]:
    """Fetch one mailbox snapshot and return only the code contract.

    The URL is supplied by a server-side row binding.  It is never returned
    by this helper and no response body is included in errors.
    """
    source = str(mailbox_source or "").strip().lower()
    if source == "remail" or "remail.aishop6.com/v1/pickup" in str(mailbox_url or "").lower():
        try:
            from .free_mailbox_otp import build_free_mailbox_otp_provider
        except ImportError:
            from free_mailbox_otp import build_free_mailbox_otp_provider  # type: ignore[no-redef]
        provider = build_free_mailbox_otp_provider(
            str(mailbox_url or ""), str(proxy or ""),
            {"email_code_timeout": int(timeout_seconds)},
            mailbox_source="remail", mailbox_email=str(mailbox_email or ""), service_token=str(service_token or ""),
        )
        reader = provider.service.client
        selection = reader.latest_code(include_existing=True)
        code = str(getattr(selection, "code", "") or "").strip()
        return {
            "ok": True, "kind": "email", "code": code,
            "message": "已找到最新 OpenAI 邮箱验证码" if code else "未找到新的 OpenAI 邮箱验证码",
            "fetched_at": int(reader.now_fn()),
        }
    reader = MailboxUrlClient(str(mailbox_url or ""), timeout_seconds=timeout_seconds, proxy=str(proxy or "").strip())
    selection = reader.latest_code(include_existing=True)
    code = str(getattr(selection, "code", "") or "").strip()
    if not code:
        record_client_parser_failure(reader, {
            "scope": "free",
            "chain": "free",
            "workflow": "free_latest_code",
            "driver": "unknown",
            "stage": "free_mailbox_latest_code",
            "mailbox_url": str(mailbox_url or ""),
            "reason": str(getattr(selection, "reason", "") or "mailbox_code_timeout"),
            "diagnostics": {},
            "parser_version": MAILBOX_PARSER_REVISION,
        })
    return {
        "ok": True,
        "kind": "email",
        "code": code,
        "message": "已找到最新 OpenAI 邮箱验证码" if code else "未找到新的 OpenAI 邮箱验证码",
        "fetched_at": int(reader.now_fn()),
    }


__all__ = ["fetch_latest_code"]
