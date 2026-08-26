"""Credential-safe one-shot lookup for Free mailbox quick-copy actions."""

from __future__ import annotations

from typing import Any

try:
    from .mailbox_url_runtime import MailboxUrlClient
except ImportError:  # pragma: no cover - top-level runtime loading
    from mailbox_url_runtime import MailboxUrlClient  # type: ignore[no-redef]


def fetch_latest_code(mailbox_url: str, *, timeout_seconds: int = 5, proxy: str = "") -> dict[str, Any]:
    """Fetch one mailbox snapshot and return only the code contract.

    The URL is supplied by a server-side row binding.  It is never returned
    by this helper and no response body is included in errors.
    """
    reader = MailboxUrlClient(str(mailbox_url or ""), timeout_seconds=timeout_seconds, proxy=str(proxy or "").strip())
    selection = reader.latest_code(include_existing=True)
    code = str(getattr(selection, "code", "") or "").strip()
    return {
        "ok": True,
        "kind": "email",
        "code": code,
        "message": "已找到最新 OpenAI 邮箱验证码" if code else "未找到新的 OpenAI 邮箱验证码",
        "fetched_at": int(reader.now_fn()),
    }


__all__ = ["fetch_latest_code"]
