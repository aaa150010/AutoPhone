"""Collect runtime secrets that must be removed from public diagnostics."""

from __future__ import annotations

from typing import Any, Callable


def collect_failure_secrets(
    importer: Any = None,
    entry: Any = None,
    settings: Any = None,
    *,
    mailbox_admin: Any,
    sms_keys_from_config: Callable[[dict[str, Any]], Any],
) -> tuple[str, ...]:
    values: list[Any] = []
    if importer is not None and entry is not None:
        try:
            source_row = str(importer._source_row(entry) or "")
            values.extend(mailbox_admin.MailboxAdminService._row_secrets(source_row))
        except Exception:
            pass
    for name in ("password", "totp_secret", "client_id", "refresh_token"):
        value = str(getattr(entry, name, "") or "") if entry is not None else ""
        if value:
            values.append(value)
    config = settings if isinstance(settings, dict) else {}
    pool_content = str(config.get("pool_content") or "")
    if pool_content:
        for row in pool_content.splitlines():
            try:
                values.extend(mailbox_admin.MailboxAdminService._row_secrets(row))
            except Exception:
                continue
    sub2api = config.get("sub2api") if isinstance(config.get("sub2api"), dict) else {}
    notification = config.get("email_notification") if isinstance(config.get("email_notification"), dict) else {}
    online_mailbox = config.get("online_mailbox") if isinstance(config.get("online_mailbox"), dict) else {}
    values.extend(sms_keys_from_config(config))
    values.extend(
        (
            config.get("gptmail_api_key"),
            sub2api.get("password"),
            notification.get("password"),
            online_mailbox.get("api_token"),
            *mailbox_admin.url_credential_secrets(config.get("proxy")),
        )
    )
    return tuple(dict.fromkeys(str(item) for item in values if str(item or "")))


__all__ = ["collect_failure_secrets"]
