"""Dependency wiring for the runtime mailbox administration service."""

from __future__ import annotations

from typing import Any, Callable

try:
    from . import current_run_append
    from . import imap_poller
    from . import mailbox_admin
    from . import mailbox_priority_runtime
    from . import mailbox_url_runtime
    from . import openai_quota_runtime
except ImportError:  # Loaded as top-level runtime overrides by the Mac launcher.
    import current_run_append  # type: ignore[no-redef]
    import imap_poller  # type: ignore[no-redef]
    import mailbox_admin  # type: ignore[no-redef]
    import mailbox_priority_runtime  # type: ignore[no-redef]
    import mailbox_url_runtime  # type: ignore[no-redef]
    import openai_quota_runtime  # type: ignore[no-redef]


def build_mailbox_admin(
    store: Any,
    importer: Any,
    logs: Any,
    *,
    runtime: Any,
    next_batch_priority: Any,
    notification_context_for: Callable[[Any], Any],
    task_progress: Any,
    task_progress_runtime: Any,
    sub2_runtime: Any,
    openai_direct_runtime: Any,
    openai_quota_snapshots: Any,
    actionable_phone_risk_status: Callable[[str], Any],
    run_batch_manifest: Any,
) -> Any:
    def append_to_current_run(source_rows):
        return current_run_append.append_imported_mailboxes(
            source_rows,
            importer=importer,
            row_id_from_source=mailbox_admin.row_id_from_source,
            reserve_specific_available=mailbox_priority_runtime.reserve_specific_available,
            release_owned_batch_leases=mailbox_priority_runtime.release_owned_batch_leases,
            mailbox_error_type=runtime.MailboxPoolError,
            next_batch_priority=next_batch_priority,
            notification_context_for=notification_context_for,
        )

    return mailbox_admin.MailboxAdminService(
        store,
        validate_pool=lambda config: importer._pool(config).validate(),
        imap_poller_factory=imap_poller.ImapPoller,
        runtime_status=importer.status,
        progress_lookup=task_progress.progress,
        is_active_progress=task_progress_runtime.is_active_progress,
        log_fn=logs.add,
        error_formatter=getattr(runtime, "_safe", str),
        sub2_status_lookup=sub2_runtime.status_for,
        sub2_batch_tester=sub2_runtime.test_rows,
        openai_status_lookup=openai_direct_runtime.status_for,
        openai_direct_batch_tester=openai_direct_runtime.test_rows,
        mailbox_url_reader_factory=mailbox_url_runtime.MailboxUrlClient,
        openai_quota_query=lambda document, proxy: openai_quota_runtime.OpenAIQuotaClient(
            proxy=proxy
        ).query(document),
        openai_quota_status_lookup=openai_quota_snapshots.status_for,
        openai_quota_status_store=openai_quota_snapshots.put,
        phone_risk_lookup=actionable_phone_risk_status,
        next_batch_priority=next_batch_priority,
        run_batch_membership=run_batch_manifest.latest_row_bindings,
        current_run_append=append_to_current_run,
    )


__all__ = ["build_mailbox_admin"]
