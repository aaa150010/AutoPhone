"""Flask route assembly for the recovered web GUI."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any, Callable

try:
    from . import web_routes_sections
    from .web_routes_sections import RouteScope
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    import web_routes_sections  # type: ignore[no-redef]
    from web_routes_sections import RouteScope  # type: ignore[no-redef]

try:
    from .mailbox_state_runtime import mark_mailboxes_unavailable
except ImportError:  # Loaded as a top-level runtime override by web_gui.py.
    from mailbox_state_runtime import mark_mailboxes_unavailable


@dataclass(frozen=True)
class WebRouteContext:
    module: Any
    app_dir: Path
    send_from_directory: Callable[..., Any]
    closure_values: Callable[[Callable[..., Any]], dict[str, Any]]
    lifecycle_lock: Any
    read_local_config: Callable[[], dict[str, Any]]
    write_local_config: Callable[[dict[str, Any]], dict[str, Any]]
    local_config_from_runtime: Callable[..., dict[str, Any]]
    local_config_secret: Callable[[str], Any]
    masked_local_config: Callable[[dict[str, Any]], dict[str, Any]]
    masked_state: Callable[[dict[str, Any]], dict[str, Any]]
    apply_server_defaults: Callable[[dict[str, Any]], dict[str, Any]]
    configure_sms_pool: Callable[..., str]
    preflight_sms_pool: Callable[..., list[dict[str, Any]]]
    safe_runtime_error: Callable[[Any], str]
    test_email_notification: Callable[[dict[str, Any]], dict[str, Any]]
    sms_alerts: Any
    sms_cost_ledger: Any
    sms_route_policy: Any
    sms_key_pool: Any
    sms_phone_gate: Any
    mailbox_admin_factory: Callable[[Any, Any, Any], Any]
    mailbox_manager_html: str
    run_batch_manifest: Any | None = None
    sub2_payload_builder: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None
    mailbox_url_test_factory: Callable[[], Any] | None = None
    query_sms_balances: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None
    online_mailbox_client_factory: Callable[[str, str], Any] | None = None
    failure_secrets: Callable[[dict[str, Any]], Sequence[Any]] | None = None
    free_register_manager: Any | None = None
    free_config_store: Any | None = None
    free_data_dir: Path | None = None
    diagnostic_store: Any | None = None
    mailbox_parser_sample_store: Any | None = None
    free_mailbox_parser_sample_store: Any | None = None


def patch_flask_app(app: Any, context: WebRouteContext) -> Any:
    """Install the macOS dashboard routes once on a recovered Flask app."""
    if getattr(app, "_gptphone_mac_patched", False):
        return app
    original_start = app.view_functions.get("start")
    if original_start is None:
        return app

    module = context.module
    closure = context.closure_values(original_start)
    importer = closure["importer"]
    logs = closure["logs"]
    settings = closure["settings"]
    state = closure["state"]
    store = closure["store"]
    mailbox_admin = context.mailbox_admin_factory(store, importer, logs)

    free_manager = context.free_register_manager
    free_config_store = context.free_config_store
    diagnostic_store = context.diagnostic_store

    scope = RouteScope(
        host=sys.modules[__name__],
        module=module,
        context=context,
        app=app,
        importer=importer,
        logs=logs,
        settings=settings,
        state=state,
        store=store,
        mailbox_admin=mailbox_admin,
        free_manager=free_manager,
        free_config_store=free_config_store,
        diagnostic_store=diagnostic_store,
    )
    views = web_routes_sections.build_route_sections(scope)
    mailbox_manager = views["mailbox_manager"]
    api_mailboxes = views["api_mailboxes"]
    api_remail_profile = views["api_remail_profile"]
    api_remail_config = views["api_remail_config"]
    api_remail_projects = views["api_remail_projects"]
    api_remail_wallet = views["api_remail_wallet"]
    api_remail_purchase = views["api_remail_purchase"]
    api_remail_orders = views["api_remail_orders"]
    api_remail_import_orders = views["api_remail_import_orders"]
    api_free_state = views["api_free_state"]
    api_free_camoufox_debug_state = views["api_free_camoufox_debug_state"]
    api_free_camoufox_debug_close = views["api_free_camoufox_debug_close"]
    api_free_preflight = views["api_free_preflight"]
    api_free_start = views["api_free_start"]
    api_free_stop = views["api_free_stop"]
    api_free_logs = views["api_free_logs"]
    api_mailboxes_website_import = views["api_mailboxes_website_import"]
    api_mailboxes_latest_code = views["api_mailboxes_latest_code"]
    api_mailboxes_password = views["api_mailboxes_password"]
    api_mailboxes_totp = views["api_mailboxes_totp"]
    api_mailboxes_url = views["api_mailboxes_url"]
    api_runtime_task_mailbox_url = views["api_runtime_task_mailbox_url"]
    api_runtime_task_latest_code = views["api_runtime_task_latest_code"]
    api_runtime_task_mailbox_password = views["api_runtime_task_mailbox_password"]
    api_runtime_task_mailbox_totp = views["api_runtime_task_mailbox_totp"]
    api_mailboxes_relogin = views["api_mailboxes_relogin"]
    api_mailbox_url_test = views["api_mailbox_url_test"]
    api_mailboxes_sub2_test = views["api_mailboxes_sub2_test"]
    api_mailboxes_openai_test = views["api_mailboxes_openai_test"]
    api_mailboxes_quota = views["api_mailboxes_quota"]
    api_run_batches = views["api_run_batches"]
    api_run_batch = views["api_run_batch"]
    api_mailboxes_sub2_export = views["api_mailboxes_sub2_export"]
    api_local_config = views["api_local_config"]
    api_sms_balances = views["api_sms_balances"]
    api_local_config_export = views["api_local_config_export"]
    api_local_config_import = views["api_local_config_import"]
    api_local_config_secret = views["api_local_config_secret"]
    api_notification_email_test = views["api_notification_email_test"]
    diagnostic_routes = views["diagnostic_routes"]
    free_control_routes = views["free_control_routes"]
    free_pool_routes = views["free_pool_routes"]
    free_account_routes = views["free_account_routes"]
    free_rebind_routes = views["free_rebind_routes"]
    mailbox_mutation_routes = views["mailbox_mutation_routes"]
    parser_sample_routes = views["parser_sample_routes"]


    routes = (
        ("/mailboxes", "mailbox_manager", mailbox_manager, ["GET"]),
        ("/splitter", "mailbox_splitter", mailbox_manager, ["GET"]),
        ("/url-test", "mailbox_url_test_page", mailbox_manager, ["GET"]),
        ("/mailbox-parser-samples", "mailbox_parser_samples_page", mailbox_manager, ["GET"]),
        # Legacy deep links remain harmless aliases; the account-management menu is gone.
        ("/accounts", "account_manager", mailbox_manager, ["GET"]),
        ("/settings", "settings_page", mailbox_manager, ["GET"]),
        ("/api/mailboxes", "api_mailboxes", api_mailboxes, ["GET"]),
        ("/api/free/config", "api_free_config", free_control_routes.config, ["GET", "POST"]),
        ("/api/free/config/secret", "api_free_config_secret", free_control_routes.config_secret, ["POST"]),
        ("/api/remail/profile", "api_remail_profile", api_remail_profile, ["GET"]),
        ("/api/remail/config", "api_remail_config", api_remail_config, ["GET", "POST"]),
        ("/api/remail/projects", "api_remail_projects", api_remail_projects, ["GET"]),
        ("/api/remail/wallet", "api_remail_wallet", api_remail_wallet, ["GET"]),
        ("/api/remail/purchase", "api_remail_purchase", api_remail_purchase, ["POST"]),
        ("/api/remail/orders", "api_remail_orders", api_remail_orders, ["GET"]),
        ("/api/remail/orders/import", "api_remail_import_orders", api_remail_import_orders, ["POST"]),
        ("/api/free/state", "api_free_state", api_free_state, ["GET"]),
        ("/api/free/camoufox/debug", "api_free_camoufox_debug_state", api_free_camoufox_debug_state, ["GET"]),
        ("/api/free/camoufox/debug/close", "api_free_camoufox_debug_close", api_free_camoufox_debug_close, ["POST"]),
        ("/api/free/preflight", "api_free_preflight", api_free_preflight, ["POST"]),
        ("/api/free/start", "api_free_start", api_free_start, ["POST"]),
        ("/api/free/stop", "api_free_stop", api_free_stop, ["POST"]),
        ("/api/free/logs", "api_free_logs", api_free_logs, ["GET"]),
        ("/api/diagnostics/search", "api_diagnostics_search", diagnostic_routes.search if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["POST"]),
        ("/api/diagnostics/incidents/<incident_id>", "api_diagnostics_incident", diagnostic_routes.incident if diagnostic_routes else lambda incident_id: module.jsonify(ok=False, error="日志中心尚未初始化"), ["GET"]),
        ("/api/diagnostics/export", "api_diagnostics_export", diagnostic_routes.export if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["POST"]),
        ("/api/diagnostics/delete", "api_diagnostics_delete", diagnostic_routes.delete if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["POST"]),
        ("/api/diagnostics/clear-all", "api_diagnostics_clear_all", diagnostic_routes.clear_all if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["POST"]),
        ("/api/diagnostics/health", "api_diagnostics_health", diagnostic_routes.health if diagnostic_routes else lambda: module.jsonify(ok=False, error="日志中心尚未初始化"), ["GET"]),
        ("/api/free/tasks/delete", "api_free_tasks_delete", free_control_routes.delete_tasks, ["POST"]),
        *free_pool_routes.routes(),
        ("/api/free/mailboxes/url", "api_free_mailbox_url", free_account_routes.mailbox_url, ["POST"]),
        ("/api/free/mailboxes/latest-code", "api_free_mailbox_latest_code", free_account_routes.mailbox_latest_code, ["POST"]),
        ("/api/free/tasks/latest-code", "api_free_task_latest_code", free_account_routes.task_latest_code, ["POST"]),
        ("/api/free/2fa/retry", "api_free_twofa_retry", free_account_routes.retry_twofa, ["POST"]),
        ("/api/free/password/retry", "api_free_password_retry", free_account_routes.retry_password, ["POST"]),
        ("/api/free/retry/batch", "api_free_retry_batch", free_account_routes.batch_retry, ["POST"]),
        ("/api/free/rerun", "api_free_rerun", free_account_routes.rerun, ["POST"]),
        ("/api/free/live-check", "api_free_live_check", free_account_routes.live_check, ["POST"]),
        ("/api/free/live-check/state", "api_free_live_check_state", free_account_routes.live_check_state, ["GET"]),
        ("/api/free/plan-check", "api_free_plan_check", free_account_routes.plan_check, ["POST"]),
        ("/api/free/plan-check/state", "api_free_plan_check_state", free_account_routes.plan_check_state, ["GET"]),
        ("/api/free/rebind/state", "api_free_rebind_state", free_rebind_routes.state, ["GET"]),
        ("/api/free/rebind/mailboxes", "api_free_rebind_mailboxes", free_rebind_routes.mailboxes, ["GET"]),
        ("/api/free/rebind/mailboxes/url", "api_free_rebind_mailboxes_url", free_rebind_routes.mailbox_url, ["POST"]),
        ("/api/free/rebind/mailboxes/import", "api_free_rebind_mailboxes_import", free_rebind_routes.import_mailboxes, ["POST"]),
        ("/api/free/rebind/mailboxes/latest-code", "api_free_rebind_mailboxes_latest_code", free_rebind_routes.mailbox_latest_code, ["POST"]),
        ("/api/free/rebind/mailboxes/delete", "api_free_rebind_mailboxes_delete", free_rebind_routes.delete_mailboxes, ["POST"]),
        ("/api/free/rebind/mailboxes/available", "api_free_rebind_mailboxes_available", lambda: free_rebind_routes.mailbox_status("available"), ["POST"]),
        ("/api/free/rebind/mailboxes/unavailable", "api_free_rebind_mailboxes_unavailable", lambda: free_rebind_routes.mailbox_status("unavailable"), ["POST"]),
        ("/api/free/rebind/start", "api_free_rebind_start", free_rebind_routes.start, ["POST"]),
        ("/api/free/rebind/retry", "api_free_rebind_retry", free_rebind_routes.retry, ["POST"]),
        ("/api/free/rebind/stop", "api_free_rebind_stop", free_rebind_routes.stop, ["POST"]),
        *mailbox_mutation_routes.routes(),
        ("/api/mailboxes/website-import", "api_mailboxes_website_import", api_mailboxes_website_import, ["POST"]),
        ("/api/mailboxes/latest-code", "api_mailboxes_latest_code", api_mailboxes_latest_code, ["POST"]),
        ("/api/mailboxes/password", "api_mailboxes_password", api_mailboxes_password, ["POST"]),
        ("/api/mailboxes/totp", "api_mailboxes_totp", api_mailboxes_totp, ["POST"]),
        ("/api/mailboxes/url", "api_mailboxes_url", api_mailboxes_url, ["POST"]),
        (
            "/api/runtime/tasks/mailbox-url",
            "api_runtime_task_mailbox_url",
            api_runtime_task_mailbox_url,
            ["POST"],
        ),
        (
            "/api/runtime/tasks/latest-code",
            "api_runtime_task_latest_code",
            api_runtime_task_latest_code,
            ["POST"],
        ),
        (
            "/api/runtime/tasks/mailbox-password",
            "api_runtime_task_mailbox_password",
            api_runtime_task_mailbox_password,
            ["POST"],
        ),
        (
            "/api/runtime/tasks/mailbox-totp",
            "api_runtime_task_mailbox_totp",
            api_runtime_task_mailbox_totp,
            ["POST"],
        ),
        ("/api/mailboxes/relogin", "api_mailboxes_relogin", api_mailboxes_relogin, ["POST"]),
        ("/api/mailbox-url-test", "api_mailbox_url_test", api_mailbox_url_test, ["POST"]),
        ("/api/mailbox-parser-samples/status", "api_mailbox_parser_samples_status", parser_sample_routes.status, ["POST"]),
        ("/api/mailbox-parser-samples/delete", "api_mailbox_parser_samples_delete", parser_sample_routes.delete, ["POST"]),
        ("/api/mailbox-parser-samples/cleanup", "api_mailbox_parser_samples_cleanup", parser_sample_routes.cleanup, ["POST"]),
        ("/api/mailbox-parser-samples/export", "api_mailbox_parser_samples_export", parser_sample_routes.export, ["POST"]),
        ("/api/mailbox-parser-samples/health", "api_mailbox_parser_samples_health", parser_sample_routes.health, ["GET"]),
        ("/api/mailbox-parser-samples", "api_mailbox_parser_samples", parser_sample_routes.list, ["GET"]),
        ("/api/mailbox-parser-samples/<sample_id>", "api_mailbox_parser_sample_detail", parser_sample_routes.detail, ["GET"]),
        ("/api/mailbox-parser-samples/<sample_id>/reveal", "api_mailbox_parser_sample_reveal", parser_sample_routes.reveal, ["POST"]),
        ("/api/mailbox-parser-samples/<sample_id>/reparse", "api_mailbox_parser_sample_reparse", parser_sample_routes.reparse, ["POST"]),
        ("/api/mailboxes/sub2-test", "api_mailboxes_sub2_test", api_mailboxes_sub2_test, ["POST"]),
        ("/api/mailboxes/openai-test", "api_mailboxes_openai_test", api_mailboxes_openai_test, ["POST"]),
        ("/api/mailboxes/quota", "api_mailboxes_quota", api_mailboxes_quota, ["POST"]),
        ("/api/run-batches", "api_run_batches", api_run_batches, ["GET"]),
        (
            "/api/run-batches/<batch_id>",
            "api_run_batch",
            api_run_batch,
            ["GET"],
        ),
        ("/api/mailboxes/sub2-export", "api_mailboxes_sub2_export", api_mailboxes_sub2_export, ["POST"]),
        ("/api/local-config", "api_local_config", api_local_config, ["GET"]),
        ("/api/sms/balances", "api_sms_balances", api_sms_balances, ["POST"]),
        ("/api/local-config/export", "api_local_config_export", api_local_config_export, ["POST"]),
        ("/api/local-config/import", "api_local_config_import", api_local_config_import, ["POST"]),
        ("/api/local-config/secret", "api_local_config_secret", api_local_config_secret, ["POST"]),
        ("/api/notifications/email/test", "api_notification_email_test", api_notification_email_test, ["POST"]),
    )
    for rule, endpoint, view_func, methods in routes:
        if endpoint not in app.view_functions:
            app.add_url_rule(rule, endpoint, view_func, methods=methods)

    app._gptphone_mac_patched = True
    return app


__all__ = [
    "RouteScope",
    "WebRouteContext",
    "patch_flask_app",
]
