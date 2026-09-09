"""Mac launcher overrides for the recovered web GUI."""

from __future__ import annotations

from contextvars import ContextVar
import importlib.util
import copy
import hmac
import json
import math
import os
import re
import threading
import time
import uuid
from pathlib import Path

from flask import send_from_directory as _send_from_directory

import node_runtime as _node_runtime_ext

# Resolve this before importing recovered modules so their first subprocess
# lookup sees the same verified Node binary as later runtime calls.
_node_runtime_ext.configure_node_runtime()

import codex_oauth_chain as _codex_oauth_chain
import codex_node_bridge as _codex_node_bridge
try:
    import sentinel_bridge_pool_patch as _sentinel_pool_patch_ext

    _sentinel_pool_patch_ext.apply_sentinel_pool_patch(_codex_node_bridge)
    _sentinel_pool_patch_ext.register_exit_cleanup()
except Exception as exc:
    # The resident pool is a latency optimization only; a patch failure must
    # keep the recovered one-shot bridge fully functional. Module import time:
    # no _note_stderr exists yet, print the exception class directly.
    print(f"[web_gui/sentinel_pool_patch] {type(exc).__name__}", file=sys.stderr)
import chatgpt_plan_gate as _chatgpt_plan_gate_ext
import chatgpt_totp as _chatgpt_totp_ext
import configuration_runtime as _configuration_runtime_ext
import error_observability as _error_observability_ext
import failure_secrets as _failure_secrets_ext
import auth_request_runtime as _auth_request_runtime_ext
import auth_challenge_runtime as _auth_challenge_runtime_ext
import auth_session_runtime as _auth_session_runtime_ext
import auth_connectivity_runtime as _auth_connectivity_runtime_ext
import connectivity_notifications as _connectivity_notifications_ext
import connectivity_routes as _connectivity_routes_ext
import connectivity_diagnostics as _connectivity_diagnostics_ext
import diagnostic_store as _diagnostic_store_ext
import mfa_retry_runtime as _mfa_retry_runtime_ext
import oauth_mfa_runtime as _oauth_mfa_runtime_ext
import manual_verification_runtime as _manual_verification_runtime_ext
import manual_verification_routes as _manual_verification_routes_ext
import phase1_checkpoint_runtime as _phase1_checkpoint_runtime_ext
import phase1_checkpoint_hooks as _phase1_checkpoint_hooks_ext
import adaptive_concurrency as _adaptive_concurrency_ext
import importer_watch_runtime as _importer_watch_runtime_ext
import importer_scheduler as _importer_scheduler_ext
import inflight_pipeline_runtime as _inflight_pipeline_runtime_ext
import legacy_ui as _legacy_ui_ext
import log_retention as _log_retention_ext
import mailbox_admin as _mailbox_admin_ext
import mailbox_admin_factory as _mailbox_admin_factory_ext
import mailbox_priority_runtime as _mailbox_priority_runtime_ext
import mailbox_otp_service as _mailbox_otp_service_ext
import mailbox_url_runtime as _mailbox_url_runtime_ext
import mailbox_url_test_runtime as _mailbox_url_test_runtime_ext
import mailbox_parser_sample_store as _mailbox_parser_sample_store_ext
import mailbox_retention as _mailbox_retention_ext
import free_register_runtime as _free_register_runtime_ext
import free_register_config as _free_register_config_ext
import free_storage_adapters as _free_storage_adapters_ext
import phone_risk_runtime as _phone_risk_runtime_ext
import phone_binding_runtime as _phone_binding_runtime_ext
import performance_runtime as _performance_runtime_ext
import phase_concurrency as _phase_concurrency_ext
import sms_optimization_guard as _sms_optimization_guard_ext
import public_state_runtime as _public_state_runtime_ext
import openai_quota_runtime as _openai_quota_runtime_ext
import openai_direct_test_runtime as _openai_direct_test_runtime_ext
import online_mailbox_runtime as _online_mailbox_runtime_ext
import run_notifications as _run_notifications_ext
import notification_runtime as _notification_runtime_ext
import run_batch_runtime as _run_batch_runtime_ext
import result_persistence_runtime as _result_persistence_runtime_ext
import runtime as _runtime
import runtime_policy as _runtime_policy_ext
import network_runtime as _network_runtime_ext
import sms_providers as _sms_providers
import sms_cost_history as _sms_cost_history_ext
import sms_runtime as _sms_runtime_ext
import sms_selector as _sms_selector
import sms_web as _sms_web_ext
import sub2_binding_runtime as _sub2_binding_runtime_ext
import sub2_runtime as _sub2_runtime_ext
import sub2_update_runtime as _sub2_update_runtime_ext
import sub2_upload_override as _sub2_upload_override_ext
import task_progress as _task_progress_ext
import transport_lifecycle as _transport_lifecycle_ext
import web_routes as _web_routes_ext
import network_tools_routes as _network_tools_routes_ext
import free_protocol_diagnostics as _free_protocol_diagnostics_ext
import sys
import web_gui_config_patches as _config_patches_mod
import web_gui_config_lifecycle as _config_lifecycle_mod
import web_gui_importer_patches as _importer_patches
import web_gui_codex_patches as _codex_patches

_codex_patches.bind_host(sys.modules[__name__])


# Do not allow the host shell's proxy settings to silently affect OpenAI,
# mailbox, SMS, or SUB2 requests. Each caller below supplies its own
# explicit proxy when that scope is enabled.
_network_runtime_ext.clear_inherited_proxy_environment()


APP_DIR = Path(__file__).resolve().parent.parent
BUSINESS_DIR = APP_DIR / "business_pyc"
ORIGINAL_WEB_GUI = BUSINESS_DIR / "web_gui.pyc"
_RUNTIME_DATA_DIR = Path(
    os.environ.get("GPTPHONE_DATA_DIR") or APP_DIR / "data"
).expanduser().resolve()
_FREE_DATA_DIR = _RUNTIME_DATA_DIR / "free_register"
_FREE_CONFIG_STORE = _free_register_config_ext.FreeConfigStore(_FREE_DATA_DIR)
_DIAGNOSTIC_STORE = _diagnostic_store_ext.DiagnosticStore(_RUNTIME_DATA_DIR / "diagnostics")
_MAILBOX_PARSER_SAMPLE_STORE = _mailbox_parser_sample_store_ext.MailboxParserSampleStore(
    _RUNTIME_DATA_DIR / "mailbox_parser_samples"
)
_FREE_MAILBOX_PARSER_SAMPLE_STORE = _mailbox_parser_sample_store_ext.MailboxParserSampleStore(
    _FREE_DATA_DIR / "mailbox_parser_samples"
)
_mailbox_parser_sample_store_ext.configure_sample_stores(
    ordinary=_MAILBOX_PARSER_SAMPLE_STORE,
    free=_FREE_MAILBOX_PARSER_SAMPLE_STORE,
    diagnostic_store=_DIAGNOSTIC_STORE,
)
if os.environ.get("GPTPHONE_DATA_DIR"):
    _runtime.DEFAULT_DATA_DIR = _RUNTIME_DATA_DIR


def _manual_disabled(*args, **kwargs):
    raise _runtime.MailboxPoolError("手动邮箱验证码功能已禁用")


_runtime.ImporterConfigStore.save_manual_pool_text = _manual_disabled
_runtime.EmailAuthImporter.submit_manual_code = _manual_disabled

_spec = importlib.util.spec_from_file_location("_gptphone_original_web_gui", ORIGINAL_WEB_GUI)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load original web_gui from {ORIGINAL_WEB_GUI}")

_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


_ORIGINAL_POOL_ENTRIES_UNLOCKED = _runtime.MailboxPool._entries_unlocked
_ORIGINAL_POOL_LEASE = _runtime.MailboxPool.lease
_ORIGINAL_POOL_RESTORE_ENTRY = _runtime.MailboxPool.restore_entry
_ORIGINAL_POOL_REMOVE_ENTRY = _runtime.MailboxPool.remove_entry
_ORIGINAL_OUTLOOK_OTP_PROVIDER = _runtime.OutlookMailboxOtpProvider
_ORIGINAL_OUTLOOK_OTP_WAIT_CODE = _runtime.OutlookMailboxOtpProvider.wait_code
_ORIGINAL_GPTMAIL_OTP_WAIT_CODE = _runtime.GptMailOtpProvider.wait_code
_ORIGINAL_MAILBOX_URL_SNAPSHOT = _runtime.MailboxUrlCodeProvider.snapshot
_ORIGINAL_MAILBOX_URL_SAME_AS_BASELINE = _runtime.MailboxUrlCodeProvider._same_as_baseline
_ORIGINAL_URL_MAILBOX_MARK_SENT = _runtime.UrlMailboxOtpProvider.mark_sent
_ORIGINAL_URL_MAILBOX_WAIT_CODE = _runtime.UrlMailboxOtpProvider.wait_code
_ORIGINAL_ACCOUNT_LABEL = _runtime.EmailAuthImporter._account_label
_ORIGINAL_REAL_TRANSPORT_INIT = _codex_oauth_chain.RealCodexTransport.__init__
_ORIGINAL_REAL_NEW_SESSION = _codex_oauth_chain.RealCodexTransport._new_session
_ORIGINAL_REAL_HEADERS = _codex_oauth_chain.RealCodexTransport._headers
_ORIGINAL_REAL_POST_AUTH_JSON = _codex_oauth_chain.RealCodexTransport._post_auth_json
_ORIGINAL_REAL_SEND_EMAIL_OTP = _codex_oauth_chain.RealCodexTransport.send_email_otp
_ORIGINAL_REAL_IMPORT_PHASE1_SESSION = _codex_oauth_chain.RealCodexTransport.import_phase1_session
_ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER = _codex_oauth_chain.RealCodexTransport.submit_email_identifier
_ORIGINAL_REAL_VERIFY_PASSWORD = _codex_oauth_chain.RealCodexTransport.verify_password
_ORIGINAL_REAL_VERIFY_EMAIL_OTP = _codex_oauth_chain.RealCodexTransport.verify_email_otp
_ORIGINAL_REAL_VERIFY_SIGNUP_EMAIL_OTP = (
    _codex_oauth_chain.RealCodexTransport.verify_signup_email_otp
)
_ORIGINAL_REAL_VERIFY_MFA_OTP = _codex_oauth_chain.RealCodexTransport.verify_mfa_otp
_ORIGINAL_REAL_SEND_MFA_OTP = _codex_oauth_chain.RealCodexTransport.send_mfa_otp
_ORIGINAL_REAL_INITIATE_OAUTH = _codex_oauth_chain.RealCodexTransport.initiate_oauth
_ORIGINAL_REAL_VISIT_CONTINUE = _codex_oauth_chain.RealCodexTransport.visit_continue
_ORIGINAL_REAL_COMPLETE_CHATGPT_CALLBACK = _codex_oauth_chain.RealCodexTransport.complete_chatgpt_callback
_ORIGINAL_REAL_VERIFY_PHONE_OTP = _codex_oauth_chain.RealCodexTransport.verify_phone_otp
_ORIGINAL_REAL_CREATE_ACCOUNT_PROFILE = _codex_oauth_chain.RealCodexTransport.create_account_profile
_ORIGINAL_REAL_ACCEPT_CONSENT = _codex_oauth_chain.RealCodexTransport.accept_consent
_ORIGINAL_REAL_FOLLOW_CONTINUE_UNTIL_CODE = _codex_oauth_chain.RealCodexTransport.follow_continue_until_code
_ORIGINAL_REAL_EXCHANGE_CODE = _codex_oauth_chain.RealCodexTransport.exchange_code
_ORIGINAL_SUB2_SESSION_EXCHANGE = _codex_oauth_chain.Sub2SessionExchanger.exchange
_ORIGINAL_REAL_SUB2_UPLOAD = _codex_oauth_chain.RealSub2Uploader.upload
_ORIGINAL_GENERATE_SUB2_OAUTH_SESSION = _runtime._generate_sub2_oauth_session
_ORIGINAL_FRIENDLY_LOG_MESSAGE = _runtime._friendly_log_message
_ORIGINAL_SMART_BUILD_CANDIDATES = _sms_selector.SmartSmsSelector._build_candidates_locked
_ORIGINAL_PERSIST_RESULT = _runtime.EmailAuthImporter._persist_result
_ORIGINAL_RETIRE_AFTER_FAILURE = _runtime.EmailAuthImporter._retire_after_failure
_ORIGINAL_CONFIG_SAVE = _runtime.ImporterConfigStore.save
_ORIGINAL_TASK_CONFIG = _runtime.EmailAuthImporter._task_config
_ORIGINAL_TASK_STATE = _runtime.EmailAuthImporter._task_state
_ORIGINAL_IMPORTER_START = _runtime.EmailAuthImporter.start
_ORIGINAL_IMPORTER_STOP = _runtime.EmailAuthImporter.stop
_ORIGINAL_IMPORTER_WATCH = _runtime.EmailAuthImporter._watch
_ORIGINAL_IMPORTER_RUN_ONE = _runtime.EmailAuthImporter._run_one
_ORIGINAL_PRE_AUTH_SESSION_RETRYABLE = _runtime.EmailAuthImporter._pre_auth_session_retryable
_ORIGINAL_PASSWORD_CREDENTIALS_REJECTED = _runtime.EmailAuthImporter._password_credentials_rejected
_ORIGINAL_RUN_CODEX_AFTER_REGISTRATION = _runtime.run_codex_after_registration
_ORIGINAL_GUI_LOG_ADD = _module.GuiLog.add
_ORIGINAL_GUI_LOG_SNAPSHOT = _module.GuiLog.snapshot
_ORIGINAL_CREATE_PROVIDER = _sms_providers.create_provider
_ORIGINAL_SMS_BASE_TRY_GET = _sms_providers.BaseSmsProvider._try_get
_ORIGINAL_FIVESIM_REST_GET = _sms_providers.FiveSimProvider._rest_get
_ORIGINAL_SMS_ADAPTER_GET_NUMBER = _codex_oauth_chain.SmsProviderAdapter.get_number
_ORIGINAL_SMS_ADAPTER_WAIT_CODE = _codex_oauth_chain.SmsProviderAdapter.wait_code
_ORIGINAL_SMS_ADAPTER_COMPLETE = _codex_oauth_chain.SmsProviderAdapter.complete
_ORIGINAL_SMS_ADAPTER_CANCEL = _codex_oauth_chain.SmsProviderAdapter.cancel
_ORIGINAL_REAL_SEND_PHONE_NUMBER_OTP = _codex_oauth_chain.RealCodexTransport.send_phone_number_otp
_ORIGINAL_SMART_CLASSIFY_ERROR = _sms_selector.SmartSmsSelector.classify_error
_ORIGINAL_SMART_RECORD_RESULT = _sms_selector.SmartSmsSelector.record_result
_ORIGINAL_CHAIN_EMIT = _codex_oauth_chain._emit
_ORIGINAL_CHAIN_EVENT = _codex_oauth_chain._event
_SMS_PRIORITY_COUNTRIES = ()
_SMS_MIN_PRICE_DEFAULT = 0.01
_SMS_MAX_PRICE_DEFAULT = "0.15"
_SMS_MAX_PRICE_HARD_LIMIT = 0.18
_EMAIL_CODE_TIMEOUT_DEFAULT = 60
_EMAIL_TIMEOUT_STRATEGY_VERSION = 3
_EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT = 2
_EMAIL_OTP_RESEND_ON_RETRY_DEFAULT = True
_EMAIL_PROXY_SCOPE_STRATEGY_VERSION = 1
_SMS_PRIORITY_COUNTRIES_TEXT = ",".join(_SMS_PRIORITY_COUNTRIES)
_SMS_PRIORITY_ROUTES = ()
_SMS_BLOCKED_ROUTES = (
    ("151", "3335"),
    ("33", "3160"),
    ("33", "3253"),
    ("33", "2236"),
    ("1", "3371"),
    ("91", "2266"),
    ("91", "3160"),
    ("151", "3235"),
    ("33", "3243"),
    ("1", "2920"),
)
_LOCAL_CONFIG_FILE = Path(
    os.environ.get("GPTPHONE_LOCAL_CONFIG_FILE") or _RUNTIME_DATA_DIR / "local_config.json"
)
_SECRET_MASK = "********"
_SMS_KEY_POOL = _sms_runtime_ext.SmsKeyPool(
    lambda key, proxy="": _ORIGINAL_CREATE_PROVIDER("smsbower", key, proxy=proxy)
)
_SMS_PROVIDER_REGISTRY = _sms_runtime_ext.SmsProviderRegistry(
    _ORIGINAL_CREATE_PROVIDER,
    legacy_pool=_SMS_KEY_POOL,
)
_SMS_COST_LEDGER = _sms_runtime_ext.SmsCostLedger()
_SMS_CLEANUP_QUEUE = _sms_runtime_ext.SmsCleanupQueue(
    _RUNTIME_DATA_DIR / "sms_cleanup_queue.json"
)
_SMS_EXCHANGE_RATE = _sms_runtime_ext.ExchangeRateCache(_RUNTIME_DATA_DIR / "usd_cny_rate.json")
_SMS_PHONE_GATE = _sms_runtime_ext.PhoneSubmissionGate(concurrency=2, interval_seconds=0.75)
_SMS_ROUTE_POLICY = _sms_runtime_ext.SmsRoutePolicy()
_SMS_QUALITY_GUARD = _sms_optimization_guard_ext.SmsOptimizationGuard(
    baseline_path=_RUNTIME_DATA_DIR / "sms_optimization_baseline.json"
)
_SMS_ALERTS = _sms_runtime_ext.RuntimeAlertBuffer()
_GUI_LOG_RETENTION = _log_retention_ext.GuiLogRetention()
_TASK_PROGRESS = _task_progress_ext.TaskProgressTracker()
_MANUAL_VERIFICATION = _manual_verification_runtime_ext.ManualVerificationBroker()
_NOTIFICATION_LIFECYCLE = _notification_runtime_ext.RunNotificationLifecycle(
    notifications=_run_notifications_ext,
    ledger=_SMS_COST_LEDGER,
    exchange=_SMS_EXCHANGE_RATE,
    progress_lookup=lambda task_id: _TASK_PROGRESS.progress(task_id) or {},
    terminal_statuses=_task_progress_ext.TERMINAL_TASK_STATUSES,
    sms_exhausted=lambda: _SMS_PROVIDER_REGISTRY.is_exhausted(),
    refresh_sms_balances=lambda: (
        getattr(globals().get("_SMS_WEB"), "refresh_balances", lambda: [])()
    ),
    observe_resource_pressure=lambda importer: _observe_runtime_fd_pressure(importer),
    int_value=lambda value, default=0, minimum=None, maximum=None: _int_value(
        value, default, minimum, maximum
    ),
)
_PHASE1_CHECKPOINTS = _phase1_checkpoint_runtime_ext.Phase1CheckpointStore(
    _RUNTIME_DATA_DIR / "phase1_checkpoints",
    enabled=True,
    ttl_seconds=_phase1_checkpoint_runtime_ext.DEFAULT_TTL_SECONDS,
)
_PHONE_RISK_STORE = _phone_risk_runtime_ext.PhoneRiskStore(
    _RUNTIME_DATA_DIR / "phone_risk_markers.json"
)
def _as_enabled(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", "unchecked", "disabled"}


def _host_module():
    """Return this module by name so split-out patches stay late-bound.

    Resolving via :data:`sys.modules` instead of a captured module object
    keeps the delegated patch callables reading the live ``web_gui`` globals
    exactly as the original inline implementations did.
    """
    return sys.modules[__name__]


def _actionable_phone_risk_status(email):
    status = _PHONE_RISK_STORE.status(email)
    if str(status.get("reason_code") or "").strip().lower() in {
        "oauth_session_invalid",
        "auth_session_invalid",
    }:
        return {}
    return status


_TASK_CONTEXT: ContextVar[str] = ContextVar("gptphone_task_id", default="")
_CHECKPOINT_CONTEXT: ContextVar[dict[str, str] | None] = ContextVar(
    "gptphone_checkpoint_context",
    default=None,
)
_TASK_ADMISSION_CONTEXT: ContextVar[object | None] = ContextVar(
    "gptphone_task_admission",
    default=None,
)
_RUN_MODE_CONTEXT: ContextVar[str] = ContextVar("gptphone_run_mode", default="register")
_ACTIVE_SMS_TRANSPORT: ContextVar[object | None] = ContextVar(
    "gptphone_active_sms_transport",
    default=None,
)
_PROTOCOL_REQUEST_ACTIVITY: ContextVar[int] = ContextVar(
    "gptphone_protocol_request_activity",
    default=0,
)
_SMS_TRANSPORT_REGISTRY = _transport_lifecycle_ext.TaskTransportRegistry()
_MAILBOX_LEASE_FILTER_ACTIVE: ContextVar[bool] = ContextVar(
    "gptphone_mailbox_lease_filter_active",
    default=False,
)
_MAILBOX_RUN_SELECTION: ContextVar[frozenset[tuple[str, int]]] = ContextVar(
    "gptphone_mailbox_run_selection",
    default=frozenset(),
)
_MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE: ContextVar[bool] = ContextVar(
    "gptphone_mailbox_next_batch_priority_active",
    default=False,
)
_MAILBOX_TOTP_SECRET_CONTEXT: ContextVar[str] = ContextVar("gptphone_mailbox_totp_secret", default="")
_TASK_TOTP_SECRETS = _oauth_mfa_runtime_ext.TaskSecretRegistry()
_ACCOUNT_BANNED_DETAIL_CONTEXT: ContextVar[str] = ContextVar(
    "gptphone_account_banned_detail",
    default="",
)
_PASSWORD_DAMAGED_MESSAGE = "OpenAI 登录密码验证失败，请检查账号密码；手动恢复后才会重跑"
_HISTORICAL_SUCCESS_REASONS = frozenset({"sub2_uploaded"})
_TASK_FAILURES: dict[str, dict] = {}
_TASK_FAILURES_LOCK = threading.RLock()
_CHECKPOINT_PUBLIC_STATE = _phase1_checkpoint_hooks_ext.CheckpointPublicState()
_RUN_LIFECYCLE_LOCK = threading.Lock()
_CURRENT_TASK_ADMISSION = None
_CURRENT_INFLIGHT_GATE = None
_FAST_ACCOUNT_BANNED_MAX_EXECUTION_SECONDS = 90
_FAST_ACCOUNT_BANNED_ALLOWED_GROUPS = frozenset({"queue", "oauth", "email"})
_FAST_ACCOUNT_BANNED_TERMINAL_GROUPS = frozenset({"oauth", "email"})
_PROTOCOL_GATE = _sms_runtime_ext.ProxyProtocolGate(
    default_limit=5,
    launch_interval_seconds=1.0,
)
_PROTOCOL_PRESSURE_POLICY = _sms_runtime_ext.ProtocolPressurePolicy(
    progress_getter=lambda task_id: _TASK_PROGRESS.progress(task_id),
    classify_failure=_error_observability_ext.classify_failure,
    task_gate_getter=lambda: (
        _TASK_ADMISSION_CONTEXT.get()
        or globals().get("_CURRENT_TASK_ADMISSION")
    ),
    inflight_gate_getter=lambda: globals().get("_CURRENT_INFLIGHT_GATE"),
    fd_exhaustion=_transport_lifecycle_ext.is_fd_exhaustion,
)
_report_task_pressure = _PROTOCOL_PRESSURE_POLICY.report_task_pressure
_CONNECTIVITY_PROXY = ""
_CONNECTIVITY_BATCH_ID = ""
_CONNECTIVITY_NOTIFICATION_CONTEXTS = (
    _connectivity_notifications_ext.ConnectivityIncidentContextStore()
)


def _set_stall_notifications_suspended(suspended):
    context_for = globals().get("_notification_context_for")
    try:
        context = context_for() if callable(context_for) else None
        service = context.get("service") if isinstance(context, dict) else None
        setter = getattr(service, "set_stall_suspended", None)
        if callable(setter):
            setter(bool(suspended))
    except Exception as exc:
        # Stall-notification suspension is best-effort UI state.
        _note_stderr("stall_suspended", exc)


def _submit_connectivity_email(payload):
    try:
        capacity = _PROTOCOL_GATE.snapshot(_CONNECTIVITY_PROXY)
        notification = _CONNECTIVITY_NOTIFICATION_CONTEXTS.build_notification(
            payload,
            batch_id=_CONNECTIVITY_BATCH_ID,
            capacity=capacity,
        )
        _CONNECTIVITY_EMAILS.submit(notification)
    except Exception as exc:
        # Connectivity alerting must never break the calling flow.
        _note_stderr("connectivity_alert_submit", exc)


def _on_connectivity_outage(payload):
    _PROTOCOL_GATE.pause_connectivity(_CONNECTIVITY_PROXY)
    inflight = globals().get("_CURRENT_INFLIGHT_GATE")
    if _PROTOCOL_GATE.snapshot(_CONNECTIVITY_PROXY).get("sticky_baseline"):
        reporter = getattr(inflight, "report_pressure", None)
        if callable(reporter):
            reporter("repeated_connectivity_outage")
    else:
        suspend = getattr(inflight, "suspend", None)
        if callable(suspend):
            suspend("openai_connectivity_outage")
    _set_stall_notifications_suspended(True)
    _submit_connectivity_email(payload)


def _on_connectivity_recovery(payload):
    _PROTOCOL_GATE.resume_connectivity(_CONNECTIVITY_PROXY)
    _set_stall_notifications_suspended(False)
    _submit_connectivity_email(payload)


_CONNECTIVITY_EMAILS = _connectivity_notifications_ext.OpenAIConnectivityNotificationService(
    lambda: globals().get("_read_local_config", lambda: {})()
)
_OPENAI_CONNECTIVITY = _auth_connectivity_runtime_ext.OpenAIAuthConnectivityRuntime(
    state_path=_RUNTIME_DATA_DIR / "openai_auth_connectivity.json",
    on_outage=_on_connectivity_outage,
    on_recovery=_on_connectivity_recovery,
)


def _is_fast_account_banned_progress(progress) -> bool:
    if not isinstance(progress, dict):
        return False
    if str(progress.get("group") or "").strip() not in _FAST_ACCOUNT_BANNED_TERMINAL_GROUPS:
        return False
    timing = progress.get("timing") if isinstance(progress.get("timing"), dict) else {}
    if timing.get("execution_started_at") is None or timing.get("finished_at") is None:
        return False
    try:
        elapsed = float(timing.get("execution_elapsed_seconds"))
    except (TypeError, ValueError):
        return False
    if not math.isfinite(elapsed) or elapsed < 0 or elapsed > _FAST_ACCOUNT_BANNED_MAX_EXECUTION_SECONDS:
        return False
    stages = timing.get("stages") if isinstance(timing.get("stages"), list) else []
    groups = {
        str(item.get("group") or "").strip()
        for item in stages
        if isinstance(item, dict)
    }
    return bool(
        groups
        and groups.intersection(_FAST_ACCOUNT_BANNED_TERMINAL_GROUPS)
        and groups.issubset(_FAST_ACCOUNT_BANNED_ALLOWED_GROUPS)
    )


_is_mailbox_local_pressure = _PROTOCOL_PRESSURE_POLICY.is_mailbox_local
_pressure_failure = _PROTOCOL_PRESSURE_POLICY.pressure_failure
_is_sms_provider_local_pressure = _PROTOCOL_PRESSURE_POLICY.is_sms_local
_is_main_chain_pressure_source = _PROTOCOL_PRESSURE_POLICY.main_chain_source
_is_rate_limited_failure = _PROTOCOL_PRESSURE_POLICY.is_rate_limited


def _transport_task_id(transport) -> str:
    config = getattr(transport, "config", None)
    if not isinstance(config, dict):
        return ""
    return str(config.get("sms_task_id") or config.get("run_id") or "").strip()


def _checkpoint_public_update(task_id, value) -> None:
    _CHECKPOINT_PUBLIC_STATE.update(task_id, value)


def _checkpoint_public_for(task_id):
    return _CHECKPOINT_PUBLIC_STATE.get(task_id)


def _checkpoint_context_for_entry(importer, settings, entry, task_id):
    return _phase1_checkpoint_hooks_ext.checkpoint_context_for_entry(
        importer,
        settings,
        entry,
        task_id,
        row_id_from_source=_mailbox_admin_ext.row_id_from_source,
    )


def _register_sms_transport(task_id, transport) -> None:
    _SMS_TRANSPORT_REGISTRY.register(task_id, transport)


def _transport_for_task(task_id):
    return _SMS_TRANSPORT_REGISTRY.get(task_id)


def _unregister_sms_transport(task_id, transport=None) -> None:
    _SMS_TRANSPORT_REGISTRY.unregister(task_id, transport)


def _safe_runtime_error(error):
    value = _module._safe(error) if hasattr(_module, "_safe") else str(error)
    return _SMS_PROVIDER_REGISTRY.safe_error(value)


def _isolated_sms_try_get(url, params, proxy, timeout=30):
    return _sms_runtime_ext.isolated_sms_get(
        url,
        params=params,
        proxy=proxy,
        timeout=timeout,
    )


def _isolated_fivesim_rest_get(self, path, timeout=15):
    return _sms_runtime_ext.isolated_sms_get(
        f"{self.BASE_URL}{path}",
        headers=self._headers(),
        proxy=str(getattr(self, "proxy", "") or ""),
        timeout=timeout,
        as_json=True,
    )


def _is_oauth_session_invalid_failure(result=None, error=""):
    if _auth_session_runtime_ext.is_session_invalid(error):
        return True
    value = result if isinstance(result, dict) else {}
    return any(
        _auth_session_runtime_ext.is_session_invalid(value.get(key))
        for key in ("error", "phase2_error", "technical_error")
    )


def _is_auth_session_reset_failure(result=None, error=""):
    if _is_oauth_session_invalid_failure(result, error):
        return True
    values = [error]
    if isinstance(result, dict):
        values.extend(result.get(key) for key in ("error", "phase2_error", "technical_error"))
    text = " ".join(str(value or "").lower() for value in values)
    return any(
        marker in text
        for marker in (
            "phone_flow_mfa_regressed",
            "phone_flow_login_regressed",
            "auth_context_page_mismatch",
            "auth_context_cookies_missing",
            "auth_context_task_mismatch",
            "auth_context_generation_mismatch",
            "invalid authorization step",
            "mfa_authorization_step_expired",
        )
    )


def _failure_secrets(importer=None, entry=None, settings=None):
    return _failure_secrets_ext.collect_failure_secrets(
        importer,
        entry,
        settings,
        mailbox_admin=_mailbox_admin_ext,
        sms_keys_from_config=_sms_keys_from_config,
    )


def _remember_task_failure(task_id, failure):
    public = _error_observability_ext.public_failure(failure)
    if not public:
        return None
    key = str(task_id or "").strip()
    if key:
        with _TASK_FAILURES_LOCK:
            _TASK_FAILURES[key] = public
    return public


def _known_task_failure(task_id):
    with _TASK_FAILURES_LOCK:
        value = _TASK_FAILURES.get(str(task_id or "").strip())
        return copy.deepcopy(value) if isinstance(value, dict) else None


def _clear_known_node_failure(task_id):
    key = str(task_id or "").strip()
    if not key:
        return
    with _TASK_FAILURES_LOCK:
        failure = _TASK_FAILURES.get(key)
        if isinstance(failure, dict) and failure.get("node_code") == "oauth_create_node":
            _TASK_FAILURES.pop(key, None)


def _classify_task_failure(task_id, result=None, error="", *, status="failed", secrets=()):
    existing = result.get("failure") if isinstance(result, dict) else None
    public = _error_observability_ext.public_failure(existing)
    if public is None:
        public = _error_observability_ext.classify_failure(
            result,
            error,
            _TASK_PROGRESS.progress(task_id),
            status=status,
            secrets=secrets,
        )
    return _remember_task_failure(task_id, public) or public


_TASK_ID_LOG_RE = re.compile(r"\b(T\d{3}(?:-[A-Za-z0-9]+)?)\b")
_PUBLIC_LOG_INPUT_LIMIT = 4096
_FAILURE_LOG_MARKERS = (
    "失败",
    "failed",
    "error",
    "exception",
    "rejected",
    "timeout",
    "no_numbers",
    "missing",
    "invalid",
    "denied",
    "拒绝",
    "失效",
    "异常",
)


def _diagnostic_friendly_log_message(value):
    redacted = _runtime._redact_text(value) if hasattr(_runtime, "_redact_text") else str(value)
    safe = _error_observability_ext.sanitize_failure_detail(
        _SMS_PROVIDER_REGISTRY.safe_error(redacted),
        limit=800,
    )
    if _error_observability_ext.is_success_diagnostic_trace(safe):
        return safe
    if re.search(r"\[[^\]]+/[a-z0-9_]+\]", safe, re.IGNORECASE):
        return safe
    lower = safe.lower()
    if not any(marker in lower for marker in _FAILURE_LOG_MARKERS):
        return _ORIGINAL_FRIENDLY_LOG_MESSAGE(safe)
    match = _TASK_ID_LOG_RE.search(safe)
    task_id = match.group(1) if match else _TASK_CONTEXT.get()
    if _error_observability_ext.is_node_retry_log(safe):
        return _error_observability_ext.format_node_retry_log(task_id, safe)
    failure = _known_task_failure(task_id)
    if failure is None:
        detail = safe[match.end():].strip(" :-") if match else safe
        detail = re.sub(r"^(?:失败|failed)\s*[:：-]?\s*", "", detail, flags=re.IGNORECASE)
        failure = _error_observability_ext.classify_failure(
            error=detail,
            progress=_TASK_PROGRESS.progress(task_id),
        )
    formatted = _error_observability_ext.format_failure_log(task_id, failure)
    return formatted or safe


def _int_value(value, default=0, minimum=None, maximum=None):
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = int(default)
    if minimum is not None:
        result = max(int(minimum), result)
    if maximum is not None:
        result = min(int(maximum), result)
    return result


def _safe_response_status(value) -> int | None:
    pending = [value]
    for _depth in range(2):
        next_pending = []
        for current in pending:
            if not isinstance(current, dict):
                continue
            for key in ("_status", "status_code", "http_status", "status"):
                try:
                    status = int(current.get(key))
                except (TypeError, ValueError):
                    continue
                if 100 <= status <= 599:
                    return status
            for key in ("error", "response"):
                if isinstance(current.get(key), dict):
                    next_pending.append(current[key])
        pending = next_pending
    return None


_migrate_email_timeout_config = _configuration_runtime_ext.make_email_timeout_migrator(
    strategy_version=_EMAIL_TIMEOUT_STRATEGY_VERSION,
    default_timeout=_EMAIL_CODE_TIMEOUT_DEFAULT,
)
_migrate_email_proxy_scope_config = _configuration_runtime_ext.make_email_proxy_scope_migrator(
    strategy_version=_EMAIL_PROXY_SCOPE_STRATEGY_VERSION,
)
_read_store_config = _configuration_runtime_ext.read_store_config
_atomic_write_private_json = _configuration_runtime_ext.atomic_write_private_json
_write_store_config = _configuration_runtime_ext.write_store_config


def _patched_config_load(self):
    return _config_patches_mod.patched_config_load(_host_module(), self)


def _patched_config_save(self, values):
    return _config_patches_mod.patched_config_save(_host_module(), self, values)


def _patched_task_config(self, settings, email, task_id, *, password=""):
    return _config_patches_mod.patched_task_config(_host_module(), self, settings, email, task_id, password=password)


def _set_current_task_stage(code):
    task_id = _TASK_CONTEXT.get()
    if task_id:
        _TASK_PROGRESS.set_stage(task_id, code)


def _note_stderr(where: str, exc: BaseException) -> None:
    """Last-resort stderr note for swallowed best-effort web-gui side paths."""
    try:
        print(f"[web_gui/{where}] {type(exc).__name__}", file=sys.stderr)
    except Exception:
        return


def _record_task_segment(task_id, code, elapsed_seconds):
    try:
        if task_id:
            _TASK_PROGRESS.record_segment(task_id, code, elapsed_seconds)
    except Exception as exc:
        # Segment telemetry must never change the task outcome.
        _note_stderr("record_task_segment", exc)


def _generate_sub2_oauth_session(config, *, upload_proxy="", log_fn=None):
    _set_current_task_stage("oauth_session")
    labels = {
        "remote_disconnected": "远端提前断开连接",
        "invalid_json_response": "服务端返回空或无效 JSON",
        "empty_response": "服务端未返回响应正文",
        "tls_connection_failed": "TLS 连接异常",
    }

    def on_retry(error_code, next_attempt, attempts, delay):
        cause = labels.get(error_code, "瞬时网络故障")
        _call_log(
            log_fn,
            f"  [建立 SUB2 OAuth 会话/oauth_session] {cause}（{error_code}），"
            f"{delay:.2f} 秒后重试 {next_attempt}/{attempts}",
            "warn",
        )

    stop_requested = config.get("_stop_requested") if isinstance(config, dict) else None
    return _runtime_policy_ext.call_with_transient_pre_auth_retry(
        lambda: _ORIGINAL_GENERATE_SUB2_OAUTH_SESSION(
            config,
            upload_proxy=upload_proxy,
            log_fn=log_fn,
        ),
        attempts=2,
        delay_seconds=0.25,
        stop_requested=stop_requested if callable(stop_requested) else None,
        on_retry=on_retry,
        retry_codes=frozenset(
            {
                "remote_disconnected",
                "invalid_json_response",
                "empty_response",
                "tls_connection_failed",
            }
        ),
    )


def _real_initiate_oauth(self, oauth_url):
    _set_current_task_stage("oauth_authorize_node")
    labels = {
        "remote_disconnected": "远端提前断开连接",
        "invalid_json_response": "OpenAI 返回空或无效 JSON",
        "empty_response": "OpenAI 未返回响应正文",
        "tls_connection_failed": "TLS 连接异常",
        "connection_timeout": "连接超时",
    }

    def on_retry(error_code, next_attempt, attempts, delay):
        cause = labels.get(error_code, "瞬时网络故障")
        _call_log(
            getattr(self, "log_fn", None),
            f"  [OpenAI OAuth 授权/oauth_authorize_node] {cause}（{error_code}），"
            f"保留 Node/SUB2 前置状态，{delay:.2f} 秒后重试 {next_attempt}/{attempts}",
            "warn",
        )

    config = getattr(self, "config", None)
    stop_requested = config.get("_stop_requested") if isinstance(config, dict) else None
    if isinstance(config, dict) and config.get("free_protocol_state_machine"):
        # Free owns session invalidation/rebuild.  The ordinary pre-auth retry
        # can replay a stale authorize context before Free has recorded the
        # first response, so it must perform one request only here.
        response = _with_transport_protocol_lease(
            self,
            lambda: _ORIGINAL_REAL_INITIATE_OAUTH(self, oauth_url),
        )
    else:
        response = _runtime_policy_ext.call_with_transient_pre_auth_retry(
            lambda: _with_transport_protocol_lease(
                self,
                lambda: _ORIGINAL_REAL_INITIATE_OAUTH(self, oauth_url),
            ),
            attempts=2,
            delay_seconds=0.25,
            stop_requested=stop_requested if callable(stop_requested) else None,
            on_retry=on_retry,
            retry_result=True,
        )
    _observe_auth_step(self, response, "oauth_authorize_node")
    return response


def _real_create_account_profile(self, name, birthdate):
    _set_current_task_stage("finalizing_profile")
    return _ORIGINAL_REAL_CREATE_ACCOUNT_PROFILE(self, name, birthdate)


def _real_send_email_otp(self, continue_url=""):
    _set_current_task_stage("email_code_waiting")
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        provider = getattr(self, "sentinel_provider", None)
        reset = getattr(provider, "reset", None)
        if callable(reset):
            reset("password_verify" if "password" in str(continue_url or "").lower() else "email_verification")
    return _with_transport_protocol_lease(
        self,
        lambda: _ORIGINAL_REAL_SEND_EMAIL_OTP(self, continue_url),
    )


def _real_send_passwordless_otp(self, continue_url=""):
    """Send the explicit one-time-code action from a login-password page.

    The Auth UI can return ``/api/accounts/email-otp/send`` as a continuation
    URL while the visible page is ``login_password``.  AutoRegister instead
    submits the page's passwordless action, which maps to the dedicated
    ``passwordless/send-otp`` endpoint.  Keep this adapter scoped to Free so
    ordinary SMS/OAuth callers retain the recovered transport behavior.
    """
    _set_current_task_stage("email_code_waiting")
    if not _is_free_transport(self):
        return _ORIGINAL_REAL_SEND_EMAIL_OTP(self, continue_url)

    provider = getattr(self, "sentinel_provider", None)
    reset = getattr(provider, "reset", None)
    if callable(reset):
        reset("password_verify")

    endpoint = f"{_codex_oauth_chain.AUTH}/api/accounts/passwordless/send-otp"
    # This action is rendered on ``/log-in/password``.  Reusing the generic
    # email-verification header flow produces a syntactically valid Sentinel
    # token for the wrong server-side transition and Auth responds with
    # ``invalid_state``.  Keep the request aligned with AutoRegister's
    # password-page contract: password_verify token + password-page referer.
    referer = f"{_codex_oauth_chain.AUTH}/log-in/password"

    def request() -> dict[str, object]:
        try:
            try:
                headers = self._headers("password_verify", referer)
            except Exception:
                headers = {
                    **getattr(_codex_oauth_chain, "PAGE_HEADERS", {}),
                    "referer": referer,
                    "sec-fetch-site": "same-origin",
                }
            response = self.session.post(
                endpoint,
                json={},
                headers=headers,
                allow_redirects=True,
                timeout=30,
            )
            parser = getattr(self, "_gptphone_json_response", None)
            if not callable(parser):
                parser = getattr(_codex_oauth_chain, "_json_response", None)
            data = parser(response) if callable(parser) else {}
            if not isinstance(data, dict):
                data = {}
        except Exception as exc:
            data = {
                "_status": 0,
                "error": f"passwordless_otp_send_failed: {type(exc).__name__}",
            }
        try:
            self.last_response = data
        except Exception as exc:
            _DIAGNOSTIC_STORE.record({
                "level": "warn",
                "outcome": "error",
                "chain": "ordinary",
                "workflow": "run",
                "driver": "sms_oauth",
                "node_code": "passwordless_otp_send",
                "node_label": "passwordless OTP 发送",
                "message": f"passwordless OTP 响应回写失败：{type(exc).__name__}",
            })
        if _codex_oauth_chain._is_success_response(data):
            _call_log(
                getattr(self, "log_fn", None),
                "  [Codex] 一次性验证码发送入口成功: /api/accounts/passwordless/send-otp",
                "info",
            )
        return data

    return _with_transport_protocol_lease(self, request)


def _real_visit_continue(self, continue_url, referer):
    return _with_transport_protocol_lease(
        self,
        lambda: _ORIGINAL_REAL_VISIT_CONTINUE(self, continue_url, referer),
    )


def _real_complete_chatgpt_callback(self, continue_url):
    return _with_transport_protocol_lease(
        self,
        lambda: _ORIGINAL_REAL_COMPLETE_CHATGPT_CALLBACK(self, continue_url),
    )


def _real_chatgpt_access_token(self) -> str:
    return _CHATGPT_PLAN_GATE.capture_access_token(self)


def _real_accept_consent(self, continue_url=""):
    _set_current_task_stage("finalizing_callback")
    return _with_transport_protocol_lease(
        self,
        lambda: _ORIGINAL_REAL_ACCEPT_CONSENT(self, continue_url),
    )


def _real_follow_continue_until_code(self, continue_url, oauth_params, *, _reauth=False):
    _set_current_task_stage("finalizing_callback")
    return _with_transport_protocol_lease(
        self,
        lambda: _ORIGINAL_REAL_FOLLOW_CONTINUE_UNTIL_CODE(
            self,
            continue_url,
            oauth_params,
            _reauth=_reauth,
        ),
    )


def _real_exchange_code(self, code, code_verifier, client_id, redirect_uri, account_email):
    _set_current_task_stage("finalizing_token")
    return _with_transport_protocol_lease(
        self,
        lambda: _ORIGINAL_REAL_EXCHANGE_CODE(
            self,
            code,
            code_verifier,
            client_id,
            redirect_uri,
            account_email,
        ),
    )


def _sub2_session_exchange(self, *, code, account_email):
    _set_current_task_stage("finalizing_token")
    return _ORIGINAL_SUB2_SESSION_EXCHANGE(self, code=code, account_email=account_email)


def _real_sub2_upload(self, *, credentials, email):
    _set_current_task_stage("finalizing_upload")
    return _sub2_upload_override_ext.upload_sub2_with_relogin_policy(
        self,
        credentials=credentials,
        email=email,
        original_upload=_ORIGINAL_REAL_SUB2_UPLOAD,
        identity_locations=_codex_oauth_chain._sub2_identity_locations,
        update_runtime=_sub2_update_runtime_ext,
        binding_runtime=_sub2_binding_runtime_ext,
        sub2_runtime=globals().get("_SUB2_RUNTIME"),
        direct_runtime=globals().get("_OPENAI_DIRECT_RUNTIME"),
        call_log=_call_log,
    )


def _patched_task_state(self, task_id: str, **values):
    return _importer_patches.patched_task_state(_host_module(), self, task_id, **values)


def _patched_chain_event(events, state, *, detail="", extra=None, log_fn=None, tag="info"):
    return _importer_patches.patched_chain_event(
        _host_module(), events, state, detail=detail, extra=extra, log_fn=log_fn, tag=tag,
    )


def _patched_chain_emit(log_fn, message, tag="info"):
    return _importer_patches.patched_chain_emit(_host_module(), log_fn, message, tag)


def _observe_runtime_fd_pressure(importer):
    return _importer_patches.observe_runtime_fd_pressure(_host_module(), importer)


def _notify_sms_balances(importer, statuses):
    return _importer_patches.notify_sms_balances(_host_module(), importer, statuses)


_notification_task_snapshot = _NOTIFICATION_LIFECYCLE.task_snapshot
_notification_aggregate = _NOTIFICATION_LIFECYCLE.aggregate
_notification_context_for = _NOTIFICATION_LIFECYCLE.context_for
_notification_watchdog = _NOTIFICATION_LIFECYCLE.watchdog
_begin_notification_run = _NOTIFICATION_LIFECYCLE.begin
_cancel_notification_run = _NOTIFICATION_LIFECYCLE.cancel


def _unfinished_batch_task_ids(importer):
    return _importer_patches.unfinished_batch_task_ids(_host_module(), importer)


def _reconcile_finished_batch(importer, context):
    return _importer_patches.reconcile_finished_batch(_host_module(), importer, context)


def _patched_pre_auth_session_retryable(result):
    return _importer_patches.patched_pre_auth_session_retryable(_host_module(), result)


def _patched_password_credentials_rejected(result):
    return _importer_patches.patched_password_credentials_rejected(_host_module(), result)


def _patched_persist_result(self, settings, task_id, entry, result, *, error="", status="failed"):
    return _importer_patches.patched_persist_result(
        _host_module(), self, settings, task_id, entry, result, error=error, status=status,
    )


def _patched_retire_after_failure(self, settings, pool, entry, task_id, result, error):
    return _importer_patches.patched_retire_after_failure(
        _host_module(), self, settings, pool, entry, task_id, result, error,
    )


def _patched_importer_start(self, settings):
    return _importer_patches.patched_importer_start(_host_module(), self, settings)


def _patched_importer_run_one(
    self,
    settings,
    ordinal,
    assigned_entry=None,
    assigned_task_id="",
):
    return _importer_patches.patched_importer_run_one(
        _host_module(), self, settings, ordinal, assigned_entry, assigned_task_id,
    )


def _patched_importer_stop(self):
    return _importer_patches.patched_importer_stop(_host_module(), self)


def _patched_importer_watch(self):
    return _importer_patches.patched_importer_watch(_host_module(), self)


def _phone_channel(value):
    return re.sub(r"[^a-z0-9_-]+", "", str(value or "").strip().lower())[:32]


def _response_phone_channel(response):
    if not isinstance(response, dict):
        return ""
    containers = [response]
    for key in ("page", "data", "error"):
        value = response.get(key)
        if isinstance(value, dict):
            containers.append(value)
    for value in containers:
        for key in (
            "channel",
            "verification_channel",
            "selected_channel",
            "delivery_channel",
        ):
            channel = _phone_channel(value.get(key))
            if channel:
                return channel
    text = json.dumps(response, ensure_ascii=True, default=str).lower()
    if any(
        marker in text
        for marker in (
            "whatsapp_required",
            "sms_not_available",
            "sms_unavailable",
            "switch_to_whatsapp",
            "switched_to_whatsapp",
        )
    ):
        return "whatsapp"
    return ""


def _reject_phone_channel_mismatch(response, requested_channel):
    requested = _phone_channel(requested_channel)
    actual = _response_phone_channel(response)
    if not requested or not actual or requested == actual:
        return response
    try:
        upstream_status = int(response.get("_status") or 0)
    except (TypeError, ValueError):
        upstream_status = 0
    return {
        **response,
        "_status": 409,
        "_upstream_status": upstream_status,
        "error": {
            "code": "phone_channel_mismatch",
            "message": (
                f"phone_channel_mismatch: requested={requested} actual={actual}"
            ),
        },
        "requested_channel": requested,
        "actual_channel": actual,
    }


_AUTH_SESSIONS = _auth_session_runtime_ext.AuthSessionRegistry()
_PHONE_BINDING_METRICS = _phone_binding_runtime_ext.PhoneBindingMetrics()


def _real_send_phone_number_otp(self, phone, channel="sms"):
    return _PHONE_BINDING_RUNTIME.send_phone_number_otp(self, phone, channel)


def _preflight_sms_phone_context(_adapter, task_id):
    """Prepare the ordinary SMS phone step without a ChatGPT plan gate.

    Free registration performs its own independent plan/eligibility lookup.
    The recovered SMS/OAuth workflow must keep the original phone allocation
    path and must not make a second session or accounts/check request here.
    """
    expected_task_id = str(task_id or "").strip()
    transport = _ACTIVE_SMS_TRANSPORT.get()
    if transport is not None and expected_task_id:
        if _transport_task_id(transport) != expected_task_id:
            transport = None
    if transport is None:
        transport = _transport_for_task(expected_task_id)
    if transport is None:
        _set_current_task_stage("phone_submitting")
        raise _codex_oauth_chain.CodexChainError(
            "auth_context_transport_missing: 当前任务没有可用的登录 Transport，已阻止申请手机号"
        )

    _set_current_task_stage("phone_submitting")
    try:
        context = _PHONE_BINDING_RUNTIME.prepare_phone_entry(
            transport,
            expected_task_id=expected_task_id,
        )
    except _auth_request_runtime_ext.AuthRequestContextError as exc:
        _auth_request_runtime_ext.invalidate_auth_session(
            transport,
            _AUTH_SESSIONS,
            f"{exc.code}: {exc}",
            stage="phone_submitting",
        )
        raise _codex_oauth_chain.CodexChainError(f"{exc.code}: {exc}") from exc

    _set_current_task_stage("phone_acquiring")
    return context


_SMS_WEB = _sms_web_ext.SmsWebIntegration(
    sms_runtime=_sms_runtime_ext,
    original_create_provider=_ORIGINAL_CREATE_PROVIDER,
    original_build_candidates=_ORIGINAL_SMART_BUILD_CANDIDATES,
    original_adapter_get_number=_ORIGINAL_SMS_ADAPTER_GET_NUMBER,
    original_adapter_wait_code=_ORIGINAL_SMS_ADAPTER_WAIT_CODE,
    original_adapter_complete=_ORIGINAL_SMS_ADAPTER_COMPLETE,
    original_adapter_cancel=_ORIGINAL_SMS_ADAPTER_CANCEL,
    original_classify_error=_ORIGINAL_SMART_CLASSIFY_ERROR,
    original_record_result=_ORIGINAL_SMART_RECORD_RESULT,
    original_send_phone_otp=_real_send_phone_number_otp,
    key_pool=_SMS_KEY_POOL,
    cost_ledger=_SMS_COST_LEDGER,
    phone_gate=_SMS_PHONE_GATE,
    route_policy=_SMS_ROUTE_POLICY,
    alerts=_SMS_ALERTS,
    task_progress=_TASK_PROGRESS,
    priority_countries=_SMS_PRIORITY_COUNTRIES,
    priority_routes=_SMS_PRIORITY_ROUTES,
    blocked_routes=_SMS_BLOCKED_ROUTES,
    min_price_default=_SMS_MIN_PRICE_DEFAULT,
    max_price_default=_SMS_MAX_PRICE_DEFAULT,
    max_price_hard_limit=_SMS_MAX_PRICE_HARD_LIMIT,
    sms_keys_from_config=lambda value: _sms_keys_from_config(value),
    as_enabled=_as_enabled,
    safe_error=_safe_runtime_error,
    provider_registry=_SMS_PROVIDER_REGISTRY,
    phone_context_preflight=_preflight_sms_phone_context,
    cleanup_queue=_SMS_CLEANUP_QUEUE,
    optimization_guard=_SMS_QUALITY_GUARD,
)
_AUTH_SESSIONS.set_cancel_sms(_SMS_WEB.cancel_active_lease)


def _persist_phone_risk_marker(task_id, email, reason_code, stage):
    normalized_stage = str(stage or "").strip()
    if normalized_stage not in {"phone_submitting", "sms_verifying"}:
        return
    transport = _transport_for_task(task_id)
    checkpoint_coordinator = globals().get("_PHASE1_CHECKPOINTS_COORDINATOR")
    if transport is not None and checkpoint_coordinator is not None:
        checkpoint_coordinator.delete(transport)
    if str(reason_code or "").strip().lower() in {
        "oauth_session_invalid",
        "auth_session_invalid",
    }:
        return
    marker = _PHONE_RISK_STORE.mark(
        email,
        reason_code=reason_code,
        stage=normalized_stage,
    )
    if not marker.get("active"):
        return
    config = getattr(transport, "config", None)
    if isinstance(config, dict):
        config["_phone_risk_retry"] = True
        config["_phone_risk_reason_code"] = str(
            marker.get("reason_code") or "oauth_session_invalid"
        )


_AUTH_SESSIONS.set_invalidation_callback(_persist_phone_risk_marker)
_PHASE1_CHECKPOINTS_COORDINATOR = _phase1_checkpoint_hooks_ext.CheckpointCoordinator(
    _PHASE1_CHECKPOINTS,
    context_getter=lambda: _CHECKPOINT_CONTEXT.get(),
    generation_getter=lambda task_id: _manual_task_generation(task_id),
    public_update=_checkpoint_public_update,
)
_CHECKPOINT_AUTH_HOOKS = _phase1_checkpoint_hooks_ext.CheckpointAuthHooks(
    original_import=_ORIGINAL_REAL_IMPORT_PHASE1_SESSION,
    run_mode=_RUN_MODE_CONTEXT.get,
    session_invalid=_auth_session_runtime_ext.is_session_invalid,
    success=_codex_oauth_chain._is_success_response,
    coordinator=_PHASE1_CHECKPOINTS_COORDINATOR,
)
_TOTP_PATCHES = _chatgpt_totp_ext.build_chatgpt_totp_patches(
    runtime_module=_runtime,
    codex_oauth_chain=_codex_oauth_chain,
    original_entries_unlocked=_ORIGINAL_POOL_ENTRIES_UNLOCKED,
    original_outlook_otp_provider=_ORIGINAL_OUTLOOK_OTP_PROVIDER,
    original_account_label=_ORIGINAL_ACCOUNT_LABEL,
    original_verify_password=_ORIGINAL_REAL_VERIFY_PASSWORD,
    original_send_mfa_otp=_ORIGINAL_REAL_SEND_MFA_OTP,
    original_verify_mfa_otp=_ORIGINAL_REAL_VERIFY_MFA_OTP,
    parse_oauth_mailbox_row=_mailbox_admin_ext.parse_oauth_mailbox_row,
)


def _real_transport_init(
    self,
    config,
    *,
    oauth_params,
    proxy="",
    sentinel_provider,
    device_id="",
    log_fn=None,
):
    return _codex_patches.real_transport_init(
        _host_module(), self, config,
        oauth_params=oauth_params, proxy=proxy,
        sentinel_provider=sentinel_provider, device_id=device_id, log_fn=log_fn,
    )


def _is_free_transport(self) -> bool:
    return _codex_patches.is_free_transport(_host_module(), self)


def _real_new_session(self, impersonate="chrome"):
    return _codex_patches.real_new_session(_host_module(), self, impersonate)


def _real_headers(self, flow, referer):
    headers = _ORIGINAL_REAL_HEADERS(self, flow, referer)
    _chatgpt_totp_ext.refresh_transport_totp_payload(self, flow)
    return _auth_request_runtime_ext.request_headers(self, headers)


_checkpoint_save_after_auth = _CHECKPOINT_AUTH_HOOKS.save_after_auth
_checkpoint_delete_after_auth = _CHECKPOINT_AUTH_HOOKS.delete_after_auth
_real_import_phase1_session = _CHECKPOINT_AUTH_HOOKS.import_phase1_session


def _observe_protocol_request_activity():
    return _codex_patches.observe_protocol_request_activity(_host_module())


_PROTOCOL_COORDINATOR = _sms_runtime_ext.TransportProtocolCoordinator(
    gate=lambda: globals().get("_PROTOCOL_GATE"),
    inflight_pipeline=_inflight_pipeline_runtime_ext,
    success_fn=_codex_oauth_chain._is_success_response,
    task_id_getter=_transport_task_id,
    task_context_getter=_TASK_CONTEXT.get,
    main_chain_source=_is_main_chain_pressure_source,
    rate_limited_failure=_is_rate_limited_failure,
    report_task_pressure=_report_task_pressure,
    connectivity_getter=lambda: _OPENAI_CONNECTIVITY,
    inflight_gate_getter=lambda: globals().get("_CURRENT_INFLIGHT_GATE"),
    activity_observer=_observe_protocol_request_activity,
    segment_observer=_record_task_segment,
)
_staged_transport_pipeline = _PROTOCOL_COORDINATOR.staged
_transport_protocol_proxy = _PROTOCOL_COORDINATOR.proxy
_record_transport_protocol_result = _PROTOCOL_COORDINATOR.record_result
_with_transport_protocol_lease = _PROTOCOL_COORDINATOR.call
_PHONE_BINDING_RUNTIME = _phone_binding_runtime_ext.PhoneBindingRuntime(
    auth_origin=_codex_oauth_chain.AUTH,
    json_headers=_codex_oauth_chain.JSON_HEADERS,
    phone_for_openai=_codex_oauth_chain._phone_for_openai,
    json_response=_codex_oauth_chain._json_response,
    codex_error=_codex_oauth_chain.CodexChainError,
    auth_requests=_auth_request_runtime_ext,
    auth_sessions=_auth_session_runtime_ext,
    registry=_AUTH_SESSIONS,
    with_protocol_lease=_with_transport_protocol_lease,
    protocol_coordinator=_PROTOCOL_COORDINATOR,
    record_segment=_record_task_segment,
    task_id_for=_transport_task_id,
    current_task_id=lambda: _TASK_CONTEXT.get(),
    set_stage=_set_current_task_stage,
    normalize_channel=_phone_channel,
    reject_channel_mismatch=_reject_phone_channel_mismatch,
    sanitize_error=_error_observability_ext.sanitize_failure_detail,
    metrics=_PHONE_BINDING_METRICS,
)
_CHATGPT_PLAN_GATE = _chatgpt_plan_gate_ext.ChatGptPlanGate(
    chatgpt_origin=_codex_oauth_chain.CHATGPT,
    json_response=_codex_oauth_chain._json_response,
    clean=_codex_oauth_chain._clean,
    with_protocol_lease=_with_transport_protocol_lease,
    request_headers=_auth_request_runtime_ext.request_headers,
    active_transport=_ACTIVE_SMS_TRANSPORT.get,
    transport_for_task=_transport_for_task,
    transport_task_id=_transport_task_id,
    prepare_phone_entry=_PHONE_BINDING_RUNTIME.prepare_phone_entry,
    set_stage=_set_current_task_stage,
    auth_context_error=_auth_request_runtime_ext.AuthRequestContextError,
    invalidate_auth_session=lambda transport, error: _auth_request_runtime_ext.invalidate_auth_session(
        transport,
        _AUTH_SESSIONS,
        f"{error.code}: {error}",
        stage="phone_submitting",
    ),
    chain_error=_codex_oauth_chain.CodexChainError,
)


def _real_post_auth_json(self, path, payload, *, flow, referer, timeout=30):
    return _codex_patches.real_post_auth_json(
        _host_module(), self, path, payload, flow=flow, referer=referer, timeout=timeout,
    )


def _real_post_auth_json_without_sentinel(self, path, payload, *, flow, referer, timeout=30):
    return _codex_patches.real_post_auth_json_without_sentinel(
        _host_module(), self, path, payload, flow=flow, referer=referer, timeout=timeout,
    )


def _observe_auth_step(transport, response, stage):
    return _codex_patches.observe_auth_step(_host_module(), transport, response, stage)


def _real_submit_email_identifier(self, email):
    return _codex_patches.real_submit_email_identifier(_host_module(), self, email)


def _real_verify_password(self, password):
    return _codex_patches.real_verify_password(_host_module(), self, password)


def _manual_totp_fallback(self, response):
    return _codex_patches.manual_totp_fallback(_host_module(), self, response)


def _real_verify_mfa_otp(self, code):
    return _codex_patches.real_verify_mfa_otp(_host_module(), self, code)


def _real_send_mfa_otp(self, continue_url=""):
    return _codex_patches.real_send_mfa_otp(_host_module(), self, continue_url)


# The relogin stop provider keeps one class object across both modules so
# ``isinstance`` checks against either name keep working.
_ReloginPhoneOtpProvider = _codex_patches.ReloginPhoneOtpProvider


def _run_codex_after_registration(
    *,
    oauth_url,
    code_verifier="",
    account_email="",
    password="",
    phase1_register=None,
    phase1_response=None,
    phase1_continue_url="",
    sms_provider=None,
    config=None,
    proxy="",
    email_proxy="",
    upload_proxy="",
    log_fn=None,
    mode="",
    local_oauth_client_id="app_EMoamEEZ73f0CkXaXp7hrann",
    local_oauth_redirect_uri="http://localhost:1455/auth/callback",
    oauth_provider="",
    oauth_session_id="",
    oauth_state="",
    upload_target_name="local",
    node_result=None,
    runtime_context_expected=None,
    runtime_context_strict=False,
    transport=None,
    sentinel_provider=None,
    email_otp_provider=None,
    phone_otp_provider=None,
):
    return _codex_patches.run_codex_after_registration(
        _host_module(),
        oauth_url=oauth_url,
        code_verifier=code_verifier,
        account_email=account_email,
        password=password,
        phase1_register=phase1_register,
        phase1_response=phase1_response,
        phase1_continue_url=phase1_continue_url,
        sms_provider=sms_provider,
        config=config,
        proxy=proxy,
        email_proxy=email_proxy,
        upload_proxy=upload_proxy,
        log_fn=log_fn,
        mode=mode,
        local_oauth_client_id=local_oauth_client_id,
        local_oauth_redirect_uri=local_oauth_redirect_uri,
        oauth_provider=oauth_provider,
        oauth_session_id=oauth_session_id,
        oauth_state=oauth_state,
        upload_target_name=upload_target_name,
        node_result=node_result,
        runtime_context_expected=runtime_context_expected,
        runtime_context_strict=runtime_context_strict,
        transport=transport,
        sentinel_provider=sentinel_provider,
        email_otp_provider=email_otp_provider,
        phone_otp_provider=phone_otp_provider,
    )


def _mailbox_entries_for_run_selection(pool_self):
    entries, errors = _TOTP_PATCHES.entries_unlocked(pool_self)
    if not _MAILBOX_LEASE_FILTER_ACTIVE.get():
        return entries, errors
    selected = _MAILBOX_RUN_SELECTION.get()
    if selected:
        selected_by_public_line: dict[int, set[str]] = {}
        for row_id, line_no in selected:
            selected_by_public_line.setdefault(line_no, set()).add(row_id)

        selected_physical_lines = set()
        public_line_no = 0
        raw_lines = Path(pool_self.pool_path).read_text(encoding="utf-8-sig").splitlines()
        for physical_line_no, raw in enumerate(raw_lines, start=1):
            source_row = raw.strip()
            if not source_row:
                continue
            public_line_no += 1
            expected_row_ids = selected_by_public_line.get(public_line_no)
            if not expected_row_ids:
                continue
            actual_row_id = _mailbox_admin_ext.row_id_from_source(source_row)
            if any(hmac.compare_digest(actual_row_id, row_id) for row_id in expected_row_ids):
                selected_physical_lines.add(physical_line_no)
        entries = [
            entry
            for entry in entries
            if int(getattr(entry, "line_no", 0) or 0) in selected_physical_lines
        ]
    elif _MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.get():
        entries = _MAILBOX_NEXT_BATCH_PRIORITY.prioritize(entries)
    return entries, errors


def _mailbox_lease_for_run_selection(self, *, lease_seconds=1800):
    token = _MAILBOX_LEASE_FILTER_ACTIVE.set(True)
    try:
        entry = _ORIGINAL_POOL_LEASE(self, lease_seconds=lease_seconds)
        if _MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.get():
            _MAILBOX_NEXT_BATCH_PRIORITY.consume(getattr(entry, "source_row", ""))
        return entry
    finally:
        _MAILBOX_LEASE_FILTER_ACTIVE.reset(token)


def _reserve_mailbox_batch(
    pool,
    target,
    *,
    lease_seconds=3600,
    before_reserve=None,
    after_reserve=None,
    on_reserve_failed=None,
    lease_owner_batch_id="",
):
    def committed(entries):
        if callable(after_reserve):
            after_reserve(entries)
        if _MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.get():
            for entry in entries:
                try:
                    _MAILBOX_NEXT_BATCH_PRIORITY.consume(
                        getattr(entry, "source_row", "")
                    )
                except Exception as exc:
                    # Priority consumption is optional bookkeeping for the reservation.
                    _note_stderr("priority_consume", exc)

    entries = _mailbox_priority_runtime_ext.reserve_available_batch(
        pool,
        target,
        lease_seconds=lease_seconds,
        before_reserve=before_reserve,
        after_reserve=committed,
        on_reserve_failed=on_reserve_failed,
        mailbox_error_type=_runtime.MailboxPoolError,
        lease_owner_batch_id=lease_owner_batch_id,
    )
    return entries


def _release_recovered_batch_leases(
    batch_id,
    members,
    *,
    pool_path=None,
    state_path=None,
):
    pool = _runtime.MailboxPool(
        Path(pool_path) if pool_path else _RUNTIME_DATA_DIR / "mailbox_pool.txt",
        Path(state_path) if state_path else _RUNTIME_DATA_DIR / "mailbox_pool_state.json",
    )
    return _mailbox_priority_runtime_ext.release_owned_batch_leases(
        pool,
        batch_id,
        members,
    )


def _mailbox_restore_preserving_relogin(self, entry, *, reason="manual_restore"):
    if _RUN_MODE_CONTEXT.get() == "relogin":
        return True
    return _ORIGINAL_POOL_RESTORE_ENTRY(self, entry, reason=reason)


def _sms_build_candidates(self, raw_rows, now, allowed_countries, blocked_countries):
    return _SMS_WEB.smart_build_candidates(self, raw_rows, now, allowed_countries, blocked_countries)


def _sms_adapter_get_number(self, **kwargs):
    return _SMS_WEB.adapter_get_number(self, **kwargs)


def _sms_adapter_mark_ready(self, lease):
    return _SMS_WEB.adapter_mark_ready(self, lease)


def _sms_adapter_wait_code(self, lease, timeout=180):
    return _SMS_WEB.adapter_wait_code(self, lease, timeout=timeout)


def _sms_adapter_complete(self, lease):
    return _SMS_WEB.adapter_complete(self, lease)


def _sms_adapter_cancel(self, lease, reason=""):
    return _SMS_WEB.adapter_cancel(self, lease, reason=reason)


def _sms_record_result(self, candidate, ok, error=""):
    return _SMS_WEB.smart_record_result(self, candidate, ok, error)


def _sms_route_limit(self, candidate, stat, now):
    return _SMS_WEB.route_limit(self, candidate, stat, now)


def _sms_send_phone_number_otp(self, phone, channel="sms"):
    return _SMS_WEB.send_phone_number_otp(self, phone, channel)


def _phone_otp_was_accepted(response):
    if not _codex_oauth_chain._is_success_response(response):
        return False
    page_type = _auth_request_runtime_ext.normalize_page_type(
        _codex_oauth_chain._page_type(response)
    )
    return page_type not in (
        _auth_request_runtime_ext.PHONE_PAGE_TYPES
        | _auth_request_runtime_ext.MFA_PAGE_TYPES
        | _auth_request_runtime_ext.LOGIN_PAGE_TYPES
    )


def _real_verify_phone_otp(self, code):
    try:
        response = self._post_auth_json(
            "/api/accounts/phone-otp/validate",
            {"code": code},
            flow="authorize_continue",
            referer=f"{_codex_oauth_chain.AUTH}/phone-verification",
            timeout=30,
        )
    except Exception as exc:
        _SMS_WEB.ensure_account_active(self, exc)
        raise
    response = _SMS_WEB.ensure_account_active(self, response)
    if _auth_session_runtime_ext.is_session_invalid(response):
        _checkpoint_delete_after_auth(self)
        task_id = _transport_task_id(self)
        state = _AUTH_SESSIONS.get(task_id) if task_id else None
        if state is None or not state.invalid:
            _auth_request_runtime_ext.invalidate_auth_session(
                self,
                _AUTH_SESSIONS,
                response,
                stage="sms_verifying",
            )
        raise _codex_oauth_chain.CodexChainError(
            "oauth_session_invalid: OpenAI 登录会话已失效"
        )
    _observe_auth_step(self, response, "sms_verifying")
    if _phone_otp_was_accepted(response):
        email = str(
            getattr(self, "account_email", "")
            or (getattr(self, "config", None) or {}).get("_auth_account_email")
            or ""
        ).strip().lower()
        _PHONE_RISK_STORE.clear(email)
        config = getattr(self, "config", None)
        if isinstance(config, dict):
            config.pop("_phone_risk_retry", None)
            config.pop("_phone_risk_reason_code", None)
        _checkpoint_delete_after_auth(self)
    return response


def _call_log(log_fn, message, level="info"):
    if not callable(log_fn):
        return
    try:
        log_fn(message, level)
    except TypeError as exc:
        if "positional argument" not in str(exc) and "arguments" not in str(exc):
            raise
        log_fn(message)


def _retained_gui_log_add(self, message, level="info"):
    diagnostic_id = ""
    try:
        raw = str(message or "")
        match = re.search(r"\[([^\]/]{1,160})/([^\]/]{1,160})(?:/([^\]]{1,160}))?\]", raw)
        task_id = ""
        node_label = ""
        node_code = ""
        if match:
            first, second, third = match.groups()
            if first.startswith("T"):
                task_id = first
                node_label, node_code = second, third or second
            else:
                node_label, node_code = second, third or second
        task_match = _TASK_ID_LOG_RE.search(raw)
        task_id = task_id or (task_match.group(1) if task_match else "")
        diagnostic_id = _DIAGNOSTIC_STORE.record({
            "level": level,
            "outcome": "error" if str(level).lower() in {"error", "danger"} else str(level or "info"),
            "message": raw,
            "task_id": task_id,
            "node_code": node_code,
            "node_label": node_label,
            "chain": "ordinary",
            "workflow": "run",
            "driver": "sms_oauth",
            "stage_group": node_code,
        })
    except Exception:
        diagnostic_id = ""
    if diagnostic_id and str(level).lower() in {"error", "danger"} and "日志 ID" not in str(message):
        message = f"{message}（日志 ID: {diagnostic_id}）"
    return _GUI_LOG_RETENTION.add(
        self,
        message,
        level,
        safe_fn=_diagnostic_friendly_log_message,
        max_items=_module.MAX_LOGS,
    )


def _retained_gui_log_snapshot(self):
    return _GUI_LOG_RETENTION.snapshot(self)


def _mailbox_url_snapshot(self):
    try:
        selection = _mailbox_otp_service_ext.runtime_snapshot(self)
    except _mailbox_url_runtime_ext.MailboxUrlError as exc:
        raise _runtime.MailboxPoolError(str(exc)) from exc
    fingerprint = selection.fingerprint
    if selection.reason in {
        "mailbox_baseline_code_fallback",
        "mailbox_final_baseline_code_fallback",
    }:
        fingerprint = f"baseline-fallback:{fingerprint}"
    snapshot = _runtime.MailboxSnapshot(
        hash=fingerprint,
        code=selection.code,
        received_at=selection.received_at,
    )
    self.last_snapshot = snapshot
    return snapshot


def _mailbox_url_same_as_baseline(current, baseline):
    if str(getattr(current, "hash", "") or "").startswith("baseline-fallback:"):
        return False
    return _ORIGINAL_MAILBOX_URL_SAME_AS_BASELINE(current, baseline)


def _url_mailbox_mark_sent(self):
    result = _ORIGINAL_URL_MAILBOX_MARK_SENT(self)
    if getattr(self, "_gptphone_email_code_deadline", None) is None:
        timeout = _int_value(getattr(self, "timeout", 90), 90, minimum=1, maximum=600)
        self._gptphone_email_code_deadline = time.monotonic() + timeout
    provider = self.provider
    # Give the shared mailbox service stable ordinary-flow context without
    # changing the recovered provider constructor signature.
    setattr(provider, "task_id", str(getattr(self, "task_id", "") or _TASK_CONTEXT.get() or ""))
    setattr(provider, "batch_id", str(getattr(self, "batch_id", "") or ""))
    setattr(provider, "workflow", "ordinary_run")
    setattr(provider, "driver", "sms_oauth")
    setattr(provider, "sample_scope", "ordinary")
    _mailbox_otp_service_ext.configure_runtime_request(
        provider,
        max_poll_attempts=_int_value(getattr(self, "max_attempts", 30), 30, minimum=1, maximum=1000),
    )
    _mailbox_otp_service_ext.begin_runtime_request(provider)
    return result


def _automatic_url_mailbox_wait_code(self, email):
    entry = getattr(self, "entry", None)
    if (
        getattr(entry, "oauth_client_id", "") == "chatgpt_totp"
        and getattr(entry, "oauth_refresh_token", "")
        and getattr(self, "_chatgpt_email_otp_verified", False)
    ):
        code = _chatgpt_totp_ext.totp_code(getattr(entry, "oauth_refresh_token", ""))
        _mailbox_otp_service_ext.finish_runtime_request(getattr(self, "provider", None))
        _call_log(getattr(self, "log_fn", None), "  [Codex] 已根据 2FA 密钥生成临时验证码", "info")
        return code
    provider = getattr(self, "provider", None)
    max_poll_attempts = _int_value(
        getattr(self, "max_attempts", 30),
        30,
        minimum=1,
        maximum=1000,
    )
    timeout_seconds = _int_value(getattr(self, "timeout", 90), 90, minimum=1, maximum=600)
    interval_seconds = _int_value(getattr(self, "interval", 5), 5, minimum=1, maximum=60)
    deadline = getattr(self, "_gptphone_email_code_deadline", None)
    code = _mailbox_otp_service_ext.legacy_wait_code(
        self,
        email,
        wait_fn=_ORIGINAL_URL_MAILBOX_WAIT_CODE,
        max_poll_attempts=max_poll_attempts,
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
        deadline_monotonic=float(deadline) if deadline is not None else None,
    )
    if code:
        setattr(self, "_chatgpt_email_otp_verified", True)
        if (
            getattr(entry, "oauth_client_id", "") == "chatgpt_totp"
            and getattr(entry, "oauth_refresh_token", "")
        ):
            _MAILBOX_TOTP_SECRET_CONTEXT.set(str(getattr(entry, "oauth_refresh_token", "") or ""))
    return code


def _automatic_outlook_mailbox_wait_code(self, email):
    used_codes = set(getattr(self, "_gptphone_used_email_otp_codes", ()) or ())
    poller = getattr(self, "poller", None)
    original_poll_code = getattr(poller, "poll_code", None)
    restore_instance_override = False
    previous_instance_override = None

    if used_codes and callable(original_poll_code):
        poller_vars = getattr(poller, "__dict__", {})
        restore_instance_override = "poll_code" in poller_vars
        previous_instance_override = poller_vars.get("poll_code")

        def poll_distinct_code(*args, **kwargs):
            excluded = set(kwargs.get("exclude_codes") or ())
            excluded.update(used_codes)
            kwargs["exclude_codes"] = excluded
            return original_poll_code(*args, **kwargs)

        poller.poll_code = poll_distinct_code
        _call_log(
            getattr(self, "log_fn", None),
            "  [邮箱取码诊断/email_code_waiting] 重发后已排除本任务上一轮验证码，等待新邮件",
            "info",
        )

    try:
        code = _ORIGINAL_OUTLOOK_OTP_WAIT_CODE(self, email)
    finally:
        if used_codes and callable(original_poll_code):
            if restore_instance_override:
                poller.poll_code = previous_instance_override
            else:
                del poller.poll_code

    normalized = str(code or "").strip()
    if normalized:
        used_codes.add(normalized)
        self._gptphone_used_email_otp_codes = used_codes
    return code


def _manual_task_generation(task_id):
    free_manager = globals().get("_FREE_REGISTER")
    if free_manager is not None:
        try:
            task = next(
                item for item in free_manager.public_tasks()
                if str(item.get("task_id") or "") == str(task_id or "").strip()
            )
            return int(free_manager._manual_generation(str(task_id)))
        except (StopIteration, TypeError, ValueError, AttributeError):
            pass
    return _oauth_mfa_runtime_ext.task_generation(task_id, _AUTH_SESSIONS.public_snapshot)
_manual_stop_event = _oauth_mfa_runtime_ext.provider_stop_event


def _submit_manual_code(self, task_id, code):
    task = str(task_id or "").strip()
    prompt = _MANUAL_VERIFICATION.public(task)
    if not isinstance(prompt, dict) or not prompt.get("input_kind"):
        raise _runtime.MailboxPoolError("当前任务没有等待人工验证码")
    try:
        _MANUAL_VERIFICATION.submit(
            task,
            prompt.get("input_kind"),
            prompt.get("generation"),
            code,
        )
    except _manual_verification_runtime_ext.ManualVerificationError as exc:
        raise _runtime.MailboxPoolError(str(exc)) from exc


def _manual_email_wait(provider, email, automatic_wait, *, parser_provider=None):
    # The recovered call sites (and older integrations) use the historic
    # three-argument helper signature.  Infer the URL parser owner from the
    # wrapper provider when the optional context is omitted so those callers
    # remain compatible while still recording parser samples.
    if parser_provider is None:
        parser_provider = getattr(provider, "provider", None)
    task_id = str(_TASK_CONTEXT.get() or getattr(provider, "task_id", "") or "").strip()
    if not task_id:
        return automatic_wait()
    timeout = _int_value(getattr(provider, "timeout", 90), 90, minimum=1, maximum=600)
    return _manual_verification_runtime_ext.wait_with_manual_fallback(
        automatic_wait,
        broker=_MANUAL_VERIFICATION,
        task_id=task_id,
        input_kind="email_otp",
        generation=_manual_task_generation(task_id),
        stop_event=_manual_stop_event(provider),
        automatic_timeout_seconds=timeout,
        manual_timeout_seconds=_manual_verification_runtime_ext.DEFAULT_WINDOW_SECONDS,
        on_automatic_unmatched=(
            lambda cause: _mailbox_otp_service_ext.record_runtime_parser_sample(
                parser_provider,
                cause,
            )
        ) if parser_provider is not None else None,
        on_manual_selected=lambda: _call_log(
            getattr(provider, "log_fn", None),
            "  [人工邮箱验证码/email_code_waiting] 已接收当前任务的人工验证码",
            "info",
        ),
    )


def _url_mailbox_wait_code(self, email):
    _oauth_mfa_runtime_ext.remember_provider_totp_secret(self, _TASK_TOTP_SECRETS, current_task_get=_TASK_CONTEXT.get)
    return _manual_email_wait(
        self,
        email,
        lambda: _automatic_url_mailbox_wait_code(self, email),
    )


def _outlook_mailbox_wait_code(self, email):
    _oauth_mfa_runtime_ext.remember_provider_totp_secret(self, _TASK_TOTP_SECRETS, current_task_get=_TASK_CONTEXT.get)
    return _manual_email_wait(
        self,
        email,
        lambda: _automatic_outlook_mailbox_wait_code(self, email),
    )


def _gptmail_mailbox_wait_code(self, email):
    return _manual_email_wait(
        self,
        email,
        lambda: _ORIGINAL_GPTMAIL_OTP_WAIT_CODE(self, email),
    )


def _mfa_factor_id_from_response(response):
    return _mfa_retry_runtime_ext.mfa_factor_id_from_response(
        response,
        continue_url_fn=_codex_oauth_chain._continue_url,
    )


_EMAIL_OTP_MFA_RUNTIME = _oauth_mfa_runtime_ext.EmailOtpMfaRuntime(
    secret_get=lambda transport=None: _oauth_mfa_runtime_ext.resolve_totp_secret(
        transport,
        context_secret_get=lambda: _MAILBOX_TOTP_SECRET_CONTEXT.get(""),
        task_secret_get=_TASK_TOTP_SECRETS.get,
        task_id_get=lambda current: _transport_task_id(current) or _TASK_CONTEXT.get(),
    ),
    # Keep the task registry through a bounded MFA retry; task finalization clears it.
    secret_clear=lambda *_args: _MAILBOX_TOTP_SECRET_CONTEXT.set(""),
    checkpoint_save=lambda transport, response: _checkpoint_save_after_auth(
        transport, response
    ),
    response_error_code=lambda response: _mfa_retry_runtime_ext.response_error_code(
        response
    ),
    page_type=lambda response: _codex_oauth_chain._page_type(response),
    observe_auth_step=lambda transport, response, stage: _observe_auth_step(
        transport, response, stage
    ),
    continue_if_needed=lambda *args, **kwargs: _auth_challenge_runtime_ext.continue_if_needed(
        *args, **kwargs
    ),
    factor_id=lambda response: _mfa_factor_id_from_response(response),
    verify_totp=lambda *args, **kwargs: _mfa_retry_runtime_ext.verify_email_totp_with_one_window_retry(
        *args, **kwargs
    ),
    verify_mfa=lambda *args, **kwargs: _TOTP_PATCHES.verify_mfa_otp(*args, **kwargs),
    manual_fallback=lambda transport, response: _manual_totp_fallback(transport, response),
    session_invalid=lambda response: _auth_session_runtime_ext.is_session_invalid(
        response
    ),
    stop_event=lambda transport: _manual_stop_event(transport),
    requires_secret=lambda transport: _oauth_mfa_runtime_ext.transport_expects_totp(transport, _TASK_TOTP_SECRETS, transport_task_id_get=_transport_task_id, current_task_get=_TASK_CONTEXT.get),
)


def _real_verify_email_otp(self, code):
    return _EMAIL_OTP_MFA_RUNTIME.verify(self, code, _ORIGINAL_REAL_VERIFY_EMAIL_OTP)


def _real_verify_signup_email_otp(self, code):
    return _EMAIL_OTP_MFA_RUNTIME.verify(
        self,
        code,
        _ORIGINAL_REAL_VERIFY_SIGNUP_EMAIL_OTP,
    )


_clamp_sms_max_price = _SMS_WEB.clamp_max_price
_configure_sms_pool = _SMS_WEB.configure_pool
_preflight_sms_pool = _SMS_WEB.preflight_pool


_runtime.MailboxPool._entries_unlocked = _mailbox_entries_for_run_selection
_runtime.MailboxPool.lease = _mailbox_lease_for_run_selection
_runtime.MailboxPool.restore_entry = _mailbox_restore_preserving_relogin
_runtime.MailboxPool.remove_entry = _mailbox_retention_ext.preserve_consumed_entry
_runtime.ManualMailboxPool.remove_entry = _mailbox_retention_ext.preserve_consumed_entry
_runtime.GptMailOtpProvider.wait_code = _gptmail_mailbox_wait_code
_ORIGINAL_OUTLOOK_OTP_PROVIDER.wait_code = _outlook_mailbox_wait_code
_runtime.OutlookMailboxOtpProvider = _TOTP_PATCHES.outlook_otp_provider
_runtime.MailboxUrlCodeProvider.snapshot = _mailbox_url_snapshot
_runtime.MailboxUrlCodeProvider._same_as_baseline = staticmethod(_mailbox_url_same_as_baseline)
_runtime.UrlMailboxOtpProvider.mark_sent = _url_mailbox_mark_sent
_runtime.UrlMailboxOtpProvider.wait_code = _url_mailbox_wait_code
_runtime.EmailAuthImporter._account_label = _TOTP_PATCHES.account_label
_runtime.EmailAuthImporter._persist_result = _patched_persist_result
_runtime.EmailAuthImporter._retire_after_failure = _patched_retire_after_failure
_runtime.EmailAuthImporter._task_config = _patched_task_config
_runtime.EmailAuthImporter._task_state = _patched_task_state
_runtime.EmailAuthImporter.start = _patched_importer_start
_runtime.EmailAuthImporter._run_one = _patched_importer_run_one
_runtime.EmailAuthImporter.stop = _patched_importer_stop
_runtime.EmailAuthImporter.submit_manual_code = _submit_manual_code
_runtime.EmailAuthImporter._watch = _patched_importer_watch
_runtime.EmailAuthImporter._pre_auth_session_retryable = staticmethod(_patched_pre_auth_session_retryable)
_runtime.EmailAuthImporter._password_credentials_rejected = staticmethod(
    _patched_password_credentials_rejected
)
_runtime._generate_sub2_oauth_session = _generate_sub2_oauth_session
_runtime.run_codex_after_registration = _run_codex_after_registration
_runtime._friendly_log_message = _diagnostic_friendly_log_message
# The recovered web_gui._safe function resolves this module-global by name;
# update that reference as well so its log panel cannot retain the old mapper.
_module._friendly_log_message = _diagnostic_friendly_log_message
_runtime.ImporterConfigStore.load = _patched_config_load
_runtime.ImporterConfigStore.save = _patched_config_save
_module.GuiLog.add = _retained_gui_log_add
_module.GuiLog.snapshot = _retained_gui_log_snapshot
_runtime.create_provider = _SMS_WEB.create_provider
_sms_providers.create_provider = _SMS_WEB.create_provider
_sms_providers.BaseSmsProvider._try_get = staticmethod(_isolated_sms_try_get)
_sms_providers.FiveSimProvider._rest_get = _isolated_fivesim_rest_get
_codex_oauth_chain._emit = _patched_chain_emit
_codex_oauth_chain.SmsProviderAdapter.get_number = _sms_adapter_get_number
_codex_oauth_chain.SmsProviderAdapter.mark_ready = _sms_adapter_mark_ready
_codex_oauth_chain.SmsProviderAdapter.wait_code = _sms_adapter_wait_code
_codex_oauth_chain.SmsProviderAdapter.complete = _sms_adapter_complete
_codex_oauth_chain.SmsProviderAdapter.cancel = _sms_adapter_cancel
_codex_oauth_chain._event = _patched_chain_event
_codex_oauth_chain.RealCodexTransport.__init__ = _real_transport_init
_codex_oauth_chain.RealCodexTransport._new_session = _real_new_session
_codex_oauth_chain.RealCodexTransport.import_phase1_session = _real_import_phase1_session
_codex_oauth_chain.RealCodexTransport._headers = _real_headers
_codex_oauth_chain.RealCodexTransport._post_auth_json = _real_post_auth_json
_codex_oauth_chain.RealCodexTransport._post_auth_json_without_sentinel = _real_post_auth_json_without_sentinel
_codex_oauth_chain.RealCodexTransport.send_email_otp = _real_send_email_otp
_codex_oauth_chain.RealCodexTransport.send_passwordless_otp = _real_send_passwordless_otp
_codex_oauth_chain.RealCodexTransport.submit_email_identifier = _real_submit_email_identifier
_codex_oauth_chain.RealCodexTransport.verify_password = _real_verify_password
_codex_oauth_chain.RealCodexTransport.verify_email_otp = _real_verify_email_otp
_codex_oauth_chain.RealCodexTransport.verify_signup_email_otp = _real_verify_signup_email_otp
_codex_oauth_chain.RealCodexTransport.send_mfa_otp = _real_send_mfa_otp
_codex_oauth_chain.RealCodexTransport.verify_mfa_otp = _real_verify_mfa_otp
_codex_oauth_chain.RealCodexTransport.initiate_oauth = _real_initiate_oauth
_codex_oauth_chain.RealCodexTransport.visit_continue = _real_visit_continue
_codex_oauth_chain.RealCodexTransport.complete_chatgpt_callback = _real_complete_chatgpt_callback
_codex_oauth_chain.RealCodexTransport.chatgpt_access_token = _real_chatgpt_access_token
_codex_oauth_chain.RealCodexTransport.send_phone_number_otp = _sms_send_phone_number_otp
_codex_oauth_chain.RealCodexTransport.verify_phone_otp = _real_verify_phone_otp
_codex_oauth_chain.RealCodexTransport.create_account_profile = _real_create_account_profile
_codex_oauth_chain.RealCodexTransport.accept_consent = _real_accept_consent
_codex_oauth_chain.RealCodexTransport.follow_continue_until_code = _real_follow_continue_until_code
_codex_oauth_chain.RealCodexTransport.exchange_code = _real_exchange_code
_codex_oauth_chain.Sub2SessionExchanger.exchange = _sub2_session_exchange
_codex_oauth_chain.RealSub2Uploader.upload = _real_sub2_upload
_sms_selector.SmartSmsSelector._build_candidates_locked = _sms_build_candidates
_sms_selector.SmartSmsSelector.classify_error = staticmethod(_SMS_WEB.classify_error)
_sms_selector.SmartSmsSelector.record_result = _sms_record_result
_sms_selector.SmartSmsSelector._route_limit = _sms_route_limit

_legacy_ui_ext.apply_legacy_ui_overrides(
    _module,
    min_price_default=_SMS_MIN_PRICE_DEFAULT,
    max_price_default=_SMS_MAX_PRICE_DEFAULT,
    max_price_hard_limit=_SMS_MAX_PRICE_HARD_LIMIT,
    priority_countries_text=_SMS_PRIORITY_COUNTRIES_TEXT,
)


for _name in dir(_module):
    if _name.startswith("__") and _name not in {"__doc__", "__all__"}:
        continue
    globals()[_name] = getattr(_module, _name)


_ORIGINAL_CREATE_APP = globals()["create_app"]


def _closure_values(fn):
    cells = fn.__closure__ or ()
    return dict(zip(fn.__code__.co_freevars, (cell.cell_contents for cell in cells), strict=False))


def _read_local_config():
    return _config_lifecycle_mod.read_local_config(_host_module())


def _write_local_config(data):
    return _config_lifecycle_mod.write_local_config(_host_module(), data)
# Copy the pre-existing Free files once, then keep the ordinary runtime config
# free of Free mailbox, proxy, target and driver settings.
_FREE_CONFIG_MIGRATION = _FREE_CONFIG_STORE.migrate_legacy(_read_local_config(), _RUNTIME_DATA_DIR)
_FREE_PROXY_POLICY_MIGRATION = _FREE_CONFIG_STORE.migrate_single_pool_state()
_legacy_local_config = _read_local_config()
if any(key in _legacy_local_config for key in _free_register_config_ext.FREE_LEGACY_CONFIG_KEYS):
    _write_local_config(_legacy_local_config)


_initial_connectivity_config = _read_local_config()
_OPENAI_CONNECTIVITY.set_enabled(
    _performance_runtime_ext.as_bool(
        _initial_connectivity_config.get("openai_connectivity_guard"),
        True,
    )
)
_OPENAI_CONNECTIVITY.configure_proxy(
    _initial_connectivity_config.get("proxy") or ""
)
_OPENAI_DIAGNOSTICS = _connectivity_diagnostics_ext.OpenAIConnectivityDiagnostics(
    config_getter=_read_local_config,
    node_bridge=_codex_node_bridge.run_node_bridge,
)


_MAILBOX_NEXT_BATCH_PRIORITY = (
    _mailbox_priority_runtime_ext.MailboxNextBatchPriorityStore(_RUNTIME_DATA_DIR)
)
_RUN_BATCH_MANIFEST = _run_batch_runtime_ext.RunBatchManifestStore(
    _RUNTIME_DATA_DIR,
    recover_pending=True,
    lease_releaser=_release_recovered_batch_leases,
    # A finished batch must retire its staged gates: protocol pressure reports
    # and connectivity resumes would otherwise target a stale run's gates.
    finalize_callback=lambda _batch_id: (
        globals().__setitem__("_CURRENT_TASK_ADMISSION", None),
        globals().__setitem__("_CURRENT_INFLIGHT_GATE", None),
    ),
)
_FREE_REGISTER = _free_register_runtime_ext.FreeRegisterManager(
    _FREE_DATA_DIR,
    diagnostic_store=_DIAGNOSTIC_STORE,
    storage_adapters=_free_storage_adapters_ext.build_free_storage_adapters(_FREE_DATA_DIR),
    manual_broker=_MANUAL_VERIFICATION,
    config_provider=_FREE_CONFIG_STORE.load,
    notification_config_getter=lambda: (_read_local_config() or {}).get("email_notification", {}),
)
_SUB2_RUNTIME = _sub2_runtime_ext.Sub2Runtime(
    _read_local_config,
    _RUNTIME_DATA_DIR / "sub2_test_snapshots.json",
)
_OPENAI_DIRECT_RUNTIME = _openai_direct_test_runtime_ext.OpenAIDirectTestRuntime(
    _read_local_config,
    _RUNTIME_DATA_DIR / "openai_direct_test_snapshots.json",
)
_OPENAI_QUOTA_SNAPSHOTS = _openai_quota_runtime_ext.OpenAIQuotaSnapshotStore(
    _RUNTIME_DATA_DIR / "openai_quota_snapshots.json",
)


_LOCAL_CONFIG_RUNTIME = _configuration_runtime_ext.LocalConfigRuntime(
    clean=_module._clean,
    secret_mask=_SECRET_MASK,
    sms_runtime=_sms_runtime_ext,
    performance_runtime=_performance_runtime_ext,
    notifications=_run_notifications_ext,
    migrate_email_timeout=_migrate_email_timeout_config,
    migrate_email_proxy_scope=_migrate_email_proxy_scope_config,
    read_local_config=_read_local_config,
    online_mailbox_default_url=_online_mailbox_runtime_ext.DEFAULT_ONLINE_MAILBOX_BASE_URL,
    email_timeout_strategy_version=_EMAIL_TIMEOUT_STRATEGY_VERSION,
    sms_min_price_default=_SMS_MIN_PRICE_DEFAULT,
    int_value=_int_value,
    as_enabled=_as_enabled,
    clamp_sms_max_price=_clamp_sms_max_price,
)


_local_secret = _LOCAL_CONFIG_RUNTIME.local_secret


def _mask_secret(value):
    return _SECRET_MASK if _module._clean(value) else ""


_sms_provider_pools_from_config = _LOCAL_CONFIG_RUNTIME.sms_provider_pools_from_config
_sms_keys_from_config = _LOCAL_CONFIG_RUNTIME.sms_keys_from_config
_resolve_sms_provider_pools = _LOCAL_CONFIG_RUNTIME.resolve_sms_provider_pools
_resolve_sms_keys = _LOCAL_CONFIG_RUNTIME.resolve_sms_keys


_MAILBOX_ADMIN_REF = {"service": None}


_PUBLIC_STATE = _public_state_runtime_ext.PublicStateRuntime(
    clean=_module._clean,
    secret_mask=_SECRET_MASK,
    sms_runtime=_sms_runtime_ext,
    sms_provider_pools_from_config=lambda data: _sms_provider_pools_from_config(data),
    sms_keys_from_config=lambda data: _sms_keys_from_config(data),
    read_local_config=lambda: _read_local_config(),
    mailbox_admin=_mailbox_admin_ext,
    error_observability=_error_observability_ext,
    task_progress_runtime=_task_progress_ext,
    sms_provider_registry_getter=lambda: globals().get("_SMS_PROVIDER_REGISTRY"),
    sms_alerts_getter=lambda: globals().get("_SMS_ALERTS"),
    task_progress_getter=lambda: globals().get("_TASK_PROGRESS"),
    current_task_admission_getter=lambda: globals().get("_CURRENT_TASK_ADMISSION"),
    inflight_gate_getter=lambda: globals().get("_CURRENT_INFLIGHT_GATE"),
    openai_connectivity_getter=lambda: globals().get("_OPENAI_CONNECTIVITY"),
    protocol_gate_getter=lambda: globals().get("_PROTOCOL_GATE"),
    sms_phone_gate_getter=lambda: globals().get("_SMS_PHONE_GATE"),
    sms_optimization_guard_getter=lambda: globals().get("_SMS_QUALITY_GUARD"),
    process_resource_snapshot_getter=_transport_lifecycle_ext.process_resource_snapshot,
    transport_registry_getter=lambda: _SMS_TRANSPORT_REGISTRY,
    phone_binding_metrics_getter=lambda: _PHONE_BINDING_METRICS,
    notification_context_for=lambda: _notification_context_for(),
    known_task_failure=lambda task_id: _known_task_failure(task_id),
    historical_success_reasons=_HISTORICAL_SUCCESS_REASONS,
    task_id_log_re=_TASK_ID_LOG_RE,
    public_log_input_limit=_PUBLIC_LOG_INPUT_LIMIT,
    masked_local_config_view=lambda data: _masked_local_config(data),
    public_task_view=lambda task: _public_task(task),
    runtime_summary_view=lambda tasks: _sms_cost_history_ext.with_historical_sms_cost(_runtime_summary(tasks), _RUNTIME_DATA_DIR),
    notification_public_status_view=lambda: _notification_public_status(),
    public_logs_view=lambda logs, tasks: _public_logs(logs, tasks),
    mailbox_pool_summary_getter=lambda: _MAILBOX_ADMIN_REF.get("service"),
)


_masked_local_config = _PUBLIC_STATE.masked_local_config


def _public_task(task):
    public = _PUBLIC_STATE.public_task(task)
    task_id = str((task or {}).get("task_id") or "").strip() if isinstance(task, dict) else ""
    if task_id and not public.get("incident_id"):
        try:
            lookup = {"task_id": task_id, "limit": 1}
            batch_id = str((task or {}).get("batch_id") or "").strip() if isinstance(task, dict) else ""
            if batch_id:
                lookup["batch_id"] = batch_id
            matches = _DIAGNOSTIC_STORE.search(lookup)
            if not matches and batch_id:
                # Legacy ordinary log events may predate batch_id metadata;
                # retain the stable task join without crossing to another
                # task.
                matches = _DIAGNOSTIC_STORE.search({"task_id": task_id, "limit": 1})
            if matches:
                public["incident_id"] = str(matches[0].get("incident_id") or "")
        except Exception as exc:
            # A diagnostic index outage must never make the main task state
            # unavailable; the log center health endpoint reports the outage.
            _note_stderr("task_incident_lookup", exc)
    prompt = _MANUAL_VERIFICATION.public(task_id) if task_id else {}
    if isinstance(prompt, dict) and prompt and prompt.get("input_kind"):
        public["manual_verification"] = prompt
        public["capabilities"] = ["submit_manual_verification"]
    checkpoint = task.get("_checkpoint_public") if isinstance(task, dict) else None
    if not isinstance(checkpoint, dict):
        checkpoint = _checkpoint_public_for(task_id)
    if isinstance(checkpoint, dict):
        public["checkpoint"] = {
            key: copy.deepcopy(checkpoint[key])
            for key in (
                "state",
                "resume_stage",
                "expires_at",
                "age_seconds",
                "remaining_seconds",
                "reason",
            )
            if key in checkpoint
        }
    return public


def _task_exists(task_id):
    importer = getattr(_module, "importer", None)
    tasks = getattr(importer, "tasks", {}) if importer is not None else {}
    normalized = str(task_id or "").strip()
    if normalized in tasks:
        return True
    free_manager = globals().get("_FREE_REGISTER")
    if free_manager is not None:
        try:
            return any(str(item.get("task_id") or "") == normalized for item in free_manager.public_tasks())
        except Exception as exc:
            # A broken Free manager must not corrupt the plain-flow state check.
            _note_stderr("free_task_exists", exc)
    return False


def _free_manual_task_input_kind(task_id):
    """Expose email OTP input only while a Free task is in an OTP stage."""
    normalized = str(task_id or "").strip()
    free_manager = globals().get("_FREE_REGISTER")
    if free_manager is None or not normalized:
        return ""
    allowed_stages = {
        "free_email_otp_wait",
        "free_existing_login_otp",
        "free_email_otp_validate",
    }
    try:
        with free_manager._lock:
            task = free_manager._tasks.get(normalized)
            if not isinstance(task, dict):
                return ""
            status = str(task.get("status") or "")
            progress = task.get("progress") if isinstance(task.get("progress"), dict) else {}
            stage = str(task.get("stage") or progress.get("stage") or "")
        if status in {"queued", "running"} and stage in allowed_stages:
            return "email_otp"
    except Exception:
        return ""
    return ""


def _free_task_exists(task_id):
    """Return whether an identifier belongs to the isolated Free task store."""
    normalized = str(task_id or "").strip()
    free_manager = globals().get("_FREE_REGISTER")
    if free_manager is None or not normalized:
        return False
    try:
        with free_manager._lock:
            return normalized in free_manager._tasks
    except Exception:
        return False


_runtime_summary = _PUBLIC_STATE.runtime_summary
_notification_public_status = _PUBLIC_STATE.notification_public_status
_public_logs = _PUBLIC_STATE.public_logs
_masked_state = _PUBLIC_STATE.masked_state
_local_config_secret = _LOCAL_CONFIG_RUNTIME.local_config_secret
_local_config_from_runtime = _LOCAL_CONFIG_RUNTIME.local_config_from_runtime
_merge_nonempty = _LOCAL_CONFIG_RUNTIME.merge_nonempty
_merge_email_notification = _LOCAL_CONFIG_RUNTIME.merge_email_notification
_merge_local_config = _LOCAL_CONFIG_RUNTIME.merge_local_config
_apply_server_defaults = _LOCAL_CONFIG_RUNTIME.apply_server_defaults
_test_email_notification = _LOCAL_CONFIG_RUNTIME.test_email_notification


def _mailbox_admin_factory(store, importer, logs):
    service = _mailbox_admin_factory_ext.build_mailbox_admin(
        store, importer, logs,
        runtime=_runtime,
        next_batch_priority=_MAILBOX_NEXT_BATCH_PRIORITY,
        notification_context_for=_notification_context_for,
        task_progress=_TASK_PROGRESS,
        task_progress_runtime=_task_progress_ext,
        sub2_runtime=_SUB2_RUNTIME,
        openai_direct_runtime=_OPENAI_DIRECT_RUNTIME,
        openai_quota_snapshots=_OPENAI_QUOTA_SNAPSHOTS,
        actionable_phone_risk_status=_actionable_phone_risk_status,
        run_batch_manifest=_RUN_BATCH_MANIFEST,
    )
    _MAILBOX_ADMIN_REF["service"] = service
    return service


def _online_mailbox_client_factory(base_url, api_token):
    return _online_mailbox_runtime_ext.OnlineMailboxClient(base_url, api_token)


_WEB_ROUTE_CONTEXT = _web_routes_ext.WebRouteContext(
    module=_module,
    app_dir=APP_DIR,
    send_from_directory=_send_from_directory,
    closure_values=_closure_values,
    lifecycle_lock=_RUN_LIFECYCLE_LOCK,
    read_local_config=_read_local_config,
    write_local_config=_write_local_config,
    local_config_from_runtime=_local_config_from_runtime,
    local_config_secret=_local_config_secret,
    masked_local_config=_masked_local_config,
    masked_state=_masked_state,
    apply_server_defaults=_apply_server_defaults,
    configure_sms_pool=_configure_sms_pool,
    preflight_sms_pool=_preflight_sms_pool,
    safe_runtime_error=_safe_runtime_error,
    test_email_notification=_test_email_notification,
    sms_alerts=_SMS_ALERTS,
    sms_cost_ledger=_SMS_COST_LEDGER,
    sms_route_policy=_SMS_ROUTE_POLICY,
    sms_key_pool=_SMS_PROVIDER_REGISTRY,
    sms_phone_gate=_SMS_PHONE_GATE,
    mailbox_admin_factory=_mailbox_admin_factory,
    mailbox_manager_html=_legacy_ui_ext.MAILBOX_MANAGER_HTML,
    mailbox_url_test_factory=_mailbox_url_test_runtime_ext.MailboxUrlTester,
    sub2_payload_builder=_sub2_runtime_ext.build_sub2_export_payload,
    run_batch_manifest=_RUN_BATCH_MANIFEST,
    free_register_manager=_FREE_REGISTER,
    query_sms_balances=_SMS_WEB.query_balances,
    online_mailbox_client_factory=_online_mailbox_client_factory,
    failure_secrets=lambda config: _failure_secrets(settings=config),
    free_config_store=_FREE_CONFIG_STORE,
    free_data_dir=_FREE_DATA_DIR,
    diagnostic_store=_DIAGNOSTIC_STORE,
    mailbox_parser_sample_store=_MAILBOX_PARSER_SAMPLE_STORE,
    free_mailbox_parser_sample_store=_FREE_MAILBOX_PARSER_SAMPLE_STORE,
)


def _patch_flask_app(app):
    original_start = app.view_functions.get("start")
    route_values = _closure_values(original_start) if callable(original_start) else {}
    patched = _web_routes_ext.patch_flask_app(app, _WEB_ROUTE_CONTEXT)
    # Network tools own their store and routes; they do not use the ordinary
    # SMS or Free task stores beyond explicit Free Token lookup.
    tools_root = _FREE_DATA_DIR.parent
    _network_tools_routes_ext.install_network_routes(
        patched, module=_module, data_root=tools_root, diagnostic_store=_DIAGNOSTIC_STORE,
    )
    patched = _connectivity_routes_ext.patch_openai_connectivity_guard_route(
        patched,
        module=_module,
        lifecycle_lock=_RUN_LIFECYCLE_LOCK,
        store=route_values.get("store"),
        logs=route_values.get("logs"),
        state_getter=route_values.get("state"),
        read_local_config=_read_local_config,
        write_local_config=_write_local_config,
        masked_local_config=_masked_local_config,
        masked_state=_masked_state,
        diagnostics=_OPENAI_DIAGNOSTICS,
    )
    return _manual_verification_routes_ext.patch_flask_app(
        patched,
        broker=_MANUAL_VERIFICATION,
        task_exists=_task_exists,
        task_is_free=_free_task_exists,
        task_generation=_manual_task_generation,
        task_input_kind=_free_manual_task_input_kind,
    )


def create_app(data_dir=None):
    return _patch_flask_app(_ORIGINAL_CREATE_APP(data_dir))


_module.create_app = create_app
if hasattr(_module, "app"):
    _module.app = _patch_flask_app(_module.app)


__doc__ = _module.__doc__
__all__ = [name for name in globals() if not name.startswith("_")]
