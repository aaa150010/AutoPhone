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
from urllib.parse import urlsplit

from flask import send_from_directory as _send_from_directory

import node_runtime as _node_runtime_ext

# Resolve this before importing recovered modules so their first subprocess
# lookup sees the same verified Node binary as later runtime calls.
_node_runtime_ext.configure_node_runtime()

import codex_oauth_chain as _codex_oauth_chain
import codex_node_bridge as _codex_node_bridge
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
import mfa_retry_runtime as _mfa_retry_runtime_ext
import oauth_mfa_runtime as _oauth_mfa_runtime_ext
import manual_verification_runtime as _manual_verification_runtime_ext
import manual_verification_routes as _manual_verification_routes_ext
import phase1_checkpoint_runtime as _phase1_checkpoint_runtime_ext
import phase1_checkpoint_hooks as _phase1_checkpoint_hooks_ext
import adaptive_concurrency as _adaptive_concurrency_ext
import pixel_runtime as _pixel_runtime_ext
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
import mailbox_retention as _mailbox_retention_ext
import free_register_runtime as _free_register_runtime_ext
import free_register_config as _free_register_config_ext
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
import payment_tools_routes as _payment_tools_routes_ext
import network_tools_routes as _network_tools_routes_ext


# Do not allow the host shell's proxy settings to silently affect OpenAI,
# mailbox, SMS, SUB2, or Pixel requests. Each caller below supplies its own
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
    except Exception:
        pass


def _submit_connectivity_email(payload):
    try:
        capacity = _PROTOCOL_GATE.snapshot(_CONNECTIVITY_PROXY)
        notification = _CONNECTIVITY_NOTIFICATION_CONTEXTS.build_notification(
            payload,
            batch_id=_CONNECTIVITY_BATCH_ID,
            capacity=capacity,
        )
        _CONNECTIVITY_EMAILS.submit(notification)
    except Exception:
        pass


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
    if re.search(r"\[[^\]]+/[a-z0-9_]+\]", safe, re.IGNORECASE) or safe.startswith("Pixel "):
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
    raw = _read_store_config(self)
    removed_legacy_fields = False
    # These fields belonged to the removed ordinary-SMS plan gate.  Drop them
    # during the next config read so stale local settings cannot re-enable a
    # gate that is no longer part of the SMS workflow.
    for key in (
        "nvtoken",
        "nvtoken_upload",
        "pixel_upload_enabled",
        "allow_free_plan_sms_binding",
        "allow_unknown_plan_sms_binding",
    ):
        if key in raw:
            raw.pop(key, None)
            removed_legacy_fields = True
    raw, email_timeout_migrated = _migrate_email_timeout_config(raw)
    raw, email_proxy_scope_migrated = _migrate_email_proxy_scope_config(raw)
    defaults = _runtime.default_settings(self.data_dir)
    defaults["proxy_scope"] = {
        **dict(defaults.get("proxy_scope") or {}),
        "email": True,
    }
    defaults["email_proxy_scope_strategy_version"] = _EMAIL_PROXY_SCOPE_STRATEGY_VERSION
    defaults["email_code_timeout"] = _EMAIL_CODE_TIMEOUT_DEFAULT
    defaults["email_timeout_strategy_version"] = _EMAIL_TIMEOUT_STRATEGY_VERSION
    if "sms_mode" not in raw:
        smart = raw.get("sms_smart") if isinstance(raw.get("sms_smart"), dict) else {}
        defaults["sms_mode"] = "smart" if _runtime._as_bool(smart.get("enabled"), True) else "fixed"

    loaded = _runtime._merge(defaults, raw)
    changed = (
        self._enforce_private_paths(loaded, defaults)
        or email_timeout_migrated
        or email_proxy_scope_migrated
    )
    if "email_otp_verify_attempts" not in raw or raw.get("email_otp_verify_attempts") in (None, ""):
        if loaded.get("email_otp_verify_attempts") != _EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT:
            loaded["email_otp_verify_attempts"] = _EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT
            changed = True
    else:
        normalized_attempts = _int_value(
            raw.get("email_otp_verify_attempts"),
            _EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT,
            minimum=1,
            maximum=5,
        )
        if loaded.get("email_otp_verify_attempts") != normalized_attempts:
            loaded["email_otp_verify_attempts"] = normalized_attempts
            changed = True
    if "email_otp_resend_on_retry" not in raw or raw.get("email_otp_resend_on_retry") in (None, ""):
        if loaded.get("email_otp_resend_on_retry") != _EMAIL_OTP_RESEND_ON_RETRY_DEFAULT:
            loaded["email_otp_resend_on_retry"] = _EMAIL_OTP_RESEND_ON_RETRY_DEFAULT
            changed = True
    else:
        normalized_resend = _as_enabled(raw.get("email_otp_resend_on_retry"), False)
        if loaded.get("email_otp_resend_on_retry") != normalized_resend:
            loaded["email_otp_resend_on_retry"] = normalized_resend
            changed = True

    try:
        auth_strategy_version = int(raw.get("email_auth_strategy_version") or 0)
    except (TypeError, ValueError):
        auth_strategy_version = 0
    if auth_strategy_version < 2:
        loaded["email_auth_preference"] = "auto"
        loaded["email_auth_strategy_version"] = 2
        changed = True

    try:
        node_timeout_strategy_version = int(raw.get("node_timeout_strategy_version") or 0)
    except (TypeError, ValueError):
        node_timeout_strategy_version = 0
    if node_timeout_strategy_version < 1:
        loaded["node_timeout"] = 45
        loaded["node_timeout_strategy_version"] = 1
        changed = True

    normalized, migrated = _sms_runtime_ext.migrate_performance_config(loaded)
    normalized = _performance_runtime_ext.normalize_feature_flags(normalized)
    normalized["dynamic_auth_challenges"] = _as_enabled(
        raw.get("dynamic_auth_challenges"), True
    )
    normalized.pop("allow_free_plan_sms_binding", None)
    normalized.pop("allow_unknown_plan_sms_binding", None)
    normalized.pop("pixel_upload_enabled", None)
    policy_keys = (
        "performance_policy_version",
        "auto_email_login_concurrency",
        "phone_submission_concurrency",
        "pixel_upload_concurrency",
        "phone_max_attempts",
        "phone_attempts_per_provider",
        "phone_session_cycle_seconds",
        "auth_session_retries",
        "email_code_timeout",
        "email_timeout_strategy_version",
        "email_otp_verify_attempts",
        "email_otp_resend_on_retry",
        "sms_provider_pools",
        "sms_provider",
        "sms_api_keys",
        "sms_api_key",
        "sms_quality_optimization",
        "adaptive_task_concurrency",
        "task_inflight_optimization",
        "task_inflight_limit",
        "openai_connectivity_guard",
        "phone_binding_compatibility",
        "mailbox_result_index_cache",
        "protocol_concurrency_ceiling",
        "dynamic_auth_challenges",
        "proxy_scope",
        "email_proxy_scope_strategy_version",
    )
    if migrated or any(raw.get(key) != normalized.get(key) for key in policy_keys):
        changed = True
    if changed or removed_legacy_fields:
        _write_store_config(self, normalized)
    return normalized


def _patched_config_save(self, values):
    previous = _read_store_config(self)
    cleaned = dict(values or {})
    if "email_proxy_scope_strategy_version" not in cleaned:
        prior_version = previous.get("email_proxy_scope_strategy_version")
        if prior_version is not None:
            cleaned["email_proxy_scope_strategy_version"] = prior_version
    if "proxy_scope" not in cleaned and isinstance(previous.get("proxy_scope"), dict):
        cleaned["proxy_scope"] = copy.deepcopy(previous["proxy_scope"])
    cleaned.pop("nvtoken", None)
    cleaned.pop("nvtoken_upload", None)
    cleaned.pop("pixel_upload_enabled", None)
    cleaned.pop("allow_free_plan_sms_binding", None)
    cleaned.pop("allow_unknown_plan_sms_binding", None)
    if cleaned.get("email_otp_verify_attempts") in (None, ""):
        cleaned["email_otp_verify_attempts"] = _EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT
    if cleaned.get("email_otp_resend_on_retry") in (None, ""):
        cleaned["email_otp_resend_on_retry"] = _EMAIL_OTP_RESEND_ON_RETRY_DEFAULT
    cleaned, _email_timeout_migrated = _migrate_email_timeout_config(cleaned)
    cleaned, _email_proxy_scope_migrated = _migrate_email_proxy_scope_config(cleaned)
    normalized, _migrated = _sms_runtime_ext.migrate_performance_config(cleaned)
    normalized = _performance_runtime_ext.normalize_feature_flags(normalized)
    normalized["dynamic_auth_challenges"] = _as_enabled(
        cleaned.get("dynamic_auth_challenges"), True
    )
    normalized.pop("allow_free_plan_sms_binding", None)
    normalized.pop("allow_unknown_plan_sms_binding", None)
    saved = dict(_ORIGINAL_CONFIG_SAVE(self, normalized) or {})
    for key in (
        "performance_policy_version",
        "auto_email_login_concurrency",
        "phone_submission_concurrency",
        "pixel_upload_concurrency",
        "phone_max_attempts",
        "phone_attempts_per_provider",
        "phone_session_cycle_seconds",
        "auth_session_retries",
        "email_code_timeout",
        "email_timeout_strategy_version",
        "email_otp_verify_attempts",
        "email_otp_resend_on_retry",
        "sms_provider_pools",
        "sms_provider",
        "sms_api_keys",
        "sms_api_key",
        "sms_quality_optimization",
        "adaptive_task_concurrency",
        "task_inflight_optimization",
        "task_inflight_limit",
        "openai_connectivity_guard",
        "phone_binding_compatibility",
        "mailbox_result_index_cache",
        "protocol_concurrency_ceiling",
        "dynamic_auth_challenges",
        "proxy_scope",
        "email_proxy_scope_strategy_version",
    ):
        saved[key] = normalized[key]
    _write_store_config(self, saved)
    return saved


def _patched_task_config(self, settings, email, task_id, *, password=""):
    config = _ORIGINAL_TASK_CONFIG(self, settings, email, task_id, password=password)
    run_mode = str((settings or {}).get("run_mode") or "register").strip().lower()
    relogin = run_mode == "relogin"
    pools = _sms_provider_pools_from_config(settings or {})
    enabled_pools = [pool for pool in pools if _as_enabled(pool.get("enabled"), True) and pool.get("api_keys")]
    primary = enabled_pools[0] if enabled_pools else (pools[0] if pools else {})
    keys = _sms_runtime_ext.legacy_sms_provider_keys(
        pools,
        primary.get("provider") or "smsbower",
    )
    attempts_per_provider = _int_value(
        (settings or {}).get("phone_attempts_per_provider"),
        15,
        minimum=1,
        maximum=15,
    )
    attempts = min(45, attempts_per_provider * max(1, len(enabled_pools)))
    phone_seconds = _int_value(
        (settings or {}).get("phone_session_cycle_seconds"),
        1800,
        minimum=30,
        maximum=1800,
    )
    route_lease_seconds = (
        2 * _int_value(config.get("code_timeout"), 30, minimum=5, maximum=300)
    ) + 20
    raw_email_attempts = (settings or {}).get("email_otp_verify_attempts")
    email_attempts = _int_value(
        raw_email_attempts,
        _EMAIL_OTP_VERIFY_ATTEMPTS_DEFAULT,
        minimum=1,
        maximum=5,
    )
    raw_email_resend = (settings or {}).get("email_otp_resend_on_retry")
    email_resend = _as_enabled(raw_email_resend, _EMAIL_OTP_RESEND_ON_RETRY_DEFAULT)
    config.update(
        {
            "sms_provider_pools": pools,
            "sms_provider": str(primary.get("provider") or "smsbower"),
            "sms_api_keys": keys,
            "sms_api_key": keys[0] if keys else "",
            "sms_task_id": str(task_id),
            "phone_max_attempts": attempts,
            "phone_attempts_per_provider": attempts_per_provider,
            "phone_session_cycle_seconds": phone_seconds,
            "phone_session_max_seconds": phone_seconds,
            "phone_retry_sleep_seconds": 1,
            "email_otp_verify_attempts": email_attempts,
            "email_otp_resend_on_retry": email_resend,
            "sms_quality_optimization": _performance_runtime_ext.as_bool(
                (settings or {}).get("sms_quality_optimization"),
                True,
            ),
            "dynamic_auth_challenges": _as_enabled(
                (settings or {}).get("dynamic_auth_challenges"), True
            ),
            "phone_binding_compatibility": _performance_runtime_ext.as_bool(
                (settings or {}).get("phone_binding_compatibility"),
                True,
            ),
        }
    )
    risk_status = _actionable_phone_risk_status(email)
    if risk_status.get("active"):
        config["_phone_risk_retry"] = True
        config["_phone_risk_reason_code"] = str(
            risk_status.get("reason_code") or "oauth_session_invalid"
        )
    normalized_email = str(email or "").strip().lower()
    results_value = str((settings or {}).get("results_dir") or "results").strip() or "results"
    results_dir = Path(results_value)
    if not results_dir.is_absolute():
        results_dir = Path(getattr(self, "data_dir", _RUNTIME_DATA_DIR)) / results_dir
    historical = _mailbox_admin_ext.latest_sub2_accounts_by_email(results_dir).get(
        normalized_email
    )
    if relogin:
        binding = next(
            (
                item
                for item in (settings or {}).get("_gptphone_relogin_rows") or ()
                if isinstance(item, dict)
                and str(item.get("email") or "").strip().lower() == normalized_email
                and str(item.get("sub2api_account_id") or "").strip()
            ),
            None,
        )
        if binding is None:
            raise RuntimeError(
                "relogin_sub2_binding_missing: 重登邮箱缺少经过校验的 SUB2 原账号绑定"
            )
        config["run_mode"] = "relogin"
        config["sms_provider"] = "smsbower"
        config["sms_api_key"] = "relogin-disabled"
        config["sms_api_keys"] = ["relogin-disabled"]
        remote_id = str(binding.get("sub2api_account_id") or "").strip()
        config["_sub2_update_existing"] = {
            "account_id": remote_id,
            "openai_account_id": _sub2_binding_runtime_ext.historical_openai_account_id(
                historical, remote_id
            ),
            "email": normalized_email,
            "status_code": binding.get("status_code"),
            "status_kind": str(binding.get("status_kind") or "").strip().lower(),
        }
    elif historical:
        update_binding = _sub2_binding_runtime_ext.resolve_existing_update_binding(
            historical,
            direct_status_lookup=getattr(_OPENAI_DIRECT_RUNTIME, "status_for", None),
            sub2_status_lookup=getattr(_SUB2_RUNTIME, "status_for", None),
        )
        if update_binding:
            config["_sub2_update_existing"] = {**update_binding, "email": normalized_email}
    for pool in pools:
        provider = str(pool.get("provider") or "")
        if not provider:
            continue
        provider_keys = list(pool.get("api_keys") or [])
        config[provider] = {
            **dict(config.get(provider) or {}),
            "api_key": provider_keys[0] if provider_keys else "",
        }
    config["sms_smart"] = {
        **dict(config.get("sms_smart") or {}),
        "enabled": True,
        "throughput_priority": False,
        "route_hard_max_inflight": 2,
        "route_max_inflight": 2,
        "route_semi_max_inflight": 2,
        "route_hot_max_inflight": 2,
        "route_lease_seconds": route_lease_seconds,
        "timeout_cooldown": 180,
        "phone_rejected_cooldown": 180,
        "register_rejected_cooldown": 60,
        "register_rejected_min_cooldown": 180,
    }
    return config


def _set_current_task_stage(code):
    task_id = _TASK_CONTEXT.get()
    if task_id:
        _TASK_PROGRESS.set_stage(task_id, code)


def _record_task_segment(task_id, code, elapsed_seconds):
    try:
        if task_id:
            _TASK_PROGRESS.record_segment(task_id, code, elapsed_seconds)
    except Exception:
        pass


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
    values = dict(values)
    status = str(values.get("status") or "").strip().lower()
    failure_statuses = set(_task_progress_ext.TERMINAL_TASK_STATUSES).difference({"success", "stopped", "stopped_before_start"})
    if status in failure_statuses:
        task_result = values.get("result") if isinstance(values.get("result"), dict) else {}
        failure = _classify_task_failure(
            task_id,
            task_result,
            values.get("technical_error") or values.get("error") or values.get("reason") or "",
            status=status,
        )
        values["failure"] = failure
        values["error"] = failure["public_message"]
        values["technical_error"] = failure["technical_summary"]
        if task_result:
            task_result = dict(task_result)
            task_result["failure"] = failure
            values["result"] = task_result
    if status == "success":
        _clear_known_node_failure(task_id)
        auth_sessions = globals().get("_AUTH_SESSIONS")
        if auth_sessions is not None:
            auth_sessions.clear(task_id)
    result = _ORIGINAL_TASK_STATE(self, task_id, **values)
    batch_manifest = globals().get("_RUN_BATCH_MANIFEST")
    if batch_manifest is not None and status:
        try:
            batch_manifest.observe_task(task_id, status)
        except KeyError:
            pass
        except Exception as exc:
            try:
                self._log(
                    "[运行批次对账/run_batch_manifest] 任务状态落盘失败"
                    f"（{type(exc).__name__}）",
                    "error",
                )
            except Exception:
                pass
    if status == "authorizing":
        _TASK_CONTEXT.set(str(task_id or ""))
    _TASK_PROGRESS.observe_task_state(task_id, status)
    if status in _task_progress_ext.TERMINAL_TASK_STATUSES:
        admission = getattr(self, "task_admission", None)
        observe_resources = getattr(admission, "observe_resource_ratio", None)
        if callable(observe_resources):
            resource_snapshot = _transport_lifecycle_ext.process_resource_snapshot()
            if resource_snapshot.fd_ratio is not None:
                observe_resources(resource_snapshot.fd_ratio)
        # The 83.9% reference is a completed-attempt baseline.  User stops
        # and scheduler cancellations are not completed attempts and must not
        # lower the observed success rate.
        completed_attempt = status not in {
            "stopped",
            "stopped_before_start",
            "cancelled",
            "canceled",
        }
        rollback_event = (
            _SMS_QUALITY_GUARD.observe_task(
                task_id,
                status,
                values.get("result"),
            )
            if completed_attempt
            else None
        )
        if rollback_event is not None:
            try:
                metrics = rollback_event.get("metrics") or {}
                reasons = "、".join(rollback_event.get("reasons") or ())
                self._log(
                    "[短信质量优化/sms_quality_optimization] 已自动关闭优化："
                    f"{reasons or 'rolling_window_regression'}；"
                    f"窗口 {metrics.get('window_tasks', 0)}，"
                    f"成功率 {metrics.get('success_rate', 0):.2%}",
                    "warn",
                )
            except Exception:
                pass
        progress = _TASK_PROGRESS.progress(task_id)
        admission = getattr(self, "task_admission", None)
        if admission is not None:
            if status == "success":
                admission.report_success(task_id)
            else:
                if status == "account_banned" and _is_fast_account_banned_progress(progress):
                    try:
                        admission.report_account_banned(task_id)
                    except Exception:
                        pass
                detail = (
                    values.get("technical_error")
                    or values.get("error")
                    or values.get("reason")
                    or ""
                )
                failure = values.get("failure") if isinstance(values.get("failure"), dict) else {}
                main_chain_pressure, pressure_failure = _is_main_chain_pressure_source(
                    task_id,
                    detail,
                    failure=failure,
                )
                node_pressure = (
                    main_chain_pressure
                    and _error_observability_ext.is_retryable_node_failure(detail)
                )
                protocol_pressure = (
                    main_chain_pressure
                    and (
                        _is_rate_limited_failure(pressure_failure)
                        or _sms_runtime_ext.is_protocol_pressure_error(detail)
                    )
                )
                if node_pressure or protocol_pressure:
                    _report_task_pressure(
                        task_id,
                        detail,
                        node_code=(
                            failure.get("node_code")
                            if node_pressure
                            else "protocol_pressure"
                        ),
                        immediate=True,
                    )
                admission.report_failure(task_id)
    if status in _task_progress_ext.TERMINAL_TASK_STATUSES:
        _SMS_PROVIDER_REGISTRY.clear_task_attempt_counts(task_id)
    if status in _task_progress_ext.TERMINAL_TASK_STATUSES and _TASK_CONTEXT.get() == str(task_id or ""):
        _TASK_CONTEXT.set("")
    return result


def _patched_chain_event(
    events,
    state,
    *,
    detail="",
    extra=None,
    log_fn=None,
    tag="info",
):
    task_id = _TASK_CONTEXT.get()
    if task_id:
        _TASK_PROGRESS.observe_chain_state(task_id, state)
    if str(state or "").strip().upper() in {"SENTINEL_READY", "TOKEN_EXCHANGED", "DONE"}:
        _clear_known_node_failure(task_id)
    if (
        str(state or "").strip().upper() == "RUNTIME_CONTEXT_ISSUE"
        and str(detail or "").strip().lower() == "warn:code_verifier_present"
    ):
        return _ORIGINAL_CHAIN_EVENT(
            events,
            state,
            detail=detail,
            extra=extra,
            log_fn=None,
            tag=tag,
        )
    retrying_node = (
        str(state or "").strip().upper() == "FAILED"
        and _error_observability_ext.is_retryable_node_failure(detail)
    )
    if not retrying_node:
        return _ORIGINAL_CHAIN_EVENT(
            events,
            state,
            detail=detail,
            extra=extra,
            log_fn=log_fn,
            tag=tag,
        )

    _report_task_pressure(task_id, detail)

    # Keep the FAILED event in the persisted chain for diagnosis. The chain
    # may immediately create a fresh bridge and continue, so emit a retry
    # notice instead of a terminal-looking red failure line.
    _ORIGINAL_CHAIN_EVENT(
        events,
        state,
        detail=detail,
        extra=extra,
        log_fn=None,
        tag=tag,
    )
    retry_message = _error_observability_ext.format_node_retry_log("", detail)
    if log_fn and retry_message:
        try:
            log_fn(retry_message, "warn")
        except TypeError:
            log_fn(retry_message)


def _patched_chain_emit(log_fn, message, tag="info"):
    raw = str(message or "")
    if "[SentinelRunner]" in raw:
        if "token 生成成功" in raw:
            _clear_known_node_failure(_TASK_CONTEXT.get())
            coordinator = globals().get("_PROTOCOL_COORDINATOR")
            if coordinator is not None:
                coordinator.observe_connectivity_result(
                    "sentinel.openai.com",
                    succeeded=True,
                    task_id=_TASK_CONTEXT.get(),
                    proxy=_CONNECTIVITY_PROXY,
                )
        elif "token 生成失败" in raw:
            coordinator = globals().get("_PROTOCOL_COORDINATOR")
            if coordinator is not None:
                coordinator.observe_connectivity_result(
                    "sentinel.openai.com",
                    raw,
                    task_id=_TASK_CONTEXT.get(),
                    proxy=_CONNECTIVITY_PROXY,
                )
    if _error_observability_ext.is_node_retry_log(raw):
        retry_message = _error_observability_ext.format_node_retry_log("", raw)
        return _ORIGINAL_CHAIN_EMIT(log_fn, retry_message, "warn")
    return _ORIGINAL_CHAIN_EMIT(log_fn, message, tag)


_notification_task_snapshot = _NOTIFICATION_LIFECYCLE.task_snapshot
_notification_aggregate = _NOTIFICATION_LIFECYCLE.aggregate
_notification_context_for = _NOTIFICATION_LIFECYCLE.context_for


def _observe_runtime_fd_pressure(importer):
    admission = getattr(importer, "task_admission", None)
    observer = getattr(admission, "observe_resource_ratio", None)
    if not callable(observer):
        return None
    try:
        ratio = _transport_lifecycle_ext.process_fd_ratio()
        return observer(ratio) if ratio is not None else None
    except Exception:
        return None


def _notify_sms_balances(importer, statuses):
    """Forward sanitized preflight balances to the active run notification."""
    try:
        context = _notification_context_for(importer)
        if not isinstance(context, dict) or not statuses:
            return ()
        service = context.get("service")
        observer = getattr(service, "observe_sms_balances", None)
        if not callable(observer):
            return ()
        aggregate, last_activity_at = _notification_aggregate(importer, context)
        context["last_activity_at"] = last_activity_at or context.get(
            "last_activity_at",
            context.get("started_at", 0),
        )
        return observer(context.get("run_id"), aggregate, statuses)
    except Exception:
        # Notification delivery is advisory and must never abort registration.
        return ()


_notification_watchdog = _NOTIFICATION_LIFECYCLE.watchdog
_begin_notification_run = _NOTIFICATION_LIFECYCLE.begin
_cancel_notification_run = _NOTIFICATION_LIFECYCLE.cancel


def _patched_importer_start(self, settings):
    global _CURRENT_TASK_ADMISSION, _CURRENT_INFLIGHT_GATE
    global _CONNECTIVITY_PROXY, _CONNECTIVITY_BATCH_ID
    internal = copy.deepcopy(dict(settings or {}))
    additional_retries = _int_value(internal.get("auth_session_retries"), 1, minimum=0, maximum=4)
    internal["auth_session_retries"] = additional_retries + 1
    already_running = bool(self.status(internal).get("running"))
    preflight_sms_statuses = internal.pop(
        "_gptphone_sms_preflight_statuses",
        (),
    )
    task_admission = getattr(self, "task_admission", None)
    inflight_gate = getattr(self, "inflight_gate", None)
    staged_inflight = False
    node_phase_gate = None
    if not already_running:
        _SMS_QUALITY_GUARD.begin_run(
            _performance_runtime_ext.as_bool(
                internal.get("sms_quality_optimization"),
                True,
            ),
            baseline=internal.get("sms_optimization_baseline"),
        )
        admission_policy = _performance_runtime_ext.resolve_task_admission(
            internal.get("concurrency"),
            run_mode=internal.get("run_mode"),
            adaptive_enabled=internal.get("adaptive_task_concurrency"),
        )
        task_limit = admission_policy.base_limit
        internal["concurrency"] = task_limit
        node_limit = _int_value(
            internal.get("node_concurrency"),
            task_limit,
            minimum=1,
            maximum=task_limit,
        )
        phase_adaptive = admission_policy.adaptive and node_limit == task_limit
        phase_ceiling = (
            admission_policy.restore_ceiling if phase_adaptive else node_limit
        )
        node_phase_gate = _phase_concurrency_ext.AdjustablePhaseGate(
            node_limit,
            ceiling=phase_ceiling,
        )
        protocol_baseline = min(task_limit, node_limit)
        inflight_expansion = (
            str(internal.get("run_mode") or "register").strip().lower() == "register"
            and _performance_runtime_ext.as_bool(
                internal.get("task_inflight_optimization"),
                True,
            )
            and _int_value(
                internal.get("task_inflight_limit"),
                20,
                minimum=1,
                maximum=20,
            ) > task_limit
        )
        protocol_healthy_ceiling = (
            _int_value(
                internal.get("protocol_concurrency_ceiling"),
                12,
                minimum=8,
                maximum=15,
            )
            if inflight_expansion
            else protocol_baseline
        )
        next_proxy = str(internal.get("proxy") or "").strip()
        next_batch_id = str(internal.get("batch_id") or "").strip()
        with _OPENAI_CONNECTIVITY._callback_lock:
            _PROTOCOL_GATE.begin_run(
                protocol_baseline,
                healthy_ceiling=protocol_healthy_ceiling,
            )
            _OPENAI_CONNECTIVITY.begin_run(
                proxy=next_proxy,
                enabled=_performance_runtime_ext.as_bool(
                    internal.get("openai_connectivity_guard"), True,
                ),
            )
            _CONNECTIVITY_PROXY, _CONNECTIVITY_BATCH_ID = next_proxy, next_batch_id
        _SMS_PHONE_GATE.configure(
            _int_value(
                internal.get("phone_submission_concurrency"),
                2,
                minimum=1,
                maximum=5,
            )
        )
        _SMS_PHONE_GATE.begin_run()

        def log_task_limit_change(event):
            if phase_adaptive:
                try:
                    phase_limit = max(
                        1,
                        min(phase_ceiling, int((event or {}).get("new_limit") or task_limit)),
                    )
                    phase_reason = str((event or {}).get("reason") or "task_admission")
                    node_phase_gate.set_capacity(phase_limit, reason=phase_reason)
                    _PROTOCOL_GATE.synchronize_capacity(phase_limit)
                except Exception:
                    # Capacity observability must not break task state updates.
                    pass
            formatted = _performance_runtime_ext.format_task_admission_event(event)
            if formatted is None:
                return
            message, level = formatted
            try:
                self._log(message, level)
            except Exception:
                pass

        task_admission = _adaptive_concurrency_ext.AdaptiveConcurrencyGate(
            task_limit,
            ceiling=admission_policy.absolute_ceiling,
            restore_ceiling=admission_policy.restore_ceiling,
            # With the feature switch off this gate remains only as the
            # scheduler's compatibility wrapper.  It may pause for pressure,
            # but it must not alter the configured fixed task concurrency.
            minimum=(min(4, task_limit) if admission_policy.adaptive else task_limit),
            immediate_reset_limit=(task_limit if admission_policy.adaptive else None),
            adaptive_enabled=admission_policy.adaptive,
            require_backlog_for_restore=True,
            on_change=log_task_limit_change,
        )
        inflight_gate = None
        if str(internal.get("run_mode") or "register").strip().lower() != "relogin":
            inflight_baseline = (
                internal["task_inflight_baseline"]
                if "task_inflight_baseline" in internal
                else _SMS_QUALITY_GUARD.inflight_rollback_baseline()
            )
            inflight_gate = _performance_runtime_ext.InflightAdmissionGate(
                task_limit,
                limit=internal.get("task_inflight_limit", 20),
                enabled=internal.get("task_inflight_optimization", True),
                baseline=inflight_baseline,
                on_rollback=lambda event: self._log(
                    "[任务在途/task_inflight] 优化已自动回退到配置并发："
                    f"{event.get('reason', 'unknown')}",
                    "warn",
                ),
            )
        _CURRENT_TASK_ADMISSION = task_admission
        _CURRENT_INFLIGHT_GATE = inflight_gate
        _PROTOCOL_COORDINATOR.synchronize_connectivity_pause(
            _CONNECTIVITY_PROXY, inflight_gate,
        )
        staged_inflight = _inflight_pipeline_runtime_ext.optimization_active(
            inflight_gate
        )
        _TASK_PROGRESS.reset()
        with _TASK_FAILURES_LOCK:
            _TASK_FAILURES.clear()
    selection = set()
    for item in internal.get("_gptphone_run_mailbox_rows") or ():
        if not isinstance(item, dict):
            continue
        try:
            line_no = int(item.get("line_no") or 0)
        except (TypeError, ValueError):
            line_no = 0
        row_id = str(item.get("row_id") or "").strip().lower()
        if row_id and line_no > 0:
            selection.add((row_id, line_no))
    selection_token = _MAILBOX_RUN_SELECTION.set(frozenset(selection))
    priority_token = _MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.set(
        not selection
        and str(internal.get("run_mode") or "register").strip().lower() != "relogin"
    )
    lease_filter_token = None
    if str(internal.get("run_mode") or "").strip().lower() != "relogin":
        lease_filter_token = _MAILBOX_LEASE_FILTER_ACTIVE.set(True)
    notification_context = None

    def observed_phase_gate(limit, segment_code):
        return _importer_scheduler_ext.ObservedPhaseGate(
            _runtime.AutoEmailPhaseGate(limit),
            lambda elapsed: _record_task_segment(
                _TASK_CONTEXT.get(),
                segment_code,
                elapsed,
            ),
        )

    def observed_node_phase_gate(limit):
        gate = node_phase_gate or _runtime.AutoEmailPhaseGate(limit)
        return _importer_scheduler_ext.ObservedPhaseGate(
            gate,
            lambda elapsed: _record_task_segment(
                _TASK_CONTEXT.get(),
                "node_slot_waiting",
                elapsed,
            ),
        )

    def task_started(task_id, elapsed):
        _TASK_PROGRESS.mark_execution_started(task_id)
        _record_task_segment(task_id, "task_slot_waiting", elapsed)

    try:
        if not already_running:
            notification_context = _begin_notification_run(self, internal)
            _PROTOCOL_COORDINATOR.synchronize_connectivity_pause(
                _CONNECTIVITY_PROXY, inflight_gate,
                on_paused=lambda _state: _set_stall_notifications_suspended(True),
            )
        result = _importer_scheduler_ext.start_bounded_importer(
            self,
            internal,
            mailbox_error_type=_runtime.MailboxPoolError,
            manual_code_factory=_runtime.ManualCodeCoordinator,
            phase_gate_factory=_runtime.AutoEmailPhaseGate,
            task_admission=task_admission,
            inflight_gate=inflight_gate,
            staged_inflight=staged_inflight,
            email_phase_gate_factory=lambda limit: observed_phase_gate(
                limit,
                "email_slot_waiting",
            ),
            node_phase_gate_factory=observed_node_phase_gate,
            on_task_started=task_started,
            batch_manifest=_RUN_BATCH_MANIFEST,
            batch_reserve=_reserve_mailbox_batch,
        )
        if notification_context is not None:
            with self.lock:
                actual_target = len(self.tasks)
            if actual_target > 0:
                notification_context["target"] = actual_target
            aggregate, last_activity_at = _notification_aggregate(self, notification_context)
            notification_context["last_activity_at"] = last_activity_at or notification_context["started_at"]
            notification_context["service"].observe_run(notification_context["run_id"], aggregate)
            _notify_sms_balances(self, preflight_sms_statuses)
            monitor = threading.Thread(
                target=_notification_watchdog,
                args=(self, notification_context),
                name="run-notification-watchdog",
                daemon=True,
            )
            notification_context["monitor"] = monitor
            monitor.start()
        return result
    except Exception:
        if notification_context is not None:
            _cancel_notification_run(self, notification_context)
        if not already_running:
            if _CURRENT_TASK_ADMISSION is task_admission:
                _CURRENT_TASK_ADMISSION = None
            if _CURRENT_INFLIGHT_GATE is inflight_gate:
                _CURRENT_INFLIGHT_GATE = None
            _TASK_PROGRESS.reset()
            with _TASK_FAILURES_LOCK:
                _TASK_FAILURES.clear()
        raise
    finally:
        if lease_filter_token is not None:
            _MAILBOX_LEASE_FILTER_ACTIVE.reset(lease_filter_token)
        _MAILBOX_NEXT_BATCH_PRIORITY_ACTIVE.reset(priority_token)
        _MAILBOX_RUN_SELECTION.reset(selection_token)


def _patched_importer_run_one(
    self,
    settings,
    ordinal,
    assigned_entry=None,
    assigned_task_id="",
):
    run_mode = str((settings or {}).get("run_mode") or "register").strip().lower()
    task_id = str(assigned_task_id or "").strip()
    if not task_id:
        task_id = f"T{int(ordinal):03d}-{uuid.uuid4().hex[:6]}"
    _MAILBOX_TOTP_SECRET_CONTEXT.set("")
    _TASK_TOTP_SECRETS.clear(task_id)
    _TOTP_PATCHES.reset_task_state()
    _MANUAL_VERIFICATION.cancel_task(task_id)
    token = _RUN_MODE_CONTEXT.set(run_mode)
    task_token = _TASK_CONTEXT.set(task_id)
    checkpoint_token = _CHECKPOINT_CONTEXT.set(
        _checkpoint_context_for_entry(self, settings, assigned_entry, task_id)
    )
    admission_token = _TASK_ADMISSION_CONTEXT.set(getattr(self, "task_admission", None))
    try:
        return _ORIGINAL_IMPORTER_RUN_ONE(
            self,
            settings,
            ordinal,
            assigned_entry,
            task_id,
        )
    finally:
        transport = _transport_for_task(task_id)
        challenge_runtime = globals().get("_auth_challenge_runtime_ext")
        clear_challenge = getattr(challenge_runtime, "clear_transport_context", None)
        if callable(clear_challenge) and transport is not None:
            try:
                clear_challenge(transport)
            except Exception:
                pass
        if not _SMS_TRANSPORT_REGISTRY.close_task(task_id):
            _SMS_TRANSPORT_REGISTRY.close_task(task_id)
        _AUTH_SESSIONS.clear(task_id)
        _SMS_PROVIDER_REGISTRY.clear_task_attempt_counts(task_id)
        _MAILBOX_TOTP_SECRET_CONTEXT.set("")
        _TASK_TOTP_SECRETS.clear(task_id)
        _TOTP_PATCHES.reset_task_state()
        _MANUAL_VERIFICATION.cancel_task(task_id)
        if transport is not None:
            try:
                delattr(transport, "_gptphone_totp_manual_secret")
            except AttributeError:
                pass
        _PHASE1_CHECKPOINTS_COORDINATOR.release(transport)
        _TASK_ADMISSION_CONTEXT.reset(admission_token)
        _CHECKPOINT_CONTEXT.reset(checkpoint_token)
        _TASK_CONTEXT.reset(task_token)
        _RUN_MODE_CONTEXT.reset(token)


def _patched_importer_stop(self):
    stop_event = getattr(self, "stop_event", None)
    set_stopped = getattr(stop_event, "set", None)
    if callable(set_stopped):
        set_stopped()
    _MANUAL_VERIFICATION.cancel_all()
    _OPENAI_CONNECTIVITY.wake_waiters()
    _PROTOCOL_GATE.wake_all()
    context = _notification_context_for(self)
    if isinstance(context, dict):
        try:
            aggregate, _last_activity_at = _notification_aggregate(self, context)
            context["service"].mark_manual_stop(context["run_id"], aggregate)
        except Exception:
            pass
    return _importer_scheduler_ext.stop_bounded_importer(self)


def _unfinished_batch_task_ids(importer):
    terminal = set(_task_progress_ext.TERMINAL_TASK_STATUSES)
    rows = _notification_task_snapshot(importer)
    rows.sort(key=lambda task: _int_value(task.get("ordinal"), 0, minimum=0))
    return tuple(
        str(task.get("task_id") or "").strip()
        for task in rows
        if str(task.get("task_id") or "").strip()
        and str(task.get("status") or "").strip().lower() not in terminal
    )


def _reconcile_finished_batch(importer, context):
    manifest = getattr(importer, "_gptphone_batch_manifest", None)
    batch_id = str((context or {}).get("batch_id") or "").strip()
    if manifest is None or not batch_id:
        return None
    with importer.lock:
        tasks = copy.deepcopy(dict(importer.tasks))
    summary = manifest.finalize(
        batch_id,
        tasks=tasks,
        reason="watch_returned_with_unfinished_tasks",
    )
    terminal = set(_task_progress_ext.TERMINAL_TASK_STATUSES)
    reconciled = []
    for member in summary.get("members") or ():
        if not isinstance(member, dict) or not member.get("reconciled_missing"):
            continue
        task_id = str(member.get("task_id") or "").strip()
        current = tasks.get(task_id) if isinstance(tasks.get(task_id), dict) else {}
        if not task_id or str(current.get("status") or "").strip().lower() in terminal:
            continue
        cause = "任务未产生终态，已由批次清单补记失败"
        failure = _run_batch_runtime_ext.reconciliation_failure(
            "batch_member_missing_terminal",
            cause,
        )
        result = dict(current.get("result") or {})
        result.update(
            batch_id=batch_id,
            reconciled_by_batch_manifest=True,
            reconcile_reason="watch_returned_with_unfinished_tasks",
            failure=failure,
        )
        importer._task_state(
            task_id,
            status="failed",
            error=failure["public_message"],
            technical_error=failure["technical_summary"],
            failure=failure,
            result=result,
        )
        reconciled.append(task_id)
    if reconciled:
        importer._log(
            "[运行批次对账/batch_member_missing_terminal] "
            f"已补写 {len(reconciled)} 个缺失终态任务：{', '.join(reconciled)}",
            "warn",
        )
    return summary


def _patched_importer_watch(self):
    context = _notification_context_for(self)
    watch_failed = False
    try:
        return _ORIGINAL_IMPORTER_WATCH(self)
    except BaseException:
        watch_failed = True
        raise
    finally:
        if isinstance(context, dict):
            _importer_watch_runtime_ext.finalize_importer_watch(
                self,
                context,
                watch_failed=watch_failed,
                aggregate_fn=_notification_aggregate,
                unfinished_fn=_unfinished_batch_task_ids,
                reconcile_fn=_reconcile_finished_batch,
                sms_exhausted_fn=_SMS_PROVIDER_REGISTRY.is_exhausted,
            )
        admission = getattr(self, "task_admission", None)
        if admission is not None:
            try:
                capacity = admission.snapshot()
                self._log(
                    "[任务并发/registration_admission] 批次并发汇总："
                    f"基础 {capacity.get('base', 0)}，峰值 {capacity.get('peak_limit', 0)}，"
                    f"常规恢复 {capacity.get('restorations', 0)} 次，"
                    f"快速升档 {capacity.get('burst_promotions', 0)} 次，"
                    f"快速撤销 {capacity.get('burst_revocations', 0)} 次，"
                    f"降档 {capacity.get('degradations', 0)} 次，"
                    f"累计排队 {capacity.get('total_wait_seconds', 0)} 秒",
                    "info",
                )
            except Exception:
                pass
        try:
            with self.lock:
                active_task_ids = set(getattr(self, "active_task_ids", set()) or ())
                futures = list(getattr(self, "futures", ()) or ())
            futures_done = all(
                callable(getattr(future, "done", None)) and future.done()
                for future in futures
            )
            if not active_task_ids and futures_done:
                _SMS_TRANSPORT_REGISTRY.clear()
                pending = _SMS_TRANSPORT_REGISTRY.snapshot().get("pending_cleanup", 0)
                if pending:
                    self._log(
                        "[运行结束清理/transport_cleanup] "
                        f"仍有 {pending} 个 Transport 等待下次安全重试",
                        "warn",
                    )
        except Exception:
            pass


def _patched_pre_auth_session_retryable(result):
    if any(
        marker in str(result or "").lower()
        for marker in ("relogin_phone_required",)
    ):
        return False
    if _runtime_policy_ext.is_account_banned_failure(result):
        return False
    if _is_auth_session_reset_failure(result):
        # The recovered importer owns the configured whole-session retry
        # limit. Do not impose a second, hidden cap here.
        return True
    if _RUN_MODE_CONTEXT.get() == "relogin":
        return _runtime_policy_ext.is_relogin_transient_failure(result)
    if _runtime_policy_ext.should_retry_expired_sub2_session(result):
        return True
    return _ORIGINAL_PRE_AUTH_SESSION_RETRYABLE(result)


def _patched_password_credentials_rejected(result):
    if _RUN_MODE_CONTEXT.get() == "relogin":
        return False
    return _ORIGINAL_PASSWORD_CREDENTIALS_REJECTED(result)


def _as_enabled(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", "unchecked", "disabled"}


def _patched_persist_result(self, settings, task_id, entry, result, *, error="", status="failed"):
    persisted_settings = _result_persistence_runtime_ext.settings_with_absolute_results_dir(
        settings,
        self.data_dir,
    )
    if status == "success":
        _TASK_PROGRESS.set_stage(task_id, "finalizing_save")
    failure = None
    failure_statuses = set(_task_progress_ext.TERMINAL_TASK_STATUSES).difference(
        {"success", "stopped", "stopped_before_start"}
    )
    secrets = _failure_secrets(self, entry, settings)
    batch_id = str((settings or {}).get("batch_id") or "").strip()[:80]
    batch_started_at = _int_value((settings or {}).get("batch_started_at"), 0, minimum=0)
    if isinstance(result, dict):
        risk_status = _actionable_phone_risk_status(getattr(entry, "email", ""))
        if risk_status.get("active"):
            result["phone_risk_retry"] = True
            result["phone_risk_label"] = "手机号风控重试：已启用成熟线路优先"
            result["phone_risk_reason_code"] = str(
                risk_status.get("reason_code") or "oauth_session_invalid"
            )
        progress_snapshot = _TASK_PROGRESS.progress(task_id) or {}
        if isinstance(progress_snapshot.get("timing"), dict):
            result["timing"] = copy.deepcopy(progress_snapshot["timing"])
        run_mode = str((settings or {}).get("run_mode") or "").strip().lower()
        if run_mode == "relogin":
            result["run_mode"] = "relogin"
        if _is_auth_session_reset_failure(result, error):
            result["resume_stage"] = "fresh_oauth"
        if batch_id:
            result["batch_id"] = batch_id
            result["batch_started_at"] = batch_started_at
        _sms_cost_history_ext.attach_task_sms_cost(result, task_id, _SMS_COST_LEDGER, _SMS_EXCHANGE_RATE)
        if str(status or "").strip().lower() in failure_statuses:
            failure = _classify_task_failure(
                task_id,
                result,
                error,
                status=status,
                secrets=secrets,
            )
            result["failure"] = failure
            error = failure["public_message"]
    try:
        persisted = _ORIGINAL_PERSIST_RESULT(
            self,
            persisted_settings,
            task_id,
            entry,
            result,
            error=error,
            status=status,
        )
    except Exception as exc:
        _TASK_PROGRESS.set_stage(task_id, "finalizing_save")
        persistence_failure = _error_observability_ext.classify_failure(
            error=f"result_persistence_failed: {exc}",
            progress=_TASK_PROGRESS.progress(task_id),
            status="failed",
            secrets=secrets,
        )
        _remember_task_failure(task_id, persistence_failure)
        raise RuntimeError(persistence_failure["public_message"]) from exc
    _TASK_PROGRESS.finish(task_id)
    timing_snapshot = (_TASK_PROGRESS.progress(task_id) or {}).get("timing")
    if isinstance(timing_snapshot, dict):
        if isinstance(result, dict):
            result["timing"] = copy.deepcopy(timing_snapshot)
    metadata_persisted = _result_persistence_runtime_ext.apply_result_json_metadata(
        persisted_settings,
        self.data_dir,
        task_id,
        getattr(entry, "email", ""),
        timing=timing_snapshot if isinstance(timing_snapshot, dict) else None,
        batch_id=batch_id,
        batch_started_at=batch_started_at,
        failure=failure,
        status=status,
        account_banned_detail=_ACCOUNT_BANNED_DETAIL_CONTEXT.get(""),
        account_banned_message=_runtime_policy_ext.ACCOUNT_BANNED_MESSAGE,
        secrets=secrets,
        atomic_write_json=_runtime.atomic_write_json,
        sanitize_failure_detail=_error_observability_ext.sanitize_failure_detail,
        logger=getattr(self, "_log", None),
    )
    _sms_cost_history_ext.note_persisted_result(self.data_dir, persisted_settings, task_id, getattr(entry, "email", ""))
    if batch_id and metadata_persisted:
        try:
            _RUN_BATCH_MANIFEST.mark_persisted(batch_id, task_id, status)
        except KeyError:
            pass
        except Exception as exc:
            try:
                self._log(
                    "[运行批次对账/run_batch_manifest] 结果持久化计数更新失败"
                    f"（{type(exc).__name__}）",
                    "error",
                )
            except Exception:
                pass
    terminal_text = " ".join(
        str(value or "")
        for value in (
            error,
            result.get("error") if isinstance(result, dict) else "",
            result.get("error_code") if isinstance(result, dict) else "",
        )
    ).lower()
    if _phase1_checkpoint_hooks_ext.should_delete_checkpoint(
        status,
        invalid_session=_is_auth_session_reset_failure(result, error),
        values=(terminal_text,),
    ):
        _PHASE1_CHECKPOINTS_COORDINATOR.cleanup_terminal(
            identity=_checkpoint_context_for_entry(self, settings, entry, task_id)
        )
    return persisted


def _patched_retire_after_failure(self, settings, pool, entry, task_id, result, error):
    if str((settings or {}).get("run_mode") or "").strip().lower() == "relogin":
        safe_error = _error_observability_ext.sanitize_failure_detail(
            error,
            secrets=_failure_secrets(self, entry, settings),
        ) or "重登未返回错误详情"
        self._persist_result(
            settings,
            task_id,
            entry,
            result if isinstance(result, dict) else {},
            error=safe_error,
            status="failed",
        )
        try:
            pool.remove_entry(entry, reason="relogin_failed")
        except Exception:
            pass
        public_result = _runtime._public_result(result if isinstance(result, dict) else {})
        self._task_state(
            task_id,
            status="failed",
            error=safe_error,
            technical_error=safe_error,
            result=public_result,
        )
        try:
            self._log(f"{task_id} 无手机号重登失败: {safe_error}", "error")
        except Exception:
            pass
        return None
    if _is_auth_session_reset_failure(result, error):
        if isinstance(result, dict):
            result["resume_stage"] = "fresh_oauth"
    password_rejected = False
    if isinstance(result, dict):
        try:
            password_rejected = bool(self._password_credentials_rejected(result))
        except Exception:
            password_rejected = False
    if password_rejected:
        pool.mark_damaged_entry(entry, reason=_PASSWORD_DAMAGED_MESSAGE)
        self._persist_result(
            settings,
            task_id,
            entry,
            result,
            error=error,
            status="email_damaged",
        )
        public_result = _runtime._public_result(result)
        self._task_state(
            task_id,
            status="email_damaged",
            error=_PASSWORD_DAMAGED_MESSAGE,
            technical_error=_PASSWORD_DAMAGED_MESSAGE,
            result=public_result,
        )
        try:
            self._log(
                f"{task_id} [验证邮箱密码/email_password] {_PASSWORD_DAMAGED_MESSAGE}",
                "error",
            )
        except Exception:
            pass
        return None

    if not _runtime_policy_ext.is_account_banned_failure(result, error):
        return _ORIGINAL_RETIRE_AFTER_FAILURE(
            self,
            settings,
            pool,
            entry,
            task_id,
            result,
            error,
        )

    message = _runtime_policy_ext.ACCOUNT_BANNED_MESSAGE
    technical_detail = _SMS_WEB.pop_account_banned_detail(task_id)
    if not technical_detail:
        value = result if isinstance(result, dict) else {}
        technical_source = next(
            (
                value.get(key)
                for key in ("technical_error", "phase2_error", "error")
                if value.get(key)
            ),
            error,
        )
        technical_detail = _safe_runtime_error(technical_source)
    token = _ACCOUNT_BANNED_DETAIL_CONTEXT.set(str(technical_detail or message)[:1000])
    try:
        self._persist_result(
            settings,
            task_id,
            entry,
            result if isinstance(result, dict) else {},
            error=message,
            status="account_banned",
        )
    finally:
        _ACCOUNT_BANNED_DETAIL_CONTEXT.reset(token)

    removal_error = ""
    try:
        removed_from_pool = _mailbox_retention_ext.remove_banned_entry(
            pool,
            entry,
            _ORIGINAL_POOL_REMOVE_ENTRY,
            reason="account_banned",
        )
    except Exception as exc:
        removed_from_pool = False
        removal_error = _safe_runtime_error(exc)
    if not removed_from_pool:
        pool.mark_damaged_entry(entry, reason=message)

    public_result = _runtime._public_result(result if isinstance(result, dict) else {})
    if isinstance(public_result, dict):
        public_result = dict(public_result)
        for key in ("technical_error", "phase2_error", "local_oauth_exchange_error"):
            public_result.pop(key, None)
        if "error" in public_result:
            public_result["error"] = message
    self._task_state(
        task_id,
        status="account_banned",
        error=message,
        technical_error=message,
        result=public_result,
    )
    try:
        if removed_from_pool:
            self._log(f"{message}；已从邮箱池移除", "error")
        else:
            detail = removal_error or "未找到对应的邮箱源行"
            self._log(
                f"{task_id} [检查 OpenAI 账号状态/account_banned] {message}；"
                f"邮箱池移除失败：{detail}；已标记损坏",
                "error",
            )
    except Exception:
        pass
    return None


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
    _ORIGINAL_REAL_TRANSPORT_INIT(
        self,
        config,
        oauth_params=oauth_params,
        proxy=proxy,
        sentinel_provider=sentinel_provider,
        device_id=device_id,
        log_fn=log_fn,
    )
    runtime_config = config if isinstance(config, dict) else {}
    self.account_email = str(runtime_config.get("_auth_account_email") or "").strip().lower()
    self._gptphone_totp_refresh_in_headers = True
    self._gptphone_totp_manual_secret = ""
    self._gptphone_mfa_fresh_retry_generation = None
    self._gptphone_mfa_fresh_retry_markers = set()
    self._gptphone_checkpoint_restored = False
    _auth_request_runtime_ext.ensure_transport_context(self, _AUTH_SESSIONS, force_new=True)
    # The recovered transport creates curl_cffi sessions with certificate
    # verification disabled.  Free must not inherit that unsafe default; set
    # the session policy after construction without touching the recovered
    # runtime artifact.
    session = getattr(self, "session", None)
    if runtime_config.get("free_protocol_state_machine") and session is not None and hasattr(session, "verify"):
        try:
            session.verify = True
        except Exception:
            pass
    # Free's protocol state machine owns a fresh OAuth session and its single
    # controlled rebuild. Restoring a recovered Phase1 checkpoint here would
    # reintroduce ordinary SMS cookies/CSRF and make a supposedly new Free
    # authorization depend on another workflow's persisted state.
    is_free_protocol = bool(runtime_config.get("free_protocol_state_machine"))
    if _RUN_MODE_CONTEXT.get() != "relogin" and not is_free_protocol:
        # Keep bounded checkpoint recovery visible as its own OAuth node.
        _set_current_task_stage("oauth_session")
        restored = _PHASE1_CHECKPOINTS_COORDINATOR.restore(self)
        if not restored:
            _set_current_task_stage("oauth_create_node")
    elif is_free_protocol:
        _set_current_task_stage("oauth_create_node")
    _register_sms_transport(_transport_task_id(self), self)
    _ACTIVE_SMS_TRANSPORT.set(self)


def _is_free_transport(self) -> bool:
    """Return whether a recovered transport belongs to a Free workflow.

    The recovered transport is shared by ordinary SMS/OAuth and Free.  Keep
    the stricter TLS/environment policy scoped to Free so ordinary behavior is
    not changed accidentally.
    """
    config = getattr(self, "config", None)
    if not isinstance(config, dict):
        return False
    if config.get("free_protocol_state_machine") or config.get("free_register_no_phone"):
        return True
    return str(config.get("run_mode") or "").strip().lower().startswith("free_")


def _real_new_session(self, impersonate="chrome"):
    """Create a Free session with explicit TLS and proxy semantics.

    ``RealCodexTransport.initiate_oauth`` calls this method again when it
    rotates an impersonation or rebuilds an expired OAuth session.  The
    recovered implementation hard-codes ``verify=False`` and leaves
    ``trust_env`` enabled, which silently reintroduces the unsafe policy after
    ``__init__`` has applied its one-time fix.  Ordinary transports continue
    through the captured implementation unchanged.
    """
    if not _is_free_transport(self):
        return _ORIGINAL_REAL_NEW_SESSION(self, impersonate)

    session = None
    curl_requests = getattr(self, "_curl_requests", None)
    if bool(getattr(self, "_curl", False)) and curl_requests is not None:
        try:
            session = curl_requests.Session(
                impersonate=str(impersonate or "chrome"),
                verify=True,
                trust_env=False,
            )
        except TypeError:
            # A small number of curl_cffi-compatible test doubles do not
            # accept constructor keyword arguments; enforce the same policy
            # after creating the object.
            try:
                session = curl_requests.Session(impersonate=str(impersonate or "chrome"))
            except TypeError:
                session = curl_requests.Session()
    else:
        import requests

        session = requests.Session()

    try:
        session.verify = True
    except Exception:
        pass
    try:
        session.trust_env = False
    except Exception:
        pass

    # The registration proxy is explicit and remains fixed for this task.
    # Never merge values from the process environment into a Free session.
    proxy = str(getattr(self, "proxy", "") or "").strip()
    if proxy:
        try:
            session.proxies = {"http": proxy, "https": proxy}
        except Exception:
            pass
    return session


_real_import_phase1_session = _CHECKPOINT_AUTH_HOOKS.import_phase1_session


def _real_headers(self, flow, referer):
    headers = _ORIGINAL_REAL_HEADERS(self, flow, referer)
    _chatgpt_totp_ext.refresh_transport_totp_payload(self, flow)
    return _auth_request_runtime_ext.request_headers(self, headers)


_checkpoint_save_after_auth = _CHECKPOINT_AUTH_HOOKS.save_after_auth
_checkpoint_delete_after_auth = _CHECKPOINT_AUTH_HOOKS.delete_after_auth


def _observe_protocol_request_activity():
    _PROTOCOL_REQUEST_ACTIVITY.set(_PROTOCOL_REQUEST_ACTIVITY.get() + 1)


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
    stage = {
        "/api/accounts/email-otp/validate": "email_code_verifying",
        "/api/accounts/mfa/verify": "mfa_otp_verifying",
        "/api/accounts/phone-otp/validate": "sms_verifying",
    }.get(str(path), "oauth_authorize_node")
    _set_current_task_stage(stage)
    request_context = _auth_request_runtime_ext.begin_request(
        self,
        _AUTH_SESSIONS,
        endpoint=path,
        stage=stage,
    )
    try:
        response = _with_transport_protocol_lease(
            self,
            lambda: _ORIGINAL_REAL_POST_AUTH_JSON(
                self,
                path,
                payload,
                flow=flow,
                referer=referer,
                timeout=timeout,
            ),
        )
    except Exception as exc:
        if _auth_session_runtime_ext.is_session_invalid(exc):
            _checkpoint_delete_after_auth(self)
            _auth_request_runtime_ext.invalidate_auth_session(
                self,
                _AUTH_SESSIONS,
                exc,
                stage=str(request_context.get("stage") or "oauth_authorize_node"),
            )
        raise
    def _fresh_mfa_post_json(transport, fresh_path, fresh_payload, **kwargs):
        """Keep one-time MFA recovery inside the staged protocol gate."""
        return _with_transport_protocol_lease(
            transport,
            lambda: _ORIGINAL_REAL_POST_AUTH_JSON(
                transport,
                fresh_path,
                fresh_payload,
                **kwargs,
            ),
        )

    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        # Free's protocol state machine owns MFA phase boundaries and allows
        # only its own bounded resend/rebuild policy.  The ordinary SMS
        # recovery helper may issue a hidden challenge refresh here, which can
        # consume a second OTP before Free has recorded its baseline.
        _mfa_retry_attempted = False
    else:
        response, _mfa_retry_attempted = _mfa_retry_runtime_ext.retry_expired_mfa_step(
            self,
            path=path,
            payload=payload,
            response=response,
            generation=request_context.get("session_generation"),
            post_json=_fresh_mfa_post_json,
            pending_totp_payload=_chatgpt_totp_ext.pending_transport_totp_payload,
            success_fn=_codex_oauth_chain._is_success_response,
            auth_origin=_codex_oauth_chain.AUTH,
            timeout=timeout,
            log_fn=getattr(self, "log_fn", None),
        )
    finished = _auth_request_runtime_ext.finish_request(
        self,
        _AUTH_SESSIONS,
        request_context,
        response,
    )
    self._gptphone_last_request_context = finished
    if _auth_session_runtime_ext.is_session_invalid(response):
        _checkpoint_delete_after_auth(self)
        _auth_request_runtime_ext.invalidate_auth_session(
            self,
            _AUTH_SESSIONS,
            response,
            stage=str(request_context.get("stage") or "oauth_authorize_node"),
        )
    return response


def _observe_auth_step(transport, response, stage):
    _auth_request_runtime_ext.observe_auth_response(
        transport,
        _AUTH_SESSIONS,
        response,
        stage=stage,
    )
    page_type = _codex_oauth_chain._page_type(response)
    if _auth_request_runtime_ext.is_phone_page_type(page_type):
        provider = getattr(transport, "sentinel_provider", None)
        reset = getattr(provider, "reset", None)
        if callable(reset):
            reset()
        _auth_request_runtime_ext.mark_phone_ready(
            transport,
            _AUTH_SESSIONS,
            response,
            continue_url=_codex_oauth_chain._continue_url(response),
        )


def _real_submit_email_identifier(self, email):
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        # The recovered method retries an invalid authorize session internally
        # and may switch fingerprint after a challenge. Free's state machine
        # owns those policies, so perform exactly one POST here and let the
        # caller classify/rebuild it.
        response = _with_transport_protocol_lease(
            self,
            lambda: _ORIGINAL_REAL_POST_AUTH_JSON(
                self,
                "/api/accounts/authorize/continue",
                {"username": {"kind": "email", "value": email}},
                flow="authorize_continue",
                referer="https://auth.openai.com/log-in",
                timeout=30,
            ),
        )
    else:
        response = _ORIGINAL_REAL_SUBMIT_EMAIL_IDENTIFIER(self, email)
    _observe_auth_step(self, response, "email_identifier")
    if (
        not _codex_oauth_chain._is_success_response(response)
        or _codex_oauth_chain._page_type(response) != "email_otp_verification"
    ):
        if getattr(self, "_gptphone_free_protocol_state_machine", False):
            return response
        return _auth_challenge_runtime_ext.continue_if_needed(
            self, response, origin="submit_email"
        )

    # The successful browser trace explicitly resends after reaching the OTP
    # page. Merely receiving that page does not prove that an email was sent.
    _set_current_task_stage("email_code_waiting")
    continue_url = _codex_oauth_chain._continue_url(response)
    send_response = self.send_email_otp(continue_url)
    if not _codex_oauth_chain._is_success_response(send_response):
        cause = _codex_oauth_chain._error_text(send_response) or "发送接口未返回错误详情"
        failure = _error_observability_ext.classify_failure(
            result=send_response,
            error=cause,
            progress={"code": "email_code_waiting"},
            status="retryable_infra",
        )
        qualifiers = []
        status = _safe_response_status(send_response)
        if status is not None:
            qualifiers.append(f"HTTP {status}")
        provider_code = str(failure.get("provider_code") or "").strip().lower()
        if provider_code:
            qualifiers.append(provider_code)
        prefix = f"{' / '.join(dict.fromkeys(qualifiers))}: " if qualifiers else ""
        raise _codex_oauth_chain.CodexChainError(
            f"email_otp_send_failed: {prefix}{cause}"
        )
    self._gptphone_initial_email_otp_send_confirmed = True
    _call_log(
        getattr(self, "log_fn", None),
        "  [邮箱验证码发送/email_code_waiting] 首次邮箱验证码发送接口已确认",
        "info",
    )
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        return response
    return _auth_challenge_runtime_ext.continue_if_needed(
        self, response, origin="submit_email"
    )


def _real_verify_password(self, password):
    response = _TOTP_PATCHES.verify_password(self, password)
    _observe_auth_step(self, response, "email_password")
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        return response
    return _auth_challenge_runtime_ext.continue_if_needed(
        self, response, origin="password"
    )


def _manual_totp_fallback(self, response):
    error_code = _mfa_retry_runtime_ext.response_error_code(response)
    secret = str(getattr(self, "_gptphone_totp_manual_secret", "") or "").strip()
    task_id = _transport_task_id(self) or _TASK_CONTEXT.get()
    manual_generation = _manual_task_generation(task_id) if task_id else -1
    manual_attempted = (
        getattr(self, "_gptphone_totp_manual_retry_generation", None)
        == manual_generation
    )
    setattr(self, "_gptphone_totp_manual_fallback_consumed", manual_attempted)
    session_invalid = _auth_session_runtime_ext.is_session_invalid(response)
    if session_invalid:
        try:
            delattr(self, "_gptphone_totp_manual_secret")
        except AttributeError:
            pass
    if error_code == "incorrect_code" and secret and task_id and not session_invalid:
        setattr(self, "_gptphone_totp_manual_fallback_consumed", True)
        try:
            delattr(self, "_gptphone_totp_manual_secret")
        except AttributeError:
            pass
        _call_log(
            getattr(self, "log_fn", None),
            "  [2FA/mfa_otp_verifying] 动态码自动验证失败，不打开人工输入",
            "warn",
        )
    elif error_code == "incorrect_code" and manual_attempted:
        try:
            delattr(self, "_gptphone_totp_manual_secret")
        except AttributeError:
            pass
    return response


def _real_verify_mfa_otp(self, code):
    response = _manual_totp_fallback(self, _TOTP_PATCHES.verify_mfa_otp(self, code))
    _checkpoint_save_after_auth(self, response)
    _observe_auth_step(self, response, "mfa_otp_verifying")
    if (
        getattr(self, "_gptphone_totp_manual_fallback_consumed", False)
        and _mfa_retry_runtime_ext.response_error_code(response) == "incorrect_code"
    ):
        return response
    if getattr(self, "_gptphone_free_protocol_state_machine", False):
        return response
    return _auth_challenge_runtime_ext.continue_if_needed(
        self, response, origin="mfa"
    )


def _real_send_mfa_otp(self, continue_url=""):
    _set_current_task_stage("mfa_otp_verifying")
    return _with_transport_protocol_lease(
        self,
        lambda: _TOTP_PATCHES.send_mfa_otp(self, continue_url),
    )


class _ReloginPhoneOtpProvider:
    """Hard stop for relogin tasks before any SMS provider can be called."""

    @staticmethod
    def get_number(**_kwargs):
        _set_current_task_stage("phone_acquiring")
        raise _codex_oauth_chain.CodexChainError(
            "relogin_phone_required: 重登进入手机号验证页面，已停止且未调用接码平台"
        )

    @staticmethod
    def mark_ready(_lease):
        return None

    @staticmethod
    def wait_code(_lease, timeout=180):
        del timeout
        raise _codex_oauth_chain.CodexChainError(
            "relogin_phone_required: 重登禁止等待短信验证码"
        )

    @staticmethod
    def complete(_lease):
        return None

    @staticmethod
    def cancel(_lease, reason=""):
        del reason
        return None


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
    runtime_config = config if isinstance(config, dict) else {}
    task_id_hint = _oauth_mfa_runtime_ext.runtime_task_id(
        runtime_config,
        context_task_get=_TASK_CONTEXT.get,
        transport=transport,
        transport_task_id_get=_transport_task_id,
    )
    bound_totp_task_id = _oauth_mfa_runtime_ext.bind_provider_totp_secret(
        email_otp_provider,
        _TASK_TOTP_SECRETS,
        task_id=task_id_hint,
        current_task_get=_TASK_CONTEXT.get,
    )
    if str(runtime_config.get("run_mode") or "").strip().lower() == "relogin":
        phone_otp_provider = _ReloginPhoneOtpProvider()
    runtime_config["_auth_account_email"] = str(account_email or "").strip().lower()
    if transport is not None:
        transport.config = runtime_config
        transport.account_email = runtime_config["_auth_account_email"]
        _auth_challenge_runtime_ext.bind_transport_context(
            transport,
            account_email=account_email,
            password=password,
            email_otp_provider=email_otp_provider,
            config=runtime_config,
            log_fn=log_fn,
            page_type_fn=_codex_oauth_chain._page_type,
            continue_url_fn=_codex_oauth_chain._continue_url,
            success_fn=_codex_oauth_chain._is_success_response,
        )
        existing_context = getattr(transport, "_gptphone_request_context", None)
        expected_task_id = task_id_hint
        request_context = _auth_request_runtime_ext.ensure_transport_context(
            transport,
            _AUTH_SESSIONS,
            force_new=bool(
                existing_context is None
                or getattr(existing_context, "task_id", "") != expected_task_id
            ),
        )
        del request_context
        _register_sms_transport(expected_task_id, transport)
    transport_token = _ACTIVE_SMS_TRANSPORT.set(transport)
    protocol_activity_token = _PROTOCOL_REQUEST_ACTIVITY.set(0)
    task_id = task_id_hint

    def record_protocol_wait(elapsed_seconds):
        _record_task_segment(
            task_id,
            "protocol_slot_waiting",
            elapsed_seconds,
        )

    def log_protocol_limit_change(event):
        value = dict(event or {})
        old_limit = int(value.get("old_limit") or 0)
        new_limit = int(value.get("new_limit") or 0)
        if old_limit <= 0 or new_limit <= 0 or old_limit == new_limit:
            return
        restored = str(value.get("kind") or "") == "restored"
        reason = "连续成功后恢复" if restored else "60 秒内连接压力达到阈值"
        _call_log(
            log_fn,
            f"  [并发保护] 协议并发 {old_limit} -> {new_limit}（{reason}）",
            "info" if restored else "warn",
        )

    staged_pipeline = _inflight_pipeline_runtime_ext.optimization_active(
        globals().get("_CURRENT_INFLIGHT_GATE")
    ) and str(runtime_config.get("run_mode") or "register").strip().lower() != "relogin"
    try:
        with _inflight_pipeline_runtime_ext.protocol_session_scope(
            staged=staged_pipeline,
            gate=_PROTOCOL_GATE,
            proxy=proxy,
            stop_event=runtime_config.get("_stop_requested"),
            on_wait=record_protocol_wait,
        ):
            try:
                result = _ORIGINAL_RUN_CODEX_AFTER_REGISTRATION(
                    oauth_url=oauth_url,
                    code_verifier=code_verifier,
                    account_email=account_email,
                    password=password,
                    phase1_register=phase1_register,
                    phase1_response=phase1_response,
                    phase1_continue_url=phase1_continue_url,
                    sms_provider=sms_provider,
                    config=runtime_config,
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
            except Exception as exc:
                main_chain_pressure, pressure_failure = _is_main_chain_pressure_source(
                    task_id,
                    exc,
                )
                has_request_activity = _PROTOCOL_REQUEST_ACTIVITY.get() > 0
                if main_chain_pressure and not has_request_activity:
                    _PROTOCOL_COORDINATOR.observe_main_chain_outcome(
                        exc,
                        succeeded=False,
                        task_id=task_id,
                        proxy=proxy,
                        failure=pressure_failure,
                        on_limit_change=log_protocol_limit_change,
                    )
                raise
            else:
                failure_value = result
                if isinstance(result, dict):
                    failure_value = " ".join(
                        str(result.get(key) or "")
                        for key in ("error", "technical_error", "phase2_error")
                    )
                succeeded = bool(isinstance(result, dict) and result.get("ok"))
                main_chain_pressure, pressure_failure = _is_main_chain_pressure_source(
                    task_id,
                    result if isinstance(result, dict) else failure_value,
                )
                pressure_signal_value = (
                    result if isinstance(result, dict) else failure_value
                )
                has_request_activity = _PROTOCOL_REQUEST_ACTIVITY.get() > 0
                if (succeeded or main_chain_pressure) and not has_request_activity:
                    _PROTOCOL_COORDINATOR.observe_main_chain_outcome(
                        pressure_signal_value,
                        succeeded=succeeded,
                        task_id=task_id,
                        proxy=proxy,
                        failure=pressure_failure,
                        on_limit_change=log_protocol_limit_change,
                    )
    finally:
        runtime_config.pop("phase1_active_session", None)
        _PROTOCOL_REQUEST_ACTIVITY.reset(protocol_activity_token)
        _ACTIVE_SMS_TRANSPORT.reset(transport_token)
        _oauth_mfa_runtime_ext.clear_task_secrets(
            _TASK_TOTP_SECRETS,
            task_id,
            bound_totp_task_id,
        )
        if task_id and _TASK_CONTEXT.get() != task_id:
            _SMS_TRANSPORT_REGISTRY.close_task(task_id)
            _AUTH_SESSIONS.clear(task_id)
    if isinstance(result, dict) and _is_auth_session_reset_failure(result):
        result = dict(result)
        result["resume_stage"] = "fresh_oauth"
        runtime_config.pop("phase1_active_session", None)
        task_id = str(runtime_config.get("sms_task_id") or runtime_config.get("run_id") or "")
        if task_id:
            context = _AUTH_SESSIONS.get(task_id, email=account_email)
            result["auth_session_invalid_count"] = int(context.invalidations)
            result["sms_platform_attempts"] = _SMS_PROVIDER_REGISTRY.snapshot_task_attempt_counts(
                task_id
            )
    elif isinstance(result, dict):
        task_id = str(runtime_config.get("sms_task_id") or runtime_config.get("run_id") or "")
        if task_id:
            result = dict(result)
            result["sms_platform_attempts"] = _SMS_PROVIDER_REGISTRY.snapshot_task_attempt_counts(
                task_id
            )
    if isinstance(result, dict) and result.get("ok"):
        _clear_known_node_failure(str(runtime_config.get("sms_task_id") or ""))
    return result


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
                except Exception:
                    pass

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


_manual_task_generation = lambda task_id: _oauth_mfa_runtime_ext.task_generation(task_id, _AUTH_SESSIONS.public_snapshot)
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


def _manual_email_wait(provider, email, automatic_wait):
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
_codex_oauth_chain.RealCodexTransport.send_email_otp = _real_send_email_otp
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
    if _LOCAL_CONFIG_FILE.exists():
        try:
            value = json.loads(_LOCAL_CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    else:
        value = {}
    if not isinstance(value, dict):
        value = {}
    changed = False
    if "nvtoken" in value or "nvtoken_upload" in value or "pixel_upload_enabled" in value:
        value.pop("nvtoken", None)
        value.pop("nvtoken_upload", None)
        value.pop("pixel_upload_enabled", None)
        changed = True
    value, timeout_migrated = _migrate_email_timeout_config(value)
    value, email_proxy_scope_migrated = _migrate_email_proxy_scope_config(value)
    value, performance_migrated = _sms_runtime_ext.migrate_performance_config(value)
    if changed or timeout_migrated or email_proxy_scope_migrated or performance_migrated:
        _write_local_config(value)
    return value


def _write_local_config(data):
    value = dict(data) if isinstance(data, dict) else {}
    previous = _read_store_config(_LOCAL_CONFIG_FILE)
    if "email_proxy_scope_strategy_version" not in value:
        prior_version = previous.get("email_proxy_scope_strategy_version")
        if prior_version is not None:
            value["email_proxy_scope_strategy_version"] = prior_version
    if "proxy_scope" not in value and isinstance(previous.get("proxy_scope"), dict):
        value["proxy_scope"] = copy.deepcopy(previous["proxy_scope"])
    value = _free_register_config_ext.strip_legacy_free_config(value)
    value.pop("nvtoken", None)
    value.pop("nvtoken_upload", None)
    value.pop("pixel_upload_enabled", None)
    value, _timeout_migrated = _migrate_email_timeout_config(value)
    value, _email_proxy_scope_migrated = _migrate_email_proxy_scope_config(value)
    value, _performance_migrated = _sms_runtime_ext.migrate_performance_config(value)
    _atomic_write_private_json(_LOCAL_CONFIG_FILE, value)
    phone_gate = globals().get("_SMS_PHONE_GATE")
    if phone_gate is not None:
        try:
            phone_gate.configure(value.get("phone_submission_concurrency", 2))
        except Exception:
            pass
    connectivity = globals().get("_OPENAI_CONNECTIVITY")
    if connectivity is not None:
        try:
            guard_enabled = _performance_runtime_ext.as_bool(
                value.get("openai_connectivity_guard"),
                True,
            )
            was_paused = bool(connectivity.snapshot().get("paused"))
            connectivity.set_enabled(guard_enabled)
            if was_paused and not guard_enabled:
                _PROTOCOL_GATE.resume_connectivity(_CONNECTIVITY_PROXY)
                resume = getattr(globals().get("_CURRENT_INFLIGHT_GATE"), "resume", None)
                if callable(resume):
                    resume()
                _set_stall_notifications_suspended(False)
            connectivity.configure_proxy(value.get("proxy") or "")
        except Exception:
            pass
    return value


# Copy the pre-existing Free files once, then keep the ordinary runtime config
# free of Free mailbox, proxy, target and driver settings.
_FREE_CONFIG_MIGRATION = _FREE_CONFIG_STORE.migrate_legacy(_read_local_config(), _RUNTIME_DATA_DIR)
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
)
_FREE_REGISTER = _free_register_runtime_ext.FreeRegisterManager(
    _FREE_DATA_DIR,
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
)


_masked_local_config = _PUBLIC_STATE.masked_local_config


def _public_task(task):
    public = _PUBLIC_STATE.public_task(task)
    task_id = str((task or {}).get("task_id") or "").strip() if isinstance(task, dict) else ""
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
    return str(task_id or "").strip() in tasks


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
    return _mailbox_admin_factory_ext.build_mailbox_admin(
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
    pixel_payload_builder=_pixel_runtime_ext.build_pixel_import_payload,
    run_batch_manifest=_RUN_BATCH_MANIFEST,
    free_register_manager=_FREE_REGISTER,
    query_sms_balances=_SMS_WEB.query_balances,
    online_mailbox_client_factory=_online_mailbox_client_factory,
    failure_secrets=lambda config: _failure_secrets(settings=config),
    free_config_store=_FREE_CONFIG_STORE,
    free_data_dir=_FREE_DATA_DIR,
)


def _patch_flask_app(app):
    original_start = app.view_functions.get("start")
    route_values = _closure_values(original_start) if callable(original_start) else {}
    patched = _web_routes_ext.patch_flask_app(app, _WEB_ROUTE_CONTEXT)
    # Payment and network tools own their stores and routes; they do not use
    # the ordinary SMS or Free task stores beyond explicit Free Token lookup.
    tools_root = _FREE_DATA_DIR.parent
    _payment_tools_routes_ext.install_payment_routes(
        patched, module=_module, data_root=tools_root, free_manager=_FREE_REGISTER,
    )
    _network_tools_routes_ext.install_network_routes(
        patched, module=_module, data_root=tools_root,
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
        task_generation=_manual_task_generation,
    )


def create_app(data_dir=None):
    return _patch_flask_app(_ORIGINAL_CREATE_APP(data_dir))


_module.create_app = create_app
if hasattr(_module, "app"):
    _module.app = _patch_flask_app(_module.app)


__doc__ = _module.__doc__
__all__ = [name for name in globals() if not name.startswith("_")]
