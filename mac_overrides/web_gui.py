"""Mac launcher overrides for the recovered web GUI."""

from __future__ import annotations

from contextvars import ContextVar
import importlib.util
import copy
import html
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from flask import send_from_directory as _send_from_directory

import codex_oauth_chain as _codex_oauth_chain
import chatgpt_totp as _chatgpt_totp_ext
import error_observability as _error_observability_ext
import imap_poller as _imap_poller
import importer_scheduler as _importer_scheduler_ext
import legacy_ui as _legacy_ui_ext
import mailbox_admin as _mailbox_admin_ext
import mailbox_retention as _mailbox_retention_ext
import pixel_runtime as _pixel_runtime_ext
import run_notifications as _run_notifications_ext
import runtime as _runtime
import runtime_policy as _runtime_policy_ext
import sms_providers as _sms_providers
import sms_runtime as _sms_runtime_ext
import sms_selector as _sms_selector
import sms_web as _sms_web_ext
import sub2_runtime as _sub2_runtime_ext
import task_progress as _task_progress_ext
import web_routes as _web_routes_ext


APP_DIR = Path(__file__).resolve().parent.parent
BUSINESS_DIR = APP_DIR / "business_pyc"
ORIGINAL_WEB_GUI = BUSINESS_DIR / "web_gui.pyc"
_RUNTIME_DATA_DIR = Path(
    os.environ.get("GPTPHONE_DATA_DIR") or APP_DIR / "data"
).expanduser().resolve()
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
_ORIGINAL_OUTLOOK_OTP_PROVIDER = _runtime.OutlookMailboxOtpProvider
_ORIGINAL_MAILBOX_URL_FETCH_RAW = _runtime.MailboxUrlCodeProvider.fetch_raw
_ORIGINAL_URL_MAILBOX_WAIT_CODE = _runtime.UrlMailboxOtpProvider.wait_code
_ORIGINAL_ACCOUNT_LABEL = _runtime.EmailAuthImporter._account_label
_ORIGINAL_REAL_VERIFY_PASSWORD = _codex_oauth_chain.RealCodexTransport.verify_password
_ORIGINAL_REAL_VERIFY_EMAIL_OTP = _codex_oauth_chain.RealCodexTransport.verify_email_otp
_ORIGINAL_REAL_VERIFY_MFA_OTP = _codex_oauth_chain.RealCodexTransport.verify_mfa_otp
_ORIGINAL_REAL_SEND_MFA_OTP = _codex_oauth_chain.RealCodexTransport.send_mfa_otp
_ORIGINAL_REAL_INITIATE_OAUTH = _codex_oauth_chain.RealCodexTransport.initiate_oauth
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
_ORIGINAL_PRE_AUTH_SESSION_RETRYABLE = _runtime.EmailAuthImporter._pre_auth_session_retryable
_ORIGINAL_CREATE_PROVIDER = _sms_providers.create_provider
_ORIGINAL_SMS_ADAPTER_GET_NUMBER = _codex_oauth_chain.SmsProviderAdapter.get_number
_ORIGINAL_SMS_ADAPTER_WAIT_CODE = _codex_oauth_chain.SmsProviderAdapter.wait_code
_ORIGINAL_SMS_ADAPTER_COMPLETE = _codex_oauth_chain.SmsProviderAdapter.complete
_ORIGINAL_SMS_ADAPTER_CANCEL = _codex_oauth_chain.SmsProviderAdapter.cancel
_ORIGINAL_REAL_SEND_PHONE_NUMBER_OTP = _codex_oauth_chain.RealCodexTransport.send_phone_number_otp
_ORIGINAL_SMART_CLASSIFY_ERROR = _sms_selector.SmartSmsSelector.classify_error
_ORIGINAL_SMART_RECORD_RESULT = _sms_selector.SmartSmsSelector.record_result
_ORIGINAL_CHAIN_EVENT = _codex_oauth_chain._event
_SMS_PRIORITY_COUNTRIES = ()
_SMS_MIN_PRICE_DEFAULT = 0.01
_SMS_MAX_PRICE_DEFAULT = "0.1"
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
_SMS_COST_LEDGER = _sms_runtime_ext.SmsCostLedger()
_SMS_EXCHANGE_RATE = _sms_runtime_ext.ExchangeRateCache(_RUNTIME_DATA_DIR / "usd_cny_rate.json")
_SMS_PHONE_GATE = _sms_runtime_ext.PhoneSubmissionGate(concurrency=2, interval_seconds=0.75)
_SMS_ROUTE_POLICY = _sms_runtime_ext.SmsRoutePolicy()
_SMS_ALERTS = _sms_runtime_ext.RuntimeAlertBuffer()
_TASK_PROGRESS = _task_progress_ext.TaskProgressTracker()
_TASK_CONTEXT: ContextVar[str] = ContextVar("gptphone_task_id", default="")
_MAILBOX_TOTP_SECRET_CONTEXT: ContextVar[str] = ContextVar("gptphone_mailbox_totp_secret", default="")
_ACCOUNT_BANNED_DETAIL_CONTEXT: ContextVar[str] = ContextVar(
    "gptphone_account_banned_detail",
    default="",
)
_PASSWORD_DAMAGED_MESSAGE = "OpenAI 登录密码验证失败，请检查账号密码；手动恢复后才会重跑"
_HISTORICAL_SUCCESS_REASONS = frozenset({"sub2_uploaded"})
_TASK_FAILURES: dict[str, dict] = {}
_TASK_FAILURES_LOCK = threading.RLock()
_RUN_LIFECYCLE_LOCK = threading.Lock()
_RUN_NOTIFICATION_LOCK = threading.RLock()
_RUN_NOTIFICATION_CONTEXT = None


def _safe_runtime_error(error):
    value = _module._safe(error) if hasattr(_module, "_safe") else str(error)
    return _SMS_KEY_POOL.safe_error(value)


def _failure_secrets(importer=None, entry=None, settings=None):
    values = []
    if importer is not None and entry is not None:
        try:
            source_row = str(importer._source_row(entry) or "")
            values.extend(_mailbox_admin_ext.MailboxAdminService._row_secrets(source_row))
        except Exception:
            pass
    for name in ("password", "totp_secret", "client_id", "refresh_token"):
        value = str(getattr(entry, name, "") or "") if entry is not None else ""
        if value:
            values.append(value)
    config = settings if isinstance(settings, dict) else {}
    sub2api = config.get("sub2api") if isinstance(config.get("sub2api"), dict) else {}
    notification = (
        config.get("email_notification")
        if isinstance(config.get("email_notification"), dict)
        else {}
    )
    values.extend(_sms_keys_from_config(config))
    values.extend(
        (
            config.get("gptmail_api_key"),
            sub2api.get("password"),
            notification.get("password"),
            *_mailbox_admin_ext.url_credential_secrets(config.get("proxy")),
        )
    )
    return tuple(dict.fromkeys(str(item) for item in values if str(item or "")))


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
        _SMS_KEY_POOL.safe_error(redacted),
        limit=800,
    )
    if re.search(r"\[[^\]]+/[a-z0-9_]+\]", safe, re.IGNORECASE) or safe.startswith("Pixel "):
        return safe
    lower = safe.lower()
    if not any(marker in lower for marker in _FAILURE_LOG_MARKERS):
        return _ORIGINAL_FRIENDLY_LOG_MESSAGE(safe)
    match = _TASK_ID_LOG_RE.search(safe)
    task_id = match.group(1) if match else _TASK_CONTEXT.get()
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


def _read_store_config(store):
    try:
        value = json.loads(Path(store.path).read_text(encoding="utf-8-sig"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _write_store_config(store, value):
    path = Path(store.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _patched_config_load(self):
    raw = _read_store_config(self)
    removed_legacy_fields = False
    for key in ("nvtoken", "nvtoken_upload"):
        if key in raw:
            raw.pop(key, None)
            removed_legacy_fields = True
    defaults = _runtime.default_settings(self.data_dir)
    if "sms_mode" not in raw:
        smart = raw.get("sms_smart") if isinstance(raw.get("sms_smart"), dict) else {}
        defaults["sms_mode"] = "smart" if _runtime._as_bool(smart.get("enabled"), True) else "fixed"

    loaded = _runtime._merge(defaults, raw)
    changed = self._enforce_private_paths(loaded, defaults)

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
    pixel_upload_enabled = _as_enabled(raw.get("pixel_upload_enabled"), True)
    if normalized.get("pixel_upload_enabled") != pixel_upload_enabled:
        changed = True
    normalized["pixel_upload_enabled"] = pixel_upload_enabled
    policy_keys = (
        "performance_policy_version",
        "phone_max_attempts",
        "phone_session_cycle_seconds",
        "auth_session_retries",
        "sms_api_keys",
        "sms_api_key",
    )
    if migrated or any(raw.get(key) != normalized.get(key) for key in policy_keys):
        changed = True
    if changed or removed_legacy_fields:
        _write_store_config(self, normalized)
    return normalized


def _patched_config_save(self, values):
    cleaned = dict(values or {})
    cleaned.pop("nvtoken", None)
    cleaned.pop("nvtoken_upload", None)
    normalized, _migrated = _sms_runtime_ext.migrate_performance_config(cleaned)
    saved = dict(_ORIGINAL_CONFIG_SAVE(self, normalized) or {})
    for key in (
        "performance_policy_version",
        "phone_max_attempts",
        "phone_session_cycle_seconds",
        "auth_session_retries",
        "sms_api_keys",
        "sms_api_key",
    ):
        saved[key] = normalized[key]
    _write_store_config(self, saved)
    return saved


def _patched_task_config(self, settings, email, task_id, *, password=""):
    config = _ORIGINAL_TASK_CONFIG(self, settings, email, task_id, password=password)
    keys = _sms_runtime_ext.normalize_sms_keys(
        (settings or {}).get("sms_api_keys"),
        (settings or {}).get("sms_api_key"),
    )
    attempts = _int_value((settings or {}).get("phone_max_attempts"), 15, minimum=1, maximum=15)
    phone_seconds = _int_value(
        (settings or {}).get("phone_session_cycle_seconds"),
        480,
        minimum=30,
        maximum=480,
    )
    route_lease_seconds = _int_value(config.get("code_timeout"), 30, minimum=5, maximum=300) + 20
    config.update(
        {
            "sms_api_keys": keys,
            "sms_api_key": keys[0] if keys else "",
            "sms_task_id": str(task_id),
            "phone_max_attempts": attempts,
            "phone_session_cycle_seconds": phone_seconds,
            "phone_session_max_seconds": phone_seconds,
            "phone_retry_sleep_seconds": 2,
        }
    )
    config["smsbower"] = {
        **dict(config.get("smsbower") or {}),
        "api_key": keys[0] if keys else "",
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
        "timeout_cooldown": 0,
        "phone_rejected_cooldown": 600,
        "register_rejected_cooldown": 60,
        "register_rejected_min_cooldown": 180,
    }
    return config


def _set_current_task_stage(code):
    task_id = _TASK_CONTEXT.get()
    if task_id:
        _TASK_PROGRESS.set_stage(task_id, code)


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
    return _runtime_policy_ext.call_with_transient_pre_auth_retry(
        lambda: _ORIGINAL_REAL_INITIATE_OAUTH(self, oauth_url),
        attempts=2,
        delay_seconds=0.25,
        stop_requested=stop_requested if callable(stop_requested) else None,
        on_retry=on_retry,
        retry_result=True,
    )


def _real_create_account_profile(self, name, birthdate):
    _set_current_task_stage("finalizing_profile")
    return _ORIGINAL_REAL_CREATE_ACCOUNT_PROFILE(self, name, birthdate)


def _real_accept_consent(self, continue_url=""):
    _set_current_task_stage("finalizing_callback")
    return _ORIGINAL_REAL_ACCEPT_CONSENT(self, continue_url)


def _real_follow_continue_until_code(self, continue_url, oauth_params, *, _reauth=False):
    _set_current_task_stage("finalizing_callback")
    return _ORIGINAL_REAL_FOLLOW_CONTINUE_UNTIL_CODE(
        self,
        continue_url,
        oauth_params,
        _reauth=_reauth,
    )


def _real_exchange_code(self, code, code_verifier, client_id, redirect_uri, account_email):
    _set_current_task_stage("finalizing_token")
    return _ORIGINAL_REAL_EXCHANGE_CODE(
        self,
        code,
        code_verifier,
        client_id,
        redirect_uri,
        account_email,
    )


def _sub2_session_exchange(self, *, code, account_email):
    _set_current_task_stage("finalizing_token")
    return _ORIGINAL_SUB2_SESSION_EXCHANGE(self, code=code, account_email=account_email)


def _real_sub2_upload(self, *, credentials, email):
    _set_current_task_stage("finalizing_upload")
    return _ORIGINAL_REAL_SUB2_UPLOAD(self, credentials=credentials, email=email)


def _patched_task_state(self, task_id: str, **values):
    values = dict(values)
    status = str(values.get("status") or "").strip().lower()
    failure_statuses = set(_task_progress_ext.TERMINAL_TASK_STATUSES).difference(
        {"success", "stopped", "stopped_before_start"}
    )
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
    result = _ORIGINAL_TASK_STATE(self, task_id, **values)
    if status == "authorizing":
        _TASK_CONTEXT.set(str(task_id or ""))
    _TASK_PROGRESS.observe_task_state(task_id, status)
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
    return _ORIGINAL_CHAIN_EVENT(
        events,
        state,
        detail=detail,
        extra=extra,
        log_fn=log_fn,
        tag=tag,
    )


def _notification_task_snapshot(importer):
    try:
        with importer.lock:
            return [copy.deepcopy(dict(task)) for task in importer.tasks.values()]
    except Exception:
        return []


def _notification_aggregate(importer, context=None, *, finished=False):
    tasks = _notification_task_snapshot(importer)
    terminal = set(_task_progress_ext.TERMINAL_TASK_STATUSES)
    succeeded = 0
    failed = 0
    stopped = 0
    active = 0
    pending = 0
    cost_cny = 0.0
    last_activity_at = 0
    for task in tasks:
        status = str(task.get("status") or "").strip().lower()
        if status == "success":
            succeeded += 1
        elif status in {"stopped", "stopped_before_start"}:
            stopped += 1
        elif status in terminal:
            failed += 1
        elif status == "queued":
            pending += 1
        else:
            active += 1
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        try:
            cost_cny += float(result.get("sms_cost_cny") or task.get("sms_cost_cny") or 0)
        except (TypeError, ValueError):
            pass
        tracked_progress = _TASK_PROGRESS.progress(str(task.get("task_id") or "")) or {}
        for candidate in (
            task.get("updated_at"),
            task.get("created_at"),
            (task.get("progress") or {}).get("entered_at") if isinstance(task.get("progress"), dict) else 0,
            tracked_progress.get("entered_at") if isinstance(tracked_progress, dict) else 0,
        ):
            try:
                last_activity_at = max(last_activity_at, int(candidate or 0))
            except (TypeError, ValueError):
                pass

    value = context if isinstance(context, dict) else {}
    started_at = int(value.get("started_at") or 0)
    finished_at = int(value.get("finished_at") or (time.time() if finished else 0))
    duration_end = finished_at or int(time.time())
    duration_seconds = max(0, duration_end - started_at) if started_at else 0
    aggregate = _run_notifications_ext.RunAggregate(
        total=len(tasks),
        succeeded=succeeded,
        failed=failed,
        stopped=stopped,
        active=active,
        pending=pending,
        duration_seconds=duration_seconds,
        cost_cny=cost_cny,
        started_at=started_at,
        finished_at=finished_at,
        last_activity_at=last_activity_at,
    )
    return aggregate, last_activity_at


def _notification_context_for(importer=None):
    if importer is not None:
        value = getattr(importer, "_gptphone_notification_context", None)
        if isinstance(value, dict):
            return value
    with _RUN_NOTIFICATION_LOCK:
        return _RUN_NOTIFICATION_CONTEXT


def _notification_watchdog(importer, context):
    stop_event = context["stop_event"]
    while not stop_event.wait(10):
        try:
            aggregate, last_activity_at = _notification_aggregate(importer, context)
            context["last_activity_at"] = last_activity_at or context.get("last_activity_at", 0)
            context["service"].observe_run(
                context["run_id"],
                aggregate,
                sms_exhausted=_SMS_KEY_POOL.is_exhausted(),
            )
        except Exception:
            continue


def _begin_notification_run(importer, settings):
    global _RUN_NOTIFICATION_CONTEXT
    config = _run_notifications_ext.validate_email_notification(
        (settings or {}).get("email_notification") or {}
    )
    previous = _notification_context_for()
    if isinstance(previous, dict):
        try:
            previous["service"].close(wait=False)
        except Exception:
            pass
    context = {
        "run_id": uuid.uuid4().hex,
        "service": _run_notifications_ext.RunNotificationService(config),
        "started_at": int(time.time()),
        "finished_at": 0,
        "last_activity_at": int(time.time()),
        "target": _int_value((settings or {}).get("target_count"), 1, minimum=1),
        "stop_event": threading.Event(),
    }
    context["service"].start_run(context["run_id"], {"total": 0, "pending": context["target"]})
    importer._gptphone_notification_context = context
    with _RUN_NOTIFICATION_LOCK:
        _RUN_NOTIFICATION_CONTEXT = context
    return context


def _cancel_notification_run(importer, context):
    global _RUN_NOTIFICATION_CONTEXT
    context["stop_event"].set()
    try:
        context["service"].close(wait=False)
    except Exception:
        pass
    if getattr(importer, "_gptphone_notification_context", None) is context:
        importer._gptphone_notification_context = None
    with _RUN_NOTIFICATION_LOCK:
        if _RUN_NOTIFICATION_CONTEXT is context:
            _RUN_NOTIFICATION_CONTEXT = None


def _patched_importer_start(self, settings):
    internal = copy.deepcopy(dict(settings or {}))
    additional_retries = _int_value(internal.get("auth_session_retries"), 1, minimum=0, maximum=10)
    internal["auth_session_retries"] = additional_retries + 1
    already_running = bool(self.status(internal).get("running"))
    if not already_running:
        _TASK_PROGRESS.reset()
        with _TASK_FAILURES_LOCK:
            _TASK_FAILURES.clear()
    notification_context = None
    try:
        if not already_running:
            notification_context = _begin_notification_run(self, internal)
        result = _importer_scheduler_ext.start_bounded_importer(
            self,
            internal,
            mailbox_error_type=_runtime.MailboxPoolError,
            manual_code_factory=_runtime.ManualCodeCoordinator,
            phase_gate_factory=_runtime.AutoEmailPhaseGate,
        )
        if notification_context is not None:
            aggregate, last_activity_at = _notification_aggregate(self, notification_context)
            notification_context["last_activity_at"] = last_activity_at or notification_context["started_at"]
            notification_context["service"].observe_run(notification_context["run_id"], aggregate)
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
            _TASK_PROGRESS.reset()
            with _TASK_FAILURES_LOCK:
                _TASK_FAILURES.clear()
        raise


def _patched_importer_stop(self):
    context = _notification_context_for(self)
    if isinstance(context, dict):
        try:
            aggregate, _last_activity_at = _notification_aggregate(self, context)
            context["service"].mark_manual_stop(context["run_id"], aggregate)
        except Exception:
            pass
    return _importer_scheduler_ext.stop_bounded_importer(self)


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
            context["finished_at"] = int(time.time())
            context["stop_event"].set()
            try:
                aggregate, last_activity_at = _notification_aggregate(self, context, finished=True)
                context["last_activity_at"] = last_activity_at or context.get("last_activity_at", 0)
                completed = not watch_failed and not aggregate.has_unfinished_work
                context["service"].observe_run(
                    context["run_id"],
                    aggregate,
                    sms_exhausted=_SMS_KEY_POOL.is_exhausted(),
                )
                context["service"].finalize_run(
                    context["run_id"],
                    aggregate,
                    completed=completed,
                )
            except Exception:
                pass


def _patched_pre_auth_session_retryable(result):
    if _runtime_policy_ext.should_retry_expired_sub2_session(result):
        return True
    return _ORIGINAL_PRE_AUTH_SESSION_RETRYABLE(result)


def _as_enabled(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", "unchecked", "disabled"}


def _patched_persist_result(self, settings, task_id, entry, result, *, error="", status="failed"):
    if status == "success":
        _TASK_PROGRESS.set_stage(task_id, "finalizing_save")
    failure = None
    failure_statuses = set(_task_progress_ext.TERMINAL_TASK_STATUSES).difference(
        {"success", "stopped", "stopped_before_start"}
    )
    secrets = _failure_secrets(self, entry, settings)
    if isinstance(result, dict):
        cost_summary = _SMS_COST_LEDGER.summary(str(task_id), _SMS_EXCHANGE_RATE)
        if cost_summary.get("sms_order_outcomes") or "sms_cost_usd" not in result:
            result.update(cost_summary)
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
            settings,
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
    if failure is not None:
        try:
            root = Path(
                str((settings or {}).get("results_dir") or "").strip()
                or Path(self.data_dir) / "results"
            )
            target = root / f"{task_id}_{str(getattr(entry, 'email', '') or '').replace('@', '_at_')}.json"
            payload = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload["failure"] = failure
                payload["error"] = failure["public_message"]
                payload["technical_error"] = failure["technical_summary"]
                payload_result = payload.get("result")
                if isinstance(payload_result, dict):
                    payload_result["failure"] = failure
                _runtime.atomic_write_json(target, payload)
        except Exception as exc:
            try:
                detail = _error_observability_ext.sanitize_failure_detail(exc, secrets=secrets)
                self._log(
                    f"{task_id} [保存任务结果/finalizing_save] 结构化诊断写入失败：{detail or '未返回错误详情'}",
                    "error",
                )
            except Exception:
                pass
    if status == "account_banned":
        detail = _ACCOUNT_BANNED_DETAIL_CONTEXT.get("")
        if detail:
            try:
                root = Path(
                    str((settings or {}).get("results_dir") or "").strip()
                    or Path(self.data_dir) / "results"
                )
                target = root / f"{task_id}_{str(getattr(entry, 'email', '') or '').replace('@', '_at_')}.json"
                payload = json.loads(target.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    payload["error"] = _runtime_policy_ext.ACCOUNT_BANNED_MESSAGE
                    payload["technical_error"] = _runtime_policy_ext.ACCOUNT_BANNED_MESSAGE
                    payload["account_banned_local_diagnostic"] = (
                        _error_observability_ext.sanitize_failure_detail(
                            detail,
                            secrets=secrets,
                            limit=1000,
                        )
                        or _runtime_policy_ext.ACCOUNT_BANNED_MESSAGE
                    )
                    _runtime.atomic_write_json(target, payload)
            except Exception:
                pass
    if status == "success" and _as_enabled((settings or {}).get("pixel_upload_enabled"), True):
        try:
            root = Path(
                str((settings or {}).get("results_dir") or "").strip()
                or Path(self.data_dir) / "results"
            )
            email = str(getattr(entry, "email", "") or "")
            result_file = root / f"{task_id}_{email.replace('@', '_at_')}.json"
            _PIXEL_UPLOAD_QUEUE.enqueue(task_id, result_file)
        except Exception as exc:
            try:
                detail = _error_observability_ext.sanitize_failure_detail(exc, secrets=secrets)
                self._log(
                    "Pixel 自动上传记录创建失败 [自动上传队列/pixel_enqueue]："
                    f"{detail or '未返回错误详情'}；注册结果已保留，可稍后从账号管理重试",
                    "error",
                )
            except Exception:
                pass
    return persisted


def _patched_retire_after_failure(self, settings, pool, entry, task_id, result, error):
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
        pool.mark_damaged_entry(entry, reason=message)
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
        self._log(message, "error")
    except Exception:
        pass
    return None


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
    original_send_phone_otp=lambda transport, phone, _channel="sms": transport._post_auth_json(
        "/api/accounts/add-phone/send",
        {"phone_number": _codex_oauth_chain._phone_for_openai(phone)},
        flow="authorize_continue",
        referer=f"{_codex_oauth_chain.AUTH}/add-phone",
        timeout=30,
    ),
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
    sms_keys_from_config=lambda value: _sms_keys_from_config(value),
    as_enabled=_as_enabled,
    safe_error=_safe_runtime_error,
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
    return _SMS_WEB.ensure_account_active(self, response)


def _call_log(log_fn, message, level="info"):
    if not callable(log_fn):
        return
    try:
        log_fn(message, level)
    except TypeError as exc:
        if "positional argument" not in str(exc) and "arguments" not in str(exc):
            raise
        log_fn(message)


def _fetch_dispose_lol_inbox_payload(provider, original_raw):
    parsed = urllib.parse.urlsplit(str(getattr(provider, "mailbox_url", "") or ""))
    if parsed.netloc.lower() != "dispose.lol":
        return original_raw
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) != 2 or path_parts[0] != "ib" or not path_parts[1]:
        return original_raw

    key = urllib.parse.quote(path_parts[1], safe="")
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    messages_url = f"{base}/api/inbox-link/{key}/messages"

    def load_json(url):
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json,text/plain,*/*",
                "User-Agent": "self-mailbox-pool/1.0",
                "Cache-Control": "no-cache, no-store, max-age=0",
                "Pragma": "no-cache",
            },
            method="GET",
        )
        with provider._opener().open(request, timeout=getattr(provider, "timeout_seconds", 15)) as response:
            raw = response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
        try:
            return json.loads(raw), raw
        except Exception:
            return None, raw

    data, raw_messages = load_json(messages_url)
    if not isinstance(data, dict):
        return f"{original_raw}\n{raw_messages}"

    def code_from_detail(value):
        payload = value if isinstance(value, dict) else {}
        message = payload.get("message") if isinstance(payload.get("message"), dict) else payload
        text = "\n".join(str(message.get(field) or "") for field in ("textBody", "htmlBody"))
        text = html.unescape(text)
        text = re.sub(r"<script\b[^>]*>[\s\S]*?</script>", " ", text, flags=re.I)
        text = re.sub(r"<style\b[^>]*>[\s\S]*?</style>", " ", text, flags=re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
        for pattern in (
            r"(?i)(?:verification|security|login|sign[-\s]?in|code|验证码|登录代码).{0,300}?(\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d)",
            r"(\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d[\s-]*\d).{0,180}?(?i:verification|security|login|sign[-\s]?in|code|验证码|登录代码)",
        ):
            match = re.search(pattern, text)
            if match:
                digits = re.sub(r"\D", "", match.group(1))
                if len(digits) == 6:
                    return digits
        return ""

    fragments = []
    messages = data.get("messages") if isinstance(data.get("messages"), list) else []
    for message in messages[:8]:
        if not isinstance(message, dict):
            continue
        message_id = str(message.get("id") or "").strip()
        if not message_id:
            continue
        haystack = " ".join(str(message.get(key) or "") for key in ("sender", "subject"))
        if "openai" not in haystack.lower() and "chatgpt" not in haystack.lower():
            continue
        detail_url = (
            f"{base}/api/inbox-link/{key}/message?"
            f"{urllib.parse.urlencode({'id': message_id})}"
        )
        detail, raw_detail = load_json(detail_url)
        code = code_from_detail(detail)
        if code:
            fragments.append(f"verification code {code}")
        fragments.append(raw_detail)
    return "\n".join(fragment for fragment in fragments if fragment) or original_raw


def _mailbox_url_fetch_raw(self):
    raw = _ORIGINAL_MAILBOX_URL_FETCH_RAW(self)
    try:
        return _fetch_dispose_lol_inbox_payload(self, raw)
    except Exception:
        return raw


def _url_mailbox_wait_code(self, email):
    entry = getattr(self, "entry", None)
    if (
        getattr(entry, "oauth_client_id", "") == "chatgpt_totp"
        and getattr(entry, "oauth_refresh_token", "")
        and getattr(self, "_chatgpt_email_otp_verified", False)
    ):
        code = _chatgpt_totp_ext.totp_code(getattr(entry, "oauth_refresh_token", ""))
        _call_log(getattr(self, "log_fn", None), "  [Codex] 已根据 2FA 密钥生成临时验证码", "info")
        return code
    code = _ORIGINAL_URL_MAILBOX_WAIT_CODE(self, email)
    if code:
        setattr(self, "_chatgpt_email_otp_verified", True)
        if (
            getattr(entry, "oauth_client_id", "") == "chatgpt_totp"
            and getattr(entry, "oauth_refresh_token", "")
        ):
            _MAILBOX_TOTP_SECRET_CONTEXT.set(str(getattr(entry, "oauth_refresh_token", "") or ""))
    return code


def _mfa_factor_id_from_response(response):
    value = response if isinstance(response, dict) else {}
    page = value.get("page") if isinstance(value.get("page"), dict) else {}
    payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    factor_id = str(payload.get("factor_id") or "").strip()
    if factor_id:
        return factor_id
    for key in ("mfa_challenge_factors", "mfa_factors"):
        factors = value.get(key)
        if not isinstance(factors, list):
            auth = value.get("oai-client-auth-session")
            factors = auth.get(key) if isinstance(auth, dict) else None
        if not isinstance(factors, list):
            continue
        for factor in factors:
            if isinstance(factor, dict) and factor.get("factor_type") == "totp":
                factor_id = str(factor.get("id") or "").strip()
                if factor_id:
                    return factor_id
    match = re.search(r"/mfa-challenge/([^/?#]+)", _codex_oauth_chain._continue_url(value))
    return match.group(1) if match else ""


def _real_verify_email_otp(self, code):
    response = _ORIGINAL_REAL_VERIFY_EMAIL_OTP(self, code)
    secret = _MAILBOX_TOTP_SECRET_CONTEXT.get("")
    try:
        page_type = _codex_oauth_chain._page_type(response)
    except Exception:
        page_type = ""
    if page_type not in {"mfa_otp", "mfa_challenge", "mfa_otp_verification"} or not secret:
        return response
    factor_id = _mfa_factor_id_from_response(response)
    if not factor_id:
        return response
    mfa_code = _chatgpt_totp_ext.totp_code(secret)
    _call_log(
        getattr(self, "log_fn", None),
        "  [Codex] 邮箱验证码后遇到 MFA，已根据 2FA 密钥生成临时验证码",
        "info",
    )
    return self._post_auth_json(
        "/api/accounts/mfa/verify",
        {"id": factor_id, "type": "totp", "code": mfa_code},
        flow="mfa_otp_verify",
        referer=f"{_codex_oauth_chain.AUTH}/mfa-challenge/{factor_id}",
        timeout=30,
    )


_clamp_sms_max_price = _SMS_WEB.clamp_max_price
_configure_sms_pool = _SMS_WEB.configure_pool
_preflight_sms_pool = _SMS_WEB.preflight_pool


_runtime.MailboxPool._entries_unlocked = _TOTP_PATCHES.entries_unlocked
_runtime.MailboxPool.remove_entry = _mailbox_retention_ext.preserve_consumed_entry
_runtime.ManualMailboxPool.remove_entry = _mailbox_retention_ext.preserve_consumed_entry
_runtime.OutlookMailboxOtpProvider = _TOTP_PATCHES.outlook_otp_provider
_runtime.MailboxUrlCodeProvider.fetch_raw = _mailbox_url_fetch_raw
_runtime.UrlMailboxOtpProvider.wait_code = _url_mailbox_wait_code
_runtime.EmailAuthImporter._account_label = _TOTP_PATCHES.account_label
_runtime.EmailAuthImporter._persist_result = _patched_persist_result
_runtime.EmailAuthImporter._retire_after_failure = _patched_retire_after_failure
_runtime.EmailAuthImporter._task_config = _patched_task_config
_runtime.EmailAuthImporter._task_state = _patched_task_state
_runtime.EmailAuthImporter.start = _patched_importer_start
_runtime.EmailAuthImporter.stop = _patched_importer_stop
_runtime.EmailAuthImporter._watch = _patched_importer_watch
_runtime.EmailAuthImporter._pre_auth_session_retryable = staticmethod(_patched_pre_auth_session_retryable)
_runtime._generate_sub2_oauth_session = _generate_sub2_oauth_session
_runtime._friendly_log_message = _diagnostic_friendly_log_message
_runtime.ImporterConfigStore.load = _patched_config_load
_runtime.ImporterConfigStore.save = _patched_config_save
_runtime.create_provider = _SMS_WEB.create_provider
_sms_providers.create_provider = _SMS_WEB.create_provider
_codex_oauth_chain.SmsProviderAdapter.get_number = _sms_adapter_get_number
_codex_oauth_chain.SmsProviderAdapter.mark_ready = _sms_adapter_mark_ready
_codex_oauth_chain.SmsProviderAdapter.wait_code = _sms_adapter_wait_code
_codex_oauth_chain.SmsProviderAdapter.complete = _sms_adapter_complete
_codex_oauth_chain.SmsProviderAdapter.cancel = _sms_adapter_cancel
_codex_oauth_chain._event = _patched_chain_event
_codex_oauth_chain.RealCodexTransport.verify_password = _TOTP_PATCHES.verify_password
_codex_oauth_chain.RealCodexTransport.verify_email_otp = _real_verify_email_otp
_codex_oauth_chain.RealCodexTransport.send_mfa_otp = _TOTP_PATCHES.send_mfa_otp
_codex_oauth_chain.RealCodexTransport.verify_mfa_otp = _TOTP_PATCHES.verify_mfa_otp
_codex_oauth_chain.RealCodexTransport.initiate_oauth = _real_initiate_oauth
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
    if not _LOCAL_CONFIG_FILE.exists():
        return {}
    try:
        value = json.loads(_LOCAL_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(value, dict):
        return {}
    if "nvtoken" in value or "nvtoken_upload" in value:
        value.pop("nvtoken", None)
        value.pop("nvtoken_upload", None)
        _write_local_config(value)
    return value


def _write_local_config(data):
    value = dict(data) if isinstance(data, dict) else {}
    value.pop("nvtoken", None)
    value.pop("nvtoken_upload", None)
    _LOCAL_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = _LOCAL_CONFIG_FILE.with_suffix(_LOCAL_CONFIG_FILE.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(_LOCAL_CONFIG_FILE)
    return value


_PIXEL_CLIENT = _pixel_runtime_ext.PixelProxyClient(
    os.environ.get("GPTPHONE_PIXEL_PROXY_URL")
    or _pixel_runtime_ext.DEFAULT_PIXEL_PROXY_BASE_URL
)
_PIXEL_UPLOAD_QUEUE = _pixel_runtime_ext.PixelUploadQueue(
    _RUNTIME_DATA_DIR,
    client=_PIXEL_CLIENT,
    auto_start=True,
    resume_pending=_as_enabled(
        _read_local_config().get("pixel_upload_enabled"),
        True,
    ),
)
_SUB2_RUNTIME = _sub2_runtime_ext.Sub2Runtime(
    _read_local_config,
    _RUNTIME_DATA_DIR / "sub2_test_snapshots.json",
)


def _local_secret(value, fallback=""):
    text = str(value or "")
    if not _module._clean(text) or text == _SECRET_MASK:
        return str(fallback or "")
    return text


def _mask_secret(value):
    return _SECRET_MASK if _module._clean(value) else ""


def _sms_keys_from_config(data):
    value = data if isinstance(data, dict) else {}
    return _sms_runtime_ext.normalize_sms_keys(value.get("sms_api_keys"), value.get("sms_api_key"))


def _resolve_sms_keys(data, existing=None):
    value = data if isinstance(data, dict) else {}
    previous = _sms_keys_from_config(existing or {})
    if "sms_api_keys" in value:
        raw = value.get("sms_api_keys")
        rows = raw if isinstance(raw, (list, tuple)) else [raw]
        resolved = []
        for index, row in enumerate(rows):
            text = str(row or "").strip()
            if text == _SECRET_MASK:
                text = previous[index] if index < len(previous) else ""
            resolved.append(text)
        return _sms_runtime_ext.normalize_sms_keys(resolved)
    if "sms_api_key" in value:
        text = str(value.get("sms_api_key") or "").strip()
        if text == _SECRET_MASK:
            return previous[:1]
        return _sms_runtime_ext.normalize_sms_keys(text)
    return previous


def _masked_local_config(data):
    value = json.loads(json.dumps(data if isinstance(data, dict) else {}))
    value.pop("nvtoken", None)
    value.pop("nvtoken_upload", None)
    sub2api = dict(value.get("sub2api") or {})
    email_notification = dict(value.get("email_notification") or {})
    sms_keys = _sms_keys_from_config(value)
    value["sms_api_keys"] = [_SECRET_MASK for _key in sms_keys]
    value.pop("sms_api_key", None)
    if "gptmail_api_key" in value:
        value["gptmail_api_key"] = _mask_secret(value.get("gptmail_api_key"))
    if "proxy" in value:
        value["proxy"] = _mask_secret(value.get("proxy"))
    if "password" in value:
        value["password"] = _mask_secret(value.get("password"))
    if sub2api:
        sub2api["password"] = _mask_secret(sub2api.get("password"))
        value["sub2api"] = sub2api
    if email_notification:
        email_notification["password"] = _mask_secret(email_notification.get("password"))
        value["email_notification"] = email_notification
    return value


def _public_task(task):
    if not isinstance(task, dict):
        return {}
    source_row = str(task.get("source_row") or "")
    try:
        secrets = _mailbox_admin_ext.MailboxAdminService._row_secrets(source_row)
    except Exception:
        secrets = (source_row,) if source_row else ()

    def safe_text(value):
        redacted = _mailbox_admin_ext.redact_mailbox_credentials(value, secrets)
        return _error_observability_ext.sanitize_failure_detail(
            _SMS_KEY_POOL.safe_error(redacted),
            secrets=secrets,
        )

    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    raw_failure = task.get("failure")
    if not isinstance(raw_failure, dict):
        raw_failure = result.get("failure")
    failure = _error_observability_ext.public_failure(raw_failure)
    task_status = str(task.get("status") or "").strip().lower()
    failure_statuses = set(_task_progress_ext.TERMINAL_TASK_STATUSES).difference(
        {"success", "stopped", "stopped_before_start"}
    )
    if failure is None and task_status in failure_statuses:
        failure = _error_observability_ext.classify_failure(
            result,
            safe_text(task.get("technical_error") or task.get("error") or task.get("reason") or ""),
            task.get("progress"),
            status=task_status,
            secrets=secrets,
        )
    if failure is not None:
        failure["public_message"] = safe_text(failure.get("public_message"))
        failure["technical_summary"] = safe_text(failure.get("technical_summary"))
    safe_result = {
        key: copy.deepcopy(result[key])
        for key in ("sms_cost_usd", "sms_cost_cny", "sms_exchange_rate", "sms_exchange_date")
        if key in result
    }
    progress = task.get("progress") if isinstance(task.get("progress"), dict) else None
    safe_progress = None
    if progress is not None:
        safe_progress = {
            key: copy.deepcopy(progress[key])
            for key in ("code", "label", "group", "entered_at", "finished_at")
            if key in progress
        }
    public = {
        key: copy.deepcopy(task[key])
        for key in ("task_id", "ordinal", "status", "created_at", "updated_at")
        if key in task
    }
    public_email = _mailbox_admin_ext.public_task_account(task, source_row)
    if public_email:
        public["email"] = public_email
        public["account"] = public_email
    if failure is not None:
        public["failure"] = failure
        public["error"] = failure["public_message"]
    elif task.get("error"):
        value = str(task.get("error") or "").strip().lower()
        if value not in _HISTORICAL_SUCCESS_REASONS:
            public["error"] = safe_text(task.get("error"))
    if task.get("reason"):
        value = str(task.get("reason") or "").strip().lower()
        if value not in _HISTORICAL_SUCCESS_REASONS:
            public["reason"] = safe_text(task.get("reason"))
    if safe_result:
        public["result"] = safe_result
    if safe_progress is not None:
        public["progress"] = safe_progress
    return public


def _runtime_summary(tasks):
    rows = [task for task in tasks if isinstance(task, dict)]
    terminal = set(_task_progress_ext.TERMINAL_TASK_STATUSES)
    success = sum(1 for task in rows if str(task.get("status") or "").lower() == "success")
    stopped = sum(
        1 for task in rows
        if str(task.get("status") or "").lower() in {"stopped", "stopped_before_start"}
    )
    active = sum(
        1 for task in rows
        if str(task.get("status") or "").lower() not in terminal
    )
    failed = max(0, len(rows) - success - stopped - active)
    cost_usd = 0.0
    cost_cny = 0.0
    last_activity_at = 0
    for task in rows:
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        try:
            cost_usd += float(result.get("sms_cost_usd") or 0)
            cost_cny += float(result.get("sms_cost_cny") or 0)
        except (TypeError, ValueError):
            pass
        for candidate in (task.get("updated_at"), task.get("created_at")):
            try:
                last_activity_at = max(last_activity_at, int(candidate or 0))
            except (TypeError, ValueError):
                pass
    context = _notification_context_for()
    value = context if isinstance(context, dict) else {}
    return {
        "run_id": value.get("run_id") or "",
        "target": int(value.get("target") or len(rows)),
        "total": len(rows),
        "active": active,
        "success": success,
        "failed": failed,
        "stopped": stopped,
        "started_at": int(value.get("started_at") or 0) or None,
        "last_activity_at": last_activity_at or int(value.get("last_activity_at") or 0) or None,
        "finished_at": int(value.get("finished_at") or 0) or None,
        "sms_cost_usd": round(cost_usd, 6),
        "sms_cost_cny": round(cost_cny, 4),
    }


def _notification_public_status():
    context = _notification_context_for()
    if not isinstance(context, dict):
        return {}
    try:
        status = context["service"].public_status()
    except Exception:
        return {}
    result = {
        "event": str(status.get("event") or ""),
        "status": str(status.get("status") or ""),
        "timestamp": int(status.get("timestamp") or 0),
        "recipient_count": int(status.get("recipient_count") or 0),
    }
    if result["status"] == "failed":
        result["error"] = "SMTP 发送失败或通知队列已满"
    return result


def _public_logs(logs, tasks):
    if not isinstance(logs, list):
        return logs
    local = _read_local_config()
    sub2api = dict(local.get("sub2api") or {})
    notification = dict(local.get("email_notification") or {})
    secrets = [
        *_sms_keys_from_config(local),
        sub2api.get("password"),
        notification.get("password"),
        *_mailbox_admin_ext.url_credential_secrets(local.get("proxy")),
    ]
    task_failures = {}
    for task in tasks:
        source_row = str(task.get("source_row") or "") if isinstance(task, dict) else ""
        if source_row:
            try:
                secrets.extend(_mailbox_admin_ext.MailboxAdminService._row_secrets(source_row))
            except Exception:
                secrets.append(source_row)
        if not isinstance(task, dict):
            continue
        task_id = str(task.get("task_id") or "").strip()
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        failure = _error_observability_ext.public_failure(
            task.get("failure") if isinstance(task.get("failure"), dict) else result.get("failure")
        )
        if failure is None:
            failure = _known_task_failure(task_id)
        if task_id and failure is not None:
            task_failures[task_id] = failure
    public = []
    for log in logs:
        row = dict(log) if isinstance(log, dict) else {"message": str(log or "")}
        for key in ("message", "text"):
            if key in row:
                row[key] = _error_observability_ext.sanitize_failure_detail(
                    _SMS_KEY_POOL.safe_error(
                        _mailbox_admin_ext.redact_mailbox_credentials(row.get(key), secrets)
                    ),
                    secrets=secrets,
                    limit=800,
                )
                message = str(row[key] or "")
                explicit_node = bool(re.search(r"\[[^\]]+/[a-z0-9_]+\]", message, re.IGNORECASE))
                level = str(row.get("level") or row.get("type") or "").strip().lower()
                if not explicit_node and (level in {"error", "danger"} or "失败" in message):
                    for task_id, failure in task_failures.items():
                        if task_id in message:
                            row[key] = _error_observability_ext.format_failure_log(task_id, failure)
                            break
        public.append(row)
    return public


def _masked_state(data):
    snapshot = json.loads(json.dumps(data if isinstance(data, dict) else {}))
    settings = snapshot.get("settings")
    if isinstance(settings, dict):
        snapshot["settings"] = _masked_local_config({**settings, **_read_local_config()})
    statuses = _SMS_KEY_POOL.public_statuses()
    alerts = _SMS_ALERTS.snapshot()
    snapshot["sms_key_statuses"] = statuses
    snapshot["sms_alerts"] = alerts
    runtime = snapshot.get("runtime")
    if isinstance(runtime, dict):
        runtime["sms_key_statuses"] = statuses
        runtime["sms_alerts"] = alerts
        runtime["sms_safe_stop"] = _SMS_KEY_POOL.is_exhausted()
        _TASK_PROGRESS.decorate_runtime(runtime)
        raw_tasks = runtime.get("tasks") if isinstance(runtime.get("tasks"), list) else []
        runtime["tasks"] = [_public_task(task) for task in raw_tasks]
        runtime["summary"] = _runtime_summary(runtime["tasks"])
        runtime["notification"] = _notification_public_status()
        if isinstance(runtime.get("logs"), list):
            runtime["logs"] = _public_logs(runtime.get("logs"), raw_tasks)
        if isinstance(snapshot.get("logs"), list):
            snapshot["logs"] = _public_logs(snapshot.get("logs"), raw_tasks)
    return snapshot


def _local_config_secret(secret_id):
    local = _read_local_config()
    sub2api = dict(local.get("sub2api") or {})
    email_notification = dict(local.get("email_notification") or {})
    sms_keys = _sms_keys_from_config(local)
    values = {
        "sms_api_keys": sms_keys,
        "sms_api_key": sms_keys[0] if sms_keys else "",
        "sub2_password": sub2api.get("password") or "",
        "notification_email_password": email_notification.get("password") or "",
        "proxy": local.get("proxy") or "",
    }
    return values.get(str(secret_id or ""), "")


def _local_config_from_runtime(data, existing=None):
    raw_data = dict(data or {}) if isinstance(data, dict) else {}
    existing = dict(existing or {})
    sms_keys = _resolve_sms_keys(raw_data, existing)
    raw_data["sms_api_keys"] = sms_keys
    raw_data["sms_api_key"] = sms_keys[0] if sms_keys else ""
    data, _migrated = _sms_runtime_ext.migrate_performance_config(raw_data)
    sub2api = dict(data.get("sub2api") or {})
    existing_sub2api = dict(existing.get("sub2api") or {})
    email_notification = dict(data.get("email_notification") or {})
    existing_email_notification = dict(existing.get("email_notification") or {})
    resolved_email_notification = _run_notifications_ext.normalize_email_notification(
        _merge_email_notification(existing_email_notification, email_notification)
    )
    resolved_email_notification["password"] = _local_secret(
        email_notification.get("password"),
        existing_email_notification.get("password"),
    ).strip()
    result = {
        "performance_policy_version": _sms_runtime_ext.PERFORMANCE_POLICY_VERSION,
        "sms_api_keys": sms_keys,
        "sub2api": {
            "url": str(sub2api.get("url") or "").strip(),
            "email": str(sub2api.get("email") or "").strip(),
            "password": _local_secret(sub2api.get("password"), existing_sub2api.get("password")),
            "group": str(sub2api.get("group") or "").strip(),
        },
        "email_notification": resolved_email_notification,
    }
    if "proxy" in data or "proxy" in existing:
        result["proxy"] = _local_secret(data.get("proxy"), existing.get("proxy")).strip()
    for key in (
        "proxy_scope",
        "target_count",
        "concurrency",
        "node_concurrency",
        "node_timeout",
        "auth_session_retries",
        "sms_min_price",
        "max_price",
        "sms_timeout",
        "phone_max_attempts",
        "phone_session_cycle_seconds",
        "pixel_upload_enabled",
    ):
        if key in data:
            result[key] = copy.deepcopy(data[key])
        elif key in existing:
            result[key] = copy.deepcopy(existing[key])
    return result


def _merge_nonempty(base, override):
    result = dict(base or {})
    for key, value in dict(override or {}).items():
        if _module._clean(value) and value != _SECRET_MASK:
            result[key] = value
    return result


def _merge_email_notification(base, override):
    previous = copy.deepcopy(dict(base or {}))
    incoming = copy.deepcopy(dict(override or {}))
    events = {
        **dict(previous.get("events") or {}),
        **dict(incoming.get("events") or {}),
    }
    result = {**previous, **incoming}
    result["events"] = events
    result["password"] = _local_secret(incoming.get("password"), previous.get("password"))
    return result


def _merge_local_config(data):
    patched = dict(data or {})
    local = _read_local_config()
    sms_keys = _resolve_sms_keys(patched, local)
    patched["sms_api_keys"] = sms_keys
    patched["sms_api_key"] = sms_keys[0] if sms_keys else ""
    patched["proxy"] = _local_secret(patched.get("proxy"), local.get("proxy"))
    if isinstance(local.get("sub2api"), dict):
        patched["sub2api"] = _merge_nonempty(local.get("sub2api") or {}, patched.get("sub2api") or {})
    if isinstance(local.get("email_notification"), dict):
        patched["email_notification"] = _merge_email_notification(
            local.get("email_notification") or {},
            patched.get("email_notification") or {},
        )
    return patched


def _apply_server_defaults(data):
    patched = dict(data or {})
    patched = _merge_local_config(patched)
    patched, _migrated = _sms_runtime_ext.migrate_performance_config(patched)
    if patched.get("sms_provider") == "localpool":
        patched["sms_provider"] = "smsbower"
    patched["email_mode"] = "auto"
    patched["sms_mode"] = "smart"
    patched["country"] = ""
    patched["provider_ids"] = ""
    patched.pop("manual_pool_content", None)
    patched.pop("nvtoken", None)
    patched.pop("nvtoken_upload", None)
    patched["sub2api"] = dict(patched.get("sub2api") or {})
    patched["email_notification"] = _run_notifications_ext.validate_email_notification(
        patched.get("email_notification") or {}
    )
    if not _module._clean(patched.get("proxy")):
        patched["proxy"] = "http://127.0.0.1:7897"
    if not _module._clean(patched.get("concurrency")):
        patched["concurrency"] = "5"
    if not _module._clean(patched.get("node_concurrency")):
        patched["node_concurrency"] = "5"
    if not _module._clean(patched.get("sms_min_price")):
        patched["sms_min_price"] = str(_SMS_MIN_PRICE_DEFAULT)
    patched["max_price"] = _clamp_sms_max_price(patched.get("max_price"))
    route_lease_seconds = _int_value(patched.get("sms_timeout"), 30, minimum=5, maximum=300) + 20
    patched["sms_smart"] = {
        **dict(patched.get("sms_smart") or {}),
        "enabled": True,
        "countries": "",
        "preferred_countries": "",
        "throughput_priority": False,
        "route_hard_max_inflight": 2,
        "route_max_inflight": 2,
        "route_semi_max_inflight": 2,
        "route_hot_max_inflight": 2,
        "route_lease_seconds": route_lease_seconds,
        "timeout_cooldown": 0,
        "phone_rejected_cooldown": 600,
        "register_rejected_cooldown": 60,
        "register_rejected_min_cooldown": 180,
    }
    patched["pixel_upload_enabled"] = _as_enabled(patched.get("pixel_upload_enabled"), True)
    return patched


def _test_email_notification(data):
    local = _local_config_from_runtime(data, _read_local_config())
    config = dict(local.get("email_notification") or {})
    config["enabled"] = True
    return _run_notifications_ext.send_test_notification(config)


def _mailbox_admin_factory(store, importer, logs):
    return _mailbox_admin_ext.MailboxAdminService(
        store,
        validate_pool=lambda config: importer._pool(config).validate(),
        imap_poller_factory=_imap_poller.ImapPoller,
        runtime_status=importer.status,
        progress_lookup=_TASK_PROGRESS.progress,
        is_active_progress=_task_progress_ext.is_active_progress,
        log_fn=logs.add,
        error_formatter=_module._safe if hasattr(_module, "_safe") else str,
        sub2_status_lookup=_SUB2_RUNTIME.status_for,
        sub2_batch_tester=_SUB2_RUNTIME.test_rows,
    )


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
    sms_key_pool=_SMS_KEY_POOL,
    sms_phone_gate=_SMS_PHONE_GATE,
    mailbox_admin_factory=_mailbox_admin_factory,
    mailbox_manager_html=_legacy_ui_ext.MAILBOX_MANAGER_HTML,
    pixel_client=_PIXEL_CLIENT,
    pixel_upload_queue=_PIXEL_UPLOAD_QUEUE,
)


def _patch_flask_app(app):
    return _web_routes_ext.patch_flask_app(app, _WEB_ROUTE_CONTEXT)


def create_app(data_dir=None):
    return _patch_flask_app(_ORIGINAL_CREATE_APP(data_dir))


_module.create_app = create_app
if hasattr(_module, "app"):
    _module.app = _patch_flask_app(_module.app)


__doc__ = _module.__doc__
__all__ = [name for name in globals() if not name.startswith("_")]
