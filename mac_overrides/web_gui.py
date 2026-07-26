"""Mac launcher overrides for the recovered web GUI."""

from __future__ import annotations

import importlib.util
import base64
import copy
import hashlib
import hmac
import json
import re
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from flask import send_from_directory as _send_from_directory

import codex_oauth_chain as _codex_oauth_chain
import imap_poller as _imap_poller
import runtime as _runtime
import sms_providers as _sms_providers
import sms_runtime as _sms_runtime_ext
import sms_selector as _sms_selector


APP_DIR = Path(__file__).resolve().parent.parent
BUSINESS_DIR = APP_DIR / "business_pyc"
ORIGINAL_WEB_GUI = BUSINESS_DIR / "web_gui.pyc"


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
_ORIGINAL_ACCOUNT_LABEL = _runtime.EmailAuthImporter._account_label
_ORIGINAL_REAL_VERIFY_PASSWORD = _codex_oauth_chain.RealCodexTransport.verify_password
_ORIGINAL_REAL_VERIFY_MFA_OTP = _codex_oauth_chain.RealCodexTransport.verify_mfa_otp
_ORIGINAL_REAL_SEND_MFA_OTP = _codex_oauth_chain.RealCodexTransport.send_mfa_otp
_ORIGINAL_SMART_BUILD_CANDIDATES = _sms_selector.SmartSmsSelector._build_candidates_locked
_ORIGINAL_PERSIST_RESULT = _runtime.EmailAuthImporter._persist_result
_ORIGINAL_CONFIG_SAVE = _runtime.ImporterConfigStore.save
_ORIGINAL_TASK_CONFIG = _runtime.EmailAuthImporter._task_config
_ORIGINAL_IMPORTER_START = _runtime.EmailAuthImporter.start
_ORIGINAL_CREATE_PROVIDER = _sms_providers.create_provider
_ORIGINAL_SMS_ADAPTER_GET_NUMBER = _codex_oauth_chain.SmsProviderAdapter.get_number
_ORIGINAL_SMS_ADAPTER_WAIT_CODE = _codex_oauth_chain.SmsProviderAdapter.wait_code
_ORIGINAL_SMS_ADAPTER_COMPLETE = _codex_oauth_chain.SmsProviderAdapter.complete
_ORIGINAL_SMS_ADAPTER_CANCEL = _codex_oauth_chain.SmsProviderAdapter.cancel
_ORIGINAL_REAL_SEND_PHONE_NUMBER_OTP = _codex_oauth_chain.RealCodexTransport.send_phone_number_otp
_ORIGINAL_SMART_CLASSIFY_ERROR = _sms_selector.SmartSmsSelector.classify_error
_ORIGINAL_SMART_RECORD_RESULT = _sms_selector.SmartSmsSelector.record_result
_CHATGPT_TOTP_MFA_ACTIVE_UNTIL = 0
_SMS_PRIORITY_COUNTRIES = ("151", "37", "33", "1", "91", "55")
_SMS_MIN_PRICE_DEFAULT = 0.01
_SMS_MAX_PRICE_DEFAULT = "0.1"
_SMS_PRIORITY_COUNTRIES_TEXT = ",".join(_SMS_PRIORITY_COUNTRIES)
_SMS_PRIORITY_ROUTES = (("151", "3109"), ("151", "3419"), ("37", "3237"))
_SMS_OFFICIAL_TOP_COUNTRY_IDS = {
    "brazil": "55",
    "philippines": "37",
    "united-states": "1",
    "united-states-virtual": "1",
    "colombia": "33",
    "india": "91",
    "viet-nam": "84",
    "united-kingdom": "16",
    "south-africa": "31",
    "greece": "129",
}
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
_SMSBOWER_TOP_CACHE = {"key": None, "expires_at": 0.0, "routes": ()}
_LOCAL_CONFIG_FILE = APP_DIR / "data" / "local_config.json"
_NVTOKEN_IMPORT_URL_DEFAULT = "https://nvtokens.com/api/inventory/cards/import"
_SECRET_MASK = "********"
_SMS_KEY_POOL = _sms_runtime_ext.SmsKeyPool(
    lambda key, proxy="": _ORIGINAL_CREATE_PROVIDER("smsbower", key, proxy=proxy)
)
_SMS_COST_LEDGER = _sms_runtime_ext.SmsCostLedger()
_SMS_EXCHANGE_RATE = _sms_runtime_ext.ExchangeRateCache(APP_DIR / "data" / "usd_cny_rate.json")
_SMS_PHONE_GATE = _sms_runtime_ext.PhoneSubmissionGate(concurrency=2, interval_seconds=0.75)
_SMS_ROUTE_POLICY = _sms_runtime_ext.SmsRoutePolicy()
_SMS_ALERTS = _sms_runtime_ext.RuntimeAlertBuffer()


def _safe_runtime_error(error):
    value = _module._safe(error) if hasattr(_module, "_safe") else str(error)
    return _SMS_KEY_POOL.safe_error(value)


def _parse_chatgpt_totp_row(raw):
    parts = [part.strip() for part in str(raw or "").strip().split("|")]
    if len(parts) != 3 or not all(parts):
        return None
    email, password, totp_secret = parts
    if not re.fullmatch(
        r"(?i)[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}",
        email,
    ):
        return None
    return email.lower(), password, totp_secret.replace(" ", "")


def _totp_code(secret, *, now=None, digits=6, period=30):
    normalized = re.sub(r"[^A-Za-z2-7=]", "", str(secret or "")).upper()
    if not normalized:
        raise ValueError("2FA 密钥为空")
    normalized += "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized, casefold=True)
    counter = int((time.time() if now is None else now) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def _is_chatgpt_totp_active():
    return time.time() < _CHATGPT_TOTP_MFA_ACTIVE_UNTIL


def _activate_chatgpt_totp_mfa(seconds=600):
    global _CHATGPT_TOTP_MFA_ACTIVE_UNTIL
    _CHATGPT_TOTP_MFA_ACTIVE_UNTIL = max(_CHATGPT_TOTP_MFA_ACTIVE_UNTIL, time.time() + seconds)


def _chatgpt_totp_page_type(response):
    try:
        return _codex_oauth_chain._page_type(response)
    except Exception:
        page = response.get("page") if isinstance(response, dict) else None
        return page.get("type") if isinstance(page, dict) else ""


def _chatgpt_totp_continue_url(response):
    try:
        return _codex_oauth_chain._continue_url(response)
    except Exception:
        return str(response.get("continue_url") or "") if isinstance(response, dict) else ""


def _chatgpt_totp_error(response):
    if not isinstance(response, dict):
        return ""
    error = response.get("error") or response.get("message") or ""
    if isinstance(error, dict):
        return str(error.get("code") or error.get("message") or "")
    return str(error)


def _chatgpt_totp_factor_id_from(response):
    if not isinstance(response, dict):
        return ""
    page = response.get("page") if isinstance(response.get("page"), dict) else {}
    payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    factor_id = str(payload.get("factor_id") or "").strip()
    if factor_id:
        return factor_id
    for key in ("mfa_challenge_factors", "mfa_factors"):
        factors = response.get(key)
        if not isinstance(factors, list):
            auth = response.get("oai-client-auth-session")
            factors = auth.get(key) if isinstance(auth, dict) else None
        if not isinstance(factors, list):
            continue
        for factor in factors:
            if isinstance(factor, dict) and factor.get("factor_type") == "totp":
                factor_id = str(factor.get("id") or "").strip()
                if factor_id:
                    return factor_id
    continue_url = _chatgpt_totp_continue_url(response)
    match = re.search(r"/mfa-challenge/([^/?#]+)", continue_url)
    return match.group(1) if match else ""


def _chatgpt_totp_trace(self, step, endpoint, response, **extra):
    if not callable(getattr(self, "log_fn", None)):
        return
    parts = [
        f"endpoint={endpoint}",
        f"_status={int(response.get('_status') or 0) if isinstance(response, dict) else 0}",
        f"page_type={_chatgpt_totp_page_type(response) or '-'}",
        f"continue_url={_chatgpt_totp_continue_url(response) or '-'}",
        f"error={_chatgpt_totp_error(response) or '-'}",
    ]
    for key, value in extra.items():
        parts.append(f"{key}={value if value else '-'}")
    self.log_fn(f"  [CodexTOTP] {step} " + " ".join(parts), "info")


def _patched_real_verify_password(self, password):
    response = _ORIGINAL_REAL_VERIFY_PASSWORD(self, password)
    factor_id = _chatgpt_totp_factor_id_from(response)
    if factor_id:
        setattr(self, "_chatgpt_totp_factor_id", factor_id)
    continue_url = _chatgpt_totp_continue_url(response)
    if continue_url:
        setattr(self, "_chatgpt_totp_mfa_continue_url", continue_url)
    if _is_chatgpt_totp_active():
        _chatgpt_totp_trace(
            self,
            "password_verify",
            "/api/accounts/password/verify",
            response,
            factor_id_present="1" if factor_id else "0",
        )
    return response


def _patched_real_send_mfa_otp(self, continue_url):
    if not _is_chatgpt_totp_active():
        return _ORIGINAL_REAL_SEND_MFA_OTP(self, continue_url)
    if continue_url:
        setattr(self, "_chatgpt_totp_mfa_continue_url", continue_url)
        match = re.search(r"/mfa-challenge/([^/?#]+)", str(continue_url))
        if match and not getattr(self, "_chatgpt_totp_factor_id", ""):
            setattr(self, "_chatgpt_totp_factor_id", match.group(1))
    response = {
        "_status": 200,
        "page": {"type": "mfa_challenge"},
        "continue_url": continue_url or getattr(self, "_chatgpt_totp_mfa_continue_url", ""),
    }
    _chatgpt_totp_trace(
        self,
        "send_mfa_otp_noop",
        "/api/accounts/mfa-otp/send",
        response,
        skipped="totp_local_code",
    )
    return response


def _patched_real_verify_mfa_otp(self, code):
    if not _is_chatgpt_totp_active():
        return _ORIGINAL_REAL_VERIFY_MFA_OTP(self, code)
    factor_id = str(getattr(self, "_chatgpt_totp_factor_id", "") or "").strip()
    if not factor_id:
        continue_url = str(getattr(self, "_chatgpt_totp_mfa_continue_url", "") or "")
        match = re.search(r"/mfa-challenge/([^/?#]+)", continue_url)
        factor_id = match.group(1) if match else ""
    if not factor_id:
        response = {
            "_status": 400,
            "page": {"type": "mfa_challenge"},
            "error": {"code": "mfa_factor_id_missing", "message": "TOTP factor id missing"},
        }
        _chatgpt_totp_trace(self, "mfa_verify", "/api/accounts/mfa/verify", response)
        return response
    response = self._post_auth_json(
        "/api/accounts/mfa/verify",
        {"id": factor_id, "type": "totp", "code": code},
        flow="mfa_otp_verify",
        referer=f"{_codex_oauth_chain.AUTH}/mfa-challenge/{factor_id}",
        timeout=30,
    )
    _chatgpt_totp_trace(
        self,
        "mfa_verify",
        "/api/accounts/mfa/verify",
        response,
        factor_id_present="1",
    )
    return response


def _patched_entries_unlocked(self):
    entries, errors = _ORIGINAL_POOL_ENTRIES_UNLOCKED(self)
    try:
        raw_lines = self.pool_path.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        raw_lines = []

    replacements = {}
    for line_no, raw in enumerate(raw_lines, start=1):
        parsed_totp = _parse_chatgpt_totp_row(raw)
        parsed_oauth = _parse_oauth_mailbox_row(raw)
        if parsed_totp:
            email, password, totp_secret = parsed_totp
            key = _runtime._mailbox_pool._entry_key(email, raw.strip()) if hasattr(_runtime, "_mailbox_pool") else hashlib.sha256(f"{email}\n{raw.strip()}".encode()).hexdigest()
            replacements[line_no] = _runtime.PoolEntry(
                email=email,
                mailbox_url="",
                line_no=line_no,
                key=key,
                mailbox_type="outlook_password",
                password=password,
                oauth_client_id="chatgpt_totp",
                oauth_refresh_token=totp_secret,
                source_row=f"{email}|***|***",
            )
        elif parsed_oauth:
            email, password, oauth_client_id, oauth_refresh_token = parsed_oauth
            key = _runtime._mailbox_pool._entry_key(email, raw.strip()) if hasattr(_runtime, "_mailbox_pool") else hashlib.sha256(f"{email}\n{raw.strip()}".encode()).hexdigest()
            replacements[line_no] = _runtime.PoolEntry(
                email=email,
                mailbox_url="",
                line_no=line_no,
                key=key,
                mailbox_type="outlook_oauth",
                password=password,
                oauth_client_id=oauth_client_id,
                oauth_refresh_token=oauth_refresh_token,
                source_row=f"{email}----***----{oauth_client_id}----***",
            )
    if not replacements:
        return entries, errors

    replaced_lines = set(replacements)
    errors = [
        error
        for error in errors
        if not any(str(error).startswith(f"line {line_no}:") for line_no in replaced_lines)
    ]

    patched = [replacements.get(getattr(entry, "line_no", 0), entry) for entry in entries]
    existing_lines = {getattr(entry, "line_no", 0) for entry in patched}
    patched.extend(entry for line_no, entry in replacements.items() if line_no not in existing_lines)
    patched.sort(key=lambda entry: getattr(entry, "line_no", 0))
    return patched, errors


class _ChatGptTotpOtpProvider:
    def __init__(self, entry, config, log_fn, *, phase_gate=None, stop_event=None, task_id="", state_fn=None):
        self.entry = entry
        self.log_fn = log_fn
        self.stop_event = stop_event
        self.task_id = task_id
        self.state_fn = state_fn
        self.phase_gate = phase_gate
        self.sent_at = 0
        _activate_chatgpt_totp_mfa()

    def acquire_login_slot(self):
        return None

    def mark_sent(self):
        _activate_chatgpt_totp_mfa()
        self.sent_at = time.time()

    def mark_verified(self):
        return None

    def wait_code(self, email):
        if self.stop_event is not None and self.stop_event.is_set():
            return ""
        code = _totp_code(getattr(self.entry, "oauth_refresh_token", ""))
        _activate_chatgpt_totp_mfa(120)
        if callable(self.log_fn):
            self.log_fn("  [Codex] 已根据 2FA 密钥生成临时验证码", "info")
        return code

    def close(self):
        return None


def _patched_outlook_otp_provider(entry, config, log_fn, **kwargs):
    if _parse_chatgpt_totp_row(getattr(entry, "source_row", "")) or (
        getattr(entry, "oauth_client_id", "") == "chatgpt_totp"
        and getattr(entry, "oauth_refresh_token", "")
    ):
        return _ChatGptTotpOtpProvider(entry, config, log_fn, **kwargs)
    return _ORIGINAL_OUTLOOK_OTP_PROVIDER(entry, config, log_fn, **kwargs)


def _patched_account_label(self, entry):
    if getattr(entry, "oauth_client_id", "") == "chatgpt_totp":
        return getattr(entry, "email", "")
    try:
        return _ORIGINAL_ACCOUNT_LABEL(entry)
    except TypeError as exc:
        if "positional argument" not in str(exc):
            raise
        return _ORIGINAL_ACCOUNT_LABEL(self, entry)


def _clamp_sms_max_price(value):
    try:
        price = float(str(value or "").strip())
    except (TypeError, ValueError):
        return _SMS_MAX_PRICE_DEFAULT
    if price <= 0 or price > 0.1:
        return _SMS_MAX_PRICE_DEFAULT
    return f"{price:g}"


def _smsbower_official_top_routes(selector, max_price=0.1):
    try:
        cfg = getattr(selector, "config", None) or {}
    except Exception:
        cfg = {}
    if str((cfg or {}).get("sms_provider") or "smsbower").lower() != "smsbower":
        return ()
    api_key = str((cfg or {}).get("sms_api_key") or "").strip()
    service = str((cfg or {}).get("service") or "dr").strip() or "dr"
    if not api_key:
        return ()
    cache_key = (api_key, service, float(max_price or 0.1))
    if _SMSBOWER_TOP_CACHE.get("key") == cache_key and time.time() < float(_SMSBOWER_TOP_CACHE.get("expires_at") or 0):
        return tuple(_SMSBOWER_TOP_CACHE.get("routes") or ())
    params = urllib.parse.urlencode(
        {
            "api_key": api_key,
            "action": "getTopCountriesByService",
            "service": service,
        }
    )
    url = f"https://smsbower.page/stubs/handler_api.php?{params}"
    try:
        with urllib.request.urlopen(url, timeout=8) as response:
            data = json.loads(response.read(65536).decode("utf-8", errors="replace"))
    except Exception:
        return ()
    routes = []
    if isinstance(data, dict):
        for country_slug, providers in data.items():
            country = _SMS_OFFICIAL_TOP_COUNTRY_IDS.get(str(country_slug).lower())
            if not country or not isinstance(providers, dict):
                continue
            for provider_id, info in providers.items():
                if not isinstance(info, dict):
                    continue
                try:
                    price = float(info.get("price") or 999.0)
                    count = int(info.get("count") or 0)
                except (TypeError, ValueError):
                    continue
                if count > 0 and 0 < price <= float(max_price or 0.1):
                    routes.append((country, str(provider_id)))
    routes = tuple(dict.fromkeys(routes))
    _SMSBOWER_TOP_CACHE.update({"key": cache_key, "expires_at": time.time() + 60, "routes": routes})
    return routes


def _patched_smart_build_candidates(self, raw_rows, now, allowed_countries, blocked_countries):
    rows = _ORIGINAL_SMART_BUILD_CANDIDATES(self, raw_rows, now, allowed_countries, blocked_countries)
    priority = {country: index for index, country in enumerate(_SMS_PRIORITY_COUNTRIES)}
    full_cfg = getattr(self, "config", {}) or {}
    try:
        max_price = float(str(full_cfg.get("max_price") or _SMS_MAX_PRICE_DEFAULT).strip())
    except (TypeError, ValueError):
        max_price = float(_SMS_MAX_PRICE_DEFAULT)
    try:
        min_price = float(str(full_cfg.get("sms_min_price") or _SMS_MIN_PRICE_DEFAULT).strip())
    except (TypeError, ValueError):
        min_price = _SMS_MIN_PRICE_DEFAULT
    official_routes = _smsbower_official_top_routes(self, max_price=max_price)
    route_order = tuple(dict.fromkeys((*_SMS_PRIORITY_ROUTES, *official_routes)))
    route_priority = {route: index for index, route in enumerate(route_order)}
    blocked_routes = set(_SMS_BLOCKED_ROUTES)
    if not rows:
        return rows
    rows = [
        item
        for item in rows
        if (str(getattr(item, "country", "")), str(getattr(item, "provider_id", ""))) not in blocked_routes
        and str(getattr(item, "country", "")) in priority
        and min_price <= float(getattr(item, "price", 999.0) or 999.0) <= max_price
    ]
    # Favor local winners first, then SMSBower top routes, while keeping local bad routes blocked.
    return sorted(
        rows,
        key=lambda item: (
            route_priority.get(
                (str(getattr(item, "country", "")), str(getattr(item, "provider_id", ""))),
                len(route_priority),
            ),
            priority.get(str(getattr(item, "country", "")), len(priority)),
            -float(getattr(item, "score", 0.0) or 0.0),
            float(getattr(item, "price", 999.0) or 999.0),
            -int(getattr(item, "count", 0) or 0),
        ),
    )


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
    if changed:
        _write_store_config(self, normalized)
    return normalized


def _patched_config_save(self, values):
    normalized, _migrated = _sms_runtime_ext.migrate_performance_config(values)
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
    attempts = _int_value((settings or {}).get("phone_max_attempts"), 10, minimum=1, maximum=10)
    phone_seconds = _int_value(
        (settings or {}).get("phone_session_cycle_seconds"),
        480,
        minimum=30,
        maximum=480,
    )
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
        "route_hard_max_inflight": 2,
        "route_max_inflight": 2,
        "route_semi_max_inflight": 2,
        "route_hot_max_inflight": 2,
        "timeout_cooldown": 0,
        "phone_rejected_cooldown": 600,
        "register_rejected_cooldown": 60,
        "register_rejected_min_cooldown": 180,
    }
    return config


def _patched_importer_start(self, settings):
    internal = copy.deepcopy(dict(settings or {}))
    additional_retries = _int_value(internal.get("auth_session_retries"), 1, minimum=0, maximum=10)
    internal["auth_session_retries"] = additional_retries + 1
    return _ORIGINAL_IMPORTER_START(self, internal)


def _patched_create_provider(name, api_key, proxy=""):
    if str(name or "").strip().lower() == "smsbower" and _SMS_KEY_POOL.has_keys():
        return _sms_runtime_ext.PooledSmsBowerProvider(_SMS_KEY_POOL, proxy=proxy)
    return _ORIGINAL_CREATE_PROVIDER(name, api_key, proxy=proxy)


def _adapter_task_id(adapter):
    config = getattr(adapter, "config", None) or {}
    return str(config.get("sms_task_id") or config.get("run_id") or "")


def _patched_sms_adapter_get_number(self, **kwargs):
    lease = _ORIGINAL_SMS_ADAPTER_GET_NUMBER(self, **kwargs)
    meta = dict(getattr(lease, "meta", None) or {})
    provider_meta = dict(getattr(getattr(self, "provider", None), "current_order_meta", None) or {})
    for key, value in provider_meta.items():
        if value is not None:
            meta[key] = value
    candidate = meta.get("candidate")
    if meta.get("price_usd") is None and candidate is not None:
        meta["price_usd"] = getattr(candidate, "price", None)
    lease.meta = meta
    task_id = _adapter_task_id(self)
    if task_id:
        _SMS_COST_LEDGER.record_lease(task_id, lease)
    return lease


def _patched_sms_adapter_mark_ready(self, lease):
    provider = getattr(self, "provider", None)
    if provider is not None and hasattr(provider, "set_ready"):
        provider.set_ready()
    meta = dict(getattr(lease, "meta", None) or {})
    meta["ready_sent"] = True
    lease.meta = meta


def _patched_sms_adapter_wait_code(self, lease, timeout=180):
    code = _ORIGINAL_SMS_ADAPTER_WAIT_CODE(self, lease, timeout=timeout)
    task_id = _adapter_task_id(self)
    if code and task_id:
        _SMS_COST_LEDGER.mark_code_received(task_id, getattr(lease, "activation_id", ""))
    return code


def _patched_sms_adapter_complete(self, lease):
    task_id = _adapter_task_id(self)
    try:
        result = _ORIGINAL_SMS_ADAPTER_COMPLETE(self, lease)
    except Exception as exc:
        if task_id:
            _SMS_COST_LEDGER.mark_finished(
                task_id,
                getattr(lease, "activation_id", ""),
                "complete_error",
                _safe_runtime_error(exc),
            )
        raise
    if task_id:
        _SMS_COST_LEDGER.mark_finished(task_id, getattr(lease, "activation_id", ""), "completed")
    return result


def _patched_sms_adapter_cancel(self, lease, reason=""):
    task_id = _adapter_task_id(self)
    try:
        return _ORIGINAL_SMS_ADAPTER_CANCEL(self, lease, reason=reason)
    finally:
        if task_id:
            _SMS_COST_LEDGER.mark_finished(
                task_id,
                getattr(lease, "activation_id", ""),
                "cancelled",
                _safe_runtime_error(reason or ""),
            )


def _patched_smart_classify_error(error):
    if _sms_runtime_ext.is_transient_openai_error(error):
        return "transient_server"
    text = str(error or "").lower()
    if any(marker in text for marker in ("phone_otp_empty", "no sms code", "no verification code", "未收到验证码")):
        return "timeout"
    return _ORIGINAL_SMART_CLASSIFY_ERROR(error)


def _update_route_stat(selector, candidate, update_fn):
    if candidate is None:
        return
    key = (str(getattr(candidate, "country", "")), str(getattr(candidate, "provider_id", "")))
    if not all(key):
        return
    with selector.lock:
        try:
            route_row, country_row = selector._update_shared_route_and_country(
                key,
                update_fn,
                lambda stat: dict(stat or {}),
            )
            selector.stats[key] = route_row
            selector.country_stats[str(getattr(candidate, "country", ""))] = country_row
        except Exception:
            stat = dict(selector.stats.get(key) or {})
            selector.stats[key] = update_fn(stat)


def _release_route_without_score(selector, candidate):
    now = time.time()

    def update(stat):
        row = dict(stat or {})
        inflight = selector._route_inflight(row, now)
        if inflight > 1:
            row["inflight"] = inflight - 1
        else:
            row.pop("inflight", None)
            row.pop("lease_until", None)
        return row

    _update_route_stat(selector, candidate, update)


def _set_route_cooldown(selector, candidate, seconds):
    until = time.time() + max(0, int(seconds))

    def update(stat):
        row = dict(stat or {})
        row["cooldown_until"] = max(float(row.get("cooldown_until") or 0), until)
        return row

    _update_route_stat(selector, candidate, update)


def _patched_smart_record_result(self, candidate, ok, error=""):
    kind = _patched_smart_classify_error(error)
    if not ok and kind == "transient_server":
        _release_route_without_score(self, candidate)
        return None
    result = _ORIGINAL_SMART_RECORD_RESULT(self, candidate, ok, error)
    cooldown = _SMS_ROUTE_POLICY.cooldown_for(candidate, ok=bool(ok), kind=kind, error=error)
    if cooldown > 0:
        _set_route_cooldown(self, candidate, cooldown)
        log_fn = getattr(self, "log_fn", None)
        if callable(log_fn):
            log_fn(
                f"  [SMS智能] 线路 {getattr(candidate, 'country', '-')}/{getattr(candidate, 'provider_id', '-')} 冷却 {cooldown} 秒",
                "warn",
            )
    return result


def _patched_route_limit(self, candidate, stat, now):
    return _SMS_ROUTE_POLICY.route_limit(stat)


def _patched_real_send_phone_number_otp(self, phone, channel="sms"):
    last_error = None
    for attempt, delay in enumerate((0, 2, 4, 8)):
        if delay:
            time.sleep(delay)
        try:
            response = _SMS_PHONE_GATE.call(_ORIGINAL_REAL_SEND_PHONE_NUMBER_OTP, self, phone, channel)
        except Exception as exc:
            last_error = exc
            if attempt >= 3 or not _sms_runtime_ext.is_transient_openai_error(exc):
                raise
        else:
            if attempt >= 3 or not _sms_runtime_ext.is_transient_openai_error(response):
                return response
            last_error = response
        log_fn = getattr(self, "log_fn", None)
        if callable(log_fn):
            log_fn(f"  [Codex] 手机提交遇到临时服务错误，{(2, 4, 8)[attempt]} 秒后复用同一号码", "warn")
    if isinstance(last_error, Exception):
        raise last_error
    return last_error


def _as_enabled(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", "unchecked", "disabled"}


def _nvtoken_result_payload(result, entry):
    if not isinstance(result, dict):
        return None
    data = {
        "access_token": str(result.get("access_token") or "").strip(),
        "refresh_token": str(result.get("refresh_token") or "").strip(),
        "email": str(result.get("email") or getattr(entry, "email", "") or "").strip(),
        "type": "codex",
    }
    if not data["access_token"] or not data["refresh_token"] or not data["email"]:
        return None
    return {"data": data}


def _upload_nvtoken(payload, settings, timeout=30):
    nvtoken = dict(((settings or {}).get("nvtoken") or {}))
    url = str(nvtoken.get("url") or _NVTOKEN_IMPORT_URL_DEFAULT).strip()
    api_key = str(nvtoken.get("api_key") or "").strip()
    if not api_key:
        return False, 0, "nvtoken api_key is empty"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read(4096).decode("utf-8", errors="replace")
            return True, int(response.status), text
    except urllib.error.HTTPError as exc:
        text = exc.read(4096).decode("utf-8", errors="replace")
        return False, int(exc.code), text
    except Exception as exc:
        return False, 0, str(exc)


def _patched_persist_result(self, settings, task_id, entry, result, *, error="", status="failed"):
    if isinstance(result, dict):
        cost_summary = _SMS_COST_LEDGER.summary(str(task_id), _SMS_EXCHANGE_RATE)
        if cost_summary.get("sms_order_outcomes") or "sms_cost_usd" not in result:
            result.update(cost_summary)
    if status == "success" and _as_enabled((settings or {}).get("nvtoken_upload"), True):
        payload = _nvtoken_result_payload(result, entry)
        if payload is None:
            result["nvtoken_upload_ok"] = False
            result["nvtoken_upload_error"] = "missing access_token/refresh_token/email"
            self._log(f"{task_id} [NVToken] 跳过上传: 缺少 token 或 email", "warn")
        elif result.get("nvtoken_upload_ok") is not True:
            ok, http_status, text = _upload_nvtoken(payload, settings)
            result["nvtoken_upload_ok"] = ok
            result["nvtoken_upload_status"] = http_status
            if ok:
                result["nvtoken_upload_response"] = text[:1000]
                self._log(f"{task_id} [NVToken] 已上传 nvtoken 平台: {payload['data']['email']}", "success")
            else:
                result["nvtoken_upload_error"] = text[:1000]
                self._log(f"{task_id} [NVToken] 上传失败 status={http_status}: {text[:240]}", "warn")
    return _ORIGINAL_PERSIST_RESULT(self, settings, task_id, entry, result, error=error, status=status)


_runtime.MailboxPool._entries_unlocked = _patched_entries_unlocked
_runtime.OutlookMailboxOtpProvider = _patched_outlook_otp_provider
_runtime.EmailAuthImporter._account_label = _patched_account_label
_runtime.EmailAuthImporter._persist_result = _patched_persist_result
_runtime.EmailAuthImporter._task_config = _patched_task_config
_runtime.EmailAuthImporter.start = _patched_importer_start
_runtime.ImporterConfigStore.load = _patched_config_load
_runtime.ImporterConfigStore.save = _patched_config_save
_runtime.create_provider = _patched_create_provider
_sms_providers.create_provider = _patched_create_provider
_codex_oauth_chain.SmsProviderAdapter.get_number = _patched_sms_adapter_get_number
_codex_oauth_chain.SmsProviderAdapter.mark_ready = _patched_sms_adapter_mark_ready
_codex_oauth_chain.SmsProviderAdapter.wait_code = _patched_sms_adapter_wait_code
_codex_oauth_chain.SmsProviderAdapter.complete = _patched_sms_adapter_complete
_codex_oauth_chain.SmsProviderAdapter.cancel = _patched_sms_adapter_cancel
_codex_oauth_chain.RealCodexTransport.verify_password = _patched_real_verify_password
_codex_oauth_chain.RealCodexTransport.send_mfa_otp = _patched_real_send_mfa_otp
_codex_oauth_chain.RealCodexTransport.verify_mfa_otp = _patched_real_verify_mfa_otp
_codex_oauth_chain.RealCodexTransport.send_phone_number_otp = _patched_real_send_phone_number_otp
_sms_selector.SmartSmsSelector._build_candidates_locked = _patched_smart_build_candidates
_sms_selector.SmartSmsSelector.classify_error = staticmethod(_patched_smart_classify_error)
_sms_selector.SmartSmsSelector.record_result = _patched_smart_record_result
_sms_selector.SmartSmsSelector._route_limit = _patched_route_limit

_ROOT_HEADER_HTML = (
    '<header class="top"><h1>plus绑号码脚本</h1>'
    '<span>独立运行 · 邮箱优先 Auth · SMS 智能选号 · SUB2 严格分组</span></header>'
)
_ROOT_MAILBOX_IMPORT_HTML = (
    '<section class="panel"><h2>自建邮箱池</h2><div class="field"><label>批量粘贴（每行：邮箱----邮箱取码地址）</label>'
    '<textarea id="pool_content" placeholder="user@example.test----https://mail.example.test/show/opaque"></textarea></div>'
    '<div class="actions"><button onclick="importPool()">导入邮箱池</button></div>'
    '<div class="hint">池文件、接口地址和状态均仅保存在本工具的 data 目录，不写入主项目配置。</div>'
    '<div class="section"><h2>SMS 接码</h2>'
)
_ROOT_MAILBOX_MANAGER_HTML = (
    '<section class="panel"><h2>邮箱队列</h2>'
    '<textarea id="pool_content" style="display:none"></textarea>'
    '<div class="section"><h2>SMS 接码</h2>'
)
_module._HTML = _module._HTML.replace(_ROOT_HEADER_HTML, "")
_module._HTML = _module._HTML.replace(_ROOT_MAILBOX_IMPORT_HTML, _ROOT_MAILBOX_MANAGER_HTML)
_module._HTML = _module._HTML.replace("SMS API Key / 本地号码池文件路径", "SMS API Key")
_module._HTML = _module._HTML.replace('<option value="localpool">本地号码池</option>', "")
_module._HTML = _module._HTML.replace('<label>管理密码</label><input id="sub2_password">', '<label>管理密码</label><input id="sub2_password" type="password">')
if isinstance(getattr(_module, "_LOGIN_FORM_USABILITY_INJECT", None), str):
    _module._LOGIN_FORM_USABILITY_INJECT = _module._LOGIN_FORM_USABILITY_INJECT.replace(
        "if(input){input.type='text';input.autocomplete='off'}",
        "if(input){input.type='password';input.autocomplete='new-password'}",
    )
_module._HTML = _module._HTML.replace(
    '<div class="field"><label>目标分组</label><input id="sub2_group"></div></div><div class="section"><h2>网络与运行</h2>',
    '<div class="field"><label>目标分组</label><input id="sub2_group"></div>'
    '<div class="checks"><label><input id="nvtoken_upload" type="checkbox" checked>上传到 nvtoken 平台</label></div>'
    '<div class="row"><div class="field"><label>nvtoken 地址</label><input id="nvtoken_url" placeholder="https://nvtokens.com/api/inventory/cards/import"></div>'
    '<div class="field"><label>nvtoken API Key</label><input id="nvtoken_api_key" type="password" value="********"></div></div>'
    '</div><div class="section"><h2>网络与运行</h2>',
)

_module._LOGIN_FORM_USABILITY_INJECT += r"""
<style>
.log,.log *,.line,.line *{user-select:text!important;-webkit-user-select:text!important}
.line{cursor:text!important;white-space:pre-wrap!important}
.log-selection-hint{font-size:11px;color:#60708a;margin-left:4px}
</style>
<script>
(function(){
  const installSelectableLogs = () => {
    const logBox = typeof g === "function" ? g("logs") : document.getElementById("logs");
    if (!logBox || logBox.dataset.selectableLogs === "1") return;
    logBox.dataset.selectableLogs = "1";
    logBox.setAttribute("tabindex", "0");
    logBox.style.userSelect = "text";
    logBox.style.webkitUserSelect = "text";
    const pauseButton = document.getElementById("toggle_log_pause");
    if (pauseButton && !document.querySelector(".log-selection-hint")) {
      const hint = document.createElement("span");
      hint.className = "log-selection-hint";
      hint.textContent = "拖选任意日志行会自动暂停刷新，方便复制";
      pauseButton.insertAdjacentElement("afterend", hint);
    }
    logBox.addEventListener("mousedown", event => {
      if (event.button !== 0) return;
      const toggle = document.getElementById("toggle_log_pause");
      if (toggle && toggle.textContent.includes("暂停")) toggle.click();
    });
    logBox.addEventListener("dblclick", event => {
      const line = event.target && event.target.closest ? event.target.closest(".line") : null;
      if (!line) return;
      const selection = window.getSelection && window.getSelection();
      if (!selection) return;
      const range = document.createRange();
      range.selectNodeContents(line);
      selection.removeAllRanges();
      selection.addRange(range);
    });
  };
  installSelectableLogs();
  setTimeout(installSelectableLogs, 0);
  setTimeout(installSelectableLogs, 500);
  document.addEventListener("DOMContentLoaded", installSelectableLogs);
})();
</script>
"""

_module._MANUAL_EMAIL_INJECT = ""
if hasattr(_module, "_GPTMAIL_INJECT"):
    _module._GPTMAIL_INJECT = ""
for _inject_name in dir(_module):
    if not _inject_name.endswith("_INJECT"):
        continue
    _inject_value = getattr(_module, _inject_name, "")
    if isinstance(_inject_value, str) and any(
        marker in _inject_value
        for marker in ("GPTMail", "gptmail", "邮箱验证码来源", "GPTMail 收码")
    ):
        setattr(_module, _inject_name, "")
_module._LOGIN_FORM_USABILITY_INJECT += r"""
<style>
:root{color-scheme:light!important;background:#f5f7fb!important;color:#172033!important}
html,body{height:100%!important;overflow:hidden!important}
body{background:#f5f7fb!important;color:#172033!important}
.top{display:none!important;background:#ffffff!important;border-bottom-color:#d7deea!important;box-shadow:0 1px 2px rgba(16,24,40,.06)!important}
.top h1{color:#172033!important}.top span{color:#60708a!important;border-left-color:#d7deea!important}
.shell{height:100vh!important;max-width:none!important;margin:0!important;padding:10px!important;gap:10px!important;overflow:hidden!important}
.panel{background:#ffffff!important;border-color:#d7deea!important;box-shadow:0 8px 24px rgba(16,24,40,.08)!important;min-height:0!important}
.shell>section.panel{height:100%!important;overflow:auto!important}.main{height:100%!important;min-height:0!important;gap:10px!important;overflow:hidden!important;grid-template-rows:auto minmax(0,.42fr) minmax(0,1fr)!important}.main>.panel{min-height:0!important;overflow:hidden!important;display:flex!important;flex-direction:column!important}.main>.panel h2{flex:0 0 auto!important}
.panel h2{color:#172033!important}.section{border-top-color:#e3e8f2!important}
.field label{color:#465872!important}
input,select,textarea,.field input,.field select,.field textarea{background:#ffffff!important;color:#172033!important;border-color:#c6d0df!important;box-shadow:inset 0 1px 1px rgba(16,24,40,.04)!important}
input::placeholder,textarea::placeholder{color:#92a0b4!important}
.checks label,.hint,.sms-mode-hint,.automatic-count-hint,.status{color:#60708a!important}
button{background:#eef3fb!important;color:#172033!important;border-color:#b8c5d8!important}
button:hover:not(:disabled){background:#e4ecf8!important;border-color:#8eacd2!important}
button.primary{background:#1f73d8!important;border-color:#1f73d8!important;color:#ffffff!important}
button.warn{background:#fff3e8!important;border-color:#f0b780!important;color:#7a3e07!important}
.metric,.tasks{background:#f8fafd!important;border-color:#d7deea!important}
.tasks{flex:1 1 auto!important;min-height:0!important;height:auto!important;max-height:none!important;overflow:auto!important}
.metric span{color:#60708a!important}.metric b{color:#172033!important}
.task{border-bottom-color:#e5eaf3!important}.task-account{color:#172033!important}
.log{background:#fbfcff!important;color:#172033!important;border-color:#d7deea!important;flex:1 1 auto!important;min-height:0!important;height:auto!important;overflow:auto!important}
.line{border-bottom-color:#e5eaf3!important}.time{color:#6b7d98!important}
.ok,.success{color:#178a54!important}.failed,.error{color:#c93545!important}.repair_pending,.warn{color:#a86613!important}.info{color:#416f9d!important}
.toast-host{position:fixed;left:50%;top:18px;z-index:9999;display:flex;flex-direction:column;align-items:center;gap:10px;width:min(520px,calc(100vw - 28px));pointer-events:none;transform:translateX(-50%)}
.toast{pointer-events:auto;display:grid;grid-template-columns:18px 1fr;align-items:start;gap:8px;min-width:min(380px,calc(100vw - 28px));max-width:100%;border:1px solid #dcdfe6;border-radius:4px;background:#f4f4f5;color:#303133;box-shadow:0 6px 18px rgba(31,45,61,.14);padding:10px 14px;font-size:14px;line-height:1.45;white-space:pre-wrap;overflow-wrap:anywhere;animation:gptphone-message-in .18s ease-out}
.toast-icon{font-weight:700;line-height:1.45;text-align:center}.toast-message{min-width:0}
.toast.info{background:#edf2fc;border-color:#d9ecff;color:#409eff}.toast.success{background:#f0f9eb;border-color:#e1f3d8;color:#67c23a}.toast.error{background:#fef0f0;border-color:#fde2e2;color:#f56c6c}.toast.warning,.toast.warn{background:#fdf6ec;border-color:#faecd8;color:#e6a23c}
@keyframes gptphone-message-in{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
.mailbox-link-panel{border:1px solid #d7deea;border-radius:7px;background:#f8fafd;padding:12px;margin-bottom:12px}
.mailbox-link-panel b{display:block;color:#172033;font-size:13px;margin-bottom:5px}.mailbox-link-panel span{display:block;color:#60708a;font-size:12px;line-height:1.45;margin-bottom:10px}
.secret-input-wrap{position:relative;display:block;width:100%}
.secret-input-wrap>input{padding-right:42px!important}
.secret-reveal-btn{position:absolute!important;right:5px!important;top:50%!important;transform:translateY(-50%)!important;display:flex!important;align-items:center!important;justify-content:center!important;width:32px!important;height:27px!important;min-width:0!important;padding:0!important;border:1px solid #c6d0df!important;border-radius:5px!important;background:#f8fafd!important;box-shadow:0 1px 2px rgba(16,24,40,.08)!important;color:#465872!important;font-size:15px!important;line-height:1!important;cursor:pointer!important;z-index:2!important}
.secret-reveal-btn:hover{background:#eef3fb!important;border-color:#8eacd2!important;color:#174ea6!important}
.secret-reveal-btn svg{width:17px!important;height:17px!important;display:block!important;stroke:currentColor!important;fill:none!important;stroke-width:2!important;stroke-linecap:round!important;stroke-linejoin:round!important;pointer-events:none!important}
</style>
<script>
(()=>{
  const PROXY_DEFAULT = "http://127.0.0.1:7897";
  const MAX_PRICE_DEFAULT = "0.1";
  const MIN_PRICE_DEFAULT = "0.01";
  const SMS_PRIORITY_COUNTRIES = ["151", "37", "33", "1", "91", "55"];
  let localConfig = {};
  const SECRET_INPUT_IDS = ["sms_api_key", "sub2_password", "nvtoken_api_key"];
  const SECRET_MASK = "********";
  const clampMaxPrice = value => {
    const parsed = Number(String(value || "").trim());
    if (!Number.isFinite(parsed) || parsed <= 0 || parsed > Number(MAX_PRICE_DEFAULT)) return MAX_PRICE_DEFAULT;
    return String(parsed);
  };
  const normalizeType = (type) => {
    const value = String(type || "info").toLowerCase();
    if (value === "warn") return "warning";
    return ["success", "warning", "error", "info"].includes(value) ? value : "info";
  };
  const messageText = (payload) => {
    if (payload && typeof payload === "object" && "message" in payload) {
      return payload.message;
    }
    if (payload && payload.message) return payload.message;
    return payload;
  };
  const showMessage = (payload, fallbackType="info") => {
    const type = normalizeType(payload && typeof payload === "object" ? payload.type || fallbackType : fallbackType);
    const message = String(messageText(payload) || "");
    let host = document.querySelector(".toast-host");
    if (!host) {
      host = document.createElement("div");
      host.className = "toast-host";
      document.body.appendChild(host);
    }
    const item = document.createElement("div");
    item.className = "toast " + type;
    const iconMap = {success: "✓", warning: "!", error: "×", info: "i"};
    const icon = document.createElement("span");
    icon.className = "toast-icon";
    icon.textContent = iconMap[type] || "i";
    const body = document.createElement("span");
    body.className = "toast-message";
    body.textContent = message;
    item.append(icon, body);
    host.appendChild(item);
    setTimeout(() => {
      item.style.opacity = "0";
      item.style.transform = "translateY(-4px)";
      item.style.transition = "opacity .18s ease, transform .18s ease";
      setTimeout(() => item.remove(), 220);
    }, type === "error" ? 6500 : 3000);
  };
  const toast = (message, type="info") => showMessage(message, type);
  window.showMessage = showMessage;
  window.toast = toast;
  window.ElMessage = function(payload){ showMessage(payload, payload && payload.type); };
  ["success", "warning", "error", "info"].forEach(type => {
    window.ElMessage[type] = (message) => showMessage(message, type);
  });
  window.alert = (message) => showMessage(message, "info");
  const eyeIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
  const eyeOffIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18"></path><path d="M10.6 10.6A3 3 0 0 0 13.4 13.4"></path><path d="M9.9 5.2A10.7 10.7 0 0 1 12 5c6.5 0 10 7 10 7a18.6 18.6 0 0 1-3.1 4.2"></path><path d="M6.1 6.7C3.4 8.5 2 12 2 12s3.5 7 10 7a10.8 10.8 0 0 0 4.1-.8"></path></svg>';
  const friendlyError = (text) => {
    const value = String(text || "");
    if (value.includes("deleted or deactivated") || value.includes("You do not have an account")) {
      return "邮箱对应的 OpenAI 账号不可用（已删除或停用）";
    }
    if (value.includes("email_otp_failed")) {
      return "邮箱验证码提交后被 OpenAI 拒绝，请确认该邮箱对应的 OpenAI 账号是否可用";
    }
    return value;
  };
  window.msg = function(error){
    const text = friendlyError(error && error.message ? error.message : String(error || "操作失败"));
    if (text.includes("自动模式请先在邮箱池输入框粘贴本次要运行的邮箱")) {
      fetch("/api/state").then(r => r.json()).then(j => {
        const pool = (((j || {}).state || {}).runtime || {}).pool || {};
        if (Number(pool.available || 0) > 0) {
          showMessage("邮箱池已有可领取邮箱，将直接使用现有邮箱池启动", "info");
        } else {
          showMessage("邮箱池没有可领取邮箱，请先导入邮箱", "warning");
        }
      }).catch(() => showMessage("邮箱池没有可领取邮箱，请先导入邮箱", "warning"));
      return;
    }
    showMessage(text, "error");
  };
  const ensureSecretRevealControl = (input) => {
    if (!input || input.dataset.revealControl === "1") return;
    const parent = input.parentElement;
    if (!parent || !parent.classList.contains("secret-input-wrap")) {
      const wrapper = document.createElement("div");
      wrapper.className = "secret-input-wrap";
      input.insertAdjacentElement("beforebegin", wrapper);
      wrapper.appendChild(input);
    }
    const wrapper = input.parentElement;
    if (!wrapper.querySelector(".secret-reveal-btn")) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "secret-reveal-btn";
      button.innerHTML = eyeIcon;
      button.title = "显示";
      button.setAttribute("aria-label", "显示");
      button.addEventListener("click", async () => {
        if (input.dataset.revealedSecret === "1") {
          input.dataset.revealedSecret = "0";
          input.type = "password";
          if (input.dataset.savedSecret === "1") input.value = SECRET_MASK;
          button.innerHTML = eyeIcon;
          button.title = "显示";
          button.setAttribute("aria-label", "显示");
          input.focus();
          return;
        }
        let value = input.value;
        if (input.dataset.savedSecret === "1" && input.value === SECRET_MASK) {
          try {
            const response = await fetch("/api/local-config/secret", {
              method: "POST",
              headers: {"Content-Type": "application/json"},
              body: JSON.stringify({id: input.id})
            });
            const payload = await response.json();
            if (!response.ok || !payload.ok) throw Error(payload.error || "读取失败");
            value = payload.value || "";
          } catch (error) {
            msg(error);
            return;
          }
        }
        input.dataset.revealedSecret = "1";
        input.type = "text";
        if (value) input.value = value;
        button.innerHTML = eyeOffIcon;
        button.title = "隐藏";
        button.setAttribute("aria-label", "隐藏");
        input.focus();
      });
      wrapper.appendChild(button);
    }
    input.dataset.revealControl = "1";
  };
  const enforceSecretInputs = () => {
    SECRET_INPUT_IDS.forEach(id => {
      const input = g(id);
      if (!input) return;
      ensureSecretRevealControl(input);
      if (input.dataset.revealedSecret !== "1") input.type = "password";
      input.autocomplete = "new-password";
      input.spellcheck = false;
      input.dataset.secretField = "1";
      if (input.dataset.secretBound !== "1") {
        input.dataset.secretBound = "1";
        input.addEventListener("input", () => {
          if (input.value !== SECRET_MASK) input.dataset.savedSecret = "0";
        });
        input.addEventListener("focus", () => {
          if (input.value === SECRET_MASK) input.select();
        });
      }
    });
  };
  const savedSecretFor = (id) => {
    if (id === "sms_api_key") return String(localConfig.sms_api_key || "");
    if (id === "sub2_password") return String(((localConfig.sub2api || {}).password) || "");
    if (id === "nvtoken_api_key") return String(((localConfig.nvtoken || {}).api_key) || "");
    return "";
  };
  const mergeLocalConfigFromSettings = (data) => {
    if (!data || typeof data !== "object") return;
    const sub2api = data.sub2api || {};
    const nvtoken = data.nvtoken || {};
    localConfig = Object.assign({}, localConfig || {});
    if (data.sms_api_key) localConfig.sms_api_key = data.sms_api_key;
    localConfig.sub2api = Object.assign({}, localConfig.sub2api || {});
    ["url", "email", "group"].forEach(key => {
      if (sub2api[key]) localConfig.sub2api[key] = sub2api[key];
    });
    if (sub2api.password) localConfig.sub2api.password = sub2api.password;
    localConfig.nvtoken = Object.assign({}, localConfig.nvtoken || {});
    if (nvtoken.url) localConfig.nvtoken.url = nvtoken.url;
    if (nvtoken.api_key) localConfig.nvtoken.api_key = nvtoken.api_key;
  };
  const secretInputValue = (id) => {
    const input = g(id);
    if (!input) return "";
    const raw = String(input.value || "");
    if (raw === SECRET_MASK && input.dataset.savedSecret === "1") return savedSecretFor(id);
    return raw;
  };
  const maskSecretInput = (id, value, force=false) => {
    const input = g(id);
    if (!input) return;
    enforceSecretInputs();
    if (input.dataset.revealedSecret === "1") return;
    const hasSecret = String(value || "").length > 0;
    input.dataset.savedSecret = hasSecret ? "1" : "0";
    if (hasSecret) {
      if (force || !input.value || input.value === SECRET_MASK || input.dataset.savedSecret === "1") input.value = SECRET_MASK;
    } else if (force) {
      input.value = "";
    }
  };
  const setEditableValue = (id, value, password=false, force=false) => {
    const input = g(id);
    if (!input) return;
    input.readOnly = false;
    input.disabled = false;
    input.autocomplete = password ? "new-password" : "off";
    if (password) {
      maskSecretInput(id, value, force);
      input.title = "";
      return;
    }
    if (value !== undefined && value !== null && (force || !input.value)) input.value = value;
    input.title = "";
  };
  const applyLocalConfig = (force=false) => {
    const sub2api = localConfig.sub2api || {};
    const nvtoken = localConfig.nvtoken || {};
    setEditableValue("sms_api_key", localConfig.sms_api_key || "", true, force);
    setEditableValue("sub2_url", sub2api.url || "", false, force);
    setEditableValue("sub2_email", sub2api.email || "", false, force);
    setEditableValue("sub2_password", sub2api.password || "", true, force);
    setEditableValue("sub2_group", sub2api.group || "", false, force);
    setEditableValue("nvtoken_api_key", nvtoken.api_key || "", true, force);
    setEditableValue("nvtoken_url", nvtoken.url || "https://nvtokens.com/api/inventory/cards/import", false, force);
    const proxyInput = g("proxy");
    if (proxyInput && !proxyInput.value.trim()) {
      proxyInput.value = PROXY_DEFAULT;
    }
    const maxPriceInput = g("max_price");
    if (maxPriceInput) {
      maxPriceInput.value = clampMaxPrice(maxPriceInput.value);
    }
    ensureSmsMinPriceControl();
  };
  const loadLocalConfig = async () => {
    try {
      const response = await fetch("/api/local-config");
      const payload = await response.json();
      if (payload && payload.ok && payload.config) {
        localConfig = payload.config;
        applyLocalConfig(true);
      }
    } catch(e) {}
  };
  const restoreSecretPlaceholders = () => {
    ensureNvTokenUploadControl();
    ensureLocalConfigControls();
    enforceSecretInputs();
    applyLocalConfig(true);
  };
  const reloadSecretPlaceholders = async () => {
    await loadLocalConfig();
    restoreSecretPlaceholders();
  };
  const ensureNvTokenUploadControl = () => {
    if (g("nvtoken_upload")) return;
    const sub2Group = g("sub2_group");
    const groupField = sub2Group && sub2Group.closest(".field");
    if (!groupField) return;
    const host = document.createElement("div");
    host.className = "checks";
    const label = document.createElement("label");
    label.innerHTML = '<input id="nvtoken_upload" type="checkbox" checked>上传到 nvtoken 平台';
    host.appendChild(label);
    groupField.insertAdjacentElement("afterend", host);
  };
  const ensureLocalConfigControls = () => {
    enforceSecretInputs();
    const smsKey = g("sms_api_key");
    if (smsKey) {
      smsKey.type = "password";
      smsKey.autocomplete = "new-password";
    }
    const sub2Password = g("sub2_password");
    if (sub2Password) {
      sub2Password.type = "password";
      sub2Password.autocomplete = "new-password";
    }
    const smsField = smsKey && smsKey.closest(".field");
    if (smsField && !g("local_config_export")) {
      const actions = document.createElement("div");
      actions.className = "actions";
      actions.innerHTML = '<button id="local_config_export" type="button" onclick="exportLocalConfig()">导出本地配置</button><button id="local_config_import_btn" type="button" onclick="document.getElementById(\\'local_config_import\\').click()">导入本地配置</button><input id="local_config_import" type="file" accept="application/json,.json" style="display:none" onchange="importLocalConfig(this.files&&this.files[0])">';
      smsField.insertAdjacentElement("afterend", actions);
    }
    const nvTokenInput = g("nvtoken_upload");
    const checks = nvTokenInput && nvTokenInput.closest(".checks");
    if (checks && !g("nvtoken_api_key")) {
      const fields = document.createElement("div");
      fields.className = "row";
      fields.innerHTML = '<div class="field"><label>nvtoken 地址</label><input id="nvtoken_url" placeholder="https://nvtokens.com/api/inventory/cards/import"></div><div class="field"><label>nvtoken API Key</label><input id="nvtoken_api_key" type="password" value="********"></div>';
      checks.insertAdjacentElement("afterend", fields);
    }
  };
  window.exportLocalConfig = async function(){
    try {
      const data = Object.assign({}, cfg(), {download: true});
      const response = await fetch("/api/local-config/export", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw Error(payload.error || "导出失败");
      localConfig = payload.config || {};
      applyLocalConfig(true);
      const blob = new Blob([JSON.stringify(payload.config || {}, null, 2)], {type:"application/json"});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "gptphone-local-config.json";
      a.click();
      URL.revokeObjectURL(url);
      showMessage("本地配置已导出", "success");
    } catch(e) { msg(e); }
  };
  window.importLocalConfig = async function(file){
    if (!file) return;
    try {
      const text = await file.text();
      const config = JSON.parse(text);
      const response = await fetch("/api/local-config/import", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({config})});
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw Error(payload.error || "导入失败");
      localConfig = payload.config || {};
      applyLocalConfig(true);
      showMessage("本地配置已导入", "success");
    } catch(e) { msg(e); }
  };
  const ensureSmsMinPriceControl = () => {
    if (g("sms_min_price")) return;
    const maxPriceInput = g("max_price");
    const maxPriceField = maxPriceInput && maxPriceInput.closest(".field");
    if (!maxPriceField || !maxPriceField.parentNode) return;
    const minPriceField = document.createElement("div");
    minPriceField.className = "field";
    minPriceField.innerHTML = '<label>最低价格</label><input id="sms_min_price" inputmode="decimal" placeholder="0.01" value="' + MIN_PRICE_DEFAULT + '">';
    maxPriceField.insertAdjacentElement("beforebegin", minPriceField);
  };
  const replaceRootMailboxImport = () => {
    const input = g("pool_content");
    if (!input || input.dataset.rootMailboxReplaced === "1") return;
    input.dataset.rootMailboxReplaced = "1";
    const field = input.closest(".field");
    if (!field) return;
    const actions = field && field.nextElementSibling;
    const hint = actions && actions.nextElementSibling;
    const title = field && field.parentNode && field.parentNode.querySelector("h2");
    if (title) title.textContent = "邮箱队列";
    if (field) field.style.display = "none";
    if (actions) actions.style.display = "none";
    if (hint) hint.style.display = "none";
  };
  const baseCfg = cfg;
  cfg = function(){
    const data = baseCfg();
    data.concurrency = String(data.concurrency || "5");
    data.node_concurrency = String(data.node_concurrency || "5");
    data.sms_api_key = String(secretInputValue("sms_api_key").trim() || data.sms_api_key || "");
    data.max_price = clampMaxPrice(data.max_price);
    const minPriceInput = g("sms_min_price");
    data.sms_min_price = String((minPriceInput && minPriceInput.value.trim()) || data.sms_min_price || MIN_PRICE_DEFAULT);
    data.sms_mode = "smart";
    data.country = "";
    data.provider_ids = "";
    data.sms_smart = Object.assign({}, data.sms_smart || {}, {
      enabled: true,
      countries: SMS_PRIORITY_COUNTRIES.join(","),
      preferred_countries: SMS_PRIORITY_COUNTRIES.join(",")
    });
    const nvTokenInput = g("nvtoken_upload");
    data.nvtoken_upload = !nvTokenInput || nvTokenInput.checked;
    data.nvtoken = Object.assign({}, data.nvtoken || {}, {
      url: String((g("nvtoken_url") && g("nvtoken_url").value.trim()) || "https://nvtokens.com/api/inventory/cards/import"),
      api_key: String(secretInputValue("nvtoken_api_key").trim() || "")
    });
    data.sub2api = Object.assign({}, data.sub2api || {}, {
      url: String((g("sub2_url") && g("sub2_url").value.trim()) || ""),
      email: String((g("sub2_email") && g("sub2_email").value.trim()) || ""),
      password: String(secretInputValue("sub2_password") || ""),
      group: String((g("sub2_group") && g("sub2_group").value.trim()) || "")
    });
    data.email_mode = "auto";
    delete data.manual_pool_content;
    return data;
  };
  const baseLoad = load;
  load = function(data){
    const patched = Object.assign({}, data || {});
    mergeLocalConfigFromSettings(patched);
    patched.sms_api_key = patched.sms_api_key || localConfig.sms_api_key || "";
    patched.email_mode = "auto";
    patched.concurrency = patched.concurrency || "5";
    patched.node_concurrency = patched.node_concurrency || "5";
    if (patched.sms_provider === "localpool") patched.sms_provider = "smsbower";
    if (!patched.proxy) patched.proxy = PROXY_DEFAULT;
    patched.max_price = clampMaxPrice(patched.max_price);
    patched.sms_min_price = patched.sms_min_price || MIN_PRICE_DEFAULT;
    patched.sms_mode = "smart";
    patched.country = "";
    patched.provider_ids = "";
    patched.sms_smart = Object.assign({}, patched.sms_smart || {}, {
      enabled: true,
      countries: SMS_PRIORITY_COUNTRIES.join(","),
      preferred_countries: SMS_PRIORITY_COUNTRIES.join(",")
    });
    patched.nvtoken_upload = patched.nvtoken_upload !== false;
    patched.nvtoken = Object.assign({url: "https://nvtokens.com/api/inventory/cards/import"}, localConfig.nvtoken || {}, patched.nvtoken || {});
    patched.sub2api = Object.assign({}, patched.sub2api || {}, {
      ...(localConfig.sub2api || {}),
      ...(patched.sub2api || {})
    });
    const displayPatched = Object.assign({}, patched, {
      sms_api_key: patched.sms_api_key ? SECRET_MASK : "",
      nvtoken: Object.assign({}, patched.nvtoken || {}, {
        api_key: (patched.nvtoken || {}).api_key ? SECRET_MASK : ""
      }),
      sub2api: Object.assign({}, patched.sub2api || {}, {
        password: (patched.sub2api || {}).password ? SECRET_MASK : ""
      })
    });
    baseLoad(displayPatched);
    ensureNvTokenUploadControl();
    ensureLocalConfigControls();
    enforceSecretInputs();
    ensureSmsMinPriceControl();
    applyLocalConfig();
    const minPriceInput = g("sms_min_price");
    if (minPriceInput) minPriceInput.value = patched.sms_min_price || MIN_PRICE_DEFAULT;
    const nvTokenInput = g("nvtoken_upload");
    if (nvTokenInput) nvTokenInput.checked = patched.nvtoken_upload !== false;
    applyLocalConfig();
  };
  ensureNvTokenUploadControl();
  ensureLocalConfigControls();
  enforceSecretInputs();
  ensureSmsMinPriceControl();
  loadLocalConfig();
  applyLocalConfig();
  replaceRootMailboxImport();
  setTimeout(reloadSecretPlaceholders, 0);
  setTimeout(reloadSecretPlaceholders, 500);
  setTimeout(reloadSecretPlaceholders, 1500);
  setTimeout(reloadSecretPlaceholders, 3000);
  setTimeout(applyLocalConfig, 0);
  setTimeout(applyLocalConfig, 500);
  setTimeout(ensureNvTokenUploadControl, 0);
  setTimeout(ensureNvTokenUploadControl, 500);
  setTimeout(ensureLocalConfigControls, 0);
  setTimeout(ensureLocalConfigControls, 500);
  setTimeout(enforceSecretInputs, 0);
  setTimeout(enforceSecretInputs, 500);
  setTimeout(ensureSmsMinPriceControl, 0);
  setTimeout(ensureSmsMinPriceControl, 500);
  setTimeout(replaceRootMailboxImport, 0);
  setTimeout(replaceRootMailboxImport, 500);
  window.addEventListener("storage", event => {
    if (event.key === "gptphone_mailboxes_changed" && typeof refresh === "function") {
      refresh();
    }
  });
  const visibilityBaseLoad = load;
  load = function(data){
    visibilityBaseLoad(data);
  };
  const baseRenderForFriendlyErrors = render;
  render = function(state){
    const logBox = g("logs");
    const keepLogScroll = logBox && (logBox.scrollTop + logBox.clientHeight < logBox.scrollHeight - 24);
    const previousLogScrollTop = keepLogScroll ? logBox.scrollTop : 0;
    const patched = JSON.parse(JSON.stringify(state || {}));
    const tasks = ((patched.runtime || {}).tasks || []);
    tasks.forEach(task => {
      const detail = task.technical_error || (task.result && (task.result.local_oauth_exchange_error || task.result.error)) || task.error;
      const friendly = friendlyError(detail);
      if (friendly) task.error = friendly;
    });
    baseRenderForFriendlyErrors(patched);
    setTimeout(restoreSecretPlaceholders, 0);
    setTimeout(enforceSecretInputs, 50);
    if (keepLogScroll && logBox) {
      logBox.scrollTop = previousLogScrollTop;
    }
  };
  window.preflight = async function(){
    try {
      const content = v("pool_content");
      if (content) {
        await req("/api/pool/import", {pool_content: content});
      }
      await req("/api/preflight", cfg());
      showMessage("预检通过", "success");
    } catch(e) {
      msg(e);
    }
  };
  window.startRun = async function(){
    try {
      const content = v("pool_content");
      const data = cfg();
      if (content) {
        data.pool_content = content;
        await req("/api/start", data);
      } else {
        const current = await (await fetch("/api/state")).json();
        const pool = (((current || {}).state || {}).runtime || {}).pool || {};
        if (Number(pool.available || 0) > 0) {
          showMessage("使用现有邮箱池启动", "info");
          await req("/api/start-existing", data);
        } else {
          showMessage("邮箱池没有可领取邮箱，请先导入邮箱", "warning");
          return;
        }
      }
      showMessage("已开始运行", "success");
    } catch(e) {
      msg(e);
    }
  };
  window.importPool = async function(){
    const content = v("pool_content");
    if (!content) {
      showMessage("邮箱池输入框为空，未导入新邮箱", "warning");
      return;
    }
    try {
      await req("/api/pool/import", {pool_content: content});
      g("pool_content").value = "";
      showMessage("邮箱池已导入", "success");
    } catch(e) {
      msg(e);
    }
  };
  window.saveConfig = async function(){
    try {
      const data = cfg();
      const saved = await req("/api/local-config/export", data);
      localConfig = saved.config || {};
      applyLocalConfig(true);
      await req("/api/config", data);
      showMessage("配置已保存", "success");
    } catch(e) {
      msg(e);
    }
  };
  window.stopRun = async function(){
    try {
      await req("/api/stop");
      showMessage("已请求安全停止", "success");
    } catch(e) {
      msg(e);
    }
  };
})();
</script>
"""

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
    return value if isinstance(value, dict) else {}


def _write_local_config(data):
    value = data if isinstance(data, dict) else {}
    _LOCAL_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LOCAL_CONFIG_FILE.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    return value


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
    sub2api = dict(value.get("sub2api") or {})
    nvtoken = dict(value.get("nvtoken") or {})
    sms_keys = _sms_keys_from_config(value)
    value["sms_api_keys"] = [_SECRET_MASK for _key in sms_keys]
    value.pop("sms_api_key", None)
    if "gptmail_api_key" in value:
        value["gptmail_api_key"] = _mask_secret(value.get("gptmail_api_key"))
    if sub2api:
        sub2api["password"] = _mask_secret(sub2api.get("password"))
        value["sub2api"] = sub2api
    if nvtoken:
        nvtoken["api_key"] = _mask_secret(nvtoken.get("api_key"))
        value["nvtoken"] = nvtoken
    return value


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
    return snapshot


def _local_config_secret(secret_id):
    local = _read_local_config()
    sub2api = dict(local.get("sub2api") or {})
    nvtoken = dict(local.get("nvtoken") or {})
    sms_keys = _sms_keys_from_config(local)
    values = {
        "sms_api_keys": sms_keys,
        "sms_api_key": sms_keys[0] if sms_keys else "",
        "sub2_password": sub2api.get("password") or "",
        "nvtoken_api_key": nvtoken.get("api_key") or "",
    }
    return values.get(str(secret_id or ""), "")


def _local_config_from_runtime(data, existing=None):
    data, _migrated = _sms_runtime_ext.migrate_performance_config(data)
    existing = dict(existing or {})
    sub2api = dict(data.get("sub2api") or {})
    existing_sub2api = dict(existing.get("sub2api") or {})
    nvtoken = dict(data.get("nvtoken") or {})
    existing_nvtoken = dict(existing.get("nvtoken") or {})
    sms_keys = _resolve_sms_keys(data, existing)
    result = {
        "performance_policy_version": _sms_runtime_ext.PERFORMANCE_POLICY_VERSION,
        "sms_api_keys": sms_keys,
        "sub2api": {
            "url": str(sub2api.get("url") or "").strip(),
            "email": str(sub2api.get("email") or "").strip(),
            "password": _local_secret(sub2api.get("password"), existing_sub2api.get("password")),
            "group": str(sub2api.get("group") or "").strip(),
        },
        "nvtoken": {
            "url": str(nvtoken.get("url") or _NVTOKEN_IMPORT_URL_DEFAULT).strip(),
            "api_key": _local_secret(nvtoken.get("api_key"), existing_nvtoken.get("api_key")).strip(),
        },
    }
    for key in (
        "proxy",
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
        "nvtoken_upload",
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


def _merge_local_config(data):
    patched = dict(data or {})
    local = _read_local_config()
    sms_keys = _resolve_sms_keys(patched, local)
    patched["sms_api_keys"] = sms_keys
    patched["sms_api_key"] = sms_keys[0] if sms_keys else ""
    if isinstance(local.get("sub2api"), dict):
        patched["sub2api"] = _merge_nonempty(local.get("sub2api") or {}, patched.get("sub2api") or {})
    if isinstance(local.get("nvtoken"), dict):
        patched["nvtoken"] = _merge_nonempty(local.get("nvtoken") or {}, patched.get("nvtoken") or {})
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
    patched["sub2api"] = dict(patched.get("sub2api") or {})
    patched["nvtoken"] = {
        "url": _NVTOKEN_IMPORT_URL_DEFAULT,
        **dict(patched.get("nvtoken") or {}),
    }
    if not _module._clean(patched.get("proxy")):
        patched["proxy"] = "http://127.0.0.1:7897"
    if not _module._clean(patched.get("concurrency")):
        patched["concurrency"] = "5"
    if not _module._clean(patched.get("node_concurrency")):
        patched["node_concurrency"] = "5"
    if not _module._clean(patched.get("sms_min_price")):
        patched["sms_min_price"] = str(_SMS_MIN_PRICE_DEFAULT)
    patched["max_price"] = _clamp_sms_max_price(patched.get("max_price"))
    patched["sms_smart"] = {
        **dict(patched.get("sms_smart") or {}),
        "enabled": True,
        "countries": _SMS_PRIORITY_COUNTRIES_TEXT,
        "preferred_countries": _SMS_PRIORITY_COUNTRIES_TEXT,
        "route_hard_max_inflight": 2,
        "route_max_inflight": 2,
        "route_semi_max_inflight": 2,
        "route_hot_max_inflight": 2,
        "timeout_cooldown": 0,
        "phone_rejected_cooldown": 600,
        "register_rejected_cooldown": 60,
        "register_rejected_min_cooldown": 180,
    }
    patched["nvtoken_upload"] = _as_enabled(patched.get("nvtoken_upload"), True)
    _write_local_config(_local_config_from_runtime(patched, _read_local_config()))
    return patched


def _sms_runtime_alert(payload):
    value = dict(payload or {})
    _SMS_ALERTS.add(
        str(value.get("kind") or "sms_warning"),
        str(value.get("message") or "SMS Key 状态异常"),
        level="warning",
        dedupe_key=f"runtime:{value.get('fingerprint')}:{value.get('kind')}",
        persistent=True,
        key_index=value.get("index"),
        fingerprint=value.get("fingerprint") or "",
    )


def _configure_sms_pool(config, *, logs=None, importer=None):
    value = dict(config or {})
    keys = _sms_keys_from_config(value)
    proxy_scope = dict(value.get("proxy_scope") or {})
    sms_proxy = str(value.get("proxy") or "") if _as_enabled(proxy_scope.get("sms"), False) else ""

    def exhausted():
        message = "所有 SMS Key 均已耗尽，停止创建新短信订单，已领取号码处理完成后安全停止"
        _SMS_ALERTS.add(
            "sms_pool_exhausted",
            message,
            level="error",
            dedupe_key="runtime:all_sms_keys_exhausted",
            persistent=True,
        )
        if logs is not None:
            logs.add(message, "error")

    logger = logs.add if logs is not None else None
    try:
        min_price = float(value.get("sms_min_price") or _SMS_MIN_PRICE_DEFAULT)
    except (TypeError, ValueError):
        min_price = _SMS_MIN_PRICE_DEFAULT
    _SMS_KEY_POOL.configure(
        keys,
        service=str(value.get("service") or "dr"),
        min_price=min_price,
        max_price=float(_clamp_sms_max_price(value.get("max_price"))),
        logger=logger,
        alert_fn=_sms_runtime_alert,
        exhausted_fn=exhausted,
    )
    return sms_proxy


def _preflight_sms_pool(config, *, logs=None, importer=None):
    proxy = _configure_sms_pool(config, logs=logs, importer=importer)
    if not _SMS_KEY_POOL.has_keys():
        raise ValueError("请至少填写一个 SMS API Key")
    statuses = _SMS_KEY_POOL.preflight(proxy=proxy)
    insufficient = [item for item in statuses if item.get("status") == "insufficient_balance"]
    usable = [item for item in statuses if item.get("status") == "usable"]
    if statuses and len(insufficient) == len(statuses):
        raise ValueError("所有 SMS Key 余额不足")
    if not usable:
        details = "；".join(
            f"Key {item.get('index')}: {item.get('message') or item.get('status')}" for item in statuses
        )
        raise ValueError(f"所有 SMS Key 均不可用{f'：{details}' if details else ''}")
    if insufficient:
        indexes = "、".join(str(item.get("index")) for item in insufficient)
        message = f"{len(insufficient)} 个 SMS Key 余额不足（Key {indexes}），其余 Key 仍可运行"
        _SMS_ALERTS.add(
            "sms_balance_insufficient",
            message,
            level="warning",
            dedupe_key=f"preflight:balance:{indexes}",
            persistent=False,
        )
        if logs is not None:
            logs.add(message, "warn")
    unavailable = [item for item in statuses if item.get("status") not in {"usable", "insufficient_balance"}]
    if unavailable:
        indexes = "、".join(str(item.get("index")) for item in unavailable)
        message = f"{len(unavailable)} 个 SMS Key 不可用（Key {indexes}），本次运行已停用"
        _SMS_ALERTS.add(
            "sms_key_unavailable",
            message,
            level="warning",
            dedupe_key=f"preflight:unavailable:{indexes}",
            persistent=False,
        )
        if logs is not None:
            logs.add(message, "warn")
    return statuses


def _resolve_config_path(store, value):
    target = Path(value or "")
    if not target.is_absolute():
        target = store.data_dir / target
    return target


def _read_json_file(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _email_from_row(row):
    match = re.search(
        r"(?i)\b[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
        row or "",
    )
    return match.group(0).lower() if match else ""


def _parse_oauth_mailbox_row(row):
    raw = str(row or "").strip()
    if "----" not in raw:
        return None
    parts = [part.strip() for part in raw.split("----")]
    if len(parts) < 4:
        return None
    email = _email_from_row(parts[0])
    password, oauth_client_id, oauth_refresh_token = parts[1], parts[2], parts[3]
    if not email or not password or not oauth_client_id or not oauth_refresh_token:
        return None
    return email, password, oauth_client_id, oauth_refresh_token


def _is_importable_mailbox_row(row):
    raw = str(row or "").strip()
    if not raw or raw.startswith("#") or not _email_from_row(raw):
        return False
    if "----" in raw:
        return len([part for part in raw.split("----") if part.strip()]) >= 2
    if "|" in raw:
        return len([part for part in raw.split("|") if part.strip()]) >= 3
    return False


def _password_from_row(row):
    raw = str(row or "").strip()
    if not raw:
        return ""
    if "----" in raw:
        parts = [part.strip() for part in raw.split("----")]
        return parts[1] if len(parts) >= 2 else ""
    if "|" in raw:
        parts = [part.strip() for part in raw.split("|")]
        return parts[1] if len(parts) >= 2 else ""
    return ""


def _pool_row_by_line(store, line_no):
    cfg = store.load()
    pool_path = _resolve_config_path(store, cfg.get("pool_path"))
    if not pool_path.exists():
        return "", ""
    try:
        target = int(line_no)
    except (TypeError, ValueError):
        return "", ""
    for index, row in enumerate(pool_path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        row = row.strip()
        if row and index == target:
            return row, _email_from_row(row)
    return "", ""


def _latest_mailbox_code(store, payload):
    row, email = _pool_row_by_line(store, payload.get("line_no"))
    if not row:
        return {"ok": False, "error": "没有找到这一行邮箱"}
    parsed_totp = _parse_chatgpt_totp_row(row)
    if parsed_totp:
        account, _password, secret = parsed_totp
        code = _totp_code(secret)
        remaining = 30 - (int(time.time()) % 30)
        return {
            "ok": True,
            "kind": "totp",
            "email": account,
            "code": code,
            "remaining": remaining,
            "message": f"当前 2FA 验证码，约 {remaining} 秒后刷新",
        }

    parts = [part.strip() for part in row.split("----")]
    password = parts[1] if len(parts) >= 2 else ""
    oauth_client_id = parts[2] if len(parts) >= 3 else ""
    oauth_refresh_token = parts[3] if len(parts) >= 4 else ""
    if not email or not password:
        return {"ok": False, "error": "这一行没有可用于 IMAP 查询的邮箱密码"}
    try:
        poller = _imap_poller.ImapPoller(
            email,
            password,
            verbose=False,
            oauth_client_id=oauth_client_id,
            oauth_refresh_token=oauth_refresh_token,
            proxy="",
        )
        try:
            code = poller.poll_code(
                timeout=5,
                interval=1,
                since_ts=time.time() - 1800,
                recent_scan_limit=40,
                include_existing=True,
            )
        finally:
            try:
                poller.close()
            except Exception:
                pass
    except Exception as exc:
        return {"ok": False, "error": f"IMAP 查询失败: {exc}"}
    if not code:
        return {"ok": True, "kind": "email", "email": email, "code": "", "message": "未找到新的 OpenAI 邮箱验证码"}
    return {"ok": True, "kind": "email", "email": email, "code": str(code), "message": "已找到最新 OpenAI 邮箱验证码"}


def _latest_results_by_email(results_dir):
    latest = {}
    if not results_dir.exists():
        return latest
    for path in results_dir.glob("*.json"):
        data = _read_json_file(path)
        email = _email_from_row(data.get("email") or data.get("source_row") or "")
        if not email:
            continue
        created = int(data.get("created_at") or data.get("updated_at") or path.stat().st_mtime)
        previous = latest.get(email)
        if previous is None or created >= previous.get("_created", 0):
            data["_created"] = created
            latest[email] = data
    return latest


def _human_mailbox_status(state_item, now=None):
    status = _pool_count_status(state_item, now)
    if status == "running":
        return "running", "运行中"
    if status == "consumed":
        return "consumed", "已使用"
    if status == "damaged":
        return "failed", "失败"
    return "available", "可用"


def _friendly_mailbox_error(error):
    value = str(error or "")
    status_messages = {
        "stopped": "任务已停止",
        "stopped_before_start": "任务开始前已停止",
        "manual_restore": "",
    }
    if value in status_messages:
        return status_messages[value]
    if "deleted or deactivated" in value or "You do not have an account" in value:
        return "邮箱对应的 OpenAI 账号不可用（已删除或停用）"
    if "email_otp_failed" in value:
        return "邮箱验证码提交后被 OpenAI 拒绝，请确认该邮箱对应的 OpenAI 账号是否可用"
    return value


def _pool_count_status(state_item, now=None):
    status = str((state_item or {}).get("status") or "").lower()
    if status in {"damaged", "consumed"}:
        return status
    if status == "leased":
        try:
            lease_until = float((state_item or {}).get("lease_until") or 0)
        except (TypeError, ValueError):
            lease_until = 0
        if lease_until > (time.time() if now is None else now):
            return "running"
    return "available"


def _mailbox_rows(store):
    cfg = store.load()
    pool_path = _resolve_config_path(store, cfg.get("pool_path"))
    state_path = _resolve_config_path(store, cfg.get("state_path"))
    results_dir = _resolve_config_path(store, cfg.get("results_dir"))
    lines = []
    if pool_path.exists():
        lines = [line.strip() for line in pool_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]

    state = _read_json_file(state_path)
    state_by_line = {}
    state_by_email = {}
    for item in (state.get("items") or {}).values():
        email = _email_from_row(item.get("email") or "")
        if item.get("line_no"):
            state_by_line[int(item["line_no"])] = item
        if email:
            state_by_email[email] = item

    latest_results = _latest_results_by_email(results_dir)
    rows = []
    counts = {"total": 0, "available": 0, "running": 0, "success": 0, "failed": 0}
    now = time.time()
    for index, row in enumerate(lines, start=1):
        email = _email_from_row(row)
        state_item = state_by_line.get(index) or state_by_email.get(email) or {}
        result = latest_results.get(email) or {}
        manually_restored = (
            str(state_item.get("status") or "").lower() == "available"
            and str(state_item.get("reason") or "") == "manual_restore"
        )
        if manually_restored:
            result = {}
        result_status = str(result.get("status") or "").lower()
        detail_error = (
            result.get("technical_error")
            or (result.get("result") or {}).get("local_oauth_exchange_error")
            or (result.get("result") or {}).get("error")
            or result.get("error")
            or ("" if manually_restored else state_item.get("reason"))
            or ""
        )
        friendly_error = _friendly_mailbox_error(detail_error)
        result_payload = result.get("result") if isinstance(result.get("result"), dict) else {}
        succeeded = result_status in {"success", "ok", "uploaded"}
        sms_cost_usd = result_payload.get("sms_cost_usd", result.get("sms_cost_usd")) if succeeded else None
        sms_cost_cny = result_payload.get("sms_cost_cny", result.get("sms_cost_cny")) if succeeded else None
        sms_exchange_rate = result_payload.get("sms_exchange_rate", result.get("sms_exchange_rate")) if succeeded else None
        sms_exchange_date = result_payload.get("sms_exchange_date", result.get("sms_exchange_date")) if succeeded else ""
        status_key, status_label = _human_mailbox_status(state_item, now)
        counts["total"] += 1
        count_status = _pool_count_status(state_item, now)
        if count_status == "consumed":
            count_status = "success"
        counts[count_status] = counts.get(count_status, 0) + 1
        rows.append(
            {
                "line_no": index,
                "email": email,
                "password": _password_from_row(row),
                "status": status_key,
                "status_label": status_label,
                "pool_status": state_item.get("status") or "available",
                "reason": state_item.get("reason") or "",
                "error": friendly_error,
                "technical_error": detail_error,
                "task_id": result.get("task_id") or "",
                "sms_cost_usd": sms_cost_usd,
                "sms_cost_cny": sms_cost_cny,
                "sms_exchange_rate": sms_exchange_rate,
                "sms_exchange_date": sms_exchange_date or "",
                "updated_at": result.get("created_at") or state_item.get("updated_at") or 0,
                "source_row": row,
            }
        )
    return {"ok": True, "counts": counts, "rows": rows, "pool_path": str(pool_path)}


def _append_mailbox_rows(store, importer, logs, content):
    new_lines = [
        line.strip()
        for line in str(content or "").splitlines()
        if _is_importable_mailbox_row(line)
    ]
    if not new_lines:
        return {"ok": False, "error": "请粘贴要导入的邮箱"}
    cfg = store.load()
    pool_path = _resolve_config_path(store, cfg.get("pool_path"))
    pool_path.parent.mkdir(parents=True, exist_ok=True)
    old_lines = []
    if pool_path.exists():
        old_lines = [line.strip() for line in pool_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    seen = {line.lower() for line in old_lines}
    appended = []
    skipped = 0
    for line in new_lines:
        if line.lower() in seen:
            skipped += 1
            continue
        seen.add(line.lower())
        appended.append(line)
    if not appended:
        return {"ok": False, "error": "没有新增邮箱，可能都是重复行"}
    merged = old_lines + appended
    pool_path.write_text("\n".join(merged).strip() + "\n", encoding="utf-8")
    check = importer._pool(store.load()).validate()
    logs.add(f"邮箱管理追加导入: 新增 {len(appended)} 条，跳过重复 {skipped} 条", "success")
    return {"ok": True, "imported": len(appended), "skipped": skipped, "validate": check}


def _selected_line_numbers(payload):
    result = []
    for value in payload.get("line_nos") or []:
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number > 0:
            result.append(number)
    return sorted(set(result))


def _write_pool_lines(store, lines):
    cfg = store.load()
    pool_path = _resolve_config_path(store, cfg.get("pool_path"))
    pool_path.parent.mkdir(parents=True, exist_ok=True)
    pool_path.write_text(("\n".join(lines).strip() + "\n") if lines else "", encoding="utf-8")
    return pool_path


def _read_pool_lines(store):
    cfg = store.load()
    pool_path = _resolve_config_path(store, cfg.get("pool_path"))
    if not pool_path.exists():
        return []
    return [line.strip() for line in pool_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def _state_paths(store):
    cfg = store.load()
    return _resolve_config_path(store, cfg.get("state_path"))


def _rewrite_state_after_delete(store, kept_lines, deleted_line_nos, deleted_emails):
    state_path = _state_paths(store)
    state = _read_json_file(state_path)
    items = state.get("items") or {}
    kept_email_to_line = {_email_from_row(row): index for index, row in enumerate(kept_lines, start=1)}
    new_items = {}
    for key, item in items.items():
        email = _email_from_row(item.get("email") or "")
        line_no = int(item.get("line_no") or 0)
        if line_no in deleted_line_nos or email in deleted_emails:
            continue
        if email in kept_email_to_line:
            item["line_no"] = kept_email_to_line[email]
            new_items[key] = item
    state["items"] = new_items
    state["updated_at"] = int(time.time())
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _delete_mailboxes(store, importer, logs, payload):
    selected = _selected_line_numbers(payload)
    if not selected:
        return {"ok": False, "error": "请先勾选要删除的邮箱"}
    lines = _read_pool_lines(store)
    selected_set = set(selected)
    deleted_lines = [line for index, line in enumerate(lines, start=1) if index in selected_set]
    kept_lines = [line for index, line in enumerate(lines, start=1) if index not in selected_set]
    if not deleted_lines:
        return {"ok": False, "error": "选中的邮箱不存在或已经删除"}
    _write_pool_lines(store, kept_lines)
    deleted_emails = {_email_from_row(line) for line in deleted_lines if _email_from_row(line)}
    _rewrite_state_after_delete(store, kept_lines, selected_set, deleted_emails)
    importer._pool(store.load()).validate()
    logs.add(f"邮箱管理删除: {len(deleted_lines)} 条", "warn")
    return {"ok": True, "deleted": len(deleted_lines)}


def _restore_mailboxes(store, importer, logs, payload):
    selected = _selected_line_numbers(payload)
    if not selected:
        return {"ok": False, "error": "请先勾选要放回可领取的邮箱"}
    lines = _read_pool_lines(store)
    selected_emails = {
        _email_from_row(line)
        for index, line in enumerate(lines, start=1)
        if index in set(selected) and _email_from_row(line)
    }
    if not selected_emails:
        return {"ok": False, "error": "选中的邮箱不存在"}
    pool = importer._pool(store.load())
    pool.validate()
    state_path = _state_paths(store)
    state = _read_json_file(state_path)
    restored = 0
    now = int(time.time())
    for item in (state.get("items") or {}).values():
        email = _email_from_row(item.get("email") or "")
        if email not in selected_emails:
            continue
        item.update({"status": "available", "lease_until": 0, "reason": "manual_restore", "updated_at": now})
        history = item.setdefault("history", [])
        if isinstance(history, list):
            history.append({"event": "restored", "reason": "manual_restore", "at": now})
        restored += 1
    if restored == 0:
        restored = len(selected_emails)
    state["updated_at"] = now
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    logs.add(f"邮箱管理放回可领取: {restored} 条", "success")
    return {"ok": True, "restored": restored}


_MAILBOX_MANAGER_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>邮箱管理 - gptPhone</title>
<style>
:root{font-family:Arial,"Microsoft YaHei",sans-serif;background:#f5f7fb;color:#172033}*{box-sizing:border-box}html,body{height:100%;overflow:hidden}body{margin:0}.shell{height:100vh;max-width:none;margin:0;padding:10px;display:grid;grid-template-columns:390px minmax(0,1fr);gap:10px;overflow:hidden}.panel{min-height:0;background:#fff;border:1px solid #d7deea;border-radius:8px;padding:12px;box-shadow:0 8px 24px rgba(16,24,40,.08)}.shell>.panel{height:100%;overflow:auto}.shell>.panel:nth-child(2){display:flex;flex-direction:column;overflow:hidden}h2{font-size:15px;margin:0 0 10px}.field label{display:block;color:#465872;font-size:12px;margin-bottom:6px}textarea{width:100%;min-height:260px;resize:vertical;border:1px solid #c6d0df;border-radius:6px;padding:9px;background:#fff;color:#172033;font-family:Consolas,monospace;font-size:13px;line-height:1.45}button{height:32px;padding:0 11px;border:1px solid #b8c5d8;border-radius:6px;background:#eef3fb;color:#172033;font-weight:700;cursor:pointer}button:disabled{opacity:.45;cursor:not-allowed}button.primary{background:#1f73d8;border-color:#1f73d8;color:#fff}button.danger{background:#fff0f0;border-color:#f2b8b8;color:#b42318}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.hint{font-size:12px;color:#60708a;line-height:1.5;margin-top:9px}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:10px}.metric{border:1px solid #d7deea;border-radius:7px;background:#f8fafd;padding:9px}.metric span{display:block;color:#60708a;font-size:11px}.metric b{display:block;font-size:20px;margin-top:4px}.pager{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:8px 0 0;color:#60708a;font-size:12px}.pager-controls{display:flex;align-items:center;gap:8px}.pager select,.bulk-actions select{height:30px;border:1px solid #c6d0df;border-radius:6px;background:#fff;color:#172033}.bulk-actions{display:flex;align-items:center;gap:8px;margin:0 0 8px}.table{flex:1;min-height:0;border:1px solid #d7deea;border-radius:8px;overflow:auto}.row{display:grid;grid-template-columns:34px 54px minmax(220px,1fr) minmax(150px,.58fr) minmax(210px,.9fr) 108px minmax(240px,1.08fr);gap:10px;padding:10px;border-bottom:1px solid #e5eaf3;font-size:12px;align-items:start}.row.head{position:sticky;top:0;background:#f8fafd;font-weight:700;color:#465872;z-index:1}.row input[type=checkbox]{width:16px;height:16px}.email,.password,.code{font-family:Consolas,monospace;word-break:break-all}.code-box{display:flex;gap:6px;align-items:flex-start;flex-wrap:nowrap;min-width:0}.code-box .muted{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.code-box button{height:25px;padding:0 8px;font-size:12px;flex:0 0 auto}.copy-cell{cursor:pointer;color:#174ea6;text-decoration:underline;text-decoration-color:rgba(23,78,166,.25);text-underline-offset:2px}.copy-cell:hover{color:#0b57d0;text-decoration-color:#0b57d0}.muted{color:#7a8798}.reason{color:#465872;word-break:break-word}.status{font-weight:700}.status.available{color:#416f9d}.status.running{color:#a86613}.status.success{color:#178a54}.status.failed{color:#c93545}.toast-host{position:fixed;left:50%;top:18px;z-index:9999;display:flex;flex-direction:column;align-items:center;gap:10px;width:min(520px,calc(100vw - 28px));pointer-events:none;transform:translateX(-50%)}.toast{pointer-events:auto;border:1px solid #dcdfe6;border-radius:4px;background:#f4f4f5;color:#303133;box-shadow:0 6px 18px rgba(31,45,61,.14);padding:10px 14px;font-size:14px}.toast.success{background:#f0f9eb;border-color:#e1f3d8;color:#67c23a}.toast.error{background:#fef0f0;border-color:#fde2e2;color:#f56c6c}.toast.warning{background:#fdf6ec;border-color:#faecd8;color:#e6a23c}@media(max-width:980px){html,body{overflow:auto}.shell{height:auto;min-height:100vh;grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.table{height:560px;flex:none}.row{grid-template-columns:34px 44px 1fr}.row>div:nth-child(n+4){grid-column:3}} 
</style></head><body>
<main class="shell"><section class="panel"><h2>批量追加导入</h2><div class="field"><label>第一种格式：邮箱----取码地址<br>第二种格式：邮箱----密码----client_id----refresh_token<br>第三种格式：GPT账号|登录密码|2FA密钥</label><textarea id="pool_content" placeholder="user@hotmail.com----https://mail.example.test/show/token&#10;user@hotmail.com----password----client_id----refresh_token&#10;gpt-account@example.com|login-password|TOTPSECRET"></textarea></div><div class="actions"><button class="primary" onclick="appendMailboxes()">追加导入</button><button onclick="refreshMailboxes()">刷新状态</button></div><div class="hint">每行一个账号；导入会追加到现有邮箱池，不会覆盖旧邮箱；完全重复的行会跳过。</div></section>
<section class="panel"><h2>邮箱状态</h2><div class="metrics"><div class="metric"><span>总数</span><b id="m_total">0</b></div><div class="metric"><span>可领取</span><b id="m_available">0</b></div><div class="metric"><span>运行中</span><b id="m_running">0</b></div><div class="metric"><span>成功</span><b id="m_success">0</b></div><div class="metric"><span>失败</span><b id="m_failed">0</b></div></div><div class="bulk-actions"><select id="status_filter" onchange="setStatusFilter()"><option value="all">全部</option><option value="not_success">未成功</option><option value="available">可领取</option><option value="running">运行中</option><option value="success">成功</option><option value="failed">失败</option></select><button onclick="restoreSelected()">放回可领取</button><button class="danger" onclick="deleteSelected()">删除选中</button></div><div class="table" id="mailbox_table"></div><div class="pager"><span id="page_info">第 1 / 1 页 · 共 0 条 · 已选 0 条</span><div class="pager-controls"><span>每页</span><select id="page_size" onchange="setPageSize()"><option>25</option><option selected>50</option><option>100</option><option>200</option></select><button onclick="prevPage()">上一页</button><button onclick="nextPage()">下一页</button></div></div></section></main>
<script>
const g=id=>document.getElementById(id);
function toast(message,type="info"){let host=document.querySelector(".toast-host");if(!host){host=document.createElement("div");host.className="toast-host";document.body.appendChild(host)}const item=document.createElement("div");item.className="toast "+type;item.textContent=String(message||"");host.appendChild(item);setTimeout(()=>item.remove(),type==="error"?6500:3000)}
function esc(x){let d=document.createElement("div");d.textContent=x||"";return d.innerHTML}
async function api(path,body){const options=body?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}:{};const r=await fetch(path,options);const j=await r.json();if(!r.ok||!j.ok)throw Error(j.error||"操作失败");return j}
async function copyText(value,label){const text=String(value||"");if(!text||text==="-"){toast(`${label}为空`,"warning");return}try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text)}else{const t=document.createElement("textarea");t.value=text;t.style.position="fixed";t.style.left="-9999px";document.body.appendChild(t);t.focus();t.select();document.execCommand("copy");t.remove()}toast(`已复制${label}`,"success")}catch(e){toast(`复制失败：${e.message||e}`,"error")}}
let mailboxRows=[];let page=1;let pageSize=50;let statusFilter="all";let selected=new Set();let latestCodes={};let checkingCodes=new Set();
function render(data){const c=data.counts||{};["total","available","running","success","failed"].forEach(k=>g("m_"+k).textContent=c[k]||0);mailboxRows=data.rows||[];renderPage()}
function codeCell(row){const item=latestCodes[row.line_no]||{};const busy=checkingCodes.has(row.line_no);const code=item.code||"";const text=busy?"查询中...":(code||item.message||"未查询");const copy=code?`<span class="code copy-cell" data-label="验证码" data-copy="${esc(code)}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(code)}</span>`:`<span class="muted">${esc(text)}</span>`;return `<div class="code-box">${copy}<button onclick="checkCode(${row.line_no})" ${busy?"disabled":""}>查码</button></div>`}
function filteredRows(){return mailboxRows.filter(row=>statusFilter==="all"||(statusFilter==="not_success"?row.status!=="success":row.status===statusFilter))}
function renderPage(){const visible=filteredRows();const total=visible.length;const totalPages=Math.max(1,Math.ceil(total/pageSize));page=Math.min(Math.max(1,page),totalPages);const start=(page-1)*pageSize;const rows=visible.slice(start,start+pageSize);g("page_info").textContent=`第 ${page} / ${totalPages} 页 · 共 ${total} 条 · 已选 ${selected.size} 条`;g("mailbox_table").innerHTML='<div class="row head"><div><input type="checkbox" onchange="togglePage(this.checked)"></div><div>#</div><div>邮箱</div><div>密码</div><div>最新验证码</div><div>状态</div><div>失败原因/说明</div></div>'+rows.map(row=>`<div class="row"><div><input type="checkbox" ${selected.has(row.line_no)?"checked":""} onchange="toggleOne(${row.line_no},this.checked)"></div><div>${row.line_no}</div><div class="email copy-cell" title="点击复制邮箱" data-label="邮箱" data-copy="${esc(row.email||"")}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(row.email||"-")}</div><div class="password copy-cell" title="点击复制密码" data-label="密码" data-copy="${esc(row.password||"")}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(row.password||"-")}</div>${codeCell(row)}<div class="status ${esc(row.status)}">${esc(row.status_label||"-")}</div><div class="reason">${esc(row.error||row.reason||"-")}</div></div>`).join("")}
async function checkCode(lineNo){try{checkingCodes.add(lineNo);renderPage();const j=await api("/api/mailboxes/latest-code",{line_no:lineNo});latestCodes[lineNo]=j;toast(j.message||"查询完成",j.code?"success":"warning")}catch(e){latestCodes[lineNo]={message:e.message||"查询失败"};toast(e.message,"error")}finally{checkingCodes.delete(lineNo);renderPage()}}
function toggleOne(lineNo,checked){if(checked)selected.add(lineNo);else selected.delete(lineNo);renderPage()}
function togglePage(checked){const start=(page-1)*pageSize;filteredRows().slice(start,start+pageSize).forEach(row=>checked?selected.add(row.line_no):selected.delete(row.line_no));renderPage()}
function setStatusFilter(){statusFilter=g("status_filter").value||"all";page=1;renderPage()}
function setPageSize(){pageSize=Number(g("page_size").value||50);page=1;renderPage()}
function prevPage(){page-=1;renderPage()}
function nextPage(){page+=1;renderPage()}
async function refreshMailboxes(){try{render(await api("/api/mailboxes"))}catch(e){toast(e.message,"error")}}
async function appendMailboxes(){try{const content=g("pool_content").value.trim();const j=await api("/api/mailboxes/import",{pool_content:content});g("pool_content").value="";toast(`已追加 ${j.imported||0} 条，跳过 ${j.skipped||0} 条`,"success");localStorage.setItem("gptphone_mailboxes_changed",String(Date.now()));render(j.mailboxes)}catch(e){toast(e.message,"error")}}
async function deleteSelected(){try{if(!selected.size){toast("请先勾选要删除的邮箱","warning");return}if(!confirm(`确定删除选中的 ${selected.size} 条邮箱吗？删除后不会参与运行。`))return;const line_nos=[...selected];const j=await api("/api/mailboxes/delete",{line_nos});selected.clear();toast(`已删除 ${j.deleted||0} 条`,"success");localStorage.setItem("gptphone_mailboxes_changed",String(Date.now()));render(j.mailboxes)}catch(e){toast(e.message,"error")}}
async function restoreSelected(){try{if(!selected.size){toast("请先勾选要放回可领取的邮箱","warning");return}const line_nos=[...selected];const j=await api("/api/mailboxes/restore",{line_nos});selected.clear();toast(`已放回可领取 ${j.restored||0} 条`,"success");localStorage.setItem("gptphone_mailboxes_changed",String(Date.now()));render(j.mailboxes)}catch(e){toast(e.message,"error")}}
refreshMailboxes();setInterval(refreshMailboxes,3000);
</script></body></html>"""


def _patch_flask_app(app):
    if getattr(app, "_gptphone_mac_patched", False):
        return app
    original_start = app.view_functions.get("start")
    original_preflight = app.view_functions.get("preflight")
    if original_start is None:
        return app
    closure = _closure_values(original_start)
    importer = closure["importer"]
    logs = closure["logs"]
    settings = closure["settings"]
    state = closure["state"]
    store = closure["store"]
    initial_config = store.load()
    _write_local_config(_local_config_from_runtime(initial_config, _read_local_config()))
    _configure_sms_pool(initial_config, logs=logs, importer=importer)

    frontend_dist = APP_DIR / "frontend" / "dist"

    def spa_index():
        return _send_from_directory(str(frontend_dist), "index.html")

    def spa_asset(filename):
        return _send_from_directory(str(frontend_dist / "assets"), filename)

    if frontend_dist.exists():
        if "index" in app.view_functions:
            app.view_functions["index"] = spa_index
        else:
            app.add_url_rule("/", "index", spa_index, methods=["GET"])
        if "spa_asset" not in app.view_functions:
            app.add_url_rule("/assets/<path:filename>", "spa_asset", spa_asset, methods=["GET"])

    def public_state():
        return _masked_state(state())

    def api_state():
        return _module.jsonify(ok=True, state=public_state())

    if "api_state" in app.view_functions:
        app.view_functions["api_state"] = api_state

    def save_config():
        if importer.status(settings()).get("running"):
            return _module.jsonify(
                ok=False,
                error="任务运行中，停止后才能修改配置",
                state=public_state(),
            ), 409
        data = _module.request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return _module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
        data = _apply_server_defaults(data)
        data.pop("pool_content", None)
        saved = store.save(data)
        _configure_sms_pool(saved, logs=logs, importer=importer)
        logs.add("独立导入器配置已保存到本工具 data 目录", "success")
        return _module.jsonify(ok=True, settings=_masked_local_config(saved), state=public_state())

    if "save_config" in app.view_functions:
        app.view_functions["save_config"] = save_config

    def stop():
        importer.stop()
        return _module.jsonify(ok=True, state=public_state())

    if "stop" in app.view_functions:
        app.view_functions["stop"] = stop

    def preflight():
        if importer.status(settings()).get("running"):
            return _module.jsonify(ok=False, error="任务运行中，停止后才能执行预检", state=public_state()), 409
        data = _module.request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return _module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400
        try:
            _SMS_ALERTS.begin_run()
            config = store.save(_apply_server_defaults(data))
            statuses = _preflight_sms_pool(config, logs=logs, importer=importer)
            result = importer.settings_validation(config, remote=True)
        except Exception as exc:
            safe = _safe_runtime_error(exc)
            logs.add(f"SMS 预检失败: {safe}", "error")
            return _module.jsonify(
                ok=False,
                error=safe,
                sms_key_statuses=_SMS_KEY_POOL.public_statuses(),
                state=public_state(),
            ), 400
        logs.add(
            f"预检通过: 邮箱池 {result['pool']['entries']} 条，"
            f"SUB2 分组 {result['sub2_group']}#{result['sub2_group_id']}",
            "success",
        )
        return _module.jsonify(
            ok=True,
            result=result,
            sms_key_statuses=statuses,
            state=public_state(),
        )

    if "preflight" in app.view_functions:
        app.view_functions["preflight"] = preflight

    @app.after_request
    def no_cache_response(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    def start():
        try:
            if importer.status(settings()).get("running"):
                return _module.jsonify(
                    ok=False,
                    error="已有任务运行中，请先停止并等待任务结束",
                    state=public_state(),
                ), 409

            data = _module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return _module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400

            data = _apply_server_defaults(data)
            auto_content = _module._clean(data.pop("pool_content", ""))
            cfg = store.save(data)
            pool = importer._pool(cfg)

            if auto_content:
                path = store.save_pool_text(auto_content)
                data.update({"email_mode": "auto", "pool_path": str(path)})
                cfg = store.save(data)
                pool = importer._pool(cfg)
                check = pool.validate()
                if not check.get("ok"):
                    return _module.jsonify(
                        ok=False,
                        error="; ".join(check.get("errors") or ["邮箱池为空"]),
                        state=public_state(),
                    ), 400
                cleared = pool.reset_for_pool_replacement()
                logs.add(f"本次启动已覆盖自动邮箱池: {check['entries']} 条，清除旧状态 {cleared} 条", "success")
            else:
                check = pool.validate()
                if not check.get("ok"):
                    return _module.jsonify(
                        ok=False,
                        error="; ".join(check.get("errors") or ["邮箱池为空"]),
                        state=public_state(),
                    ), 400

            _SMS_ALERTS.begin_run()
            _SMS_COST_LEDGER.clear()
            _SMS_ROUTE_POLICY.reset()
            _SMS_KEY_POOL.begin_run()
            try:
                _preflight_sms_pool(cfg, logs=logs, importer=importer)
            except ValueError as exc:
                return _module.jsonify(ok=False, error=_safe_runtime_error(exc), state=public_state()), 400
            importer.start(cfg)
            return _module.jsonify(ok=True, state=public_state())
        except Exception as exc:
            safe = _safe_runtime_error(exc)
            logs.add(f"启动失败: {safe}", "error")
            return _module.jsonify(ok=False, error=f"启动失败: {safe}", state=public_state()), 500

    app.view_functions["start"] = start

    def start_existing():
        try:
            if importer.status(settings()).get("running"):
                return _module.jsonify(
                    ok=False,
                    error="已有任务运行中，请先停止并等待任务结束",
                    state=public_state(),
                ), 409

            data = _module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return _module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400

            data = _apply_server_defaults(data)
            data.pop("pool_content", None)
            cfg = store.save(data)
            pool = importer._pool(cfg)
            check = pool.validate()
            if not check.get("ok"):
                return _module.jsonify(
                    ok=False,
                    error="; ".join(check.get("errors") or ["邮箱池为空"]),
                    state=public_state(),
                ), 400

            logs.add(f"使用现有自动邮箱池启动: {check['entries']} 条", "info")
            _SMS_ALERTS.begin_run()
            _SMS_COST_LEDGER.clear()
            _SMS_ROUTE_POLICY.reset()
            _SMS_KEY_POOL.begin_run()
            try:
                _preflight_sms_pool(cfg, logs=logs, importer=importer)
            except ValueError as exc:
                return _module.jsonify(ok=False, error=_safe_runtime_error(exc), state=public_state()), 400
            importer.start(cfg)
            return _module.jsonify(ok=True, state=public_state())
        except Exception as exc:
            safe = _safe_runtime_error(exc)
            logs.add(f"启动失败: {safe}", "error")
            return _module.jsonify(ok=False, error=f"启动失败: {safe}", state=public_state()), 500

    if "start_existing" not in app.view_functions:
        app.add_url_rule("/api/start-existing", "start_existing", start_existing, methods=["POST"])

    def mailbox_manager():
        if frontend_dist.exists():
            return spa_index()
        return _module.Response(_MAILBOX_MANAGER_HTML, mimetype="text/html")

    def api_mailboxes():
        return _module.jsonify(_mailbox_rows(store))

    def api_mailboxes_import():
        try:
            data = _module.request.get_json(silent=True) or {}
            result = _append_mailbox_rows(store, importer, logs, data.get("pool_content", ""))
            if not result.get("ok"):
                return _module.jsonify(result), 400
            result["mailboxes"] = _mailbox_rows(store)
            result["state"] = public_state()
            return _module.jsonify(result)
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            logs.add(f"邮箱管理导入失败: {safe}", "error")
            return _module.jsonify(ok=False, error=f"邮箱管理导入失败: {safe}"), 500

    def api_mailboxes_delete():
        try:
            data = _module.request.get_json(silent=True) or {}
            result = _delete_mailboxes(store, importer, logs, data)
            if not result.get("ok"):
                return _module.jsonify(result), 400
            result["mailboxes"] = _mailbox_rows(store)
            result["state"] = public_state()
            return _module.jsonify(result)
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            logs.add(f"邮箱管理删除失败: {safe}", "error")
            return _module.jsonify(ok=False, error=f"邮箱管理删除失败: {safe}"), 500

    def api_mailboxes_restore():
        try:
            data = _module.request.get_json(silent=True) or {}
            result = _restore_mailboxes(store, importer, logs, data)
            if not result.get("ok"):
                return _module.jsonify(result), 400
            result["mailboxes"] = _mailbox_rows(store)
            result["state"] = public_state()
            return _module.jsonify(result)
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            logs.add(f"邮箱管理放回可领取失败: {safe}", "error")
            return _module.jsonify(ok=False, error=f"邮箱管理放回可领取失败: {safe}"), 500

    def api_mailboxes_latest_code():
        try:
            data = _module.request.get_json(silent=True) or {}
            result = _latest_mailbox_code(store, data)
            if not result.get("ok"):
                return _module.jsonify(result), 400
            return _module.jsonify(result)
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            logs.add(f"邮箱管理查码失败: {safe}", "error")
            return _module.jsonify(ok=False, error=f"邮箱管理查码失败: {safe}"), 500

    def api_local_config():
        return _module.jsonify(ok=True, config=_masked_local_config(_read_local_config()))

    def api_local_config_export():
        try:
            data = _module.request.get_json(silent=True) or {}
            download = bool(data.pop("download", False)) if isinstance(data, dict) else False
            config = _write_local_config(_local_config_from_runtime(data, _read_local_config()))
            return _module.jsonify(ok=True, config=config if download else _masked_local_config(config))
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            return _module.jsonify(ok=False, error=f"导出本地配置失败: {safe}"), 500

    def api_local_config_import():
        try:
            data = _module.request.get_json(silent=True) or {}
            config = data.get("config") if isinstance(data, dict) else {}
            if not isinstance(config, dict):
                return _module.jsonify(ok=False, error="配置 JSON 必须是对象"), 400
            config = _write_local_config(_local_config_from_runtime(config, _read_local_config()))
            return _module.jsonify(ok=True, config=_masked_local_config(config))
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            return _module.jsonify(ok=False, error=f"导入本地配置失败: {safe}"), 500

    def api_local_config_secret():
        try:
            data = _module.request.get_json(silent=True) or {}
            value = _local_config_secret(data.get("id") if isinstance(data, dict) else "")
            if not value:
                return _module.jsonify(ok=False, error="本地配置没有保存这个密钥"), 404
            return _module.jsonify(ok=True, value=value)
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            return _module.jsonify(ok=False, error=f"读取本地密钥失败: {safe}"), 500

    if "mailbox_manager" not in app.view_functions:
        app.add_url_rule("/mailboxes", "mailbox_manager", mailbox_manager, methods=["GET"])
    if "api_mailboxes" not in app.view_functions:
        app.add_url_rule("/api/mailboxes", "api_mailboxes", api_mailboxes, methods=["GET"])
    if "api_mailboxes_import" not in app.view_functions:
        app.add_url_rule("/api/mailboxes/import", "api_mailboxes_import", api_mailboxes_import, methods=["POST"])
    if "api_mailboxes_delete" not in app.view_functions:
        app.add_url_rule("/api/mailboxes/delete", "api_mailboxes_delete", api_mailboxes_delete, methods=["POST"])
    if "api_mailboxes_restore" not in app.view_functions:
        app.add_url_rule("/api/mailboxes/restore", "api_mailboxes_restore", api_mailboxes_restore, methods=["POST"])
    if "api_mailboxes_latest_code" not in app.view_functions:
        app.add_url_rule("/api/mailboxes/latest-code", "api_mailboxes_latest_code", api_mailboxes_latest_code, methods=["POST"])
    if "api_local_config" not in app.view_functions:
        app.add_url_rule("/api/local-config", "api_local_config", api_local_config, methods=["GET"])
    if "api_local_config_export" not in app.view_functions:
        app.add_url_rule("/api/local-config/export", "api_local_config_export", api_local_config_export, methods=["POST"])
    if "api_local_config_import" not in app.view_functions:
        app.add_url_rule("/api/local-config/import", "api_local_config_import", api_local_config_import, methods=["POST"])
    if "api_local_config_secret" not in app.view_functions:
        app.add_url_rule("/api/local-config/secret", "api_local_config_secret", api_local_config_secret, methods=["POST"])
    app._gptphone_mac_patched = True
    return app


def create_app(data_dir=None):
    return _patch_flask_app(_ORIGINAL_CREATE_APP(data_dir))


_module.create_app = create_app
if hasattr(_module, "app"):
    _module.app = _patch_flask_app(_module.app)


__doc__ = _module.__doc__
__all__ = [name for name in globals() if not name.startswith("_")]
