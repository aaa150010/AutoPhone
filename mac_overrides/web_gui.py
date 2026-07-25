"""Mac launcher overrides for the recovered web GUI."""

from __future__ import annotations

import importlib.util
import base64
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

import codex_oauth_chain as _codex_oauth_chain
import imap_poller as _imap_poller
import runtime as _runtime
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
_NVTOKEN_IMPORT_URL = "https://nvtokens.com/api/inventory/cards/import"
_NVTOKEN_API_KEY = "irk-c83cad4edd3d3feef6d9effb3fff556bace65c1272e7a28d"


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
        parsed = _parse_chatgpt_totp_row(raw)
        if not parsed:
            continue
        email, password, totp_secret = parsed
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


def _upload_nvtoken(payload, timeout=30):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        _NVTOKEN_IMPORT_URL,
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": _NVTOKEN_API_KEY,
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
    if status == "success" and _as_enabled((settings or {}).get("nvtoken_upload"), True):
        payload = _nvtoken_result_payload(result, entry)
        if payload is None:
            result["nvtoken_upload_ok"] = False
            result["nvtoken_upload_error"] = "missing access_token/refresh_token/email"
            self._log(f"{task_id} [NVToken] 跳过上传: 缺少 token 或 email", "warn")
        elif result.get("nvtoken_upload_ok") is not True:
            ok, http_status, text = _upload_nvtoken(payload)
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
_codex_oauth_chain.RealCodexTransport.verify_password = _patched_real_verify_password
_codex_oauth_chain.RealCodexTransport.send_mfa_otp = _patched_real_send_mfa_otp
_codex_oauth_chain.RealCodexTransport.verify_mfa_otp = _patched_real_verify_mfa_otp
_sms_selector.SmartSmsSelector._build_candidates_locked = _patched_smart_build_candidates

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
.gptmail-section:not(.gptmail-enabled)>.field,
.gptmail-section:not(.gptmail-enabled)>.hint{display:none!important}
#sub2_url[readonly],
#sub2_email[readonly],
#sub2_password[readonly],
#sub2_group[readonly],
#sms_api_key[readonly] {
  opacity: .82;
  cursor: not-allowed;
}
</style>
<script>
(()=>{
  const SUB2_URL = "http://39.106.173.33:8080/";
  const SUB2_EMAIL = "admin@sub2api.local";
  const SUB2_PASSWORD = "7ZdieFkNOe8K5ilM4Tzd4x";
  const SUB2_GROUP = "自动化接码分组";
  const SMS_API_KEY = "YSCqaPKnXepkGFk0q4TwCcr4gMO9Y0lm";
  const PROXY_DEFAULT = "http://127.0.0.1:7897";
  const MAX_PRICE_DEFAULT = "0.1";
  const MIN_PRICE_DEFAULT = "0.01";
  const SMS_PRIORITY_COUNTRIES = ["151", "37", "33", "1", "91", "55"];
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
  const setLocked = (id, value, password=false) => {
    const input = g(id);
    if (!input) return;
    input.value = value;
    input.readOnly = true;
    input.autocomplete = "off";
    if (password) input.type = "password";
    input.title = "已写死为默认值";
  };
  const applyHardwiredDefaults = () => {
    setLocked("sub2_url", SUB2_URL);
    setLocked("sub2_email", SUB2_EMAIL);
    setLocked("sub2_password", SUB2_PASSWORD, true);
    setLocked("sub2_group", SUB2_GROUP);
    setLocked("sms_api_key", SMS_API_KEY, true);
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
  const ensureNvTokenUploadControl = () => {
    if (g("nvtoken_upload")) return;
    const uploadProxy = g("proxy_upload");
    const host = uploadProxy && uploadProxy.closest(".checks");
    if (!host) return;
    const label = document.createElement("label");
    label.innerHTML = '<input id="nvtoken_upload" type="checkbox" checked>上传到 nvtoken 平台';
    host.appendChild(label);
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
    data.sms_api_key = SMS_API_KEY;
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
    data.sub2api = Object.assign({}, data.sub2api || {}, {
      url: SUB2_URL,
      email: SUB2_EMAIL,
      password: SUB2_PASSWORD,
      group: SUB2_GROUP
    });
    data.email_mode = "auto";
    delete data.manual_pool_content;
    return data;
  };
  const baseLoad = load;
  load = function(data){
    const patched = Object.assign({}, data || {});
    patched.sms_api_key = SMS_API_KEY;
    patched.email_mode = "auto";
    patched.concurrency = patched.concurrency || "5";
    patched.node_concurrency = patched.node_concurrency || "5";
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
    patched.sub2api = Object.assign({}, patched.sub2api || {}, {
      url: SUB2_URL,
      email: SUB2_EMAIL,
      password: SUB2_PASSWORD,
      group: SUB2_GROUP
    });
    baseLoad(patched);
    ensureNvTokenUploadControl();
    ensureSmsMinPriceControl();
    const minPriceInput = g("sms_min_price");
    if (minPriceInput) minPriceInput.value = patched.sms_min_price || MIN_PRICE_DEFAULT;
    const nvTokenInput = g("nvtoken_upload");
    if (nvTokenInput) nvTokenInput.checked = patched.nvtoken_upload !== false;
    applyHardwiredDefaults();
  };
  ensureNvTokenUploadControl();
  ensureSmsMinPriceControl();
  applyHardwiredDefaults();
  replaceRootMailboxImport();
  setTimeout(applyHardwiredDefaults, 0);
  setTimeout(applyHardwiredDefaults, 500);
  setTimeout(ensureNvTokenUploadControl, 0);
  setTimeout(ensureNvTokenUploadControl, 500);
  setTimeout(ensureSmsMinPriceControl, 0);
  setTimeout(ensureSmsMinPriceControl, 500);
  setTimeout(replaceRootMailboxImport, 0);
  setTimeout(replaceRootMailboxImport, 500);
  window.addEventListener("storage", event => {
    if (event.key === "gptphone_mailboxes_changed" && typeof refresh === "function") {
      refresh();
    }
  });
  const updateGptmailVisibility = () => {
    const checkbox = g("gptmail_enabled");
    const section = checkbox && checkbox.closest(".gptmail-section");
    if (!section) return;
    const enabled = checkbox.checked;
    section.classList.toggle("gptmail-enabled", enabled);
    section.querySelectorAll(".field,.hint").forEach(node => {
      node.style.display = enabled ? "" : "none";
    });
  };
  const bindGptmailVisibility = () => {
    const checkbox = g("gptmail_enabled");
    if (!checkbox || checkbox.dataset.visibilityBound === "1") return;
    checkbox.dataset.visibilityBound = "1";
    checkbox.addEventListener("change", updateGptmailVisibility);
    updateGptmailVisibility();
  };
  bindGptmailVisibility();
  setTimeout(bindGptmailVisibility, 0);
  setTimeout(bindGptmailVisibility, 500);
  setInterval(() => {
    bindGptmailVisibility();
    updateGptmailVisibility();
  }, 1000);
  const visibilityBaseLoad = load;
  load = function(data){
    visibilityBaseLoad(data);
    bindGptmailVisibility();
    updateGptmailVisibility();
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
      await req("/api/config", cfg());
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


def _apply_hardwired_server_defaults(data):
    patched = dict(data or {})
    patched["sms_api_key"] = "YSCqaPKnXepkGFk0q4TwCcr4gMO9Y0lm"
    patched["email_mode"] = "auto"
    patched["sms_mode"] = "smart"
    patched["country"] = ""
    patched["provider_ids"] = ""
    patched.pop("manual_pool_content", None)
    patched["sub2api"] = {
        **dict(patched.get("sub2api") or {}),
        "url": "http://39.106.173.33:8080/",
        "email": "admin@sub2api.local",
        "password": "7ZdieFkNOe8K5ilM4Tzd4x",
        "group": "自动化接码分组",
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
    }
    patched["nvtoken_upload"] = _as_enabled(patched.get("nvtoken_upload"), True)
    return patched


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


def _human_mailbox_status(pool_status, result_status, error):
    if result_status in {"success", "ok", "uploaded"}:
        return "success", "成功"
    if error or (result_status and result_status not in {"", "available"}):
        if result_status == "retryable_email":
            return "failed", "失败（可重试）"
        return "failed", "失败"
    if pool_status == "leased":
        return "running", "运行中"
    if pool_status == "consumed":
        return "success", "已消耗"
    if pool_status == "damaged":
        return "failed", "损坏"
    return "available", "可领取"


def _friendly_mailbox_error(error):
    value = str(error or "")
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
        status_key, status_label = _human_mailbox_status(
            str(state_item.get("status") or "available").lower(),
            result_status,
            friendly_error,
        )
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
                "updated_at": result.get("created_at") or state_item.get("updated_at") or 0,
                "source_row": row,
            }
        )
    return {"ok": True, "counts": counts, "rows": rows, "pool_path": str(pool_path)}


def _append_mailbox_rows(store, importer, logs, content):
    new_lines = [line.strip() for line in str(content or "").splitlines() if line.strip()]
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
:root{font-family:Arial,"Microsoft YaHei",sans-serif;background:#f5f7fb;color:#172033}*{box-sizing:border-box}html,body{height:100%;overflow:hidden}body{margin:0}.shell{height:100vh;max-width:none;margin:0;padding:10px;display:grid;grid-template-columns:390px minmax(0,1fr);gap:10px;overflow:hidden}.panel{min-height:0;background:#fff;border:1px solid #d7deea;border-radius:8px;padding:12px;box-shadow:0 8px 24px rgba(16,24,40,.08)}.shell>.panel{height:100%;overflow:auto}.shell>.panel:nth-child(2){display:flex;flex-direction:column;overflow:hidden}h2{font-size:15px;margin:0 0 10px}.field label{display:block;color:#465872;font-size:12px;margin-bottom:6px}textarea{width:100%;min-height:260px;resize:vertical;border:1px solid #c6d0df;border-radius:6px;padding:9px;background:#fff;color:#172033;font-family:Consolas,monospace;font-size:13px;line-height:1.45}button{height:32px;padding:0 11px;border:1px solid #b8c5d8;border-radius:6px;background:#eef3fb;color:#172033;font-weight:700;cursor:pointer}button:disabled{opacity:.45;cursor:not-allowed}button.primary{background:#1f73d8;border-color:#1f73d8;color:#fff}button.danger{background:#fff0f0;border-color:#f2b8b8;color:#b42318}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.hint{font-size:12px;color:#60708a;line-height:1.5;margin-top:9px}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:10px}.metric{border:1px solid #d7deea;border-radius:7px;background:#f8fafd;padding:9px}.metric span{display:block;color:#60708a;font-size:11px}.metric b{display:block;font-size:20px;margin-top:4px}.pager{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:0 0 8px;color:#60708a;font-size:12px}.pager-controls{display:flex;align-items:center;gap:8px}.pager select{height:30px;border:1px solid #c6d0df;border-radius:6px;background:#fff;color:#172033}.bulk-actions{display:flex;align-items:center;gap:8px;margin:0 0 8px}.table{flex:1;min-height:0;border:1px solid #d7deea;border-radius:8px;overflow:auto}.row{display:grid;grid-template-columns:34px 54px minmax(220px,1fr) minmax(150px,.58fr) 116px 108px minmax(240px,1.08fr) 116px;gap:10px;padding:10px;border-bottom:1px solid #e5eaf3;font-size:12px;align-items:start}.row.head{position:sticky;top:0;background:#f8fafd;font-weight:700;color:#465872;z-index:1}.row input[type=checkbox]{width:16px;height:16px}.email,.password,.code{font-family:Consolas,monospace;word-break:break-all}.code-box{display:flex;gap:6px;align-items:flex-start;flex-wrap:wrap}.code-box button{height:25px;padding:0 8px;font-size:12px}.copy-cell{cursor:pointer;color:#174ea6;text-decoration:underline;text-decoration-color:rgba(23,78,166,.25);text-underline-offset:2px}.copy-cell:hover{color:#0b57d0;text-decoration-color:#0b57d0}.muted{color:#7a8798}.reason{color:#465872;word-break:break-word}.status{font-weight:700}.status.available{color:#416f9d}.status.running{color:#a86613}.status.success{color:#178a54}.status.failed{color:#c93545}.toast-host{position:fixed;left:50%;top:18px;z-index:9999;display:flex;flex-direction:column;align-items:center;gap:10px;width:min(520px,calc(100vw - 28px));pointer-events:none;transform:translateX(-50%)}.toast{pointer-events:auto;border:1px solid #dcdfe6;border-radius:4px;background:#f4f4f5;color:#303133;box-shadow:0 6px 18px rgba(31,45,61,.14);padding:10px 14px;font-size:14px}.toast.success{background:#f0f9eb;border-color:#e1f3d8;color:#67c23a}.toast.error{background:#fef0f0;border-color:#fde2e2;color:#f56c6c}.toast.warning{background:#fdf6ec;border-color:#faecd8;color:#e6a23c}@media(max-width:980px){html,body{overflow:auto}.shell{height:auto;min-height:100vh;grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.table{height:560px;flex:none}.row{grid-template-columns:34px 44px 1fr}.row>div:nth-child(n+4){grid-column:3}} 
</style></head><body>
<main class="shell"><section class="panel"><h2>批量追加导入</h2><div class="field"><label>第一种格式：邮箱----密码----client_id----refresh_token<br>第二种格式：GPT账号|登录密码|2FA密钥</label><textarea id="pool_content" placeholder="user@hotmail.com----password----client_id----refresh_token&#10;gpt-account@example.com|login-password|TOTPSECRET"></textarea></div><div class="actions"><button class="primary" onclick="appendMailboxes()">追加导入</button><button onclick="refreshMailboxes()">刷新状态</button></div><div class="hint">每行一个账号；导入会追加到现有邮箱池，不会覆盖旧邮箱；完全重复的行会跳过。</div></section>
<section class="panel"><h2>邮箱状态</h2><div class="metrics"><div class="metric"><span>总数</span><b id="m_total">0</b></div><div class="metric"><span>可领取</span><b id="m_available">0</b></div><div class="metric"><span>运行中</span><b id="m_running">0</b></div><div class="metric"><span>成功</span><b id="m_success">0</b></div><div class="metric"><span>失败</span><b id="m_failed">0</b></div></div><div class="bulk-actions"><button onclick="restoreSelected()">放回可领取</button><button class="danger" onclick="deleteSelected()">删除选中</button></div><div class="pager"><span id="page_info">第 1 / 1 页</span><div class="pager-controls"><span>每页</span><select id="page_size" onchange="setPageSize()"><option>25</option><option selected>50</option><option>100</option><option>200</option></select><button onclick="prevPage()">上一页</button><button onclick="nextPage()">下一页</button></div></div><div class="table" id="mailbox_table"></div></section></main>
<script>
const g=id=>document.getElementById(id);
function toast(message,type="info"){let host=document.querySelector(".toast-host");if(!host){host=document.createElement("div");host.className="toast-host";document.body.appendChild(host)}const item=document.createElement("div");item.className="toast "+type;item.textContent=String(message||"");host.appendChild(item);setTimeout(()=>item.remove(),type==="error"?6500:3000)}
function esc(x){let d=document.createElement("div");d.textContent=x||"";return d.innerHTML}
async function api(path,body){const options=body?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}:{};const r=await fetch(path,options);const j=await r.json();if(!r.ok||!j.ok)throw Error(j.error||"操作失败");return j}
async function copyText(value,label){const text=String(value||"");if(!text||text==="-"){toast(`${label}为空`,"warning");return}try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text)}else{const t=document.createElement("textarea");t.value=text;t.style.position="fixed";t.style.left="-9999px";document.body.appendChild(t);t.focus();t.select();document.execCommand("copy");t.remove()}toast(`已复制${label}`,"success")}catch(e){toast(`复制失败：${e.message||e}`,"error")}}
let mailboxRows=[];let page=1;let pageSize=50;let selected=new Set();let latestCodes={};let checkingCodes=new Set();
function render(data){const c=data.counts||{};["total","available","running","success","failed"].forEach(k=>g("m_"+k).textContent=c[k]||0);mailboxRows=data.rows||[];renderPage()}
function codeCell(row){const item=latestCodes[row.line_no]||{};const busy=checkingCodes.has(row.line_no);const code=item.code||"";const text=busy?"查询中...":(code||item.message||"未查询");const copy=code?`<span class="code copy-cell" data-label="验证码" data-copy="${esc(code)}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(code)}</span>`:`<span class="muted">${esc(text)}</span>`;return `<div class="code-box">${copy}<button onclick="checkCode(${row.line_no})" ${busy?"disabled":""}>查码</button></div>`}
function renderPage(){const total=mailboxRows.length;const totalPages=Math.max(1,Math.ceil(total/pageSize));page=Math.min(Math.max(1,page),totalPages);const start=(page-1)*pageSize;const rows=mailboxRows.slice(start,start+pageSize);g("page_info").textContent=`第 ${page} / ${totalPages} 页，共 ${total} 条，已选 ${selected.size} 条`;g("mailbox_table").innerHTML='<div class="row head"><div><input type="checkbox" onchange="togglePage(this.checked)"></div><div>#</div><div>邮箱</div><div>密码</div><div>最新验证码</div><div>状态</div><div>失败原因/说明</div><div>任务</div></div>'+rows.map(row=>`<div class="row"><div><input type="checkbox" ${selected.has(row.line_no)?"checked":""} onchange="toggleOne(${row.line_no},this.checked)"></div><div>${row.line_no}</div><div class="email copy-cell" title="点击复制邮箱" data-label="邮箱" data-copy="${esc(row.email||"")}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(row.email||"-")}</div><div class="password copy-cell" title="点击复制密码" data-label="密码" data-copy="${esc(row.password||"")}" onclick="copyText(this.dataset.copy,this.dataset.label)">${esc(row.password||"-")}</div>${codeCell(row)}<div class="status ${esc(row.status)}">${esc(row.status_label||"-")}</div><div class="reason">${esc(row.error||row.reason||"-")}</div><div>${esc(row.task_id||"-")}</div></div>`).join("")}
async function checkCode(lineNo){try{checkingCodes.add(lineNo);renderPage();const j=await api("/api/mailboxes/latest-code",{line_no:lineNo});latestCodes[lineNo]=j;toast(j.message||"查询完成",j.code?"success":"warning")}catch(e){latestCodes[lineNo]={message:e.message||"查询失败"};toast(e.message,"error")}finally{checkingCodes.delete(lineNo);renderPage()}}
function toggleOne(lineNo,checked){if(checked)selected.add(lineNo);else selected.delete(lineNo);renderPage()}
function togglePage(checked){const start=(page-1)*pageSize;mailboxRows.slice(start,start+pageSize).forEach(row=>checked?selected.add(row.line_no):selected.delete(row.line_no));renderPage()}
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
    if original_start is None:
        return app
    closure = _closure_values(original_start)
    importer = closure["importer"]
    logs = closure["logs"]
    settings = closure["settings"]
    state = closure["state"]
    store = closure["store"]

    def start():
        try:
            if importer.status(settings()).get("running"):
                return _module.jsonify(
                    ok=False,
                    error="已有任务运行中，请先停止并等待任务结束",
                    state=state(),
                ), 409

            data = _module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return _module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400

            data = _apply_hardwired_server_defaults(data)
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
                        state=state(),
                    ), 400
                cleared = pool.reset_for_pool_replacement()
                logs.add(f"本次启动已覆盖自动邮箱池: {check['entries']} 条，清除旧状态 {cleared} 条", "success")
            else:
                check = pool.validate()
                if not check.get("ok"):
                    return _module.jsonify(
                        ok=False,
                        error="; ".join(check.get("errors") or ["邮箱池为空"]),
                        state=state(),
                    ), 400

            importer.start(cfg)
            return _module.jsonify(ok=True, state=state())
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            logs.add(f"启动失败: {safe}", "error")
            return _module.jsonify(ok=False, error=f"启动失败: {safe}", state=state()), 500

    app.view_functions["start"] = start

    def start_existing():
        try:
            if importer.status(settings()).get("running"):
                return _module.jsonify(
                    ok=False,
                    error="已有任务运行中，请先停止并等待任务结束",
                    state=state(),
                ), 409

            data = _module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return _module.jsonify(ok=False, error="配置必须是 JSON 对象"), 400

            data = _apply_hardwired_server_defaults(data)
            data.pop("pool_content", None)
            cfg = store.save(data)
            pool = importer._pool(cfg)
            check = pool.validate()
            if not check.get("ok"):
                return _module.jsonify(
                    ok=False,
                    error="; ".join(check.get("errors") or ["邮箱池为空"]),
                    state=state(),
                ), 400

            logs.add(f"使用现有自动邮箱池启动: {check['entries']} 条", "info")
            importer.start(cfg)
            return _module.jsonify(ok=True, state=state())
        except Exception as exc:
            safe = _module._safe(exc) if hasattr(_module, "_safe") else str(exc)
            logs.add(f"启动失败: {safe}", "error")
            return _module.jsonify(ok=False, error=f"启动失败: {safe}", state=state()), 500

    if "start_existing" not in app.view_functions:
        app.add_url_rule("/api/start-existing", "start_existing", start_existing, methods=["POST"])

    def mailbox_manager():
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
            result["state"] = state()
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
            result["state"] = state()
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
            result["state"] = state()
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
    app._gptphone_mac_patched = True
    return app


def create_app(data_dir=None):
    return _patch_flask_app(_ORIGINAL_CREATE_APP(data_dir))


_module.create_app = create_app
if hasattr(_module, "app"):
    _module.app = _patch_flask_app(_module.app)


__doc__ = _module.__doc__
__all__ = [name for name in globals() if not name.startswith("_")]
