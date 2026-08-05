"""Structured, credential-redacted diagnostics for runtime pipeline failures."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit


FAILURE_FIELDS = (
    "node_code",
    "node_label",
    "error_code",
    "provider_code",
    "public_message",
    "technical_summary",
    "retryable",
    "http_status",
)

NODE_LABELS = {
    "queue_waiting": "排队等待",
    "queue_reserved": "预留邮箱",
    "oauth_create_node": "初始化 Node/Sentinel",
    "oauth_session": "建立 SUB2 OAuth 会话",
    "oauth_authorize_node": "OpenAI OAuth 授权",
    "email_slot_waiting": "等待邮箱验证槽",
    "email_login": "登录邮箱",
    "email_password": "验证邮箱密码",
    "email_code_waiting": "等待邮箱验证码",
    "email_code_verifying": "验证邮箱验证码",
    "phone_acquiring": "获取接码号码",
    "phone_submitting": "提交接码号码",
    "sms_waiting": "等待短信验证码",
    "sms_verifying": "验证短信验证码",
    "finalizing_profile": "完善 OpenAI 账号资料",
    "finalizing_callback": "获取 OAuth 回调",
    "finalizing_token": "交换 OAuth Token",
    "finalizing_upload": "上传 SUB2 账号",
    "finalizing_save": "保存任务结果",
    "unexpected": "运行任务",
    "account_banned": "检查 OpenAI 账号状态",
    "openai_quota": "查询 OpenAI 额度",
}

ACCOUNT_BANNED_MESSAGE = "OpenAI 账号已被封禁，无法继续接码"

_GENERIC_ERRORS = frozenset(
    {
        "",
        "unknown error",
        "未知错误",
        "failed",
        "operation failed",
        "操作失败",
        "授权或上传未完成",
    }
)

_CHAIN_NEXT_NODE = {
    "START": "oauth_create_node",
    "CHAT_REQUIREMENTS_READY": "oauth_authorize_node",
    "OAUTH_STARTED": "oauth_authorize_node",
    "SENTINEL_READY": "email_login",
    "PASSWORD_REQUIRED": "email_password",
    "PASSWORD_VERIFIED": "email_login",
    "MFA_OTP_REQUIRED": "email_code_waiting",
    "MFA_OTP_VERIFIED": "email_code_verifying",
    "EMAIL_OTP_REQUIRED": "email_code_waiting",
    "EMAIL_OTP_VERIFIED": "phone_acquiring",
    "PHONE_REQUIRED": "phone_acquiring",
    "PHONE_SEND_REJECTED": "phone_submitting",
    "PHONE_OTP_SENT": "sms_waiting",
    "PHONE_OTP_VERIFIED": "finalizing_profile",
    "CONSENT_REQUIRED": "finalizing_callback",
    "CALLBACK_RECEIVED": "finalizing_token",
    "TOKEN_EXCHANGED": "finalizing_upload",
    "UPLOADED": "finalizing_save",
    "UPLOAD_SKIPPED": "finalizing_save",
    "DONE": "finalizing_save",
}

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?P<prefix>[\"']?)(?P<key>"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|admin[_-]?token|"
    r"authorization|cookie|set-cookie|password|passwd|client[_-]?secret|"
    r"client[_-]?id|api[_-]?key|sms[_-]?key|totp(?:[_-]?secret)?|2fa|"
    r"sms[_-]?code|email[_-]?code|code[_-]?verifier|session[_-]?id|"
    r"oauth[_-]?state|proxy[_-]?(?:password|username)"
    r")(?P=prefix)\s*[:=]\s*(?P<quote>[\"']?)(?P<value>[^\s,;\]}]+)(?P=quote)"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<![\w])\+?\d{8,15}(?![\w])")
_SIX_DIGIT_CODE_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")
_JWT_RE = re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?(?![\w-])")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_LONG_HEX_RE = re.compile(r"(?<![A-Za-z0-9])[A-Fa-f0-9]{24,}(?![A-Za-z0-9])")
_HTTP_STATUS_RES = (
    re.compile(r"(?i)\bHTTP(?:\s+status)?\s*[:=]?\s*(\d{3})\b"),
    re.compile(r"(?i)\bstatus(?:_code)?\s*[:=]\s*(\d{3})\b"),
)
_PROVIDER_CODE_RE = re.compile(
    r"(?i)\b(?:error[_-]?code|provider[_-]?code|type)\s*[:=]\s*[\"']?([A-Za-z][A-Za-z0-9_.-]{1,79})"
)

_NODE_FAILURE_MARKERS = (
    "node_sentinel_failed",
    "sentinelrunner",
    "sentinel launcher",
    "node_bridge",
    "node bridge",
    "node/sentinel",
)

_NODE_OPERATION_NODES = (
    (("mfa_otp_verify", "mfa_otp_failed", "verify_mfa_otp"), "email_code_verifying"),
    (("email_otp_verify", "email_otp_failed", "verify_email_otp"), "email_code_verifying"),
    (("mfa_otp_issue", "email_otp_send_failed"), "email_code_waiting"),
    (("password_verify", "password_verify_failed"), "email_password"),
    (("phone_otp_verify", "phone_otp_failed", "verify_phone_otp"), "sms_verifying"),
    (("phone_number_send", "phone_send_rejected", "send_phone_number_otp"), "phone_submitting"),
    (("create_account_profile", "profile completion"), "finalizing_profile"),
    (("authorize_continue", "initiate_oauth"), "oauth_authorize_node"),
)

_NODE_CAUSE_RULES = (
    (
        ("node executable not found",),
        "node_runtime_missing",
        "未找到可用的 Node.js 可执行文件，请检查 CODEX_NODE_BINARY 或 PATH",
    ),
    (
        (
            "sentinelrunner missing",
            "sentinelrunner not configured",
            "sentinelrunner not found",
            "real node sentinelrunner not configured",
            "real node sentinelrunner not found",
        ),
        "node_runner_missing",
        "SentinelRunner 文件缺失或路径无效",
    ),
    (
        (
            "proxy_connect_failed",
            "proxy_connect_timeout",
            "unsupported_node_proxy_protocol",
            "unable to connect to proxy",
            "proxyerror",
        ),
        "node_proxy_failed",
        "Node/Sentinel 无法连接当前显式代理",
    ),
    (
        ("tls_connect_error", "tls_connect_timeout", "tls connection", "tls connect"),
        "node_tls_failed",
        "Node/Sentinel TLS 连接异常",
    ),
    (
        (
            "node_bridge_timeout",
            "node bridge timeout",
            "request_timeout",
            "operation timed out",
            "timeoutexpired",
        ),
        "node_sentinel_timeout",
        "Node/Sentinel 请求超时",
    ),
    (
        (
            "sentinel_sdk_unavailable",
            "sentinel sdk cache invalid",
            "sentinel sdk patch failed",
        ),
        "node_sentinel_sdk_failed",
        "Sentinel SDK 缓存不可用或与当前版本不兼容",
    ),
    (
        (
            "sentinel_empty_token",
            "empty_requirements_token",
            "empty_enforcement_token",
            "empty_so_token",
            "returned no token",
            "no token",
        ),
        "node_sentinel_token_missing",
        "Sentinel 服务未返回有效 token",
    ),
    (
        ("invalid node json", "empty node stdout", "does not contain a json object"),
        "node_bridge_invalid_response",
        "Node/Sentinel 子进程未返回有效 JSON",
    ),
    (
        (
            "node_json_post_failed",
            "python_json_post_failed",
            "connection reset",
            "remote_disconnected",
        ),
        "node_sentinel_request_failed",
        "Node/Sentinel 网络请求中断",
    ),
    (
        ("token generation failed", "token 生成失败", "token 生成未成功"),
        "node_sentinel_token_failed",
        "Sentinel token 生成未成功",
    ),
)


def _strip_url_secrets(match: re.Match[str]) -> str:
    value = match.group(0).rstrip(".,;:)")
    suffix = match.group(0)[len(value):]
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        if parsed.port:
            hostname = f"{hostname}:{parsed.port}"
        clean = urlunsplit((parsed.scheme, hostname, parsed.path, "", ""))
        return clean + suffix
    except (TypeError, ValueError):
        return "<url>" + suffix


def _diagnostic_text(value: Any, *, depth: int = 0) -> str:
    if value is None:
        return ""
    if isinstance(value, BaseException):
        detail = str(value).strip()
        return f"{type(value).__name__}: {detail}" if detail else type(value).__name__
    if isinstance(value, Mapping):
        if depth >= 3:
            return ""
        parts: list[str] = []
        preferred = (
            "status_code",
            "status",
            "error_code",
            "code",
            "type",
            "error_description",
            "error_message",
            "message",
            "detail",
            "reason",
            "error",
            "technical_error",
        )
        for key in preferred:
            if key not in value or value.get(key) in (None, "", [], {}):
                continue
            child = _diagnostic_text(value.get(key), depth=depth + 1)
            if child:
                parts.append(f"{key}={child}")
        return "; ".join(dict.fromkeys(parts))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if depth >= 3:
            return ""
        parts = [_diagnostic_text(item, depth=depth + 1) for item in list(value)[:5]]
        return "; ".join(item for item in parts if item)
    text = str(value).strip()
    if depth < 3 and text[:1] in {"{", "["} and text[-1:] in {"}", "]"}:
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        else:
            return _diagnostic_text(parsed, depth=depth + 1)
    return text


def sanitize_failure_detail(value: Any, *, secrets: Sequence[Any] = (), limit: int = 500) -> str:
    """Return a short diagnostic summary with credential-shaped values removed."""

    text = _diagnostic_text(value)[:8192]
    if not text:
        return ""
    for secret in secrets:
        item = str(secret or "")
        if len(item) >= 3 and not set(item).issubset({"*"}):
            text = text.replace(item, "********")
    text = _URL_RE.sub(_strip_url_secrets, text)
    text = _BEARER_RE.sub("Bearer ********", text)
    text = _JWT_RE.sub("********", text)
    text = _SENSITIVE_KEY_RE.sub(lambda match: f"{match.group('key')}=********", text)
    text = _EMAIL_RE.sub("<email>", text)
    text = _PHONE_RE.sub("<phone>", text)
    text = _SIX_DIGIT_CODE_RE.sub("<code>", text)
    text = _LONG_HEX_RE.sub("********", text)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip(" ;")
    return text[: max(1, int(limit))]


def _failure_sources(result: Any, error: Any) -> list[Any]:
    values: list[Any] = []
    if isinstance(result, Mapping):
        existing = result.get("failure")
        if isinstance(existing, Mapping):
            values.extend((existing.get("technical_summary"), existing.get("public_message")))
        for key in (
            "technical_error",
            "phase2_error",
            "local_oauth_exchange_error",
            "error",
            "error_description",
            "message",
        ):
            if result.get(key) not in (None, ""):
                values.append(result.get(key))
    if error not in (None, ""):
        values.append(error)
    return values


def _combined_search_text(values: Sequence[Any]) -> str:
    return " ".join(_diagnostic_text(value) for value in values if value not in (None, "")).lower()


def _last_chain_state(result: Any) -> str:
    if not isinstance(result, Mapping):
        return ""
    events = result.get("codex_chain_events")
    if not isinstance(events, list):
        return ""
    for item in reversed(events):
        if isinstance(item, Mapping):
            state = str(item.get("state") or "").strip().upper()
            if state:
                return state
    return ""


def _chain_states(result: Any) -> set[str]:
    if not isinstance(result, Mapping) or not isinstance(result.get("codex_chain_events"), list):
        return set()
    return {
        str(item.get("state") or "").strip().upper()
        for item in result["codex_chain_events"]
        if isinstance(item, Mapping) and item.get("state")
    }


def _current_node(result: Any, progress: Any) -> str:
    if isinstance(progress, Mapping):
        code = str(progress.get("code") or "").strip()
        if code in NODE_LABELS:
            return code
    state = _last_chain_state(result)
    return _CHAIN_NEXT_NODE.get(state, "unexpected")


def _extract_http_status(values: Sequence[Any]) -> int | None:
    for value in values:
        if isinstance(value, Mapping):
            for key in ("status_code", "http_status", "status"):
                try:
                    status = int(value.get(key))
                except (TypeError, ValueError):
                    continue
                if 100 <= status <= 599:
                    return status
        text = _diagnostic_text(value)
        for pattern in _HTTP_STATUS_RES:
            match = pattern.search(text)
            if match:
                return int(match.group(1))
    return None


def _extract_provider_code(values: Sequence[Any]) -> str:
    for value in values:
        if isinstance(value, Mapping):
            for key in ("error_code", "provider_code", "code", "type"):
                candidate = str(value.get(key) or "").strip()
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{1,79}", candidate):
                    return candidate.lower().replace("-", "_").replace(".", "_")
        match = _PROVIDER_CODE_RE.search(_diagnostic_text(value))
        if match:
            return match.group(1).lower().replace("-", "_").replace(".", "_")
    return ""


_RULES = (
    (("account_banned", "account_deactivated", "account_suspended", ACCOUNT_BANNED_MESSAGE.lower()), "account_banned", "account_banned", "", False),
    (("sub2_exchange_failed", "sub2_session_expired", "openai_oauth_session_not_found", "openai_oauth_token_exchange_failed", "sub2 exchange-code failed", "sub2 exchange-code request failed"), "finalizing_token", "sub2_exchange_failed", "SUB2 OAuth 会话已过期或 Token 兑换被拒绝", True),
    (("oauth_callback_missing_code", "oauth_callback_state_mismatch", "callback missing code", "state mismatch", "oauth_state_mismatch", "invalid_state", "follow_continue_until_code"), "finalizing_callback", "oauth_callback_failed", "OAuth 回调未返回有效 code 或 state 校验失败", True),
    (("exchange_code", "token_exchange_failed", "token exchange", "token endpoint", "invalid_grant"), "finalizing_token", "oauth_token_exchange_failed", "OAuth Token 交换被服务端拒绝", True),
    (("sub2api登录失败", "generate-auth-url", "generate_auth_url", "missing auth_url", "missing session_id", "missing oauth session"), "oauth_session", "sub2_oauth_session_failed", "SUB2 管理员登录或 OAuth 会话创建失败", True),
    (("node_sentinel_failed", "sentinel launcher", "node_bridge", "node bridge", "sentinel"), "oauth_create_node", "node_sentinel_failed", "Node/Sentinel 授权桥接初始化失败", True),
    (("create_account_profile_failed", "create_account_profile", "profile completion"), "finalizing_profile", "profile_completion_failed", "OpenAI 账号资料提交失败", True),
    (("sub2_update_existing_failed", "sub2_update_verification_failed", "sub2_update_group_verification_failed", "sub2_update_identity_verification_failed", "sub2_update_binding_mismatch", "sub2_update_target_missing"), "finalizing_upload", "sub2_update_existing_failed", "SUB2 原账号更新或远端校验未完成", True),
    (("sub2_upload", "sub2 uploaded but chatgpt_account_id verification failed", "cpa_upload_failed", "cpa_token_upload_failed", "upload_failed", "remote_verified", "group_verified", "chatgpt_account_id_verified", "sub2_upload_failed"), "finalizing_upload", "sub2_upload_failed", "SUB2 账号上传或远端校验未完成", True),
    (("password_verify_failed", "incorrect password", "invalid password", "wrong password"), "email_password", "email_password_failed", "OpenAI 登录密码验证失败", False),
    (("microsoft token refresh failed", "authenticated but not connected", "mailbox_imap_error", "authenticate failed", "authenticationfailed", "imap"), "email_login", "mailbox_login_failed", "邮箱登录或 IMAP 授权失败", False),
    (("email_otp_send_failed",), "email_code_waiting", "email_otp_send_failed", "OpenAI 邮箱验证码发送接口失败", True),
    (("mailbox_code_timeout", "gptmail_code_timeout", "email_otp_timeout", "manual_code_timeout", "mailbox still returns baseline code"), "email_code_waiting", "email_code_timeout", "邮箱验证码等待超时，未获取到新验证码", True),
    (("email_otp_failed", "mfa_otp_failed", "verify_email_otp", "verify_mfa_otp"), "email_code_verifying", "email_code_verification_failed", "邮箱验证码或 MFA 验证失败", True),
    (("sms_provider_pool_unavailable",), "phone_acquiring", "sms_provider_pool_unavailable", "所有启用接码平台均无可用线路或号码", True),
    (("sms_smart_no_candidate",), "phone_acquiring", "sms_route_pool_exhausted", "当前候选线路均已失败、无号或处于冷却中", True),
    (("sms_key_pool_temporarily_unavailable",), "phone_acquiring", "sms_key_pool_temporarily_unavailable", "所有 SMS Key 正在临时冷却，当前没有可用 Key", True),
    (("no_numbers", "getnumber failed", "get_number", "no numbers"), "phone_acquiring", "phone_acquisition_failed", "接码平台当前没有可用号码", True),
    (("auth_context_page_mismatch",), "phone_submitting", "auth_context_page_mismatch", "手机号提交页面上下文无效，需要重新建立登录会话", True),
    (("auth_context_cookies_missing",), "phone_submitting", "auth_context_cookies_missing", "手机号提交会话缺少有效 cookies，需要重新建立登录会话", True),
    (("phone_send_rejected", "send_phone_number_otp", "suspicious behavior from phone numbers", "unsupported_country_region_territory", "country, region, or territory not supported"), "phone_submitting", "phone_submission_failed", "OpenAI 拒绝当前号码或号码所属地区", True),
    (("sms wait", "sms_timeout", "wait_code", "sms code timeout"), "sms_waiting", "sms_wait_failed", "短信验证码等待失败或超时", True),
    (("verify_phone_otp", "phone_otp_failed", "sms verification"), "sms_verifying", "sms_verification_failed", "短信验证码校验失败", True),
    (("oauth_session_invalid", "sign-in session is no longer valid"), "oauth_authorize_node", "oauth_session_invalid", "OpenAI 登录会话已失效", True),
    (("proxyerror", "unable to connect to proxy", "proxy_connect_failed", "connection refused"), "oauth_authorize_node", "proxy_connection_failed", "代理连接失败", True),
    (("ssleoferror", "sslerror", "unexpected_eof_while_reading"), "oauth_authorize_node", "tls_connection_failed", "TLS 连接异常", True),
    (("mailbox_dead",), "email_login", "mailbox_unavailable", "邮箱已确认不可用", False),
    (("persist", "atomic_write", "permission denied", "no space left"), "finalizing_save", "result_persistence_failed", "任务结果写入本地文件失败", True),
)


def _is_oauth_session_invalid(text: str) -> bool:
    return "oauth_session_invalid" in text or "sign-in session is no longer valid" in text


def _rule_for(text: str) -> tuple[str, str, str, bool] | None:
    if any(marker in text for marker in _NODE_FAILURE_MARKERS):
        operation_node = next(
            (
                node_code
                for markers, node_code in _NODE_OPERATION_NODES
                if any(marker in text for marker in markers)
            ),
            "oauth_create_node",
        )
        for markers, error_code, cause in _NODE_CAUSE_RULES:
            if any(marker in text for marker in markers):
                return operation_node, error_code, cause, True
        return (
            operation_node,
            "node_sentinel_failed",
            "Node/Sentinel 授权桥接初始化失败",
            True,
        )
    for markers, node_code, error_code, cause, retryable in _RULES:
        if any(marker in text for marker in markers):
            return node_code, error_code, cause, retryable
    return None


def is_retryable_node_failure(value: Any) -> bool:
    text = _diagnostic_text(value).lower()
    return any(marker in text for marker in _NODE_FAILURE_MARKERS)


def is_node_retry_log(value: Any) -> bool:
    """Return true only for a Node/Sentinel failure explicitly being retried."""

    text = _diagnostic_text(value).lower()
    if not is_retryable_node_failure(text):
        return False
    return "重试" in text or bool(re.search(r"\bretr(?:y|ied|ying)\b", text))


def _best_technical_summary(values: Sequence[Any], *, secrets: Sequence[Any]) -> str:
    for value in values:
        text = sanitize_failure_detail(value, secrets=secrets)
        if not text:
            continue
        if text.strip().lower() not in _GENERIC_ERRORS:
            return text
    return ""


def classify_failure(
    result: Any = None,
    error: Any = "",
    progress: Any = None,
    *,
    status: Any = "failed",
    secrets: Sequence[Any] = (),
) -> dict[str, Any]:
    """Normalize a runtime failure into a stable and safe public contract."""

    values = _failure_sources(result, error)
    search_text = _combined_search_text(values)
    current_node = _current_node(result, progress)
    rule = _rule_for(search_text)
    # A session error can contain the phone endpoint name. Preserve the
    # operation that actually failed instead of letting a broad OAuth marker
    # or phone-rejection rule rewrite it as a generic authorization failure.
    if _is_oauth_session_invalid(search_text):
        states = _chain_states(result)
        if current_node in {"phone_submitting", "sms_verifying"}:
            session_node = current_node
        elif "PHONE_OTP_SENT" in states:
            session_node = "sms_verifying"
        elif states.intersection({"PHONE_REQUIRED", "PHONE_SEND_REJECTED"}):
            session_node = "phone_submitting"
        else:
            session_node = "oauth_authorize_node"
        rule = (
            session_node,
            "oauth_session_invalid",
            "OpenAI 登录会话已失效",
            True,
        )
    if str(status or "").strip().lower() == "account_banned":
        rule = ("account_banned", "account_banned", "", False)

    if rule is None:
        node_code = current_node
        error_code = _extract_provider_code(values) or f"{node_code}_failed"
        cause = ""
        retryable = node_code not in {"email_password", "account_banned"}
    else:
        node_code, error_code, cause, retryable = rule

    if node_code not in NODE_LABELS:
        node_code = "unexpected"
    node_label = NODE_LABELS[node_code]
    http_status = _extract_http_status(values)
    provider_code = _extract_provider_code(values)

    technical_summary = _best_technical_summary(values, secrets=secrets)
    if node_code == "account_banned":
        public_message = ACCOUNT_BANNED_MESSAGE
        technical_summary = technical_summary or ACCOUNT_BANNED_MESSAGE
    else:
        cause = cause or technical_summary or "服务端未返回错误详情"
        qualifiers = []
        if http_status is not None and f"{http_status}" not in cause:
            qualifiers.append(f"HTTP {http_status}")
        if provider_code and provider_code not in cause.lower() and provider_code != error_code:
            qualifiers.append(provider_code)
        if qualifiers:
            cause = f"{cause}（{' / '.join(qualifiers)}）"
        public_message = f"{node_label}失败：{cause}"

    return {
        "node_code": node_code,
        "node_label": node_label,
        "error_code": sanitize_failure_detail(error_code, limit=80) or f"{node_code}_failed",
        "provider_code": sanitize_failure_detail(provider_code, limit=80),
        "public_message": sanitize_failure_detail(public_message, secrets=secrets, limit=500),
        "technical_summary": sanitize_failure_detail(
            technical_summary or cause or "服务端未返回错误详情",
            secrets=secrets,
            limit=500,
        ),
        "retryable": bool(retryable),
        "http_status": http_status,
    }


def public_failure(value: Any) -> dict[str, Any] | None:
    """Return only known, re-sanitized fields from a persisted failure object."""

    if not isinstance(value, Mapping):
        return None
    node_code = str(value.get("node_code") or "").strip()
    if node_code not in NODE_LABELS:
        return None
    result = {
        "node_code": node_code,
        "node_label": NODE_LABELS[node_code],
        "error_code": sanitize_failure_detail(value.get("error_code"), limit=80),
        "provider_code": sanitize_failure_detail(value.get("provider_code"), limit=80),
        "public_message": sanitize_failure_detail(value.get("public_message"), limit=500),
        "technical_summary": sanitize_failure_detail(value.get("technical_summary"), limit=500),
        "retryable": bool(value.get("retryable")),
        "http_status": None,
    }
    try:
        status = int(value.get("http_status"))
    except (TypeError, ValueError):
        status = None
    result["http_status"] = status if status is not None and 100 <= status <= 599 else None
    if not result["public_message"]:
        return None
    return result


def format_failure_log(task_id: Any, failure: Any) -> str:
    public = public_failure(failure)
    if public is None:
        return ""
    prefix = f"{str(task_id or '').strip()} " if str(task_id or "").strip() else ""
    return (
        f"{prefix}[{public['node_label']}/{public['node_code']}] "
        f"{public['public_message']}"
    )


def format_node_retry_log(task_id: Any, detail: Any) -> str:
    """Format a non-terminal Node retry without presenting it as task failure."""

    failure = classify_failure(error=detail)
    message = str(failure.get("public_message") or "")
    cause = message.split("失败：", 1)[-1] if "失败：" in message else message
    cause = sanitize_failure_detail(cause, limit=300) or "本次授权桥接未返回错误详情"
    if cause == "Node/Sentinel 授权桥接初始化失败":
        cause = "Sentinel token 生成未成功"
    prefix = f"{str(task_id or '').strip()} " if str(task_id or "").strip() else ""
    return (
        f"{prefix}[Node/Sentinel 重试/oauth_create_node] "
        f"本次尝试未完成，正在自动重试：{cause}"
    )
