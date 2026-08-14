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
    "action_hint",
    "diagnostic_action",
)

NODE_LABELS = {
    "run_start": "启动注册任务",
    "relogin_start": "启动重登任务",
    "queue_waiting": "排队等待",
    "queue_reserved": "预留邮箱",
    "oauth_create_node": "初始化 Node/Sentinel",
    "oauth_session": "建立 SUB2 OAuth 会话",
    "oauth_authorize_node": "OpenAI OAuth 授权",
    "openai_connectivity_diagnostic": "OpenAI 链路诊断",
    "email_slot_waiting": "等待邮箱验证槽",
    "email_login": "登录邮箱",
    "email_password": "验证邮箱密码",
    "email_code_waiting": "等待邮箱验证码",
    "email_code_verifying": "验证邮箱验证码",
    "mfa_otp_verifying": "验证 2FA 动态码",
    "phone_acquiring": "获取接码号码",
    "phone_submitting": "提交接码号码",
    "sms_waiting": "等待短信验证码",
    "sms_verifying": "验证短信验证码",
    "finalizing_profile": "完善 OpenAI 账号资料",
    "finalizing_callback": "获取 OAuth 回调",
    "finalizing_token": "交换 OAuth Token",
    "finalizing_upload": "上传 SUB2 账号",
    "finalizing_save": "保存任务结果",
    "batch_member_missing_terminal": "运行批次对账",
    "batch_result_missing": "运行批次对账",
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
        "node/sentinel 授权桥接初始化失败",
    }
)

_ACTION_HINTS = {
    "resource_fd_exhausted": "停止继续扩容并等待现有 Node 子进程清理；若持续出现，请降低 Node 并发后重启应用。",
    "node_runtime_missing": "检查 CODEX_NODE_BINARY 或 PATH 中的 Node.js 可执行文件。",
    "node_runner_missing": "检查 SentinelRunner 是否已解包并且 codex_node_runner 路径有效。",
    "node_proxy_failed": "运行 OpenAI 链路诊断并检查当前显式代理地址、认证和可用性。",
    "node_dns_failed": "运行 OpenAI 链路诊断并检查代理或本机 DNS 是否能解析 OpenAI 域名。",
    "node_tls_failed": "运行 OpenAI 链路诊断并检查代理 TLS 转发、证书和系统时间。",
    "node_sentinel_timeout": "运行 OpenAI 链路诊断；若延迟持续偏高，请更换代理或降低 Node 并发。",
    "node_sentinel_http_failed": "查看保留的 HTTP 状态；429 请等待冷却，5xx 可稍后重试或更换代理。",
    "node_sentinel_sdk_failed": "重新准备 Sentinel SDK 缓存，并确认 Runner 与当前 SDK 版本匹配。",
    "node_sentinel_token_missing": "运行 Sentinel 深测；网络正常时请检查 SDK 缓存和 Runner 版本。",
    "node_bridge_invalid_response": "检查 Node 子进程输出和 Runner 版本，确保 stdout 最终返回 JSON。",
    "node_process_failed": "检查 Node 进程退出状态、Runner 文件权限和本机资源限制。",
    "node_sentinel_request_failed": "运行 OpenAI 链路诊断并检查代理稳定性。",
    "node_sentinel_token_failed": "运行 Sentinel 深测以区分网络、SDK 和空 token。",
    "proxy_connection_failed": "检查当前显式代理，确认地址、端口和认证仍然有效。",
    "tls_connection_failed": "检查代理 TLS 转发、证书和系统时间后重试。",
    "remote_disconnected": "更换不稳定代理或降低并发后重试。",
    "oauth_session_invalid": "建立全新 OAuth 会话后重试当前步骤。",
    "email_password_failed": "更新邮箱密码或授权信息后再运行。",
    "mailbox_login_failed": "检查邮箱授权、IMAP 可用性和邮箱代理配置。",
    "email_code_timeout": "确认邮箱可以收到新邮件，并检查取码方式和等待超时。",
    "phone_acquisition_failed": "检查接码平台余额、地区库存和价格上限。",
    "sms_provider_pool_unavailable": "检查已启用平台、Key 状态、余额和号码库存。",
    "sms_timeout": "确认订单仍有效并检查接码平台短信状态。",
    "sub2_oauth_session_failed": "检查 SUB2 管理地址、管理员凭据和上传代理。",
    "sub2_exchange_failed": "重新建立 SUB2 OAuth 会话后再交换 Token。",
    "sub2_upload_failed": "检查 SUB2 服务状态、分组配置和远端校验结果。",
    "result_persistence_failed": "检查结果目录权限和磁盘剩余空间。",
}

_OPENAI_DIAGNOSTIC_CODES = frozenset(
    {
        "node_runtime_missing", "node_runner_missing", "node_proxy_failed",
        "node_dns_failed", "node_tls_failed", "node_sentinel_timeout",
        "node_sentinel_http_failed", "node_sentinel_sdk_failed",
        "node_sentinel_token_missing", "node_bridge_invalid_response",
        "node_process_failed", "node_sentinel_request_failed",
        "node_sentinel_token_failed", "node_sentinel_failed",
        "proxy_connection_failed", "tls_connection_failed", "remote_disconnected",
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
_CODEX_TOTP_STATUS_RE = re.compile(r"\b_status=(\d{3})\b")
_CODEX_TOTP_ERROR_RE = re.compile(r"\berror=([^\s]+)")

_NODE_FAILURE_MARKERS = (
    "node_sentinel_failed",
    "sentinelrunner",
    "sentinel launcher",
    "node_bridge",
    "node bridge",
    "node/sentinel",
)

_SENTINEL_LIFECYCLE_MARKERS = (
    "调用 node 生成 token",
    "token 生成成功",
)

_NODE_OPERATION_NODES = (
    (("mfa_otp_verify", "mfa_otp_failed", "verify_mfa_otp"), "mfa_otp_verifying"),
    (("email_otp_verify", "email_otp_failed", "verify_email_otp"), "email_code_verifying"),
    (("mfa_otp_issue", "email_otp_send_failed"), "email_code_waiting"),
    (("password_verify", "password_verify_failed"), "email_password"),
    (("phone_otp_verify", "phone_otp_failed", "verify_phone_otp"), "sms_verifying"),
    (("phone_number_send", "phone_send_rejected", "send_phone_number_otp"), "phone_submitting"),
    (("create_account_profile", "profile completion"), "finalizing_profile"),
    (("authorize_continue", "initiate_oauth"), "oauth_authorize_node"),
)

_RELOGIN_NON_RETRYABLE_MARKERS = (
    "relogin_phone_required",
    "password_verify_failed",
    "incorrect password",
    "invalid password",
    "wrong password",
    "mfa_otp_failed",
    "verify_mfa_otp",
    "oauth_callback_state_mismatch",
    "oauth_state_mismatch",
    "state mismatch",
    "invalid_state",
    "account_banned",
    "account_deactivated",
    "account_suspended",
    "account_deleted",
)

_NODE_CAUSE_RULES = (
    (
        ("too many open files", "errno 24", "emfile"),
        "resource_fd_exhausted",
        "本机文件描述符已耗尽，系统已暂停新 Node 任务并清理连接",
    ),
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
        ("name resolution", "could not resolve", "getaddrinfo", "nodename nor servname"),
        "node_dns_failed",
        "Node/Sentinel 无法解析 OpenAI 域名",
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
        ("http 429", "http 500", "http 502", "http 503", "http 504", "status_code=429", "status_code=500", "status_code=502", "status_code=503", "status_code=504"),
        "node_sentinel_http_failed",
        "Node/Sentinel 收到异常 HTTP 响应",
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
        ("process exited", "exit code", "returncode", "terminated by signal", "subprocess failed"),
        "node_process_failed",
        "Node/Sentinel 子进程异常退出",
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
    (("batch_member_missing_terminal",), "batch_member_missing_terminal", "batch_member_missing_terminal", "任务线程已结束但没有产生终态，已由批次清单补记失败", True),
    (("batch_result_missing",), "batch_result_missing", "batch_result_missing", "任务终态存在但结果文件缺失，已由批次清单补记失败", True),
    (("account_banned", "account_deactivated", "account_suspended", ACCOUNT_BANNED_MESSAGE.lower()), "account_banned", "account_banned", "", False),
    (("invalid authorization step", "mfa_authorization_step_expired"), "mfa_otp_verifying", "mfa_authorization_step_expired", "2FA 授权步骤在动态码提交前已失效，需要重新建立 OAuth 会话", True),
    (("relogin_phone_required",), "phone_acquiring", "relogin_phone_required", "重登进入手机号验证页面，已停止且未调用接码平台", False),
    (("relogin_sub2_binding_missing",), "finalizing_upload", "relogin_sub2_binding_missing", "重登缺少经过服务端校验的 SUB2 原账号绑定", False),
    (("sub2_update_binding_missing",), "finalizing_upload", "sub2_update_binding_missing", "SUB2 原账号绑定信息缺失", False),
    (("sub2_update_config_missing",), "finalizing_upload", "sub2_update_config_missing", "SUB2 管理员配置不完整", False),
    (("sub2_update_token_incomplete",), "finalizing_upload", "sub2_update_token_incomplete", "用于更新的 OAuth Token 不完整", False),
    (("sub2_update_prepare_failed",), "finalizing_upload", "sub2_update_prepare_failed", "SUB2 原账号更新准备失败", True),
    (("sub2_update_target_missing",), "finalizing_upload", "sub2_update_target_missing", "SUB2 原账号不存在，已停止且未创建新账号", False),
    (("sub2_update_binding_mismatch",), "finalizing_upload", "sub2_update_binding_mismatch", "SUB2 原账号与当前邮箱不匹配，已停止且未创建新账号", False),
    (("sub2_update_existing_failed",), "finalizing_upload", "sub2_update_existing_failed", "SUB2 原账号更新请求失败", True),
    (("sub2_update_verification_failed",), "finalizing_upload", "sub2_update_verification_failed", "SUB2 原账号更新后回查失败", True),
    (("sub2_update_group_verification_failed",), "finalizing_upload", "sub2_update_group_verification_failed", "SUB2 原账号更新后分组校验失败", False),
    (("sub2_update_identity_verification_failed",), "finalizing_upload", "sub2_update_identity_verification_failed", "SUB2 原账号更新后 OpenAI 身份校验失败", False),
    (("sub2_exchange_failed", "sub2_session_expired", "openai_oauth_session_not_found", "openai_oauth_token_exchange_failed", "sub2 exchange-code failed", "sub2 exchange-code request failed"), "finalizing_token", "sub2_exchange_failed", "SUB2 OAuth 会话已过期或 Token 兑换被拒绝", True),
    (("oauth_callback_missing_code", "oauth_callback_state_mismatch", "callback missing code", "state mismatch", "oauth_state_mismatch", "invalid_state", "follow_continue_until_code"), "finalizing_callback", "oauth_callback_failed", "OAuth 回调未返回有效 code 或 state 校验失败", True),
    (("exchange_code", "token_exchange_failed", "token exchange", "token endpoint", "invalid_grant"), "finalizing_token", "oauth_token_exchange_failed", "OAuth Token 交换被服务端拒绝", True),
    (("sub2api登录失败", "generate-auth-url", "generate_auth_url", "missing auth_url", "missing session_id", "missing oauth session"), "oauth_session", "sub2_oauth_session_failed", "SUB2 管理员登录或 OAuth 会话创建失败", True),
    (("node_sentinel_failed", "sentinel launcher", "node_bridge", "node bridge", "sentinel"), "oauth_create_node", "node_sentinel_failed", "Node/Sentinel 授权桥接初始化失败", True),
    (("create_account_profile_failed", "create_account_profile", "profile completion"), "finalizing_profile", "profile_completion_failed", "OpenAI 账号资料提交失败", True),
    (("sub2_upload", "sub2 uploaded but chatgpt_account_id verification failed", "cpa_upload_failed", "cpa_token_upload_failed", "upload_failed", "remote_verified", "group_verified", "chatgpt_account_id_verified", "sub2_upload_failed"), "finalizing_upload", "sub2_upload_failed", "SUB2 账号上传或远端校验未完成", True),
    (("password_verify_failed", "incorrect password", "invalid password", "wrong password"), "email_password", "email_password_failed", "OpenAI 登录密码验证失败", False),
    (("microsoft token refresh failed", "authenticated but not connected", "mailbox_imap_error", "authenticate failed", "authenticationfailed", "imap"), "email_login", "mailbox_login_failed", "邮箱登录或 IMAP 授权失败", False),
    (("email_otp_send_failed",), "email_code_waiting", "email_otp_send_failed", "OpenAI 邮箱验证码发送接口失败", True),
    (("mailbox_code_timeout", "gptmail_code_timeout", "email_otp_timeout", "manual_code_timeout", "mailbox still returns baseline code"), "email_code_waiting", "email_code_timeout", "邮箱验证码等待超时，未获取到新验证码", True),
    (("mfa_otp_failed", "verify_mfa_otp"), "mfa_otp_verifying", "mfa_otp_verification_failed", "2FA 动态码验证失败", True),
    (("email_otp_failed", "verify_email_otp"), "email_code_verifying", "email_code_verification_failed", "邮箱验证码验证失败", True),
    (("sms_provider_pool_unavailable",), "phone_acquiring", "sms_provider_pool_unavailable", "所有启用接码平台均无可用线路或号码", True),
    (("sms_smart_no_candidate",), "phone_acquiring", "sms_route_pool_exhausted", "当前候选线路均已失败、无号或处于冷却中", True),
    (("sms_key_pool_temporarily_unavailable",), "phone_acquiring", "sms_key_pool_temporarily_unavailable", "所有 SMS Key 正在临时冷却，当前没有可用 Key", True),
    (("no_numbers", "getnumber failed", "get_number", "no numbers"), "phone_acquiring", "phone_acquisition_failed", "接码平台当前没有可用号码", True),
    (("phone_flow_mfa_regressed",), "phone_submitting", "phone_flow_mfa_regressed", "手机号流程回退到 2FA/MFA 页面，需要重新建立登录会话", True),
    (("phone_flow_login_regressed",), "phone_submitting", "phone_flow_login_regressed", "手机号流程回退到登录页面，需要重新建立登录会话", True),
    (("auth_context_page_mismatch",), "phone_submitting", "auth_context_page_mismatch", "手机号提交页面上下文无效，需要重新建立登录会话", True),
    (("auth_context_cookies_missing",), "phone_submitting", "auth_context_cookies_missing", "手机号提交会话缺少有效 cookies，需要重新建立登录会话", True),
    (("auth_context_task_mismatch", "auth_context_generation_mismatch"), "phone_submitting", "auth_context_session_mismatch", "手机号提交会话不属于当前任务，需要重新建立登录会话", True),
    (("phone_channel_mismatch",), "phone_submitting", "phone_channel_mismatch", "OpenAI 将当前号码切换到非短信渠道，无法使用 SMS 接码", True),
    (("phone_security_challenge_required",), "phone_submitting", "phone_security_challenge_required", "OpenAI 要求完成浏览器安全验证，当前手机号提交已停止", True),
    (("phone_send_rejected", "send_phone_number_otp", "suspicious behavior from phone numbers", "unsupported_country_region_territory", "country, region, or territory not supported"), "phone_submitting", "phone_submission_failed", "OpenAI 拒绝当前号码或号码所属地区", True),
    (("sms_provider_ready_failed",), "sms_waiting", "sms_provider_ready_failed", "接码平台确认短信订单失败", True),
    (("sms_provider_poll_failed",), "sms_waiting", "sms_provider_poll_failed", "接码平台短信状态查询失败", True),
    (("sms_activation_replaced",), "sms_waiting", "sms_activation_replaced", "短信轮询结果所属订单已被替换", True),
    (("sms_poll_already_active",), "sms_waiting", "sms_poll_already_active", "同一短信订单出现重复轮询", True),
    (("sms_timeout",), "sms_waiting", "sms_timeout", "短信验证码在两轮等待后仍未送达", True),
    (("phone_otp_empty",), "sms_waiting", "sms_no_code", "接码平台本次等待未返回短信验证码", True),
    (("sms wait", "sms_timeout", "wait_code", "sms code timeout"), "sms_waiting", "sms_wait_failed", "短信验证码等待失败或超时", True),
    (("verify_phone_otp", "phone_otp_failed", "sms verification"), "sms_verifying", "sms_verification_failed", "短信验证码校验失败", True),
    (("oauth_session_invalid", "sign-in session is no longer valid"), "oauth_authorize_node", "oauth_session_invalid", "OpenAI 登录会话已失效", True),
    (("proxyerror", "unable to connect to proxy", "proxy_connect_failed", "connection refused"), "oauth_authorize_node", "proxy_connection_failed", "代理连接失败", True),
    (("ssleoferror", "sslerror", "unexpected_eof_while_reading"), "oauth_authorize_node", "tls_connection_failed", "TLS 连接异常", True),
    (("curl: (56)", "connection closed abruptly"), "oauth_authorize_node", "remote_disconnected", "OpenAI OAuth 请求被远端或代理中途断开，可重试", True),
    (("mailbox_dead",), "email_login", "mailbox_unavailable", "邮箱已确认不可用", False),
    (("persist", "atomic_write", "permission denied", "no space left"), "finalizing_save", "result_persistence_failed", "任务结果写入本地文件失败", True),
)


def _is_oauth_session_invalid(text: str) -> bool:
    return "oauth_session_invalid" in text or "sign-in session is no longer valid" in text


def _rule_for(text: str) -> tuple[str, str, str, bool] | None:
    if (
        not _is_sentinel_lifecycle_trace(text)
        and any(marker in text for marker in _NODE_FAILURE_MARKERS)
    ):
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
    return (
        not _is_sentinel_lifecycle_trace(text)
        and any(marker in text for marker in _NODE_FAILURE_MARKERS)
    )


def is_node_retry_log(value: Any) -> bool:
    """Return true only for a Node/Sentinel failure explicitly being retried."""

    text = _diagnostic_text(value).lower()
    if not is_retryable_node_failure(text):
        return False
    return "重试" in text or bool(re.search(r"\bretr(?:y|ied|ying)\b", text))


def _is_sentinel_lifecycle_trace(value: Any) -> bool:
    text = _diagnostic_text(value).lower()
    return (
        "sentinelrunner" in text
        and not any(marker in text for marker in ("失败", "failed", "error"))
        and any(marker in text for marker in _SENTINEL_LIFECYCLE_MARKERS)
    )


def _best_technical_summary(values: Sequence[Any], *, secrets: Sequence[Any]) -> str:
    best = ""
    best_score = -1
    for value in values:
        text = sanitize_failure_detail(value, secrets=secrets)
        if not text:
            continue
        lowered = text.strip().lower()
        score = 1
        if lowered in _GENERIC_ERRORS or lowered.endswith("：操作失败"):
            score = 0
        if any(marker in lowered for marker in ("http", "status", "timeout", "timed out", "proxy", "tls", "errno", "exception", "error_code")):
            score += 3
        if len(text) > 20:
            score += 1
        if score > best_score:
            best, best_score = text, score
    return best if best_score > 0 else ""


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
    # Keep session expiry at the operation where it surfaced. It is not proof
    # that the leased number itself was rejected or risk-controlled.
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
        cause = "OpenAI 登录会话已失效"
        if session_node in {"phone_submitting", "sms_verifying"}:
            cause += "（发生于手机号绑定阶段，不代表号码已被确认风控）"
        rule = (
            session_node,
            "oauth_session_invalid",
            cause,
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
    if (
        isinstance(result, Mapping)
        and str(result.get("run_mode") or "").strip().lower() == "relogin"
    ):
        if any(marker in search_text for marker in _RELOGIN_NON_RETRYABLE_MARKERS):
            retryable = False
        else:
            retryable = bool(
                http_status == 429
                or any(
                    marker in search_text
                    for marker in (
                        "tls connect",
                        "tls_connection",
                        "ssleoferror",
                        "sslerror",
                        "unexpected_eof",
                        "connection reset",
                        "connection aborted",
                        "connection refused",
                        "remote disconnected",
                        "remote end closed connection",
                        "server disconnected",
                        "connection timeout",
                        "connection timed out",
                        "operation timed out",
                        "timed out after",
                        "curl: (28)",
                        "curl: (35)",
                        "curl: (56)",
                        "http 429",
                        "status=429",
                        "status_code=429",
                        "too many requests",
                        "rate limit",
                        "rate_limited",
                    )
                )
            )
        if http_status is not None and 400 <= http_status < 500 and http_status != 429:
            retryable = False

    technical_summary = _best_technical_summary(values, secrets=secrets)
    if node_code == "account_banned":
        public_message = ACCOUNT_BANNED_MESSAGE
        technical_summary = technical_summary or ACCOUNT_BANNED_MESSAGE
    else:
        if cause in {"Node/Sentinel 授权桥接初始化失败", "node/sentinel 授权桥接初始化失败"}:
            cause = technical_summary or "Node/Sentinel 未返回可识别的底层错误详情"
        cause = cause or technical_summary or "服务端未返回错误详情"
        qualifiers = []
        if http_status is not None and f"{http_status}" not in cause:
            qualifiers.append(f"HTTP {http_status}")
        if provider_code and provider_code not in cause.lower() and provider_code != error_code:
            qualifiers.append(provider_code)
        if qualifiers:
            cause = f"{cause}（{' / '.join(qualifiers)}）"
        public_message = f"{node_label}失败：{cause}"

    action_hint = _ACTION_HINTS.get(error_code, "")
    diagnostic_action = "openai_connectivity" if error_code in _OPENAI_DIAGNOSTIC_CODES else ""
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
        "action_hint": action_hint,
        "diagnostic_action": diagnostic_action,
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
        "action_hint": sanitize_failure_detail(value.get("action_hint"), limit=500),
        "diagnostic_action": sanitize_failure_detail(value.get("diagnostic_action"), limit=80),
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


def is_success_diagnostic_trace(value: Any) -> bool:
    """Recognize a successful protocol trace that merely names an error field."""

    text = str(value or "")
    if _is_sentinel_lifecycle_trace(text):
        return True
    if "[CodexTOTP]" not in text:
        return False
    status_match = _CODEX_TOTP_STATUS_RE.search(text)
    error_match = _CODEX_TOTP_ERROR_RE.search(text)
    if status_match is None or error_match is None:
        return False
    status = int(status_match.group(1))
    error = error_match.group(1).strip().lower()
    return 200 <= status < 300 and error in {"-", "none", "null"}


def format_node_retry_log(task_id: Any, detail: Any) -> str:
    """Format a non-terminal Node retry without presenting it as task failure."""

    failure = classify_failure(error=detail)
    message = str(failure.get("public_message") or "")
    cause = message.rsplit("失败：", 1)[-1] if "失败：" in message else message
    cause = sanitize_failure_detail(cause, limit=300) or "本次授权桥接未返回错误详情"
    if cause == "Node/Sentinel 授权桥接初始化失败":
        cause = "Sentinel token 生成未成功"
    prefix = f"{str(task_id or '').strip()} " if str(task_id or "").strip() else ""
    return (
        f"{prefix}[Node/Sentinel 重试/oauth_create_node] "
        f"本次尝试未完成，正在自动重试：{cause}"
    )
