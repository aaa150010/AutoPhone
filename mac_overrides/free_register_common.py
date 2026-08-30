"""Shared primitives for the isolated Free registration runtime."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import secrets
import socket
import time
from typing import Any, Mapping
from urllib.parse import quote, unquote, urlsplit, urlunsplit


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
OTP_RE = re.compile(r"\b(\d{6})\b")
SECRET_MASK = "********"
# Default used by both the signup password page and the optional
# post-registration password continuation.  The value is configurable through
# the isolated Free config; this constant only provides the fallback for old
# direct callers that do not pass a config snapshot.
FIXED_PASSWORD = "Aa150010150010"
FREE_PROXY_SCHEMES = frozenset({"http", "https", "socks4", "socks5", "socks5h"})
DEFAULT_FREE_PROXY_SCHEME = "socks5"
DEFAULT_SOCKS5_DNS_MODE = "remote"
TERMINAL_STATUSES = frozenset({"success", "partial_success", "failed", "stopped", "twofa_pending"})
LOG_SECRET_RE = re.compile(
    r"(?i)(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|token|authorization|"
    r"password|(?:totp|sms|email)[_ -]?(?:secret|code)?|csrf(?:[_ -]?token)?|"
    r"admin[_ -]?token|code[_ -]?verifier|oauth[_ -]?state|state|client[_ -]?secret|api[_ -]?key|"
    r"proxy(?:[_ -]?url)?|mailbox[_ -]?url|cookie|secret)\s*([=:])\s*([^\s,;]+)"
)
# Header values are commonly rendered as ``Authorization: Basic <base64>``.
# The generic assignment rule would otherwise mask only ``Basic`` and leave the
# credential tail in the diagnostic trace. Treat the complete scheme/value as
# one secret before applying the narrower rules below.
LOG_AUTH_HEADER_RE = re.compile(
    r"(?i)(?P<prefix>\bAuthorization\s*:\s*)(?:Basic|Bearer)\s+[^\s,;]+"
)
# JSON and JavaScript object dumps commonly quote both the field name and its
# value.  The legacy assignment expression above intentionally stays narrow
# for plain log lines; handle quoted assignments separately before it runs.
LOG_JSON_SECRET_RE = re.compile(
    r'''(?ix)
        (?<![\w])
        (?P<prefix>[\"']?(?:access[_ -]?token|refresh[_ -]?token|id[_ -]?token|admin[_ -]?token|
            token|authorization|password|cookie|csrf(?:[_ -]?token)?|pkce|
            code[_ -]?verifier|code[_ -]?challenge|oauth[_ -]?code|auth[_ -]?code|
            state|nonce|session(?:[_ -]?token)?|totp[_ -]?secret|
            (?:sms|email|otp)[_ -]?code|proxy[_ -]?username|proxy[_ -]?password|
            (?:proxy|mailbox|pickup)[_ -]?url|
            (?:api|mailbox|pickup|proxy)[_ -]?(?:key|secret|token)|secret)[\"']?\s*:\s*)
        (?P<value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,}\s]+)
    '''
)
LOG_URL_RE = re.compile(r"(?:https?|socks4|socks5h?)://[^\s\"'<>]+", re.IGNORECASE)
LOG_PROXY_CREDENTIAL_RE = re.compile(
    r"(?i)(?<![\w@])(?:"
    r"(?:\[[0-9a-f:]+\]|[a-z0-9.-]+):\d{1,5}:[^:\s,;@]+:[^\s,;@]+|"
    r"[^:\s,;@]+:[^@\s,;]+@(?:\[[0-9a-f:]+\]|[a-z0-9.-]+):\d{1,5}|"
    r"(?:\[[0-9a-f:]+\]|[a-z0-9.-]+):\d{1,5}@[^:\s,;@]+:[^\s,;@]+"
    r")(?![\w@])"
)
LOG_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
LOG_JWT_RE = re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?(?![\w-])")
LOG_CODE_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")
INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")

FREE_STAGE_LABELS = {
    "oauth_create_node": "初始化 Node/Sentinel",
    "free_protocol_preflight": "协议网络预检",
    "free_protocol_warmup": "匿名态 ChatGPT 预热",
    "free_authenticated_warmup": "认证态 ChatGPT 预热",
    "free_protocol_fingerprint": "协议设备与出口画像",
    "free_proxy_geo": "出口地区画像",
    "free_proxy_binding": "绑定 Free 注册代理",
    "proxy_protocol_mismatch": "代理协议不匹配",
    "proxy_auth_rejected": "代理认证失败",
    "proxy_dns_failed": "代理 DNS 解析失败",
    "proxy_connect_timeout": "代理连接超时",
    "proxy_connection_reset": "代理连接被重置",
    "proxy_tls_certificate_error": "代理证书校验失败",
    "proxy_connect_failed": "代理连接失败",
    "free_existing_login": "已有 Free 账号登录",
    "free_existing_login_password": "验证已有 Free 账号密码",
    "free_existing_login_otp": "已有 Free 账号邮箱验证",
    "free_camoufox_dependency": "检查 Camoufox 依赖",
    "free_camoufox_launch": "启动 Camoufox 浏览器池",
    "camoufox_pool_shutdown_pending": "等待 Camoufox 浏览器池关闭",
    "free_camoufox_signup": "Camoufox 页面注册",
    "free_camoufox_signup_email": "填写 Camoufox 注册邮箱",
    "free_camoufox_signup_password": "提交 Camoufox 注册密码",
    "free_camoufox_browser": "Camoufox 注册页面",
    "free_camoufox_navigation": "打开 Camoufox 注册页面",
    "free_camoufox_profile": "填写 Camoufox 账号资料",
    "free_camoufox_challenge": "等待 Camoufox 安全验证",
    "oauth_create_node": "初始化 Node/Sentinel",
    "free_oauth_session": "Free OAuth 会话",
    "free_twofa_reauth": "Free 2FA 重认证诊断",
    "free_twofa_reauth_csrf": "2FA 重认证 CSRF",
    "free_twofa_reauth_signin": "启动 2FA 重认证",
    "free_twofa_reauth_authorize": "打开 2FA 重认证授权页面",
    "free_twofa_otp_wait": "等待 2FA 邮箱验证码",
    "free_twofa_otp_validate": "验证 2FA 邮箱验证码",
    "free_twofa_reauth_callback": "刷新 2FA 重认证会话",
    "free_oauth_security_challenge": "等待 Free OAuth 安全验证",
    "oauth_bootstrap_html": "识别 Free OAuth 授权页面",
    "free_email_identifier": "识别 Free 注册邮箱",
    "free_email_password": "验证 Free 注册密码",
    "free_email_otp_wait": "等待 Free 邮箱验证码",
    "free_existing_login_otp": "等待已有 Free 账号登录验证码",
    "free_email_otp_validate": "验证 Free 邮箱验证码",
    "free_account_create": "创建 Free 账号",
    "free_oauth_callback": "Free OAuth 回调",
    "free_protocol_result": "读取 Free 协议注册结果",
    "free_access_token": "获取 Free access token",
    "free_phone_required": "Free 注册手机号节点",
    "free_plan_check": "查询 Free 套餐资格",
    "free_twofa_enroll": "注册 Free 账号 2FA",
    "free_twofa_activate": "激活 Free 账号 2FA",
    "free_password_eligibility": "检查 Free 账号密码资格",
    "free_password_reauth_csrf": "密码设置重认证 CSRF",
    "free_password_reauth_signin": "启动密码设置重认证",
    "free_password_reauth_authorize": "打开密码设置授权页面",
    "free_password_otp_wait": "等待密码设置邮箱验证码",
    "free_password_otp_validate": "验证密码设置邮箱验证码",
    "free_password_enroll": "打开新密码页面",
    "free_password_add": "提交 Free 账号密码",
    "free_password_callback": "刷新密码设置会话",
    "free_mailbox_released": "释放 Free 邮箱",
    "free_result_save": "保存 Free 注册结果",
    "free_live_proxy_blocked": "出口或服务端安全策略拒绝",
    "free_live_session_rejected": "深度测活会话被拒绝",
    "free_live_rate_limited": "Free 测活触发限流",
    "free_live_upstream_error": "Free 测活上游服务异常",
    "free_live_network_error": "Free 测活网络异常",
    "free_live_password_required": "深度测活需要真实账号密码",
    "free_live_password_context_unknown": "识别深度测活密码页面",
}

FIRST_NAMES = (
    "James", "Robert", "John", "Michael", "David", "William", "Richard", "Joseph",
    "Thomas", "Daniel", "Matthew", "Anthony", "Mark", "Andrew", "Joshua", "Kevin",
    "Brian", "George", "Jason", "Ryan", "Jacob", "Adam", "Nathan", "Henry", "Ethan",
    "Noah", "Liam", "Lucas", "Oliver", "Mary", "Patricia", "Jennifer", "Elizabeth",
    "Jessica", "Sarah", "Karen", "Lisa", "Nancy", "Margaret", "Sandra", "Ashley",
    "Emily", "Michelle", "Amanda", "Melissa", "Rebecca", "Laura", "Rachel", "Maria",
    "Sophia", "Grace",
)
LAST_NAMES = (
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis", "Wilson",
    "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson",
    "Moore", "Young", "Allen", "King", "Wright", "Scott", "Green", "Baker", "Hall",
    "Campbell", "Mitchell", "Roberts", "Carter", "Phillips", "Evans", "Turner", "Parker",
    "Collins", "Stewart", "Morris", "Murphy", "Cook", "Rogers", "Morgan", "Cooper",
    "Peterson", "Reed", "Bailey", "Howard", "Ward", "Watson", "Brooks", "Fisher", "Price",
)


class FreeRegisterError(RuntimeError):
    def __init__(
        self,
        node_code: str,
        node_label: str,
        message: str,
        *,
        retryable: bool = True,
        provider_status: int | str | None = None,
        error_code: str | None = None,
        provider_code: str | None = None,
        action_hint: str | None = None,
        diagnostic: str | None = None,
        page_type: str | None = None,
        safe_page: str | None = None,
        content_type: str | None = None,
        session_rebuilds: int | None = None,
        retry_after_seconds: int | float | None = None,
        declared_scheme: str | None = None,
        transport_scheme: str | None = None,
        target_domain: str | None = None,
        request_stage: str | None = None,
        retry_count: int | None = None,
        transport_error_code: str | None = None,
        debug_session_id: str | None = None,
        debug_artifact_id: str | None = None,
        artifact_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.node_code = node_code
        self.node_label = node_label
        self.retryable = retryable
        self.provider_status = provider_status
        self.error_code = error_code or f"{node_code}_failed"
        self.provider_code = safe_log_message(provider_code)[:120]
        self.action_hint = safe_log_message(action_hint)[:300]
        self.diagnostic = safe_log_message(diagnostic)[:500]
        self.page_type = clean(page_type, 120)
        self.safe_page = safe_log_message(safe_page)[:500]
        self.content_type = clean(content_type, 120)
        self.session_rebuilds = max(0, int(session_rebuilds or 0))
        try:
            parsed_retry_after = float(retry_after_seconds or 0)
        except (TypeError, ValueError):
            parsed_retry_after = 0.0
        self.retry_after_seconds = max(0, min(86400, int(parsed_retry_after)))
        allowed_schemes = FREE_PROXY_SCHEMES
        self.declared_scheme = str(declared_scheme or "").strip().lower()
        if self.declared_scheme not in allowed_schemes:
            self.declared_scheme = ""
        self.transport_scheme = str(transport_scheme or "").strip().lower()
        if self.transport_scheme not in allowed_schemes:
            self.transport_scheme = ""
        self.target_domain = clean(target_domain, 255).lower()
        if self.target_domain:
            try:
                self.target_domain = str(urlsplit(self.target_domain).hostname or self.target_domain).lower()
            except (TypeError, ValueError):
                self.target_domain = ""
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?", self.target_domain):
                self.target_domain = ""
        self.request_stage = clean(request_stage, 120)
        try:
            parsed_retry_count = int(retry_count or 0)
        except (TypeError, ValueError):
            parsed_retry_count = 0
        self.retry_count = max(0, min(100, parsed_retry_count))
        allowed_transport_errors = {
            "proxy_protocol_mismatch", "proxy_auth_rejected", "proxy_dns_failed",
            "proxy_connect_timeout", "proxy_connection_reset",
            "proxy_tls_certificate_error", "proxy_connect_failed", "tls_connection_failed",
        }
        self.transport_error_code = (
            str(transport_error_code or "").strip()
            if str(transport_error_code or "").strip() in allowed_transport_errors else ""
        )
        self.debug_session_id = clean(debug_session_id, 120)
        self.debug_artifact_id = clean(debug_artifact_id or artifact_id, 120)
        self.artifact_id = self.debug_artifact_id


class FreeTwoFaPending(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        token: str,
        plan_type: str,
        plus_trial_eligible: bool,
        node_code: str = "free_twofa_activate",
        node_label: str = "激活 Free 账号 2FA",
        error_code: str | None = None,
        provider_status: int | str | None = None,
        retryable: bool = True,
        provider_code: str | None = None,
        action_hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.token = token
        self.plan_type = plan_type
        self.plus_trial_eligible = plus_trial_eligible
        self.node_code = node_code
        self.node_label = node_label
        self.error_code = error_code or f"{node_code}_failed"
        self.provider_status = provider_status
        self.retryable = retryable
        self.provider_code = safe_log_message(provider_code)[:120]
        self.action_hint = safe_log_message(action_hint)[:300]


@dataclass(frozen=True, slots=True)
class ProxyBinding:
    proxy: str
    fingerprint: str
    masked: str
    exit_ip: str
    proxy_id: str = ""
    scheme: str = ""
    country: str = "ZZ"
    group: str = "默认组"
    # Observed transport scheme.  Appended after the legacy positional fields
    # so recovered callers constructing ProxyBinding positionally remain safe.
    effective_scheme: str = ""
    chatgpt_login_status: int = 0
    chatgpt_login_checked: bool = False
    chatgpt_login_probe_mode: str = ""


@dataclass(frozen=True, slots=True)
class FreeMailbox:
    row_id: str
    line_no: int
    email: str
    mailbox_url: str


def clean(value: Any, limit: int = 500) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()[:limit]


def configured_free_password(config: Mapping[str, Any] | None) -> str:
    """Resolve the configured Free account password without accepting a mask."""
    value = clean((config or {}).get("account_password"), 256) if isinstance(config, Mapping) else ""
    return value if value and value != SECRET_MASK else FIXED_PASSWORD


def safe_log_message(value: Any) -> str:
    message = clean(value, 800).replace(FIXED_PASSWORD, SECRET_MASK)

    def redact_json_secret(match: re.Match[str]) -> str:
        value = match.group("value")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            masked = f"{value[0]}{SECRET_MASK}{value[-1]}"
        else:
            masked = SECRET_MASK
        return f"{match.group('prefix')}{masked}"

    def redact_url(match: re.Match[str]) -> str:
        parsed = urlsplit(match.group(0))
        if not parsed.scheme or not parsed.hostname:
            return SECRET_MASK
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = host + (f":{port}" if port else "")
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))

    def redact_auth_header(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{SECRET_MASK}"

    message = LOG_AUTH_HEADER_RE.sub(redact_auth_header, message)
    message = LOG_URL_RE.sub(redact_url, message)
    message = LOG_PROXY_CREDENTIAL_RE.sub("[代理凭据已隐藏]", message)
    message = LOG_JSON_SECRET_RE.sub(redact_json_secret, message)
    message = LOG_SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}{SECRET_MASK}", message)
    message = LOG_BEARER_RE.sub(f"Bearer {SECRET_MASK}", message)
    message = LOG_JWT_RE.sub(SECRET_MASK, message)
    # Structured task prefixes are identifiers, not OTP values. Keep them
    # intact so account logs can still be matched to their task after redaction.
    prefix = re.match(r"^\[[^\]]{1,500}\]", message)
    if prefix:
        start = prefix.end()
        return message[:start] + LOG_CODE_RE.sub(SECRET_MASK, message[start:])
    return LOG_CODE_RE.sub(SECRET_MASK, message)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(str(value or "").strip().encode("utf-8")).hexdigest()[:16]


def proxy_error_detail(error: BaseException) -> str:
    name = type(error).__name__
    parts: list[str] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(parts) < 3:
        seen.add(id(current))
        value = clean(str(current or ""), 180)
        if value:
            parts.append(value)
        current = current.__cause__ or current.__context__
    technical = " | ".join(parts)
    lowered = technical.lower()
    hint = {
        "SSLError": "TLS/证书握手失败，请确认代理协议与端口匹配",
        "CertificateVerifyError": "TLS/证书校验失败，请确认代理协议与端口匹配",
        "TimeoutError": "连接超时，请检查代理地址、端口和可达性",
        "ConnectTimeout": "连接超时，请检查代理地址、端口和可达性",
        "ProxyError": "代理连接失败，请确认地址、端口和认证信息",
        "ConnectionError": "代理连接失败，请确认地址、端口和认证信息",
        "ValueError": "代理探测响应无效，请确认代理能访问探测地址",
    }.get(name, "请求未建立，请检查代理可达性")
    if "wrong_version_number" in lowered or "wrong version number" in lowered or "proxy protocol" in lowered:
        hint = "代理协议或端口不匹配，请确认代理声明协议"
    elif any(marker in lowered for marker in ("certificate", "cert verify", "ssl", "tls", "handshake")):
        hint = "TLS/证书握手失败，请确认代理协议、端口和证书校验设置"
    elif "407" in lowered or "auth" in lowered or "unauthorized" in lowered:
        hint = "代理认证被拒绝，请确认用户名、密码或白名单"
    elif "timed out" in lowered or "timeout" in lowered:
        hint = "连接超时，请检查代理地址、端口和可达性"
    elif "resolve" in lowered or "name or service" in lowered:
        hint = "代理域名解析失败，请确认主机名和本机 DNS"
    elif "curl: (97)" in lowered or "proxy connect" in lowered or "connect tunnel" in lowered:
        hint = "代理 CONNECT 隧道建立失败，请确认代理协议、端口和白名单"
    # curl-cffi often hides the useful libcurl text inside ProxyError. Keep a
    # short redacted diagnostic so users can distinguish auth, TLS and routing
    # failures without exposing proxy credentials.
    detail = safe_log_message(technical) if technical else "未返回底层错误详情"
    if detail and detail.lower() not in {name.lower(), "proxy error"}:
        return f"{name}（{hint}；底层：{detail}）"
    return f"{name}（{hint}）"


def atomic_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def mask_proxy(value: Any) -> str:
    parsed = urlsplit(str(value or "").strip())
    if not parsed.scheme or not parsed.hostname:
        return ""
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    return urlunsplit((parsed.scheme, host + (f":{port}" if port else ""), "", "", ""))


def parse_mailbox_line(raw: Any) -> tuple[str, str] | None:
    text = clean(raw, 4096)
    if not text:
        return None
    parts = re.split(r"---+|\|", text, maxsplit=2)
    email = parts[0].strip().lower()
    mailbox_url = parts[1].strip() if len(parts) > 1 else ""
    parsed = urlsplit(mailbox_url)
    if not EMAIL_RE.fullmatch(email) or parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return email, urlunsplit(parsed)


def normalize_proxy_value(raw: Any, *, default_scheme: str = DEFAULT_FREE_PROXY_SCHEME) -> str:
    value = clean(raw, 4096)
    if not value:
        return ""
    if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
        value = value[1:-1].strip()
    if INVALID_PERCENT_ESCAPE_RE.search(value):
        return ""
    for separator in ("\t", ",", "|"):
        value = value.replace(separator, " ")
    value = " ".join(value.split())
    if "://" not in value and " " in value:
        parts = value.split()
        if len(parts) >= 2:
            host, port = parts[:2]
            user = parts[2] if len(parts) >= 3 else ""
            password = parts[3] if len(parts) >= 4 else ""
            auth = f"{quote(user, safe='')}:{quote(password, safe='')}@" if user or password else ""
            value = f"{default_scheme}://{auth}{host}:{port}"
    if "://" not in value:
        if "::" in value and "[" not in value:
            return ""
        if "@" in value:
            left, right = value.rsplit("@", 1)
            right_host, separator, right_port = right.rpartition(":")
            left_host, left_separator, left_port = left.rpartition(":")
            if separator and right_host and right_port.isdigit():
                user, auth_separator, password = left.partition(":")
                if not auth_separator:
                    return ""
                value = (
                    f"{default_scheme}://{quote(unquote(user), safe='')}:"
                    f"{quote(unquote(password), safe='')}@{right_host}:{right_port}"
                )
            elif left_separator and left_host and left_port.isdigit():
                user, auth_separator, password = right.partition(":")
                if not auth_separator:
                    return ""
                value = (
                    f"{default_scheme}://{quote(unquote(user), safe='')}:"
                    f"{quote(unquote(password), safe='')}@{left_host}:{left_port}"
                )
            else:
                return ""
        else:
            parts = value.split(":")
            if len(parts) == 4 and parts[1].isdigit():
                host, port, user, password = parts
                value = (
                    f"{default_scheme}://{quote(unquote(user), safe='')}:"
                    f"{quote(unquote(password), safe='')}@{host}:{port}"
                )
            else:
                value = f"{default_scheme}://{value}"
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in FREE_PROXY_SCHEMES or not parsed.hostname or not parsed.port:
            return ""
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return ""
    except ValueError:
        return ""
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    username = quote(unquote(str(parsed.username or "")), safe="")
    password = quote(unquote(str(parsed.password or "")), safe="")
    if bool(username) != bool(password):
        return ""
    auth = f"{username}:{password}@" if username else ""
    return urlunsplit((scheme, f"{auth}{host}:{parsed.port}", "", "", ""))


_FAKE_IP_NETWORKS = (
    ipaddress.ip_network("198.18.0.0/15"),
)
_FAKE_DNS_CACHE: tuple[float, bool] = (0.0, False)


def _local_dns_returns_fake_ip() -> bool:
    """Detect Clash-style synthetic DNS without treating it as proxy health."""
    global _FAKE_DNS_CACHE
    now = time.monotonic()
    cached_at, cached_value = _FAKE_DNS_CACHE
    if now - cached_at < 30:
        return cached_value
    result = False
    try:
        answers = socket.getaddrinfo("chatgpt.com", 443, type=socket.SOCK_STREAM)
        for answer in answers:
            address = str(answer[4][0] or "").split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if any(ip in network for network in _FAKE_IP_NETWORKS):
                result = True
                break
    except OSError:
        result = False
    _FAKE_DNS_CACHE = (now, result)
    return result


def _effective_socks5_scheme(mode: Any) -> str:
    selected = str(mode or "declared").strip().lower()
    if selected not in {"declared", "local", "remote", "auto"}:
        selected = "declared"
    if selected == "remote" or (selected == "auto" and _local_dns_returns_fake_ip()):
        return "socks5h"
    return "socks5"


def proxy_transport_value(
    value: Any,
    *,
    driver: str = "protocol",
    socks5_dns_mode: str = "declared",
) -> str:
    """Return the proxy URL expected by a concrete Free transport.

    The declared scheme is authoritative for protocol requests and probes.
    Browser integrations may normalize only schemes they cannot represent.
    """
    normalized = normalize_proxy_value(value)
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    scheme = parsed.scheme.lower()
    selected_driver = str(driver or "protocol").strip().lower()
    if selected_driver in {"camoufox", "playwright", "browser"} and scheme == "socks5h":
        scheme = "socks5"
    elif selected_driver in {"protocol", "probe", "live"} and scheme == "socks5":
        # SOCKS5 and SOCKS5H use the same proxy wire protocol. The latter is
        # only the curl naming for proxy-side DNS. Preserve the declared
        # scheme in storage and public metadata; use remote DNS only when the
        # configured policy explicitly requests it or the host exposes a
        # Clash-style synthetic address that cannot be routed upstream.
        scheme = _effective_socks5_scheme(socks5_dns_mode)
    return urlunsplit((scheme, parsed.netloc, "", "", ""))


def proxy_transport_config(value: Any, *, driver: str = "protocol") -> dict[str, str]:
    """Build a credential-separated proxy configuration for a transport."""
    normalized = normalize_proxy_value(value)
    if not normalized:
        return {}
    parsed = urlsplit(normalized)
    declared_scheme = parsed.scheme.lower()
    effective = proxy_transport_value(normalized, driver=driver)
    effective_scheme = urlsplit(effective).scheme.lower()
    host = str(parsed.hostname or "")
    if not host or not parsed.port or not effective_scheme:
        return {}
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    result = {
        "server": urlunsplit((effective_scheme, f"{host}:{parsed.port}", "", "", "")),
        "declared_scheme": declared_scheme,
        "effective_scheme": effective_scheme,
    }
    username = unquote(str(parsed.username or ""))
    password = unquote(str(parsed.password or ""))
    if username:
        result["username"] = username
    if password:
        result["password"] = password
    return result


def proxy_error_code(error: BaseException) -> str:
    """Classify transport failures without exposing proxy credentials."""
    parts: list[str] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(parts) < 4:
        seen.add(id(current))
        value = clean(str(current or ""), 240)
        if value:
            parts.append(value)
        current = current.__cause__ or current.__context__
    text = " | ".join(parts).lower()
    if any(marker in text for marker in ("407", "proxy authentication", "authentication required", "auth failed", "invalid username", "invalid password")):
        return "proxy_auth_rejected"
    if any(marker in text for marker in ("wrong_version_number", "wrong version number", "proxy protocol", "socks handshake", "unsupported proxy protocol")):
        return "proxy_protocol_mismatch"
    if any(marker in text for marker in ("could not resolve", "couldn't resolve", "name or service not known", "getaddrinfo", "nodename nor servname", "dns")):
        return "proxy_dns_failed"
    if any(marker in text for marker in ("connection reset", "connectionreset", "reset by peer")):
        return "proxy_connection_reset"
    if any(marker in text for marker in ("timed out", "timeout", "curl: (28)")):
        return "proxy_connect_timeout"
    if any(marker in text for marker in ("certificate verify", "cert verify", "self signed certificate", "curl: (60)", "curl: (77)")):
        return "proxy_tls_certificate_error"
    return "proxy_connect_failed"


def proxy_error_label(code: str) -> str:
    return {
        "proxy_protocol_mismatch": "代理协议不匹配",
        "proxy_auth_rejected": "代理认证失败",
        "proxy_dns_failed": "代理 DNS 解析失败",
        "proxy_connect_timeout": "代理连接超时",
        "proxy_connection_reset": "代理连接被重置",
        "proxy_tls_certificate_error": "代理证书校验失败",
        "proxy_connect_failed": "代理连接失败",
    }.get(str(code or ""), "代理连接失败")


def timezone_offset_minutes() -> int:
    local = time.localtime()
    return -int(local.tm_gmtoff / 60) if hasattr(local, "tm_gmtoff") else int(time.timezone / 60)


def plus_trial_from_accounts(data: Any) -> bool:
    if not isinstance(data, Mapping):
        return False
    accounts = data.get("accounts")
    if not isinstance(accounts, Mapping):
        return False
    candidates = [value for value in accounts.values() if isinstance(value, Mapping)]
    for item in candidates:
        for source in (item, item.get("account")):
            campaigns = source.get("eligible_promo_campaigns") if isinstance(source, Mapping) else None
            if isinstance(campaigns, Mapping) and bool(campaigns.get("plus") or campaigns.get("PLUS")):
                return True
    return False


def random_display_name(rng: random.Random | None = None) -> str:
    source = rng or random.SystemRandom()
    return f"{source.choice(FIRST_NAMES)} {source.choice(LAST_NAMES)}"


def random_birthdate(rng: random.Random | None = None, today: date | None = None) -> str:
    source = rng or random.SystemRandom()
    current = today or date.today()
    newest = current - timedelta(days=18 * 365 + 4)
    oldest = current - timedelta(days=65 * 365 + 16)
    return (oldest + timedelta(days=source.randrange(max(1, (newest - oldest).days) + 1))).isoformat()


__all__ = [
    "DEFAULT_FREE_PROXY_SCHEME", "DEFAULT_SOCKS5_DNS_MODE", "FIXED_PASSWORD", "FREE_PROXY_SCHEMES", "FREE_STAGE_LABELS",
    "FreeMailbox", "FreeRegisterError", "FreeTwoFaPending", "OTP_RE", "ProxyBinding",
    "SECRET_MASK", "TERMINAL_STATUSES", "atomic_write", "clean",
    "configured_free_password", "fingerprint", "mask_proxy", "normalize_proxy_value", "parse_mailbox_line", "proxy_transport_value",
    "proxy_transport_config", "proxy_error_code", "proxy_error_label", "plus_trial_from_accounts", "proxy_error_detail", "random_birthdate", "random_display_name",
    "safe_log_message", "timezone_offset_minutes",
]
