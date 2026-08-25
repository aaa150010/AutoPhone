"""Shared primitives for the isolated Free registration runtime."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
import hashlib
import json
import os
from pathlib import Path
import random
import re
import secrets
import time
from typing import Any, Mapping
from urllib.parse import quote, unquote, urlsplit, urlunsplit


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
OTP_RE = re.compile(r"\b(\d{6})\b")
SECRET_MASK = "********"
FIXED_PASSWORD = "Aa150010@150010"
FREE_PROXY_SCHEMES = frozenset({"http", "https", "socks4", "socks5", "socks5h"})
ROXY_PROXY_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})
DEFAULT_FREE_PROXY_SCHEME = "http"
TERMINAL_STATUSES = frozenset({"success", "partial_success", "failed", "stopped", "twofa_pending"})
LOG_SECRET_RE = re.compile(
    r"(?i)(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|token|authorization|"
    r"password|(?:totp|sms|email)[_ -]?(?:secret|code)?|csrf(?:[_ -]?token)?|"
    r"code[_ -]?verifier|oauth[_ -]?state|state|client[_ -]?secret|api[_ -]?key|"
    r"proxy(?:[_ -]?url)?|mailbox[_ -]?url|cookie|secret)\s*([=:])\s*([^\s,;]+)"
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
    "free_roxy_create": "创建 RoxyBrowser 环境",
    "free_roxy_open": "打开 RoxyBrowser 环境",
    "free_roxy_connect": "连接 RoxyBrowser",
    "free_roxy_ip_verify": "校验 RoxyBrowser 出口 IP",
    "free_roxy_signup": "RoxyBrowser 页面注册",
    "free_roxy_signup_bootstrap": "打开 RoxyBrowser 注册页",
    "free_roxy_signup_email": "填写 Free 注册邮箱",
    "free_roxy_signup_email_submit": "提交 Free 注册邮箱",
    "free_roxy_signup_password": "提交 Free 注册密码",
    "free_roxy_profile": "填写 Free 账号资料",
    "free_roxy_page_state": "等待 RoxyBrowser 页面状态",
    "free_roxy_login_password": "识别登录密码页",
    "free_existing_login": "已有 Free 账号登录",
    "free_existing_login_otp": "已有 Free 账号邮箱验证",
    "free_roxy_challenge": "等待注册页安全验证",
    "free_camoufox_dependency": "检查 Camoufox 依赖",
    "free_camoufox_launch": "启动 Camoufox 浏览器池",
    "free_camoufox_signup": "Camoufox 页面注册",
    "free_camoufox_signup_email": "填写 Camoufox 注册邮箱",
    "free_camoufox_signup_password": "提交 Camoufox 注册密码",
    "free_camoufox_browser": "Camoufox 注册页面",
    "free_camoufox_navigation": "打开 Camoufox 注册页面",
    "free_camoufox_profile": "填写 Camoufox 账号资料",
    "free_camoufox_challenge": "等待 Camoufox 安全验证",
    "oauth_create_node": "初始化 Node/Sentinel",
    "free_oauth_session": "Free OAuth 会话",
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
    "free_roxy_cleanup": "清理 RoxyBrowser 环境",
    "free_roxy_window_quota_exhausted": "RoxyBrowser 窗口额度",
    "free_mailbox_released": "释放 Free 邮箱",
    "free_result_save": "保存 Free 注册结果",
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


def safe_log_message(value: Any) -> str:
    message = clean(value, 800).replace(FIXED_PASSWORD, SECRET_MASK)

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

    message = LOG_URL_RE.sub(redact_url, message)
    message = LOG_PROXY_CREDENTIAL_RE.sub("[代理凭据已隐藏]", message)
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
        "ValueError": "出口 IP 响应无效，请确认代理能访问预检地址",
    }.get(name, "请求未建立，请检查代理可达性")
    if any(marker in lowered for marker in ("certificate", "cert verify", "ssl", "tls", "handshake")):
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


def proxy_transport_value(value: Any, *, driver: str = "protocol") -> str:
    """Return the proxy URL expected by a concrete Free transport."""
    normalized = normalize_proxy_value(value)
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    scheme = parsed.scheme.lower()
    selected_driver = str(driver or "protocol").strip().lower()
    if selected_driver in {"protocol", "probe"} and scheme == "socks5":
        scheme = "socks5h"
    elif selected_driver == "roxybrowser" and scheme == "socks5h":
        scheme = "socks5"
    return urlunsplit((scheme, parsed.netloc, "", "", ""))


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
    "DEFAULT_FREE_PROXY_SCHEME", "FIXED_PASSWORD", "FREE_PROXY_SCHEMES", "FREE_STAGE_LABELS",
    "FreeMailbox", "FreeRegisterError", "FreeTwoFaPending", "OTP_RE", "ProxyBinding",
    "ROXY_PROXY_SCHEMES", "SECRET_MASK", "TERMINAL_STATUSES", "atomic_write", "clean",
    "fingerprint", "mask_proxy", "normalize_proxy_value", "parse_mailbox_line", "proxy_transport_value",
    "plus_trial_from_accounts", "proxy_error_detail", "random_birthdate", "random_display_name",
    "safe_log_message", "timezone_offset_minutes",
]
