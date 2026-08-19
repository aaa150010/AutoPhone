"""Isolated Free-account registration runtime.

This module deliberately owns its mailbox pool, proxy bindings, task records,
and secret storage.  It is usable with fake protocol runners in unit tests and
loads the recovered OAuth chain lazily when the desktop application runs.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date, timedelta
import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import random
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote, urlsplit, urlunsplit


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
OTP_RE = re.compile(r"\b(\d{6})\b")
SECRET_MASK = "********"
FIXED_PASSWORD = "nuHf5UFg2vtCW!/"
FREE_PROXY_SCHEMES = frozenset({"http", "https", "socks4", "socks5", "socks5h"})
# autoRegister/proxy_scope normalizes protocol-less rows as HTTP. Explicit
# SOCKS URLs remain unchanged and are passed through to the same transport.
DEFAULT_FREE_PROXY_SCHEME = "http"
TERMINAL_STATUSES = frozenset({"success", "failed", "stopped", "twofa_pending"})
LOG_SECRET_RE = re.compile(
    r"(?i)(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|authorization|"
    r"password|(?:totp|sms|email)[_ -]?(?:secret|code)?|proxy(?:[_ -]?url)?|"
    r"mailbox[_ -]?url|secret)\s*([=:])\s*([^\s,;]+)"
)
LOG_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
LOG_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
LOG_JWT_RE = re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?(?![\w-])")
LOG_CODE_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")

FREE_STAGE_LABELS = {
    "free_proxy_binding": "绑定 Free 注册代理",
    "free_oauth_session": "Free OAuth 会话",
    "free_email_identifier": "识别 Free 注册邮箱",
    "free_email_password": "验证 Free 注册密码",
    "free_email_otp_wait": "等待 Free 邮箱验证码",
    "free_email_otp_validate": "验证 Free 邮箱验证码",
    "free_account_create": "创建 Free 账号",
    "free_oauth_callback": "Free OAuth 回调",
    "free_access_token": "获取 Free access token",
    "free_plan_check": "查询 Free 套餐资格",
    "free_twofa_enroll": "注册 Free 账号 2FA",
    "free_twofa_activate": "激活 Free 账号 2FA",
    "free_result_save": "保存 Free 注册结果",
}

FIRST_NAMES = (
    "James", "Robert", "John", "Michael", "David", "William", "Richard",
    "Joseph", "Thomas", "Daniel", "Matthew", "Anthony", "Mark", "Andrew",
    "Joshua", "Kevin", "Brian", "George", "Jason", "Ryan", "Jacob", "Adam",
    "Nathan", "Henry", "Ethan", "Noah", "Liam", "Lucas", "Oliver", "Mary",
    "Patricia", "Jennifer", "Elizabeth", "Jessica", "Sarah", "Karen", "Lisa",
    "Nancy", "Margaret", "Sandra", "Ashley", "Emily", "Michelle", "Amanda",
    "Melissa", "Rebecca", "Laura", "Rachel", "Maria", "Sophia", "Grace",
)
LAST_NAMES = (
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis",
    "Wilson", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris",
    "Martin", "Thompson", "Moore", "Young", "Allen", "King", "Wright", "Scott",
    "Green", "Baker", "Hall", "Campbell", "Mitchell", "Roberts", "Carter",
    "Phillips", "Evans", "Turner", "Parker", "Collins", "Stewart", "Morris",
    "Murphy", "Cook", "Rogers", "Morgan", "Cooper", "Peterson", "Reed",
    "Bailey", "Howard", "Ward", "Watson", "Brooks", "Fisher", "Price",
)


def _clean(value: Any, limit: int = 500) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()[:limit]


def _safe_log_message(value: Any) -> str:
    message = _clean(value, 800).replace(FIXED_PASSWORD, SECRET_MASK)

    def redact_url(match: re.Match[str]) -> str:
        parsed = urlsplit(match.group(0))
        if not parsed.scheme or not parsed.hostname:
            return SECRET_MASK
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))

    message = LOG_URL_RE.sub(redact_url, message)
    message = LOG_SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}{SECRET_MASK}", message)
    message = LOG_BEARER_RE.sub(f"Bearer {SECRET_MASK}", message)
    message = LOG_JWT_RE.sub(SECRET_MASK, message)
    return LOG_CODE_RE.sub(SECRET_MASK, message)


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(str(value or "").strip().encode("utf-8")).hexdigest()[:16]


def _proxy_error_detail(error: BaseException) -> str:
    """Return a credential-free hint while preserving the exception class."""
    name = type(error).__name__
    hint = {
        "SSLError": "TLS/证书握手失败，请确认代理协议与端口匹配",
        "CertificateVerifyError": "TLS/证书校验失败，请确认代理协议与端口匹配",
        "TimeoutError": "连接超时，请检查代理地址、端口和可达性",
        "ConnectTimeout": "连接超时，请检查代理地址、端口和可达性",
        "ProxyError": "代理连接失败，请确认地址、端口和认证信息",
        "ConnectionError": "代理连接失败，请确认地址、端口和认证信息",
        "ValueError": "出口 IP 响应无效，请确认代理能访问预检地址",
    }.get(name, "请求未建立，请检查代理可达性")
    return f"{name}（{hint}）"


def _timezone_offset_minutes() -> int:
    """Return the browser-compatible signed offset used by the accounts check."""
    local = time.localtime()
    if hasattr(local, "tm_gmtoff"):
        return -int(local.tm_gmtoff / 60)
    return int(time.timezone / 60)


def _plus_trial_from_accounts(data: Any) -> bool:
    """Read the campaign flag from the selected account response without exposing it."""
    if not isinstance(data, Mapping):
        return False
    accounts = data.get("accounts")
    if not isinstance(accounts, Mapping):
        return False
    candidates: list[Mapping[str, Any]] = []
    default = accounts.get("default")
    if isinstance(default, Mapping):
        candidates.append(default)
    candidates.extend(value for key, value in accounts.items() if key != "default" and isinstance(value, Mapping))
    for item in candidates:
        campaigns = item.get("eligible_promo_campaigns")
        if isinstance(campaigns, Mapping) and bool(campaigns.get("plus") or campaigns.get("PLUS")):
            return True
        account = item.get("account")
        if isinstance(account, Mapping):
            campaigns = account.get("eligible_promo_campaigns")
            if isinstance(campaigns, Mapping) and bool(campaigns.get("plus") or campaigns.get("PLUS")):
                return True
    return False


def _atomic_write(path: Path, value: Any) -> None:
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


def _mask_proxy(value: Any) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme and parsed.hostname:
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, "", "", ""))
    return ""


def _parse_mailbox_line(raw: Any) -> tuple[str, str] | None:
    text = _clean(raw, 4096)
    if not text:
        return None
    # Accept the common three-dash form as well as the legacy four-dash form.
    parts = re.split(r"---+|\|", text, maxsplit=2)
    email = parts[0].strip().lower()
    mailbox_url = parts[1].strip() if len(parts) > 1 else ""
    parsed = urlsplit(mailbox_url)
    if not EMAIL_RE.fullmatch(email) or parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return email, urlunsplit(parsed)


def _normalize_proxy_value(raw: Any, *, default_scheme: str = DEFAULT_FREE_PROXY_SCHEME) -> str:
    """Apply the recovered ``proxy_scope.normalize_proxy_url`` rules."""
    value = _clean(raw, 4096)
    if not value:
        return ""
    if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
        value = value[1:-1].strip()
    for separator in ("\t", ",", "|"):
        value = value.replace(separator, " ")
    value = " ".join(value.split())
    if not value:
        return ""

    # The recovered helper accepts whitespace-delimited host rows and always
    # emits HTTP for rows without an explicit scheme.
    if "://" not in value and " " in value:
        parts = value.split()
        if len(parts) >= 2:
            host, port = parts[0], parts[1]
            user = parts[2] if len(parts) >= 3 else ""
            password = parts[3] if len(parts) >= 4 else ""
            auth = (
                f"{quote(user, safe='')}:{quote(password, safe='')}@"
                if user or password
                else ""
            )
            value = f"http://{auth}{host}:{port}"

    if "://" not in value:
        if value.startswith("[") or "@[" in value:
            value = f"http://{value}"
        else:
            colon_parts = value.split(":")
            if "::" in value and "[" not in value:
                return ""
            if len(colon_parts) == 4 and "@" not in value and colon_parts[1].isdigit():
                host, port, user, password = colon_parts
                value = (
                    f"http://{quote(user, safe='')}:{quote(password, safe='')}@"
                    f"{host}:{port}"
                )
            else:
                value = f"http://{value}"

    try:
        parsed = urlsplit(value)
        if parsed.scheme not in FREE_PROXY_SCHEMES or not parsed.hostname or not parsed.port:
            return ""
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return ""
    except ValueError:
        return ""
    return value


def random_display_name(rng: random.Random | None = None) -> str:
    source = rng or random.SystemRandom()
    return f"{source.choice(FIRST_NAMES)} {source.choice(LAST_NAMES)}"


def random_birthdate(rng: random.Random | None = None, today: date | None = None) -> str:
    source = rng or random.SystemRandom()
    current = today or date.today()
    newest = current - timedelta(days=18 * 365 + 4)
    oldest = current - timedelta(days=65 * 365 + 16)
    span = max(1, (newest - oldest).days)
    return (oldest + timedelta(days=source.randrange(span + 1))).isoformat()


class FreeRegisterError(RuntimeError):
    def __init__(self, node_code: str, node_label: str, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.node_code = node_code
        self.node_label = node_label
        self.retryable = retryable


class FreeTwoFaPending(RuntimeError):
    def __init__(self, message: str, *, token: str, plan_type: str, plus_trial_eligible: bool) -> None:
        super().__init__(message)
        self.token = token
        self.plan_type = plan_type
        self.plus_trial_eligible = plus_trial_eligible


@dataclass(frozen=True, slots=True)
class ProxyBinding:
    proxy: str
    fingerprint: str
    masked: str
    exit_ip: str


@dataclass(frozen=True, slots=True)
class FreeMailbox:
    row_id: str
    line_no: int
    email: str
    mailbox_url: str


class FreeMailboxPool:
    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.pool_path = self.data_dir / "free_mailbox_pool.txt"
        self.state_path = self.data_dir / "free_mailbox_state.json"
        self.results_dir = self.data_dir / "free_register_results"
        self._lock = threading.RLock()

    def _state(self) -> dict[str, Any]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            value = {}
        rows = value.get("rows") if isinstance(value, dict) else {}
        return {"version": 1, "rows": rows if isinstance(rows, dict) else {}}

    def import_text(self, content: str) -> int:
        added, _skipped = self.import_text_with_stats(content)
        return added

    def import_text_with_stats(self, content: str) -> tuple[int, int]:
        """Append valid mailbox rows while preserving the existing pool order."""
        incoming = self._parse_content(content)
        if not incoming:
            raise FreeRegisterError("free_pool", "Free 邮箱池", "Free 邮箱池没有有效的邮箱-取码 URL")
        with self._lock:
            existing = self.entries()
            existing_ids = {entry.row_id for entry in existing}
            combined: list[FreeMailbox] = []
            seen: set[str] = set()
            for entry in [*existing, *incoming]:
                if entry.row_id in seen:
                    continue
                seen.add(entry.row_id)
                combined.append(entry)
            added = sum(1 for entry in incoming if entry.row_id not in existing_ids)
            skipped = max(0, len(incoming) - added)
            self._write_entries(combined)
            state = self._state()
            rows = state["rows"]
            for entry in combined:
                rows.setdefault(
                    entry.row_id,
                    {"email": entry.email, "mailbox_url": entry.mailbox_url, "status": "available"},
                )
            _atomic_write(self.state_path, state)
        return added, skipped

    def _write_entries(self, entries: Sequence[FreeMailbox]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = "".join(f"{entry.email}----{entry.mailbox_url}\n" for entry in entries)
        self.pool_path.write_text(payload, encoding="utf-8")
        os.chmod(self.pool_path, 0o600)

    def _parse_content(self, content: str) -> list[FreeMailbox]:
        entries: list[FreeMailbox] = []
        seen: set[str] = set()
        for line_no, raw in enumerate(str(content or "").splitlines(), 1):
            parsed = _parse_mailbox_line(raw)
            if parsed is None:
                continue
            email, mailbox_url = parsed
            row_id = _fingerprint(f"{email}|{mailbox_url}")
            if row_id in seen:
                continue
            seen.add(row_id)
            entries.append(FreeMailbox(row_id, line_no, email, mailbox_url))
        return entries

    def entries(self) -> list[FreeMailbox]:
        try:
            content = self.pool_path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError, UnicodeError):
            return []
        return self._parse_content(content)

    def _row_state(self, row_id: str) -> dict[str, Any]:
        return self._state()["rows"].get(row_id, {})

    def available(self, count: int) -> list[FreeMailbox]:
        with self._lock:
            state = self._state()["rows"]
            rows = [row for row in self.entries() if str(state.get(row.row_id, {}).get("status") or "available") == "available"]
            return rows[: max(0, int(count))]

    def reserve(self, rows: Sequence[FreeMailbox], batch_id: str) -> None:
        with self._lock:
            state = self._state()
            for row in rows:
                current = state["rows"].setdefault(row.row_id, {})
                if current.get("status") not in (None, "available"):
                    raise FreeRegisterError("free_pool_reserve", "预留 Free 邮箱", "Free 邮箱已被其他任务预留")
                current.update({"email": row.email, "mailbox_url": row.mailbox_url, "status": "reserved", "batch_id": batch_id})
            _atomic_write(self.state_path, state)

    def update(self, row_id: str, **values: Any) -> None:
        with self._lock:
            state = self._state()
            row = state["rows"].setdefault(str(row_id), {})
            for key, value in values.items():
                if value is not None:
                    row[key] = value
            _atomic_write(self.state_path, state)

    def save_result(self, row_id: str, result: Mapping[str, Any]) -> None:
        with self._lock:
            _atomic_write(self.results_dir / f"{_fingerprint(row_id)}.json", copy.deepcopy(dict(result)))

    def result(self, row_id: str) -> dict[str, Any]:
        path = self.results_dir / f"{_fingerprint(row_id)}.json"
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {}
        return dict(current) if isinstance(current, dict) else {}

    def entry(self, row_id: str) -> FreeMailbox | None:
        target = str(row_id or "")
        return next((row for row in self.entries() if row.row_id == target), None)

    def delete(self, row_ids: Sequence[str]) -> int:
        requested = list(dict.fromkeys(str(row_id or "").strip().lower() for row_id in row_ids if str(row_id or "").strip()))
        if not requested:
            return 0
        with self._lock:
            entries = self.entries()
            by_id = {entry.row_id: entry for entry in entries}
            targets = [by_id[row_id] for row_id in requested if row_id in by_id]
            if not targets:
                return 0
            state = self._state()
            active = [
                entry for entry in targets
                if str(state["rows"].get(entry.row_id, {}).get("status") or "available")
                in {"reserved", "queued", "running"}
            ]
            if active:
                raise FreeRegisterError(
                    "free_pool_delete",
                    "删除 Free 邮箱",
                    "选中的 Free 邮箱仍在排队或运行中，请等待任务结束后再删除",
                    retryable=False,
                )
            target_ids = {entry.row_id for entry in targets}
            self._write_entries([entry for entry in entries if entry.row_id not in target_ids])
            for row_id in target_ids:
                state["rows"].pop(row_id, None)
            _atomic_write(self.state_path, state)
            return len(targets)

    def public_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            state = self._state()["rows"]
            output = []
            for row in self.entries():
                current = state.get(row.row_id, {})
                result = self.result(row.row_id)
                output.append({
                    "row_id": row.row_id,
                    "line_no": row.line_no,
                    "email": row.email,
                    "status": current.get("status", "available"),
                    "stage": current.get("stage", ""),
                    "proxy_masked": current.get("proxy_masked", ""),
                    "proxy_fingerprint": current.get("proxy_fingerprint", ""),
                    "exit_ip": current.get("exit_ip", ""),
                    "plan_type": result.get("plan_type", ""),
                    "plus_trial_eligible": bool(result.get("plus_trial_eligible", False)),
                    "twofa_status": result.get("twofa_status", ""),
                    "twofa_error": result.get("twofa_error", ""),
                    "has_access_token": bool(result.get("access_token")),
                    "has_password": bool(result.get("password")),
                    "has_totp": bool(result.get("totp_secret")),
                    "has_credential": bool(result.get("credential_line")),
                    "credential_line": "邮箱----密码----2FA" if result.get("credential_line") else "",
                    "task_id": result.get("task_id", ""),
                    "error": current.get("error", ""),
                })
            return output


class FreeProxyPool:
    def __init__(self, data_dir: str | Path, *, default_scheme: str = DEFAULT_FREE_PROXY_SCHEME) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = self.data_dir / "free_proxy_pool.txt"
        scheme = str(default_scheme or DEFAULT_FREE_PROXY_SCHEME).strip().lower()
        self.default_scheme = scheme if scheme in FREE_PROXY_SCHEMES else DEFAULT_FREE_PROXY_SCHEME

    def import_text(self, content: str) -> int:
        rows = [line.strip() for line in str(content or "").splitlines() if line.strip()]
        valid = [
            normalized
            for row in rows
            if (normalized := _normalize_proxy_value(row, default_scheme=self.default_scheme))
        ]
        if not valid:
            raise FreeRegisterError("free_proxy_pool", "Free 代理池", "Free 代理池没有有效代理")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(valid) + "\n", encoding="utf-8")
        os.chmod(self.path, 0o600)
        return len(valid)

    def values(self, content: str = "") -> list[str]:
        if content.strip():
            rows = [line.strip() for line in content.splitlines() if line.strip()]
        else:
            try:
                rows = [line.strip() for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
            except (FileNotFoundError, OSError, UnicodeError):
                rows = []
        return [
            normalized
            for row in rows
            if (normalized := _normalize_proxy_value(row, default_scheme=self.default_scheme))
        ]

    @staticmethod
    def _probe(proxy: str, target: str) -> str:
        from curl_cffi import requests as curl_requests

        # Match autoRegister's RealCodexTransport: one curl session, the same
        # proxy for HTTP/HTTPS, Chrome impersonation, and disabled TLS verify.
        session = curl_requests.Session(impersonate="chrome", verify=False)
        session.proxies = {"http": proxy, "https": proxy}
        try:
            response = session.get(
                target,
                headers={"Accept": "text/plain", "Cache-Control": "no-cache"},
                timeout=12,
            )
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()
        status = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= status < 300:
            raise ValueError(f"代理出口检测返回 HTTP {status}")
        value = bytes(getattr(response, "content", b"") or b"")[:128].decode("utf-8", "ignore").strip()
        if not re.fullmatch(r"[0-9a-fA-F:.]{3,64}", value):
            raise ValueError("代理出口 IP 响应格式无效")
        return value

    def bind(self, count: int, *, content: str = "", probe: Callable[[str, str], str] | None = None, probe_url: str = "https://api.ipify.org") -> list[ProxyBinding]:
        values = self.values(content)
        if len(values) < count:
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", f"Free 代理数量不足：需要 {count} 个，当前只有 {len(values)} 个", retryable=False)
        selected = values[:count]
        fingerprints = [_fingerprint(value) for value in selected]
        if len(set(fingerprints)) != len(fingerprints):
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "代理池包含重复代理，无法建立一号一代理绑定", retryable=False)
        check = probe or self._probe
        bound_values: list[str] = []
        exit_ips: list[str] = []
        for index, value in enumerate(selected, 1):
            try:
                exit_ip = str(check(value, probe_url)).strip()
            except FreeRegisterError:
                raise
            except Exception as exc:
                raise FreeRegisterError(
                    "free_proxy_preflight",
                    "Free 代理预检",
                    f"代理池第 {index} 条出口 IP 检测失败：{_proxy_error_detail(exc)}",
                    retryable=True,
                ) from exc
            bound_values.append(value)
            exit_ips.append(exit_ip)
        bound_fingerprints = [_fingerprint(value) for value in bound_values]
        if len(set(bound_fingerprints)) != len(bound_fingerprints):
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "代理协议转换后出现重复代理，无法建立一号一代理绑定", retryable=False)
        if len(set(exit_ips)) != len(exit_ips):
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "代理出口 IP 重复，无法建立一号一 IP 绑定", retryable=False)
        return [ProxyBinding(value, fingerprint, _mask_proxy(value), ip) for value, fingerprint, ip in zip(bound_values, bound_fingerprints, exit_ips)]

    def verify(self, binding: ProxyBinding, *, probe: Callable[[str, str], str] | None = None, probe_url: str = "https://api.ipify.org") -> None:
        check = probe or self._probe
        try:
            current = str(check(binding.proxy, probe_url)).strip()
        except Exception as exc:
            raise FreeRegisterError(
                "free_proxy_binding",
                "绑定 Free 注册代理",
                f"固定代理出口复核失败：{_proxy_error_detail(exc)}",
            ) from exc
        if current != binding.exit_ip:
            raise FreeRegisterError(
                "free_proxy_drift",
                "校验 Free 代理出口",
                "固定代理的出口 IP 在任务期间发生变化，任务已停止且未切换代理",
                retryable=False,
            )


class MailboxUrlOtpProvider:
    """Mailbox URL OTP reader which keeps its own proxy and baseline state."""

    def __init__(self, mailbox_url: str, proxy: str, *, timeout: int, log_fn: Callable[..., Any] | None = None, task_id: str = "", stage_fn: Callable[[str, str], None] | None = None) -> None:
        try:
            from mailbox_url_runtime import MailboxRequestState, MailboxResponse, MailboxUrlClient
        except ImportError:
            from .mailbox_url_runtime import MailboxRequestState, MailboxResponse, MailboxUrlClient

        timeout_seconds = max(3, min(int(timeout), 60))

        def fetcher(url: str) -> Any:
            from curl_cffi import requests as curl_requests

            response = curl_requests.get(
                url,
                headers={
                    "Accept": "application/json,text/plain,text/html,*/*",
                    "User-Agent": "gptphone-mailbox/1.0",
                    "Cache-Control": "no-cache, no-store, max-age=0",
                    "Pragma": "no-cache",
                },
                proxies={"http": proxy, "https": proxy},
                timeout=timeout_seconds,
                allow_redirects=True,
                impersonate="chrome",
                verify=False,
            )
            return MailboxResponse(
                str(getattr(response, "url", "") or url),
                bytes(getattr(response, "content", b"") or b""),
                str(getattr(response, "headers", {}).get("content-type", "") or ""),
                int(getattr(response, "status_code", 0) or 0),
            )

        self.client = MailboxUrlClient(
            mailbox_url,
            timeout_seconds=timeout_seconds,
            proxy=proxy,
            fetcher=fetcher,
        )
        self.state = MailboxRequestState(self.client)
        self.timeout = max(5, int(timeout))
        self.log_fn = log_fn
        self.task_id = str(task_id or "")
        self.stage_fn = stage_fn

    def _stage(self, code: str) -> None:
        if self.task_id and callable(self.stage_fn):
            self.stage_fn(self.task_id, code)

    def mark_sent(self) -> None:
        self._stage("free_email_otp_wait")
        self.state.begin_request()

    def wait_code(self, _email: str) -> str:
        self._stage("free_email_otp_wait")
        if not self.state.active:
            self.state.begin_request()
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            selection = self.state.snapshot()
            code = str(getattr(selection, "code", "") or "").strip()
            if OTP_RE.fullmatch(code):
                self.state.finish_request()
                return code
            time.sleep(1)
        raise FreeRegisterError("free_email_otp_wait", "等待 Free 邮箱验证码", "邮箱验证码等待超时")


class FreeRegisterManager:
    def __init__(self, data_dir: str | Path, *, progress: Any = None, log_fn: Callable[[str, str], None] | None = None, runner: Callable[..., Mapping[str, Any]] | None = None, proxy_probe: Callable[[str, str], str] | None = None) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.pool = FreeMailboxPool(self.data_dir)
        self.proxies = FreeProxyPool(self.data_dir)
        self.progress = progress
        self.log_fn = log_fn
        self.runner = runner or self._run_protocol
        self.proxy_probe = proxy_probe
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._executor: ThreadPoolExecutor | None = None
        self._futures: set[Future[Any]] = set()
        self._tasks: dict[str, dict[str, Any]] = {}
        self._batch_id = ""

    def _log(self, message: str, level: str = "info") -> None:
        if callable(self.log_fn):
            try:
                self.log_fn(_safe_log_message(message), level)
            except Exception:
                pass

    def _stage(self, task_id: str, code: str) -> None:
        changed = False
        if self.progress is not None and callable(getattr(self.progress, "set_stage", None)):
            try:
                changed = bool(self.progress.set_stage(task_id, code))
            except Exception:
                pass
        with self._lock:
            if task_id in self._tasks:
                changed = changed or self._tasks[task_id].get("stage") != code
                self._tasks[task_id]["stage"] = code
                self._tasks[task_id]["updated_at"] = int(time.time())
        if changed:
            label = FREE_STAGE_LABELS.get(code, code)
            self._log(f"[{task_id}/{label}/{code}] 开始", "info")

    def _save_task(self, task_id: str, **values: Any) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task.update(values)
            task["updated_at"] = int(time.time())

    def _public_task(self, task: Mapping[str, Any]) -> dict[str, Any]:
        result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
        public = {key: copy.deepcopy(task[key]) for key in ("task_id", "ordinal", "status", "created_at", "updated_at", "batch_id", "run_mode", "email", "stage", "proxy_masked", "proxy_fingerprint", "exit_ip") if key in task}
        public["account"] = public.get("email", "")
        public["result"] = {
            key: copy.deepcopy(result[key])
            for key in ("plan_type", "plus_trial_eligible", "twofa_status", "twofa_error", "has_access_token")
            if key in result
        }
        public["result"]["has_credential"] = bool(result.get("credential_line"))
        progress = None
        if self.progress is not None and callable(getattr(self.progress, "progress", None)):
            try:
                progress = self.progress.progress(task.get("task_id"))
            except Exception:
                progress = None
        if isinstance(progress, Mapping):
            public["progress"] = copy.deepcopy(progress)
            if isinstance(progress.get("timing"), Mapping):
                public["timing"] = copy.deepcopy(progress["timing"])
        if isinstance(task.get("failure"), Mapping):
            public["failure"] = copy.deepcopy(task["failure"])
            public["error"] = str(task["failure"].get("public_message") or "Free 注册失败")
        return public

    def public_tasks(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public_task(task) for task in sorted(self._tasks.values(), key=lambda item: int(item.get("ordinal") or 0))]

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            tasks = self.public_tasks()
            active = sum(1 for task in tasks if task.get("status") not in TERMINAL_STATUSES)
            success = sum(1 for task in tasks if task.get("status") == "success")
            failed = sum(1 for task in tasks if task.get("status") == "failed")
            return {
                "running": bool(self._executor and active),
                "batch_id": self._batch_id,
                "tasks": tasks,
                "pool": {
                    "total": len(self.pool.entries()),
                    "available": self._available_count(),
                    "proxies": len(self.proxies.values()),
                },
                "summary": {
                    "total": len(tasks),
                    "active": active,
                    "success": success,
                    "failed": failed,
                    "stopped": sum(1 for task in tasks if task.get("status") == "stopped"),
                },
            }

    def _available_count(self) -> int:
        return len(self.pool.available(10_000))

    def start(self, config: Mapping[str, Any], *, pool_content: str = "", proxy_content: str = "") -> dict[str, Any]:
        with self._lock:
            if self.public_state().get("running"):
                raise FreeRegisterError("free_run_start", "启动 Free 注册", "已有 Free 注册任务运行中", retryable=False)
            if pool_content.strip():
                self.pool.import_text(pool_content)
            if proxy_content.strip():
                self.proxies.import_text(proxy_content)
            available_count = self._available_count()
            configured_free_count = config.get("free_target_count")
            try:
                configured_free_count_value = int(configured_free_count)
            except (TypeError, ValueError):
                configured_free_count_value = 0
            if "free_target_count" in config and configured_free_count_value <= 0:
                configured_free_count = available_count
            elif "free_target_count" not in config or configured_free_count in (None, ""):
                configured_count = int(config.get("target_count") or 0)
                # The shared OAuth target is often larger than the isolated Free pool.
                # Use it when it deliberately selects a smaller batch; otherwise run the
                # available Free rows instead of failing on an unrelated OAuth setting.
                configured_free_count = (
                    configured_count
                    if 0 < configured_count <= available_count
                    else available_count
                )
            target_count = max(1, min(int(configured_free_count or 1), 10_000))
            rows = self.pool.available(target_count)
            if len(rows) < target_count:
                raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", f"Free 邮箱数量不足：需要 {target_count} 条，当前只有 {len(rows)} 条", retryable=False)
            bindings = self.proxies.bind(target_count, content=str(config.get("free_proxy_pool_content") or ""), probe=self.proxy_probe, probe_url=str(config.get("free_proxy_probe_url") or "https://api.ipify.org"))
            batch_id = f"free-{int(time.time())}-{secrets.token_hex(4)}"
            self.pool.reserve(rows, batch_id)
            self._batch_id = batch_id
            self._stop.clear()
            self._tasks = {}
            now = int(time.time())
            for ordinal, (row, binding) in enumerate(zip(rows, bindings), 1):
                task_id = f"{batch_id}-{ordinal}"
                self._tasks[task_id] = {"task_id": task_id, "ordinal": ordinal, "status": "queued", "created_at": now, "updated_at": now, "batch_id": batch_id, "run_mode": "free_register", "email": row.email, "row_id": row.row_id, "mailbox_url": row.mailbox_url, "proxy": binding.proxy, "proxy_masked": binding.masked, "proxy_fingerprint": binding.fingerprint, "exit_ip": binding.exit_ip, "result": {"twofa_status": "pending"}}
                self.pool.update(row.row_id, status="queued", batch_id=batch_id, proxy=binding.proxy, proxy_masked=binding.masked, proxy_fingerprint=binding.fingerprint, exit_ip=binding.exit_ip)
                self._stage(task_id, "free_proxy_binding")
            workers = max(1, min(int(config.get("free_concurrency") or config.get("concurrency") or 1), target_count, 32))
            self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="free-register")
            for task_id in list(self._tasks):
                if self._tasks[task_id].get("batch_id") != batch_id:
                    continue
                future = self._executor.submit(self._worker, task_id, dict(config))
                self._futures.add(future)
                future.add_done_callback(self._future_done)
            self._log(f"[启动 Free 注册/free_run_start] 已绑定 {target_count} 个邮箱和代理，{workers} 并发", "success")
            return {"batch_id": batch_id, "tasks": self.public_tasks(), "state": self.public_state()}

    def _future_done(self, future: Future[Any]) -> None:
        with self._lock:
            self._futures.discard(future)
            if not self._futures and self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=False)
                self._executor = None

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for task_id, task in self._tasks.items():
                if task.get("status") == "queued":
                    task["status"] = "stopped"
                    task["updated_at"] = int(time.time())
                    self.pool.update(task["row_id"], status="stopped")
                    if self.progress is not None and callable(getattr(self.progress, "finish", None)):
                        self.progress.finish(task_id)
        self._log("[停止 Free 注册/free_stop] 已请求停止，运行中的账号不切换代理", "warn")

    def retry_twofa(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(str(task_id))
            if task is None:
                row = self.pool.entry(str(task_id))
                saved = self.pool.result(str(task_id)) if row is not None else {}
                if row is not None and saved.get("twofa_status") == "pending" and saved.get("proxy"):
                    now = int(time.time())
                    recovered_task_id = f"free-2fa-{now}-{secrets.token_hex(4)}"
                    task = {
                        "task_id": recovered_task_id,
                        "ordinal": 1,
                        "status": "twofa_pending",
                        "created_at": now,
                        "updated_at": now,
                        "batch_id": str(saved.get("batch_id") or "free-2fa-retry"),
                        "run_mode": "free_register",
                        "email": row.email,
                        "row_id": row.row_id,
                        "mailbox_url": row.mailbox_url,
                        "proxy": str(saved.get("proxy") or ""),
                        "proxy_masked": _mask_proxy(saved.get("proxy")),
                        "proxy_fingerprint": _fingerprint(saved.get("proxy")),
                        "exit_ip": str(saved.get("exit_ip") or ""),
                        "result": saved,
                    }
                    self._tasks[recovered_task_id] = task
            if task is None or task.get("status") != "twofa_pending":
                raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该任务当前没有待重试的 2FA", retryable=False)
            task["status"] = "queued"
            task["updated_at"] = int(time.time())
            self._stop.clear()
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="free-2fa-retry")
            resolved_task_id = str(task["task_id"])
            future = self._executor.submit(self._worker, resolved_task_id, dict(config), True)
            self._futures.add(future)
            future.add_done_callback(self._future_done)
            return self._public_task(task)

    def secret(self, task_ids: Sequence[str], kind: str, *, row_ids: Sequence[str] = ()) -> str:
        if kind not in {"token", "password", "totp", "proxy", "credential"}:
            raise FreeRegisterError("free_secret", "读取 Free 敏感字段", "不支持的敏感字段类型", retryable=False)
        values: list[str] = []
        seen_rows: set[str] = set()
        with self._lock:
            for task_id in task_ids:
                task = self._tasks.get(str(task_id))
                if not task:
                    continue
                seen_rows.add(str(task.get("row_id") or ""))
                result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
                value = {"token": result.get("access_token"), "password": result.get("password"), "totp": result.get("totp_secret"), "proxy": task.get("proxy"), "credential": result.get("credential_line")}.get(kind)
                if value:
                    values.append(str(value))
            for row_id in row_ids:
                normalized = str(row_id or "")
                if not normalized or normalized in seen_rows:
                    continue
                result = self.pool.result(normalized)
                private_state = self.pool._row_state(normalized)
                value = {"token": result.get("access_token"), "password": result.get("password"), "totp": result.get("totp_secret"), "proxy": result.get("proxy") or private_state.get("proxy"), "credential": result.get("credential_line")}.get(kind)
                if value:
                    values.append(str(value))
        return "\n".join(values)

    def _verify_binding(self, task: Mapping[str, Any], config: Mapping[str, Any]) -> None:
        binding = ProxyBinding(
            str(task.get("proxy") or ""),
            str(task.get("proxy_fingerprint") or ""),
            str(task.get("proxy_masked") or ""),
            str(task.get("exit_ip") or ""),
        )
        if not binding.proxy or not binding.exit_ip:
            raise FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", "任务缺少固定代理绑定", retryable=False)
        self.proxies.verify(
            binding,
            probe=self.proxy_probe,
            probe_url=str(config.get("free_proxy_probe_url") or "https://api.ipify.org"),
        )

    def _worker(self, task_id: str, config: dict[str, Any], twofa_retry: bool = False) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task["status"] = "running"
            task["updated_at"] = int(time.time())
            snapshot = dict(task)
        self._log(f"[{task_id}/free_oauth_session] Free 任务开始", "info")
        try:
            if self._stop.is_set():
                raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在执行前已停止", retryable=False)
            self._verify_binding(snapshot, config)
            result = dict(self.runner(snapshot, config, self._stop, self._stage, self._log, twofa_retry=twofa_retry))
            self._verify_binding(snapshot, config)
            result.update({
                "task_id": task_id,
                "batch_id": snapshot.get("batch_id", ""),
                "proxy": snapshot.get("proxy", ""),
                "exit_ip": snapshot.get("exit_ip", ""),
            })
            status = "twofa_pending" if result.get("twofa_status") == "pending" else "success"
            self._save_task(task_id, status=status, result=result)
            self.pool.save_result(snapshot["row_id"], result)
            self.pool.update(snapshot["row_id"], status=status, stage="free_result_save")
            self._stage(task_id, "free_result_save")
            if self.progress is not None and callable(getattr(self.progress, "finish", None)):
                self.progress.finish(task_id)
            self._log(f"[{task_id}/free_result_save] Free 任务{'完成' if status == 'success' else '注册完成，2FA 待重试'}", "success" if status == "success" else "warn")
        except FreeRegisterError as exc:
            failure = {"node_code": exc.node_code, "node_label": exc.node_label, "error_code": exc.node_code, "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{_clean(exc)}", "technical_summary": _clean(exc), "retryable": bool(exc.retryable)}
            self._save_task(task_id, status="failed" if not self._stop.is_set() else "stopped", failure=failure)
            self.pool.update(snapshot["row_id"], status="failed" if not self._stop.is_set() else "stopped", stage=exc.node_code, error=failure["public_message"])
            if self.progress is not None and callable(getattr(self.progress, "finish", None)):
                self.progress.finish(task_id)
            self._log(f"[{task_id}/{exc.node_label}/{exc.node_code}] {failure['public_message']}", "error")
        except FreeTwoFaPending as pending:
            # A retry can fail after the account and token already exist. Keep
            # the task retryable and persist the token/plan context instead of
            # turning the recoverable 2FA state into a generic protocol error.
            with self._lock:
                current = self._tasks.get(task_id, {})
                saved = current.get("result") if isinstance(current.get("result"), Mapping) else {}
            result = dict(saved)
            result.update({
                "access_token": pending.token,
                "password": str(result.get("password") or FIXED_PASSWORD),
                "plan_type": pending.plan_type,
                "plus_trial_eligible": bool(pending.plus_trial_eligible),
                "twofa_status": "pending",
                "twofa_error": _clean(pending),
                "has_access_token": bool(pending.token),
            })
            self._save_task(task_id, status="twofa_pending", result=result, failure=None)
            self.pool.save_result(snapshot["row_id"], result)
            self.pool.update(snapshot["row_id"], status="twofa_pending", stage="free_twofa_activate", error=result["twofa_error"])
            self._stage(task_id, "free_twofa_activate")
            if self.progress is not None and callable(getattr(self.progress, "finish", None)):
                self.progress.finish(task_id)
            self._log(f"[{task_id}/free_twofa_activate] 2FA 重试未完成，保留待重试状态：{_clean(pending)}", "warn")
        except Exception as exc:
            failure = {"node_code": "free_protocol", "node_label": "Free 注册协议", "error_code": "free_protocol_failed", "public_message": f"Free 注册协议 [Free 注册协议/free_protocol]：{type(exc).__name__}", "technical_summary": type(exc).__name__, "retryable": True}
            self._save_task(task_id, status="failed", failure=failure)
            self.pool.update(snapshot["row_id"], status="failed", stage="free_protocol", error=failure["public_message"])
            if self.progress is not None and callable(getattr(self.progress, "finish", None)):
                self.progress.finish(task_id)
            self._log(f"[{task_id}/Free 注册协议/free_protocol] {failure['public_message']}", "error")

    @staticmethod
    def _totp_code(secret: str, now: float | None = None) -> str:
        normalized = re.sub(r"\s+", "", secret or "").upper()
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        key = base64.b32decode(normalized + padding, casefold=True)
        counter = int((now or time.time()) // 30).to_bytes(8, "big")
        digest = hmac.new(key, counter, hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
        return f"{value % 1_000_000:06d}"

    def _run_protocol(self, task: Mapping[str, Any], config: Mapping[str, Any], stop_event: threading.Event, stage: Callable[[str, str], None], log: Callable[[str, str], None], *, twofa_retry: bool = False) -> Mapping[str, Any]:
        # The recovered chain is imported only inside a worker so tests can use a
        # fake runner without loading the bundled runtime.
        import codex_chain_runner
        import codex_oauth_chain

        task_id = str(task["task_id"])
        email = str(task["email"])
        proxy = str(task["proxy"])
        password = FIXED_PASSWORD
        if twofa_retry:
            stage(task_id, "free_twofa_enroll")
        else:
            stage(task_id, "free_oauth_session")
        oauth_url, code_verifier, _state = codex_chain_runner.build_oauth_url(login_hint=email, screen_hint="signup")
        parsed = codex_oauth_chain.parse_oauth_url(oauth_url)
        device_id = str(task.get("device_id") or f"free-{secrets.token_hex(16)}")
        sentinel = codex_oauth_chain.RealNodeSentinelProvider(config=dict(config), device_id=device_id, proxy_label=str(task.get("proxy_fingerprint") or ""), proxy=proxy, log_fn=log)
        otp_provider = MailboxUrlOtpProvider(
            str(task["mailbox_url"]),
            proxy,
            timeout=int(config.get("email_code_timeout") or 90),
            log_fn=log,
            task_id=task_id,
            stage_fn=stage,
        )
        chain_config = dict(config)
        # The recovered OAuth chain names this setting ``codex_node_runner``;
        # the dashboard stores the same path as ``node_runner``. Keep both
        # names populated so Free uses the configured SentinelRunner instead
        # of silently entering the missing-runner retry path.
        chain_config["codex_node_runner"] = str(
            config.get("codex_node_runner")
            or config.get("node_runner")
            or (config.get("node") or {}).get("runner")
            or ""
        ).strip()
        chain_config.update({
            "run_mode": "free_register",
            "codex_chain_mode": "real",
            "run_chatgpt_signup_phase": True,
            "free_register_no_phone": True,
            "phone_max_attempts": 1,
            "code_timeout": int(config.get("email_code_timeout") or 90),
            "_stop_requested": stop_event.is_set,
            "_auth_account_email": email,
            "register": {
                "password": password,
                "name": random_display_name(),
                "birthdate": random_birthdate(),
            },
        })

        def reject_phone(*_args: Any, **_kwargs: Any) -> Any:
            raise FreeRegisterError("free_phone_required", "Free 注册手机号节点", "Free 注册流程要求手机号，未调用接码平台")

        class NoPhoneProvider:
            get_number = staticmethod(reject_phone)

        transport = codex_oauth_chain.RealCodexTransport(
            chain_config,
            oauth_params=parsed,
            proxy=proxy,
            sentinel_provider=sentinel,
            device_id=device_id,
            log_fn=log,
        )
        self._instrument_transport(transport, task_id, stage)

        try:
            if twofa_retry:
                saved = self.pool.result(str(task["row_id"]))
                token = str(saved.get("access_token") or "")
                if not token:
                    raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "原账号没有可用 access token", retryable=False)
                twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
                result = dict(saved)
                result.update(twofa)
                result["password"] = str(saved.get("password") or password)
                if result.get("totp_secret"):
                    result["credential_line"] = f"{email}----{result['password']}----{result['totp_secret']}"
                return result

            stage(task_id, "free_email_identifier")
            result = codex_oauth_chain.run_codex_after_registration(
                oauth_url=oauth_url,
                code_verifier=code_verifier,
                account_email=email,
                password=password,
                config=chain_config,
                proxy=proxy,
                email_proxy=proxy,
                log_fn=log,
                mode="real",
                transport=transport,
                sentinel_provider=sentinel,
                email_otp_provider=otp_provider,
                phone_otp_provider=NoPhoneProvider(),
            )
            token = str((result or {}).get("access_token") or (result or {}).get("token") or "")
            if not token:
                stage(task_id, "free_access_token")
                token = str(transport.chatgpt_access_token() or "")
            if not token:
                raise FreeRegisterError("free_access_token", "获取 Free access token", "注册完成但未返回 access token")
            stage(task_id, "free_plan_check")
            plan_type, eligible = self._plan_check(transport, token)
            try:
                twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
            except FreeTwoFaPending as pending:
                twofa = {"twofa_status": "pending", "twofa_error": _clean(pending)}
            twofa.update({"access_token": token, "password": password, "plan_type": plan_type, "plus_trial_eligible": eligible, "has_access_token": True})
            if twofa.get("totp_secret"):
                twofa["twofa_status"] = "enabled"
                twofa["credential_line"] = f"{email}----{password}----{twofa['totp_secret']}"
            return twofa
        finally:
            self._close_transport(transport)

    @staticmethod
    def _instrument_transport(transport: Any, task_id: str, stage: Callable[[str, str], None]) -> None:
        mapping = {
            "start_chatgpt_signup_authorize": "free_oauth_session",
            "register_user": "free_email_identifier",
            "verify_password": "free_email_password",
            "send_email_otp": "free_email_otp_wait",
            "verify_signup_email_otp": "free_email_otp_validate",
            "verify_email_otp": "free_email_otp_validate",
            "create_account_profile": "free_account_create",
            "complete_chatgpt_callback": "free_oauth_callback",
            "follow_continue_until_code": "free_oauth_callback",
            "exchange_code": "free_access_token",
            "chatgpt_access_token": "free_access_token",
        }
        for name, code in mapping.items():
            original = getattr(transport, name, None)
            if not callable(original):
                continue

            def wrapped(*args: Any, __original: Callable[..., Any] = original, __code: str = code, **kwargs: Any) -> Any:
                stage(task_id, __code)
                return __original(*args, **kwargs)

            setattr(transport, name, wrapped)

    @staticmethod
    def _close_transport(transport: Any) -> None:
        candidates = [getattr(transport, "session", None), transport]
        for candidate in candidates:
            close = getattr(candidate, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

    def _plan_check(self, transport: Any, token: str) -> tuple[str, bool]:
        if transport is None:
            raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "认证传输会话不可用")
        session = getattr(transport, "session", None)
        if session is None:
            raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "认证 HTTP 会话不可用")
        try:
            response = session.get(
                "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
                f"?timezone_offset_min={_timezone_offset_minutes()}",
                headers={"authorization": f"Bearer {token}", "accept": "*/*"},
                timeout=20,
            )
            status = getattr(response, "status_code", None)
            if status is not None and not 200 <= int(status) < 300:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", f"套餐接口返回 HTTP {int(status)}")
            data = response.json() if hasattr(response, "json") else {}
            try:
                from .chatgpt_plan_gate import plan_from_accounts_check
            except ImportError:
                from chatgpt_plan_gate import plan_from_accounts_check
            plan, _ = plan_from_accounts_check(data, token=token)
            if not plan:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "套餐接口未返回可识别的套餐")
            eligible = _plus_trial_from_accounts(data)
            eligibility = session.get("https://chatgpt.com/backend-api/aip/first-party/eligibility", headers={"authorization": f"Bearer {token}", "accept": "application/json"}, timeout=20)
            eligibility_status = getattr(eligibility, "status_code", None)
            if eligibility_status is not None and not 200 <= int(eligibility_status) < 300:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", f"试用资格接口返回 HTTP {int(eligibility_status)}")
            eligible_data = eligibility.json() if hasattr(eligibility, "json") else {}
            if not isinstance(eligible_data, Mapping):
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "试用资格接口响应不是 JSON 对象")
            eligible = eligible or _plus_trial_from_accounts(eligible_data)
            campaigns = eligible_data.get("eligible_promo_campaigns")
            eligible = eligible or (isinstance(campaigns, Mapping) and bool(campaigns.get("plus")))
            return plan, eligible
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError(
                "free_plan_check",
                "查询 Free 套餐资格",
                f"套餐或试用资格查询异常（{type(exc).__name__}）",
            ) from exc

    def _enroll_twofa(self, transport: Any, token: str, task: Mapping[str, Any], password: str, config: Mapping[str, Any], otp_provider: MailboxUrlOtpProvider, stage: Callable[[str, str], None]) -> dict[str, Any]:
        if transport is None:
            raise FreeTwoFaPending("2FA 重试缺少认证会话", token=token, plan_type="free", plus_trial_eligible=False)
        session = getattr(transport, "session", None)
        if session is None:
            raise FreeTwoFaPending("2FA 会话不可用", token=token, plan_type="free", plus_trial_eligible=False)
        stage(str(task["task_id"]), "free_twofa_enroll")
        headers = {"accept": "application/json", "content-type": "application/json", "authorization": f"Bearer {token}", "oai-device-id": str(getattr(transport, "device_id", "") or ""), "oai-language": "en-GB"}
        try:
            enrolled = session.post("https://chatgpt.com/backend-api/accounts/mfa/enroll", headers=headers, json={"factor_type": "totp"}, timeout=20)
            data = enrolled.json() if hasattr(enrolled, "json") else {}
            secret = str(data.get("secret") or "")
            session_id = str(data.get("session_id") or "")
            if not secret or not session_id:
                raise ValueError("enroll 响应缺少 TOTP 材料")
            stage(str(task["task_id"]), "free_twofa_activate")
            activated = session.post("https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment", headers=headers, json={"code": self._totp_code(secret), "factor_type": "totp", "session_id": session_id}, timeout=20)
            activated_data = activated.json() if hasattr(activated, "json") else {}
            if not bool(activated_data.get("success")):
                raise ValueError("2FA 激活返回 success=false")
            return {"twofa_status": "enabled", "totp_secret": secret}
        except Exception as exc:
            raise FreeTwoFaPending(f"2FA 设置失败：{type(exc).__name__}", token=token, plan_type="free", plus_trial_eligible=False) from exc


__all__ = ["FIXED_PASSWORD", "FreeMailboxPool", "FreeProxyPool", "FreeRegisterError", "FreeRegisterManager", "MailboxUrlOtpProvider", "ProxyBinding", "random_birthdate", "random_display_name"]
