"""Canonical, credential-safe failures for the isolated Free workflow."""

from __future__ import annotations

import copy
import re
import time
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

try:
    from .free_register_common import FREE_STAGE_LABELS, FreeRegisterError, safe_log_message
except ImportError:
    from free_register_common import (  # type: ignore[no-redef]
        FREE_STAGE_LABELS,
        FreeRegisterError,
        safe_log_message,
    )


_FAILURE_URL_RE = re.compile(
    r"(?i)\b(?:https?|socks4|socks5h?|wss?)://[^\s\"'<>]+"
)
_FAILURE_SECRET_RE = re.compile(
    r"(?i)\b(?:token|access[_ -]?token|refresh[_ -]?token|id[_ -]?token|"
    r"admin[_ -]?token|authorization|password|cookie|csrf|pkce|code[_ -]?verifier|"
    r"code[_ -]?challenge|oauth[_ -]?code|auth[_ -]?code|state|"
    r"totp[_ -]?secret|(?:sms|email|otp)[_ -]?code|"
    r"proxy[_ -]?username|proxy[_ -]?password|"
    r"(?:api|mailbox|pickup|proxy)[_ -]?(?:key|secret|token))"
    r"\s*([=:])\s*([^\s,;]+)"
)
_FAILURE_JSON_SECRET_RE = re.compile(
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
_FAILURE_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])",
    re.IGNORECASE,
)
# Incident IDs are the only digit-bearing diagnostic values that may remain
# visible.  Protect the complete generated format before applying phone
# redaction; merely exempting a ``LOG-`` prefix would allow spoofed values such
# as ``LOG-15551234567`` to leak a real phone number.
_FAILURE_INCIDENT_RE = re.compile(
    r"(?<![\w-])LOG-\d{8}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}(?![\w-])",
    re.IGNORECASE,
)
_FAILURE_PHONE_RE = re.compile(r"(?<![\w])\+?\d{8,15}(?![\w])")
_IDENTIFIER_RE = re.compile(r"[^a-zA-Z0-9_.:-]+")
_HTTP_STATUS_RE = re.compile(r"^[1-5]\d\d$")
_SCHEME_SET = frozenset({"http", "https", "socks4", "socks5", "socks5h"})
_TRANSPORT_ERROR_CODES = frozenset({
    "proxy_protocol_mismatch", "proxy_auth_rejected", "proxy_dns_failed",
    "proxy_connect_timeout", "proxy_connection_reset",
    "proxy_tls_certificate_error", "proxy_connect_failed", "tls_connection_failed",
})
_ACTION_HINTS = {
    "camoufox_pool_shutdown_pending": "等待旧 Camoufox 窗口关闭完成后再重试",
    "free_process_recovery": "确认中断账号的邮箱状态后重新创建任务",
    "free_run_stop": "可重新选择该邮箱启动 Free 注册",
    "roxy_circuit_open": "检查 RoxyBrowser API 和遗留 Profile 清理状态后重试",
    "free_protocol": "查看最后成功节点及其上游响应后重试",
    "free_proxy_binding": "检查代理绑定记录和可达性",
    "free_proxy_lease": "检查代理租约记录和代理池状态",
    "proxy_protocol_mismatch": "确认代理声明协议与服务商端口匹配",
    "proxy_auth_rejected": "确认代理用户名、密码和白名单",
    "proxy_dns_failed": "确认代理主机名和 DNS 可达性",
    "proxy_connect_timeout": "确认代理地址、端口和网络可达性",
    "proxy_connection_reset": "更换代理或稍后重试连接",
    "proxy_tls_certificate_error": "确认代理证书链和TLS配置",
    "proxy_connect_failed": "确认代理地址、端口和认证信息",
    "free_plan_check": "保留已注册账号，稍后重新查询套餐状态",
    "free_twofa_enroll": "保留已注册账号和 Token，稍后重试 2FA",
    "free_twofa_activate": "保留已注册账号和 Token，稍后重试 2FA",
}

FAILURE_KEYS = (
    "node_code",
    "node_label",
    "error_code",
    "public_message",
    "technical_summary",
    "retryable",
    "http_status",
    "provider_code",
    "action_hint",
    "page_type",
    "safe_page",
    "content_type",
    "session_rebuilds",
    "retry_after_seconds",
    "declared_scheme",
    "transport_scheme",
    "target_domain",
    "request_stage",
    "retry_count",
    "transport_error_code",
    "debug_session_id",
    "debug_artifact_id",
    "artifact_id",
)


def _redact_url(match: re.Match[str]) -> str:
    try:
        parsed = urlsplit(match.group(0))
        host = parsed.hostname or ""
        if not host:
            return "[URL 已隐藏]"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parsed.port
        origin = f"{parsed.scheme.lower()}://{host}{f':{port}' if port else ''}"
        return f"{origin}/[路径已隐藏]"
    except (TypeError, ValueError):
        return "[URL 已隐藏]"


def _redact_secret(match: re.Match[str]) -> str:
    value = match.group(2)
    return f"{match.group(0)[:-len(value)]}********"


def _redact_json_secret(match: re.Match[str]) -> str:
    value = match.group("value")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        masked = f"{value[0]}********{value[-1]}"
    else:
        masked = "********"
    return f"{match.group('prefix')}{masked}"


def sanitize_failure_text(value: Any, limit: int = 800) -> str:
    """Return diagnostic text without transport or account credentials."""
    text = safe_log_message(value)
    protected_incidents: list[str] = []

    def protect_incident(match: re.Match[str]) -> str:
        protected_incidents.append(match.group(0))
        # Use a non-numeric marker so the phone and OTP passes cannot consume
        # any part of the protected identifier.
        return f"__INCIDENT_{len(protected_incidents) - 1}__"

    text = _FAILURE_INCIDENT_RE.sub(protect_incident, text)
    text = _FAILURE_URL_RE.sub(_redact_url, text)
    text = _FAILURE_JSON_SECRET_RE.sub(_redact_json_secret, text)
    text = _FAILURE_SECRET_RE.sub(_redact_secret, text)
    text = _FAILURE_EMAIL_RE.sub("<邮箱>", text)
    text = _FAILURE_PHONE_RE.sub("<手机号>", text)
    for index, incident_id in enumerate(protected_incidents):
        text = text.replace(f"__INCIDENT_{index}__", incident_id)
    return text[: max(0, int(limit))]


def sanitize_log_message(value: Any, limit: int = 800) -> str:
    """Strongly redact log text while preserving its structured task prefix."""
    text = safe_log_message(value)
    prefix = re.match(r"^\[[^\]]{1,500}\]", text)
    if not prefix:
        return sanitize_failure_text(text, limit)
    head = prefix.group(0)[: max(0, int(limit))]
    return head + sanitize_failure_text(text[prefix.end():], max(0, int(limit) - len(head)))


def sanitize_safe_page(value: Any) -> str:
    """Keep a useful browser route without credentials or authorization data."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw == "页面地址未知":
        return raw
    try:
        parsed = urlsplit(raw)
    except (TypeError, ValueError):
        return "[页面地址已隐藏]"
    scheme = parsed.scheme.lower()
    if scheme in {"ws", "wss", "socks4", "socks5", "socks5h"}:
        return "[非页面地址已隐藏]"
    if scheme and scheme not in {"http", "https"}:
        return "about:blank" if raw == "about:blank" else "[页面地址已隐藏]"
    host = parsed.hostname or ""
    if scheme and not host:
        return "[页面地址已隐藏]"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    path = parsed.path or "/"
    trusted = host.lower() == "chatgpt.com" or host.lower().endswith(".chatgpt.com")
    trusted = trusted or host.lower() == "openai.com" or host.lower().endswith(".openai.com")
    if host and not trusted and path not in {"", "/"}:
        path = "/[路径已隐藏]"
    path = _FAILURE_EMAIL_RE.sub("<邮箱>", path)
    path = _FAILURE_PHONE_RE.sub("<手机号>", path)
    path = re.sub(r"(?<!\d)\d{6}(?!\d)", "<验证码>", path)
    netloc = host + (f":{port}" if port else "")
    return urlunsplit((scheme, netloc, path, "", ""))[:500]


def sanitize_proxy_attempts(value: Any) -> list[dict[str, Any]]:
    """Project persisted proxy-attempt history through a safe field allowlist."""
    if not isinstance(value, (list, tuple)):
        return []
    rows: list[dict[str, Any]] = []
    for raw in value[-10:]:
        if not isinstance(raw, Mapping):
            continue
        row: dict[str, Any] = {}
        for key in ("proxy_id", "stage", "outcome"):
            if raw.get(key) not in (None, ""):
                row[key] = sanitize_failure_text(raw.get(key), 160)
        if raw.get("message") not in (None, ""):
            row["message"] = sanitize_failure_text(raw.get("message"), 300)
        for key in ("retryable", "switched"):
            if isinstance(raw.get(key), bool):
                row[key] = raw[key]
        for key in ("attempt", "at"):
            if isinstance(raw.get(key), bool) or raw.get(key) in (None, ""):
                continue
            try:
                row[key] = max(0, int(raw[key]))
            except (TypeError, ValueError):
                continue
        status = raw.get("http_status")
        if status not in (None, "", False):
            try:
                parsed_status = int(status)
            except (TypeError, ValueError):
                parsed_status = 0
            if 100 <= parsed_status <= 599:
                row["http_status"] = parsed_status
        rows.append(row)
    return rows


def exception_failure_context(error: BaseException) -> dict[str, Any]:
    """Extract the safe HTTP/page context exposed by Free exceptions."""
    context: dict[str, Any] = {}
    page_type = _identifier(getattr(error, "page_type", ""), "")
    if page_type:
        context["page_type"] = page_type
    safe_page = sanitize_safe_page(getattr(error, "safe_page", ""))
    if safe_page:
        context["safe_page"] = safe_page
    content_type = sanitize_failure_text(getattr(error, "content_type", ""), 120)
    if content_type:
        context["content_type"] = content_type
    rebuilds = getattr(error, "session_rebuilds", None)
    if rebuilds is not None:
        try:
            context["session_rebuilds"] = max(0, min(100, int(rebuilds)))
        except (TypeError, ValueError):
            pass
    retry_after = getattr(error, "retry_after_seconds", None)
    if retry_after is not None:
        try:
            context["retry_after_seconds"] = max(0, min(86400, int(float(retry_after))))
        except (TypeError, ValueError):
            pass
    for key in ("declared_scheme", "transport_scheme"):
        value = str(getattr(error, key, "") or "").strip().lower()
        if value in _SCHEME_SET:
            context[key] = value
    domain = str(getattr(error, "target_domain", "") or "").strip().lower()
    if domain:
        try:
            domain = str(urlsplit(domain).hostname or domain).lower()
        except (TypeError, ValueError):
            domain = ""
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?", domain):
            context["target_domain"] = domain
    request_stage = _identifier(getattr(error, "request_stage", ""), "")
    if request_stage:
        context["request_stage"] = request_stage
    retry_count = getattr(error, "retry_count", None)
    if retry_count is not None:
        try:
            context["retry_count"] = max(0, min(100, int(retry_count)))
        except (TypeError, ValueError):
            pass
    transport_error_code = str(getattr(error, "transport_error_code", "") or "").strip()
    if transport_error_code in _TRANSPORT_ERROR_CODES:
        context["transport_error_code"] = transport_error_code
    for key in ("debug_session_id", "debug_artifact_id", "artifact_id"):
        candidate = str(getattr(error, key, "") or "").strip()
        # Debug IDs are opaque local references. Reject paths, URLs and other
        # free-form values before they can reach the public failure payload.
        if candidate and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}", candidate):
            context[key] = candidate
    return context


def exception_to_failure(
    error: BaseException,
    *,
    node_code: str = "",
    node_label: str = "",
    detail: str = "",
) -> dict[str, Any]:
    """Convert one runtime exception to the canonical public failure schema."""
    resolved_code = str(node_code or getattr(error, "node_code", "") or "free_protocol")
    resolved_label = str(
        node_label
        or getattr(error, "node_label", "")
        or FREE_STAGE_LABELS.get(resolved_code, "")
        or "Free 注册协议"
    )
    safe_detail = sanitize_failure_text(
        detail or getattr(error, "diagnostic", "") or str(error) or type(error).__name__,
        800,
    )
    value: dict[str, Any] = {
        "node_code": resolved_code,
        "node_label": resolved_label,
        "error_code": str(getattr(error, "error_code", "") or f"{resolved_code}_failed"),
        "public_message": f"{resolved_label} [{resolved_label}/{resolved_code}]：{safe_detail}",
        "technical_summary": safe_detail,
        "retryable": bool(getattr(error, "retryable", True)),
        "provider_code": getattr(error, "provider_code", ""),
        "action_hint": getattr(error, "action_hint", ""),
        **exception_failure_context(error),
    }
    provider_status = getattr(error, "provider_status", None)
    if provider_status is not None:
        value["http_status"] = provider_status
    normalized = canonical_failure(
        value,
        default_node_code=resolved_code,
        default_node_label=resolved_label,
    )
    if normalized is None:  # pragma: no cover - the required identity is populated above
        raise ValueError("Free 异常无法转换为结构化失败")
    return normalized


def _identifier(value: Any, fallback: str) -> str:
    cleaned = _IDENTIFIER_RE.sub("_", sanitize_failure_text(value, 120)).strip("_.:-")
    return cleaned or fallback


def _retryable(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"false", "0", "no", "off"}:
            return False
        if normalized in {"true", "1", "yes", "on"}:
            return True
    if value is None:
        return default
    return bool(value)


def _http_status(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    normalized = str(value or "").strip()
    if not _HTTP_STATUS_RE.fullmatch(normalized):
        return None
    return int(normalized)


def canonical_failure(
    value: Mapping[str, Any] | None,
    *,
    default_node_code: str = "free_protocol",
    default_node_label: str = "Free 注册协议",
    default_retryable: bool = True,
) -> dict[str, Any] | None:
    """Normalize persisted and public failures to one stable schema."""
    if not isinstance(value, Mapping) or not any(value.get(key) not in (None, "") for key in FAILURE_KEYS):
        return None
    node_code = _identifier(value.get("node_code"), default_node_code)
    stage_label = FREE_STAGE_LABELS.get(node_code, "")
    node_label = sanitize_failure_text(stage_label or value.get("node_label") or default_node_label, 120)
    error_code = _identifier(value.get("error_code"), f"{node_code}_failed")
    technical = sanitize_failure_text(value.get("technical_summary"), 800)
    public_message = sanitize_failure_text(value.get("public_message"), 800)
    if not technical:
        technical = "服务端未返回错误详情"
    identity = f"[{node_label}/{node_code}]"
    if not public_message:
        public_message = f"{node_label} {identity}：{technical}"
    elif identity not in public_message:
        public_message = f"{node_label} {identity}：{public_message}"
    output: dict[str, Any] = {
        "node_code": node_code,
        "node_label": node_label,
        "error_code": error_code,
        "public_message": public_message,
        "technical_summary": technical,
        "retryable": _retryable(value.get("retryable"), default_retryable),
    }
    status = _http_status(value.get("http_status"))
    if status is not None:
        output["http_status"] = status
    provider_code = sanitize_failure_text(value.get("provider_code"), 120)
    if provider_code:
        output["provider_code"] = provider_code
    action_hint = sanitize_failure_text(value.get("action_hint") or _ACTION_HINTS.get(node_code, ""), 300)
    if action_hint:
        output["action_hint"] = action_hint
    page_type = _identifier(value.get("page_type"), "")
    if page_type:
        output["page_type"] = page_type
    safe_page = sanitize_safe_page(value.get("safe_page"))
    if safe_page:
        output["safe_page"] = safe_page
    content_type = sanitize_failure_text(value.get("content_type"), 120)
    if content_type:
        output["content_type"] = content_type
    if value.get("session_rebuilds") is not None:
        try:
            output["session_rebuilds"] = max(0, min(100, int(value.get("session_rebuilds"))))
        except (TypeError, ValueError):
            pass
    if value.get("retry_after_seconds") is not None:
        try:
            output["retry_after_seconds"] = max(0, min(86400, int(float(value.get("retry_after_seconds")))))
        except (TypeError, ValueError):
            pass
    for key in ("declared_scheme", "transport_scheme"):
        candidate = str(value.get(key) or "").strip().lower()
        if candidate in _SCHEME_SET:
            output[key] = candidate
    domain = str(value.get("target_domain") or "").strip().lower()
    if domain:
        try:
            domain = str(urlsplit(domain).hostname or domain).lower()
        except (TypeError, ValueError):
            domain = ""
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?", domain):
            output["target_domain"] = domain
    request_stage = _identifier(value.get("request_stage"), "")
    if request_stage:
        output["request_stage"] = request_stage
    if value.get("retry_count") is not None:
        try:
            output["retry_count"] = max(0, min(100, int(value.get("retry_count"))))
        except (TypeError, ValueError):
            pass
    transport_error_code = str(value.get("transport_error_code") or "").strip()
    if transport_error_code in _TRANSPORT_ERROR_CODES:
        output["transport_error_code"] = transport_error_code
    for key in ("debug_session_id", "debug_artifact_id", "artifact_id"):
        candidate = str(value.get(key) or "").strip()
        if candidate and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}", candidate):
            output[key] = candidate
    return output


def first_failure(
    existing: Mapping[str, Any] | None,
    incoming: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Keep the first real business failure when cleanup reports later errors."""
    current = canonical_failure(existing)
    return current if current is not None else canonical_failure(incoming)


def plan_failure_from_result(result: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a stable package-query failure for an otherwise completed account."""
    if str(result.get("plan_check_status") or "").strip().lower() != "failed":
        return None
    explicit = canonical_failure(
        result.get("plan_failure") if isinstance(result.get("plan_failure"), Mapping) else None,
        default_node_code="free_plan_check",
        default_node_label="查询 Free 套餐资格",
    )
    if explicit is not None:
        return explicit
    detail = sanitize_failure_text(
        result.get("plan_error_detail") or result.get("plan_error") or "服务端未返回错误详情",
        800,
    )
    return canonical_failure({
        "node_code": "free_plan_check",
        "node_label": "查询 Free 套餐资格",
        "error_code": result.get("plan_error_code") or "free_plan_check_failed",
        "public_message": f"账号已注册，但套餐资格查询失败：{detail}",
        "technical_summary": detail,
        "retryable": True,
        "http_status": result.get("plan_http_status"),
        "provider_code": result.get("plan_provider_code"),
    })


def completed_result_state(
    result: Mapping[str, Any],
    *,
    post_registration_failure: Mapping[str, Any] | None = None,
) -> tuple[str, dict[str, Any], dict[str, Any] | None]:
    """Normalize one account result and remove failures from superseded attempts."""
    payload = copy.deepcopy(dict(result))
    historic = canonical_failure(
        payload.get("failure") if isinstance(payload.get("failure"), Mapping) else None
    )
    payload.pop("failure", None)

    plan_failure = plan_failure_from_result(payload)
    if plan_failure is None:
        payload.pop("plan_failure", None)
    else:
        payload["plan_failure"] = plan_failure
    payload.pop("plan_error", None)
    payload.pop("plan_error_detail", None)
    if str(payload.get("plan_check_status") or "").strip().lower() == "success":
        for key in ("plan_error_code", "plan_http_status", "plan_provider_code"):
            payload.pop(key, None)

    twofa_pending = str(payload.get("twofa_status") or "").strip().lower() == "pending"
    twofa_failure = canonical_failure(
        payload.get("twofa_failure") if isinstance(payload.get("twofa_failure"), Mapping) else None,
        default_node_code="free_twofa_activate",
        default_node_label="激活 Free 账号 2FA",
    )
    if twofa_pending and twofa_failure is None and historic and str(historic.get("node_code", "")).startswith("free_twofa_"):
        twofa_failure = historic
    if twofa_pending and twofa_failure is None:
        detail = sanitize_failure_text(payload.get("twofa_error") or "服务端未返回错误详情", 800)
        twofa_failure = canonical_failure({
            "node_code": "free_twofa_activate",
            "node_label": "激活 Free 账号 2FA",
            "error_code": "free_twofa_pending",
            "public_message": f"账号已注册，但 2FA 激活待重试：{detail}",
            "technical_summary": detail,
            "retryable": True,
        })
    if twofa_pending and twofa_failure is not None:
        twofa_failure["retryable"] = True
        payload["twofa_failure"] = twofa_failure
    else:
        payload.pop("twofa_failure", None)
        payload.pop("twofa_error", None)

    post_failure = canonical_failure(post_registration_failure)
    if post_failure is None:
        payload.pop("post_registration_failure", None)
    else:
        payload["post_registration_failure"] = post_failure
    if twofa_pending:
        status, failure = "twofa_pending", twofa_failure
    elif post_failure is not None:
        status, failure = "partial_success", post_failure
    elif plan_failure is not None:
        status, failure = "partial_success", plan_failure
    else:
        status, failure = "success", None
    payload["status"] = status
    if failure is not None:
        payload["failure"] = copy.deepcopy(failure)
    return status, payload, failure


def failure_result_payload(
    task: Mapping[str, Any],
    *,
    status: str,
    failure: Mapping[str, Any],
    result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the private result record shared by terminal failure branches."""
    payload = copy.deepcopy(dict(result or {}))
    normalized = first_failure(failure, payload.get("failure") if isinstance(payload.get("failure"), Mapping) else None)
    payload.update({"status": str(status or "failed"), "failure": normalized})
    for key in (
        "task_id", "batch_id", "driver", "expected_exit_ip", "registration_ip",
        "exit_ip", "proxy_id", "proxy_scheme", "proxy_country", "proxy_group",
        "profile_summary", "account_flow",
    ):
        if key in task and key not in payload:
            payload[key] = copy.deepcopy(task[key])
    return payload


class FreeFailureRuntimeMixin:
    """Persist one failure identity across task and mailbox result stores."""

    def _save_task_state_safely(self, context: str = "Free 任务状态") -> bool:
        """Persist task state without turning a storage outage into a new failure.

        ``FreeRegisterManager`` supplies the richer diagnostic-aware helper.
        The fallback keeps this mixin compatible with older integration hosts
        that only expose ``task_store``.
        """
        saver = getattr(self, "_save_tasks_safely", None)
        if callable(saver):
            try:
                return bool(saver(context))
            except Exception:
                return False
        try:
            self.task_store.save(self._tasks)
            return True
        except Exception as exc:
            logger = getattr(self, "_log", None)
            if callable(logger):
                try:
                    logger(
                        f"[Free 任务状态/free_task_store] {context}保存失败（{type(exc).__name__}）",
                        "warn",
                        node_code="free_task_store",
                        node_label="保存 Free 任务状态",
                        outcome="storage_warning",
                    )
                except Exception:
                    pass
            return False

    def _persist_task_failure(
        self,
        task_id: str,
        task: Mapping[str, Any],
        *,
        status: str,
        failure: Mapping[str, Any],
        result: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        persist = False
        with self._lock:
            current = self._tasks.get(task_id, {})
            existing = current.get("failure") if isinstance(current.get("failure"), Mapping) else None
            normalized = first_failure(existing, failure)
            if normalized is None:
                raise ValueError("Free 终止状态缺少结构化失败")
            context = dict(task or current)
            context.update({key: value for key, value in current.items() if key not in context})
            payload = failure_result_payload(context, status=status, failure=normalized, result=result)
            incident_id = ""
            diagnostic_store = getattr(getattr(self, "log_store", None), "diagnostic_store", None)
            if diagnostic_store is not None:
                try:
                    incident_id = diagnostic_store.record({
                        "level": "error",
                        "outcome": "error" if status == "failed" else status,
                        "task_id": task_id,
                        "batch_id": context.get("batch_id") or "",
                        "chain": "free",
                        "workflow": "register",
                        "driver": context.get("driver") or "free",
                        "subject_kind": "email" if context.get("email") else "",
                        "subject_ref": context.get("email") or "",
                        "subject_display": context.get("email") or "",
                        "node_code": normalized.get("node_code"),
                        "node_label": normalized.get("node_label"),
                        "message": normalized.get("public_message"),
                        "failure": normalized,
                    })
                except Exception:
                    incident_id = ""
            if incident_id:
                payload["incident_id"] = incident_id
            if current:
                current.update({
                    "status": status,
                    "failure": copy.deepcopy(normalized),
                    "result": copy.deepcopy(payload),
                    "updated_at": int(time.time()),
                })
                if incident_id:
                    current["incident_id"] = incident_id
                persist = True
        if persist:
            self._save_task_state_safely("记录任务失败")
        row_id = str(context.get("row_id") or "")
        if row_id:
            self.pool.save_result(row_id, payload)
        return normalized, payload

    def _persist_unexpected_task_failure(
        self,
        task_id: str,
        task: Mapping[str, Any],
        error: BaseException,
    ) -> tuple[dict[str, Any], FreeRegisterError, str, str]:
        """Attribute an untyped error to the live node and persist it safely."""
        with self._lock:
            node_code = str(
                self._tasks.get(task_id, {}).get("stage")
                or task.get("stage")
                or "free_protocol"
            )
        node_label = FREE_STAGE_LABELS.get(node_code, node_code or "Free 注册协议")
        failure = exception_to_failure(error, node_code=node_code, node_label=node_label)
        failure.setdefault("action_hint", "检查该节点最后一条日志及其上游响应后重试")
        failure, _ = self._persist_task_failure(
            task_id,
            task,
            status="failed",
            failure=failure,
        )
        if self._can_reuse_mailbox_after_failure(node_code):
            self._restore_mailbox_after_pre_registration_failure(task, failure)
        else:
            self.pool.update(
                str(task.get("row_id") or ""),
                status="pending_rerun",
                stage=node_code,
                error=failure["public_message"],
                failure=failure,
                reusable_after_failure=False,
            )
        classified = FreeRegisterError(
            node_code,
            node_label,
            failure["technical_summary"],
            retryable=bool(failure.get("retryable", True)),
            error_code=str(failure.get("error_code") or f"{node_code}_failed"),
            provider_code=str(failure.get("provider_code") or ""),
            action_hint=str(failure.get("action_hint") or ""),
            page_type=str(failure.get("page_type") or ""),
            safe_page=str(failure.get("safe_page") or ""),
            content_type=str(failure.get("content_type") or ""),
            session_rebuilds=int(failure.get("session_rebuilds") or 0),
            retry_after_seconds=failure.get("retry_after_seconds"),
            declared_scheme=str(failure.get("declared_scheme") or ""),
            transport_scheme=str(failure.get("transport_scheme") or ""),
            target_domain=str(failure.get("target_domain") or ""),
            request_stage=str(failure.get("request_stage") or ""),
            retry_count=int(failure.get("retry_count") or 0),
            transport_error_code=str(failure.get("transport_error_code") or ""),
        )
        classified.__cause__ = error
        return failure, classified, node_code, node_label


__all__ = [
    "FAILURE_KEYS",
    "FreeFailureRuntimeMixin",
    "canonical_failure",
    "completed_result_state",
    "exception_failure_context",
    "exception_to_failure",
    "failure_result_payload",
    "first_failure",
    "plan_failure_from_result",
    "sanitize_failure_text",
    "sanitize_log_message",
    "sanitize_proxy_attempts",
    "sanitize_safe_page",
]
