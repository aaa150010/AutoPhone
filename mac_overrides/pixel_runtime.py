"""Durable PixelAPI uploads through the existing account-manager proxy.

The recovered runtime should only enqueue an already-persisted success result.
OAuth credentials remain in that result file and are loaded immediately before
an upload; the outbox contains references, fingerprints, safe task metadata,
and public status only.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import copy
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import threading
import time
from typing import Any, Protocol
import urllib.error
import urllib.parse
import urllib.request
import uuid


DEFAULT_PIXEL_PROXY_BASE_URL = "https://lynote.xyz/gpt-api"
PIXEL_AUTO_TARGET_IDS = tuple(f"pixel-{index}" for index in range(2, 8))
PIXEL_EXCLUDED_TARGET_IDS = ("pixel-1",)
OUTBOX_VERSION = 3
SECRET_MASK = "********"
_SANITIZE_INPUT_LIMIT = 8192

_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EMAIL_RE = re.compile(
    r"(?i)^[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)
_GENERATED_EMAIL_LOCAL_RE = re.compile(r"(?i)^acct-[0-9a-f]{12}$")
_DUPLICATE_ACCOUNT_RE = re.compile(
    r"(?i)\b(?:account\s+already\s+exists|already\s+exists|duplicate(?:\s+account)?)\b"
)
_EXISTING_ACCOUNT_ID_RE = re.compile(
    r"(?i)\b(?:existing[_ -]?account[_ -]?id|account[_ -]?id)\s*[:=]\s*#?([0-9]+)\b"
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|authorization|"
    r"password|secret|api[_ -]?key)(?:\\?[\"'])?\s*[:=]\s*"
    r"(?:\\?[\"'])?[^\s,;}\]\"']+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")
_SECRET_KEYS = {
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "password",
    "secret",
    "api_key",
    "apikey",
    "manager_key",
}
_COMPACT_SECRET_KEYS = {
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "authorization",
    "authorizationheader",
    "password",
    "secret",
    "apikey",
    "xapikey",
    "managerkey",
    "admintoken",
    "adminpassword",
}
_RETRYABLE_STATES = {"import_failed", "share_failed", "source_unavailable", "importing"}
_ACTIVE_STATES = {"pending", "importing"}
_TERMINAL_JOB_STATUSES = {"completed", "failed"}
_TARGET_STAGES = frozenset({"source", "import", "share", "verification"})
_STAGE_LABELS = {
    "source": "源数据",
    "import": "导入",
    "share": "公开共享",
    "verification": "状态回查",
}
_STAGE_NODE_CODES = {
    "source": "pixel_enqueue",
    "import": "pixel_import",
    "share": "pixel_share",
    "verification": "pixel_verification",
}
_STAGE_NODE_LABELS = {
    "source": "Pixel 自动上传入队",
    "import": "Pixel 账号导入",
    "share": "Pixel 公开共享",
    "verification": "Pixel 状态验证",
}

_CREDENTIAL_FIELDS = (
    "id_token",
    "access_token",
    "refresh_token",
    "expires_at",
    "token_type",
    "scope",
    "email",
    "account_id",
    "chatgpt_account_id",
    "chatgpt_account_user_id",
    "chatgpt_user_id",
    "chatgpt_auth_user_id",
    "chatgpt_plan_type",
    "cpa_ready",
    "cpa_missing_reason",
)
_IDENTITY_FIELDS = (
    "account_id",
    "chatgpt_account_id",
    "chatgpt_account_user_id",
    "chatgpt_user_id",
    "chatgpt_auth_user_id",
    "chatgpt_plan_type",
)
_IDENTITY_MATCH_FIELDS = frozenset(
    {
        "account_id",
        "chatgpt_account_id",
        "chatgpt_account_user_id",
        "chatgpt_user_id",
        "chatgpt_auth_user_id",
    }
)


class PixelRuntimeError(RuntimeError):
    """Base error containing only text that is safe to return to the UI."""

    def __init__(self, public_message: str, status_code: int = 500) -> None:
        self.public_message = sanitize_error(public_message)
        self.status_code = status_code
        super().__init__(self.public_message)


class PixelSourceError(PixelRuntimeError):
    def __init__(self, public_message: str) -> None:
        super().__init__(public_message, 422)


class PixelProxyError(PixelRuntimeError):
    def __init__(
        self,
        public_message: str,
        status_code: int = 502,
        *,
        ambiguous: bool = False,
    ) -> None:
        self.ambiguous = ambiguous
        super().__init__(public_message, status_code)


class PixelStateError(PixelRuntimeError):
    pass


class PixelTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> Mapping[str, Any]: ...


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_identifier(value: Any, *, maximum: int = 128) -> str:
    text = _clean(value)
    if re.fullmatch(r"[A-Za-z0-9._:-]{1,%d}" % maximum, text):
        return text
    if not text:
        return ""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _stage_for_state(state: Any) -> str:
    normalized = _clean(state).lower()
    if normalized == "source_unavailable":
        return "source"
    if normalized == "share_failed":
        return "share"
    if normalized in {"success", "needs_confirmation"}:
        return "verification"
    return "import"


def _target_stage(item: Mapping[str, Any]) -> str:
    stage = _clean(item.get("stage")).lower()
    return stage if stage in _TARGET_STAGES else _stage_for_state(item.get("state"))


def _concurrency_by_id(value: Any, allowed_ids: Iterable[Any] | None = None) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    allowed = None
    if allowed_ids is not None:
        allowed = {account_id for account_id in (_safe_int(item) for item in allowed_ids) if account_id > 0}
    result: dict[str, int] = {}
    for raw_id, raw_concurrency in value.items():
        account_id = _safe_int(raw_id)
        concurrency = _safe_int(raw_concurrency)
        if account_id <= 0 or not 3 <= concurrency <= 10:
            continue
        if allowed is not None and account_id not in allowed:
            continue
        result[str(account_id)] = concurrency
    return result


def sanitize_error(value: Any, secrets: Iterable[Any] = (), *, maximum: int = 500) -> str:
    """Return a bounded error summary without credentials or bearer tokens."""
    if isinstance(value, Mapping):
        value = value.get("detail") or value.get("message") or value.get("error") or "请求失败"
    # Pixel import and job endpoints may echo a large provider payload. Keep
    # regex-based redaction bounded before scanning it, otherwise one response
    # can starve the Flask thread and the durable upload worker indefinitely.
    text = str(value or "")[:_SANITIZE_INPUT_LIMIT].replace("\r", " ").replace("\n", " ")
    candidates = {str(secret) for secret in secrets if str(secret or "")}
    for secret in sorted(candidates, key=len, reverse=True):
        text = text.replace(secret, SECRET_MASK)
        encoded = urllib.parse.quote(secret, safe="")
        if encoded != secret:
            text = text.replace(encoded, SECRET_MASK)
    text = _BEARER_RE.sub(f"Bearer {SECRET_MASK}", text)
    text = _SENSITIVE_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}={SECRET_MASK}", text)
    text = _JWT_RE.sub(SECRET_MASK, text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:maximum]


def _pixel_failure(stage: Any, state: Any, error: Any) -> dict[str, Any] | None:
    normalized_stage = str(stage or "").strip().lower()
    normalized_state = str(state or "").strip().lower()
    if normalized_state in {"", "pending", "importing", "success"}:
        return None
    if normalized_stage not in _TARGET_STAGES:
        normalized_stage = _stage_for_state(normalized_state)
    node_code = _STAGE_NODE_CODES.get(normalized_stage, "pixel_verification")
    node_label = _STAGE_NODE_LABELS.get(normalized_stage, "Pixel 状态验证")
    cause = sanitize_error(error) or "服务端未返回错误详情"
    return {
        "node_code": node_code,
        "node_label": node_label,
        "error_code": sanitize_error(normalized_state, maximum=80) or f"{node_code}_failed",
        "provider_code": "",
        "public_message": sanitize_error(f"{node_label}失败：{cause}"),
        "technical_summary": cause,
        "retryable": normalized_state in _RETRYABLE_STATES,
        "http_status": None,
    }


def _public_pixel_failure(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    node_code = str(value.get("node_code") or "").strip()
    if node_code not in set(_STAGE_NODE_CODES.values()) | {"pixel_persistence"}:
        return None
    return {
        "node_code": node_code,
        "node_label": sanitize_error(value.get("node_label"), maximum=80),
        "error_code": sanitize_error(value.get("error_code"), maximum=80),
        "provider_code": sanitize_error(value.get("provider_code"), maximum=80),
        "public_message": sanitize_error(value.get("public_message")),
        "technical_summary": sanitize_error(value.get("technical_summary")),
        "retryable": bool(value.get("retryable")),
        "http_status": _safe_int(value.get("http_status")) or None,
    }


def _public_proxy_value(value: Any) -> Any:
    """Defensively remove secret-shaped fields from proxy responses."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = re.sub(r"[-.]", "_", str(key).strip().lower())
            compact = re.sub(r"[^a-z0-9]", "", normalized)
            if normalized in _SECRET_KEYS or compact in _COMPACT_SECRET_KEYS:
                continue
            result[str(key)] = _public_proxy_value(item)
        return result
    if isinstance(value, list):
        return [_public_proxy_value(item) for item in value]
    if isinstance(value, tuple):
        return [_public_proxy_value(item) for item in value]
    if isinstance(value, str):
        return sanitize_error(value, maximum=1000)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:200]


def _value_sources(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    sources: list[Mapping[str, Any]] = [value]
    for key in ("credentials", "tokens"):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            sources.append(nested)
    local_oauth = value.get("local_oauth")
    if isinstance(local_oauth, Mapping):
        nested = local_oauth.get("tokens")
        if isinstance(nested, Mapping):
            sources.append(nested)
        sources.append(local_oauth)
    return sources


def _first_value(sources: Iterable[Mapping[str, Any]], key: str) -> Any:
    for source in sources:
        if key in source and source.get(key) not in (None, ""):
            return source.get(key)
    return None


def build_pixel_import_payload(success_result: Mapping[str, Any]) -> dict[str, Any]:
    """Build the one-account JSON accepted by the cost calculator proxy."""
    if not isinstance(success_result, Mapping):
        raise PixelSourceError("成功结果格式无效")

    wrapped = success_result.get("result")
    if isinstance(wrapped, Mapping):
        wrapper_status = _clean(success_result.get("status")).lower()
        if wrapper_status and wrapper_status not in {"success", "ok", "uploaded"}:
            raise PixelSourceError("结果不是成功状态")
        result = wrapped
        sources = _value_sources(result) + [success_result]
    else:
        result = success_result
        sources = _value_sources(result)

    email = _clean(_first_value(sources, "email")).lower()
    if not _EMAIL_RE.fullmatch(email):
        raise PixelSourceError("成功结果缺少有效邮箱")

    credentials: dict[str, Any] = {}
    for key in _CREDENTIAL_FIELDS:
        value = _first_value(sources, key)
        if value not in (None, ""):
            credentials[key] = value
    missing = [key for key in ("access_token", "refresh_token", "id_token") if not _clean(credentials.get(key))]
    if missing:
        raise PixelSourceError("成功结果中的 OAuth 凭据不完整")

    credentials["email"] = email
    credentials["plan_type"] = "plus"
    credentials.setdefault("token_type", "Bearer")
    extra = {"email": email}
    for key in _IDENTITY_FIELDS:
        if credentials.get(key) not in (None, ""):
            extra[key] = credentials[key]

    return {
        "proxies": [],
        "accounts": [
            {
                "name": email,
                "platform": "openai",
                "type": "oauth",
                "account_level": "plus",
                "credentials": credentials,
                "extra": extra,
            }
        ],
    }


def _source_public_metadata(
    source: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        source_email = _clean(payload["accounts"][0]["name"]).lower()
    except (KeyError, IndexError, TypeError):
        source_email = ""
    if not _EMAIL_RE.fullmatch(source_email):
        source_email = ""

    wrapped = source.get("result")
    sources = [source]
    if isinstance(wrapped, Mapping):
        sources.append(wrapped)
    batch_id = _safe_identifier(_first_value(sources, "batch_id"), maximum=80)
    batch_started_at = max(
        _safe_int(_first_value(sources, "batch_started_at")),
        0,
    )
    return {
        "source_email": source_email,
        "batch_id": batch_id,
        "batch_started_at": batch_started_at,
    }


def _payload_email_domain(payload: Mapping[str, Any]) -> str:
    try:
        account = payload["accounts"][0]
    except (KeyError, IndexError, TypeError):
        raise PixelSourceError("Pixel 上传载荷格式无效") from None
    credentials = account.get("credentials") if isinstance(account.get("credentials"), Mapping) else {}
    extra = account.get("extra") if isinstance(account.get("extra"), Mapping) else {}
    for value in (account.get("name"), credentials.get("email"), extra.get("email")):
        email = _clean(value).lower()
        if _EMAIL_RE.fullmatch(email):
            return email.rsplit("@", 1)[1]
    raise PixelSourceError("Pixel 上传载荷缺少有效邮箱")


def _result_generated_names(result: Mapping[str, Any]) -> list[str]:
    values = result.get("generatedNames")
    if not isinstance(values, list):
        values = result.get("generated_names")
    if not isinstance(values, list):
        return []
    return [_clean(value).lower()[:160] for value in values if _clean(value)]


def _safe_account_id_values(value: Any) -> list[int]:
    """Normalize account IDs from a proxy result without accepting arbitrary text."""
    values = value if isinstance(value, (list, tuple, set)) else [value]
    result: list[int] = []
    seen: set[int] = set()
    for raw in values:
        account_id = _safe_int(raw)
        if account_id <= 0 or account_id in seen:
            continue
        seen.add(account_id)
        result.append(account_id)
    return result


def _duplicate_import_details(result: Mapping[str, Any]) -> tuple[bool, list[int]]:
    """Extract a known existing Pixel account ID from duplicate-import details.

    PixelAPI may report an identity conflict while retaining the existing row.  The
    ID is only trusted when it is attached to an explicit duplicate message; an
    arbitrary ``account_id`` in an unrelated provider error must never be treated as
    a share target.
    """
    details = result.get("importErrors")
    detail_values = details if isinstance(details, list) else []
    messages: list[str] = []
    account_ids: list[int] = []
    duplicate_detail_seen = False
    for detail in detail_values:
        if not isinstance(detail, Mapping):
            continue
        message = _clean(detail.get("message") or detail.get("error"))
        if message:
            messages.append(message)
        if not _DUPLICATE_ACCOUNT_RE.search(message):
            continue
        duplicate_detail_seen = True
        for key in (
            "existingAccountId",
            "existing_account_id",
            "accountId",
            "account_id",
            "existingIds",
            "existing_ids",
        ):
            account_ids.extend(_safe_account_id_values(detail.get(key)))
        account_ids.extend(
            int(match.group(1))
            for match in _EXISTING_ACCOUNT_ID_RE.finditer(message)
            if _safe_int(match.group(1)) > 0
        )

    top_message = _clean(result.get("message") or result.get("error"))
    duplicate_seen = duplicate_detail_seen or bool(_DUPLICATE_ACCOUNT_RE.search(top_message))
    if not duplicate_seen and messages:
        # A response with only duplicate details is still a duplicate response even
        # when the top-level message is omitted.
        duplicate_seen = all(_DUPLICATE_ACCOUNT_RE.search(message) for message in messages)
    for key in (
        "existingAccountId",
        "existing_account_id",
        "existingAccountIds",
        "existing_account_ids",
    ):
        account_ids.extend(_safe_account_id_values(result.get(key)))

    return duplicate_seen, list(dict.fromkeys(account_ids))


def _account_identity_values(value: Mapping[str, Any]) -> set[str]:
    """Collect non-secret OAuth identity fields for local duplicate mapping."""
    values: set[str] = set()
    sources: list[Mapping[str, Any]] = [value]
    for key in ("credentials", "extra"):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            sources.append(nested)
    for source in sources:
        for key in _IDENTITY_MATCH_FIELDS:
            candidate = _clean(source.get(key)).lower()
            if candidate:
                values.add(candidate)
    return values


def _valid_generated_name(value: str, expected_domain: str) -> bool:
    local, separator, domain = value.rpartition("@")
    return bool(
        separator
        and _GENERATED_EMAIL_LOCAL_RE.fullmatch(local)
        and domain.lower() == expected_domain.lower()
        and _EMAIL_RE.fullmatch(value)
    )


def credential_fingerprint(payload: Mapping[str, Any]) -> str:
    try:
        credentials = payload["accounts"][0]["credentials"]
    except (KeyError, IndexError, TypeError):
        raise PixelSourceError("Pixel 上传载荷格式无效") from None
    material = "\0".join(_clean(credentials.get(key)) for key in ("access_token", "refresh_token", "id_token"))
    if not material.replace("\0", ""):
        raise PixelSourceError("Pixel 上传载荷缺少 OAuth 凭据")
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


class UrllibPixelTransport:
    """Small stdlib JSON transport; tests inject a fake implementation."""

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> Mapping[str, Any]:
        if params:
            query = urllib.parse.urlencode({key: str(value) for key, value in params.items()})
            url = f"{url}{'&' if '?' in url else '?'}{query}"
        request_headers = {"Accept": "application/json", **dict(headers or {})}
        if json_body is not None:
            if body is not None:
                raise ValueError("json_body and body are mutually exclusive")
            body = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(url, data=body, headers=request_headers, method=method.upper())
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            raw = exc.read(16384)
            message: Any = f"Pixel 管理服务返回 HTTP {exc.code}"
            try:
                message = json.loads(raw.decode("utf-8", errors="replace"))
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
            raise PixelProxyError(
                sanitize_error(message),
                int(exc.code),
                ambiguous=method.upper() != "GET" and int(exc.code) >= 500,
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise PixelProxyError(
                "无法连接 Pixel 管理服务",
                502,
                ambiguous=method.upper() != "GET",
            ) from None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise PixelProxyError("Pixel 管理服务返回了无效 JSON") from None
        if not isinstance(payload, Mapping):
            raise PixelProxyError("Pixel 管理服务返回格式无效")
        return payload


class PixelProxyClient:
    """Synchronous adapter for the account manager deployed behind /gpt-api."""

    def __init__(
        self,
        base_url: str = DEFAULT_PIXEL_PROXY_BASE_URL,
        *,
        transport: PixelTransport | None = None,
        timeout: float = 30.0,
        poll_interval: float = 2.0,
        job_timeout: float = 900.0,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        normalized = str(base_url or "").strip().rstrip("/")
        parsed = urllib.parse.urlsplit(normalized)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise PixelStateError("Pixel 管理代理地址必须是有效的 HTTPS 地址", 500)
        self.base_url = normalized
        self.transport = transport or UrllibPixelTransport()
        self.timeout = max(float(timeout), 1.0)
        self.poll_interval = max(float(poll_interval), 0.0)
        self.job_timeout = max(float(job_timeout), 1.0)
        self.sleeper = sleeper
        self.monotonic = monotonic

    @staticmethod
    def _target_id(value: Any) -> str:
        target_id = _clean(value)
        if not _TARGET_ID_RE.fullmatch(target_id):
            raise PixelStateError("Pixel 目标 ID 无效", 400)
        if target_id not in PIXEL_AUTO_TARGET_IDS:
            raise PixelStateError("Pixel 目标未开放，仅支持 pixel-2 至 pixel-7", 404)
        return target_id

    @classmethod
    def _target_ids(cls, values: Iterable[Any]) -> list[str]:
        if isinstance(values, (str, bytes)):
            values = [values]
        targets = list(dict.fromkeys(cls._target_id(value) for value in values))
        if not targets:
            raise PixelStateError("一键共享没有可执行的 Pixel 目标", 400)
        return targets

    @staticmethod
    def _account_ids(values: Iterable[Any]) -> list[int]:
        result: list[int] = []
        seen: set[int] = set()
        for value in values:
            account_id = _safe_int(value)
            if account_id <= 0 or account_id in seen:
                continue
            seen.add(account_id)
            result.append(account_id)
        if not result:
            raise PixelStateError("至少选择一个 Pixel 账号", 400)
        return result

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        try:
            payload = self.transport.request(
                method,
                f"{self.base_url}{path}",
                params=params,
                json_body=json_body,
                body=body,
                headers=headers,
                timeout=self.timeout if timeout is None else timeout,
            )
        except PixelRuntimeError:
            raise
        except Exception:
            raise PixelProxyError(
                "Pixel 管理服务请求失败",
                ambiguous=method.upper() != "GET",
            ) from None
        if not isinstance(payload, Mapping):
            raise PixelProxyError("Pixel 管理服务返回格式无效")
        return dict(_public_proxy_value(payload))

    def targets(self) -> dict[str, Any]:
        payload = self._request("GET", "/pixel-manager/targets")

        def filter_targets(value: Any) -> list[Any] | None:
            if not isinstance(value, list):
                return None
            result: list[Any] = []
            for item in value:
                if not isinstance(item, Mapping):
                    continue
                target_id = _clean(item.get("id") or item.get("target_id") or item.get("targetId"))
                if target_id in PIXEL_AUTO_TARGET_IDS:
                    result.append(item)
            return result

        filtered = filter_targets(payload.get("targets"))
        if filtered is not None:
            payload["targets"] = filtered
        data = payload.get("data")
        if isinstance(data, Mapping):
            nested = filter_targets(data.get("targets"))
            if nested is not None:
                nested_data = dict(data)
                nested_data["targets"] = nested
                payload["data"] = nested_data
        return payload

    def accounts(
        self,
        target_id: str,
        *,
        page: int = 1,
        page_size: int = 50,
        search: str = "",
        status: str = "",
    ) -> dict[str, Any]:
        target = self._target_id(target_id)
        return self._request(
            "GET",
            f"/pixel-manager/targets/{urllib.parse.quote(target, safe='')}/accounts",
            params={
                "page": max(_safe_int(page, 1), 1),
                "pageSize": min(max(_safe_int(page_size, 50), 1), 100),
                "search": _clean(search)[:120],
                "status": _clean(status)[:40],
            },
        )

    def find_accounts_by_identity(
        self,
        target_id: str,
        identity_values: Iterable[Any],
        *,
        page_size: int = 100,
        max_pages: int = 200,
    ) -> list[int]:
        """Find existing account IDs using non-secret OAuth identity fields.

        PixelAPI rejects a second import of the same OpenAI identity even when the
        display email was randomized.  The account list is scanned server-side and
        only numeric IDs are returned; credentials and identity values never leave
        this process or enter the outbox.
        """
        target = self._target_id(target_id)
        wanted = {
            _clean(value).lower()
            for value in identity_values
            if _clean(value) and len(_clean(value)) <= 200
        }
        if not wanted:
            return []
        size = min(max(_safe_int(page_size, 100), 1), 100)
        pages_limit = min(max(_safe_int(max_pages, 200), 1), 200)
        found: list[int] = []
        seen: set[int] = set()
        for page in range(1, pages_limit + 1):
            response = self.accounts(target, page=page, page_size=size)
            data = response.get("data") if isinstance(response.get("data"), Mapping) else response
            items = data.get("items") if isinstance(data, Mapping) and isinstance(data.get("items"), list) else []
            for item in items:
                if not isinstance(item, Mapping) or not (_account_identity_values(item) & wanted):
                    continue
                account_id = _safe_int(item.get("id"))
                if account_id > 0 and account_id not in seen:
                    seen.add(account_id)
                    found.append(account_id)
            pages = _safe_int(data.get("pages")) if isinstance(data, Mapping) else 0
            if not items or (pages and page >= pages) or (not pages and len(items) < size):
                break
        return found

    def bulk_test(self, target_id: str, account_ids: Iterable[Any]) -> dict[str, Any]:
        target = self._target_id(target_id)
        return self._request(
            "POST",
            f"/pixel-manager/targets/{urllib.parse.quote(target, safe='')}/accounts/bulk-test",
            json_body={"accountIds": self._account_ids(account_ids)},
            timeout=90.0,
        )

    def bulk_update(
        self,
        target_id: str,
        account_ids: Iterable[Any],
        *,
        share_mode: str | None = None,
        concurrency: int | None = None,
    ) -> dict[str, Any]:
        target = self._target_id(target_id)
        body: dict[str, Any] = {"accountIds": self._account_ids(account_ids)}
        if share_mode:
            if _clean(share_mode).lower() != "public":
                raise PixelStateError("Pixel 共享模式只允许 public", 400)
            body["shareMode"] = "public"
        if concurrency is not None:
            value = _safe_int(concurrency)
            if not 3 <= value <= 50:
                raise PixelStateError("Pixel 并发数必须是 3-50", 400)
            body["concurrency"] = value
        return self._request(
            "POST",
            f"/pixel-manager/targets/{urllib.parse.quote(target, safe='')}/accounts/bulk-update",
            json_body=body,
            timeout=120.0,
        )

    def relogin(self, target_id: str) -> dict[str, Any]:
        target = self._target_id(target_id)
        return self._request(
            "POST",
            f"/pixel-manager/targets/{urllib.parse.quote(target, safe='')}/relogin",
            json_body={},
            timeout=60.0,
        )

    def share_accounts(self, target_id: str, account_ids: Iterable[Any]) -> dict[str, Any]:
        """Use the proxy's random 3-10 per-account share implementation."""
        target = self._target_id(target_id)
        return self._request(
            "POST",
            f"/pixel-manager/targets/{urllib.parse.quote(target, safe='')}/share",
            json_body={"accountIds": self._account_ids(account_ids)},
            timeout=120.0,
        )

    def share_all(self, target_ids: Iterable[Any] = PIXEL_AUTO_TARGET_IDS) -> dict[str, Any]:
        targets = self._target_ids(target_ids)
        return self._request(
            "POST",
            "/pixel-manager/share-all",
            json_body={"targetIds": targets},
            timeout=900.0,
        )

    def import_records(self) -> dict[str, Any]:
        return self._request("GET", "/pixel-manager/import-records")

    def create_import(
        self,
        payload: Mapping[str, Any],
        target_ids: Iterable[Any],
        *,
        file_name: str,
    ) -> dict[str, Any]:
        targets = list(dict.fromkeys(self._target_id(value) for value in target_ids))
        if not targets or any(target not in PIXEL_AUTO_TARGET_IDS for target in targets):
            raise PixelStateError("自动上传只能选择 pixel-2 至 pixel-7", 400)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return self._request(
            "POST",
            "/pixel-manager/import",
            params={"targetIds": json.dumps(targets, separators=(",", ":")), "fileName": Path(file_name).name},
            body=body,
            headers={"Content-Type": "application/json"},
            timeout=60.0,
        )

    def import_job(self, job_id: str) -> dict[str, Any]:
        identifier = _safe_identifier(job_id)
        if not identifier or identifier.startswith("sha256:"):
            raise PixelStateError("Pixel 导入任务 ID 无效", 400)
        return self._request("GET", f"/pixel-manager/import-jobs/{urllib.parse.quote(identifier, safe='')}")

    def wait_import_job(self, job_id: str) -> dict[str, Any]:
        deadline = self.monotonic() + self.job_timeout
        while True:
            response = self.import_job(job_id)
            job = response.get("job") if isinstance(response.get("job"), Mapping) else {}
            status = _clean(job.get("status")).lower()
            if status in _TERMINAL_JOB_STATUSES:
                return dict(job)
            if self.monotonic() >= deadline:
                raise PixelProxyError("Pixel 导入任务等待超时", 504)
            self.sleeper(self.poll_interval)


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class PixelUploadQueue:
    """A persistent multi-worker outbox for successful registration results."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        client: PixelProxyClient | None = None,
        outbox_path: str | Path | None = None,
        target_ids: Iterable[str] = PIXEL_AUTO_TARGET_IDS,
        now: Callable[[], float] = time.time,
        log_fn: Callable[[str, str], None] | None = None,
        worker_count: int = 2,
        auto_start: bool = True,
        resume_pending: bool = True,
    ) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.outbox_path = Path(outbox_path).resolve() if outbox_path else self.data_dir / "pixel_upload_records.json"
        self.client = client or PixelProxyClient()
        normalized_targets = tuple(dict.fromkeys(_clean(value) for value in target_ids if _clean(value)))
        if not normalized_targets or any(value not in PIXEL_AUTO_TARGET_IDS for value in normalized_targets):
            raise PixelStateError("Pixel 自动上传目标只能是 pixel-2 至 pixel-7", 500)
        self.target_ids = normalized_targets
        self.now = now
        self.log_fn = log_fn
        self._lock = threading.RLock()
        self._work: queue.Queue[str] = queue.Queue()
        self._scheduled: set[str] = set()
        self._active_record_ids: set[str] = set()
        self._stop_event = threading.Event()
        self._started = False
        self._desired_workers = max(1, min(3, _safe_int(worker_count, 2)))
        self._worker_serial = 0
        self._worker_threads: dict[int, threading.Thread] = {}
        self._retiring_workers: set[int] = set()
        self._store = self._load_store()
        self._revision = max(
            (_safe_int(item.get("updated_at")) for item in self._store["records"]),
            default=0,
        )
        if self._backfill_source_metadata():
            self._save_locked()
        if resume_pending:
            self._schedule_recoverable()
        if auto_start:
            self.start()

    def _timestamp(self) -> int:
        return int(self.now())

    def _load_store(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.outbox_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": OUTBOX_VERSION, "records": []}
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {"version": OUTBOX_VERSION, "records": []}
        records = raw.get("records") if isinstance(raw, Mapping) else None
        if not isinstance(records, list):
            return {"version": OUTBOX_VERSION, "records": []}
        return {
            "version": OUTBOX_VERSION,
            "records": [copy.deepcopy(item) for item in records if isinstance(item, Mapping)],
        }

    def _save_locked(self) -> None:
        self._sync_failures_locked()
        _atomic_write_json(self.outbox_path, self._store)
        self._revision += 1

    def _sync_failures_locked(self) -> None:
        for record in self._store.get("records") or []:
            if not isinstance(record, dict):
                continue
            first_failure = None
            targets = record.get("targets") if isinstance(record.get("targets"), Mapping) else {}
            for item in targets.values():
                if not isinstance(item, dict):
                    continue
                failure = _pixel_failure(
                    _target_stage(item),
                    item.get("state"),
                    item.get("error"),
                )
                if failure is None:
                    item.pop("failure", None)
                else:
                    item["failure"] = failure
                    if first_failure is None:
                        first_failure = failure
            if first_failure is None:
                record.pop("failure", None)
            else:
                record["failure"] = first_failure

    def _backfill_source_metadata(self) -> bool:
        changed = False
        for record in self._store["records"]:
            if (
                _EMAIL_RE.fullmatch(_clean(record.get("source_email")))
                and _safe_identifier(record.get("batch_id"), maximum=80)
                and _safe_int(record.get("batch_started_at")) > 0
            ):
                continue
            try:
                _payload, _fingerprint, _secrets, metadata = self._read_source(record)
            except PixelRuntimeError:
                continue
            for key in ("source_email", "batch_id", "batch_started_at"):
                if record.get(key) or not metadata.get(key):
                    continue
                record[key] = metadata[key]
                changed = True
        return changed

    def _record_locked(self, record_id: str) -> dict[str, Any]:
        for record in self._store["records"]:
            if record.get("record_id") == record_id:
                return record
        raise PixelStateError("Pixel 上传记录不存在", 404)

    def _source_path(self, record: Mapping[str, Any]) -> Path:
        candidate = (self.data_dir / _clean(record.get("result_file"))).resolve()
        try:
            candidate.relative_to(self.data_dir)
        except ValueError:
            raise PixelSourceError("成功结果文件位置无效") from None
        return candidate

    def _read_source(
        self,
        record: Mapping[str, Any],
    ) -> tuple[dict[str, Any], str, tuple[str, ...], dict[str, Any]]:
        path = self._source_path(record)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise PixelSourceError("成功结果文件不存在") from None
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise PixelSourceError("成功结果文件格式无效") from None
        if not isinstance(raw, Mapping):
            raise PixelSourceError("成功结果文件格式无效")
        payload = build_pixel_import_payload(raw)
        credentials = payload["accounts"][0]["credentials"]
        secrets = tuple(_clean(credentials.get(key)) for key in ("access_token", "refresh_token", "id_token") if _clean(credentials.get(key)))
        return (
            payload,
            credential_fingerprint(payload),
            secrets,
            _source_public_metadata(raw, payload),
        )

    @staticmethod
    def _initial_target(target_id: str, now: int) -> dict[str, Any]:
        return {
            "target_id": target_id,
            "state": "pending",
            "stage": "import",
            "attempts": 0,
            "job_id": "",
            "generated_names": [],
            "account_ids": [],
            "failed_share_ids": [],
            "concurrency_by_id": {},
            "concurrency": None,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "shared": 0,
            "error": "",
            "retry_requested": True,
            "updated_at": now,
        }

    @staticmethod
    def _target_public(item: Mapping[str, Any]) -> dict[str, Any]:
        state = _clean(item.get("state")) or "pending"
        account_ids = [value for value in (_safe_int(value) for value in item.get("account_ids") or []) if value > 0]
        failed_share_ids = [
            value for value in (_safe_int(value) for value in item.get("failed_share_ids") or []) if value > 0
        ]
        generated_names = [
            _clean(value)[:160]
            for value in item.get("generated_names") or []
            if _clean(value) and _EMAIL_RE.fullmatch(_clean(value))
        ]
        concurrency_by_id = _concurrency_by_id(item.get("concurrency_by_id"))
        concurrency_values = set(concurrency_by_id.values())
        concurrency = next(iter(concurrency_values)) if len(concurrency_values) == 1 else None
        if concurrency is None:
            concurrency = _safe_int(item.get("concurrency")) or None
        retryable = state in _RETRYABLE_STATES
        stage = _target_stage(item)
        failure = _public_pixel_failure(item.get("failure")) or _pixel_failure(
            stage,
            state,
            item.get("error"),
        )
        return {
            "target_id": _clean(item.get("target_id")),
            "state": state,
            "status": state,
            "stage": stage,
            "attempts": max(_safe_int(item.get("attempts")), 0),
            "job_id": _safe_identifier(item.get("job_id")),
            "generated_names": generated_names,
            "generated_name": generated_names[0] if len(generated_names) == 1 else "",
            "account_ids": account_ids,
            "remote_account_id": account_ids[0] if len(account_ids) == 1 else None,
            "failed_share_ids": failed_share_ids,
            "failed_ids": failed_share_ids,
            "concurrency_by_id": concurrency_by_id,
            "concurrency": concurrency,
            "created": max(_safe_int(item.get("created")), 0),
            "updated": max(_safe_int(item.get("updated")), 0),
            "failed": max(_safe_int(item.get("failed")), 0),
            "shared": max(_safe_int(item.get("shared")), 0),
            "error": sanitize_error(item.get("error")),
            "failure": failure,
            "updated_at": max(_safe_int(item.get("updated_at")), 0),
            "needs_retry": retryable,
            "retryable": retryable,
            "needs_confirmation": state == "needs_confirmation",
        }

    def _public_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        path_available = False
        try:
            path_available = self._source_path(record).is_file()
        except PixelRuntimeError:
            pass
        metadata = {
            "source_email": _clean(record.get("source_email")).lower(),
            "batch_id": _safe_identifier(record.get("batch_id"), maximum=80),
            "batch_started_at": max(_safe_int(record.get("batch_started_at")), 0),
        }
        if (
            path_available
            and (
                not _EMAIL_RE.fullmatch(metadata["source_email"])
                or not metadata["batch_id"]
                or not metadata["batch_started_at"]
            )
        ):
            try:
                _payload, _fingerprint, _secrets, source_metadata = self._read_source(record)
                metadata = {
                    key: metadata.get(key) or source_metadata.get(key)
                    for key in ("source_email", "batch_id", "batch_started_at")
                }
            except PixelRuntimeError:
                pass
        if not _EMAIL_RE.fullmatch(_clean(metadata.get("source_email"))):
            metadata["source_email"] = ""
        targets = record.get("targets") if isinstance(record.get("targets"), Mapping) else {}
        target_values = [item for item in targets.values() if isinstance(item, Mapping)]
        job_values = sorted(
            (
                (_safe_int(item.get("updated_at")), _safe_identifier(item.get("job_id")))
                for item in target_values
                if _safe_identifier(item.get("job_id"))
            ),
            reverse=True,
        )
        can_retry = path_available and any(_clean(item.get("state")) in _RETRYABLE_STATES for item in target_values)
        return {
            "record_id": _safe_identifier(record.get("record_id")),
            "task_id": _safe_identifier(record.get("task_id")),
            "batch_id": _safe_identifier(metadata.get("batch_id"), maximum=80),
            "batch_started_at": max(_safe_int(metadata.get("batch_started_at")), 0),
            "source_email": _clean(metadata.get("source_email")).lower(),
            "credential_fingerprint": _clean(record.get("credential_fingerprint"))[:16],
            "status": _clean(record.get("status")) or "queued",
            "source_available": path_available,
            "can_retry": can_retry,
            "job_id": job_values[0][1] if job_values else "",
            "upload_file_name": Path(_clean(record.get("upload_file_name")) or "accounts.json").name,
            "error": sanitize_error(record.get("error")),
            "failure": _public_pixel_failure(record.get("failure")),
            "created_at": max(_safe_int(record.get("created_at")), 0),
            "updated_at": max(_safe_int(record.get("updated_at")), 0),
            "targets": [self._target_public(item) for item in target_values],
        }

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public_record(record) for record in reversed(self._store["records"])]

    @staticmethod
    def _batch_identifier(record: Mapping[str, Any]) -> str:
        return _safe_identifier(record.get("batch_id"), maximum=80) or "legacy"

    def _batch_summary_locked(
        self,
        batch_id: str,
        records: list[Mapping[str, Any]],
    ) -> dict[str, Any]:
        source_total = len(records)
        source_success = 0
        source_completed = 0
        source_processing = 0
        source_pending = 0
        source_failed = 0
        source_needs_confirmation = 0
        deliveries = {
            "total": source_total * len(self.target_ids),
            "success": 0,
            "pending": 0,
            "processing": 0,
            "failed": 0,
            "needs_confirmation": 0,
        }
        updated_at = 0
        started_at = 0

        for record in records:
            updated_at = max(updated_at, _safe_int(record.get("updated_at")))
            started_at = max(
                started_at,
                _safe_int(record.get("batch_started_at")),
                _safe_int(record.get("created_at")),
            )
            targets = record.get("targets") if isinstance(record.get("targets"), Mapping) else {}
            categories: list[str] = []
            for target_id in self.target_ids:
                target = targets.get(target_id) if isinstance(targets, Mapping) else None
                if not isinstance(target, Mapping):
                    category = "pending"
                else:
                    state = _clean(target.get("state")).lower() or "pending"
                    if state == "success":
                        category = "success"
                    elif state == "needs_confirmation":
                        category = "needs_confirmation"
                    elif state == "importing":
                        category = "processing"
                    elif state == "pending" or bool(target.get("retry_requested")):
                        category = "pending"
                    else:
                        category = "failed"
                categories.append(category)
                deliveries[category] += 1

            if categories and all(value == "success" for value in categories):
                source_success += 1
                source_completed += 1
            elif "processing" in categories:
                source_processing += 1
            elif "pending" in categories:
                source_pending += 1
            else:
                source_completed += 1
                source_failed += 1
            if "needs_confirmation" in categories:
                source_needs_confirmation += 1

        deliveries["completed"] = (
            deliveries["success"]
            + deliveries["failed"]
            + deliveries["needs_confirmation"]
        )
        source = {
            "total": source_total,
            "completed": source_completed,
            "success": source_success,
            "pending": source_pending,
            "processing": source_processing,
            "failed": source_failed,
            "needs_confirmation": source_needs_confirmation,
        }
        if source_total and source_success == source_total:
            status = "success"
        elif source_pending or source_processing:
            status = "processing"
        elif source_success:
            status = "partial"
        elif source_total:
            status = "failed"
        else:
            status = "empty"
        return {
            "batch_id": batch_id,
            "batch_started_at": started_at,
            "updated_at": updated_at,
            "status": status,
            "source": source,
            "deliveries": deliveries,
        }

    def _batch_summaries_locked(self) -> list[dict[str, Any]]:
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for record in self._store.get("records") or []:
            if not isinstance(record, Mapping):
                continue
            grouped.setdefault(self._batch_identifier(record), []).append(record)
        summaries = [
            self._batch_summary_locked(batch_id, records)
            for batch_id, records in grouped.items()
        ]
        summaries.sort(
            key=lambda item: (
                _safe_int(item.get("batch_started_at")),
                _safe_int(item.get("updated_at")),
                str(item.get("batch_id") or ""),
            ),
            reverse=True,
        )
        return summaries

    def queue_status(self) -> dict[str, Any]:
        with self._lock:
            alive = sum(1 for thread in self._worker_threads.values() if thread.is_alive())
            return {
                "configured_workers": self._desired_workers,
                "alive_workers": alive,
                "active_workers": len(self._active_record_ids),
                "pending_records": max(0, len(self._scheduled) - len(self._active_record_ids)),
                "running_records": len(self._active_record_ids),
            }

    def overview(self) -> dict[str, Any]:
        with self._lock:
            batches = self._batch_summaries_locked()
            current = next(
                (item for item in batches if item.get("status") == "processing"),
                batches[0] if batches else None,
            )
            alive = sum(1 for thread in self._worker_threads.values() if thread.is_alive())
            return {
                "revision": self._revision,
                "queue": {
                    "configured_workers": self._desired_workers,
                    "alive_workers": alive,
                    "active_workers": len(self._active_record_ids),
                    "pending_records": max(0, len(self._scheduled) - len(self._active_record_ids)),
                    "running_records": len(self._active_record_ids),
                },
                "current_batch": copy.deepcopy(current),
                "batch_count": len(batches),
            }

    def batches(self, *, page: Any = 1, page_size: Any = 20) -> dict[str, Any]:
        normalized_page = max(1, _safe_int(page, 1))
        normalized_size = min(max(1, _safe_int(page_size, 20)), 100)
        with self._lock:
            items = self._batch_summaries_locked()
            total = len(items)
            pages = max(1, (total + normalized_size - 1) // normalized_size)
            normalized_page = min(normalized_page, pages)
            start = (normalized_page - 1) * normalized_size
            return {
                "items": copy.deepcopy(items[start:start + normalized_size]),
                "total": total,
                "page": normalized_page,
                "page_size": normalized_size,
                "pages": pages,
                "revision": self._revision,
            }

    def batch_records(
        self,
        batch_id: Any,
        *,
        page: Any = 1,
        page_size: Any = 50,
        status: Any = "",
    ) -> dict[str, Any]:
        identifier = _safe_identifier(batch_id, maximum=80)
        if not identifier:
            raise PixelStateError("Pixel 批次 ID 无效", 400)
        normalized_page = max(1, _safe_int(page, 1))
        normalized_size = min(max(1, _safe_int(page_size, 50)), 100)
        normalized_status = _clean(status).lower()[:40]

        def matches_status(record: Mapping[str, Any]) -> bool:
            if not normalized_status:
                return True
            record_status = _clean(record.get("status")).lower()
            targets = record.get("targets") if isinstance(record.get("targets"), Mapping) else {}
            target_values = [item for item in targets.values() if isinstance(item, Mapping)]
            target_states = {_clean(item.get("state")).lower() for item in target_values}
            if normalized_status == "needs_confirmation":
                return "needs_confirmation" in target_states
            if normalized_status == "queued":
                return record_status == "queued" or any(
                    _clean(item.get("state")).lower() == "pending"
                    or bool(item.get("retry_requested"))
                    for item in target_values
                )
            if normalized_status == "processing":
                return record_status == "processing" or "importing" in target_states
            if normalized_status == "failed":
                return any(
                    _clean(item.get("state")).lower()
                    not in {"success", "pending", "importing", "needs_confirmation"}
                    and not bool(item.get("retry_requested"))
                    for item in target_values
                )
            return record_status == normalized_status

        with self._lock:
            matched = [
                record
                for record in reversed(self._store.get("records") or [])
                if isinstance(record, Mapping)
                and self._batch_identifier(record) == identifier
                and matches_status(record)
            ]
            if not matched and identifier not in {
                self._batch_identifier(record)
                for record in self._store.get("records") or []
                if isinstance(record, Mapping)
            }:
                raise PixelStateError("Pixel 上传批次不存在", 404)
            total = len(matched)
            pages = max(1, (total + normalized_size - 1) // normalized_size)
            normalized_page = min(normalized_page, pages)
            start = (normalized_page - 1) * normalized_size
            items = [
                self._public_record(record)
                for record in matched[start:start + normalized_size]
            ]
            batch_records = [
                record
                for record in self._store.get("records") or []
                if isinstance(record, Mapping)
                and self._batch_identifier(record) == identifier
            ]
            return {
                "batch": self._batch_summary_locked(identifier, batch_records),
                "items": items,
                "total": total,
                "page": normalized_page,
                "page_size": normalized_size,
                "pages": pages,
                "revision": self._revision,
            }

    def get(self, record_id: str) -> dict[str, Any]:
        with self._lock:
            return self._public_record(self._record_locked(_clean(record_id)))

    def enqueue(self, task_id: Any, result_file: str | Path) -> dict[str, Any]:
        path = Path(result_file)
        if not path.is_absolute():
            path = self.data_dir / path
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(self.data_dir).as_posix()
        except ValueError:
            raise PixelSourceError("成功结果文件必须位于本地数据目录") from None

        safe_task_id = _safe_identifier(task_id)
        if not safe_task_id:
            raise PixelStateError("任务 ID 不能为空", 400)
        now = self._timestamp()
        source_error = ""
        fingerprint = ""
        source_metadata: dict[str, Any] = {}
        temporary = {"result_file": relative}
        try:
            _payload, fingerprint, _secrets, source_metadata = self._read_source(temporary)
        except PixelSourceError as exc:
            source_error = exc.public_message
        record_id = hashlib.sha256(f"{safe_task_id}\0{relative}\0{fingerprint}".encode("utf-8")).hexdigest()[:24]

        with self._lock:
            try:
                existing = self._record_locked(record_id)
            except PixelStateError:
                existing = None
            if existing is not None:
                return self._public_record(existing)
            targets = {target: self._initial_target(target, now) for target in self.target_ids}
            if source_error:
                for target in targets.values():
                    target.update(
                        {
                            "state": "source_unavailable",
                            "stage": "source",
                            "retry_requested": False,
                            "error": source_error,
                        }
                    )
            record = {
                "record_id": record_id,
                "task_id": safe_task_id,
                "batch_id": source_metadata.get("batch_id") or "",
                "batch_started_at": source_metadata.get("batch_started_at") or 0,
                "source_email": source_metadata.get("source_email") or "",
                "result_file": relative,
                "upload_file_name": f"autophone-{record_id}.json",
                "credential_fingerprint": fingerprint,
                "status": "source_unavailable" if source_error else "queued",
                "error": source_error,
                "created_at": now,
                "updated_at": now,
                "targets": targets,
            }
            self._store["records"].append(record)
            self._save_locked()
            public = self._public_record(record)
        if not source_error:
            self._schedule(record_id)
        return public

    def requeue(self, task_id: Any, result_file: str | Path) -> dict[str, Any]:
        """Explicitly enqueue all targets again for a selected successful result."""
        public = self.enqueue(task_id, result_file)
        identifier = _clean(public.get("record_id"))
        with self._lock:
            record = self._record_locked(identifier)
            now = self._timestamp()
            record["targets"] = {
                target_id: self._initial_target(target_id, now)
                for target_id in self.target_ids
            }
            record["status"] = "queued"
            record["error"] = ""
            record["updated_at"] = now
            self._save_locked()
            public = self._public_record(record)
        self._schedule(identifier)
        return public

    def retry(self, record_id: str, target_ids: Iterable[Any] | None = None) -> dict[str, Any]:
        identifier = _clean(record_id)
        with self._lock:
            record = self._record_locked(identifier)
            targets = record.get("targets") if isinstance(record.get("targets"), Mapping) else {}
            requested = (
                list(dict.fromkeys(_clean(value) for value in target_ids if _clean(value)))
                if target_ids is not None
                else [target_id for target_id, item in targets.items() if item.get("state") in _RETRYABLE_STATES]
            )
            if not requested or any(target_id not in targets for target_id in requested):
                raise PixelStateError("没有可重试的 Pixel 目标", 409)
            changed = False
            now = self._timestamp()
            for target_id in requested:
                item = targets[target_id]
                state = item.get("state")
                if state not in _RETRYABLE_STATES:
                    continue
                if state == "source_unavailable":
                    item["state"] = "pending"
                    item["stage"] = "source"
                item["retry_requested"] = True
                item["error"] = ""
                item["updated_at"] = now
                changed = True
            if not changed:
                raise PixelStateError("所选 Pixel 目标不可重试", 409)
            record["status"] = "queued"
            record["error"] = ""
            record["updated_at"] = now
            self._save_locked()
            public = self._public_record(record)
        self._schedule(identifier)
        return public

    def recover_existing_accounts(
        self,
        record_id: str,
        target_account_ids: Mapping[Any, Iterable[Any]],
    ) -> dict[str, Any]:
        """Attach confirmed duplicate-import IDs and retry sharing only.

        This is intentionally an internal recovery operation.  IDs must come from
        a separate, trusted account-identity lookup; arbitrary IDs or excluded
        targets are rejected so a stale mapping cannot share another account.
        OAuth material is never read or copied by this method.
        """
        identifier = _clean(record_id)
        if not identifier or not isinstance(target_account_ids, Mapping):
            raise PixelStateError("Pixel 已存在账号映射参数无效", 400)
        normalized: dict[str, list[int]] = {}
        for raw_target, raw_ids in target_account_ids.items():
            target_id = _clean(raw_target)
            if target_id not in self.target_ids:
                raise PixelStateError("Pixel 已存在账号映射包含未开放目标", 400)
            ids = _safe_account_id_values(raw_ids)
            if not ids:
                raise PixelStateError("至少提供一个有效的 Pixel 远端账号 ID", 400)
            normalized[target_id] = ids
        if not normalized:
            raise PixelStateError("没有可恢复的 Pixel 账号映射", 400)

        with self._lock:
            record = self._record_locked(identifier)
            targets = record.get("targets") if isinstance(record.get("targets"), Mapping) else {}
            now = self._timestamp()
            changed = False
            for target_id, ids in normalized.items():
                item = targets.get(target_id)
                if not isinstance(item, dict):
                    raise PixelStateError("Pixel 目标记录不存在", 404)
                if item.get("state") == "success":
                    # A successful target is immutable and must never be shared twice
                    # through a manual recovery call.
                    continue
                item.update(
                    {
                        "state": "share_failed",
                        "stage": "share",
                        "account_ids": ids,
                        "failed_share_ids": ids,
                        "error": "远端账号已存在，已定位现有账号，等待公开共享",
                        "retry_requested": True,
                        "updated_at": now,
                    }
                )
                changed = True
            if not changed:
                raise PixelStateError("所选 Pixel 目标已经完成，无需恢复", 409)
            record["status"] = "queued"
            record["error"] = ""
            record["updated_at"] = now
            self._save_locked()
            public = self._public_record(record)
        self._schedule(identifier)
        return public

    def _schedule_recoverable(self) -> None:
        for record in self._store["records"]:
            targets = record.get("targets") if isinstance(record.get("targets"), Mapping) else {}
            if any(
                item.get("state") == "importing"
                or (item.get("state") in {"pending", "import_failed", "share_failed"} and item.get("retry_requested"))
                for item in targets.values()
                if isinstance(item, Mapping)
            ):
                self._schedule(_clean(record.get("record_id")))

    def _schedule(self, record_id: str) -> None:
        if not record_id:
            return
        with self._lock:
            if record_id in self._scheduled:
                return
            self._scheduled.add(record_id)
            self._work.put(record_id)

    def configure_workers(self, worker_count: Any) -> int:
        desired = max(1, min(3, _safe_int(worker_count, 2)))
        with self._lock:
            self._desired_workers = desired
            alive_ids = {
                worker_id
                for worker_id, thread in self._worker_threads.items()
                if thread.is_alive()
            }
            effective_ids = alive_ids.difference(self._retiring_workers)
            if len(effective_ids) > desired:
                retire = sorted(effective_ids, reverse=True)[:len(effective_ids) - desired]
                self._retiring_workers.update(retire)
            elif len(effective_ids) < desired:
                needed = desired - len(effective_ids)
                reusable = sorted(alive_ids.intersection(self._retiring_workers))
                for worker_id in reusable[:needed]:
                    self._retiring_workers.discard(worker_id)
                    needed -= 1
                if self._started and needed > 0:
                    self._spawn_workers_locked(needed)
            return self._desired_workers

    def _spawn_workers_locked(self, count: int) -> None:
        for _index in range(max(0, int(count))):
            self._worker_serial += 1
            worker_id = self._worker_serial
            thread = threading.Thread(
                target=self._worker,
                args=(worker_id,),
                name=f"pixel-upload-worker-{worker_id}",
                daemon=True,
            )
            self._worker_threads[worker_id] = thread
            thread.start()

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._stop_event.clear()
            self._started = True
            self._retiring_workers.clear()
            alive = sum(1 for thread in self._worker_threads.values() if thread.is_alive())
            self._spawn_workers_locked(max(0, self._desired_workers - alive))

    def stop(self, *, wait: bool = True, timeout: float = 5.0) -> None:
        with self._lock:
            self._started = False
            self._stop_event.set()
            threads = list(self._worker_threads.values())
        if wait:
            deadline = time.monotonic() + max(timeout, 0.0)
            for thread in threads:
                if thread is threading.current_thread():
                    continue
                thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def _worker(self, worker_id: int) -> None:
        try:
            while not self._stop_event.is_set():
                with self._lock:
                    if worker_id in self._retiring_workers:
                        break
                self.process_next(timeout=0.25, worker_id=worker_id)
        finally:
            with self._lock:
                self._worker_threads.pop(worker_id, None)
                self._retiring_workers.discard(worker_id)
                if self._started and not self._stop_event.is_set():
                    effective = sum(
                        1
                        for identifier, thread in self._worker_threads.items()
                        if thread.is_alive() and identifier not in self._retiring_workers
                    )
                    self._spawn_workers_locked(max(0, self._desired_workers - effective))

    def process_next(self, *, timeout: float = 0.0, worker_id: int | None = None) -> bool:
        try:
            record_id = self._work.get(timeout=max(timeout, 0.0)) if timeout else self._work.get_nowait()
        except queue.Empty:
            return False
        with self._lock:
            if worker_id is not None and (
                worker_id in self._retiring_workers or self._stop_event.is_set()
            ):
                self._work.put(record_id)
                self._work.task_done()
                return False
            self._active_record_ids.add(record_id)
        try:
            self._process_record(record_id)
        except Exception as exc:
            detail = sanitize_error(exc) or type(exc).__name__
            self._set_record_error(record_id, f"Pixel 上传队列意外失败: {detail}")
        finally:
            with self._lock:
                self._active_record_ids.discard(record_id)
                self._scheduled.discard(record_id)
            self._work.task_done()
        return True

    def _emit(self, message: str, level: str = "info") -> None:
        if self.log_fn is not None:
            try:
                self.log_fn(sanitize_error(message), level)
            except Exception:
                pass

    def _set_record_error(self, record_id: str, error: Any) -> None:
        message = sanitize_error(error)
        with self._lock:
            try:
                record = self._record_locked(record_id)
            except PixelStateError:
                return
            now = self._timestamp()
            record["error"] = message
            for item in (record.get("targets") or {}).values():
                if not isinstance(item, dict) or item.get("state") == "success":
                    continue
                stage = _target_stage(item)
                target_message = sanitize_error(
                    f"Pixel {_STAGE_LABELS[stage]}阶段意外失败: {message}"
                )
                state = _clean(item.get("state")) or "pending"
                if stage == "source":
                    state = "source_unavailable"
                elif stage == "verification":
                    state = "needs_confirmation"
                elif stage == "share" and state not in {"share_failed", "needs_confirmation"}:
                    state = "share_failed"
                elif stage == "import" and (
                    state == "pending" or (state == "importing" and not _clean(item.get("job_id")))
                ):
                    state = "import_failed"
                item.update(
                    {
                        "state": state,
                        "stage": stage,
                        "error": target_message,
                        "retry_requested": False,
                        "updated_at": now,
                    }
                )
            record["updated_at"] = now
            self._refresh_status_locked(record)
            self._save_locked()

    def _refresh_status_locked(self, record: dict[str, Any]) -> None:
        targets = list((record.get("targets") or {}).values())
        states = {_clean(item.get("state")) for item in targets if isinstance(item, Mapping)}
        if states == {"success"}:
            status = "success"
        elif states & _ACTIVE_STATES:
            status = "processing"
        elif states == {"source_unavailable"}:
            status = "source_unavailable"
        elif "success" in states:
            status = "partial"
        elif states:
            status = "failed"
        else:
            status = "failed"
        record["status"] = status
        if status == "success":
            record["error"] = ""

    def _update_targets_error(
        self,
        record_id: str,
        target_ids: Iterable[str],
        state: str,
        error: Any,
        *,
        stage: str | None = None,
    ) -> None:
        message = sanitize_error(error)
        resolved_stage = stage if stage in _TARGET_STAGES else _stage_for_state(state)
        with self._lock:
            record = self._record_locked(record_id)
            now = self._timestamp()
            for target_id in target_ids:
                item = record["targets"].get(target_id)
                if not isinstance(item, dict):
                    continue
                item.update(
                    {
                        "state": state,
                        "stage": resolved_stage,
                        "error": message,
                        "retry_requested": False,
                        "updated_at": now,
                    }
                )
            record["error"] = message
            record["updated_at"] = now
            self._refresh_status_locked(record)
            self._save_locked()

    def _set_targets_stage(self, record_id: str, target_ids: Iterable[str], stage: str) -> None:
        if stage not in _TARGET_STAGES:
            raise PixelStateError("Pixel 上传阶段无效", 500)
        with self._lock:
            record = self._record_locked(record_id)
            now = self._timestamp()
            changed = False
            for target_id in target_ids:
                item = record["targets"].get(target_id)
                if not isinstance(item, dict) or item.get("state") == "success":
                    continue
                if item.get("stage") != stage:
                    item["stage"] = stage
                    item["updated_at"] = now
                    changed = True
            if changed:
                record["updated_at"] = now
                self._save_locked()

    def _matching_import_record(self, record: Mapping[str, Any]) -> Mapping[str, Any] | None:
        response = self.client.import_records()
        records = response.get("records") if isinstance(response.get("records"), list) else []
        file_name = _clean(record.get("upload_file_name"))
        matches = []
        for item in records:
            if not isinstance(item, Mapping):
                continue
            names = [item.get("sourceFileName"), *(item.get("sourceFileNames") or [])]
            if file_name in {_clean(value) for value in names}:
                matches.append(item)
        # The proxy returns import records newest first.
        return matches[0] if matches else None

    def _apply_target_result(self, item: dict[str, Any], result: Mapping[str, Any], secrets: Iterable[Any] = ()) -> None:
        generated_names = [
            value
            for value in _result_generated_names(result)
            if _EMAIL_RE.fullmatch(value)
        ]
        duplicate_import, existing_account_ids = _duplicate_import_details(result)
        failed_share_ids = [
            value for value in (_safe_int(value) for value in result.get("failedShareIds") or []) if value > 0
        ]
        if duplicate_import and existing_account_ids:
            # PixelAPI keeps the existing row when an OAuth identity is imported a
            # second time.  Treat the confirmed IDs as a share-only recovery target;
            # never submit the credentials again in a loop.
            failed_share_ids = list(dict.fromkeys([*failed_share_ids, *existing_account_ids]))
        concurrency_by_id = _concurrency_by_id(
            result.get("concurrencyById") or result.get("concurrency_by_id")
        )
        concurrency_ids = [_safe_int(value) for value in concurrency_by_id]
        known_ids = list(
            dict.fromkeys(
                [*(item.get("account_ids") or []), *failed_share_ids, *concurrency_ids, *existing_account_ids]
            )
        )
        created = max(_safe_int(result.get("created")), 0)
        updated = max(_safe_int(result.get("updated")), 0)
        failed = max(_safe_int(result.get("failed")), 0)
        shared = max(_safe_int(result.get("shared")), 0)
        share_failed = max(_safe_int(result.get("shareFailed")), len(failed_share_ids))
        remote_status = _clean(result.get("status")).lower()
        verified_concurrency = shared > 0 and len(concurrency_by_id) == shared
        if duplicate_import and not existing_account_ids:
            state = "needs_confirmation"
            stage = "verification"
        elif duplicate_import and existing_account_ids:
            state = "share_failed"
            stage = "share"
        elif failed and created + updated:
            state = "needs_confirmation"
            stage = "import"
        elif failed_share_ids:
            state = "share_failed"
            stage = "share"
        elif share_failed:
            state = "needs_confirmation"
            stage = "share"
        elif remote_status == "success" and not failed and verified_concurrency:
            state = "success"
            stage = "verification"
        elif remote_status == "success" and not failed:
            state = "needs_confirmation"
            stage = "verification"
        elif failed and not created and not updated:
            state = "import_failed"
            stage = "import"
        elif remote_status in {"partial", "failed"}:
            state = "needs_confirmation"
            stage = "import"
        else:
            state = "needs_confirmation"
            stage = "verification"
        messages = [result.get("message")]
        for detail in result.get("importErrors") or []:
            if isinstance(detail, Mapping):
                messages.append(detail.get("message"))
        error = sanitize_error("; ".join(_clean(value) for value in messages if _clean(value)), secrets)
        if duplicate_import and not existing_account_ids:
            error = "远端账号已存在，但响应未返回账号 ID，无法安全映射；请在账号管理中人工确认"
        elif duplicate_import and existing_account_ids:
            error = "远端账号已存在，已定位现有账号，等待公开共享"
        elif state == "needs_confirmation" and remote_status == "success" and not verified_concurrency:
            error = "远端共享结果缺少已验证的 3-10 并发值"
        item.update(
            {
                "state": state,
                "stage": stage,
                "generated_names": generated_names,
                "account_ids": known_ids,
                "failed_share_ids": failed_share_ids,
                "concurrency_by_id": concurrency_by_id,
                "concurrency": (
                    next(iter(set(concurrency_by_id.values())))
                    if len(set(concurrency_by_id.values())) == 1
                    else (_safe_int(result.get("concurrency")) or None)
                ),
                "created": created,
                "updated": updated,
                "failed": failed,
                "shared": shared,
                "error": "" if state == "success" else error,
                "retry_requested": bool(duplicate_import and existing_account_ids),
                "updated_at": self._timestamp(),
            }
        )

    def _apply_results(
        self,
        record_id: str,
        results: Iterable[Any],
        selected: Iterable[str],
        secrets: Iterable[Any] = (),
        *,
        expected_domain: str,
    ) -> None:
        selected_set = set(selected)
        result_map = {
            _clean(item.get("targetId")): item
            for item in results
            if isinstance(item, Mapping) and _clean(item.get("targetId")) in selected_set
        }
        with self._lock:
            record = self._record_locked(record_id)
            generated_name_owners: dict[str, list[str]] = {}
            for target_id, target in record["targets"].items():
                if target_id in selected_set or not isinstance(target, Mapping):
                    continue
                names = target.get("generated_names") or []
                if target.get("state") == "success" and len(names) == 1:
                    name = _clean(names[0]).lower()
                    if _valid_generated_name(name, expected_domain):
                        generated_name_owners.setdefault(name, []).append(target_id)
            for target_id in selected_set:
                target = record["targets"][target_id]
                result = result_map.get(target_id)
                if result is None:
                    target.update(
                        {
                            "state": "needs_confirmation",
                            "stage": "verification",
                            "error": "远端导入结果缺少目标状态",
                            "retry_requested": False,
                            "updated_at": self._timestamp(),
                        }
                    )
                else:
                    self._apply_target_result(target, result, secrets)
                    if target.get("state") != "success":
                        continue
                    names = _result_generated_names(result)
                    if len(names) != 1:
                        target.update(
                            {
                                "state": "needs_confirmation",
                                "stage": "verification",
                                "generated_names": [],
                                "error": "远端导入结果缺少唯一的随机邮箱名",
                            }
                        )
                        continue
                    generated_name = names[0]
                    if not _valid_generated_name(generated_name, expected_domain):
                        target.update(
                            {
                                "state": "needs_confirmation",
                                "stage": "verification",
                                "generated_names": [],
                                "error": "远端随机邮箱名不符合 acct-<12位十六进制>@原域名规则",
                            }
                        )
                        continue
                    target["generated_names"] = [generated_name]
                    generated_name_owners.setdefault(generated_name, []).append(target_id)
            for generated_name, owner_ids in generated_name_owners.items():
                if len(owner_ids) < 2:
                    continue
                for target_id in owner_ids:
                    if target_id not in selected_set:
                        continue
                    target = record["targets"][target_id]
                    target.update(
                        {
                            "state": "needs_confirmation",
                            "stage": "verification",
                            "error": "远端随机邮箱名在多个 Pixel 目标间重复",
                        }
                    )
            record["updated_at"] = self._timestamp()
            self._refresh_status_locked(record)
            self._save_locked()

    def _recover_remote(
        self,
        record_id: str,
        selected: list[str],
        secrets: Iterable[Any],
        expected_domain: str,
    ) -> tuple[list[str], set[str]]:
        with self._lock:
            record = copy.deepcopy(self._record_locked(record_id))
        remote = self._matching_import_record(record)
        if remote is None:
            return selected, set()
        results = remote.get("targets") if isinstance(remote.get("targets"), list) else remote.get("results") or []
        present = {
            _clean(item.get("targetId"))
            for item in results
            if isinstance(item, Mapping) and _clean(item.get("targetId")) in selected
        }
        if present:
            self._apply_results(
                record_id,
                results,
                present,
                secrets,
                expected_domain=expected_domain,
            )
        with self._lock:
            current = self._record_locked(record_id)
            confirmed_failures = {
                target_id
                for target_id in present
                if current["targets"][target_id].get("state") == "import_failed"
            }
        return [
            target_id
            for target_id in selected
            if target_id not in present or target_id in confirmed_failures
        ], present

    def _resume_jobs(self, record_id: str, secrets: Iterable[Any], expected_domain: str) -> None:
        with self._lock:
            record = self._record_locked(record_id)
            groups: dict[str, list[str]] = {}
            missing_job = []
            for target_id, item in record["targets"].items():
                if item.get("state") != "importing":
                    continue
                job_id = _clean(item.get("job_id"))
                if job_id:
                    groups.setdefault(job_id, []).append(target_id)
                else:
                    missing_job.append(target_id)
        if missing_job:
            self._set_targets_stage(record_id, missing_job, "verification")
            try:
                remaining, matched = self._recover_remote(
                    record_id,
                    missing_job,
                    secrets,
                    expected_domain,
                )
            except PixelRuntimeError as exc:
                self._update_targets_error(
                    record_id,
                    missing_job,
                    "needs_confirmation",
                    exc.public_message,
                    stage="verification",
                )
            else:
                unknown = [target_id for target_id in remaining if target_id not in matched]
                if unknown:
                    self._update_targets_error(
                        record_id,
                        unknown,
                        "needs_confirmation",
                        "无法确认中断前的远端导入状态",
                        stage="verification",
                    )
        for job_id, targets in groups.items():
            self._set_targets_stage(record_id, targets, "import")
            try:
                job = self.client.wait_import_job(job_id)
            except PixelProxyError as exc:
                state = "needs_confirmation" if exc.status_code == 404 else "importing"
                self._update_targets_error(record_id, targets, state, exc.public_message, stage="import")
                continue
            results = job.get("results") if isinstance(job.get("results"), list) else []
            if _clean(job.get("status")).lower() == "failed" and not results:
                self._update_targets_error(
                    record_id,
                    targets,
                    "needs_confirmation",
                    job.get("error") or "远端导入任务失败且结果不完整",
                    stage="import",
                )
            else:
                self._apply_results(
                    record_id,
                    results,
                    targets,
                    secrets,
                    expected_domain=expected_domain,
                )

    def _retry_shares(self, record_id: str) -> None:
        with self._lock:
            record = self._record_locked(record_id)
            selected = [
                target_id
                for target_id, item in record["targets"].items()
                if item.get("state") == "share_failed" and item.get("retry_requested")
            ]
        for target_id in selected:
            with self._lock:
                item = self._record_locked(record_id)["targets"][target_id]
                ids = list(item.get("failed_share_ids") or [])
                item["attempts"] = max(_safe_int(item.get("attempts")), 0) + 1
                item["stage"] = "share"
                item["retry_requested"] = False
                item["updated_at"] = self._timestamp()
                self._save_locked()
            if not ids:
                self._update_targets_error(
                    record_id,
                    [target_id],
                    "needs_confirmation",
                    "共享失败记录缺少远端账号 ID",
                    stage="verification",
                )
                continue
            try:
                result = self.client.share_accounts(target_id, ids)
            except PixelRuntimeError as exc:
                self._update_targets_error(
                    record_id,
                    [target_id],
                    "share_failed",
                    exc.public_message,
                    stage="share",
                )
                continue
            remote_failed_ids = [
                value for value in (_safe_int(value) for value in result.get("failedIds") or []) if value > 0
            ]
            success_ids = [value for value in (_safe_int(value) for value in result.get("successIds") or []) if value > 0]
            if not success_ids and bool(result.get("ok")) and not remote_failed_ids:
                success_ids = list(ids)
            concurrency_by_id = _concurrency_by_id(
                result.get("concurrencyById") or result.get("concurrency_by_id"),
                success_ids,
            )
            verified_ids = {_safe_int(value) for value in concurrency_by_id}
            unresolved_ids = [value for value in ids if value not in verified_ids]
            failed_ids = list(dict.fromkeys([*remote_failed_ids, *unresolved_ids]))
            share_failed = not bool(result.get("ok")) or bool(remote_failed_ids)
            ok = not share_failed and not unresolved_ids
            stage = "share" if share_failed else "verification"
            with self._lock:
                record = self._record_locked(record_id)
                item = record["targets"][target_id]
                item["account_ids"] = list(dict.fromkeys([*(item.get("account_ids") or []), *success_ids, *failed_ids]))
                item["failed_share_ids"] = failed_ids
                item["concurrency_by_id"] = {
                    **_concurrency_by_id(item.get("concurrency_by_id")),
                    **concurrency_by_id,
                }
                concurrency_values = set(item["concurrency_by_id"].values())
                item["concurrency"] = next(iter(concurrency_values)) if len(concurrency_values) == 1 else None
                item["shared"] = max(_safe_int(item.get("shared")), 0) + len(success_ids)
                item["state"] = "success" if ok else "share_failed"
                item["stage"] = stage
                if ok:
                    item["error"] = ""
                elif stage == "verification":
                    item["error"] = "公开共享结果缺少已验证的 3-10 并发值"
                else:
                    item["error"] = sanitize_error(result.get("message") or "公开共享失败")
                item["updated_at"] = self._timestamp()
                record["updated_at"] = self._timestamp()
                self._refresh_status_locked(record)
                self._save_locked()

    def _resolve_duplicate_accounts(
        self,
        record_id: str,
        selected: Iterable[str],
        payload: Mapping[str, Any],
    ) -> None:
        """Resolve duplicate imports by scanning only non-secret identity fields.

        Older PixelAPI responses omit the existing account ID from an
        ``account already exists`` error.  A bounded account-list scan can still
        recover an unambiguous ID; ambiguous or unavailable mappings stay in
        ``needs_confirmation`` and are never guessed.
        """
        finder = getattr(self.client, "find_accounts_by_identity", None)
        if not callable(finder):
            return
        accounts = payload.get("accounts") if isinstance(payload, Mapping) else None
        source_account = accounts[0] if isinstance(accounts, list) and accounts and isinstance(accounts[0], Mapping) else None
        if source_account is None:
            return
        identity_values = _account_identity_values(source_account)
        if not identity_values:
            return
        candidates: list[str] = []
        with self._lock:
            record = self._record_locked(record_id)
            for target_id in selected:
                item = record["targets"].get(target_id)
                if not isinstance(item, Mapping):
                    continue
                if item.get("state") == "needs_confirmation" and "远端账号已存在" in _clean(item.get("error")):
                    candidates.append(target_id)
        for target_id in candidates:
            try:
                found = [
                    value
                    for value in (
                        _safe_int(account_id)
                        for account_id in finder(target_id, identity_values)
                    )
                    if value > 0
                ]
            except PixelRuntimeError as exc:
                self._update_targets_error(
                    record_id,
                    [target_id],
                    "needs_confirmation",
                    f"远端账号已存在，但账号 ID 回查失败：{exc.public_message}",
                    stage="verification",
                )
                continue
            found = list(dict.fromkeys(found))
            with self._lock:
                record = self._record_locked(record_id)
                item = record["targets"].get(target_id)
                if not isinstance(item, dict):
                    continue
                now = self._timestamp()
                if len(found) == 1:
                    account_id = found[0]
                    item.update(
                        {
                            "state": "share_failed",
                            "stage": "share",
                            "account_ids": [account_id],
                            "failed_share_ids": [account_id],
                            "retry_requested": True,
                            "error": "远端账号已存在，已通过账号身份定位现有账号，等待公开共享",
                            "updated_at": now,
                        }
                    )
                elif len(found) > 1:
                    item.update(
                        {
                            "state": "needs_confirmation",
                            "stage": "verification",
                            "error": "远端账号已存在，但身份回查匹配多个账号 ID，无法安全选择",
                            "retry_requested": False,
                            "updated_at": now,
                        }
                    )
                else:
                    item["updated_at"] = now
                record["updated_at"] = now
                self._refresh_status_locked(record)
                self._save_locked()

    def _submit_imports(
        self,
        record_id: str,
        payload: Mapping[str, Any],
        secrets: Iterable[Any],
        expected_domain: str,
    ) -> None:
        with self._lock:
            record = self._record_locked(record_id)
            selected = [
                target_id
                for target_id, item in record["targets"].items()
                if item.get("state") in {"pending", "import_failed"} and item.get("retry_requested")
            ]
            retry_targets = [target_id for target_id in selected if _safe_int(record["targets"][target_id].get("attempts")) > 0]
            upload_file_name = record["upload_file_name"]
        if not selected:
            return

        if retry_targets:
            self._set_targets_stage(record_id, selected, "verification")
            try:
                selected, matched = self._recover_remote(
                    record_id,
                    selected,
                    secrets,
                    expected_domain,
                )
            except PixelRuntimeError as exc:
                self._update_targets_error(
                    record_id,
                    selected,
                    "needs_confirmation",
                    exc.public_message,
                    stage="verification",
                )
                return
            with self._lock:
                record = self._record_locked(record_id)
                recovered_share_targets = [
                    target_id
                    for target_id in matched
                    if record["targets"][target_id].get("state") == "share_failed"
                ]
                for target_id in recovered_share_targets:
                    record["targets"][target_id]["retry_requested"] = True
                if recovered_share_targets:
                    self._save_locked()
            if recovered_share_targets:
                self._retry_shares(record_id)
            if not selected:
                return

        with self._lock:
            record = self._record_locked(record_id)
            now = self._timestamp()
            for target_id in selected:
                item = record["targets"][target_id]
                item.update(
                    {
                        "state": "importing",
                        "stage": "import",
                        "attempts": max(_safe_int(item.get("attempts")), 0) + 1,
                        "job_id": "",
                        "retry_requested": False,
                        "error": "",
                        "updated_at": now,
                    }
                )
            record["status"] = "processing"
            record["updated_at"] = now
            self._save_locked()

        try:
            response = self.client.create_import(payload, selected, file_name=upload_file_name)
            job = response.get("job") if isinstance(response.get("job"), Mapping) else {}
            job_id = _clean(job.get("jobId"))
            if not job_id:
                raise PixelProxyError("Pixel 导入响应缺少任务 ID", ambiguous=True)
        except PixelProxyError as exc:
            self._set_targets_stage(record_id, selected, "verification")
            try:
                remaining, matched = self._recover_remote(
                    record_id,
                    selected,
                    secrets,
                    expected_domain,
                )
            except PixelRuntimeError as recovery_exc:
                self._update_targets_error(
                    record_id,
                    selected,
                    "needs_confirmation",
                    f"{exc.public_message}; 远端状态回查失败: {recovery_exc.public_message}",
                    stage="verification",
                )
                return
            if remaining:
                confirmed_failures = [target_id for target_id in remaining if target_id in matched]
                unknown = [target_id for target_id in remaining if target_id not in matched]
                if confirmed_failures:
                    self._update_targets_error(
                        record_id,
                        confirmed_failures,
                        "import_failed",
                        exc.public_message,
                        stage="import",
                    )
                if unknown:
                    state = "needs_confirmation" if exc.ambiguous else "import_failed"
                    stage = "verification" if exc.ambiguous else "import"
                    self._update_targets_error(record_id, unknown, state, exc.public_message, stage=stage)
            return

        with self._lock:
            record = self._record_locked(record_id)
            for target_id in selected:
                record["targets"][target_id]["job_id"] = _safe_identifier(job_id)
                record["targets"][target_id]["stage"] = "import"
            record["updated_at"] = self._timestamp()
            self._save_locked()
        try:
            completed = self.client.wait_import_job(job_id)
        except PixelProxyError as exc:
            state = "needs_confirmation" if exc.status_code == 404 else "importing"
            self._update_targets_error(record_id, selected, state, exc.public_message, stage="import")
            return
        results = completed.get("results") if isinstance(completed.get("results"), list) else []
        if _clean(completed.get("status")).lower() == "failed" and not results:
            self._update_targets_error(
                record_id,
                selected,
                "needs_confirmation",
                completed.get("error") or "远端导入任务失败且结果不完整",
                stage="import",
            )
            return
        self._apply_results(
            record_id,
            results,
            selected,
            secrets,
            expected_domain=expected_domain,
        )

    def _process_record(self, record_id: str) -> None:
        with self._lock:
            record = copy.deepcopy(self._record_locked(record_id))
        source_targets = [
            target_id
            for target_id, item in (record.get("targets") or {}).items()
            if isinstance(item, Mapping) and item.get("state") != "success"
        ]
        self._set_targets_stage(record_id, source_targets, "source")
        try:
            payload, fingerprint, secrets, _source_metadata = self._read_source(record)
        except PixelSourceError as exc:
            self._update_targets_error(
                record_id,
                source_targets,
                "source_unavailable",
                exc.public_message,
                stage="source",
            )
            return
        expected_domain = _payload_email_domain(payload)
        with self._lock:
            current = self._record_locked(record_id)
            now = self._timestamp()
            for item in current["targets"].values():
                if not isinstance(item, dict) or item.get("state") == "success":
                    continue
                if item.get("stage") == "source":
                    item["stage"] = _stage_for_state(item.get("state"))
                    item["updated_at"] = now
            current["credential_fingerprint"] = fingerprint
            current["error"] = ""
            current["updated_at"] = now
            self._save_locked()
        self._resume_jobs(record_id, secrets, expected_domain)
        self._retry_shares(record_id)
        self._submit_imports(record_id, payload, secrets, expected_domain)
        # A duplicate-identity import can resolve to an existing account ID only
        # after the import job completes.  Scan the remote account list using the
        # local non-secret identity fields, then give that share-only recovery path
        # one immediate attempt.  Ordinary share failures keep their persisted
        # retry flag for an explicit retry.
        source_targets = [
            target_id
            for target_id, item in (record.get("targets") or {}).items()
            if isinstance(item, Mapping) and item.get("state") != "success"
        ]
        self._resolve_duplicate_accounts(record_id, source_targets, payload)
        self._retry_shares(record_id)
        with self._lock:
            record = self._record_locked(record_id)
            self._refresh_status_locked(record)
            record["updated_at"] = self._timestamp()
            self._save_locked()
            status = record["status"]
        self._emit(f"Pixel 上传记录 {record_id} 状态: {status}", "success" if status == "success" else "warn")


__all__ = [
    "DEFAULT_PIXEL_PROXY_BASE_URL",
    "PIXEL_AUTO_TARGET_IDS",
    "PIXEL_EXCLUDED_TARGET_IDS",
    "PixelProxyClient",
    "PixelProxyError",
    "PixelRuntimeError",
    "PixelSourceError",
    "PixelStateError",
    "PixelUploadQueue",
    "UrllibPixelTransport",
    "build_pixel_import_payload",
    "credential_fingerprint",
    "sanitize_error",
]
