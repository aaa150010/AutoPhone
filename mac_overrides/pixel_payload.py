"""Payload constants, errors and pure helpers for Pixel uploads.

Split out of ``pixel_runtime.py`` so the upload queue keeps a single
responsibility; the original module re-exports everything for compatibility.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import re
from typing import Any, Protocol
import urllib.parse


DEFAULT_PIXEL_PROXY_BASE_URL = "https://lynote.xyz/gpt-api"
PIXEL_AUTO_TARGET_IDS = tuple(f"pixel-{index}" for index in range(2, 8))
PIXEL_EXCLUDED_TARGET_IDS = ("pixel-1",)
OUTBOX_VERSION = 4
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
        accounts = payload["accounts"]
    except (KeyError, TypeError):
        raise PixelSourceError("Pixel 上传载荷格式无效") from None
    if not isinstance(accounts, list) or not accounts:
        raise PixelSourceError("Pixel 上传载荷格式无效")
    rows: list[str] = []
    for account in accounts:
        if not isinstance(account, Mapping) or not isinstance(account.get("credentials"), Mapping):
            raise PixelSourceError("Pixel 上传载荷格式无效")
        credentials = account["credentials"]
        rows.append(
            "\0".join(
                _clean(credentials.get(key))
                for key in ("access_token", "refresh_token", "id_token")
            )
        )
    material = "\n".join(rows)
    if not material.replace("\0", ""):
        raise PixelSourceError("Pixel 上传载荷缺少 OAuth 凭据")
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "DEFAULT_PIXEL_PROXY_BASE_URL",
    "PIXEL_AUTO_TARGET_IDS",
    "PIXEL_EXCLUDED_TARGET_IDS",
    "PixelProxyError",
    "PixelRuntimeError",
    "PixelSourceError",
    "PixelStateError",
    "PixelTransport",
    "build_pixel_import_payload",
    "credential_fingerprint",
    "sanitize_error",
]
