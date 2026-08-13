"""Credential-safe OpenAI Codex quota queries for mailbox administration."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from threading import RLock
import tempfile
import time
from typing import Any, Callable, Mapping, Protocol


OPENAI_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
OPENAI_CODEX_RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
OPENAI_QUOTA_TIMEOUT_SECONDS = 20
OPENAI_QUOTA_NODE_CODE = "openai_quota"
OPENAI_QUOTA_NODE_LABEL = "查询 OpenAI 额度"
OPENAI_CODEX_PROBE_MODEL = "gpt-5.5"
OPENAI_CODEX_PROBE_VERSION = "0.146.0"
OPENAI_CODEX_PROBE_USER_AGENT = (
    f"codex-tui/{OPENAI_CODEX_PROBE_VERSION} "
    "(Ubuntu 22.4.0; x86_64) xterm-256color"
)
_QUOTA_SUMMARY_LIMIT = 240


def _network_error_message(error: BaseException) -> str:
    text = f"{type(error).__name__}: {error}".lower()
    if any(marker in text for marker in ("proxyerror", "proxy connect", "unable to connect to proxy")):
        return "无法连接当前显式代理"
    if any(marker in text for marker in ("could not resolve", "name resolution", "getaddrinfo")):
        return "OpenAI 域名 DNS 解析失败"
    if any(marker in text for marker in ("tls", "ssl", "certificate", "handshake")):
        return "OpenAI TLS 握手失败"
    if any(marker in text for marker in ("timeout", "timed out")):
        return "OpenAI 连接或响应超时"
    if any(marker in text for marker in ("connection reset", "remote disconnected", "unexpected eof")):
        return "OpenAI 远端连接中断"
    return f"OpenAI 网络连接异常（{type(error).__name__}）"


class QuotaResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


class QuotaTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
    ) -> QuotaResponse: ...

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
    ) -> "QuotaProbeResponse": ...


@dataclass(frozen=True)
class QuotaProbeResponse:
    status_code: int
    headers: Mapping[str, str]


class OpenAIQuotaError(RuntimeError):
    def __init__(self, code: str, message: str, *, http_status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status

    def public(self) -> dict[str, Any]:
        return {
            "status": "error",
            "node_code": OPENAI_QUOTA_NODE_CODE,
            "node_label": OPENAI_QUOTA_NODE_LABEL,
            "code": self.code,
            "error": f"{OPENAI_QUOTA_NODE_LABEL}失败：{self}",
            "http_status": self.http_status,
        }


class CurlCffiQuotaTransport:
    """Cloudflare-friendly transport with environment proxy fallback disabled."""

    def __init__(self, *, proxy: str = "") -> None:
        self.proxy = str(proxy or "").strip()

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
    ) -> QuotaResponse:
        from curl_cffi import requests

        session = requests.Session(impersonate="chrome")
        session.trust_env = False
        kwargs: dict[str, Any] = {
            "headers": dict(headers),
            "timeout": timeout,
        }
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        try:
            return session.get(url, **kwargs)
        except Exception as exc:
            raise OpenAIQuotaError(
                "openai_quota_network_error",
                _network_error_message(exc),
            ) from exc
        finally:
            session.close()

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
    ) -> QuotaProbeResponse:
        from curl_cffi import requests

        session = requests.Session(impersonate="chrome")
        session.trust_env = False
        kwargs: dict[str, Any] = {
            "headers": dict(headers),
            "json": dict(json_body),
            "timeout": timeout,
            "stream": True,
        }
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        response = None
        try:
            response = session.post(url, **kwargs)
            return QuotaProbeResponse(
                status_code=int(getattr(response, "status_code", 0) or 0),
                headers={str(key): str(value) for key, value in response.headers.items()},
            )
        except Exception as exc:
            raise OpenAIQuotaError(
                "openai_quota_probe_network_error",
                f"5 小时额度探针失败：{_network_error_message(exc)}",
            ) from exc
        finally:
            if response is not None:
                response.close()
            session.close()


@dataclass(frozen=True)
class OpenAIQuotaCredentials:
    access_token: str
    account_id: str


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def credentials_from_result(document: Any) -> OpenAIQuotaCredentials:
    root = _mapping(document)
    result = _mapping(root.get("result"))
    local_oauth = _mapping(result.get("local_oauth"))
    local_tokens = _mapping(local_oauth.get("tokens"))
    access_token = str(
        result.get("access_token")
        or local_tokens.get("access_token")
        or ""
    ).strip()
    account_id = str(
        result.get("chatgpt_account_id")
        or result.get("account_id")
        or local_tokens.get("chatgpt_account_id")
        or local_tokens.get("account_id")
        or ""
    ).strip()
    if not access_token:
        raise OpenAIQuotaError(
            "openai_quota_token_missing",
            "本地成功结果没有可用的 OpenAI access token",
        )
    if not account_id:
        raise OpenAIQuotaError(
            "openai_quota_account_id_missing",
            "本地成功结果没有 ChatGPT account id",
        )
    return OpenAIQuotaCredentials(access_token=access_token, account_id=account_id)


def _number(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result


def _clean_public_text(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1********", text)
    text = re.sub(
        r'(?i)(["\']?(?:access_token|refresh_token|password|authorization)["\']?\s*[:=]\s*["\']?)[^\s,"\'}]+',
        r"\1********",
        text,
    )
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{12,}(?:\.[A-Za-z0-9_-]+){1,2}\b", "********", text)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:_QUOTA_SUMMARY_LIMIT]


def _public_quota_window(value: Any) -> dict[str, Any] | None:
    row = _mapping(value)
    remaining = _number(row.get("remaining_percent"))
    if remaining is None:
        return None
    result: dict[str, Any] = {
        "remaining_percent": round(max(0.0, min(100.0, remaining)), 2),
    }
    for field in ("limit_window_seconds", "reset_at", "reset_after_seconds", "queried_at"):
        numeric = _number(row.get(field))
        result[field] = int(numeric) if numeric is not None else None
    result["status"] = "available" if result["remaining_percent"] > 0 else "exhausted"
    return result


def public_quota_snapshot(
    value: Any,
    *,
    previous: Any = None,
    queried_at: int | None = None,
) -> dict[str, Any]:
    """Return the credential-free latest query state with last-known quota windows."""
    row = _mapping(value)
    old = _mapping(previous)
    if not row and not old:
        return {}
    status = str(row.get("status") or old.get("status") or "").strip().lower()
    if status not in {"ok", "error"}:
        status = "ok" if row.get("quota_5h") is not None or row.get("quota_7d") is not None else "error"
    result: dict[str, Any] = {
        "status": status,
        "node_code": OPENAI_QUOTA_NODE_CODE,
        "node_label": OPENAI_QUOTA_NODE_LABEL,
    }
    for field in ("quota_5h", "quota_7d"):
        window = _public_quota_window(row.get(field)) or _public_quota_window(old.get(field))
        result[field] = window
    raw_queried_at = row.get("queried_at")
    if raw_queried_at is None:
        raw_queried_at = queried_at if queried_at is not None else old.get("queried_at")
    try:
        result["queried_at"] = int(raw_queried_at) if raw_queried_at is not None else None
    except (TypeError, ValueError):
        result["queried_at"] = None
    if status == "error":
        code = str(row.get("code") or old.get("code") or "openai_quota_failed").strip()
        result["code"] = code if code.startswith("openai_quota_") else "openai_quota_failed"
        result["error"] = _clean_public_text(
            row.get("error") or old.get("error") or "查询 OpenAI 额度失败：历史记录没有保存具体原因"
        )
        try:
            http_status = row.get("http_status") if row.get("http_status") is not None else old.get("http_status")
            result["http_status"] = int(http_status) if http_status is not None else None
        except (TypeError, ValueError):
            result["http_status"] = None
    else:
        result["error"] = ""
    return result


class OpenAIQuotaSnapshotStore:
    """Atomic quota snapshots keyed by a non-reversible account fingerprint."""

    def __init__(self, path: str | Path, *, now_fn=time.time) -> None:
        self.path = Path(path)
        self.now_fn = now_fn
        self._lock = RLock()
        self._cached_signature: tuple[int, int, int, int] | None = None
        self._cached_payload: dict[str, Any] | None = None

    @staticmethod
    def _key(account_id: Any) -> str:
        value = str(account_id or "").strip()
        return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            stat = self.path.stat()
            signature = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino)
        except OSError:
            signature = None
        if self._cached_payload is not None and signature == self._cached_signature:
            return self._cached_payload
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            payload = {"version": 1, "items": {}}
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), dict):
            payload = {"version": 1, "items": {}}
        self._cached_signature = signature
        self._cached_payload = payload
        return payload

    def _write_unlocked(self, payload: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = ""
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = handle.name
                json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            stat = self.path.stat()
            self._cached_signature = (
                stat.st_mtime_ns,
                stat.st_ctime_ns,
                stat.st_size,
                stat.st_ino,
            )
            self._cached_payload = dict(payload)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def status_for(self, account_id: Any) -> dict[str, Any]:
        key = self._key(account_id)
        if not key:
            return {}
        with self._lock:
            item = self._read_unlocked().get("items", {}).get(key)
        return public_quota_snapshot(item)

    def put(self, account_id: Any, value: Any) -> dict[str, Any]:
        key = self._key(account_id)
        if not key:
            return public_quota_snapshot(value, queried_at=int(self.now_fn()))
        with self._lock:
            payload = self._read_unlocked()
            items = payload.setdefault("items", {})
            snapshot = public_quota_snapshot(
                value,
                previous=items.get(key),
                queried_at=int(self.now_fn()),
            )
            items[key] = snapshot
            payload["version"] = 1
            payload["updated_at"] = int(self.now_fn())
            self._write_unlocked(payload)
        return snapshot


def persist_quota_snapshot(
    status_store: Callable[[str, Mapping[str, Any]], Mapping[str, Any] | None] | None,
    account_id: Any,
    value: Any,
) -> dict[str, Any]:
    """Persist one completed row and surface a redacted write failure."""

    snapshot = public_quota_snapshot(value)
    key = str(account_id or "").strip()
    if not key or not callable(status_store):
        return snapshot
    try:
        stored = status_store(key, snapshot)
    except Exception:
        failed = dict(snapshot)
        failed.update(
            status="error",
            code="openai_quota_snapshot_persist_failed",
            error="OpenAI 额度已查询，但本地状态保存失败，请重试该行",
        )
        return public_quota_snapshot(failed, previous=snapshot)
    return public_quota_snapshot(stored, previous=snapshot) if isinstance(stored, Mapping) else snapshot


def _window(value: Any, queried_at: int) -> dict[str, Any] | None:
    row = _mapping(value)
    used = _number(row.get("used_percent"))
    if used is None:
        return None
    used = max(0.0, min(100.0, used))
    remaining = round(100.0 - used, 2)
    window_seconds = _number(row.get("limit_window_seconds"))
    reset_at = _number(row.get("reset_at"))
    reset_after = _number(row.get("reset_after_seconds"))
    return {
        "remaining_percent": remaining,
        "limit_window_seconds": int(window_seconds) if window_seconds is not None else None,
        "reset_at": int(reset_at) if reset_at is not None and reset_at > 0 else None,
        "reset_after_seconds": int(reset_after) if reset_after is not None else None,
        "queried_at": queried_at,
        "status": "available" if remaining > 0 else "exhausted",
    }


def _header_values(headers: Mapping[str, Any]) -> dict[str, str]:
    return {str(key).strip().lower(): str(value).strip() for key, value in headers.items()}


def normalize_quota_headers(
    headers: Mapping[str, Any],
    *,
    queried_at: int | None = None,
) -> dict[str, Any] | None:
    """Normalize Codex response headers using sub2api's duration-based mapping."""
    values = _header_values(headers)

    def header_window(prefix: str) -> dict[str, Any] | None:
        used = _number(values.get(f"x-codex-{prefix}-used-percent"))
        if used is None:
            return None
        minutes = _number(values.get(f"x-codex-{prefix}-window-minutes"))
        reset_after = _number(values.get(f"x-codex-{prefix}-reset-after-seconds"))
        reset_at = _number(values.get(f"x-codex-{prefix}-reset-at"))
        return {
            "used_percent": used,
            "limit_window_seconds": minutes * 60 if minutes is not None else None,
            "reset_after_seconds": reset_after,
            "reset_at": reset_at,
        }

    primary = header_window("primary")
    secondary = header_window("secondary")
    if primary is None and secondary is None:
        return None
    return normalize_quota_payload(
        {
            "rate_limit": {
                "primary_window": primary,
                "secondary_window": secondary,
            }
        },
        queried_at=queried_at,
    )


def normalize_quota_payload(payload: Any, *, queried_at: int | None = None) -> dict[str, Any]:
    root = _mapping(payload)
    rate_limit = _mapping(root.get("rate_limit"))
    now = int(time.time()) if queried_at is None else int(queried_at)
    primary = _window(rate_limit.get("primary_window"), now)
    secondary = _window(rate_limit.get("secondary_window"), now)

    quota_5h = None
    quota_7d = None
    candidates = [item for item in (primary, secondary) if item is not None]
    if len(candidates) == 2:
        primary_seconds = primary.get("limit_window_seconds") if primary else None
        secondary_seconds = secondary.get("limit_window_seconds") if secondary else None
        if primary_seconds is not None and secondary_seconds is not None:
            if primary_seconds < secondary_seconds:
                quota_5h, quota_7d = primary, secondary
            else:
                quota_5h, quota_7d = secondary, primary
        else:
            quota_5h, quota_7d = secondary, primary
    elif len(candidates) == 1:
        candidate = candidates[0]
        seconds = candidate.get("limit_window_seconds")
        if seconds is not None and seconds <= 6 * 60 * 60:
            quota_5h = candidate
        else:
            quota_7d = candidate

    if quota_5h is None and quota_7d is None:
        raise OpenAIQuotaError(
            "openai_quota_windows_missing",
            "OpenAI 未返回 5 小时或 7 天额度窗口",
        )
    return {
        "status": "ok",
        "node_code": OPENAI_QUOTA_NODE_CODE,
        "node_label": OPENAI_QUOTA_NODE_LABEL,
        "quota_5h": quota_5h,
        "quota_7d": quota_7d,
        "queried_at": now,
    }


def _provider_error_code(payload: Any) -> str:
    root = _mapping(payload)
    detail = _mapping(root.get("detail"))
    return str(detail.get("code") or "").strip().lower()


def _status_error(status: int, payload: Any = None) -> OpenAIQuotaError:
    if status == 402 and _provider_error_code(payload) == "deactivated_workspace":
        return OpenAIQuotaError(
            "openai_quota_deactivated_workspace",
            "OpenAI 工作空间已停用，本地邮箱将自动删除",
            http_status=status,
        )
    if status == 401:
        return OpenAIQuotaError(
            "openai_quota_unauthorized",
            "OpenAI OAuth Token 已失效，需要重新运行账号",
            http_status=status,
        )
    if status == 403:
        return OpenAIQuotaError(
            "openai_quota_forbidden",
            "OpenAI 拒绝当前账号查询额度",
            http_status=status,
        )
    if status == 429:
        return OpenAIQuotaError(
            "openai_quota_rate_limited",
            "OpenAI 额度接口限流，请稍后重试",
            http_status=status,
        )
    if status >= 500:
        return OpenAIQuotaError(
            "openai_quota_upstream_error",
            "OpenAI 额度服务暂时不可用",
            http_status=status,
        )
    return OpenAIQuotaError(
        "openai_quota_request_rejected",
        f"OpenAI 额度接口返回 HTTP {status}",
        http_status=status,
    )


class OpenAIQuotaClient:
    def __init__(
        self,
        *,
        transport: QuotaTransport | None = None,
        proxy: str = "",
        timeout: float = OPENAI_QUOTA_TIMEOUT_SECONDS,
        now_fn=time.time,
    ) -> None:
        self.transport = transport or CurlCffiQuotaTransport(proxy=proxy)
        self.timeout = max(1.0, float(timeout))
        self.now_fn = now_fn

    def query(self, document: Any) -> dict[str, Any]:
        credentials = credentials_from_result(document)
        headers = {
            "authorization": f"Bearer {credentials.access_token}",
            "chatgpt-account-id": credentials.account_id,
            "openai-beta": "codex-1",
            "oai-language": "zh-CN",
            "originator": "Codex Desktop",
            "accept": "application/json",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "empty",
            "priority": "u=4, i",
        }
        try:
            response = self.transport.get(
                OPENAI_USAGE_URL,
                headers=headers,
                timeout=self.timeout,
            )
        except OpenAIQuotaError:
            raise
        except Exception as exc:
            raise OpenAIQuotaError(
                "openai_quota_network_error",
                _network_error_message(exc),
            ) from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if status < 200 or status >= 300:
            try:
                error_payload = response.json()
            except Exception:
                error_payload = {}
            raise _status_error(status, error_payload)
        try:
            payload = response.json()
        except Exception as exc:
            raise OpenAIQuotaError(
                "openai_quota_invalid_response",
                "OpenAI 额度接口返回了无法解析的数据",
                http_status=status,
            ) from exc
        queried_at = int(self.now_fn())
        result = normalize_quota_payload(payload, queried_at=queried_at)
        if result.get("quota_5h") is not None and result.get("quota_7d") is not None:
            return result

        probe = getattr(self.transport, "post", None)
        if not callable(probe):
            return result
        probe_headers = {
            "authorization": f"Bearer {credentials.access_token}",
            "chatgpt-account-id": credentials.account_id,
            "content-type": "application/json",
            "accept": "text/event-stream",
            "openai-beta": "responses=experimental",
            "originator": "codex-tui",
            "version": OPENAI_CODEX_PROBE_VERSION,
            "user-agent": OPENAI_CODEX_PROBE_USER_AGENT,
        }
        probe_body = {
            "model": OPENAI_CODEX_PROBE_MODEL,
            "input": [
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": "hi"}],
                }
            ],
            "stream": True,
            "store": False,
            "instructions": "You are Codex, a coding agent.",
        }
        try:
            probe_response = probe(
                OPENAI_CODEX_RESPONSES_URL,
                headers=probe_headers,
                json_body=probe_body,
                timeout=self.timeout,
            )
            probed = normalize_quota_headers(
                getattr(probe_response, "headers", {}) or {},
                queried_at=queried_at,
            )
        except Exception:
            return result
        if probed is None:
            return result
        if result.get("quota_5h") is None:
            result["quota_5h"] = probed.get("quota_5h")
        if result.get("quota_7d") is None:
            result["quota_7d"] = probed.get("quota_7d")
        return result


__all__ = [
    "CurlCffiQuotaTransport",
    "OPENAI_CODEX_RESPONSES_URL",
    "OpenAIQuotaClient",
    "OpenAIQuotaCredentials",
    "OpenAIQuotaError",
    "OpenAIQuotaSnapshotStore",
    "credentials_from_result",
    "normalize_quota_headers",
    "normalize_quota_payload",
    "persist_quota_snapshot",
    "public_quota_snapshot",
]
