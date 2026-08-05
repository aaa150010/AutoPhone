"""Credential-safe OpenAI Codex quota queries for mailbox administration."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Mapping, Protocol


OPENAI_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
OPENAI_CODEX_RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
OPENAI_QUOTA_TIMEOUT_SECONDS = 20
OPENAI_QUOTA_NODE_CODE = "openai_quota"
OPENAI_QUOTA_NODE_LABEL = "查询 OpenAI 额度"
OPENAI_CODEX_PROBE_MODEL = "gpt-5.4"
OPENAI_CODEX_PROBE_VERSION = "0.146.0"
OPENAI_CODEX_PROBE_USER_AGENT = (
    f"codex_cli_rs/{OPENAI_CODEX_PROBE_VERSION} "
    "(Ubuntu 22.4.0; x86_64) xterm-256color"
)


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
                "网络请求失败，请检查当前显式代理",
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
                "5 小时额度探针网络请求失败",
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


def _status_error(status: int) -> OpenAIQuotaError:
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
                "网络请求失败，请检查当前显式代理",
            ) from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if status < 200 or status >= 300:
            raise _status_error(status)
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
            "originator": "codex_cli_rs",
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
    "credentials_from_result",
    "normalize_quota_headers",
    "normalize_quota_payload",
]
