"""Credential-safe client for the hosted online mailbox manager."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import hmac
import json
import re
import socket
from typing import Any, Protocol
import urllib.error
import urllib.parse
import urllib.request
import uuid


DEFAULT_ONLINE_MAILBOX_BASE_URL = "https://lynote.xyz/token-tool"
MAX_ONLINE_MAILBOX_ITEMS = 10_000
_MAX_RESPONSE_BYTES = 256 * 1024
_EMAIL_RE = re.compile(
    r"(?i)^[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)


class OnlineMailboxError(RuntimeError):
    """An upload failure whose message is safe for the local dashboard."""

    def __init__(
        self,
        public_message: str,
        *,
        code: str = "online_mailbox_upload_failed",
        status_code: int = 502,
        provider_status: int | None = None,
        retryable: bool = False,
    ) -> None:
        self.public_message = str(public_message or "网站邮箱上传失败")[:500]
        self.code = code
        self.status_code = status_code
        self.provider_status = provider_status
        self.retryable = retryable
        super().__init__(self.public_message)


class OnlineMailboxTransport(Protocol):
    def post_json(
        self,
        url: str,
        payload: Mapping[str, Any],
        *,
        token: str,
        timeout: float,
    ) -> Mapping[str, Any]: ...


def normalize_base_url(value: Any) -> str:
    raw = str(value or DEFAULT_ONLINE_MAILBOX_BASE_URL).strip().rstrip("/")
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        raise OnlineMailboxError(
            "网站邮箱地址无效，请检查平台集成配置",
            code="online_mailbox_config_invalid",
            status_code=400,
        ) from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise OnlineMailboxError(
            "网站邮箱地址无效，请填写完整的 HTTP 或 HTTPS 地址",
            code="online_mailbox_config_invalid",
            status_code=400,
        )
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path.rstrip("/"), "", "")
    )


def manager_url(base_url: Any) -> str:
    return f"{normalize_base_url(base_url)}/mailboxes/"


def _normalized_item(value: Any) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    email = str(value.get("email") or "").strip().lower()
    mailbox_url = str(value.get("mailbox_url") or "").strip()
    if not _EMAIL_RE.fullmatch(email) or not mailbox_url or len(mailbox_url) > 4096:
        return None
    try:
        parsed = urllib.parse.urlsplit(mailbox_url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return {"email": email, "mailbox_url": mailbox_url}


def normalize_items(values: Any) -> list[dict[str, str]]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise OnlineMailboxError(
            "网站邮箱上传参数无效",
            code="online_mailbox_items_invalid",
            status_code=400,
        )
    if len(values) > MAX_ONLINE_MAILBOX_ITEMS:
        raise OnlineMailboxError(
            f"网站邮箱单次最多上传 {MAX_ONLINE_MAILBOX_ITEMS} 条",
            code="online_mailbox_items_too_many",
            status_code=413,
        )
    normalized = []
    for item in values:
        parsed = _normalized_item(item)
        if parsed is None:
            raise OnlineMailboxError(
                "网站邮箱上传数据包含无效邮箱或取件地址",
                code="online_mailbox_items_invalid",
                status_code=400,
            )
        normalized.append(parsed)
    if not normalized:
        raise OnlineMailboxError(
            "本机没有带取件 URL 的可上传邮箱",
            code="online_mailbox_items_empty",
            status_code=400,
        )
    return normalized


class UrllibOnlineMailboxTransport:
    """Small JSON transport that never exposes provider response bodies."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def post_json(
        self,
        url: str,
        payload: Mapping[str, Any],
        *,
        token: str,
        timeout: float,
    ) -> Mapping[str, Any]:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "gptPhone-online-mailbox/1",
            },
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            status = int(exc.code or 502)
            messages = {
                401: "网站邮箱上传鉴权失败，请检查 API 密钥",
                403: "网站邮箱上传被拒绝，请检查 API 密钥",
                409: "网站邮箱批次冲突，请重新发起上传",
                413: "网站邮箱上传数据量超过服务端限制",
                429: "网站邮箱服务请求过于频繁，请稍后重试",
            }
            raise OnlineMailboxError(
                messages.get(status, f"网站邮箱服务返回 HTTP {status}"),
                code="online_mailbox_provider_http_error",
                status_code=status if status in {401, 403, 409, 413, 429} else 502,
                provider_status=status,
                retryable=status >= 500 or status == 429,
            ) from None
        except (TimeoutError, socket.timeout) as exc:
            raise OnlineMailboxError(
                "连接网站邮箱服务超时，请检查网络后重试",
                code="online_mailbox_timeout",
                status_code=504,
                retryable=True,
            ) from exc
        except urllib.error.URLError as exc:
            raise OnlineMailboxError(
                "无法连接网站邮箱服务，请检查地址和网络",
                code="online_mailbox_network_error",
                status_code=502,
                retryable=True,
            ) from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise OnlineMailboxError(
                "网站邮箱服务响应过大，无法确认上传结果",
                code="online_mailbox_response_invalid",
                status_code=502,
            )
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OnlineMailboxError(
                "网站邮箱服务未返回有效 JSON",
                code="online_mailbox_response_invalid",
                status_code=502,
            ) from exc
        if not isinstance(result, Mapping):
            raise OnlineMailboxError(
                "网站邮箱服务返回格式无效",
                code="online_mailbox_response_invalid",
                status_code=502,
            )
        return result


class OnlineMailboxClient:
    def __init__(
        self,
        base_url: Any,
        api_token: Any,
        *,
        transport: OnlineMailboxTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        self.api_token = str(api_token or "").strip()
        if not self.api_token or self.api_token == "********":
            raise OnlineMailboxError(
                "尚未配置网站邮箱 API 密钥",
                code="online_mailbox_token_missing",
                status_code=400,
            )
        self.transport = transport or UrllibOnlineMailboxTransport()
        self.timeout = max(1.0, min(float(timeout), 120.0))

    def upload(
        self,
        items: Any,
        *,
        batch_id: str | None = None,
    ) -> dict[str, Any]:
        normalized = normalize_items(items)
        upload_batch_id = str(batch_id or uuid.uuid4()).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", upload_batch_id):
            raise OnlineMailboxError(
                "网站邮箱上传批次编号无效",
                code="online_mailbox_batch_invalid",
                status_code=400,
            )
        payload = {
            "batch_id": upload_batch_id,
            "source": "autophone",
            "items": normalized,
        }
        result: Mapping[str, Any] | None = None
        for attempt in range(2):
            try:
                result = self.transport.post_json(
                    f"{self.base_url}/api/mailboxes/import",
                    payload,
                    token=self.api_token,
                    timeout=self.timeout,
                )
                break
            except OnlineMailboxError as exc:
                if attempt == 0 and exc.retryable:
                    continue
                raise
        if result is None or result.get("ok") is False:
            raise OnlineMailboxError(
                "网站邮箱服务未确认上传成功",
                code="online_mailbox_response_failed",
                status_code=502,
            )
        returned_batch = str(result.get("batch_id") or "")
        if returned_batch and not hmac.compare_digest(returned_batch, upload_batch_id):
            raise OnlineMailboxError(
                "网站邮箱服务返回了不匹配的批次编号",
                code="online_mailbox_response_invalid",
                status_code=502,
            )
        counts = {}
        for key in ("submitted", "created", "updated", "duplicates", "rejected"):
            try:
                value = int(result.get(key) or 0)
            except (TypeError, ValueError) as exc:
                raise OnlineMailboxError(
                    "网站邮箱服务返回了无效统计",
                    code="online_mailbox_response_invalid",
                    status_code=502,
                ) from exc
            if value < 0:
                raise OnlineMailboxError(
                    "网站邮箱服务返回了无效统计",
                    code="online_mailbox_response_invalid",
                    status_code=502,
                )
            counts[key] = value
        return {
            "ok": True,
            "batch_id": upload_batch_id,
            **counts,
            "manager_url": manager_url(self.base_url),
        }


def token_fingerprint(value: Any) -> str:
    text = str(value or "")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12] if text else ""


__all__ = [
    "DEFAULT_ONLINE_MAILBOX_BASE_URL",
    "MAX_ONLINE_MAILBOX_ITEMS",
    "OnlineMailboxClient",
    "OnlineMailboxError",
    "UrllibOnlineMailboxTransport",
    "manager_url",
    "normalize_base_url",
    "normalize_items",
    "token_fingerprint",
]
