"""Small, credential-safe client for the Remail Open API."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class RemailApiError(RuntimeError):
    def __init__(self, code: str, message: str, *, status: int = 0, request_id: str = "") -> None:
        self.code, self.status, self.request_id = str(code), int(status or 0), str(request_id or "")
        super().__init__(str(message)[:300])


_REMAIL_EXPIRY_KEYS = frozenset({
    "expiresat", "expireat", "expiredat", "validuntil", "expiryat", "expirationdate",
})


def remail_pickup_url(base_url: str, email: str, service_token: str) -> str:
    """Build the browser-openable, service-token-scoped pickup URL."""
    address = str(email or "").strip()
    token = str(service_token or "").strip()
    if not address or not token:
        raise ValueError("Remail 取件地址缺少邮箱或服务凭证")
    parsed = urlsplit(str(base_url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Remail 取件地址不是完整的 HTTP(S) URL")
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
             if key.lower() not in {"email", "token", "service_token", "servicetoken"}]
    query.extend((("email", address), ("token", token)))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _remail_timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000.0
        return number if number > 0 else None
    text = str(value).strip()
    try:
        number = float(text)
    except (TypeError, ValueError):
        number = 0.0
    if number > 0:
        return number / 1000.0 if number > 10_000_000_000 else number
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def remail_expiry_timestamp(value: Mapping[str, Any] | None) -> float | None:
    """Find an order expiry field without treating token TTL fields as order expiry."""
    if not isinstance(value, Mapping):
        return None
    candidates: list[float] = []
    for key, raw in value.items():
        normalized = str(key or "").replace("-", "_").lower()
        compact = normalized.replace("_", "")
        if compact in _REMAIL_EXPIRY_KEYS:
            timestamp = _remail_timestamp(raw)
            if timestamp is not None:
                candidates.append(timestamp)
        elif isinstance(raw, Mapping):
            nested = remail_expiry_timestamp(raw)
            if nested is not None:
                candidates.append(nested)
    return min(candidates) if candidates else None


def remail_order_expired(value: Mapping[str, Any] | None, *, now: float | None = None) -> bool:
    if not isinstance(value, Mapping):
        return False
    status = str(value.get("status") or value.get("orderStatus") or "").strip().lower()
    if status in {"expired", "expire", "cancelled", "canceled", "refunded"}:
        return True
    expiry = remail_expiry_timestamp(value)
    return expiry is not None and expiry <= (datetime.now(timezone.utc).timestamp() if now is None else float(now))


@dataclass(frozen=True)
class RemailClient:
    base_url: str = "https://remail.aishop6.com"
    api_key: str = ""
    timeout: float = 20.0
    opener: Any = urlopen

    def _request(self, method: str, path: str, *, query: Mapping[str, Any] | None = None, body: Any = None, idempotency_key: str = "") -> Any:
        key = str(self.api_key or "").strip()
        if not key.startswith("rk-"):
            raise RemailApiError("remail_api_key_missing", "Remail API Key 未配置")
        url = self.base_url.rstrip("/") + "/" + path.lstrip("/")
        if query:
            url += "?" + urlencode({k: v for k, v in query.items() if v not in (None, "")})
        payload = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(url, data=payload, method=method.upper(), headers={
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Origin": self.base_url.rstrip("/"),
            "Referer": self.base_url.rstrip("/") + "/docs",
            **({"Content-Type": "application/json"} if payload is not None else {}),
            **({"Idempotency-Key": str(idempotency_key)} if idempotency_key else {}),
        })
        try:
            with self.opener(request, timeout=max(1.0, float(self.timeout))) as response:
                status = int(getattr(response, "status", 200) or 200)
                raw = response.read()
        except HTTPError as exc:
            status = int(getattr(exc, "code", 0) or 0)
            try:
                raw = exc.read()
            except Exception:
                raw = b""
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeError, ValueError, json.JSONDecodeError):
                value = {}
            if isinstance(value, Mapping):
                raise RemailApiError(str(value.get("code") or "remail_http_error"), str(value.get("message") or f"Remail HTTP {status}"), status=status, request_id=str(value.get("requestId") or "")) from exc
            if status == 403:
                raise RemailApiError("remail_forbidden", "Remail 拒绝访问：请确认填写的是 rk- 开头的 Open API Key，且 Key 已启用并有订单查询权限", status=status) from exc
            raise RemailApiError("remail_http_error", f"Remail HTTP {status}", status=status) from exc
        except Exception as exc:
            raise RemailApiError("remail_network", "Remail 网络请求失败", status=0) from exc
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise RemailApiError("remail_response_invalid", "Remail 返回无法解析", status=status) from exc
        if status >= 400:
            if isinstance(value, Mapping):
                raise RemailApiError(str(value.get("code") or "remail_http_error"), str(value.get("message") or "Remail 请求失败"), status=status, request_id=str(value.get("requestId") or ""))
            if status == 403:
                raise RemailApiError("remail_forbidden", "Remail 拒绝访问：请确认填写的是 rk- 开头的 Open API Key，且 Key 已启用并有订单查询权限", status=status)
            raise RemailApiError("remail_http_error", "Remail 请求失败", status=status)
        return value

    def profile(self) -> Any:
        return self._request("GET", "/v1/open/apikey/profile")

    def projects(self, **query: Any) -> Any:
        return self._request("GET", "/v1/open/projects", query=query)

    def project(self, project_id: int) -> Any:
        return self._request("GET", f"/v1/open/projects/{int(project_id)}")

    def wallet(self) -> Any:
        return self._request("GET", "/v1/open/wallet")

    def orders(self, **query: Any) -> Any:
        query.setdefault("serviceMode", "purchase")
        query.setdefault("limit", 50)
        return self._request("GET", "/v1/open/orders", query=query)

    def order(self, order_no: str) -> Any:
        return self._request("GET", f"/v1/open/orders/{str(order_no).strip()}")

    def create_order(self, project_id: int, email_suffix: str, *, supply: str = "private_first", idempotency_key: str | None = None) -> Any:
        return self._request("POST", "/v1/open/orders", query={"serviceMode": "purchase", "supply": supply}, body={"projectId": int(project_id), "emailSuffix": str(email_suffix)}, idempotency_key=idempotency_key or str(uuid.uuid4()))

    def create_order_batch(self, project_id: int, email_suffix: str, quantity: int, *, supply: str = "private_first", idempotency_key: str | None = None) -> Any:
        return self._request("POST", "/v1/open/orders/batch", query={"serviceMode": "purchase", "supply": supply}, body={"projectId": int(project_id), "emailSuffix": str(email_suffix), "quantity": int(quantity)}, idempotency_key=idempotency_key or str(uuid.uuid4()))

    def pickup(self, email: str, token: str) -> Any:
        # Pickup deliberately has no API-key header; the service token scopes it.
        url = remail_pickup_url(self.base_url.rstrip("/") + "/v1/pickup", email, token)
        request = Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Origin": self.base_url.rstrip("/"),
            "Referer": self.base_url.rstrip("/") + "/docs",
        })
        try:
            with self.opener(request, timeout=max(1.0, float(self.timeout))) as response:
                status = int(getattr(response, "status", 200) or 200)
                value = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise RemailApiError("remail_pickup_http_error", f"Remail 邮件读取 HTTP {int(getattr(exc, 'code', 0) or 0)}", status=int(getattr(exc, "code", 0) or 0)) from exc
        except Exception as exc:
            raise RemailApiError("remail_pickup_network", "Remail 邮件读取网络失败", status=0) from exc
        if status >= 400 or not isinstance(value, Mapping):
            raise RemailApiError("remail_pickup_failed", "Remail 邮件读取失败", status=status)
        return value


__all__ = [
    "RemailApiError", "RemailClient", "remail_pickup_url", "remail_expiry_timestamp",
    "remail_order_expired",
]
