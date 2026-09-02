"""Small, credential-safe client for the Remail Open API."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlencode
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class RemailApiError(RuntimeError):
    def __init__(self, code: str, message: str, *, status: int = 0, request_id: str = "") -> None:
        self.code, self.status, self.request_id = str(code), int(status or 0), str(request_id or "")
        super().__init__(str(message)[:300])


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
        url = self.base_url.rstrip("/") + "/v1/pickup?" + urlencode({"email": email, "token": token})
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


__all__ = ["RemailApiError", "RemailClient"]
