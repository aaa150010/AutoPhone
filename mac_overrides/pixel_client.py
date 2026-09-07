"""PixelAPI HTTP client split out of ``pixel_runtime.py``.

The original module re-exports everything for compatibility; only the
transport and client live here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import json
import time
from pathlib import Path
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

try:
    from .pixel_payload import (
        DEFAULT_PIXEL_PROXY_BASE_URL,
        PIXEL_AUTO_TARGET_IDS,
        PixelProxyError,
        PixelRuntimeError,
        PixelStateError,
        PixelTransport,
        _account_identity_values,
        _clean,
        _public_proxy_value,
        _safe_identifier,
        _safe_int,
        _TARGET_ID_RE,
        _TERMINAL_JOB_STATUSES,
        sanitize_error,
    )
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from pixel_payload import (  # type: ignore[no-redef]
        DEFAULT_PIXEL_PROXY_BASE_URL,
        PIXEL_AUTO_TARGET_IDS,
        PixelProxyError,
        PixelRuntimeError,
        PixelStateError,
        PixelTransport,
        _account_identity_values,
        _clean,
        _public_proxy_value,
        _safe_identifier,
        _safe_int,
        _TARGET_ID_RE,
        _TERMINAL_JOB_STATUSES,
        sanitize_error,
    )


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


__all__ = [
    "PixelProxyClient",
    "PixelTransport",
    "UrllibPixelTransport",
]
