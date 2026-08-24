"""RoxyBrowser API client for isolated Free runs.

This module owns the Roxy API transport and profile lifecycle adapter.  The
registration runner keeps importing these symbols from its legacy module so
existing callers and test monkeypatches remain compatible.
"""

from __future__ import annotations

from dataclasses import dataclass
import random
import re
import time
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urljoin, urlsplit

import requests

try:
    from .free_register_common import FreeRegisterError, clean, mask_proxy, safe_log_message
    from .free_roxy_lifecycle import (
        MANAGED_WINDOW_PREFIX,
        MANAGED_WINDOW_REMARK,
        RoxyCleanupStore,
        RoxyLifecycle,
    )
except ImportError:
    from free_register_common import (  # type: ignore[no-redef]
        FreeRegisterError,
        clean,
        mask_proxy,
        safe_log_message,
    )
    from free_roxy_lifecycle import (  # type: ignore[no-redef]
        MANAGED_WINDOW_PREFIX,
        MANAGED_WINDOW_REMARK,
        RoxyCleanupStore,
        RoxyLifecycle,
    )


@dataclass(slots=True)
class RoxyOpenResult:
    profile_id: str
    raw: dict[str, Any]
    debugger_address: str | None = None
    webdriver_url: str | None = None
    ws_endpoint: str | None = None
    created_by_run: bool = False
    workspace_id: str = ""
    window_name: str = ""
    window_remark: str = ""
    driver_path: str | None = None
    connection_reused: bool = False
    headless: bool | None = None

    def __post_init__(self) -> None:
        """Normalize the driver path from either open or connection payload."""
        if self.driver_path:
            return
        raw = self.raw if isinstance(self.raw, Mapping) else {}
        candidates: list[Any] = [raw]
        data = raw.get("data") if isinstance(raw, Mapping) else None
        if isinstance(data, Mapping):
            candidates.insert(0, data)
        for row in candidates:
            value = _first(row, [
                ("driver",), ("driverPath",), ("driver_path",),
                ("chromedriver",), ("chromeDriver",), ("chrome_driver",),
            ])
            if value:
                self.driver_path = value
                break


def _dig(payload: Mapping[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _first(payload: Mapping[str, Any], paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        value = _dig(payload, *path)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _roxy_id(value: Any) -> str | int:
    text = str(value or "").strip()
    return int(text) if text.isdigit() else text


def _bool_config(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() not in {"", "0", "false", "no", "off", "none", "null"}


def proxy_to_roxy_info(proxy: str, check_channel: str = "IPRust.io") -> dict[str, Any]:
    parsed = urlsplit(str(proxy or "").strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        detail = (
            "RoxyBrowser 不支持 SOCKS4；SOCKS4 仍可用于纯协议注册"
            if scheme == "socks4" else f"RoxyBrowser 不支持当前代理协议：{scheme or '-'}"
        )
        raise FreeRegisterError(
            "free_roxy_proxy", "配置 RoxyBrowser 代理",
            detail,
            retryable=False,
            error_code="free_roxy_socks4_unsupported" if scheme == "socks4" else "free_roxy_proxy_scheme_unsupported",
            provider_code="unsupported_proxy_scheme",
            action_hint="改用 HTTP、HTTPS、SOCKS5 或 SOCKS5H 代理" if scheme == "socks4" else "检查代理协议与 RoxyBrowser 支持范围",
        )
    if not parsed.hostname or not parsed.port:
        raise FreeRegisterError("free_roxy_proxy", "配置 RoxyBrowser 代理", "RoxyBrowser 代理缺少主机或端口", retryable=False)
    protocol = {"http": "HTTP", "https": "HTTPS", "socks5": "SOCKS5", "socks5h": "SOCKS5"}[scheme]
    result: dict[str, Any] = {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV4",
        "protocol": protocol,
        "host": parsed.hostname,
        "port": str(parsed.port),
        "checkChannel": str(check_channel or "IPRust.io"),
    }
    if parsed.username:
        result["proxyUserName"] = unquote(parsed.username)
    if parsed.password:
        result["proxyPassword"] = unquote(parsed.password)
    return result


class RoxyBrowserClient:
    def __init__(self, config: Mapping[str, Any], *, session: Any | None = None, log_fn: Callable[[str, str], None] | None = None) -> None:
        self.config = dict(config or {})
        self.api_base = str(self.config.get("api_base") or "http://127.0.0.1:50000").rstrip("/")
        self.http = session or requests.Session()
        if hasattr(self.http, "trust_env"):
            self.http.trust_env = False
        self.log_fn = log_fn
        token = str(self.config.get("api_key") or "").strip()
        self.http.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        if token:
            self.http.headers.update({"token": token, "Authorization": f"Bearer {token}"})
        self.last_created_metadata: dict[str, str] = {}

    def _log(self, value: str, level: str = "info") -> None:
        if callable(self.log_fn):
            self.log_fn(safe_log_message(value), level)

    @staticmethod
    def _retryable(exc: BaseException) -> bool:
        text = str(exc or "").lower()
        return any(value in text for value in ("timeout", "connection", "temporarily", "http 429", "http 500", "http 502", "http 503", "http 504"))

    @staticmethod
    def _safe_response_code(value: Any) -> str:
        """Keep short provider identifiers while rejecting response text/URLs."""
        if isinstance(value, (Mapping, list, tuple, set)):
            return ""
        candidate = safe_log_message(value).strip()
        if not candidate or len(candidate) > 120 or "://" in candidate:
            return ""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}", candidate):
            return ""
        return candidate

    @classmethod
    def _response_error_codes(cls, payload: Any) -> tuple[str, str]:
        """Return ``(provider_code, server_error_code)`` from a JSON error."""
        if not isinstance(payload, Mapping):
            return "", ""
        sources: list[Mapping[str, Any]] = []

        def add(source: Any) -> None:
            if isinstance(source, Mapping) and source not in sources:
                sources.append(source)

        add(payload.get("error"))
        add(payload)
        data = payload.get("data")
        add(data)
        if isinstance(data, Mapping):
            add(data.get("error"))

        provider_code = ""
        server_error_code = ""
        for source in sources:
            if not provider_code:
                for key in ("provider_code", "providerCode", "provider"):
                    provider_code = cls._safe_response_code(source.get(key))
                    if provider_code:
                        break
            if not server_error_code:
                for key in ("error_code", "errorCode", "code", "type", "reason"):
                    candidate = cls._safe_response_code(source.get(key))
                    # Numeric HTTP/status values do not add diagnostic value.
                    if candidate and not (candidate.isdigit() and int(candidate) in {0, 200, 201, 202, 204}):
                        server_error_code = candidate
                        break
        if not provider_code:
            provider_code = server_error_code
        return provider_code, server_error_code

    @staticmethod
    def _connection_info_soft_failure(exc: BaseException) -> bool:
        """Only hide a transport race while checking an asynchronously opened Profile."""
        transport_names = {
            "connectionerror", "connectionrefusederror", "connectionreseterror",
            "connecttimeout", "readtimeout", "timeout", "timeouterror",
            "sockettimeout", "proxyerror", "sslerror", "gaierror",
        }
        pending: list[BaseException] = [exc]
        seen: set[int] = set()
        saw_transport = False
        while pending:
            current = pending.pop(0)
            if id(current) in seen:
                continue
            seen.add(id(current))
            status = getattr(current, "provider_status", None)
            if status is None:
                status = getattr(getattr(current, "response", None), "status_code", None)
            try:
                if status is not None and 100 <= int(status) <= 599:
                    return False
            except (TypeError, ValueError):
                return False
            if isinstance(current, (requests.exceptions.Timeout, requests.exceptions.ConnectionError, TimeoutError, ConnectionError)):
                saw_transport = True
            elif type(current).__name__.casefold() in transport_names:
                saw_transport = True
            cause = getattr(current, "__cause__", None)
            context = getattr(current, "__context__", None)
            if isinstance(cause, BaseException):
                pending.append(cause)
            if isinstance(context, BaseException):
                pending.append(context)
        return saw_transport

    @classmethod
    def _open_reconciliation_candidate(cls, exc: BaseException) -> bool:
        """Return whether an ``/browser/open`` error may have launched a window.

        Roxy starts a Profile before writing the HTTP response in some
        versions.  A timeout therefore is ambiguous: retrying ``/browser/open``
        can create a second window.  Walk the exception chain because
        :meth:`request` deliberately wraps transport errors in a structured
        ``FreeRegisterError`` while retaining the original cause.
        """
        pending: list[BaseException] = [exc]
        seen: set[int] = set()
        chain: list[BaseException] = []
        while pending:
            current = pending.pop(0)
            marker = id(current)
            if marker in seen:
                continue
            seen.add(marker)
            chain.append(current)
            cause = getattr(current, "__cause__", None)
            context = getattr(current, "__context__", None)
            if isinstance(cause, BaseException):
                pending.append(cause)
            if isinstance(context, BaseException):
                pending.append(context)

        # A concrete 4xx response means Roxy definitely answered the open
        # request.  In particular, 429 is a quota/rate-limit failure rather
        # than an ambiguous local timeout, so connection reconciliation would
        # only hide the provider's real node and diagnostics.
        for current in chain:
            status = getattr(current, "provider_status", None)
            if status is None:
                status = getattr(getattr(current, "response", None), "status_code", None)
            try:
                status_code = int(str(status).strip())
            except (TypeError, ValueError):
                continue
            if 400 <= status_code < 500:
                return False

        return any(cls._retryable(current) for current in chain)

    @staticmethod
    def _open_error_type(exc: BaseException) -> str:
        """Return a credential-free transport type from a wrapped exception."""
        current: BaseException | None = exc
        seen: set[int] = set()
        while isinstance(current, BaseException) and id(current) not in seen:
            seen.add(id(current))
            if not isinstance(current, FreeRegisterError):
                return type(current).__name__
            cause = getattr(current, "__cause__", None)
            context = getattr(current, "__context__", None)
            current = cause if isinstance(cause, BaseException) else context
        return type(exc).__name__

    @staticmethod
    def _open_reconciliation_failure(
        exc: BaseException,
        wait_budget: float,
    ) -> FreeRegisterError:
        """Build a stable open-stage error after connection reconciliation.

        Keep the public message useful without copying an upstream exception
        (which can contain a URL or an authorization detail).  The exception
        type and provider status are enough to diagnose the local API race;
        the original exception remains available as ``__cause__``.
        """
        provider_status = getattr(exc, "provider_status", None)
        provider_code = getattr(exc, "provider_code", None)
        original_error_code = getattr(exc, "error_code", None)
        original_diagnostic = getattr(exc, "diagnostic", None)
        original_action_hint = getattr(exc, "action_hint", None)
        error_type = RoxyBrowserClient._open_error_type(exc)
        status_text = f" HTTP {provider_status}" if provider_status else ""
        reconciliation_diagnostic = (
            f"open_request={error_type}; "
            f"connection_info_reconciliation_timeout={int(max(1, wait_budget))}s"
        )
        diagnostic = "; ".join(
            value for value in (str(original_diagnostic or "").strip(), reconciliation_diagnostic)
            if value
        )
        return FreeRegisterError(
            "free_roxy_open",
            "打开 RoxyBrowser 环境",
            f"RoxyBrowser /browser/open 请求异常（{error_type}{status_text}），"
            f"connection_info 在 {int(max(1, wait_budget))} 秒内未就绪",
            retryable=True,
            provider_status=provider_status,
            error_code=(
                original_error_code
                if original_error_code and original_error_code != "free_roxy_api_failed"
                else "free_roxy_connection_timeout"
            ),
            provider_code=provider_code,
            diagnostic=diagnostic,
            action_hint=(
                original_action_hint
                or "检查 RoxyBrowser API 状态和 Profile 启动耗时，确认 connection_info 可访问后重试"
            ),
        )

    @staticmethod
    def _quota_failure(
        message: Any,
        *,
        provider_status: int | None = None,
        provider_code: str | None = None,
    ) -> FreeRegisterError | None:
        text = clean(message, 240)
        lowered = text.casefold()
        markers = (
            "窗口额度", "窗口數量", "窗口数量", "额度不足", "quota", "window limit",
            "too many windows", "maximum number of windows", "browser limit",
        )
        if text and any(marker.casefold() in lowered for marker in markers):
            return FreeRegisterError(
                "free_roxy_window_quota_exhausted",
                "RoxyBrowser 窗口额度",
                "RoxyBrowser 当前窗口额度不足，请先释放遗留窗口后重试",
                retryable=False,
                provider_status=provider_status,
                error_code="roxy_window_quota_exhausted",
                provider_code=provider_code,
            )
        return None

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        target = urljoin(self.api_base + "/", str(path or "").lstrip("/"))
        default_attempts = 1 if str(path).rstrip("/").endswith("/create") else int(self.config.get("api_retries") or 3)
        attempts = max(1, int(default_attempts if retries is None else retries))
        request_timeout = (
            max(5.0, float(self.config.get("selenium_timeout") or 90))
            if timeout is None else max(0.05, float(timeout))
        )
        delay = float(self.config.get("api_retry_delay") or 2.0)
        last: BaseException | None = None
        for attempt in range(1, max(1, attempts) + 1):
            remaining = None if deadline is None else float(deadline) - time.monotonic()
            if remaining is not None and remaining <= 0:
                break
            current_timeout = request_timeout if remaining is None else max(0.001, min(request_timeout, remaining))
            try:
                response = self.http.request(
                    str(method or "POST").upper(),
                    target,
                    json=dict(body or {}) if body is not None else None,
                    params=dict(params or {}) if params else None,
                    timeout=current_timeout,
                )
                status = int(getattr(response, "status_code", 0) or 0)
                if not 200 <= status < 300:
                    try:
                        error_payload = response.json()
                    except Exception:
                        error_payload = None
                    provider_code, server_error_code = self._response_error_codes(error_payload)
                    quota_message = error_payload if isinstance(error_payload, Mapping) else getattr(response, "text", "")
                    quota_error = self._quota_failure(quota_message, provider_status=status, provider_code=provider_code)
                    if quota_error is not None:
                        raise quota_error
                    diagnostic_parts = [f"provider_status={status}"]
                    if provider_code:
                        diagnostic_parts.append(f"provider_code={provider_code}")
                    if server_error_code and server_error_code != provider_code:
                        diagnostic_parts.append(f"error_code={server_error_code}")
                    raise FreeRegisterError(
                        "free_roxy_api", "调用 RoxyBrowser API", f"RoxyBrowser API 返回 HTTP {status}",
                        retryable=status in {429, 500, 502, 503, 504}, provider_status=status,
                        error_code="free_roxy_api_http",
                        provider_code=provider_code,
                        diagnostic="; ".join(diagnostic_parts),
                    )
                try:
                    payload = response.json()
                except Exception as exc:
                    raise FreeRegisterError("free_roxy_api", "调用 RoxyBrowser API", "RoxyBrowser API 未返回 JSON") from exc
                if not isinstance(payload, Mapping):
                    raise FreeRegisterError("free_roxy_api", "调用 RoxyBrowser API", "RoxyBrowser API 响应格式无效")
                code = payload.get("code")
                if code not in (None, 0, 200, "0", "200") and payload.get("ok") is not True and payload.get("success") is not True:
                    provider_code, _server_error_code = self._response_error_codes(payload)
                    message_value = payload.get("message") or payload.get("msg")
                    message = safe_log_message(clean(message_value, 200)) if isinstance(message_value, str) else ""
                    quota_error = self._quota_failure(message or payload, provider_code=provider_code)
                    if quota_error is not None:
                        raise quota_error
                    diagnostic = "api_response=error"
                    if provider_code:
                        diagnostic += f"; provider_code={provider_code}"
                    if _server_error_code and _server_error_code != provider_code:
                        diagnostic += f"; error_code={_server_error_code}"
                    raise FreeRegisterError(
                        "free_roxy_api",
                        "调用 RoxyBrowser API",
                        message or "RoxyBrowser API 返回失败",
                        error_code="free_roxy_api_response",
                        provider_code=provider_code,
                        diagnostic=diagnostic,
                    )
                if attempt > 1:
                    self._log(f"[RoxyBrowser/free_roxy_api] API 第 {attempt} 次请求成功")
                return dict(payload)
            except Exception as exc:
                last = exc
                if attempt >= attempts or not self._retryable(exc):
                    if isinstance(exc, FreeRegisterError):
                        raise
                    raise FreeRegisterError(
                        "free_roxy_api", "调用 RoxyBrowser API", f"RoxyBrowser API 请求异常（{type(exc).__name__}）"
                    ) from exc
                retry_delay = delay * attempt
                if deadline is not None:
                    retry_delay = min(retry_delay, max(0.0, float(deadline) - time.monotonic()))
                if retry_delay <= 0:
                    break
                time.sleep(retry_delay)
        if isinstance(last, FreeRegisterError):
            raise last
        raise FreeRegisterError(
            "free_roxy_api", "调用 RoxyBrowser API",
            f"RoxyBrowser API 请求失败（{type(last).__name__ if last is not None else 'Timeout'}）",
        ) from last

    @staticmethod
    def _workspace_items(payload: Mapping[str, Any]) -> list[dict[str, str]]:
        data = payload.get("data") if isinstance(payload.get("data"), Mapping) else payload
        rows = data.get("rows") or data.get("list") or data.get("records") if isinstance(data, Mapping) else []
        output: list[dict[str, str]] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, Mapping):
                continue
            workspace_id = str(row.get("id") or row.get("workspaceId") or "")
            workspace_name = str(row.get("workspaceName") or row.get("name") or workspace_id)
            projects = row.get("project_details") or row.get("projectDetails") or row.get("projects") or []
            if isinstance(projects, list) and projects:
                for project in projects:
                    if not isinstance(project, Mapping):
                        continue
                    project_id = str(project.get("projectId") or project.get("id") or "")
                    project_name = str(project.get("projectName") or project.get("name") or project_id)
                    output.append({"workspace_id": workspace_id, "workspace_name": workspace_name, "project_id": project_id, "project_name": project_name, "label": f"{workspace_name} / {project_name}"})
            elif workspace_id:
                output.append({"workspace_id": workspace_id, "workspace_name": workspace_name, "project_id": "", "project_name": "", "label": workspace_name})
        return output

    def list_workspaces(self) -> list[dict[str, str]]:
        return self._workspace_items(self.request("GET", str(self.config.get("workspace_list_path") or "/browser/workspace")))

    @staticmethod
    def _profile_items(payload: Mapping[str, Any]) -> list[dict[str, str]]:
        raw_data = payload.get("data")
        data = raw_data if isinstance(raw_data, (Mapping, list)) else payload
        if isinstance(data, list):
            rows = data
        else:
            rows = data.get("rows") or data.get("list") or data.get("records")
        result: list[dict[str, str]] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, Mapping):
                continue
            profile_id = _first(row, [("dirId",), ("profileId",), ("id",)])
            if not profile_id:
                continue
            result.append({
                "profile_id": profile_id,
                "workspace_id": _first(row, [("workspaceId",), ("workspace_id",)]),
                "window_name": _first(row, [("windowName",), ("name",)]),
                "window_remark": _first(row, [("windowRemark",), ("remark",)]),
            })
        return result

    def list_profiles(self, workspace_id: str | int | None = None) -> list[dict[str, str]]:
        params: dict[str, Any] = {"page_index": 1, "page_size": 100}
        if workspace_id not in (None, ""):
            params["workspaceId"] = _roxy_id(workspace_id)
        payload = self.request("GET", str(self.config.get("list_path") or "/browser/list"), params=params)
        return self._profile_items(payload)

    def find_owned_profiles(self, *, task_id: str = "", batch_id: str = "") -> list[dict[str, str]]:
        """Find only profiles carrying this runtime's ownership marker.

        This is used after a create timeout: Roxy can allocate the profile
        before the HTTP response reaches us.  A missing marker is never
        treated as owned and is therefore never deleted automatically.
        """
        rows = self.list_profiles(self.config.get("workspace_id"))
        task = str(task_id or "").strip()
        batch = str(batch_id or "").strip()
        result: list[dict[str, str]] = []
        for row in rows:
            if str(row.get("window_remark") or "") != MANAGED_WINDOW_REMARK:
                continue
            name = str(row.get("window_name") or "")
            # The window name contains the task id when available, otherwise
            # the batch id. Prefer the most specific identity so a timeout
            # from one task cannot adopt another task's managed profile.
            if task and task not in name:
                continue
            if not task and batch and batch not in name:
                continue
            result.append(row)
        return result

    def create_profile(self, proxy: str, *, batch_id: str = "", task_id: str = "") -> str:
        choices = [str(value) for value in self.config.get("os_choices") or ["Windows", "macOS"]]
        prefix = str(self.config.get("profile_name_prefix") or "rb")
        profile_name = f"{prefix}-{int(time.time() * 1000)}-{random.randrange(65536):04x}" if bool(self.config.get("random_profile_name", True)) else prefix
        # windowRemark is the ownership boundary used by stale cleanup.  The
        # profile name remains configurable (the default rb prefix is kept for
        # compatibility), while the task suffix makes timeout recovery exact.
        owner_suffix = str(task_id or batch_id or "").strip()
        window_name = f"{MANAGED_WINDOW_PREFIX}{owner_suffix[:48]}" if owner_suffix else f"{MANAGED_WINDOW_PREFIX}{profile_name}"
        lifecycle_store_path = self.config.get("lifecycle_store_path")
        if lifecycle_store_path and task_id:
            try:
                RoxyCleanupStore(str(lifecycle_store_path)).reserve_intent(
                    task_id,
                    workspace_id=self.config.get("workspace_id"),
                    batch_id=batch_id,
                    task_id=task_id,
                    window_name=window_name,
                    window_remark=MANAGED_WINDOW_REMARK,
                )
            except Exception as exc:
                self._log(f"Roxy 创建归属记录失败（{type(exc).__name__}）", "warn")
        body: dict[str, Any] = {
            "workspaceId": _roxy_id(self.config.get("workspace_id")),
            "projectId": _roxy_id(self.config.get("project_id")),
            "name": profile_name,
            "os": random.choice(choices or ["Windows", "macOS"]) if bool(self.config.get("random_os", True)) else (choices[0] if choices else "Windows"),
            "proxyInfo": proxy_to_roxy_info(proxy, str(self.config.get("proxy_check_channel") or "IPRust.io")),
            "windowName": window_name,
            "windowRemark": MANAGED_WINDOW_REMARK,
        }
        if not body["projectId"]:
            body.pop("projectId")
        try:
            payload = self.request("POST", str(self.config.get("create_path") or "/browser/create"), body=body)
        except Exception:
            # The API may have allocated a profile before its response timed
            # out.  Keep enough ownership metadata for a later list scan.
            self.last_created_metadata = {
                "workspace_id": str(self.config.get("workspace_id") or ""),
                "window_name": window_name,
                "window_remark": MANAGED_WINDOW_REMARK,
                "batch_id": str(batch_id or ""),
                "task_id": str(task_id or ""),
            }
            raise
        # Persist the ownership marker even when the API responds with a
        # malformed success payload. A later list/connection reconciliation
        # can then identify the profile without relying on an in-memory ID.
        self.last_created_metadata = {
            "workspace_id": str(self.config.get("workspace_id") or ""),
            "window_name": window_name,
            "window_remark": MANAGED_WINDOW_REMARK,
            "batch_id": str(batch_id or ""),
            "task_id": str(task_id or ""),
        }
        profile_id = _first(payload, [
            ("id",), ("dirId",), ("profileId",), ("data", "id"), ("data", "dirId"), ("data", "profileId"),
        ])
        if not profile_id:
            raise FreeRegisterError("free_roxy_create", "创建 RoxyBrowser 环境", "创建成功但未返回 Profile ID")
        self.last_created_metadata = {
            "profile_id": profile_id,
            "workspace_id": str(self.config.get("workspace_id") or ""),
            "window_name": window_name,
            "window_remark": MANAGED_WINDOW_REMARK,
            "batch_id": str(batch_id or ""),
            "task_id": str(task_id or ""),
        }
        self._log(
            f"[创建 RoxyBrowser 环境/free_roxy_create] Profile={profile_id} "
            f"proxy={mask_proxy(proxy)} launch=deferred"
        )
        return profile_id

    def _connection_result(self, profile_id: str, payload: Mapping[str, Any]) -> RoxyOpenResult | None:
        data = payload.get("data") if isinstance(payload.get("data"), (Mapping, list)) else payload
        rows = data if isinstance(data, list) else [data]
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            candidate = _first(row, [("dirId",), ("profileId",), ("id",), ("windowId",)])
            if candidate and str(candidate) != str(profile_id):
                continue
            debugger = _first(row, [
                ("debuggerAddress",), ("debuggingPortUrl",), ("http",), ("httpEndpoint",),
            ])
            port = _first(row, [("debuggingPort",), ("port",)])
            if not debugger and port.isdigit():
                debugger = f"127.0.0.1:{port}"
            webdriver_url = _first(row, [("webdriver",), ("webdriverUrl",), ("selenium",)]) or None
            ws_endpoint = _first(row, [("ws",), ("wsEndpoint",), ("ws_endpoint",), ("debuggerWsUrl",)]) or None
            driver_path = _first(row, [
                ("driver",), ("driverPath",), ("driver_path",),
                ("chromedriver",), ("chromeDriver",), ("chrome_driver",),
            ]) or None
            if not debugger and ws_endpoint:
                parsed = urlsplit(ws_endpoint)
                if parsed.hostname and parsed.port:
                    debugger = f"{parsed.hostname}:{parsed.port}"
            if not debugger and not webdriver_url and not ws_endpoint:
                continue
            if debugger:
                debugger = debugger.replace("http://", "").replace("https://", "").split("/", 1)[0].strip()
            return RoxyOpenResult(
                str(profile_id), dict(payload), debugger or None, webdriver_url, ws_endpoint,
                driver_path=driver_path,
                created_by_run=True,
                workspace_id=str(self.config.get("workspace_id") or ""),
                window_name=str(self.last_created_metadata.get("window_name") or ""),
                window_remark=str(self.last_created_metadata.get("window_remark") or ""),
            )
        return None

    def connection_info(
        self,
        profile_id: str,
        *,
        workspace_id: Any | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        deadline: float | None = None,
    ) -> RoxyOpenResult | None:
        params: dict[str, Any] = {"dirIds": str(_roxy_id(profile_id))}
        if workspace_id not in (None, ""):
            params["workspaceId"] = _roxy_id(workspace_id)
        payload = self.request(
            "GET",
            str(self.config.get("connection_info_path") or "/browser/connection_info"),
            params=params,
            timeout=timeout,
            retries=retries,
            deadline=deadline,
        )
        return self._connection_result(profile_id, payload)

    def list_connections(self, workspace_id: Any | None = None) -> list[dict[str, str]]:
        """Return all currently connected Roxy windows for ownership recovery.

        A timed-out create can leave a connected window that is absent from
        ``/browser/list``.  The connection endpoint accepts an omitted
        ``dirIds`` filter and is therefore the only reliable source for that
        ghost-window reconciliation.  Only safe ownership metadata is
        returned; connection URLs and debugger addresses are intentionally
        not persisted by the cleanup journal.
        """
        params: dict[str, Any] = {}
        if workspace_id not in (None, ""):
            params["workspaceId"] = _roxy_id(workspace_id)
        payload = self.request(
            "GET",
            str(self.config.get("connection_info_path") or "/browser/connection_info"),
            params=params,
        )
        data = payload.get("data") if isinstance(payload, Mapping) else None
        rows = data if isinstance(data, list) else []
        result: list[dict[str, str]] = []
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            profile_id = _first(row, [("dirId",), ("profileId",), ("id",), ("windowId",)])
            if not profile_id:
                continue
            result.append({
                "profile_id": profile_id,
                "workspace_id": _first(row, [("workspaceId",), ("workspace_id",)])
                    or str(workspace_id or self.config.get("workspace_id") or ""),
                "window_name": _first(row, [("windowName",), ("window_name",), ("name",)]),
                "window_remark": _first(row, [("windowRemark",), ("window_remark",), ("remark",)]),
            })
        return result

    def open_profile(self, profile_id: str) -> RoxyOpenResult:
        headless = _bool_config(self.config.get("headless"), True)
        try:
            wait_budget = float(self.config.get("open_connection_timeout") or 15.0)
        except (TypeError, ValueError):
            wait_budget = 15.0
        # The Roxy API is local. Keep reconciliation bounded even when the
        # general Selenium timeout is configured to several minutes.
        wait_budget = max(0.1, min(15.0, wait_budget))
        deadline = time.monotonic() + wait_budget

        def remaining() -> float:
            return max(0.0, deadline - time.monotonic())

        # Roxy may finish an asynchronous create/open before returning the
        # create response.  Adopt that connection first so a second
        # /browser/open call cannot briefly foreground another window.
        try:
            already_open = self.connection_info(
                profile_id,
                timeout=min(2.0, max(0.05, remaining())),
                retries=1,
                deadline=deadline,
            )
        except Exception as exc:
            if not self._connection_info_soft_failure(exc):
                raise
            already_open = None
        if already_open is not None:
            already_open.connection_reused = True
            already_open.headless = headless
            self._log(
                f"[打开 RoxyBrowser 环境/free_roxy_open] Profile={profile_id} "
                f"已由 connection_info 对账，跳过重复打开 headless={headless}"
            )
            return already_open
        body = {
            "workspaceId": _roxy_id(self.config.get("workspace_id")),
            "dirId": _roxy_id(profile_id),
            # Roxy opens asynchronously. The connection_info reconciliation
            # below handles the short race without forcing a second window.
            "forceOpen": False,
            "headless": headless,
        }
        self._log(
            f"[打开 RoxyBrowser 环境/free_roxy_open] Profile={profile_id} "
            f"headless={headless} forceOpen=False"
        )
        if remaining() <= 0:
            raise FreeRegisterError(
                "free_roxy_open", "打开 RoxyBrowser 环境",
                "RoxyBrowser connection_info 对账在打开前已超过 15 秒预算",
                retryable=True,
                error_code="free_roxy_connection_timeout",
            )
        open_error: BaseException | None = None
        try:
            payload = self.request(
                "POST",
                str(self.config.get("open_path") or "/browser/open"),
                body=body,
                timeout=min(5.0, max(0.05, remaining())),
                retries=1,
                deadline=deadline,
            )
        except Exception as exc:
            # A Roxy API timeout is ambiguous: the Profile may already be
            # running.  Reconcile the same dirId before surfacing an error;
            # never issue a second /browser/open request.
            if not self._open_reconciliation_candidate(exc):
                raise
            open_error = exc
            error_type = self._open_error_type(exc)
            self._log(
                f"[打开 RoxyBrowser 环境/free_roxy_open] /browser/open 请求异常（{error_type}），"
                f"转入 connection_info 对账，剩余约 {int(max(0, remaining()))} 秒",
                "warn",
            )
        else:
            opened = self._connection_result(profile_id, payload)
            if opened is not None:
                opened.headless = headless
                return opened
        # Some Roxy versions return success before the CDP endpoint exists;
        # reconcile the same dirId instead of creating another Profile/window.
        # Match the mature runner's async-open window: never call /browser/open
        # again while the same dirId is still coming up.
        while remaining() > 0:
            try:
                opened = self.connection_info(
                    profile_id,
                    timeout=min(1.0, max(0.05, remaining())),
                    retries=1,
                    deadline=deadline,
                )
            except Exception as exc:
                if not self._connection_info_soft_failure(exc):
                    raise
                opened = None
            if opened is not None:
                opened.headless = headless
                # The connection was adopted from the reconciliation endpoint,
                # including the case where /browser/open itself timed out.
                opened.connection_reused = True
                return opened
            sleep_for = min(0.5, remaining())
            if sleep_for > 0:
                time.sleep(sleep_for)
        if open_error is not None:
            raise self._open_reconciliation_failure(open_error, wait_budget) from open_error
        raise FreeRegisterError(
            "free_roxy_open",
            "打开 RoxyBrowser 环境",
            "RoxyBrowser 打开成功但未返回 Selenium/CDP 连接地址，connection_info 也未就绪",
            retryable=True,
            error_code="free_roxy_connection_timeout",
            diagnostic=(
                f"open_request=success_without_connection; "
                f"connection_info_reconciliation_timeout={int(max(1, wait_budget))}s"
            ),
            action_hint="检查 RoxyBrowser connection_info 接口和 Profile 启动状态后重试",
        )

    def close_profile(self, profile_id: str, *, workspace_id: Any | None = None) -> None:
        workspace = self.config.get("workspace_id") if workspace_id in (None, "") else workspace_id
        body = {"workspaceId": _roxy_id(workspace), "dirId": _roxy_id(profile_id)}
        self.request("POST", str(self.config.get("close_path") or "/browser/close"), body=body)

    def delete_profile(self, profile_id: str, *, workspace_id: Any | None = None) -> None:
        workspace = self.config.get("workspace_id") if workspace_id in (None, "") else workspace_id
        body = {"workspaceId": _roxy_id(workspace), "dirIds": [_roxy_id(profile_id)]}
        self.request("POST", str(self.config.get("delete_path") or "/browser/delete"), body=body)

    def cleanup(self, opened: RoxyOpenResult | None) -> bool:
        if opened is None or not opened.profile_id:
            return True
        if bool(self.config.get("keep_browser_open", False)):
            self._log(f"[清理 RoxyBrowser 环境/free_roxy_cleanup] 调试保留 Profile={opened.profile_id}，跳过关闭和删除", "warn")
            return True
        lifecycle_path = self.config.get("lifecycle_store_path")
        if lifecycle_path:
            store = RoxyCleanupStore(str(lifecycle_path))
            record = store.upsert(
                opened.profile_id,
                workspace_id=opened.workspace_id or self.config.get("workspace_id"),
                batch_id=self.last_created_metadata.get("batch_id"),
                task_id=self.last_created_metadata.get("task_id"),
                window_name=opened.window_name or self.last_created_metadata.get("window_name"),
                window_remark=opened.window_remark or self.last_created_metadata.get("window_remark") or MANAGED_WINDOW_REMARK,
                state="opened",
            )
            lifecycle = RoxyLifecycle(
                self,
                store,
                log_fn=self._log,
                verify_timeout=float(self.config.get("cleanup_verify_timeout") or 8),
                verify_interval=float(self.config.get("cleanup_verify_interval") or 0.25),
                retries=int(self.config.get("api_retries") or 3),
            )
            should_delete = bool(self.config.get("one_profile_per_account", True)) and bool(self.config.get("delete_profile_after_run", True)) and bool(opened.created_by_run)
            return lifecycle.cleanup(record, delete_profile=should_delete)
        completed = True
        try:
            self.close_profile(opened.profile_id)
        except Exception as exc:
            completed = False
            self._log(f"[清理 RoxyBrowser 环境/free_roxy_cleanup] 关闭失败（{type(exc).__name__}）", "warn")
        if bool(self.config.get("one_profile_per_account", True)) and bool(self.config.get("delete_profile_after_run", True)) and opened.created_by_run:
            try:
                self.delete_profile(opened.profile_id)
            except Exception as exc:
                completed = False
                self._log(f"[清理 RoxyBrowser 环境/free_roxy_cleanup] 删除失败（{type(exc).__name__}）", "warn")
        return completed
