"""Credential-safe SUB2 account connectivity checks and snapshots."""

from __future__ import annotations

import codecs
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import tempfile
from threading import RLock
import time
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence
import urllib.parse


TEST_MODEL = "gpt-5.4"
TEST_MODE = "default"
MAX_BATCH_ROWS = 20
MAX_BATCH_WORKERS = 3
MAX_SSE_BYTES = 1024 * 1024
MAX_SUMMARY_CHARS = 240
TOKEN_TTL_SECONDS = 600


class Sub2ConfigurationError(ValueError):
    """The local SUB2 configuration is incomplete or invalid."""


class Sub2AdminError(RuntimeError):
    """A batch-wide administrator login or authorization failure."""

    def __init__(self, code: str, public_message: str) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


class Sub2RequestTimeout(TimeoutError):
    pass


class Sub2RequestNetworkError(ConnectionError):
    pass


class HttpResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
        stream: bool,
    ) -> HttpResponse: ...


class RequestsTransport:
    """Small requests adapter kept behind a testable transport boundary."""

    def __init__(self, *, proxy: str = "", session: Any = None) -> None:
        self.proxy = str(proxy or "").strip()
        self.session = session

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
        stream: bool,
    ) -> HttpResponse:
        import requests

        sender = self.session.request if self.session is not None else requests.request
        kwargs: dict[str, Any] = {
            "headers": dict(headers),
            "json": dict(json_body),
            "timeout": timeout,
            "stream": stream,
        }
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        try:
            return sender(method, url, **kwargs)
        except requests.Timeout as exc:
            raise Sub2RequestTimeout("SUB2 request timed out") from exc
        except requests.RequestException as exc:
            raise Sub2RequestNetworkError("SUB2 request failed") from exc


def normalize_sub2_base_url(value: Any) -> str:
    """Normalize a service root, UI login URL, or login API URL to its root."""
    raw = str(value or "").strip()
    if not raw:
        raise Sub2ConfigurationError("SUB2 地址未配置")
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as exc:
        raise Sub2ConfigurationError("SUB2 地址格式无效") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise Sub2ConfigurationError("SUB2 地址格式无效")
    if parsed.username or parsed.password:
        raise Sub2ConfigurationError("SUB2 地址不能包含登录凭据")

    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError as exc:
        raise Sub2ConfigurationError("SUB2 地址端口无效") from exc
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    netloc = host if not port or port == default_port else f"{host}:{port}"

    path = re.sub(r"/{2,}", "/", urllib.parse.unquote(parsed.path or ""))
    path = path.rstrip("/")
    for suffix in ("/api/v1/auth/login", "/auth/login", "/login"):
        if path.lower().endswith(suffix):
            path = path[: -len(suffix)].rstrip("/")
            break
    encoded_path = urllib.parse.quote(path, safe="/%:@-._~!$&'()*+,;=")
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, encoded_path, "", "")).rstrip("/")


def service_fingerprint(base_url: Any) -> str:
    normalized = normalize_sub2_base_url(base_url)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _clean_summary(value: Any, secrets: Sequence[Any] = ()) -> str:
    text = str(value or "")
    for secret in sorted({str(item) for item in secrets if str(item or "")}, key=len, reverse=True):
        text = re.sub(re.escape(secret), "********", text, flags=re.IGNORECASE)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1********", text)
    text = re.sub(
        r'(?i)(["\']?(?:access_token|refresh_token|password|token)["\']?\s*[:=]\s*["\']?)[^\s,"\'}]+',
        r"\1********",
        text,
    )
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{12,}(?:\.[A-Za-z0-9_-]+){1,2}\b", "********", text)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_SUMMARY_CHARS]


@dataclass(frozen=True)
class Sub2TestStatus:
    kind: str
    status_code: int | None
    label: str
    summary: str
    tested_at: int | None
    is_error: bool
    needs_rerun: bool
    is_abnormal: bool = False
    is_test_failure: bool = False

    def public(self) -> dict[str, Any]:
        result = asdict(self)
        is_error, is_abnormal, is_test_failure = _status_flags(self.kind, self.status_code)
        result.update(
            {
                "is_error": is_error,
                "is_abnormal": is_abnormal,
                "is_test_failure": is_test_failure,
                "needs_rerun": _status_needs_rerun(self.kind, self.status_code),
            }
        )
        return result


def _status_flags(kind: Any, status_code: int | None) -> tuple[bool, bool, bool]:
    normalized_kind = str(kind or "").strip().lower()
    is_abnormal = status_code == 401 or normalized_kind == "unauthorized"
    is_rate_limited = status_code == 429 or normalized_kind == "rate_limited"
    is_test_failure = (
        not is_abnormal
        and not is_rate_limited
        and normalized_kind not in {"healthy", "unlinked", "not_linked", "untested"}
    )
    return is_abnormal or is_test_failure, is_abnormal, is_test_failure


def _status_needs_rerun(kind: Any, status_code: int | None) -> bool:
    normalized_kind = str(kind or "").strip().lower()
    return status_code in {401, 404} or normalized_kind in {"unauthorized", "not_found"}


def unlinked_status() -> Sub2TestStatus:
    return Sub2TestStatus("unlinked", None, "未关联", "", None, False, False)


def untested_status() -> Sub2TestStatus:
    return Sub2TestStatus("untested", None, "未测试", "", None, False, False)


def _status(
    kind: str,
    status_code: int | None,
    label: str,
    summary: Any,
    tested_at: int,
    *,
    secrets: Sequence[Any] = (),
) -> Sub2TestStatus:
    is_error, is_abnormal, is_test_failure = _status_flags(kind, status_code)
    return Sub2TestStatus(
        kind=kind,
        status_code=status_code,
        label=label,
        summary=_clean_summary(summary, secrets),
        tested_at=int(tested_at),
        is_error=is_error,
        needs_rerun=_status_needs_rerun(kind, status_code),
        is_abnormal=is_abnormal,
        is_test_failure=is_test_failure,
    )


def _status_from_code(code: int | None, summary: Any, tested_at: int, secrets: Sequence[Any]) -> Sub2TestStatus:
    if code == 401:
        return _status(
            "unauthorized",
            401,
            "401 Token失效",
            summary,
            tested_at,
            secrets=secrets,
        )
    if code == 429:
        return _status("rate_limited", 429, "429 额度受限", summary, tested_at, secrets=secrets)
    if code == 404:
        provider_detail = _clean_summary(summary, secrets)
        detail = "SUB2 远端账号不存在或已被删除"
        if provider_detail and provider_detail.lower() not in {
            "account not found",
            "api returned 404: account not found",
        }:
            detail = f"{detail}（服务端：{provider_detail}）"
        detail = f"{detail}；请重新上传或重新关联该账号"
        return _status("not_found", 404, "404 账号不存在", detail, tested_at, secrets=secrets)
    label = f"HTTP {code}" if code else "测试失败"
    return _status("http_error", code, label, summary, tested_at, secrets=secrets)


_ACCOUNT_STATUS_RE = re.compile(
    r"(?i)(?:api\s+returned|returned|http(?:\s+error)?|status|failed)\D{0,12}([1-5]\d\d)\b"
)


def _account_status_code(value: Any) -> int | None:
    text = str(value or "")
    match = _ACCOUNT_STATUS_RE.search(text)
    if match:
        return int(match.group(1))
    lowered = text.lower()
    if "account not found" in lowered:
        return 404
    if "unauthorized" in lowered or "authentication failed" in lowered:
        return 401
    if "too many requests" in lowered or "rate limit" in lowered:
        return 429
    return None


def _event_status_code(event: Mapping[str, Any]) -> int | None:
    candidates: list[Any] = []
    for source in (event, event.get("error"), event.get("data"), event.get("result")):
        if not isinstance(source, Mapping):
            continue
        candidates.extend(
            source.get(key)
            for key in ("status_code", "statusCode", "http_status", "httpStatus", "code")
        )
    for candidate in candidates:
        if isinstance(candidate, bool):
            continue
        try:
            code = int(candidate)
        except (TypeError, ValueError):
            continue
        if 100 <= code <= 599:
            return code
    return None


def _event_failure_text(event: Mapping[str, Any], fallback: str) -> str:
    for value in (event.get("error"), event.get("message"), event.get("text"), event.get("detail")):
        if isinstance(value, Mapping):
            for key in ("message", "error", "detail", "text"):
                if value.get(key) not in (None, ""):
                    return str(value.get(key))
        elif value not in (None, ""):
            return str(value)
    return fallback


def _iter_response_chunks(response: Any) -> Iterable[bytes]:
    if callable(getattr(response, "iter_content", None)):
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                yield chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
        return
    content = getattr(response, "content", b"")
    if not content:
        content = getattr(response, "text", "")
    if content:
        yield content.encode("utf-8") if isinstance(content, str) else bytes(content)


def _parse_sse_response(
    response: Any,
    *,
    tested_at: int,
    secrets: Sequence[Any],
) -> Sub2TestStatus:
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    buffer = ""
    received = 0
    malformed = False
    complete_success = False
    failure_text = ""
    failure_code: int | None = None
    content_parts: list[str] = []

    def consume(line: str) -> None:
        nonlocal malformed, complete_success, failure_text, failure_code
        line = line.rstrip("\r")
        if not line.startswith("data:"):
            return
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            return
        try:
            event = json.loads(payload)
        except (TypeError, ValueError):
            malformed = True
            return
        if not isinstance(event, Mapping) or not str(event.get("type") or ""):
            malformed = True
            return
        event_type = str(event.get("type") or "")
        if event_type == "content" and event.get("text") is not None:
            content_parts.append(str(event.get("text")))
        elif event_type == "status" and event.get("text") is not None:
            content_parts.append(str(event.get("text")))
        elif event_type == "error":
            failure_text = _event_failure_text(event, "测试失败")
            event_code = _event_status_code(event)
            if event_code is not None and not 200 <= event_code < 300:
                failure_code = event_code
        elif event_type == "test_complete":
            event_code = _event_status_code(event)
            if event.get("success") is True and (event_code is None or 200 <= event_code < 300):
                complete_success = True
            else:
                failure_text = _event_failure_text(event, failure_text or "测试失败")
                if event_code is not None and not 200 <= event_code < 300:
                    failure_code = event_code

    try:
        for chunk in _iter_response_chunks(response):
            received += len(chunk)
            if received > MAX_SSE_BYTES:
                return _status("protocol_error", None, "协议错误", "SSE 响应过大", tested_at, secrets=secrets)
            buffer += decoder.decode(chunk)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                consume(line)
        buffer += decoder.decode(b"", final=True)
        if buffer:
            consume(buffer)
    except (Sub2RequestTimeout, TimeoutError, socket.timeout):
        return _status("timeout", None, "超时", "连接测试超时", tested_at, secrets=secrets)
    except (Sub2RequestNetworkError, ConnectionError, OSError):
        return _status("network_error", None, "网络错误", "连接测试网络错误", tested_at, secrets=secrets)

    summary = "".join(content_parts)
    if failure_text:
        return _status_from_code(
            failure_code or _account_status_code(failure_text),
            failure_text,
            tested_at,
            secrets,
        )
    if complete_success:
        return _status("healthy", 200, "200 健康", summary or "测试成功", tested_at, secrets=secrets)
    detail = "SSE 事件格式无效" if malformed else "SSE 缺少完成事件"
    return _status("protocol_error", None, "协议错误", detail, tested_at, secrets=secrets)


class AdminTokenCache:
    def __init__(self, *, now_fn: Callable[[], float] = time.time) -> None:
        self.now_fn = now_fn
        self._items: dict[tuple[str, str], tuple[str, float]] = {}
        self._lock = RLock()
        self.login_lock = RLock()

    def get(self, key: tuple[str, str]) -> str:
        with self._lock:
            token, expires_at = self._items.get(key, ("", 0.0))
            if token and expires_at - self.now_fn() > 30:
                return token
            self._items.pop(key, None)
            return ""

    def put(self, key: tuple[str, str], token: str, ttl: float = TOKEN_TTL_SECONDS) -> None:
        with self._lock:
            self._items[key] = (token, self.now_fn() + max(60.0, float(ttl)))

    def discard(self, key: tuple[str, str]) -> None:
        with self._lock:
            self._items.pop(key, None)


_DEFAULT_TOKEN_CACHE = AdminTokenCache()


class Sub2SnapshotStore:
    """Atomic, token-free status snapshots keyed by service fingerprint and account ID."""

    def __init__(self, path: str | Path, *, now_fn: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.now_fn = now_fn
        self._lock = RLock()
        self._cached_signature: tuple[int, int] | None = None
        self._cached_payload: dict[str, Any] | None = None

    @staticmethod
    def _key(fingerprint: str, account_id: Any) -> str:
        return f"{str(fingerprint).strip()}:{str(account_id).strip()}"

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            stat = self.path.stat()
            signature = (stat.st_mtime_ns, stat.st_size)
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
        body = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        temp_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_name = handle.name
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
            stat = self.path.stat()
            self._cached_signature = (stat.st_mtime_ns, stat.st_size)
            self._cached_payload = dict(payload)
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)

    def get(self, fingerprint: str, account_id: Any) -> Sub2TestStatus | None:
        key = self._key(fingerprint, account_id)
        with self._lock:
            item = self._read_unlocked().get("items", {}).get(key)
        if not isinstance(item, Mapping):
            return None
        try:
            kind = str(item.get("kind") or "protocol_error")
            status_code = int(item["status_code"]) if item.get("status_code") is not None else None
            is_error, is_abnormal, is_test_failure = _status_flags(kind, status_code)
            return Sub2TestStatus(
                kind=kind,
                status_code=status_code,
                label=str(item.get("label") or "协议错误")[:80],
                summary=_clean_summary(item.get("summary")),
                tested_at=int(item["tested_at"]) if item.get("tested_at") is not None else None,
                is_error=is_error,
                needs_rerun=_status_needs_rerun(kind, status_code),
                is_abnormal=is_abnormal,
                is_test_failure=is_test_failure,
            )
        except (TypeError, ValueError):
            return None

    def put_many(self, fingerprint: str, values: Mapping[str, Sub2TestStatus]) -> None:
        if not values:
            return
        with self._lock:
            payload = self._read_unlocked()
            items = payload.setdefault("items", {})
            for account_id, status in values.items():
                items[self._key(fingerprint, account_id)] = status.public()
            payload["version"] = 1
            payload["updated_at"] = int(self.now_fn())
            self._write_unlocked(payload)


def _response_json(response: Any) -> Mapping[str, Any]:
    try:
        payload = response.json()
    except Exception:
        try:
            payload = json.loads(str(getattr(response, "text", "") or ""))
        except Exception:
            payload = {}
    return payload if isinstance(payload, Mapping) else {}


def _close_response(response: Any) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


class Sub2Client:
    def __init__(
        self,
        base_url: Any,
        admin_email: Any,
        admin_password: Any,
        *,
        snapshot_store: Sub2SnapshotStore,
        transport: HttpTransport | None = None,
        token_cache: AdminTokenCache | None = None,
        timeout: float = 30,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.base_url = normalize_sub2_base_url(base_url)
        self.admin_email = str(admin_email or "").strip()
        self.admin_password = str(admin_password or "")
        if not self.admin_email or not self.admin_password:
            raise Sub2ConfigurationError("SUB2 管理员配置不完整")
        self.fingerprint = service_fingerprint(self.base_url)
        self.snapshot_store = snapshot_store
        self.transport = transport or RequestsTransport()
        self.token_cache = token_cache or _DEFAULT_TOKEN_CACHE
        self.timeout = max(1.0, float(timeout))
        self.now_fn = now_fn
        self._login_lock = self.token_cache.login_lock
        self._cache_key = (self.fingerprint, self.admin_email.lower())

    def _login(self) -> str:
        try:
            response = self.transport.request(
                "POST",
                f"{self.base_url}/api/v1/auth/login",
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json_body={"email": self.admin_email, "password": self.admin_password},
                timeout=self.timeout,
                stream=False,
            )
        except (Sub2RequestTimeout, TimeoutError, socket.timeout) as exc:
            raise Sub2AdminError("sub2_admin_timeout", "SUB2 管理员登录超时") from exc
        except (Sub2RequestNetworkError, ConnectionError, OSError) as exc:
            raise Sub2AdminError("sub2_admin_network_error", "SUB2 管理员登录网络错误") from exc

        status_code = int(getattr(response, "status_code", 0) or 0)
        payload = _response_json(response)
        _close_response(response)
        try:
            api_code = int(payload.get("code", status_code or -1))
        except (TypeError, ValueError):
            api_code = -1
        data = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
        token = str(data.get("access_token") or "").strip()
        if status_code not in range(200, 300) or api_code != 0 or not token:
            raise Sub2AdminError("sub2_admin_auth_failed", "SUB2 管理员鉴权失败")
        try:
            ttl = float(data.get("expires_in") or TOKEN_TTL_SECONDS)
        except (TypeError, ValueError):
            ttl = TOKEN_TTL_SECONDS
        self.token_cache.put(self._cache_key, token, ttl)
        return token

    def _admin_token(self, *, force_refresh: bool = False) -> str:
        with self._login_lock:
            if force_refresh:
                self.token_cache.discard(self._cache_key)
            token = self.token_cache.get(self._cache_key)
            return token or self._login()

    def _request_test(self, account_id: str, token: str) -> Any:
        return self.transport.request(
            "POST",
            f"{self.base_url}/api/v1/admin/accounts/{urllib.parse.quote(account_id, safe='')}/test",
            headers={
                "Accept": "text/event-stream",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-Admin-UI-Request": "1",
            },
            json_body={"model_id": TEST_MODEL, "prompt": "", "mode": TEST_MODE},
            timeout=self.timeout,
            stream=True,
        )

    def test_account(self, account_id: Any, *, persist: bool = True) -> Sub2TestStatus:
        remote_id = str(account_id or "").strip()
        if not remote_id:
            return unlinked_status()
        tested_at = int(self.now_fn())
        token = self._admin_token()
        try:
            response = self._request_test(remote_id, token)
            if int(getattr(response, "status_code", 0) or 0) == 401:
                _close_response(response)
                token = self._admin_token(force_refresh=True)
                response = self._request_test(remote_id, token)
                if int(getattr(response, "status_code", 0) or 0) == 401:
                    _close_response(response)
                    raise Sub2AdminError("sub2_admin_auth_failed", "SUB2 管理员鉴权失败")
            if int(getattr(response, "status_code", 0) or 0) == 403:
                _close_response(response)
                raise Sub2AdminError("sub2_admin_auth_failed", "SUB2 管理员鉴权失败")
        except Sub2AdminError:
            raise
        except (Sub2RequestTimeout, TimeoutError, socket.timeout):
            status = _status("timeout", None, "超时", "连接测试超时", tested_at, secrets=(self.admin_password, token))
        except (Sub2RequestNetworkError, ConnectionError, OSError):
            status = _status(
                "network_error",
                None,
                "网络错误",
                "连接测试网络错误",
                tested_at,
                secrets=(self.admin_password, token),
            )
        else:
            try:
                http_status = int(getattr(response, "status_code", 0) or 0)
                if http_status not in range(200, 300):
                    status = _status_from_code(
                        http_status,
                        f"SUB2 测试接口返回 HTTP {http_status}",
                        tested_at,
                        (self.admin_password, token),
                    )
                else:
                    status = _parse_sse_response(
                        response,
                        tested_at=tested_at,
                        secrets=(self.admin_password, token),
                    )
            finally:
                _close_response(response)
        if persist and status.tested_at is not None:
            self.snapshot_store.put_many(self.fingerprint, {remote_id: status})
        return status

    def stored_status(self, account_id: Any) -> Sub2TestStatus:
        remote_id = str(account_id or "").strip()
        if not remote_id:
            return unlinked_status()
        return self.snapshot_store.get(self.fingerprint, remote_id) or untested_status()

    def persist_statuses(self, values: Mapping[str, Sub2TestStatus]) -> None:
        self.snapshot_store.put_many(self.fingerprint, values)


class Sub2BatchService:
    def __init__(self, client: Sub2Client, *, max_workers: int = MAX_BATCH_WORKERS) -> None:
        self.client = client
        self.max_workers = max(1, min(MAX_BATCH_WORKERS, int(max_workers)))

    def _run_chunk(
        self,
        normalized: Sequence[Mapping[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Sub2TestStatus]]:
        """Run one bounded chunk without persisting until the full queue succeeds."""
        statuses: dict[int, Sub2TestStatus] = {}
        persistable: dict[str, Sub2TestStatus] = {}
        linked = [(index, row) for index, row in enumerate(normalized) if row["account_id"]]
        for index, row in enumerate(normalized):
            if not row["account_id"]:
                statuses[index] = unlinked_status()

        admin_error: Sub2AdminError | None = None
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="sub2-test") as executor:
            futures = {
                executor.submit(self.client.test_account, row["account_id"], persist=False): (index, row)
                for index, row in linked
            }
            for future in as_completed(futures):
                index, row = futures[future]
                try:
                    status = future.result()
                except Sub2AdminError as exc:
                    admin_error = admin_error or exc
                    continue
                except Exception:
                    status = _status(
                        "network_error",
                        None,
                        "网络错误",
                        "连接测试网络错误",
                        int(self.client.now_fn()),
                    )
                statuses[index] = status
                persistable[row["account_id"]] = status

        if admin_error is not None:
            return {
                "ok": False,
                "code": admin_error.code,
                "error": admin_error.public_message,
            }, {}

        linked_count = len(linked)
        result = {
            "ok": True,
            "tested": linked_count,
            "unlinked": len(normalized) - linked_count,
            "healthy": sum(1 for index, _row in linked if statuses[index].kind == "healthy"),
            "rate_limited": sum(1 for index, _row in linked if statuses[index].kind == "rate_limited"),
            "failed": sum(
                1
                for index, _row in linked
                if statuses[index].kind not in {"healthy", "rate_limited"}
            ),
            "test_failures": sum(1 for index, _row in linked if statuses[index].is_test_failure),
            "results": [
                {
                    "row_id": row["row_id"],
                    "line_no": row["line_no"],
                    "sub2_status": statuses[index].public(),
                }
                for index, row in enumerate(normalized)
            ],
        }
        return result, persistable

    def test_rows(self, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        selected = list(rows)
        if not selected:
            return {"ok": False, "code": "sub2_rows_required", "error": "请先勾选要测试的邮箱"}

        normalized: list[dict[str, Any]] = []
        for row in selected:
            if not isinstance(row, Mapping):
                return {"ok": False, "code": "sub2_rows_invalid", "error": "批量测试参数无效"}
            try:
                line_no = int(row.get("line_no") or 0)
            except (TypeError, ValueError):
                line_no = 0
            row_id = str(row.get("row_id") or "").strip()
            if line_no <= 0 or not row_id:
                return {"ok": False, "code": "sub2_rows_invalid", "error": "批量测试参数无效"}
            normalized.append(
                {
                    "row_id": row_id,
                    "line_no": line_no,
                    "account_id": str(row.get("sub2api_account_id") or "").strip(),
                }
            )

        chunks = [
            normalized[offset : offset + MAX_BATCH_ROWS]
            for offset in range(0, len(normalized), MAX_BATCH_ROWS)
        ]
        aggregate: dict[str, Any] = {
            "ok": True,
            "tested": 0,
            "unlinked": 0,
            "healthy": 0,
            "rate_limited": 0,
            "failed": 0,
            "test_failures": 0,
            "results": [],
            "batch_limit": MAX_BATCH_ROWS,
            "batch_count": len(chunks),
            "queued_batches": max(0, len(chunks) - 1),
            "completed_batches": 0,
        }
        all_persistable: dict[str, Sub2TestStatus] = {}
        for batch_index, chunk in enumerate(chunks, start=1):
            result, persistable = self._run_chunk(chunk)
            if not result.get("ok"):
                result = dict(result)
                result.update(
                    {
                        "batch_limit": MAX_BATCH_ROWS,
                        "batch_count": len(chunks),
                        "queued_batches": max(0, len(chunks) - batch_index),
                        "completed_batches": batch_index - 1,
                    }
                )
                return result
            for key in ("tested", "unlinked", "healthy", "rate_limited", "failed", "test_failures"):
                aggregate[key] += int(result.get(key) or 0)
            aggregate["results"].extend(result.get("results") or [])
            all_persistable.update(persistable)
            aggregate["completed_batches"] = batch_index

        try:
            self.client.persist_statuses(all_persistable)
        except Exception:
            return {
                "ok": False,
                "code": "sub2_snapshot_persist_failed",
                "error": "SUB2 测试结果保存失败：服务端状态未写入本地快照",
                "batch_limit": MAX_BATCH_ROWS,
                "batch_count": len(chunks),
                "queued_batches": 0,
                "completed_batches": len(chunks),
            }
        return aggregate


class Sub2Runtime:
    """Config-backed integration used by mailbox listing and the batch API."""

    def __init__(
        self,
        config_provider: Callable[[], Mapping[str, Any]],
        snapshot_path: str | Path,
        *,
        transport: HttpTransport | None = None,
        token_cache: AdminTokenCache | None = None,
        timeout: float = 30,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.config_provider = config_provider
        self.snapshot_store = Sub2SnapshotStore(snapshot_path, now_fn=now_fn)
        self.transport = transport
        self.token_cache = token_cache
        self.timeout = timeout
        self.now_fn = now_fn

    def _settings(self) -> tuple[Mapping[str, Any], str]:
        root = self.config_provider()
        root = root if isinstance(root, Mapping) else {}
        nested = root.get("sub2api")
        settings = nested if isinstance(nested, Mapping) else root
        proxy_scope = root.get("proxy_scope") if isinstance(root.get("proxy_scope"), Mapping) else {}
        proxy = str(root.get("proxy") or "").strip() if proxy_scope.get("upload") else ""
        return settings, proxy

    def _client(self) -> Sub2Client:
        settings, proxy = self._settings()
        transport = self.transport or RequestsTransport(proxy=proxy)
        return Sub2Client(
            settings.get("url"),
            settings.get("email"),
            settings.get("password"),
            snapshot_store=self.snapshot_store,
            transport=transport,
            token_cache=self.token_cache,
            timeout=self.timeout,
            now_fn=self.now_fn,
        )

    def status_for(self, account_id: Any) -> dict[str, Any]:
        remote_id = str(account_id or "").strip()
        if not remote_id:
            return unlinked_status().public()
        try:
            settings, _proxy = self._settings()
            fingerprint = service_fingerprint(settings.get("url"))
        except Sub2ConfigurationError:
            return untested_status().public()
        status = self.snapshot_store.get(fingerprint, remote_id) or untested_status()
        return status.public()

    def test_rows(self, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        try:
            client = self._client()
        except Sub2ConfigurationError as exc:
            return {"ok": False, "code": "sub2_config_invalid", "error": str(exc)}
        return Sub2BatchService(client).test_rows(rows)


__all__ = [
    "AdminTokenCache",
    "MAX_BATCH_ROWS",
    "MAX_BATCH_WORKERS",
    "RequestsTransport",
    "Sub2AdminError",
    "Sub2BatchService",
    "Sub2Client",
    "Sub2ConfigurationError",
    "Sub2RequestNetworkError",
    "Sub2RequestTimeout",
    "Sub2Runtime",
    "Sub2SnapshotStore",
    "Sub2TestStatus",
    "normalize_sub2_base_url",
    "service_fingerprint",
    "unlinked_status",
    "untested_status",
]
