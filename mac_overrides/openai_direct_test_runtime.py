"""Local OpenAI OAuth connectivity tests for mailbox administration.

The test deliberately follows the account-test contract used by sub2api, but
the request is sent by this process to ChatGPT directly. Credentials are read
from a local successful result only and never leave the worker's public result.
"""

from __future__ import annotations

import codecs
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from threading import RLock
import time
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence
import uuid

try:
    from .openai_quota_runtime import (
        OPENAI_CODEX_RESPONSES_URL,
        OPENAI_CODEX_PROBE_USER_AGENT,
        OPENAI_CODEX_PROBE_VERSION,
        OpenAIQuotaError,
        credentials_from_result,
    )
    from .openai_row_status import row_status_key
    from .sub2_runtime import (
        MAX_BATCH_ROWS,
        Sub2SnapshotStore,
        Sub2TestStatus,
        _status,
    )
except ImportError:  # Loaded as a top-level override module by the Mac launcher.
    from openai_quota_runtime import (
        OPENAI_CODEX_RESPONSES_URL,
        OPENAI_CODEX_PROBE_USER_AGENT,
        OPENAI_CODEX_PROBE_VERSION,
        OpenAIQuotaError,
        credentials_from_result,
    )
    from openai_row_status import row_status_key
    from sub2_runtime import (
        MAX_BATCH_ROWS,
        Sub2SnapshotStore,
        Sub2TestStatus,
        _status,
    )


DIRECT_TEST_MODEL = "gpt-5.4"
DIRECT_TEST_TIMEOUT_SECONDS = 30.0
DIRECT_TEST_WORKERS = 2
DIRECT_TEST_ATTEMPTS = 2
DIRECT_TEST_RETRY_DELAY_SECONDS = 0.35
DIRECT_TEST_INSTRUCTIONS = "You are Codex, a coding agent."
DIRECT_TEST_FINGERPRINT = "openai-direct-codex"
MAX_SSE_BYTES = 1024 * 1024


class DirectOpenAIRequestError(ConnectionError):
    """A transport or stream failure that can be retried with a fresh session."""


class DirectOpenAIResponse(Protocol):
    status_code: int

    def iter_content(self, chunk_size: int = 1024) -> Iterable[bytes]: ...

    def close(self) -> None: ...


class DirectOpenAITransport(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
    ) -> DirectOpenAIResponse: ...


class _ManagedResponse:
    def __init__(self, response: Any, session: Any) -> None:
        self._response = response
        self._session = session
        self.status_code = int(getattr(response, "status_code", 0) or 0)

    def iter_content(self, chunk_size: int = 1024) -> Iterable[bytes]:
        try:
            for chunk in self._response.iter_content(chunk_size=chunk_size):
                if chunk:
                    yield chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
        except Exception as exc:
            raise DirectOpenAIRequestError("OpenAI SSE 流连接中断") from exc

    def close(self) -> None:
        try:
            self._response.close()
        finally:
            try:
                self._session.close()
            except Exception:
                pass


class CurlCffiDirectOpenAITransport:
    """Use one fresh curl-cffi browser-like session per request attempt."""

    def __init__(self, *, proxy: str = "") -> None:
        self.proxy = str(proxy or "").strip()

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
    ) -> DirectOpenAIResponse:
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
        try:
            response = session.post(url, **kwargs)
            return _ManagedResponse(response, session)
        except Exception as exc:
            try:
                session.close()
            except Exception:
                pass
            raise DirectOpenAIRequestError("OpenAI 直连请求失败") from exc


@dataclass(frozen=True)
class _StreamResult:
    complete: bool
    failure_code: int | None = None
    failure_text: str = ""


def _status_from_direct_code(
    code: int | None,
    tested_at: int,
    *,
    retryable: bool = False,
) -> Sub2TestStatus:
    if code == 401:
        return _status("unauthorized", 401, "401 Token失效", "OpenAI access token 已失效", tested_at)
    if code == 429:
        return _status("rate_limited", 429, "429 额度受限", "OpenAI 账号额度暂时受限", tested_at)
    if code == 404:
        return _status(
            "http_error",
            404,
            "404 OpenAI 接口不存在或模型不支持",
            "本机直连 OpenAI 返回 HTTP 404",
            tested_at,
        )
    if code is not None and code >= 500:
        return _status(
            "upstream_error",
            code,
            f"OpenAI 服务异常（HTTP {code}）",
            "OpenAI 服务端暂时不可用",
            tested_at,
        )
    if retryable:
        return _status(
            "remote_disconnected",
            code,
            "远端连接中断",
            "OpenAI SSE 流在完成前断开",
            tested_at,
        )
    label = f"HTTP {code}" if code else "OpenAI 测试失败"
    return _status("http_error", code, label, "本机直连 OpenAI 测试失败", tested_at)


def _code_from_text(value: Any) -> int | None:
    text = str(value or "")
    match = re.search(r"\b([45]\d\d)\b", text)
    return int(match.group(1)) if match else None


def _stream_result(response: DirectOpenAIResponse) -> _StreamResult:
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    buffer = ""
    received = 0
    malformed = False
    failure_code: int | None = None
    failure_text = ""
    complete = False

    def consume(line: str) -> None:
        nonlocal malformed, failure_code, failure_text, complete
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
        if not isinstance(event, Mapping):
            malformed = True
            return
        event_type = str(event.get("type") or "")
        if event_type in {"response.completed", "response.done"}:
            complete = True
            return
        if event_type in {"error", "response.failed"}:
            error = event.get("error")
            if isinstance(error, Mapping):
                failure_text = str(error.get("message") or error.get("type") or "OpenAI 返回错误")
                failure_code = _code_from_text(error.get("code")) or _code_from_text(failure_text)
            else:
                failure_text = str(event.get("message") or error or "OpenAI 返回错误")
                failure_code = _code_from_text(event.get("code")) or _code_from_text(failure_text)

    try:
        for chunk in response.iter_content(chunk_size=1024):
            received += len(chunk)
            if received > MAX_SSE_BYTES:
                return _StreamResult(False, failure_text="OpenAI SSE 响应过大")
            buffer += decoder.decode(chunk)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                consume(line)
        buffer += decoder.decode(b"", final=True)
        if buffer:
            consume(buffer)
    except DirectOpenAIRequestError:
        raise
    except Exception as exc:
        raise DirectOpenAIRequestError("OpenAI SSE 流连接中断") from exc

    if complete:
        return _StreamResult(True)
    if failure_text:
        return _StreamResult(False, failure_code, failure_text)
    return _StreamResult(False, failure_code, "SSE 响应格式无效或在完成前结束")


class OpenAIDirectTestClient:
    def __init__(
        self,
        *,
        proxy: str = "",
        transport: DirectOpenAITransport | None = None,
        timeout: float = DIRECT_TEST_TIMEOUT_SECONDS,
        attempts: int = DIRECT_TEST_ATTEMPTS,
        sleep_fn: Callable[[float], None] = time.sleep,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.proxy = str(proxy or "").strip()
        self.transport = transport or CurlCffiDirectOpenAITransport(proxy=self.proxy)
        self.timeout = max(1.0, float(timeout))
        self.attempts = max(1, min(3, int(attempts)))
        self.sleep_fn = sleep_fn
        self.now_fn = now_fn

    @staticmethod
    def _headers(access_token: str, account_id: str) -> dict[str, str]:
        return {
            "authorization": f"Bearer {access_token}",
            "chatgpt-account-id": account_id,
            "content-type": "application/json",
            "accept": "text/event-stream",
            "openai-beta": "responses=experimental",
            "originator": "codex_cli_rs",
            "version": OPENAI_CODEX_PROBE_VERSION,
            "user-agent": OPENAI_CODEX_PROBE_USER_AGENT,
            "x-codex-window-id": str(uuid.uuid4()),
        }

    @staticmethod
    def _payload() -> dict[str, Any]:
        return {
            "model": DIRECT_TEST_MODEL,
            "input": [
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": "hi"}],
                }
            ],
            "stream": True,
            "store": False,
            "instructions": DIRECT_TEST_INSTRUCTIONS,
        }

    def test_document(self, document: Any) -> Sub2TestStatus:
        tested_at = int(self.now_fn())
        try:
            credentials = credentials_from_result(document)
        except OpenAIQuotaError as exc:
            return _status(
                "credentials_missing",
                exc.http_status,
                "缺少 OpenAI OAuth 凭据",
                "本地成功结果没有可用的 OpenAI OAuth 凭据",
                tested_at,
            )

        for attempt in range(self.attempts):
            response: DirectOpenAIResponse | None = None
            retry = False
            try:
                response = self.transport.post(
                    OPENAI_CODEX_RESPONSES_URL,
                    headers=self._headers(credentials.access_token, credentials.account_id),
                    json_body=self._payload(),
                    timeout=self.timeout,
                )
                status_code = int(getattr(response, "status_code", 0) or 0)
                if status_code < 200 or status_code >= 300:
                    if status_code >= 500 and attempt + 1 < self.attempts:
                        retry = True
                    else:
                        return _status_from_direct_code(status_code, tested_at)
                else:
                    stream = _stream_result(response)
                    if stream.complete:
                        return _status("healthy", 200, "200 健康", "本机直连 OpenAI 测试成功", tested_at)
                    if stream.failure_code in {401, 403, 404, 429}:
                        return _status_from_direct_code(stream.failure_code, tested_at)
                    retry = attempt + 1 < self.attempts
                    if not retry:
                        return _status_from_direct_code(None, tested_at, retryable=True)
            except DirectOpenAIRequestError:
                if attempt + 1 >= self.attempts:
                    return _status_from_direct_code(None, tested_at, retryable=True)
                retry = True
            finally:
                if response is not None:
                    response.close()
            if retry:
                self.sleep_fn(DIRECT_TEST_RETRY_DELAY_SECONDS)
        return _status_from_direct_code(None, tested_at, retryable=True)


class OpenAIDirectTestRuntime:
    def __init__(
        self,
        config_loader: Callable[[], Mapping[str, Any]],
        snapshot_path: str | Path,
        *,
        now_fn: Callable[[], float] = time.time,
        client_factory: Callable[..., OpenAIDirectTestClient] | None = None,
    ) -> None:
        self.config_loader = config_loader
        self.now_fn = now_fn
        self.snapshot_store = Sub2SnapshotStore(snapshot_path, now_fn=now_fn)
        self.client_factory = client_factory or OpenAIDirectTestClient
        self._lock = RLock()

    def _client(self, proxy: str) -> OpenAIDirectTestClient:
        return self.client_factory(proxy=proxy, now_fn=self.now_fn)

    @staticmethod
    def _snapshot_key(account_id: Any) -> str:
        value = str(account_id or "").strip()
        return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""

    def status_for(self, account_id: Any) -> dict[str, Any]:
        key = str(account_id or "").strip()
        if not key:
            return {
                "kind": "not_ready",
                "status_code": None,
                "label": "未上传",
                "summary": "该邮箱尚未上传到远端账号服务",
                "tested_at": None,
                "is_error": False,
                "needs_rerun": False,
            }
        status = self.snapshot_store.get(DIRECT_TEST_FINGERPRINT, self._snapshot_key(key))
        if status is None:
            status = self.snapshot_store.get(DIRECT_TEST_FINGERPRINT, key)
        if status is not None:
            return status.public()
        return {
            "kind": "untested",
            "status_code": None,
            "label": "未测试",
            "summary": "",
            "tested_at": None,
            "is_error": False,
            "needs_rerun": False,
        }

    def clear_status(self, account_id: Any) -> None:
        key = str(account_id or "").strip()
        if key:
            self.snapshot_store.discard(DIRECT_TEST_FINGERPRINT, self._snapshot_key(key))
            self.snapshot_store.discard(DIRECT_TEST_FINGERPRINT, key)

    def mark_credentials_refreshed(self, account_id: Any) -> None:
        """Replace a stale failure after a verified credential update."""

        key = str(account_id or "").strip()
        if not key:
            return
        status = _status(
            "untested",
            None,
            "凭据已更新，待复测",
            "重登已成功并更新远端凭据，尚未重新执行 OpenAI 直连测试",
            int(self.now_fn()),
        )
        self.snapshot_store.put_many(
            DIRECT_TEST_FINGERPRINT,
            {self._snapshot_key(key): status},
        )

    def test_rows(
        self,
        rows: Sequence[Mapping[str, Any]],
        proxy: str = "",
    ) -> dict[str, Any]:
        selected = list(rows)
        if not selected:
            return {"ok": False, "code": "openai_test_rows_required", "error": "请先勾选要测试的邮箱"}
        chunks = [
            selected[offset : offset + MAX_BATCH_ROWS]
            for offset in range(0, len(selected), MAX_BATCH_ROWS)
        ]
        aggregate: dict[str, Any] = {
            "ok": True,
            "tested": 0,
            "unlinked": 0,
            "healthy": 0,
            "rate_limited": 0,
            "failed": 0,
            "test_failures": 0,
            "not_ready": 0,
            "results": [],
            "batch_limit": MAX_BATCH_ROWS,
            "batch_count": len(chunks),
            "queued_batches": max(0, len(chunks) - 1),
            "completed_batches": 0,
        }
        for batch_index, chunk in enumerate(chunks, start=1):
            statuses: dict[int, Sub2TestStatus] = {}

            def persist_completed(row: Mapping[str, Any], status: Sub2TestStatus) -> None:
                status_id = str(
                    row.get("openai_status_id")
                    or row.get("sub2api_account_id")
                    or row_status_key(row.get("row_id"))
                    or ""
                ).strip()
                if status_id:
                    self.snapshot_store.put_many(
                        DIRECT_TEST_FINGERPRINT,
                        {self._snapshot_key(status_id): status},
                    )
                callback = row.get("_on_row_completed")
                if callable(callback):
                    try:
                        callback(
                            {
                                "row_id": row.get("row_id"),
                                "line_no": row.get("line_no"),
                                "sub2_status": status.public(),
                            }
                        )
                    except Exception:
                        pass

            ready_rows = [
                (index, row)
                for index, row in enumerate(chunk)
                if isinstance(row.get("document"), Mapping) and bool(row.get("document"))
            ]
            ready_indexes = {index for index, _row in ready_rows}
            for index, row in enumerate(chunk):
                if index in ready_indexes:
                    continue
                status = _status(
                    "not_ready",
                    None,
                    "未上传，无法直连 OpenAI",
                    "该邮箱还没有本地成功结果或 OpenAI OAuth access token",
                    int(self.now_fn()),
                )
                statuses[index] = status
                persist_completed(row, status)
            if ready_rows:
                client = self._client(str(proxy or "").strip())
                with ThreadPoolExecutor(
                    max_workers=min(DIRECT_TEST_WORKERS, len(ready_rows)),
                    thread_name_prefix="openai-direct-test",
                ) as executor:
                    futures = {
                        executor.submit(client.test_document, row.get("document") or {}): (index, row)
                        for index, row in ready_rows
                    }
                    for future in as_completed(futures):
                        index, row = futures[future]
                        try:
                            status = future.result()
                        except Exception:
                            status = _status(
                                "network_error",
                                None,
                                "网络错误",
                                "本机直连 OpenAI 测试网络错误",
                                int(self.now_fn()),
                            )
                        statuses[index] = status
                        persist_completed(row, status)
            for index, row in enumerate(chunk):
                status = statuses[index]
                if index in ready_indexes:
                    aggregate["tested"] += 1
                    if status.kind == "healthy":
                        aggregate["healthy"] += 1
                    elif status.kind == "rate_limited":
                        aggregate["rate_limited"] += 1
                    else:
                        aggregate["failed"] += 1
                    if status.is_test_failure:
                        aggregate["test_failures"] += 1
                else:
                    aggregate["unlinked"] += 1
                    aggregate["not_ready"] += 1
                aggregate["results"].append(
                    {
                        "row_id": row.get("row_id"),
                        "line_no": row.get("line_no"),
                        "sub2_status": status.public(),
                    }
                )
            aggregate["completed_batches"] = batch_index
        return aggregate


__all__ = [
    "DIRECT_TEST_MODEL",
    "DIRECT_TEST_TIMEOUT_SECONDS",
    "CurlCffiDirectOpenAITransport",
    "OpenAIDirectTestClient",
    "OpenAIDirectTestRuntime",
]
