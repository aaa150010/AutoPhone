"""Credential-safe, persistent NV account imports for completed run batches."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import threading
import time
from typing import Any, Protocol
import urllib.error
import urllib.parse
import urllib.request
import uuid


DEFAULT_NV_ENDPOINT = "https://nvtokens.com/api/inventory/cards/import"
DEFAULT_NV_SCHEMA_URL = "https://nvtokens.com/api/inventory/cards/import/schema"
NV_USER_AGENT = "curl/8.7.1"
OUTBOX_VERSION = 1
MAX_BATCH_SIZE = 100
NV_NODE_CODE = "nv_import"
NV_NODE_LABEL = "NV 账号导入"
_EMAIL_RE = re.compile(
    r"(?i)^[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)
_SENSITIVE_RE = re.compile(
    r"(?i)(access[_ -]?token|refresh[_ -]?token|authorization|api[_ -]?key|x-api-key)"
    r"(?:\\?[\"'])?\s*[:=]\s*(?:\\?[\"'])?[^\s,;}\]\"']+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_identifier(value: Any, maximum: int = 128) -> str:
    text = _clean(value)
    if re.fullmatch(rf"[A-Za-z0-9._:-]{{1,{maximum}}}", text):
        return text
    if not text:
        return ""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _validated_nv_url(value: Any, label: str) -> str:
    url = _clean(value)
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        parsed = None
        hostname = None
    if (
        parsed is None
        or parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise NvConfigurationError(f"{label}未配置或格式无效")

    normalized_host = hostname.lower().rstrip(".")
    is_loopback = normalized_host == "localhost"
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(normalized_host).is_loopback
        except ValueError:
            is_loopback = False
    if parsed.scheme.lower() != "https" and not is_loopback:
        raise NvConfigurationError(f"{label}必须使用 HTTPS（仅本机回环地址可使用 HTTP）")
    return parsed._replace(scheme=parsed.scheme.lower()).geturl()


def sanitize_error(value: Any, secrets: Iterable[Any] = (), maximum: int = 500) -> str:
    if isinstance(value, Mapping):
        value = value.get("detail") or value.get("message") or value.get("error") or "请求失败"
    text = str(value or "")[:8192]
    for secret in sorted({_clean(item) for item in secrets if _clean(item)}, key=len, reverse=True):
        text = re.sub(re.escape(secret), "********", text, flags=re.IGNORECASE)
    text = _SENSITIVE_RE.sub(lambda match: f"{match.group(1)}=********", text)
    text = _BEARER_RE.sub("Bearer ********", text)
    text = _JWT_RE.sub("********", text)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:maximum]


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _value_sources(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    sources: list[Mapping[str, Any]] = [value]
    wrapped = value.get("result")
    if isinstance(wrapped, Mapping):
        sources.insert(0, wrapped)
    for source in tuple(sources):
        credentials = source.get("credentials")
        if isinstance(credentials, Mapping):
            sources.insert(0, credentials)
        local_oauth = source.get("local_oauth")
        if isinstance(local_oauth, Mapping):
            nested = local_oauth.get("credentials")
            if isinstance(nested, Mapping):
                sources.insert(0, nested)
            sources.insert(0, local_oauth)
    return sources


def _first_value(sources: Iterable[Mapping[str, Any]], key: str) -> Any:
    for source in sources:
        if source.get(key) not in (None, ""):
            return source.get(key)
    return None


def build_nv_card(success_result: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(success_result, Mapping):
        raise NvSourceError("成功结果格式无效")
    status = _clean(success_result.get("status")).lower()
    if status and status not in {"success", "ok", "uploaded"}:
        raise NvSourceError("结果不是成功状态")
    sources = _value_sources(success_result)
    email = _clean(_first_value(sources, "email")).lower()
    access_token = _clean(_first_value(sources, "access_token"))
    refresh_token = _clean(_first_value(sources, "refresh_token"))
    if not _EMAIL_RE.fullmatch(email):
        raise NvSourceError("成功结果缺少有效邮箱")
    if not access_token or not refresh_token:
        raise NvSourceError("成功结果中的 OAuth 凭据不完整")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "email": email,
        "type": "codex",
    }


class NvRuntimeError(RuntimeError):
    def __init__(
        self,
        public_message: str,
        *,
        error_code: str,
        status_code: int = 500,
        provider_code: str = "",
        retryable: bool = False,
        accepted: int | None = None,
        needs_confirmation: bool = False,
    ) -> None:
        self.public_message = sanitize_error(public_message)
        self.error_code = _safe_identifier(error_code, 80) or "nv_import_failed"
        self.status_code = status_code
        self.provider_code = _safe_identifier(provider_code, 80)
        self.retryable = bool(retryable)
        self.accepted = max(_safe_int(accepted), 0) if accepted is not None else None
        self.needs_confirmation = bool(needs_confirmation)
        super().__init__(self.public_message)

    def failure(self) -> dict[str, Any]:
        return {
            "node_code": NV_NODE_CODE,
            "node_label": NV_NODE_LABEL,
            "error_code": self.error_code,
            "provider_code": self.provider_code,
            "public_message": self.public_message,
            "technical_summary": self.public_message,
            "retryable": self.retryable,
            "http_status": self.status_code if 100 <= self.status_code <= 599 else None,
        }


class NvSourceError(NvRuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="nv_source_unavailable", status_code=422)


class NvConfigurationError(NvRuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="nv_configuration_invalid", status_code=503)


class NvNetworkError(ConnectionError):
    pass


class NvTransport(Protocol):
    def request(
        self,
        endpoint: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout: float,
        proxy: str,
    ) -> tuple[int, Mapping[str, Any]]: ...


class UrllibNvTransport:
    def request(
        self,
        endpoint: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout: float,
        proxy: str,
    ) -> tuple[int, Mapping[str, Any]]:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(endpoint, data=body, headers=dict(headers), method="POST")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                status = int(getattr(response, "status", 200))
                raw = response.read(65536)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            raw = exc.read(65536)
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            raise NvNetworkError("NV 请求网络连接失败") from exc
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeError, json.JSONDecodeError):
            parsed = {}
        return status, parsed if isinstance(parsed, Mapping) else {}


class NvImportClient:
    def __init__(
        self,
        config_provider: Callable[[], Mapping[str, Any]],
        *,
        transport: NvTransport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        max_attempts: int = 3,
    ) -> None:
        self.config_provider = config_provider
        self.transport = transport or UrllibNvTransport()
        self.sleeper = sleeper
        self.max_attempts = max(1, min(3, _safe_int(max_attempts, 3)))

    def _config(self) -> tuple[str, str, str]:
        root = self.config_provider()
        nv = root.get("nv_import") if isinstance(root, Mapping) else None
        nv = nv if isinstance(nv, Mapping) else {}
        endpoint = _validated_nv_url(nv.get("endpoint") or DEFAULT_NV_ENDPOINT, "NV 导入地址")
        _validated_nv_url(nv.get("schema_url") or DEFAULT_NV_SCHEMA_URL, "NV 协议地址")
        api_key = _clean(nv.get("api_key"))
        if not api_key or api_key == "********":
            raise NvConfigurationError("NV API Key 未配置")
        proxy_scope = root.get("proxy_scope") if isinstance(root.get("proxy_scope"), Mapping) else {}
        proxy = _clean(root.get("proxy")) if bool(proxy_scope.get("upload")) else ""
        return endpoint, api_key, proxy

    def configured(self) -> bool:
        try:
            self._config()
            return True
        except NvConfigurationError:
            return False

    @staticmethod
    def _provider_detail(response: Mapping[str, Any], secrets: Iterable[Any]) -> tuple[str, str]:
        provider_code = _safe_identifier(response.get("code") or response.get("error_code"), 80)
        detail = sanitize_error(
            response.get("message") or response.get("detail") or response.get("error"),
            secrets,
        )
        return provider_code, detail

    def upload(self, cards: list[dict[str, str]]) -> Mapping[str, Any]:
        if not cards or len(cards) > MAX_BATCH_SIZE:
            raise NvSourceError("NV 单批账号数必须在 1 至 100 之间")
        endpoint, api_key, proxy = self._config()
        secrets = [api_key]
        for card in cards:
            secrets.extend((card.get("access_token"), card.get("refresh_token")))
        last_error: NvRuntimeError | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                status, response = self.transport.request(
                    endpoint,
                    headers={
                        "content-type": "application/json",
                        "user-agent": NV_USER_AGENT,
                        "x-api-key": api_key,
                    },
                    payload={"data": cards},
                    timeout=60.0,
                    proxy=proxy,
                )
            except NvNetworkError:
                last_error = NvRuntimeError(
                    "NV 导入网络连接失败",
                    error_code="nv_network_error",
                    status_code=503,
                    retryable=True,
                )
            else:
                provider_code, detail = self._provider_detail(response, secrets)
                if 200 <= status < 300:
                    counts: dict[str, int] = {}
                    invalid_counts: list[str] = []
                    for key in ("accepted", "created"):
                        if key not in response:
                            continue
                        raw_count = response.get(key)
                        try:
                            if isinstance(raw_count, bool):
                                raise ValueError
                            if isinstance(raw_count, float) and not raw_count.is_integer():
                                raise ValueError
                            parsed_count = int(raw_count)
                            if parsed_count < 0:
                                raise ValueError
                        except (TypeError, ValueError, OverflowError):
                            invalid_counts.append(key)
                        else:
                            counts[key] = parsed_count

                    false_flags = [
                        key for key in ("ok", "success")
                        if response.get(key) is False or _clean(response.get(key)).lower() == "false"
                    ]
                    failed_count: int | None = None
                    invalid_failed_count = False
                    if "failed" in response:
                        raw_failed = response.get("failed")
                        try:
                            if isinstance(raw_failed, bool):
                                raise ValueError
                            if isinstance(raw_failed, float) and not raw_failed.is_integer():
                                raise ValueError
                            failed_count = int(raw_failed)
                            if failed_count < 0:
                                raise ValueError
                        except (TypeError, ValueError, OverflowError):
                            invalid_failed_count = True
                            failed_count = None

                    reported_accepted = max(counts.values()) if counts else None
                    provider_reported_failure = bool(false_flags) or invalid_failed_count or bool(
                        failed_count is not None and failed_count > 0
                    )
                    if provider_reported_failure:
                        needs_confirmation = bool(
                            (reported_accepted or 0) > 0
                            or invalid_failed_count
                            or (failed_count is not None and 0 < failed_count < len(cards))
                        )
                        failure_signals = [f"{key}=false" for key in false_flags]
                        if "failed" in response:
                            failure_signals.append(
                                f"failed={failed_count}" if failed_count is not None else "failed=invalid"
                            )
                        signal = ", ".join(failure_signals)
                        raise NvRuntimeError(
                            f"NV 导入 HTTP {status}：服务端明确报告失败"
                            f"（{signal or 'failure'}）{f'：{detail}' if detail else ''}",
                            error_code="nv_provider_reported_failure",
                            status_code=status,
                            provider_code=provider_code,
                            retryable=not needs_confirmation,
                            accepted=reported_accepted,
                            needs_confirmation=needs_confirmation,
                        )

                    count_mismatch = bool(invalid_counts) or any(
                        value != len(cards) for value in counts.values()
                    )
                    if count_mismatch:
                        needs_confirmation = bool(invalid_counts) or bool((reported_accepted or 0) > 0)
                        if invalid_counts:
                            count_detail = f"字段 {', '.join(invalid_counts)} 不是有效的非负整数"
                            error_code = "nv_response_count_mismatch"
                        else:
                            count_detail = f"服务端确认接收 {reported_accepted}/{len(cards)} 个账号"
                            error_code = (
                                "nv_partial_import"
                                if reported_accepted is not None and reported_accepted < len(cards)
                                else "nv_response_count_mismatch"
                            )
                        raise NvRuntimeError(
                            f"NV 导入 HTTP {status}：{count_detail}",
                            error_code=error_code,
                            status_code=status,
                            provider_code=provider_code,
                            retryable=reported_accepted == 0 and not invalid_counts,
                            accepted=reported_accepted,
                            needs_confirmation=needs_confirmation,
                        )
                    return {
                        "status": status,
                        "provider_code": provider_code,
                        "accepted": reported_accepted if reported_accepted is not None else len(cards),
                    }
                retryable = status == 429 or 500 <= status <= 599
                if status == 429:
                    error_code = "nv_rate_limited"
                elif status in {401, 403}:
                    error_code = "nv_auth_rejected"
                elif 400 <= status <= 499:
                    error_code = "nv_request_rejected"
                else:
                    error_code = "nv_provider_error"
                last_error = NvRuntimeError(
                    f"NV 导入 HTTP {status}：{detail or '服务端未返回错误详情'}",
                    error_code=error_code,
                    status_code=status,
                    provider_code=provider_code,
                    retryable=retryable,
                )
            if last_error.retryable and attempt < self.max_attempts:
                self.sleeper(float(2 ** (attempt - 1)))
                continue
            raise last_error
        raise last_error or NvRuntimeError(
            "NV 导入失败：服务端未返回错误详情",
            error_code="nv_import_failed",
            status_code=502,
        )


class NvUploadQueue:
    def __init__(
        self,
        data_dir: str | Path,
        client: NvImportClient,
        *,
        outbox_path: str | Path | None = None,
        now: Callable[[], float] = time.time,
        log_fn: Callable[[str, str], None] | None = None,
        auto_start: bool = True,
        resume_pending: bool = True,
    ) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.outbox_path = Path(outbox_path).resolve() if outbox_path else self.data_dir / "nv_upload_records.json"
        self.client = client
        self.now = now
        self.log_fn = log_fn
        self._lock = threading.RLock()
        self._work: queue.Queue[str] = queue.Queue()
        self._scheduled: set[str] = set()
        self._active: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._store = self._load()
        self._revision = max((_safe_int(item.get("updated_at")) for item in self._store["records"]), default=0)
        if resume_pending:
            for record in self._store["records"]:
                if _clean(record.get("status")) in {"queued", "processing"}:
                    self._schedule(_clean(record.get("record_id")))
        if auto_start:
            self.start()

    def _timestamp(self) -> int:
        return int(self.now())

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.outbox_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {"version": OUTBOX_VERSION, "records": []}
        records = value.get("records") if isinstance(value, Mapping) else None
        return {
            "version": OUTBOX_VERSION,
            "records": [copy.deepcopy(item) for item in records or [] if isinstance(item, Mapping)],
        }

    def _save_locked(self) -> None:
        _atomic_write_json(self.outbox_path, self._store)
        self._revision += 1

    def _record_locked(self, record_id: str) -> dict[str, Any]:
        for record in self._store["records"]:
            if record.get("record_id") == record_id:
                return record
        raise NvRuntimeError("NV 上传记录不存在", error_code="nv_record_not_found", status_code=404)

    def _relative_source(self, value: str | Path) -> str:
        path = Path(value)
        if not path.is_absolute():
            path = self.data_dir / path
        try:
            return path.resolve().relative_to(self.data_dir).as_posix()
        except ValueError:
            raise NvSourceError("成功结果文件必须位于本地数据目录") from None

    def _source_paths(self, record: Mapping[str, Any]) -> list[Path]:
        values = record.get("result_files")
        if not isinstance(values, list) or not values:
            values = [record.get("result_file")]
        result: list[Path] = []
        for value in values:
            relative = _clean(value)
            if not relative:
                raise NvSourceError("成功结果文件位置无效")
            path = (self.data_dir / relative).resolve()
            try:
                path.relative_to(self.data_dir)
            except ValueError:
                raise NvSourceError("成功结果文件位置无效") from None
            result.append(path)
        return result

    def _read_cards(self, record: Mapping[str, Any]) -> tuple[list[dict[str, str]], tuple[str, ...]]:
        cards: list[dict[str, str]] = []
        secrets: list[str] = []
        for path in self._source_paths(record):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                raise NvSourceError("成功结果文件不存在") from None
            except (OSError, UnicodeError, json.JSONDecodeError):
                raise NvSourceError("成功结果文件格式无效") from None
            card = build_nv_card(raw)
            cards.append(card)
            secrets.extend((card["access_token"], card["refresh_token"]))
        if len(cards) > MAX_BATCH_SIZE:
            raise NvSourceError("NV 单批账号数不能超过 100")
        return cards, tuple(secrets)

    @staticmethod
    def _public_failure(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, Mapping):
            return None
        return {
            "node_code": NV_NODE_CODE,
            "node_label": NV_NODE_LABEL,
            "error_code": _safe_identifier(value.get("error_code"), 80) or "nv_import_failed",
            "provider_code": _safe_identifier(value.get("provider_code"), 80),
            "public_message": sanitize_error(value.get("public_message")),
            "technical_summary": sanitize_error(value.get("technical_summary")),
            "retryable": bool(value.get("retryable")),
            "http_status": _safe_int(value.get("http_status")) or None,
        }

    def _public(self, record: Mapping[str, Any]) -> dict[str, Any]:
        paths_available = False
        try:
            paths = self._source_paths(record)
            paths_available = bool(paths) and all(path.is_file() for path in paths)
        except NvRuntimeError:
            pass
        task_ids = [_safe_identifier(value) for value in record.get("task_ids") or [] if _safe_identifier(value)]
        status = _clean(record.get("status")) or "queued"
        source_count = max(_safe_int(record.get("source_count")), len(task_ids), 1)
        accepted = min(max(_safe_int(record.get("accepted")), 0), source_count)
        needs_confirmation = bool(record.get("needs_confirmation")) or status == "partial" or (
            accepted > 0 and status not in {"success", "queued", "processing"}
        )
        return {
            "record_id": _safe_identifier(record.get("record_id")),
            "batch_id": _safe_identifier(record.get("batch_id"), 80),
            "batch_started_at": max(_safe_int(record.get("batch_started_at")), 0),
            "task_ids": task_ids,
            "source_count": source_count,
            "status": status,
            "stage": "import",
            "attempts": max(_safe_int(record.get("attempts")), 0),
            "accepted": accepted,
            "needs_confirmation": needs_confirmation,
            "source_available": paths_available,
            "can_retry": paths_available and not needs_confirmation and status in {"failed", "source_unavailable"},
            "error": sanitize_error(record.get("error")),
            "failure": self._public_failure(record.get("failure")),
            "created_at": max(_safe_int(record.get("created_at")), 0),
            "updated_at": max(_safe_int(record.get("updated_at")), 0),
        }

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public(record) for record in reversed(self._store["records"])]

    def batches(self) -> list[dict[str, Any]]:
        with self._lock:
            grouped: dict[str, list[Mapping[str, Any]]] = {}
            for record in self._store["records"]:
                grouped.setdefault(_safe_identifier(record.get("batch_id"), 80) or "legacy", []).append(record)
            result = []
            for batch_id, records in grouped.items():
                total = sum(max(_safe_int(item.get("source_count")), 1) for item in records)
                counts = {"queued": 0, "processing": 0, "success": 0, "failed": 0, "partial": 0}
                updated_at = 0
                started_at = 0
                for item in records:
                    count = max(_safe_int(item.get("source_count")), 1)
                    status = _clean(item.get("status"))
                    category = status if status in counts else "failed"
                    counts[category] += count
                    updated_at = max(updated_at, _safe_int(item.get("updated_at")))
                    started_at = max(started_at, _safe_int(item.get("batch_started_at")), _safe_int(item.get("created_at")))
                status = (
                    "processing" if counts["queued"] or counts["processing"]
                    else "success" if counts["success"] == total
                    else "partial" if counts["partial"] or counts["success"]
                    else "failed"
                )
                result.append({
                    "batch_id": batch_id,
                    "batch_started_at": started_at,
                    "updated_at": updated_at,
                    "status": status,
                    "source": {"total": total, **counts},
                })
            return sorted(result, key=lambda item: (item["batch_started_at"], item["updated_at"]), reverse=True)

    def overview(self) -> dict[str, Any]:
        batches = self.batches()
        with self._lock:
            alive_workers = int(bool(self._thread is not None and self._thread.is_alive()))
            active = len(self._active)
            pending = max(0, len(self._scheduled) - active)
            return {
                "revision": self._revision,
                "configured": self.client.configured(),
                "queue": {
                    "active": active,
                    "pending": pending,
                    "alive": bool(alive_workers),
                    "configured_workers": 1,
                    "alive_workers": alive_workers,
                    "active_workers": active,
                    "pending_records": pending,
                    "running_records": active,
                },
                "current_batch": next((item for item in batches if item["status"] == "processing"), batches[0] if batches else None),
                "batch_count": len(batches),
            }

    def _enqueue_rows(
        self,
        batch_id: Any,
        rows: list[tuple[str, str]],
        *,
        batch_started_at: Any,
        identity_rows: list[tuple[str, str]] | None = None,
        source_error: NvRuntimeError | None = None,
    ) -> dict[str, Any]:
        task_ids = [item[0] for item in rows]
        result_files = [item[1] for item in rows]
        identity = "\n".join(
            f"{task_id}\0{path}"
            for task_id, path in (identity_rows if identity_rows is not None else rows)
        )
        record_id = hashlib.sha256(
            f"{_safe_identifier(batch_id, 80)}\0{identity}".encode()
        ).hexdigest()[:24]
        now = self._timestamp()
        created = False
        with self._lock:
            try:
                record = self._record_locked(record_id)
            except NvRuntimeError:
                created = True
                record = {
                    "record_id": record_id,
                    "batch_id": _safe_identifier(batch_id, 80),
                    "batch_started_at": max(_safe_int(batch_started_at), 0),
                    "task_ids": task_ids,
                    "result_file": result_files[0],
                    "result_files": result_files,
                    "source_count": len(rows),
                    "status": "source_unavailable" if source_error else "queued",
                    "attempts": 0,
                    "accepted": 0,
                    "needs_confirmation": False,
                    "error": source_error.public_message if source_error else "",
                    "failure": source_error.failure() if source_error else None,
                    "created_at": now,
                    "updated_at": now,
                }
                self._store["records"].append(record)
                self._save_locked()
            status = _clean(record.get("status"))
            public = self._public(record)
        if source_error is None and (created or status in {"queued", "processing"}):
            self._schedule(record_id)
        return public

    def enqueue_batch(
        self,
        batch_id: Any,
        sources: Iterable[Mapping[str, Any] | tuple[Any, str | Path]],
        *,
        batch_started_at: Any = 0,
    ) -> list[dict[str, Any]]:
        normalized: list[tuple[str, str]] = []
        for source in sources:
            if isinstance(source, Mapping):
                task_id, result_file = source.get("task_id"), source.get("result_file")
            else:
                try:
                    task_id, result_file = source
                except (TypeError, ValueError):
                    raise NvSourceError("NV 批量来源参数无效") from None
            safe_task_id = _safe_identifier(task_id)
            if not safe_task_id:
                raise NvSourceError("NV 批量来源缺少任务 ID")
            normalized.append((safe_task_id, self._relative_source(result_file)))
        records: list[dict[str, Any]] = []
        for offset in range(0, len(normalized), MAX_BATCH_SIZE):
            chunk = normalized[offset:offset + MAX_BATCH_SIZE]
            valid_rows: list[tuple[str, str]] = []
            rejected_rows: list[tuple[tuple[str, str], NvRuntimeError]] = []
            for row in chunk:
                try:
                    self._read_cards({"result_files": [row[1]]})
                except NvRuntimeError as exc:
                    rejected_rows.append((row, exc))
                else:
                    valid_rows.append(row)
            for row, exc in rejected_rows:
                records.append(
                    self._enqueue_rows(
                        batch_id,
                        [row],
                        batch_started_at=batch_started_at,
                        source_error=exc,
                    )
                )
            if valid_rows:
                records.append(
                    self._enqueue_rows(
                        batch_id,
                        valid_rows,
                        batch_started_at=batch_started_at,
                        identity_rows=chunk,
                    )
                )
        return records

    def retry(self, record_id: Any) -> dict[str, Any]:
        identifier = _safe_identifier(record_id)
        with self._lock:
            record = self._record_locked(identifier)
            if not self._public(record)["can_retry"]:
                raise NvRuntimeError("所选 NV 记录不可重试", error_code="nv_retry_unavailable", status_code=409)
            record.update(status="queued", error="", failure=None, needs_confirmation=False, updated_at=self._timestamp())
            self._save_locked()
            public = self._public(record)
        self._schedule(identifier)
        return public

    def _schedule(self, record_id: str) -> None:
        if not record_id:
            return
        with self._lock:
            if record_id in self._scheduled:
                return
            self._scheduled.add(record_id)
            self._work.put(record_id)

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._worker, name="nv-upload-worker", daemon=True)
            self._thread.start()

    def stop(self, *, wait: bool = True, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if wait and thread is not None:
            thread.join(timeout=max(0.0, timeout))

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                record_id = self._work.get(timeout=0.2)
            except queue.Empty:
                continue
            with self._lock:
                self._active.add(record_id)
            try:
                self._process_isolated(record_id)
            finally:
                with self._lock:
                    self._active.discard(record_id)
                    self._scheduled.discard(record_id)
                self._work.task_done()

    def process_next(self) -> bool:
        try:
            record_id = self._work.get_nowait()
        except queue.Empty:
            return False
        with self._lock:
            self._active.add(record_id)
        try:
            self._process_isolated(record_id)
        finally:
            with self._lock:
                self._active.discard(record_id)
                self._scheduled.discard(record_id)
            self._work.task_done()
        return True

    def _emit(self, message: str, level: str) -> None:
        if self.log_fn is None:
            return
        try:
            self.log_fn(sanitize_error(message), level)
        except Exception:
            pass

    def _process_isolated(self, record_id: str) -> None:
        try:
            self._process(record_id)
        except Exception:
            exc = NvRuntimeError(
                "NV 导入失败：队列处理异常，后续记录将继续处理",
                error_code="nv_worker_unexpected",
                status_code=500,
            )
            try:
                with self._lock:
                    record = self._record_locked(record_id)
                    source_count = max(_safe_int(record.get("source_count")), 1)
                    accepted = min(max(_safe_int(record.get("accepted")), 0), source_count)
                    needs_confirmation = accepted > 0
                    record.update(
                        status="partial" if needs_confirmation else "failed",
                        accepted=accepted,
                        needs_confirmation=needs_confirmation,
                        error=exc.public_message,
                        failure=exc.failure(),
                        updated_at=self._timestamp(),
                    )
                    self._save_locked()
            except Exception:
                pass
            self._emit(
                f"NV 上传记录 {record_id} 失败 [{NV_NODE_LABEL}/{NV_NODE_CODE}]：{exc.public_message}",
                "error",
            )

    def _process(self, record_id: str) -> None:
        with self._lock:
            record = self._record_locked(record_id)
            record.update(
                status="processing",
                attempts=max(_safe_int(record.get("attempts")), 0) + 1,
                error="",
                failure=None,
                needs_confirmation=False,
                updated_at=self._timestamp(),
            )
            self._save_locked()
            snapshot = copy.deepcopy(record)
        try:
            cards, _secrets = self._read_cards(snapshot)
            result = self.client.upload(cards)
        except NvRuntimeError as exc:
            with self._lock:
                record = self._record_locked(record_id)
                source_count = max(_safe_int(record.get("source_count")), 1)
                status = "source_unavailable" if isinstance(exc, NvSourceError) else "failed"
                accepted = min(max(_safe_int(record.get("accepted")), 0), source_count)
                if exc.accepted is not None:
                    accepted = min(max(accepted, exc.accepted), source_count)
                needs_confirmation = not isinstance(exc, NvSourceError) and (
                    exc.needs_confirmation or accepted > 0
                )
                if needs_confirmation:
                    status = "partial"
                record.update(
                    status=status,
                    accepted=accepted,
                    needs_confirmation=needs_confirmation,
                    error=exc.public_message,
                    failure=exc.failure(),
                    updated_at=self._timestamp(),
                )
                self._save_locked()
            self._emit(f"NV 上传记录 {record_id} 失败 [{NV_NODE_LABEL}/{NV_NODE_CODE}]：{exc.public_message}", "error")
            return
        except Exception:
            exc = NvRuntimeError("NV 导入失败：未返回可用诊断", error_code="nv_import_unexpected", status_code=500)
            with self._lock:
                record = self._record_locked(record_id)
                record.update(
                    status="failed",
                    needs_confirmation=False,
                    error=exc.public_message,
                    failure=exc.failure(),
                    updated_at=self._timestamp(),
                )
                self._save_locked()
            self._emit(f"NV 上传记录 {record_id} 失败 [{NV_NODE_LABEL}/{NV_NODE_CODE}]：{exc.public_message}", "error")
            return
        with self._lock:
            record = self._record_locked(record_id)
            record.update(
                status="success",
                accepted=min(max(_safe_int(result.get("accepted")), 0), len(cards)),
                needs_confirmation=False,
                error="",
                failure=None,
                updated_at=self._timestamp(),
            )
            self._save_locked()
        self._emit(f"NV 上传记录 {record_id} 完成，共 {len(cards)} 个账号", "success")


__all__ = [
    "DEFAULT_NV_ENDPOINT",
    "DEFAULT_NV_SCHEMA_URL",
    "NvConfigurationError",
    "NvImportClient",
    "NvNetworkError",
    "NvRuntimeError",
    "NvSourceError",
    "NvUploadQueue",
    "build_nv_card",
    "sanitize_error",
]
