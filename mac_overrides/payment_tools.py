"""Independent payment-link task center with credential-safe public state."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import copy
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlsplit

try:
    from .free_register_common import SECRET_MASK, atomic_write, mask_proxy, safe_log_message
except ImportError:
    from free_register_common import SECRET_MASK, atomic_write, mask_proxy, safe_log_message  # type: ignore[no-redef]


PAYMENT_MODES = frozenset({"local", "manual", "cdk", "http", "pay153"})
EXTERNAL_MODES = frozenset({"cdk", "http", "pay153"})
PAYMENT_CHANNELS = frozenset({
    "hosted", "ph_short", "paypal", "pix", "upi", "ideal", "gcash", "gopay", "kakao_pay", "momo",
})
TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})
DEFAULT_PAYMENT_CONFIG: dict[str, Any] = {
    "version": 1,
    "mode": "local",
    "workers": 2,
    "timeout_seconds": 180,
    "country": "US",
    "currency": "USD",
    "plan": "plus",
    "channel": "paypal",
    "apply_checkout_update": True,
    "checkout_proxy": "",
    "update_proxy": "",
    "cdk_base_url": "",
    "cdk": "",
    "http_endpoint": "",
    "http_api_token": "",
    "pay153_url": "https://pay.153.ink/",
    "pay153_headless": True,
    "try_promo": False,
    "use_sentinel": True,
}


class PaymentToolError(RuntimeError):
    def __init__(self, code: str, label: str, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.node_code = code
        self.node_label = label
        self.error_code = f"{code}_failed"
        self.retryable = retryable


def _clean(value: Any, limit: int = 300) -> str:
    return " ".join(str(value or "").split())[:limit]


def _endpoint_domain(value: Any) -> str:
    try:
        parsed = urlsplit(str(value or "").strip())
    except ValueError:
        return ""
    return (parsed.hostname or "").casefold() if parsed.scheme in {"http", "https"} else ""


def _result_summary(value: str) -> dict[str, Any]:
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None
    if parsed is not None and parsed.scheme in {"http", "https"} and parsed.hostname:
        return {"has_result": True, "result_kind": "url", "result_host": parsed.hostname}
    return {"has_result": bool(value), "result_kind": "text", "result_host": ""}


class PaymentToolsService:
    def __init__(
        self,
        data_root: str | Path,
        *,
        free_manager: Any | None = None,
        adapters: Mapping[str, Callable[..., Mapping[str, Any]]] | None = None,
        recover: bool = True,
    ) -> None:
        self.data_dir = Path(data_root).expanduser().resolve() / "payment_tools"
        self.config_path = self.data_dir / "config.json"
        self.tasks_path = self.data_dir / "tasks.json"
        self.secrets_path = self.data_dir / "secrets.json"
        self.free_manager = free_manager
        self._lock = threading.RLock()
        self._config = self._load_config()
        self._tasks = self._load_object(self.tasks_path, "tasks")
        self._secrets = self._load_object(self.secrets_path, "secrets")
        self._cancel: dict[str, threading.Event] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=int(self._config["workers"]),
            thread_name_prefix="payment-tools",
        )
        self._futures: set[Future[Any]] = set()
        self.adapters = {
            "local": self._run_local,
            "cdk": self._run_cdk,
            "http": self._run_http,
            "pay153": self._run_pay153,
            **dict(adapters or {}),
        }
        if recover:
            self._recover()

    @staticmethod
    def _load_object(path: Path, key: str) -> dict[str, dict[str, Any]]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {}
        values = payload.get(key) if isinstance(payload, Mapping) else {}
        return {str(k): dict(v) for k, v in values.items() if isinstance(v, Mapping)} if isinstance(values, Mapping) else {}

    def _normalize_config(self, value: Mapping[str, Any], previous: Mapping[str, Any] | None = None) -> dict[str, Any]:
        result = copy.deepcopy(DEFAULT_PAYMENT_CONFIG)
        result.update(copy.deepcopy(dict(previous or {})))
        for key in DEFAULT_PAYMENT_CONFIG:
            if key in value:
                incoming = value[key]
                if incoming == SECRET_MASK and key in {"cdk", "http_api_token", "checkout_proxy", "update_proxy"}:
                    continue
                result[key] = copy.deepcopy(incoming)
        mode = str(result.get("mode") or "local").lower()
        if mode not in PAYMENT_MODES:
            raise PaymentToolError("payment_config", "保存支付工具配置", "不支持的支付提链模式", retryable=False)
        channel = str(result.get("channel") or "paypal").lower()
        if channel not in PAYMENT_CHANNELS:
            raise PaymentToolError("payment_config", "保存支付工具配置", "不支持的支付通道", retryable=False)
        try:
            workers = int(result.get("workers") or 2)
        except (TypeError, ValueError):
            raise PaymentToolError("payment_config", "保存支付工具配置", "并发数必须是 1-5 的整数", retryable=False)
        try:
            timeout_seconds = int(result.get("timeout_seconds") or 180)
        except (TypeError, ValueError):
            raise PaymentToolError("payment_config", "保存支付工具配置", "超时时间必须是整数秒数", retryable=False)
        result.update({
            "version": 1,
            "mode": mode,
            "channel": channel,
            "workers": max(1, min(5, workers)),
            "timeout_seconds": max(15, min(900, timeout_seconds)),
            "country": _clean(result.get("country"), 2).upper() or "US",
            "currency": _clean(result.get("currency"), 4).upper() or "USD",
            "plan": _clean(result.get("plan"), 20).lower() or "plus",
            "apply_checkout_update": bool(result.get("apply_checkout_update", True)),
            "pay153_headless": bool(result.get("pay153_headless", True)),
            "try_promo": bool(result.get("try_promo", False)),
            "use_sentinel": bool(result.get("use_sentinel", True)),
        })
        for key in ("cdk_base_url", "http_endpoint", "pay153_url"):
            raw = str(result.get(key) or "").strip()
            if raw and not _endpoint_domain(raw):
                raise PaymentToolError("payment_config", "保存支付工具配置", f"{key} 必须是完整 HTTP/HTTPS 地址", retryable=False)
            result[key] = raw
        for key in ("cdk", "http_api_token", "checkout_proxy", "update_proxy"):
            result[key] = str(result.get(key) or "").strip()
        return result

    def _load_config(self) -> dict[str, Any]:
        try:
            value = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            value = {}
        return self._normalize_config(value if isinstance(value, Mapping) else {})

    def public_config(self) -> dict[str, Any]:
        with self._lock:
            result = copy.deepcopy(self._config)
        for key in ("cdk", "http_api_token"):
            result[key] = SECRET_MASK if result.get(key) else ""
        for key in ("checkout_proxy", "update_proxy"):
            result[key] = mask_proxy(result.get(key))
        return result

    def save_config(self, value: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            normalized = self._normalize_config(value, self._config)
            if any(task.get("status") in {"queued", "running"} for task in self._tasks.values()):
                raise PaymentToolError("payment_config", "保存支付工具配置", "支付任务运行中，暂不能修改配置", retryable=False)
            previous_workers = int(self._config["workers"])
            self._config = normalized
            atomic_write(self.config_path, normalized)
            if int(normalized["workers"]) != previous_workers:
                previous_executor = self._executor
                self._executor = ThreadPoolExecutor(
                    max_workers=int(normalized["workers"]),
                    thread_name_prefix="payment-tools",
                )
                previous_executor.shutdown(wait=False)
        return self.public_config()

    def _save(self) -> None:
        atomic_write(self.tasks_path, {"version": 1, "tasks": self._tasks})
        atomic_write(self.secrets_path, {"version": 1, "secrets": self._secrets})

    def _recover(self) -> None:
        changed = False
        now = int(time.time())
        with self._lock:
            for task in self._tasks.values():
                if task.get("status") not in {"queued", "running"}:
                    continue
                task.update({
                    "status": "failed", "stage": "payment_recovered",
                    "updated_at": now, "finished_at": now,
                    "failure": self._failure(PaymentToolError(
                        "payment_recovered", "恢复支付提链任务",
                        "应用重启导致任务中断，请使用重试按钮重新执行",
                    )),
                })
                changed = True
            if changed:
                self._save()

    @staticmethod
    def _failure(exc: BaseException) -> dict[str, Any]:
        code = str(getattr(exc, "node_code", "") or "payment_task")
        label = str(getattr(exc, "node_label", "") or "支付链接提炼")
        reason = safe_log_message(exc) or f"{label}未返回错误详情"
        return {
            "node_code": code,
            "node_label": label,
            "error_code": str(getattr(exc, "error_code", "") or f"{code}_failed"),
            "public_message": f"{label} [{code}]：{reason}",
            "retryable": bool(getattr(exc, "retryable", True)),
        }

    def _public_task(self, task: Mapping[str, Any]) -> dict[str, Any]:
        allowed = (
            "task_id", "source", "row_id", "email", "mode", "channel", "plan",
            "country", "currency", "status", "stage", "target_domain", "confirmed",
            "created_at", "updated_at", "started_at", "finished_at", "retry_count",
            "result_summary", "failure",
        )
        result = {key: copy.deepcopy(task[key]) for key in allowed if key in task}
        result["logs_count"] = len(task.get("logs") or [])
        return result

    def state(self) -> dict[str, Any]:
        with self._lock:
            tasks = [self._public_task(task) for task in self._tasks.values()]
        tasks.sort(key=lambda item: (int(item.get("created_at") or 0), item.get("task_id", "")), reverse=True)
        return {
            "tasks": tasks,
            "summary": {
                "total": len(tasks),
                "active": sum(task.get("status") in {"queued", "running"} for task in tasks),
                "awaiting_confirmation": sum(task.get("status") == "awaiting_confirmation" for task in tasks),
                "succeeded": sum(task.get("status") == "succeeded" for task in tasks),
                "failed": sum(task.get("status") == "failed" for task in tasks),
            },
        }

    def task(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(str(task_id))
            if task is None:
                raise PaymentToolError("payment_task_read", "读取支付提链任务", "任务不存在", retryable=False)
            return self._public_task(task)

    def logs(self, task_id: str) -> list[dict[str, Any]]:
        with self._lock:
            task = self._tasks.get(str(task_id))
            if task is None:
                raise PaymentToolError("payment_task_logs", "读取支付任务日志", "任务不存在", retryable=False)
            return copy.deepcopy(task.get("logs") or [])

    def _log(self, task_id: str, stage: str, message: str, level: str = "info") -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task["logs"] = list(task.get("logs") or [])[-499:]
            task["logs"].append({
                "time": int(time.time()), "stage": stage, "level": level,
                "message": safe_log_message(message),
            })
            task["stage"] = stage
            task["updated_at"] = int(time.time())
            self._save()

    def _free_source(self, row_id: str) -> tuple[str, str, str]:
        pool = getattr(self.free_manager, "pool", None)
        if pool is None:
            raise PaymentToolError("payment_source", "读取 Free 支付账号", "Free 账号服务尚未初始化")
        entry = pool.entry(row_id)
        result = pool.result(row_id)
        token = str(result.get("access_token") or "")
        if entry is None or not token:
            raise PaymentToolError("payment_source", "读取 Free 支付账号", "所选 Free 账号没有可用 Token", retryable=False)
        return str(entry.email), token, str(result.get("proxy") or "")

    def _target_domain(self, mode: str, config: Mapping[str, Any]) -> str:
        return _endpoint_domain({
            "cdk": config.get("cdk_base_url"),
            "http": config.get("http_endpoint"),
            "pay153": config.get("pay153_url"),
        }.get(mode, ""))

    def create(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        config = self._normalize_config(payload, self._config)
        mode = str(config["mode"])
        sources: list[tuple[str, str, str, str]] = []
        if mode == "manual":
            link = str(payload.get("manual_link") or "").strip()
            if not link:
                raise PaymentToolError("payment_manual", "保存手动支付链接", "请粘贴支付链接或付款码", retryable=False)
            sources.append(("manual_link", "", "", ""))
        else:
            row_ids = payload.get("row_ids") if isinstance(payload.get("row_ids"), list) else []
            for row_id in dict.fromkeys(str(value or "").strip().lower() for value in row_ids):
                if row_id:
                    email, token, proxy = self._free_source(row_id)
                    sources.append(("free", row_id, email, token + "\0" + proxy))
            manual_tokens = payload.get("manual_tokens")
            values = manual_tokens if isinstance(manual_tokens, list) else str(manual_tokens or "").splitlines()
            for raw in values:
                token = str(raw or "").strip()
                if token:
                    sources.append(("manual_token", "", "", token + "\0"))
            if not sources:
                raise PaymentToolError("payment_source", "创建支付提链任务", "请选择 Free 账号或输入 Token", retryable=False)
        created: list[dict[str, Any]] = []
        submit: list[str] = []
        with self._lock:
            for source, row_id, email, packed in sources:
                token, _, registered_proxy = packed.partition("\0")
                task_id = f"payment-{int(time.time())}-{secrets.token_hex(5)}"
                now = int(time.time())
                external = mode in EXTERNAL_MODES
                task = {
                    "task_id": task_id, "source": source, "row_id": row_id, "email": email,
                    "mode": mode, "channel": config["channel"], "plan": config["plan"],
                    "country": config["country"], "currency": config["currency"],
                    "status": "awaiting_confirmation" if external else "queued",
                    "stage": "payment_confirmation" if external else "payment_queued",
                    "target_domain": self._target_domain(mode, config), "confirmed": not external,
                    "created_at": now, "updated_at": now, "retry_count": 0, "logs": [],
                }
                if external and not task["target_domain"]:
                    raise PaymentToolError("payment_config", "创建支付提链任务", "第三方服务地址未配置", retryable=False)
                self._tasks[task_id] = task
                self._secrets[task_id] = {
                    "access_token": token,
                    "checkout_proxy": str(payload.get("checkout_proxy") or config.get("checkout_proxy") or registered_proxy),
                    "update_proxy": str(payload.get("update_proxy") or config.get("update_proxy") or registered_proxy),
                    "manual_link": str(payload.get("manual_link") or "").strip(),
                    "result": "",
                }
                created.append(self._public_task(task))
                if not external:
                    submit.append(task_id)
            self._save()
        for task_id in submit:
            self._submit(task_id)
        return {"tasks": created, "requires_confirmation": mode in EXTERNAL_MODES}

    def confirm(self, task_id: str, target_domain: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(str(task_id))
            if task is None or task.get("status") != "awaiting_confirmation":
                raise PaymentToolError("payment_confirmation", "确认第三方 Token 发送", "任务不在待确认状态", retryable=False)
            if _clean(target_domain, 253).casefold() != str(task.get("target_domain") or ""):
                raise PaymentToolError("payment_confirmation", "确认第三方 Token 发送", "确认域名与任务目标不一致", retryable=False)
            task.update({"status": "queued", "stage": "payment_queued", "confirmed": True, "updated_at": int(time.time())})
            self._save()
        self._submit(str(task_id))
        return self.task(str(task_id))

    def _submit(self, task_id: str) -> None:
        event = threading.Event()
        self._cancel[task_id] = event
        future = self._executor.submit(self._worker, task_id, event)
        with self._lock:
            self._futures.add(future)
        future.add_done_callback(lambda item: self._future_done(task_id, item))

    def _future_done(self, task_id: str, future: Future[Any]) -> None:
        with self._lock:
            self._futures.discard(future)
            self._cancel.pop(task_id, None)

    def _stage(self, task_id: str, stage: str) -> None:
        self._log(task_id, stage, f"进入步骤：{stage}")

    def _worker(self, task_id: str, cancel: threading.Event) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None or task.get("status") != "queued":
                return
            task.update({"status": "running", "stage": "payment_start", "started_at": int(time.time())})
            config = copy.deepcopy(self._config)
            config.update({key: task.get(key) for key in ("mode", "channel", "plan", "country", "currency")})
            secret = copy.deepcopy(self._secrets.get(task_id) or {})
            self._save()
        self._log(task_id, "payment_start", "支付提链任务开始，敏感凭据未写入日志")
        try:
            if cancel.is_set():
                raise PaymentToolError("payment_cancelled", "取消支付提链任务", "任务已取消", retryable=False)
            mode = str(task.get("mode") or "")
            if mode == "manual":
                result = {"value": str(secret.get("manual_link") or "")}
            else:
                adapter = self.adapters.get(mode)
                if adapter is None:
                    raise PaymentToolError("payment_adapter", "运行支付提链适配器", "提链适配器不可用", retryable=False)
                result = dict(adapter(task, secret, config, lambda stage: self._stage(task_id, stage), cancel))
            value = str(result.get("value") or result.get("url") or result.get("link") or "").strip()
            if not value:
                raise PaymentToolError("payment_result", "保存支付提链结果", "提链任务未返回支付链接或付款码")
            with self._lock:
                self._secrets[task_id]["result"] = value
                current = self._tasks[task_id]
                current.update({
                    "status": "succeeded", "stage": "payment_completed",
                    "result_summary": _result_summary(value), "finished_at": int(time.time()),
                    "updated_at": int(time.time()), "failure": None,
                })
                self._save()
            self._log(task_id, "payment_completed", "支付链接提炼完成，结果仅可按需读取", "success")
        except Exception as exc:
            failure = self._failure(exc)
            status = "cancelled" if cancel.is_set() or failure["node_code"] == "payment_cancelled" else "failed"
            with self._lock:
                current = self._tasks.get(task_id)
                if current is not None:
                    current.update({
                        "status": status, "stage": failure["node_code"], "failure": failure,
                        "finished_at": int(time.time()), "updated_at": int(time.time()),
                    })
                    self._save()
            self._log(task_id, failure["node_code"], failure["public_message"], "error")

    def cancel(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(str(task_id))
            if task is None:
                raise PaymentToolError("payment_cancel", "取消支付提链任务", "任务不存在", retryable=False)
            if task.get("status") in TERMINAL_STATUSES:
                return self._public_task(task)
            event = self._cancel.get(str(task_id))
            if event is not None:
                event.set()
            if task.get("status") == "awaiting_confirmation":
                task.update({"status": "cancelled", "stage": "payment_cancelled", "finished_at": int(time.time())})
                self._save()
            return self._public_task(task)

    def retry(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(str(task_id))
            if task is None or task.get("status") not in {"failed", "cancelled"}:
                raise PaymentToolError("payment_retry", "重试支付提链任务", "只有失败或已取消任务可以重试", retryable=False)
            external = task.get("mode") in EXTERNAL_MODES
            task.update({
                "status": "awaiting_confirmation" if external else "queued",
                "stage": "payment_confirmation" if external else "payment_queued",
                "confirmed": not external, "failure": None, "started_at": None, "finished_at": None,
                "retry_count": int(task.get("retry_count") or 0) + 1, "updated_at": int(time.time()),
            })
            self._secrets.setdefault(str(task_id), {})["result"] = ""
            self._save()
        if not external:
            self._submit(str(task_id))
        return self.task(str(task_id))

    def reveal(self, task_id: str) -> str:
        with self._lock:
            task = self._tasks.get(str(task_id))
            secret = self._secrets.get(str(task_id)) or {}
            if task is None or task.get("status") != "succeeded" or not secret.get("result"):
                raise PaymentToolError("payment_secret", "读取支付提链结果", "任务没有可读取的成功结果", retryable=False)
            return str(secret["result"])

    @staticmethod
    def _run_local(task: Mapping[str, Any], secret: Mapping[str, Any], config: Mapping[str, Any], stage: Callable[[str], None], cancel: threading.Event) -> Mapping[str, Any]:
        try:
            from .payment_protocol import ExtractionConfig, extract_payment_link
        except ImportError:
            from payment_protocol import ExtractionConfig, extract_payment_link  # type: ignore[no-redef]
        proxy = str(secret.get("checkout_proxy") or "")
        if not proxy:
            raise PaymentToolError("payment_local_proxy", "本地协议提链代理", "本地协议提链需要固定代理", retryable=False)
        channel = str(task.get("channel") or "paypal")
        if channel not in {"paypal", "gopay", "gcash"}:
            raise PaymentToolError("payment_local_channel", "本地协议提链通道", "本地协议当前仅支持 PayPal、GoPay 和 GCash", retryable=False)
        result = extract_payment_link(ExtractionConfig(
            access_token=str(secret.get("access_token") or ""),
            checkout_proxy=proxy,
            update_proxy=str(secret.get("update_proxy") or proxy),
            country=str(task.get("country") or "US"),
            payment_method=channel,
            apply_checkout_update=bool(config.get("apply_checkout_update", True)),
            verbose=False,
        ), cancel_event=cancel, stage_callback=stage)
        return {"value": result.provider_url or result.stripe_redirect_url}

    @staticmethod
    def _session():
        from curl_cffi import requests as curl_requests
        session = curl_requests.Session(impersonate="chrome")
        session.trust_env = False
        return session

    def _run_http(self, task: Mapping[str, Any], secret: Mapping[str, Any], config: Mapping[str, Any], stage: Callable[[str], None], cancel: threading.Event) -> Mapping[str, Any]:
        endpoint = str(config.get("http_endpoint") or "")
        stage("payment_http_request")
        session = self._session()
        try:
            headers = {"accept": "application/json", "content-type": "application/json"}
            if config.get("http_api_token"):
                headers["authorization"] = f"Bearer {config['http_api_token']}"
            response = session.post(endpoint, json={
                "token": secret.get("access_token"), "plan": task.get("plan"),
                "channel": task.get("channel"), "country": task.get("country"),
                "currency": task.get("currency"), "tryPromo": bool(config.get("try_promo")),
            }, headers=headers, timeout=int(config.get("timeout_seconds") or 180))
            if not 200 <= int(response.status_code) < 300:
                raise PaymentToolError("payment_http_request", "调用 HTTP 提链服务", f"提链服务返回 HTTP {response.status_code}")
            payload = response.json()
            raw = payload.get("url") or payload.get("link") or payload.get("finalUrl") or payload.get("data")
            if isinstance(raw, Mapping):
                raw = raw.get("url") or raw.get("link")
            return {"value": str(raw or "")}
        finally:
            session.close()

    def _run_cdk(self, task: Mapping[str, Any], secret: Mapping[str, Any], config: Mapping[str, Any], stage: Callable[[str], None], cancel: threading.Event) -> Mapping[str, Any]:
        base = str(config.get("cdk_base_url") or "").rstrip("/")
        cdk = str(config.get("cdk") or "")
        if not cdk:
            raise PaymentToolError("payment_cdk", "调用 CDK 提链服务", "CDK 未配置", retryable=False)
        session = self._session()
        try:
            stage("payment_cdk_create")
            response = session.post(f"{base}/api/extract", json={
                "link_type": task.get("channel"), "cdk": cdk, "token": secret.get("access_token"),
            }, timeout=int(config.get("timeout_seconds") or 180))
            payload = response.json() if 200 <= int(response.status_code) < 300 else {}
            job_id = str(payload.get("job_id") or "")
            if not job_id:
                raise PaymentToolError("payment_cdk_create", "创建 CDK 提链任务", f"服务未返回任务编号（HTTP {response.status_code}）")
            stage("payment_cdk_events")
            stream = session.get(
                f"{base}/api/jobs/{quote(job_id, safe='')}/events?cdk={quote(cdk, safe='')}",
                headers={"accept": "text/event-stream"}, stream=True,
                timeout=int(config.get("timeout_seconds") or 180),
            )
            event = "message"
            data_lines: list[str] = []
            def consume_event() -> Mapping[str, Any] | None:
                nonlocal event, data_lines
                if not data_lines:
                    event, data_lines = "message", []
                    return None
                try:
                    data = json.loads("\n".join(data_lines))
                except (TypeError, ValueError) as exc:
                    raise PaymentToolError("payment_cdk_events", "解析 CDK 提链事件", "事件流返回了无效 JSON", retryable=False) from exc
                current_event = event
                event, data_lines = "message", []
                if current_event == "result":
                    result = data.get("result") if isinstance(data, Mapping) else data
                    if isinstance(result, Mapping):
                        value = next((result.get(key) for key in ("long_url", "copy_paste", "final_paypal_link", "payment_link", "url", "link") if result.get(key)), "")
                        if value:
                            return {"value": str(value)}
                if current_event == "error":
                    raise PaymentToolError("payment_cdk_events", "监听 CDK 提链任务", "CDK 服务返回任务失败")
                return None

            for raw in stream.iter_lines():
                if cancel.is_set():
                    raise PaymentToolError("payment_cancelled", "取消支付提链任务", "任务已取消", retryable=False)
                line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw or "")
                line = line.rstrip("\r")
                if not line:
                    completed = consume_event()
                    if completed is not None:
                        return completed
                elif line.startswith("event:"):
                    event = line.split(":", 1)[1].strip()
                elif line.startswith("data:"):
                    data_lines.append(line.split(":", 1)[1].lstrip())
            completed = consume_event()
            if completed is not None:
                return completed
            raise PaymentToolError("payment_cdk_events", "监听 CDK 提链任务", "事件流结束但没有返回结果")
        finally:
            session.close()

    @staticmethod
    def _run_pay153(task: Mapping[str, Any], secret: Mapping[str, Any], config: Mapping[str, Any], stage: Callable[[str], None], cancel: threading.Event) -> Mapping[str, Any]:
        try:
            from .payment_pay153_browser import extract_pay153_link
        except ImportError:
            from payment_pay153_browser import extract_pay153_link  # type: ignore[no-redef]
        return {"value": extract_pay153_link(task, secret, config, stage=stage, cancel_event=cancel)}


__all__ = [
    "DEFAULT_PAYMENT_CONFIG", "EXTERNAL_MODES", "PAYMENT_CHANNELS", "PAYMENT_MODES",
    "PaymentToolError", "PaymentToolsService",
]
