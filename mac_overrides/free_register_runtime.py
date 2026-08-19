"""Free registration manager with isolated storage and selectable drivers."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import random
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

try:
    from .free_mailbox_otp import MailboxUrlOtpProvider
    from .free_register_common import (
        FREE_STAGE_LABELS,
        FIXED_PASSWORD,
        FreeMailbox,
        FreeRegisterError,
        FreeTwoFaPending,
        ProxyBinding,
        TERMINAL_STATUSES,
        atomic_write as _atomic_write,
        clean as _clean,
        fingerprint as _fingerprint,
        mask_proxy as _mask_proxy,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        proxy_error_detail as _proxy_error_detail,
        random_birthdate,
        random_display_name,
        safe_log_message as _safe_log_message,
        timezone_offset_minutes as _timezone_offset_minutes,
    )
    from .free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore
    from .free_roxy_runtime import RoxyRegistrationRunner
    from .free_log_runtime import FreeLogStore
except ImportError:
    from free_mailbox_otp import MailboxUrlOtpProvider  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FREE_STAGE_LABELS, FIXED_PASSWORD, FreeMailbox, FreeRegisterError, FreeTwoFaPending,
        ProxyBinding, TERMINAL_STATUSES, atomic_write as _atomic_write, clean as _clean,
        fingerprint as _fingerprint, mask_proxy as _mask_proxy,
        plus_trial_from_accounts as _plus_trial_from_accounts,
        proxy_error_detail as _proxy_error_detail, random_birthdate, random_display_name,
        safe_log_message as _safe_log_message, timezone_offset_minutes as _timezone_offset_minutes,
    )
    from free_register_store import FreeMailboxPool, FreeProxyPool, FreeTaskStore  # type: ignore[no-redef]
    from free_roxy_runtime import RoxyRegistrationRunner  # type: ignore[no-redef]
    from free_log_runtime import FreeLogStore  # type: ignore[no-redef]

class FreeRegisterManager:
    def __init__(self, data_dir: str | Path, *, progress: Any = None, log_fn: Callable[[str, str], None] | None = None, runner: Callable[..., Mapping[str, Any]] | None = None, proxy_probe: Callable[[str, str], str] | None = None) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.pool = FreeMailboxPool(self.data_dir)
        self.proxies = FreeProxyPool(self.data_dir)
        self.task_store = FreeTaskStore(self.data_dir)
        self.log_store = FreeLogStore(self.data_dir)
        self.progress = progress
        self.log_fn = log_fn or self.log_store.add
        self.runner = runner or self._run_protocol
        self._custom_runner = runner is not None
        self.proxy_probe = proxy_probe
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._executor: ThreadPoolExecutor | None = None
        self._futures: set[Future[Any]] = set()
        self._tasks: dict[str, dict[str, Any]] = self.task_store.load()
        self._batch_id = ""

    def _log(self, message: str, level: str = "info") -> None:
        if callable(self.log_fn):
            try:
                self.log_fn(_safe_log_message(message), level)
            except Exception:
                pass

    def _task_log(self, task_id: str, message: str, level: str = "info") -> None:
        text = str(message or "")
        structured = re.match(r"^\[([^\]/]+)/([^\]/]+)(?:/([^\]]+))?\]\s*(.*)$", text)
        if structured:
            first, second, third, detail = structured.groups()
            if first == task_id:
                self._log(text, level)
                return
            label = first if third is None else second
            code = second if third is None else third
            self._log(f"[{task_id}/{label}/{code}] {detail}", level)
            return
        with self._lock:
            code = str(self._tasks.get(task_id, {}).get("stage") or "free_oauth_session")
        label = FREE_STAGE_LABELS.get(code, code)
        self._log(f"[{task_id}/{label}/{code}] {text}", level)

    def _stage(self, task_id: str, code: str) -> None:
        changed = False
        if self.progress is not None and callable(getattr(self.progress, "set_stage", None)):
            try:
                changed = bool(self.progress.set_stage(task_id, code))
            except Exception:
                pass
        with self._lock:
            if task_id in self._tasks:
                changed = changed or self._tasks[task_id].get("stage") != code
                self._tasks[task_id]["stage"] = code
                self._tasks[task_id]["updated_at"] = int(time.time())
                progress = self._tasks[task_id].setdefault("progress", {})
                progress.update({
                    "stage": code,
                    "group": "free",
                    "started_at": progress.get("started_at") or int(time.time()),
                    "updated_at": int(time.time()),
                    "finished_at": None,
                })
                self.task_store.save(self._tasks)
        if changed:
            label = FREE_STAGE_LABELS.get(code, code)
            self._log(f"[{task_id}/{label}/{code}] 开始", "info")

    def _save_task(self, task_id: str, **values: Any) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task.update(values)
            task["updated_at"] = int(time.time())
            self.task_store.save(self._tasks)

    def _finish_progress(self, task_id: str) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is not None:
                progress = task.setdefault("progress", {})
                progress["finished_at"] = int(time.time())
                progress["updated_at"] = int(time.time())
                self.task_store.save(self._tasks)
        if self.progress is not None and callable(getattr(self.progress, "finish", None)):
            try:
                self.progress.finish(task_id)
            except Exception:
                pass

    def _public_task(self, task: Mapping[str, Any]) -> dict[str, Any]:
        result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
        public = {key: copy.deepcopy(task[key]) for key in ("task_id", "ordinal", "status", "created_at", "updated_at", "batch_id", "run_mode", "driver", "email", "stage", "proxy_masked", "proxy_fingerprint", "expected_exit_ip", "registration_ip", "exit_ip", "profile_summary") if key in task}
        public["account"] = public.get("email", "")
        public["stage_label"] = FREE_STAGE_LABELS.get(str(public.get("stage") or ""), str(public.get("stage") or ""))
        public["result"] = {
            key: copy.deepcopy(result[key])
            for key in ("plan_type", "plus_trial_eligible", "twofa_status", "twofa_error", "has_access_token")
            if key in result
        }
        public["result"]["has_access_token"] = bool(result.get("access_token"))
        public["result"]["has_credential"] = bool(result.get("credential_line"))
        progress = None
        if self.progress is not None and callable(getattr(self.progress, "progress", None)):
            try:
                progress = self.progress.progress(task.get("task_id"))
            except Exception:
                progress = None
        if isinstance(progress, Mapping):
            public["progress"] = copy.deepcopy(progress)
            if isinstance(progress.get("timing"), Mapping):
                public["timing"] = copy.deepcopy(progress["timing"])
        elif isinstance(task.get("progress"), Mapping):
            public["progress"] = copy.deepcopy(task["progress"])
        if isinstance(task.get("failure"), Mapping):
            public["failure"] = copy.deepcopy(task["failure"])
            public["error"] = str(task["failure"].get("public_message") or "Free 注册失败")
        return public

    def public_tasks(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public_task(task) for task in sorted(self._tasks.values(), key=lambda item: int(item.get("ordinal") or 0))]

    def public_logs(self, task_id: str = "") -> list[dict[str, Any]]:
        return self.log_store.snapshot(task_id)

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            tasks = self.public_tasks()
            active = sum(1 for task in tasks if task.get("status") not in TERMINAL_STATUSES)
            success = sum(1 for task in tasks if task.get("status") == "success")
            failed = sum(1 for task in tasks if task.get("status") == "failed")
            return {
                "running": bool(self._executor and active),
                "batch_id": self._batch_id,
                "tasks": tasks,
                "pool": {
                    "total": len(self.pool.entries()),
                    "available": self._available_count(),
                    "proxies": len(self.proxies.values()),
                },
                "driver": str(next((task.get("driver") for task in reversed(list(self._tasks.values())) if task.get("batch_id") == self._batch_id), "protocol") or "protocol"),
                "summary": {
                    "total": len(tasks),
                    "active": active,
                    "success": success,
                    "failed": failed,
                    "stopped": sum(1 for task in tasks if task.get("status") == "stopped"),
                },
            }

    def _available_count(self) -> int:
        return len(self.pool.available(10_000))

    def preflight(self, config: Mapping[str, Any], *, proxy_content: str = "") -> dict[str, Any]:
        driver = str(config.get("driver") or "protocol").strip().lower()
        if driver not in {"protocol", "roxybrowser"}:
            raise FreeRegisterError("free_config", "Free 注册预检", "Free 注册链路无效", retryable=False)
        available = self._available_count()
        requested = int(config.get("target_count") or 0)
        target = available if requested <= 0 or requested > available else requested
        if target <= 0:
            raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", "Free 邮箱池没有可用邮箱", retryable=False)
        bindings = self.proxies.bind(
            target,
            content=proxy_content,
            probe=self.proxy_probe,
            probe_url=str(config.get("proxy_probe_url") or "https://api.ipify.org"),
        )
        if driver == "roxybrowser" and not self._custom_runner:
            roxy_result = RoxyRegistrationRunner.preflight(config)
        else:
            roxy_result = {"driver": driver}
        return {
            "driver": driver,
            "target_count": target,
            "mailboxes": available,
            "proxies": len(bindings),
            "exit_ips": len({binding.exit_ip for binding in bindings}),
            "roxy": roxy_result,
        }

    def preflight_proxies(self, *, proxy_content: str = "", probe_url: str = "https://api.ipify.org") -> dict[str, Any]:
        """Probe the isolated Free proxy pool without consuming mailboxes or tasks."""
        values = self.proxies.values(proxy_content)
        if not values:
            raise FreeRegisterError("free_proxy_preflight", "Free 代理预检", "请先粘贴或保存至少一个 Free 代理", retryable=False)
        bindings = self.proxies.bind(
            len(values),
            content=proxy_content,
            probe=self.proxy_probe,
            probe_url=probe_url,
        )
        return {
            "proxies": len(bindings),
            "exit_ips": len({binding.exit_ip for binding in bindings}),
            "rows": [
                {
                    "index": index,
                    "masked": binding.masked,
                    "fingerprint": binding.fingerprint,
                    "exit_ip": binding.exit_ip,
                }
                for index, binding in enumerate(bindings, 1)
            ],
        }

    def start(self, config: Mapping[str, Any], *, pool_content: str = "", proxy_content: str = "") -> dict[str, Any]:
        with self._lock:
            if self.public_state().get("running"):
                raise FreeRegisterError("free_run_start", "启动 Free 注册", "已有 Free 注册任务运行中", retryable=False)
            if pool_content.strip():
                self.pool.import_text(pool_content)
            if proxy_content.strip():
                self.proxies.import_text(proxy_content)
            available_count = self._available_count()
            configured_free_count = config.get("target_count", config.get("free_target_count"))
            try:
                configured_free_count_value = int(configured_free_count)
            except (TypeError, ValueError):
                configured_free_count_value = 0
            if configured_free_count_value <= 0 or configured_free_count_value > available_count:
                configured_free_count = available_count
            target_count = max(1, min(int(configured_free_count or 1), 10_000))
            rows = self.pool.available(target_count)
            if len(rows) < target_count:
                raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", f"Free 邮箱数量不足：需要 {target_count} 条，当前只有 {len(rows)} 条", retryable=False)
            driver = str(config.get("driver") or "protocol").strip().lower()
            if driver not in {"protocol", "roxybrowser"}:
                raise FreeRegisterError("free_config", "启动 Free 注册", "Free 注册链路无效", retryable=False)
            if driver == "roxybrowser" and not self._custom_runner:
                RoxyRegistrationRunner.preflight(config)
            bindings = self.proxies.bind(target_count, content=proxy_content, probe=self.proxy_probe, probe_url=str(config.get("proxy_probe_url") or "https://api.ipify.org"))
            batch_id = f"free-{int(time.time())}-{secrets.token_hex(4)}"
            self.pool.reserve(rows, batch_id)
            self._batch_id = batch_id
            self._stop.clear()
            now = int(time.time())
            for ordinal, (row, binding) in enumerate(zip(rows, bindings), 1):
                task_id = f"{batch_id}-{ordinal}"
                self._tasks[task_id] = {"task_id": task_id, "ordinal": ordinal, "status": "queued", "created_at": now, "updated_at": now, "batch_id": batch_id, "run_mode": "free_register", "driver": driver, "email": row.email, "row_id": row.row_id, "mailbox_url": row.mailbox_url, "proxy": binding.proxy, "proxy_masked": binding.masked, "proxy_fingerprint": binding.fingerprint, "expected_exit_ip": binding.exit_ip, "registration_ip": "", "exit_ip": binding.exit_ip, "progress": {"stage": "free_proxy_binding", "group": "free", "started_at": now, "updated_at": now, "finished_at": None}, "result": {"twofa_status": "pending", "driver": driver, "expected_exit_ip": binding.exit_ip}}
                self.pool.update(row.row_id, status="queued", batch_id=batch_id, driver=driver, proxy=binding.proxy, proxy_masked=binding.masked, proxy_fingerprint=binding.fingerprint, expected_exit_ip=binding.exit_ip, exit_ip=binding.exit_ip)
                self._stage(task_id, "free_proxy_binding")
            self.task_store.save(self._tasks)
            workers = max(1, min(int(config.get("concurrency") or config.get("free_concurrency") or 3), target_count, 5))
            self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="free-register")
            for task_id in list(self._tasks):
                if self._tasks[task_id].get("batch_id") != batch_id:
                    continue
                future = self._executor.submit(self._worker, task_id, dict(config))
                self._futures.add(future)
                future.add_done_callback(self._future_done)
            self._log(f"[启动 Free 注册/free_run_start] 已绑定 {target_count} 个邮箱和代理，{workers} 并发", "success")
            return {"batch_id": batch_id, "tasks": self.public_tasks(), "state": self.public_state()}

    def _future_done(self, future: Future[Any]) -> None:
        with self._lock:
            self._futures.discard(future)
            self.task_store.save(self._tasks)
            if not self._futures and self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=False)
                self._executor = None

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for task_id, task in self._tasks.items():
                if task.get("status") == "queued":
                    task["status"] = "stopped"
                    task["updated_at"] = int(time.time())
                    self.pool.update(task["row_id"], status="stopped")
                    self._finish_progress(task_id)
            self.task_store.save(self._tasks)
        self._log("[停止 Free 注册/free_stop] 已请求停止，运行中的账号不切换代理", "warn")

    def retry_twofa(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(str(task_id))
            if task is None:
                row = self.pool.entry(str(task_id))
                saved = self.pool.result(str(task_id)) if row is not None else {}
                if row is not None and saved.get("twofa_status") == "pending" and saved.get("proxy"):
                    now = int(time.time())
                    recovered_task_id = f"free-2fa-{now}-{secrets.token_hex(4)}"
                    task = {
                        "task_id": recovered_task_id,
                        "ordinal": 1,
                        "status": "twofa_pending",
                        "created_at": now,
                        "updated_at": now,
                        "batch_id": str(saved.get("batch_id") or "free-2fa-retry"),
                        "run_mode": "free_register",
                        "email": row.email,
                        "row_id": row.row_id,
                        "mailbox_url": row.mailbox_url,
                        "proxy": str(saved.get("proxy") or ""),
                        "proxy_masked": _mask_proxy(saved.get("proxy")),
                        "proxy_fingerprint": _fingerprint(saved.get("proxy")),
                        "exit_ip": str(saved.get("exit_ip") or ""),
                        "result": saved,
                    }
                    self._tasks[recovered_task_id] = task
            if task is None or task.get("status") != "twofa_pending":
                raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该任务当前没有待重试的 2FA", retryable=False)
            task["status"] = "queued"
            task["updated_at"] = int(time.time())
            self.task_store.save(self._tasks)
            self._stop.clear()
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="free-2fa-retry")
            resolved_task_id = str(task["task_id"])
            future = self._executor.submit(self._worker, resolved_task_id, dict(config), True)
            self._futures.add(future)
            future.add_done_callback(self._future_done)
            return self._public_task(task)

    def secret(self, task_ids: Sequence[str], kind: str, *, row_ids: Sequence[str] = ()) -> str:
        if kind not in {"token", "password", "totp", "proxy", "credential"}:
            raise FreeRegisterError("free_secret", "读取 Free 敏感字段", "不支持的敏感字段类型", retryable=False)
        values: list[str] = []
        seen_rows: set[str] = set()
        with self._lock:
            for task_id in task_ids:
                task = self._tasks.get(str(task_id))
                if not task:
                    continue
                seen_rows.add(str(task.get("row_id") or ""))
                result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
                value = {"token": result.get("access_token"), "password": result.get("password"), "totp": result.get("totp_secret"), "proxy": task.get("proxy"), "credential": result.get("credential_line")}.get(kind)
                if value:
                    values.append(str(value))
            for row_id in row_ids:
                normalized = str(row_id or "")
                if not normalized or normalized in seen_rows:
                    continue
                result = self.pool.result(normalized)
                private_state = self.pool._row_state(normalized)
                value = {"token": result.get("access_token"), "password": result.get("password"), "totp": result.get("totp_secret"), "proxy": result.get("proxy") or private_state.get("proxy"), "credential": result.get("credential_line")}.get(kind)
                if value:
                    values.append(str(value))
        return "\n".join(values)

    def _verify_binding(self, task: Mapping[str, Any], config: Mapping[str, Any]) -> None:
        binding = ProxyBinding(
            str(task.get("proxy") or ""),
            str(task.get("proxy_fingerprint") or ""),
            str(task.get("proxy_masked") or ""),
            str(task.get("exit_ip") or ""),
        )
        if not binding.proxy or not binding.exit_ip:
            raise FreeRegisterError("free_proxy_binding", "绑定 Free 注册代理", "任务缺少固定代理绑定", retryable=False)
        self.proxies.verify(
            binding,
            probe=self.proxy_probe,
            probe_url=str(config.get("proxy_probe_url") or "https://api.ipify.org"),
        )

    def _runner_for(self, config: Mapping[str, Any]) -> Callable[..., Mapping[str, Any]]:
        if self._custom_runner:
            return self.runner
        if str(config.get("driver") or "protocol").strip().lower() == "roxybrowser":
            return RoxyRegistrationRunner()
        return self._run_protocol

    def _worker(self, task_id: str, config: dict[str, Any], twofa_retry: bool = False) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task["status"] = "running"
            task["updated_at"] = int(time.time())
            snapshot = dict(task)
        self._log(f"[{task_id}/free_oauth_session] Free 任务开始", "info")
        task_log = lambda message, level="info": self._task_log(task_id, message, level)
        try:
            if self._stop.is_set():
                raise FreeRegisterError("free_run_stop", "停止 Free 注册", "任务在执行前已停止", retryable=False)
            self._verify_binding(snapshot, config)
            result = dict(self._runner_for(config)(snapshot, config, self._stop, self._stage, task_log, twofa_retry=twofa_retry))
            self._verify_binding(snapshot, config)
            result.update({
                "task_id": task_id,
                "batch_id": snapshot.get("batch_id", ""),
                "proxy": snapshot.get("proxy", ""),
                "expected_exit_ip": snapshot.get("expected_exit_ip") or snapshot.get("exit_ip", ""),
                "registration_ip": result.get("registration_ip") or snapshot.get("expected_exit_ip") or snapshot.get("exit_ip", ""),
                "exit_ip": result.get("registration_ip") or snapshot.get("exit_ip", ""),
                "driver": snapshot.get("driver") or config.get("driver") or "protocol",
            })
            status = "twofa_pending" if result.get("twofa_status") == "pending" else "success"
            self._save_task(task_id, status=status, result=result)
            self.pool.save_result(snapshot["row_id"], result)
            self.pool.update(snapshot["row_id"], status=status, stage="free_result_save", registration_ip=result.get("registration_ip", ""), error=result.get("twofa_error", ""))
            self._stage(task_id, "free_result_save")
            self._finish_progress(task_id)
            self._log(f"[{task_id}/free_result_save] Free 任务{'完成' if status == 'success' else '注册完成，2FA 待重试'}", "success" if status == "success" else "warn")
        except FreeRegisterError as exc:
            failure = {
                "node_code": exc.node_code,
                "node_label": exc.node_label,
                "error_code": str(getattr(exc, "error_code", "") or f"{exc.node_code}_failed"),
                "public_message": f"{exc.node_label} [{exc.node_label}/{exc.node_code}]：{_safe_log_message(exc)}",
                "technical_summary": _safe_log_message(exc),
                "retryable": bool(exc.retryable),
            }
            if getattr(exc, "provider_status", None) is not None:
                failure["http_status"] = exc.provider_status
            self._save_task(task_id, status="failed" if not self._stop.is_set() else "stopped", failure=failure)
            self.pool.update(snapshot["row_id"], status="failed" if not self._stop.is_set() else "stopped", stage=exc.node_code, error=failure["public_message"], failure=failure)
            self._finish_progress(task_id)
            self._log(f"[{task_id}/{exc.node_label}/{exc.node_code}] {failure['public_message']}", "error")
        except FreeTwoFaPending as pending:
            # A retry can fail after the account and token already exist. Keep
            # the task retryable and persist the token/plan context instead of
            # turning the recoverable 2FA state into a generic protocol error.
            with self._lock:
                current = self._tasks.get(task_id, {})
                saved = current.get("result") if isinstance(current.get("result"), Mapping) else {}
            result = dict(saved)
            result.update({
                "access_token": pending.token,
                "password": str(result.get("password") or FIXED_PASSWORD),
                "plan_type": pending.plan_type,
                "plus_trial_eligible": bool(pending.plus_trial_eligible),
                "twofa_status": "pending",
                "twofa_error": _safe_log_message(pending),
                "has_access_token": bool(pending.token),
            })
            self._save_task(task_id, status="twofa_pending", result=result, failure=None)
            self.pool.save_result(snapshot["row_id"], result)
            self.pool.update(snapshot["row_id"], status="twofa_pending", stage="free_twofa_activate", error=result["twofa_error"])
            self._stage(task_id, "free_twofa_activate")
            self._finish_progress(task_id)
            self._log(f"[{task_id}/free_twofa_activate] 2FA 重试未完成，保留待重试状态：{_safe_log_message(pending)}", "warn")
        except Exception as exc:
            failure = {"node_code": "free_protocol", "node_label": "Free 注册协议", "error_code": "free_protocol_failed", "public_message": f"Free 注册协议 [Free 注册协议/free_protocol]：{type(exc).__name__}", "technical_summary": type(exc).__name__, "retryable": True}
            self._save_task(task_id, status="failed", failure=failure)
            self.pool.update(snapshot["row_id"], status="failed", stage="free_protocol", error=failure["public_message"], failure=failure)
            self._finish_progress(task_id)
            self._log(f"[{task_id}/Free 注册协议/free_protocol] {failure['public_message']}", "error")

    @staticmethod
    def _totp_code(secret: str, now: float | None = None) -> str:
        normalized = re.sub(r"\s+", "", secret or "").upper()
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        key = base64.b32decode(normalized + padding, casefold=True)
        counter = int((now or time.time()) // 30).to_bytes(8, "big")
        digest = hmac.new(key, counter, hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
        return f"{value % 1_000_000:06d}"

    def _run_protocol(self, task: Mapping[str, Any], config: Mapping[str, Any], stop_event: threading.Event, stage: Callable[[str, str], None], log: Callable[[str, str], None], *, twofa_retry: bool = False) -> Mapping[str, Any]:
        # The recovered chain is imported only inside a worker so tests can use a
        # fake runner without loading the bundled runtime.
        import codex_chain_runner
        import codex_oauth_chain

        task_id = str(task["task_id"])
        email = str(task["email"])
        proxy = str(task["proxy"])
        password = FIXED_PASSWORD
        if twofa_retry:
            stage(task_id, "free_twofa_enroll")
        else:
            stage(task_id, "free_oauth_session")
        oauth_url, code_verifier, _state = codex_chain_runner.build_oauth_url(login_hint=email, screen_hint="signup")
        parsed = codex_oauth_chain.parse_oauth_url(oauth_url)
        device_id = str(task.get("device_id") or f"free-{secrets.token_hex(16)}")
        sentinel = codex_oauth_chain.RealNodeSentinelProvider(config=dict(config), device_id=device_id, proxy_label=str(task.get("proxy_fingerprint") or ""), proxy=proxy, log_fn=log)
        otp_provider = MailboxUrlOtpProvider(
            str(task["mailbox_url"]),
            proxy,
            timeout=int(config.get("email_code_timeout") or 90),
            log_fn=log,
            task_id=task_id,
            stage_fn=stage,
        )
        chain_config = dict(config)
        # The recovered OAuth chain names this setting ``codex_node_runner``;
        # the dashboard stores the same path as ``node_runner``. Keep both
        # names populated so Free uses the configured SentinelRunner instead
        # of silently entering the missing-runner retry path.
        protocol_config = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
        chain_config["codex_node_runner"] = str(
            protocol_config.get("node_runner")
            or config.get("codex_node_runner")
            or config.get("node_runner")
            or (config.get("node") or {}).get("runner")
            or ""
        ).strip()
        chain_config.update({
            "run_mode": "free_register",
            "codex_chain_mode": "real",
            "run_chatgpt_signup_phase": True,
            "free_register_no_phone": True,
            "phone_max_attempts": 1,
            "code_timeout": int(config.get("email_code_timeout") or 90),
            "_stop_requested": stop_event.is_set,
            "_auth_account_email": email,
            "register": {
                "password": password,
                "name": random_display_name(),
                "birthdate": random_birthdate(),
            },
        })

        def reject_phone(*_args: Any, **_kwargs: Any) -> Any:
            raise FreeRegisterError("free_phone_required", "Free 注册手机号节点", "Free 注册流程要求手机号，未调用接码平台")

        class NoPhoneProvider:
            get_number = staticmethod(reject_phone)

        transport = codex_oauth_chain.RealCodexTransport(
            chain_config,
            oauth_params=parsed,
            proxy=proxy,
            sentinel_provider=sentinel,
            device_id=device_id,
            log_fn=log,
        )
        self._instrument_transport(transport, task_id, stage)

        try:
            if twofa_retry:
                saved = self.pool.result(str(task["row_id"]))
                token = str(saved.get("access_token") or "")
                if not token:
                    raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "原账号没有可用 access token", retryable=False)
                twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
                result = dict(saved)
                result.update(twofa)
                result["password"] = str(saved.get("password") or password)
                if result.get("totp_secret"):
                    result["credential_line"] = f"{email}----{result['password']}----{result['totp_secret']}"
                return result

            stage(task_id, "free_email_identifier")
            result = codex_oauth_chain.run_codex_after_registration(
                oauth_url=oauth_url,
                code_verifier=code_verifier,
                account_email=email,
                password=password,
                config=chain_config,
                proxy=proxy,
                email_proxy=proxy,
                log_fn=log,
                mode="real",
                transport=transport,
                sentinel_provider=sentinel,
                email_otp_provider=otp_provider,
                phone_otp_provider=NoPhoneProvider(),
            )
            token = str((result or {}).get("access_token") or (result or {}).get("token") or "")
            if not token:
                stage(task_id, "free_access_token")
                token = str(transport.chatgpt_access_token() or "")
            if not token:
                raise FreeRegisterError("free_access_token", "获取 Free access token", "注册完成但未返回 access token")
            stage(task_id, "free_plan_check")
            plan_type, eligible = self._plan_check(transport, token)
            if bool(config.get("auto_set_2fa", True)):
                try:
                    twofa = self._enroll_twofa(transport, token, task, password, config, otp_provider, stage)
                except FreeTwoFaPending as pending:
                    twofa = {"twofa_status": "pending", "twofa_error": _clean(pending)}
            else:
                twofa = {"twofa_status": "disabled"}
            twofa.update({"access_token": token, "password": password, "plan_type": plan_type, "plus_trial_eligible": eligible, "has_access_token": True})
            if twofa.get("totp_secret"):
                twofa["twofa_status"] = "enabled"
                twofa["credential_line"] = f"{email}----{password}----{twofa['totp_secret']}"
            return twofa
        finally:
            self._close_transport(transport)

    @staticmethod
    def _instrument_transport(transport: Any, task_id: str, stage: Callable[[str, str], None]) -> None:
        mapping = {
            "start_chatgpt_signup_authorize": "free_oauth_session",
            "register_user": "free_email_identifier",
            "verify_password": "free_email_password",
            "send_email_otp": "free_email_otp_wait",
            "verify_signup_email_otp": "free_email_otp_validate",
            "verify_email_otp": "free_email_otp_validate",
            "create_account_profile": "free_account_create",
            "complete_chatgpt_callback": "free_oauth_callback",
            "follow_continue_until_code": "free_oauth_callback",
            "exchange_code": "free_access_token",
            "chatgpt_access_token": "free_access_token",
        }
        for name, code in mapping.items():
            original = getattr(transport, name, None)
            if not callable(original):
                continue

            def wrapped(*args: Any, __original: Callable[..., Any] = original, __code: str = code, **kwargs: Any) -> Any:
                stage(task_id, __code)
                return __original(*args, **kwargs)

            setattr(transport, name, wrapped)

    @staticmethod
    def _close_transport(transport: Any) -> None:
        candidates = [getattr(transport, "session", None), transport]
        for candidate in candidates:
            close = getattr(candidate, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

    def _plan_check(self, transport: Any, token: str) -> tuple[str, bool]:
        if transport is None:
            raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "认证传输会话不可用")
        session = getattr(transport, "session", None)
        if session is None:
            raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "认证 HTTP 会话不可用")
        try:
            response = session.get(
                "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
                f"?timezone_offset_min={_timezone_offset_minutes()}",
                headers={"authorization": f"Bearer {token}", "accept": "*/*"},
                timeout=20,
            )
            status = getattr(response, "status_code", None)
            if status is not None and not 200 <= int(status) < 300:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", f"套餐接口返回 HTTP {int(status)}")
            data = response.json() if hasattr(response, "json") else {}
            try:
                from .chatgpt_plan_gate import plan_from_accounts_check
            except ImportError:
                from chatgpt_plan_gate import plan_from_accounts_check
            plan, _ = plan_from_accounts_check(data, token=token)
            if not plan:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "套餐接口未返回可识别的套餐")
            eligible = _plus_trial_from_accounts(data)
            eligibility = session.get("https://chatgpt.com/backend-api/aip/first-party/eligibility", headers={"authorization": f"Bearer {token}", "accept": "application/json"}, timeout=20)
            eligibility_status = getattr(eligibility, "status_code", None)
            if eligibility_status is not None and not 200 <= int(eligibility_status) < 300:
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", f"试用资格接口返回 HTTP {int(eligibility_status)}")
            eligible_data = eligibility.json() if hasattr(eligibility, "json") else {}
            if not isinstance(eligible_data, Mapping):
                raise FreeRegisterError("free_plan_check", "查询 Free 套餐资格", "试用资格接口响应不是 JSON 对象")
            eligible = eligible or _plus_trial_from_accounts(eligible_data)
            campaigns = eligible_data.get("eligible_promo_campaigns")
            eligible = eligible or (isinstance(campaigns, Mapping) and bool(campaigns.get("plus")))
            return plan, eligible
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError(
                "free_plan_check",
                "查询 Free 套餐资格",
                f"套餐或试用资格查询异常（{type(exc).__name__}）",
            ) from exc

    def _enroll_twofa(self, transport: Any, token: str, task: Mapping[str, Any], password: str, config: Mapping[str, Any], otp_provider: MailboxUrlOtpProvider, stage: Callable[[str, str], None]) -> dict[str, Any]:
        if transport is None:
            raise FreeTwoFaPending("2FA 重试缺少认证会话", token=token, plan_type="free", plus_trial_eligible=False)
        session = getattr(transport, "session", None)
        if session is None:
            raise FreeTwoFaPending("2FA 会话不可用", token=token, plan_type="free", plus_trial_eligible=False)
        stage(str(task["task_id"]), "free_twofa_enroll")
        headers = {"accept": "application/json", "content-type": "application/json", "authorization": f"Bearer {token}", "oai-device-id": str(getattr(transport, "device_id", "") or ""), "oai-language": "en-GB"}
        try:
            # A Free account can require a fresh re-authentication before MFA
            # enrollment. The recovered protocol exposes this as the same
            # email OTP challenge used by the signup flow; keep it on the
            # bound mailbox/proxy and never silently skip the second message.
            send_mfa_otp = getattr(transport, "send_mfa_otp", None)
            verify_mfa_otp = getattr(transport, "verify_mfa_otp", None)
            if callable(send_mfa_otp) and callable(verify_mfa_otp):
                stage(str(task["task_id"]), "free_email_otp_wait")
                sent = send_mfa_otp("")
                status = int((sent or {}).get("_status") or (sent or {}).get("status_code") or 0) if isinstance(sent, Mapping) else 0
                if status >= 400:
                    raise ValueError(f"重新认证 OTP 发送返回 HTTP {status}")
                otp_provider.mark_sent()
                code = otp_provider.wait_code(str(task.get("email") or ""))
                stage(str(task["task_id"]), "free_email_otp_validate")
                verified = verify_mfa_otp(code)
                verified_status = int((verified or {}).get("_status") or (verified or {}).get("status_code") or 0) if isinstance(verified, Mapping) else 0
                if verified_status >= 400 or (isinstance(verified, Mapping) and verified.get("ok") is False):
                    raise ValueError(f"重新认证 OTP 验证失败（HTTP {verified_status or '-'}）")
            enrolled = session.post("https://chatgpt.com/backend-api/accounts/mfa/enroll", headers=headers, json={"factor_type": "totp"}, timeout=20)
            data = enrolled.json() if hasattr(enrolled, "json") else {}
            secret = str(data.get("secret") or "")
            session_id = str(data.get("session_id") or "")
            if not secret or not session_id:
                raise ValueError("enroll 响应缺少 TOTP 材料")
            stage(str(task["task_id"]), "free_twofa_activate")
            activated = session.post("https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment", headers=headers, json={"code": self._totp_code(secret), "factor_type": "totp", "session_id": session_id}, timeout=20)
            activated_data = activated.json() if hasattr(activated, "json") else {}
            if not bool(activated_data.get("success")):
                raise ValueError("2FA 激活返回 success=false")
            return {"twofa_status": "enabled", "totp_secret": secret}
        except Exception as exc:
            raise FreeTwoFaPending(f"2FA 设置失败：{type(exc).__name__}", token=token, plan_type="free", plus_trial_eligible=False) from exc


__all__ = ["FIXED_PASSWORD", "FreeMailboxPool", "FreeProxyPool", "FreeRegisterError", "FreeRegisterManager", "MailboxUrlOtpProvider", "ProxyBinding", "random_birthdate", "random_display_name"]
