"""Pure-protocol Free account email rebind service.

This service owns only rebind tasks and destination mailboxes.  Registration
drivers are intentionally invisible here: a source row may have originated in
the protocol or RoxyBrowser flow, but the rebind worker always constructs a
fresh protocol transport and never touches a RoxyBrowser profile.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import copy
import inspect
import json
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urljoin

try:
    from .free_failure_runtime import canonical_failure, exception_to_failure, sanitize_log_message
    from .free_mailbox_otp import build_free_mailbox_otp_provider
    from .free_register_common import FreeRegisterError, atomic_write, fingerprint, mask_proxy
    from .free_rebind_store import RebindMailboxPool
except ImportError:  # pragma: no cover - top-level runtime loading
    from free_failure_runtime import canonical_failure, exception_to_failure, sanitize_log_message  # type: ignore[no-redef]
    from free_mailbox_otp import build_free_mailbox_otp_provider  # type: ignore[no-redef]
    from free_register_common import FreeRegisterError, atomic_write, fingerprint, mask_proxy  # type: ignore[no-redef]
    from free_rebind_store import RebindMailboxPool  # type: ignore[no-redef]


REBIND_STAGE_LABELS = {
    "free_rebind_proxy": "准备换绑协议代理",
    "free_rebind_login_old": "旧邮箱密码 + TOTP 登录",
    "free_rebind_eligibility": "检查换绑资格",
    "free_rebind_begin": "发送新邮箱验证码",
    "free_rebind_otp": "等待新邮箱验证码",
    "free_rebind_verify": "验证换绑邮箱",
    "free_rebind_login_new": "新邮箱密码 + TOTP 重登",
    "free_rebind_plan": "查询套餐与 Plus 资格",
    "free_rebind_result": "保存换绑结果",
    "free_rebind_process_recovery": "恢复换绑任务",
}
ACTIVE_REBIND_STATUSES = frozenset({"queued", "running"})
TERMINAL_REBIND_STATUSES = frozenset({"success", "partial_success", "failed", "stopped"})
CHAT_ORIGIN = "https://chatgpt.com"
ELIGIBILITY_PATH = "/backend-api/accounts/change_email/eligibility"
BEGIN_PATH = "/backend-api/accounts/change_email/begin"
VERIFY_PATH = "/backend-api/accounts/change_email/verify"


def _status(response: Any) -> int | None:
    raw = response.get("_status") if isinstance(response, Mapping) else getattr(response, "status_code", None)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _json(response: Any) -> dict[str, Any]:
    try:
        value = response.json() if hasattr(response, "json") else response
    except Exception:
        value = {}
    return dict(value) if isinstance(value, Mapping) else {}


def _response_value(response: Any, *keys: str) -> str:
    if not isinstance(response, Mapping):
        return ""
    for key in keys:
        value = response.get(key)
        if value:
            return str(value).strip()
    page = response.get("page")
    if isinstance(page, Mapping):
        for key in keys:
            value = page.get(key)
            if value:
                return str(value).strip()
    return ""


def _response_page_type(module: Any, response: Any) -> str:
    try:
        value = module._page_type(response)
        if value:
            return str(value).strip().lower().replace("-", "_")
    except Exception:
        pass
    return _response_value(response, "page_type", "pageType", "type").lower().replace("-", "_")


def _continue_url(module: Any, response: Any) -> str:
    try:
        value = module._continue_url(response)
        if value:
            return str(value).strip()
    except Exception:
        pass
    return _response_value(response, "continue_url", "continueUrl", "redirect_url", "url")


def _response_text(response: Any) -> str:
    if isinstance(response, Mapping):
        return str(response.get("error") or response.get("message") or response.get("detail") or "")
    return str(getattr(response, "text", "") or "")[:500]


def _factor_id(value: Any) -> str:
    """Extract only an MFA factor id or an id embedded in an MFA URL."""
    if isinstance(value, Mapping):
        for key in ("factor_id", "factorId", "mfa_factor_id"):
            candidate = str(value.get(key) or "").strip()
            if candidate:
                return candidate
        for key, nested in value.items():
            if key in {"url", "continue_url", "continueUrl", "redirect_url", "location"}:
                match = re.search(r"/mfa-challenge/([0-9a-fA-F]{16,64})", str(nested or ""))
                if match:
                    return match.group(1)
            found = _factor_id(nested)
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for nested in value:
            found = _factor_id(nested)
            if found:
                return found
    elif isinstance(value, str):
        match = re.search(r"/mfa-challenge/([0-9a-fA-F]{16,64})", value)
        if match:
            return match.group(1)
    return ""


def _call_wait(provider: Any, email: str, stage_code: str) -> str:
    waiter = getattr(provider, "wait_code", None)
    if not callable(waiter):
        raise FreeRegisterError(stage_code, REBIND_STAGE_LABELS[stage_code], "邮箱取件 Provider 缺少 wait_code 方法", retryable=False)
    try:
        inspect.signature(waiter).bind(email, stage_code=stage_code)
    except (TypeError, ValueError):
        return str(waiter(email) or "").strip()
    return str(waiter(email, stage_code=stage_code) or "").strip()


class FreeRebindService:
    """Persistent, manually paired rebind queue."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        free_manager: Any,
        config_provider: Callable[[], Mapping[str, Any]] | None = None,
        log_fn: Callable[..., Any] | None = None,
        transport_factory: Callable[..., Any] | None = None,
        otp_provider_factory: Callable[..., Any] | None = None,
        workers: int = 1,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.pool = RebindMailboxPool(self.data_dir)
        self.tasks_path = self.pool.data_dir / "tasks.json"
        self.free_manager = free_manager
        self.config_provider = config_provider
        self.log_fn = log_fn
        self.transport_factory = transport_factory
        self.otp_provider_factory = otp_provider_factory
        self.workers = max(1, min(2, int(workers or 1)))
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._executor: ThreadPoolExecutor | None = None
        self._futures: set[Future[Any]] = set()
        self._tasks = self._load_tasks()
        self._recover_interrupted_tasks()

    def _load_tasks(self) -> dict[str, dict[str, Any]]:
        try:
            payload = json.loads(self.tasks_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {}
        tasks = payload.get("tasks") if isinstance(payload, Mapping) else {}
        return {str(key): dict(value) for key, value in tasks.items() if isinstance(value, Mapping)} if isinstance(tasks, Mapping) else {}

    def _save_tasks(self) -> None:
        atomic_write(self.tasks_path, {"version": 1, "tasks": self._tasks})

    def _recover_interrupted_tasks(self) -> None:
        """Do not leave a task permanently marked running after a restart."""
        changed = False
        failure = {
            "node_code": "free_rebind_process_recovery",
            "node_label": "恢复换绑任务",
            "error_code": "free_rebind_interrupted",
            "public_message": "恢复换绑任务 [恢复换绑任务/free_rebind_process_recovery]：进程重启，中断任务未完成",
            "technical_summary": "进程重启，中断任务未完成",
            "retryable": True,
        }
        for task in self._tasks.values():
            if str(task.get("status") or "") not in ACTIVE_REBIND_STATUSES:
                continue
            task.update({"status": "failed", "stage": "free_rebind_process_recovery", "error": failure["public_message"], "failure": failure, "updated_at": int(time.time())})
            target_id = str(task.get("target_row_id") or "")
            if target_id:
                self.pool.update(target_id, status="failed", task_id=str(task.get("task_id") or ""), error=failure["public_message"], failure=failure)
            changed = True
        if changed:
            self._save_tasks()

    def _config(self) -> dict[str, Any]:
        try:
            value = self.config_provider() if callable(self.config_provider) else {}
        except Exception:
            value = {}
        return dict(value) if isinstance(value, Mapping) else {}

    def _log(self, message: str, level: str = "info", **fields: Any) -> None:
        if not callable(self.log_fn):
            return
        try:
            self.log_fn(sanitize_log_message(str(message)), level, **fields)
        except TypeError:
            try:
                self.log_fn(sanitize_log_message(str(message)), level)
            except Exception:
                pass
        except Exception:
            pass

    def _set_task(self, task_id: str, **values: Any) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return {}
            task.update(values)
            task["updated_at"] = int(time.time())
            self._save_tasks()
            return dict(task)

    def _stage(self, task_id: str, stage: str) -> None:
        self._set_task(task_id, stage=stage)
        self._log(
            f"[{task_id}/{REBIND_STAGE_LABELS.get(stage, stage)}/{stage}] 开始",
            "info", task_id=task_id, node_code=stage,
            node_label=REBIND_STAGE_LABELS.get(stage, stage),
        )

    def _check_stop(self) -> None:
        if self._stop.is_set():
            raise FreeRegisterError("free_rebind_stop", "停止换绑", "换绑任务已停止", retryable=False)

    def _source_rows(self) -> list[dict[str, Any]]:
        pool = getattr(self.free_manager, "pool", None)
        if pool is None:
            return []
        rows = pool.entries() if callable(getattr(pool, "entries", None)) else []
        result_rows: list[dict[str, Any]] = []
        for row in rows:
            saved = pool.result(row.row_id) if callable(getattr(pool, "result", None)) else {}
            private = pool._row_state(row.row_id) if callable(getattr(pool, "_row_state", None)) else {}
            password = str(saved.get("password") or "").strip()
            totp = str(saved.get("totp_secret") or "").strip()
            if not password or not totp:
                continue
            source_status = str(private.get("status") or "available")
            if source_status not in {"success", "partial_success", "available"}:
                continue
            result_rows.append({
                "row_id": row.row_id,
                "email": str(saved.get("rebind_email") or row.email),
                "driver": str(saved.get("driver") or private.get("driver") or ""),
                "status": source_status,
                "plan_type": str(saved.get("subscription_plan") or saved.get("plan_type") or ""),
                "plus_trial_eligible": bool(saved.get("plus_trial_eligible")),
                "has_password": True,
                "has_totp": True,
                "proxy_masked": mask_proxy(saved.get("proxy") or private.get("proxy") or ""),
                "rebind_email": str(saved.get("rebind_email") or ""),
                "rebind_status": str(saved.get("rebind_status") or ""),
            })
        return result_rows

    def public_sources(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._source_rows())

    def public_tasks(self) -> list[dict[str, Any]]:
        with self._lock:
            rows: list[dict[str, Any]] = []
            for task in sorted(self._tasks.values(), key=lambda item: int(item.get("created_at") or 0), reverse=True):
                public = {key: copy.deepcopy(task.get(key)) for key in (
                    "task_id", "source_row_id", "source_email", "target_row_id", "target_email",
                    "new_bound_email", "status", "stage", "created_at", "updated_at", "proxy_masked",
                    "plan_type", "subscription_plan", "plus_trial_eligible", "plan_check_status",
                    "plan_failure",
                ) if key in task}
                public["stage_label"] = REBIND_STAGE_LABELS.get(str(public.get("stage") or ""), str(public.get("stage") or ""))
                failure = canonical_failure(task.get("failure") if isinstance(task.get("failure"), Mapping) else None)
                if failure:
                    public["failure"] = failure
                    public["error"] = failure.get("public_message", "")
                elif task.get("error"):
                    public["error"] = str(task.get("error"))[:300]
                rows.append(public)
            return rows

    def public_state(self) -> dict[str, Any]:
        tasks = self.public_tasks()
        return {
            "running": any(task.get("status") in ACTIVE_REBIND_STATUSES for task in tasks),
            "tasks": tasks,
            "sources": self.public_sources(),
            "mailboxes": self.pool.public_rows(),
            "summary": {
                "total": len(tasks),
                "active": sum(task.get("status") in ACTIVE_REBIND_STATUSES for task in tasks),
                "success": sum(task.get("status") == "success" for task in tasks),
                "partial_success": sum(task.get("status") == "partial_success" for task in tasks),
                "failed": sum(task.get("status") == "failed" for task in tasks),
                "stopped": sum(task.get("status") == "stopped" for task in tasks),
            },
        }

    def import_mailboxes(self, content: str) -> tuple[int, int]:
        return self.pool.import_text_with_stats(content)

    def delete_mailboxes(self, row_ids: Sequence[str]) -> int:
        return self.pool.delete(row_ids)

    def set_mailbox_status(self, row_ids: Sequence[str], status: str) -> int:
        return self.pool.set_status(row_ids, status)

    def _source_context(self, source_row_id: str) -> dict[str, Any]:
        pool = getattr(self.free_manager, "pool", None)
        row = pool.entry(source_row_id) if pool is not None else None
        if row is None:
            raise FreeRegisterError("free_rebind_source", "读取换绑源账号", "源账号不存在或已变化", retryable=False)
        saved = pool.result(source_row_id)
        private = pool._row_state(source_row_id) if callable(getattr(pool, "_row_state", None)) else {}
        source_status = str(private.get("status") or "available")
        if source_status not in {"success", "partial_success", "available"}:
            raise FreeRegisterError("free_rebind_source", "读取换绑源账号", "源账号当前不可用于换绑", retryable=False, error_code="free_rebind_source_unavailable")
        password = str(saved.get("password") or "").strip()
        totp = str(saved.get("totp_secret") or "").strip()
        if not password or not totp:
            raise FreeRegisterError("free_rebind_source", "读取换绑源账号", "源账号必须已有密码和已启用 TOTP", retryable=False, error_code="free_rebind_credentials_missing")
        proxy = str(saved.get("proxy") or private.get("proxy") or "").strip()
        login_email = str(saved.get("rebind_email") or row.email).strip()
        return {
            "row_id": row.row_id,
            "email": row.email,
            "login_email": login_email,
            "password": password,
            "totp_secret": totp,
            "proxy": proxy,
            "proxy_id": str(saved.get("proxy_id") or private.get("proxy_id") or ""),
            "proxy_scheme": str(saved.get("proxy_scheme") or private.get("proxy_scheme") or ""),
            "proxy_country": str(saved.get("proxy_country") or private.get("proxy_country") or ""),
            "proxy_group": str(saved.get("proxy_group") or private.get("proxy_group") or ""),
            "proxy_masked": mask_proxy(proxy),
            "saved": saved,
        }

    def start(self, source_row_id: str, target_row_id: str) -> dict[str, Any]:
        source = self._source_context(str(source_row_id or "").strip().lower())
        target = self.pool.entry(str(target_row_id or "").strip().lower())
        if target is None:
            raise FreeRegisterError("free_rebind_target", "读取换绑目标邮箱", "目标邮箱不存在或已变化", retryable=False)
        if source["login_email"].casefold() == target.email.casefold():
            raise FreeRegisterError("free_rebind_target", "读取换绑目标邮箱", "目标邮箱不能与当前账号相同", retryable=False)
        with self._lock:
            for task in self._tasks.values():
                if task.get("status") in ACTIVE_REBIND_STATUSES and (task.get("source_row_id") == source["row_id"] or task.get("target_row_id") == target.row_id):
                    raise FreeRegisterError("free_rebind_start", "启动邮箱换绑", "源账号或目标邮箱已有运行中的换绑任务", retryable=False)
            task_id = f"rebind-{int(time.time())}-{secrets.token_hex(4)}"
            now = int(time.time())
            task = {
                "task_id": task_id,
                "source_row_id": source["row_id"],
                "source_email": source["login_email"],
                "target_row_id": target.row_id,
                "target_email": target.email,
                "new_bound_email": "",
                "status": "queued",
                "stage": "free_rebind_proxy",
                "created_at": now,
                "updated_at": now,
                "proxy_masked": source["proxy_masked"],
                "result": {},
            }
            self.pool.reserve(target.row_id, task_id)
            try:
                self._tasks[task_id] = task
                self._save_tasks()
                self._stop.clear()
                if self._executor is None:
                    self._executor = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="free-rebind")
                future = self._executor.submit(self._worker, task_id)
            except Exception:
                self._tasks.pop(task_id, None)
                try:
                    self.pool.update(target.row_id, status="available", task_id="", error="")
                except Exception:
                    pass
                try:
                    self._save_tasks()
                except Exception:
                    pass
                raise
            self._futures.add(future)
            future.add_done_callback(self._future_done)
            return next(row for row in self.public_tasks() if row.get("task_id") == task_id)

    def retry(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(str(task_id or ""))
            if not task or task.get("status") not in TERMINAL_REBIND_STATUSES:
                raise FreeRegisterError("free_rebind_retry", "重试邮箱换绑", "只有已结束的换绑任务可以重试", retryable=False)
            target_row_id = str(task.get("target_row_id") or "")
            self.pool.reserve(target_row_id, str(task.get("task_id") or ""))
            task.update({"status": "queued", "stage": "free_rebind_proxy", "error": "", "failure": None, "updated_at": int(time.time())})
            try:
                self._save_tasks()
                self._stop.clear()
                if self._executor is None:
                    self._executor = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="free-rebind")
                future = self._executor.submit(self._worker, str(task["task_id"]))
            except Exception:
                task.update({"status": "failed", "stage": "free_rebind_result", "error": "换绑任务未能重新排队"})
                try:
                    self.pool.update(target_row_id, status="failed", task_id=str(task.get("task_id") or ""), error="换绑任务未能重新排队")
                    self._save_tasks()
                except Exception:
                    pass
                raise
            self._futures.add(future)
            future.add_done_callback(self._future_done)
            return next(row for row in self.public_tasks() if row.get("task_id") == task["task_id"])

    def stop(self) -> None:
        self._stop.set()

    def _future_done(self, future: Future[Any]) -> None:
        with self._lock:
            self._futures.discard(future)

    def _choose_proxy(self, source: Mapping[str, Any], config: Mapping[str, Any], task_id: str) -> tuple[str, Any | None]:
        original = str(source.get("proxy") or "").strip()
        if original:
            return original, None
        proxies = getattr(self.free_manager, "proxies", None)
        binder = getattr(proxies, "bind", None)
        if not callable(binder):
            raise FreeRegisterError("free_rebind_proxy", "准备换绑协议代理", "源账号没有注册代理且共享 Free 代理池不可用", retryable=False)
        bindings = binder(1, probe=getattr(self.free_manager, "proxy_probe", None), probe_url=str(config.get("proxy_probe_url") or "https://api.ipify.org"), driver="protocol")
        if not bindings:
            raise FreeRegisterError("free_rebind_proxy", "准备换绑协议代理", "共享 Free 代理池没有健康代理", retryable=False)
        binding = bindings[0]
        lease = getattr(proxies, "lease", None)
        if callable(lease) and str(getattr(binding, "proxy_id", "") or ""):
            lease(binding, owner=task_id, batch_id=task_id, task_id=task_id, lease_seconds=300)
        return str(binding.proxy), binding

    def _build_transport(self, email: str, proxy: str, config: Mapping[str, Any], task_id: str, log: Callable[..., Any]) -> tuple[Any, str, dict[str, Any]]:
        if self.transport_factory is not None:
            value = self.transport_factory(email=email, proxy=proxy, config=config, task_id=task_id, log_fn=log)
            return value
        import codex_chain_runner
        import codex_oauth_chain

        oauth_url, state, verifier = codex_chain_runner.build_oauth_url(login_hint=email, screen_hint="login", prompt="login")
        params = codex_oauth_chain.parse_oauth_url(oauth_url)
        device_id = f"free-rebind-{secrets.token_hex(16)}"
        chain_config = dict(config)
        protocol = dict(config.get("protocol") or {}) if isinstance(config.get("protocol"), Mapping) else {}
        chain_config.update({
            "run_mode": "free_rebind",
            "codex_chain_mode": "real",
            "codex_node_runner": str(protocol.get("node_runner") or ""),
            "free_protocol_state_machine": True,
            "_auth_account_email": email,
        })
        sentinel = codex_oauth_chain.RealNodeSentinelProvider(
            config=chain_config,
            device_id=device_id,
            proxy_label=fingerprint(proxy),
            proxy=proxy,
            log_fn=log,
        )
        transport = codex_oauth_chain.RealCodexTransport(
            chain_config, oauth_params=params, proxy=proxy,
            sentinel_provider=sentinel, device_id=device_id, log_fn=log,
        )
        return transport, oauth_url, {"state": state, "verifier": verifier, "params": params, "device_id": device_id}

    @staticmethod
    def _close_transport(transport: Any) -> None:
        for candidate in (getattr(transport, "session", None), transport):
            close = getattr(candidate, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

    def _verify_totp_protocol(self, transport: Any, response: Any, totp_secret: str, *, stage_code: str) -> Any:
        """Verify TOTP through Auth's MFA challenge endpoints.

        ``RealCodexTransport.verify_mfa_otp`` is intentionally not used here:
        that method targets the email-OTP endpoint used by the registration
        state machine, while rebind requires the account's TOTP factor.
        """
        factor_id = _factor_id(response)
        session = getattr(transport, "session", None)
        if not factor_id or session is None or not callable(getattr(session, "post", None)):
            # Test doubles may model MFA as a transport method. Production
            # RealCodexTransport always has the session and factor envelope.
            fallback = getattr(transport, "verify_mfa_otp", None)
            if callable(fallback):
                return fallback(self._totp_code(totp_secret))
            raise FreeRegisterError(stage_code, REBIND_STAGE_LABELS.get(stage_code, "密码 + TOTP 登录"), "password/verify 后没有可用 TOTP factor", retryable=False, error_code="free_rebind_totp_factor_missing")
        referer = f"https://auth.openai.com/mfa-challenge/{factor_id}"
        headers_factory = getattr(transport, "_headers", None)
        if callable(headers_factory):
            headers = dict(headers_factory("mfa_otp_verify", referer))
        else:
            headers = {"accept": "application/json", "content-type": "application/json", "referer": referer, "oai-device-id": str(getattr(transport, "device_id", "") or "")}
        headers.update({"content-type": "application/json", "origin": "https://auth.openai.com"})
        issue = session.post(
            "https://auth.openai.com/api/accounts/mfa/issue_challenge",
            json={"factor_id": factor_id}, headers=headers, timeout=30,
        )
        if _status(issue) is not None and not 200 <= int(_status(issue)) < 300:
            raise FreeRegisterError(stage_code, REBIND_STAGE_LABELS.get(stage_code, "密码 + TOTP 登录"), f"TOTP challenge 返回 HTTP {_status(issue)}", provider_status=_status(issue), error_code="free_rebind_totp_challenge_failed")
        code = self._totp_code(totp_secret)
        verified = session.post(
            "https://auth.openai.com/api/accounts/mfa/verify",
            json={"factor_id": factor_id, "code": code}, headers=headers, timeout=30,
        )
        if _status(verified) is not None and not 200 <= int(_status(verified)) < 300:
            raise FreeRegisterError(stage_code, REBIND_STAGE_LABELS.get(stage_code, "密码 + TOTP 登录"), f"TOTP 验证返回 HTTP {_status(verified)}", provider_status=_status(verified), error_code="free_rebind_totp_verify_failed")
        return _json(verified)

    def _advance_password_mfa(self, transport: Any, response: Any, password: str, totp_secret: str, *, email: str, task_id: str, log: Callable[..., Any]) -> Any:
        try:
            import codex_oauth_chain
        except ImportError:  # injected transports in unit/integration tests
            codex_oauth_chain = None
        for _ in range(8):
            self._check_stop()
            page = _response_page_type(codex_oauth_chain, response)
            if page in {"password", "password_verification", "email_password", "login_password"}:
                self._stage(task_id, "free_rebind_login_old" if email == self._tasks.get(task_id, {}).get("source_email") else "free_rebind_login_new")
                response = transport.verify_password(password)
                continue
            if page in {"mfa_otp", "mfa_challenge", "mfa_otp_verification", "totp", "totp_verification"}:
                stage_code = "free_rebind_login_old" if email == self._tasks.get(task_id, {}).get("source_email") else "free_rebind_login_new"
                response = self._verify_totp_protocol(transport, response, totp_secret, stage_code=stage_code)
                continue
            if page in {"consent", "consent_required", "sign_in_with_chatgpt_codex_consent"}:
                accept = getattr(transport, "accept_consent", None)
                if not callable(accept):
                    break
                response = accept(_continue_url(codex_oauth_chain, response))
                continue
            return response
        return response

    @staticmethod
    def _totp_code(secret: str, now: float | None = None) -> str:
        try:
            from .chatgpt_totp import totp_code
        except ImportError:
            from chatgpt_totp import totp_code  # type: ignore[no-redef]
        return totp_code(secret, now=now)

    def _login(self, transport: Any, oauth_url: str, email: str, password: str, totp_secret: str, task_id: str, log: Callable[..., Any]) -> str:
        try:
            import codex_oauth_chain
        except ImportError:  # injected transports in unit/integration tests
            codex_oauth_chain = None
        response = transport.initiate_oauth(oauth_url)
        response = transport.submit_email_identifier(email)
        response = self._advance_password_mfa(transport, response, password, totp_secret, email=email, task_id=task_id, log=log)
        for _ in range(8):
            self._check_stop()
            token = str(getattr(transport, "chatgpt_access_token", lambda: "")() or "").strip()
            if token:
                return token
            continue_url = _continue_url(codex_oauth_chain, response)
            if continue_url:
                complete = getattr(transport, "complete_chatgpt_callback", None)
                if callable(complete):
                    response = complete(continue_url)
                    response = self._advance_password_mfa(transport, response, password, totp_secret, email=email, task_id=task_id, log=log)
                    continue
            page = _response_page_type(codex_oauth_chain, response)
            if page in {"email_otp", "email_verification", "email_otp_verification"}:
                raise FreeRegisterError("free_rebind_login_old", "密码 + TOTP 登录", "登录流程要求邮箱验证码，换绑只允许密码 + TOTP", retryable=False, error_code="free_rebind_email_otp_required")
            break
        raise FreeRegisterError("free_rebind_login_old", "密码 + TOTP 登录", "协议登录完成后没有刷新 Session", error_code="free_rebind_session_missing")

    def _change_headers(self, transport: Any, path: str, token: str, *, json_body: bool = False) -> dict[str, str]:
        device_id = str(getattr(transport, "device_id", "") or "")
        headers = {
            "authorization": f"Bearer {token}",
            "accept": "*/*",
            "referer": f"{CHAT_ORIGIN}/",
            "oai-device-id": device_id,
            "oai-session-id": str(getattr(transport, "_gptphone_rebind_session_id", "") or ""),
            "oai-language": "zh-CN",
            "x-openai-target-path": path,
            "x-openai-target-route": path,
        }
        if path != ELIGIBILITY_PATH:
            try:
                from .chatgpt_plan_gate import token_claims
            except ImportError:
                from chatgpt_plan_gate import token_claims  # type: ignore[no-redef]
            account_id = str(token_claims(token).get("account_id") or "").strip()
            if account_id:
                headers["chatgpt-account-id"] = account_id
        if json_body:
            headers.update({"content-type": "application/json", "origin": CHAT_ORIGIN})
        return {key: value for key, value in headers.items() if value}

    def _session_request(self, transport: Any, method: str, path: str, token: str, *, payload: Mapping[str, Any] | None = None) -> Any:
        session = getattr(transport, "session", None)
        if session is None:
            raise FreeRegisterError("free_rebind_session", "换绑协议会话", "认证 HTTP 会话不可用", retryable=False)
        url = urljoin(CHAT_ORIGIN, path)
        headers = self._change_headers(transport, path, token, json_body=payload is not None)
        request = getattr(session, method.lower(), None)
        if not callable(request):
            raise FreeRegisterError("free_rebind_session", "换绑协议会话", "认证 HTTP 会话不支持请求方法", retryable=False)
        kwargs: dict[str, Any] = {"headers": headers, "timeout": 30}
        if payload is not None:
            kwargs["json"] = dict(payload)
        return request(url, **kwargs)

    def _run_protocol_rebind(self, task_id: str, source: Mapping[str, Any], target: Any, proxy: str, config: Mapping[str, Any]) -> dict[str, Any]:
        log = lambda message, level="info": self._log(f"[{task_id}] {message}", level, task_id=task_id)
        otp = None
        transport = None
        new_transport = None
        try:
            self._stage(task_id, "free_rebind_login_old")
            transport, oauth_url, _context = self._build_transport(str(source["login_email"]), proxy, config, task_id, log)
            setattr(transport, "_gptphone_rebind_session_id", f"rebind-{secrets.token_hex(12)}")
            token = self._login(transport, oauth_url, str(source["login_email"]), str(source["password"]), str(source["totp_secret"]), task_id, log)
            self._stage(task_id, "free_rebind_eligibility")
            eligibility = self._session_request(transport, "GET", ELIGIBILITY_PATH, token)
            eligibility_data = _json(eligibility)
            if _status(eligibility) not in (None, 200) or eligibility_data.get("eligible") is not True:
                raise FreeRegisterError("free_rebind_eligibility", "检查换绑资格", "账号当前不满足 change_email eligibility", retryable=False, provider_status=_status(eligibility), error_code="free_rebind_not_eligible")

            self._stage(task_id, "free_rebind_begin")
            otp = (self.otp_provider_factory(target.mailbox_url, proxy, config=config, task_id=task_id, stage_fn=lambda _task, code: self._stage(task_id, code)) if self.otp_provider_factory else build_free_mailbox_otp_provider(target.mailbox_url, proxy, config, log_fn=log, task_id=task_id, stage_fn=lambda _task, code: self._stage(task_id, code)))
            prepare = getattr(otp, "prepare", None)
            if callable(prepare):
                prepare("free_rebind_otp", force_snapshot=True)
            begin = self._session_request(transport, "POST", BEGIN_PATH, token, payload={"email": target.email})
            begin_status = _status(begin)
            if begin_status not in (None, 200) and begin_status not in {201, 202}:
                detail = _response_text(begin).lower()
                if begin_status in {401, 403} or "recent" in detail or "reauth" in detail:
                    response = transport.verify_password(str(source["password"]))
                    self._advance_password_mfa(transport, response, str(source["password"]), str(source["totp_secret"]), email=str(source["login_email"]), task_id=task_id, log=log)
                    token = str(getattr(transport, "chatgpt_access_token", lambda: "")() or token)
                    begin = self._session_request(transport, "POST", BEGIN_PATH, token, payload={"email": target.email})
                    begin_status = _status(begin)
                if begin_status not in (None, 200, 201, 202):
                    raise FreeRegisterError("free_rebind_begin", "发送新邮箱验证码", f"change_email begin 返回 HTTP {begin_status or '-'}", provider_status=begin_status, error_code="free_rebind_begin_failed")
            mark_sent = getattr(otp, "mark_sent", None)
            if callable(mark_sent):
                mark_sent("free_rebind_otp")
            self._stage(task_id, "free_rebind_otp")
            code = _call_wait(otp, target.email, "free_rebind_otp")
            self._stage(task_id, "free_rebind_verify")
            verified = self._session_request(transport, "POST", VERIFY_PATH, token, payload={"email": target.email, "code": code})
            verify_status = _status(verified)
            if verify_status not in (None, 200, 201, 202):
                raise FreeRegisterError("free_rebind_verify", "验证换绑邮箱", f"change_email verify 返回 HTTP {verify_status or '-'}", provider_status=verify_status, error_code="free_rebind_verify_failed")

            self._close_transport(transport)
            transport = None
            self._stage(task_id, "free_rebind_login_new")
            new_transport, new_oauth_url, _new_context = self._build_transport(target.email, proxy, config, task_id, log)
            setattr(new_transport, "_gptphone_rebind_session_id", f"rebind-{secrets.token_hex(12)}")
            new_token = self._login(new_transport, new_oauth_url, target.email, str(source["password"]), str(source["totp_secret"]), task_id, log)
            self._stage(task_id, "free_rebind_plan")
            try:
                plan_type, plus_eligible = self.free_manager._plan_check(new_transport, new_token)
                plan_values = {
                    "plan_type": plan_type,
                    "subscription_plan": plan_type,
                    "plus_trial_eligible": bool(plus_eligible),
                    "plan_check_status": "success",
                }
            except FreeRegisterError as exc:
                plan_values = {
                    "plan_type": "",
                    "subscription_plan": "",
                    "plus_trial_eligible": False,
                    "plan_check_status": "failed",
                    "plan_failure": exception_to_failure(exc, node_code="free_rebind_plan", node_label="查询套餐与 Plus 资格"),
                }
            return {
                "new_bound_email": target.email,
                "access_token": new_token,
                **plan_values,
                "rebind_completed_at": int(time.time()),
            }
        finally:
            if otp is not None:
                close = getattr(otp, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass
            self._close_transport(new_transport or transport)

    def _worker(self, task_id: str) -> None:
        task = self._set_task(task_id, status="running", stage="free_rebind_proxy")
        if not task:
            return
        fallback_binding = None
        try:
            source = self._source_context(str(task.get("source_row_id") or ""))
            target = self.pool.entry(str(task.get("target_row_id") or ""))
            if target is None:
                raise FreeRegisterError("free_rebind_target", "读取换绑目标邮箱", "目标邮箱不存在或已变化", retryable=False)
            config = self._config()
            proxy, fallback_binding = self._choose_proxy(source, config, task_id)
            self._set_task(task_id, proxy_masked=mask_proxy(proxy))
            result = self._run_protocol_rebind(task_id, source, target, proxy, config)
            self._stage(task_id, "free_rebind_result")
            source_saved = dict(source.get("saved") or {})
            task_status = "partial_success" if result.get("plan_check_status") == "failed" else "success"
            source_saved.update({
                "rebind_email": target.email,
                "rebind_task_id": task_id,
                "rebind_status": task_status,
                "rebind_completed_at": result.get("rebind_completed_at"),
                "rebind_plan_type": result.get("plan_type", ""),
                "rebind_plus_trial_eligible": bool(result.get("plus_trial_eligible")),
            })
            self.free_manager.pool.save_result(str(source["row_id"]), source_saved)
            self._set_task(task_id, status=task_status, stage="free_rebind_result", new_bound_email=target.email, plan_type=result.get("plan_type", ""), subscription_plan=result.get("subscription_plan", ""), plus_trial_eligible=bool(result.get("plus_trial_eligible")), plan_check_status=result.get("plan_check_status", ""), plan_failure=result.get("plan_failure"), result={key: value for key, value in result.items() if key != "access_token"})
            self.pool.update(target.row_id, status="success", task_id=task_id, error="")
        except FreeRegisterError as exc:
            failure = exception_to_failure(exc, node_code=str(getattr(exc, "node_code", "free_rebind_result")), node_label=str(getattr(exc, "node_label", "邮箱换绑")))
            status = "stopped" if str(getattr(exc, "node_code", "")) == "free_rebind_stop" else "failed"
            self._set_task(task_id, status=status, error=failure.get("public_message", ""), failure=failure)
            self.pool.update(str(task.get("target_row_id") or ""), status="failed", task_id=task_id, error=failure.get("public_message", ""), failure=failure)
        except Exception as exc:
            failure = exception_to_failure(exc, node_code="free_rebind_result", node_label="邮箱换绑")
            self._set_task(task_id, status="failed", error=failure.get("public_message", ""), failure=failure)
            self.pool.update(str(task.get("target_row_id") or ""), status="failed", task_id=task_id, error=failure.get("public_message", ""), failure=failure)
        finally:
            if fallback_binding is not None:
                try:
                    self.free_manager.proxies.release(fallback_binding, owner=task_id)
                except Exception:
                    pass


__all__ = ["ACTIVE_REBIND_STATUSES", "REBIND_STAGE_LABELS", "FreeRebindService"]
