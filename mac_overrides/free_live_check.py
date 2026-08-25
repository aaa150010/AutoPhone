"""Isolated fast and deep liveness checks for registered Free accounts."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import copy
import secrets
import threading
import time
from typing import Any, Callable, Mapping, Sequence

try:
    from .free_failure_runtime import canonical_failure, exception_to_failure
    from .free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider
    from .free_register_common import (
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        plus_trial_from_accounts,
        proxy_transport_value,
        safe_log_message,
        timezone_offset_minutes,
    )
except ImportError:
    from free_failure_runtime import canonical_failure, exception_to_failure  # type: ignore[no-redef]
    from free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        plus_trial_from_accounts,
        proxy_transport_value,
        safe_log_message,
        timezone_offset_minutes,
    )


LIVE_MODES = frozenset({"fast", "deep"})
_ORIGINAL_MAILBOX_URL_OTP_PROVIDER = MailboxUrlOtpProvider
ACTIVE_LIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_LIVE_STATUSES = frozenset({"live", "deactivated", "token_expired", "failed"})
LIVE_STAGE_LABELS = {
    "free_live_queued": "Free 账号测活排队",
    "free_live_proxy_verify": "复核账号注册代理",
    "free_live_fast": "快速测活",
    "free_live_deep": "深度测活",
    "free_live_email": "深度测活邮箱验证",
    "free_live_mfa": "深度测活动态口令验证",
    "free_live_plan": "刷新套餐与 Plus 资格",
    "free_live_result": "保存 Free 测活结果",
}


def _status(response: Any) -> int:
    try:
        return int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _json(response: Any) -> dict[str, Any]:
    try:
        value = response.json() if hasattr(response, "json") else {}
    except Exception:
        value = {}
    return dict(value) if isinstance(value, Mapping) else {}


def _campaign_id(value: Any) -> str:
    pending = [value]
    seen: set[int] = set()
    while pending and len(seen) < 100:
        current = pending.pop()
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            for key in ("campaign_id", "campaignId", "id"):
                candidate = str(current.get(key) or "").strip()
                if candidate and ("plus" in str(current).lower() or key != "id"):
                    return candidate[:160]
            pending.extend(current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
    return ""


def _plus_eligible(value: Any) -> bool:
    if plus_trial_from_accounts(value):
        return True
    if isinstance(value, (list, tuple)):
        return any(_plus_eligible(item) for item in value)
    if not isinstance(value, Mapping):
        return False
    campaigns = value.get("eligible_promo_campaigns")
    if isinstance(campaigns, Mapping) and campaigns.get("plus"):
        return True
    return any(_plus_eligible(item) for item in value.values() if isinstance(item, (Mapping, list, tuple)))


def _is_deactivated(value: Any) -> bool:
    try:
        from .runtime_policy import is_account_banned_failure
    except ImportError:
        from runtime_policy import is_account_banned_failure  # type: ignore[no-redef]
    try:
        return bool(is_account_banned_failure(value))
    except Exception:
        return False


def _failure(exc: BaseException, *, default_code: str, default_label: str) -> dict[str, Any]:
    return exception_to_failure(
        exc,
        node_code=str(getattr(exc, "node_code", "") or default_code),
        node_label=str(getattr(exc, "node_label", "") or default_label),
    )


class FreeLiveCheckService:
    """Persistent Free-only liveness queue with fixed-proxy enforcement."""

    def __init__(
        self,
        data_dir: Any,
        *,
        pool: Any,
        proxies: Any,
        log_store: Any,
        config_provider: Callable[[], Mapping[str, Any]] | None = None,
        proxy_probe: Callable[[str, str], str] | None = None,
        task_store: Any = None,
        fast_runner: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]] | None = None,
        deep_runner: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]] | None = None,
        workers: int = 3,
        queue_limit: int = 500,
        recover: bool = True,
    ) -> None:
        from pathlib import Path

        self.path = Path(data_dir).expanduser().resolve() / "free_live_checks.json"
        self.pool = pool
        self.proxies = proxies
        self.log_store = log_store
        self.task_store = task_store
        self.config_provider = config_provider
        self.proxy_probe = proxy_probe
        self.fast_runner = fast_runner or self._run_fast
        self.deep_runner = deep_runner or self._run_deep
        self.workers = max(1, min(int(workers), 5))
        self.queue_limit = max(self.workers, min(int(queue_limit), 5_000))
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="free-live-check")
        self._futures: set[Future[Any]] = set()
        self._jobs = self._load_jobs()
        if recover:
            self._recover_jobs()

    def _load_jobs(self) -> dict[str, dict[str, Any]]:
        import json

        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            value = {}
        jobs = value.get("jobs") if isinstance(value, Mapping) else {}
        if not isinstance(jobs, Mapping):
            return {}
        result: dict[str, dict[str, Any]] = {}
        changed = False
        for key, item in jobs.items():
            if not isinstance(item, Mapping):
                changed = True
                continue
            job = dict(item)
            if isinstance(job.get("failure"), Mapping):
                normalized = canonical_failure(job["failure"])
                if normalized is None:
                    job.pop("failure", None)
                else:
                    job["failure"] = normalized
                changed = changed or job != dict(item)
            result[str(key)] = job
        if changed:
            atomic_write(self.path, {"version": 1, "jobs": result})
        return result

    def _save_jobs(self) -> None:
        atomic_write(self.path, {"version": 1, "jobs": self._jobs})

    def _recover_jobs(self) -> None:
        recovered: list[str] = []
        with self._lock:
            for task_id, job in self._jobs.items():
                if str(job.get("status") or "") not in ACTIVE_LIVE_STATUSES:
                    continue
                job.update({"status": "queued", "recovered": True, "updated_at": int(time.time())})
                recovered.append(task_id)
            if recovered:
                self._save_jobs()
        for task_id in recovered:
            self._submit(task_id)

    def _config(self) -> dict[str, Any]:
        try:
            value = self.config_provider() if callable(self.config_provider) else {}
        except Exception:
            value = {}
        return dict(value) if isinstance(value, Mapping) else {}

    def _log(self, task_id: str, stage: str, message: str, level: str = "info") -> None:
        label = LIVE_STAGE_LABELS.get(stage, stage)
        self.log_store.add(f"[{task_id}/{label}/{stage}] {safe_log_message(message)}", level)

    def _public_job(self, job: Mapping[str, Any]) -> dict[str, Any]:
        keys = (
            "task_id", "row_id", "email", "mode", "status", "stage", "created_at",
            "updated_at", "checked_at", "registration_ip", "live_check_ip",
            "token_refreshed", "recovered",
        )
        result = {key: copy.deepcopy(job[key]) for key in keys if key in job}
        result["stage_label"] = LIVE_STAGE_LABELS.get(str(result.get("stage") or ""), str(result.get("stage") or ""))
        if isinstance(job.get("failure"), Mapping):
            result["failure"] = canonical_failure(job["failure"])
        return result

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            jobs = [self._public_job(job) for job in sorted(self._jobs.values(), key=lambda item: int(item.get("created_at") or 0), reverse=True)]
        active = sum(1 for job in jobs if job.get("status") in ACTIVE_LIVE_STATUSES)
        return {
            "running": active > 0,
            "workers": self.workers,
            "queue_limit": self.queue_limit,
            "active": active,
            "jobs": jobs,
        }

    def enqueue(self, row_ids: Sequence[str], mode: str) -> dict[str, Any]:
        selected_mode = str(mode or "").strip().lower()
        if selected_mode not in LIVE_MODES:
            raise FreeRegisterError("free_live_start", "启动 Free 账号测活", "测活方式只能选择快速测活或深度测活", retryable=False)
        requested = list(dict.fromkeys(str(value or "").strip().lower() for value in row_ids if str(value or "").strip()))
        if not requested:
            raise FreeRegisterError("free_live_start", "启动 Free 账号测活", "请先选择要测活的 Free 账号", retryable=False)

        entries = {row.row_id: row for row in self.pool.entries()}
        accepted: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        submit_ids: list[str] = []
        with self._lock:
            active_rows = {
                str(job.get("row_id") or "")
                for job in self._jobs.values()
                if str(job.get("status") or "") in ACTIVE_LIVE_STATUSES
            }
            active_count = len(active_rows)
            for row_id in requested:
                if active_count >= self.queue_limit:
                    skipped.append({"row_id": row_id, "reason": "测活队列已满"})
                    continue
                entry = entries.get(row_id)
                if entry is None:
                    skipped.append({"row_id": row_id, "reason": "Free 邮箱行不存在或已变化"})
                    continue
                if row_id in active_rows:
                    skipped.append({"row_id": row_id, "reason": "该账号正在测活"})
                    continue
                registration_state = self.pool._row_state(row_id)
                if str(registration_state.get("status") or "") in {"reserved", "queued", "running"}:
                    skipped.append({"row_id": row_id, "reason": "该账号仍在注册中"})
                    continue
                result = self.pool.result(row_id)
                if not result.get("access_token"):
                    skipped.append({"row_id": row_id, "reason": "该账号没有可用 Token"})
                    continue
                proxy = str(result.get("proxy") or registration_state.get("proxy") or "").strip()
                registration_ip = str(result.get("registration_ip") or result.get("expected_exit_ip") or registration_state.get("registration_ip") or registration_state.get("expected_exit_ip") or "").strip()
                if not proxy or not registration_ip:
                    skipped.append({"row_id": row_id, "reason": "该账号缺少注册代理或注册 IP"})
                    continue
                now = int(time.time())
                task_id = f"free-live-{selected_mode}-{now}-{secrets.token_hex(4)}"
                job = {
                    "task_id": task_id,
                    "row_id": row_id,
                    "email": entry.email,
                    "mode": selected_mode,
                    "status": "queued",
                    "stage": "free_live_queued",
                    "created_at": now,
                    "updated_at": now,
                    "registration_ip": registration_ip,
                    "live_check_ip": "",
                    "token_refreshed": False,
                }
                self._jobs[task_id] = job
                active_rows.add(row_id)
                active_count += 1
                submit_ids.append(task_id)
                accepted.append(self._public_job(job))
                updated = dict(result)
                updated.update({
                    "live_check_status": "queued",
                    "live_check_mode": selected_mode,
                    "live_check_task_id": task_id,
                    "live_check_failure": None,
                    "live_check_token_refreshed": False,
                })
                self.pool.save_result(row_id, updated)
                self._log(task_id, "free_live_queued", f"{entry.email} 已加入{'快速' if selected_mode == 'fast' else '深度'}测活队列")
            self._save_jobs()
        for task_id in submit_ids:
            self._submit(task_id)
        return {"accepted": accepted, "accepted_count": len(accepted), "skipped": skipped, "skipped_count": len(skipped), "state": self.public_state()}

    def _submit(self, task_id: str) -> None:
        try:
            future = self._executor.submit(self._worker, task_id)
        except Exception as exc:
            self._finish_exception(task_id, exc, code="free_live_queue", label="启动 Free 账号测活")
            return
        with self._lock:
            self._futures.add(future)
        future.add_done_callback(self._future_done)

    def _future_done(self, future: Future[Any]) -> None:
        with self._lock:
            self._futures.discard(future)

    def _context(self, job: Mapping[str, Any]) -> dict[str, Any]:
        row_id = str(job.get("row_id") or "")
        entry = self.pool.entry(row_id)
        if entry is None:
            raise FreeRegisterError("free_live_account", "读取 Free 测活账号", "Free 邮箱行不存在或已变化", retryable=False)
        result = self.pool.result(row_id)
        private_state = self.pool._row_state(row_id)
        proxy = str(result.get("proxy") or private_state.get("proxy") or "").strip()
        registration_ip = str(result.get("registration_ip") or result.get("expected_exit_ip") or private_state.get("registration_ip") or private_state.get("expected_exit_ip") or "").strip()
        if not proxy or not registration_ip:
            raise FreeRegisterError("free_live_proxy_verify", "复核账号注册代理", "账号缺少注册时固定代理或注册 IP", retryable=False)
        return {
            "task_id": str(job.get("task_id") or ""),
            "row_id": row_id,
            "email": entry.email,
            "mailbox_url": entry.mailbox_url,
            "proxy": proxy,
            "proxy_id": str(result.get("proxy_id") or private_state.get("proxy_id") or ""),
            "proxy_scheme": str(result.get("proxy_scheme") or private_state.get("proxy_scheme") or ""),
            "proxy_country": str(result.get("proxy_country") or private_state.get("proxy_country") or ""),
            "proxy_group": str(result.get("proxy_group") or private_state.get("proxy_group") or ""),
            "proxy_masked": mask_proxy(proxy),
            "proxy_fingerprint": fingerprint(proxy),
            "registration_ip": registration_ip,
            "access_token": str(result.get("access_token") or ""),
            "password": str(result.get("password") or ""),
            "totp_secret": str(result.get("totp_secret") or ""),
            "saved_result": result,
        }

    @staticmethod
    def _binding(context: Mapping[str, Any]) -> ProxyBinding:
        return ProxyBinding(
            str(context.get("proxy") or ""),
            str(context.get("proxy_fingerprint") or ""),
            str(context.get("proxy_masked") or ""),
            str(context.get("registration_ip") or ""),
            proxy_id=str(context.get("proxy_id") or ""),
            scheme=str(context.get("proxy_scheme") or ""),
            country=str(context.get("proxy_country") or ""),
            group=str(context.get("proxy_group") or ""),
        )

    def _verify_fixed_proxy(self, binding: ProxyBinding, config: Mapping[str, Any]) -> str:
        try:
            current = self.proxies.verify(
                binding,
                probe=self.proxy_probe,
                probe_url=str(config.get("proxy_probe_url") or "https://api.ipify.org"),
            )
        except Exception as exc:
            raise FreeRegisterError(
                "free_live_proxy_verify",
                "复核账号注册代理",
                safe_log_message(exc) or "固定代理出口复核失败",
                retryable=bool(getattr(exc, "retryable", True)),
                provider_status=getattr(exc, "provider_status", None),
                error_code=str(getattr(exc, "error_code", "") or "free_live_proxy_verify_failed"),
            ) from exc
        return str(current)

    def _set_job(self, task_id: str, **values: Any) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(task_id)
            if job is None:
                return {}
            job.update(values)
            job["updated_at"] = int(time.time())
            self._save_jobs()
            return dict(job)

    def _save_live_result(self, row_id: str, values: Mapping[str, Any]) -> dict[str, Any]:
        current = self.pool.result(row_id)
        current.update(copy.deepcopy(dict(values)))
        # A registration can be complete while only the first plan request
        # failed.  Once any later result confirms the plan, clear that stale
        # plan-only partial status.  The live request itself may fail after
        # the plan was refreshed (for example, a fixed proxy can return 403),
        # but that must not reclassify an otherwise complete registration.
        failure = current.get("failure") if isinstance(current.get("failure"), Mapping) else {}
        failure_code = str(failure.get("error_code") or current.get("plan_error_code") or "")
        promoted = False
        if (
            str(current.get("status") or "") == "partial_success"
            and str(current.get("plan_check_status") or "") == "success"
            and failure_code.startswith("free_plan_")
        ):
            promoted = True
            current["status"] = "success"
            current.pop("failure", None)
            current.pop("error", None)
            for key in ("plan_failure", "plan_error_code", "plan_error_detail", "plan_provider_code"):
                current.pop(key, None)
        self.pool.save_result(row_id, current)
        if promoted:
            # The mailbox pool has its own task status used by the UI. Keep it
            # in sync with the normalized result instead of leaving a stale
            # partial_success row after a successful plan refresh.
            try:
                self.pool.update(row_id, status="success", stage="free_live_result", error="", failure=None)
            except Exception:
                # Result persistence remains authoritative if a legacy/test
                # pool does not expose the optional status update API.
                pass
            task_id = str(current.get("task_id") or "")
            if task_id and self.task_store is not None:
                try:
                    tasks = self.task_store.load()
                    task = tasks.get(task_id)
                    if isinstance(task, dict) and str(task.get("status") or "") == "partial_success":
                        task.update({"status": "success", "stage": "free_result_save", "error": ""})
                        task.pop("failure", None)
                        task["result"] = copy.deepcopy(current)
                        self.task_store.save(tasks)
                except Exception:
                    # Keep the result file and mailbox row authoritative when
                    # reading legacy task snapshots is not possible.
                    pass
        return current

    def _worker(self, task_id: str) -> None:
        job = self._set_job(task_id, status="running", stage="free_live_proxy_verify")
        if not job:
            return
        binding: ProxyBinding | None = None
        lease_owner = task_id
        context: dict[str, Any] = {}
        try:
            config = self._config()
            context = self._context(job)
            self._log(task_id, "free_live_proxy_verify", f"使用注册代理 {context['proxy_masked']} 复核出口 IP")
            binding = self._binding(context)
            if binding.proxy_id:
                self.proxies.lease(binding, owner=lease_owner, batch_id=lease_owner, task_id=task_id)
            live_ip = self._verify_fixed_proxy(binding, config)
            # A healthy proxy may rotate its egress during a long-lived
            # account check. Continue with the verified current IP.
            context["registration_ip"] = live_ip
            mode = str(job.get("mode") or "fast")
            stage = "free_live_fast" if mode == "fast" else "free_live_deep"
            self._set_job(task_id, stage=stage, live_check_ip=live_ip)
            self._log(task_id, stage, f"固定代理出口已确认：{live_ip}")
            runner = self.fast_runner if mode == "fast" else self.deep_runner
            checked = dict(runner(context, config))
            status = str(checked.get("status") or "").strip().lower()
            if status not in TERMINAL_LIVE_STATUSES:
                raise FreeRegisterError(stage, LIVE_STAGE_LABELS[stage], "测活执行器未返回有效状态")
            checked_at = int(time.time())
            failure = checked.get("failure") if isinstance(checked.get("failure"), Mapping) else None
            token = str(checked.get("access_token") or "")
            token_refreshed = bool(mode == "deep" and status == "live" and token)
            result_values = {
                "live_check_status": status,
                "live_check_mode": mode,
                "live_check_task_id": task_id,
                "live_checked_at": checked_at,
                "live_check_ip": live_ip,
                "expected_exit_ip": live_ip,
                "exit_ip": live_ip,
                "live_check_token_refreshed": token_refreshed,
                "live_check_http_status": checked.get("http_status"),
                "live_check_failure": copy.deepcopy(failure) if failure else None,
            }
            for key in (
                "plan_check_status", "plan_type", "subscription_plan", "has_active_subscription",
                "plus_trial_eligible", "eligible_campaign_id", "plan_checked_at",
                "plan_error_code", "plan_http_status",
            ):
                if key in checked:
                    result_values[key] = copy.deepcopy(checked[key])
            if token_refreshed:
                result_values["access_token"] = token
                result_values["has_access_token"] = True
            self._save_live_result(str(context["row_id"]), result_values)
            self._set_job(
                task_id,
                status=status,
                stage="free_live_result",
                checked_at=checked_at,
                live_check_ip=live_ip,
                token_refreshed=token_refreshed,
                failure=copy.deepcopy(failure) if failure else None,
            )
            label = {"live": "账号正常", "deactivated": "账号已停用", "token_expired": "Token 已失效，建议深度测活", "failed": "测活失败"}[status]
            self._log(task_id, "free_live_result", label, "success" if status == "live" else "warn" if status == "token_expired" else "error")
        except Exception as exc:
            self._finish_exception(task_id, exc, row_id=str(context.get("row_id") or job.get("row_id") or ""))
        finally:
            if binding is not None and binding.proxy_id:
                try:
                    self.proxies.release(binding, owner=lease_owner)
                except Exception as exc:
                    self._log(task_id, "free_live_result", f"测活代理租约释放失败（{type(exc).__name__}）", "warn")

    def _finish_exception(self, task_id: str, exc: BaseException, *, row_id: str = "", code: str = "free_live_check", label: str = "Free 账号测活") -> None:
        failure = _failure(exc, default_code=code, default_label=label)
        checked_at = int(time.time())
        job = self._set_job(task_id, status="failed", stage=failure["node_code"], checked_at=checked_at, failure=failure)
        target_row = row_id or str(job.get("row_id") or "")
        if target_row:
            self._save_live_result(target_row, {
                "live_check_status": "failed",
                "live_check_mode": str(job.get("mode") or ""),
                "live_check_task_id": task_id,
                "live_checked_at": checked_at,
                "live_check_ip": str(job.get("live_check_ip") or ""),
                "live_check_token_refreshed": False,
                "live_check_failure": failure,
            })
        self._log(task_id, failure["node_code"], failure["public_message"], "error")

    def _query_account(self, session: Any, token: str) -> dict[str, Any]:
        headers = {"authorization": f"Bearer {token}", "accept": "application/json"}
        accounts_response = session.get(
            "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
            f"?timezone_offset_min={timezone_offset_minutes()}",
            headers=headers,
            timeout=20,
        )
        accounts_status = _status(accounts_response)
        accounts = _json(accounts_response)
        if accounts_status == 401:
            return {"status": "token_expired", "http_status": 401}
        if _is_deactivated(accounts):
            failure = {
                "node_code": "free_live_deactivated",
                "node_label": "确认 Free 账号状态",
                "error_code": "account_deactivated",
                "public_message": "确认 Free 账号状态 [确认 Free 账号状态/free_live_deactivated]：服务端明确返回账号已停用",
                "technical_summary": "服务端明确返回账号已停用",
                "retryable": False,
                "http_status": accounts_status or None,
            }
            return {"status": "deactivated", "http_status": accounts_status or None, "failure": failure}
        if not 200 <= accounts_status < 300:
            raise FreeRegisterError(
                "free_live_fast",
                "快速测活",
                f"账号接口返回 HTTP {accounts_status or '-'}",
                provider_status=accounts_status or None,
                error_code="free_live_account_http_failed",
            )
        try:
            from .chatgpt_plan_gate import plan_from_accounts_check
        except ImportError:
            from chatgpt_plan_gate import plan_from_accounts_check  # type: ignore[no-redef]
        try:
            plan, _ = plan_from_accounts_check(accounts, token=token)
        except Exception:
            plan = ""
        plan = str(plan or "").strip().lower()
        result: dict[str, Any] = {
            "status": "live",
            "http_status": accounts_status,
            "plan_check_status": "success" if plan else "partial",
            "plan_type": plan,
            "subscription_plan": plan,
            "has_active_subscription": bool(plan and plan != "free"),
            "plus_trial_eligible": _plus_eligible(accounts),
            "eligible_campaign_id": _campaign_id(accounts),
            "plan_checked_at": int(time.time()),
        }
        try:
            eligibility_response = session.get(
                "https://chatgpt.com/backend-api/aip/first-party/eligibility",
                headers=headers,
                timeout=20,
            )
            eligibility_status = _status(eligibility_response)
            eligibility = _json(eligibility_response)
            if 200 <= eligibility_status < 300:
                result["plus_trial_eligible"] = bool(result["plus_trial_eligible"] or _plus_eligible(eligibility))
                result["eligible_campaign_id"] = result["eligible_campaign_id"] or _campaign_id(eligibility)
            else:
                result.update({"plan_check_status": "partial", "plan_error_code": "free_live_eligibility_http_failed", "plan_http_status": eligibility_status or None})
        except Exception as exc:
            result.update({"plan_check_status": "partial", "plan_error_code": f"free_live_eligibility_{type(exc).__name__.lower()}"})
        return result

    def _run_fast(self, context: Mapping[str, Any], _config: Mapping[str, Any]) -> Mapping[str, Any]:
        from curl_cffi import requests as curl_requests

        session = curl_requests.Session(impersonate="chrome", verify=True)
        session.trust_env = False
        transport_proxy = proxy_transport_value(context["proxy"], driver="protocol")
        if not transport_proxy:
            raise FreeRegisterError("free_live_fast", "快速测活", "测活代理格式无效", retryable=False)
        session.proxies = {"http": transport_proxy, "https": transport_proxy}
        try:
            return self._query_account(session, str(context["access_token"]))
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreeRegisterError("free_live_fast", "快速测活", f"账号在线查询异常（{type(exc).__name__}）") from exc
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()

    @staticmethod
    def _page_type(module: Any, response: Any) -> str:
        try:
            return str(module._page_type(response) or "").strip().lower()
        except Exception:
            return ""

    @staticmethod
    def _continue_url(module: Any, response: Any) -> str:
        try:
            return str(module._continue_url(response) or "").strip()
        except Exception:
            return ""

    def _run_deep(self, context: Mapping[str, Any], config: Mapping[str, Any]) -> Mapping[str, Any]:
        import codex_chain_runner
        import codex_oauth_chain

        email = str(context["email"])
        task_id = str(context["task_id"])
        proxy = str(context["proxy"])
        oauth_url, _code_verifier, _state = codex_chain_runner.build_oauth_url(
            login_hint=email,
            prompt="login",
        )
        oauth_params = codex_oauth_chain.parse_oauth_url(oauth_url)
        device_id = f"free-live-{secrets.token_hex(16)}"
        protocol = config.get("protocol") if isinstance(config.get("protocol"), Mapping) else {}
        chain_config = dict(config)
        chain_config.update({
            "run_mode": "free_live_check",
            "codex_chain_mode": "real",
            "codex_node_runner": str(protocol.get("node_runner") or ""),
            "_auth_account_email": email,
        })
        log_fn = lambda message, level="info": self._log(task_id, "free_live_deep", str(message), str(level))
        sentinel = codex_oauth_chain.RealNodeSentinelProvider(
            config=chain_config,
            device_id=device_id,
            proxy_label=str(context.get("proxy_fingerprint") or ""),
            proxy=proxy,
            log_fn=log_fn,
        )
        transport = codex_oauth_chain.RealCodexTransport(
            chain_config,
            oauth_params=oauth_params,
            proxy=proxy,
            sentinel_provider=sentinel,
            device_id=device_id,
            log_fn=log_fn,
        )
        stage_fn = lambda _task_id, code: self._set_job(task_id, stage="free_live_email" if "email" in code else "free_live_deep")
        if MailboxUrlOtpProvider is _ORIGINAL_MAILBOX_URL_OTP_PROVIDER:
            otp = build_free_mailbox_otp_provider(
                str(context["mailbox_url"]), proxy, config,
                log_fn=log_fn, task_id=task_id, stage_fn=stage_fn,
            )
        else:
            # Preserve the historic module-level injection point used by
            # tests and integrations while keeping production on the shared
            # Free mailbox network policy above.
            otp = MailboxUrlOtpProvider(
                str(context["mailbox_url"]), proxy,
                timeout=int(config.get("email_code_timeout") or 90),
                log_fn=log_fn, task_id=task_id, stage_fn=stage_fn,
            )
        try:
            response = transport.start_chatgpt_signup_authorize(email)
            if _is_deactivated(response):
                return self._deactivated_result(_status(response))
            otp.mark_sent()
            response = transport.submit_email_identifier(email)
            for _attempt in range(10):
                if _is_deactivated(response):
                    return self._deactivated_result(_status(response))
                page_type = self._page_type(codex_oauth_chain, response)
                continue_url = self._continue_url(codex_oauth_chain, response)
                if page_type in {"email_otp", "email_otp_verification", "email_verification"}:
                    if not bool(getattr(transport, "_gptphone_initial_email_otp_send_confirmed", False)):
                        otp.mark_sent()
                        sent = transport.send_email_otp(continue_url)
                        if not bool(codex_oauth_chain._is_success_response(sent)):
                            raise FreeRegisterError("free_live_email", "深度测活邮箱验证", "登录 OTP 发送失败")
                    self._set_job(task_id, stage="free_live_email")
                    code = otp.wait_code(email)
                    response = transport.verify_email_otp(code)
                    continue
                if page_type in {"password", "password_verification", "email_password"}:
                    password = str(context.get("password") or "")
                    if not password:
                        raise FreeRegisterError("free_live_password", "深度测活密码验证", "账号没有保存注册密码", retryable=False)
                    response = transport.verify_password(password)
                    continue
                if page_type in {"mfa_otp", "mfa_challenge", "mfa_otp_verification"}:
                    secret = str(context.get("totp_secret") or "")
                    if not secret:
                        raise FreeRegisterError("free_live_mfa", "深度测活动态口令验证", "账号已启用 2FA，但没有保存动态口令密钥", retryable=False)
                    try:
                        from .free_protocol_runtime import FreeProtocolMixin
                    except ImportError:
                        from free_protocol_runtime import FreeProtocolMixin  # type: ignore[no-redef]
                    self._set_job(task_id, stage="free_live_mfa")
                    response = transport.verify_mfa_otp(FreeProtocolMixin._totp_code(secret))
                    continue
                if page_type in {"phone", "phone_otp", "phone_verification"}:
                    raise FreeRegisterError("free_live_phone_required", "深度测活手机号验证", "重新登录进入手机号验证页面，未调用接码平台", retryable=False)
                if page_type in {"about_you", "about-you", "create_account"}:
                    raise FreeRegisterError("free_live_incomplete_account", "确认 Free 账号状态", "重新登录进入资料创建页面，账号注册状态不完整", retryable=False)
                if page_type in {"consent", "consent_required"}:
                    response = transport.accept_consent(continue_url)
                    continue
                if continue_url:
                    response = transport.complete_chatgpt_callback(continue_url)
                token = str(transport.chatgpt_access_token() or "")
                if token:
                    checked = dict(self._query_account(transport.session, token))
                    if checked.get("status") == "live":
                        checked["access_token"] = token
                    return checked
                if not continue_url:
                    break
                response = transport.visit_continue(continue_url, "https://auth.openai.com")
            raise FreeRegisterError("free_live_deep", "深度测活", "重新登录完成后未取得新的 access token")
        except FreeRegisterError:
            raise
        except Exception as exc:
            if _is_deactivated(exc):
                return self._deactivated_result(getattr(exc, "provider_status", None))
            raise FreeRegisterError("free_live_deep", "深度测活", f"重新登录异常（{type(exc).__name__}）") from exc
        finally:
            otp_close = getattr(otp, "close", None)
            if callable(otp_close):
                otp_close()
            for candidate in (getattr(transport, "session", None), transport):
                close = getattr(candidate, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

    @staticmethod
    def _deactivated_result(http_status: Any = None) -> dict[str, Any]:
        failure = {
            "node_code": "free_live_deactivated",
            "node_label": "确认 Free 账号状态",
            "error_code": "account_deactivated",
            "public_message": "确认 Free 账号状态 [确认 Free 账号状态/free_live_deactivated]：重新登录明确返回账号已停用",
            "technical_summary": "重新登录明确返回账号已停用",
            "retryable": False,
        }
        if http_status:
            failure["http_status"] = http_status
        return {"status": "deactivated", "http_status": http_status, "failure": failure}

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=False)


def build_free_live_check_service(
    data_dir: Any,
    *,
    pool: Any,
    proxies: Any,
    log_store: Any,
    proxy_probe: Callable[[str, str], str] | None = None,
    task_store: Any = None,
) -> FreeLiveCheckService:
    """Construct the Free-only service without expanding the main manager."""
    try:
        from .free_register_config import FreeConfigStore
    except ImportError:
        from free_register_config import FreeConfigStore  # type: ignore[no-redef]
    config_store = FreeConfigStore(data_dir)
    return FreeLiveCheckService(
        data_dir,
        pool=pool,
        proxies=proxies,
        log_store=log_store,
        task_store=task_store,
        config_provider=config_store.load,
        proxy_probe=proxy_probe,
    )


__all__ = [
    "ACTIVE_LIVE_STATUSES",
    "FreeLiveCheckService",
    "build_free_live_check_service",
    "LIVE_MODES",
    "LIVE_STAGE_LABELS",
    "TERMINAL_LIVE_STATUSES",
]
