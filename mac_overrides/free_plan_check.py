"""Independent Free plan refresh queue.

This queue deliberately has narrower semantics than live-check: it only uses
the saved access token and registration proxy, and never logs in, requests an
OTP, runs 2FA, or starts a browser.  Result files remain the source of truth;
task and mailbox snapshots are updated after each atomic result write.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import copy
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Callable, Mapping, Sequence

try:
    from .free_account_service import (
        CHATGPT_ACCOUNTS_URL,
        CHATGPT_ELIGIBILITY_URL,
        CHATGPT_ME_URL,
        CHATGPT_WHAM_USAGE_URL,
        plan_details_with_fallbacks,
    )
    from .free_failure_runtime import canonical_failure, exception_to_failure
    from .free_register_common import (
        FreeRegisterError,
        atomic_write,
        proxy_transport_value,
        timezone_offset_minutes,
    )
except ImportError:  # pragma: no cover - recovery import
    from free_account_service import (  # type: ignore[no-redef]
        CHATGPT_ACCOUNTS_URL,
        CHATGPT_ELIGIBILITY_URL,
        CHATGPT_ME_URL,
        CHATGPT_WHAM_USAGE_URL,
        plan_details_with_fallbacks,
    )
    from free_failure_runtime import canonical_failure, exception_to_failure  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FreeRegisterError,
        atomic_write,
        proxy_transport_value,
        timezone_offset_minutes,
    )


ACTIVE_STATUSES = frozenset({"queued", "running"})
PLAN_STAGE = "free_plan_check"
PLAN_LABEL = "查询 Free 套餐资格"


class FreePlanCheckError(FreeRegisterError):
    pass


def _status(value: Any) -> int:
    try:
        return int(getattr(value, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _json(value: Any) -> dict[str, Any]:
    try:
        payload = value.json()
    except Exception:
        payload = {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def _retry_after(response: Any) -> int | None:
    try:
        raw = response.headers.get("retry-after") or response.headers.get("Retry-After")
    except Exception:
        raw = ""
    try:
        seconds = int(float(str(raw).strip()))
    except (TypeError, ValueError):
        return None
    return seconds if 0 <= seconds <= 86400 else None


class FreePlanCheckService:
    def __init__(
        self,
        data_dir: str | Path,
        *,
        pool: Any,
        task_store: Any = None,
        log_store: Any = None,
        config_provider: Callable[[], Mapping[str, Any]] | None = None,
        task_updater: Callable[[str, Mapping[str, Any], bool], None] | None = None,
        workers: int = 2,
        queue_limit: int = 500,
        recover: bool = True,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = self.data_dir / "free_plan_checks.json"
        self.pool = pool
        self.task_store = task_store
        self.log_store = log_store
        self.config_provider = config_provider
        self.task_updater = task_updater
        self.workers = max(1, min(int(workers), 5))
        self.queue_limit = max(self.workers, min(int(queue_limit), 5000))
        self._lock = threading.RLock()
        self._jobs = self._load()
        self._executor = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="free-plan-check")
        self._futures: set[Future[Any]] = set()
        if recover:
            self._recover()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {}
        jobs = payload.get("jobs") if isinstance(payload, Mapping) else {}
        if not isinstance(jobs, Mapping):
            return {}
        result: dict[str, dict[str, Any]] = {}
        for key, item in jobs.items():
            if not isinstance(item, Mapping):
                continue
            job = dict(item)
            if isinstance(job.get("failure"), Mapping):
                normalized = canonical_failure(job["failure"], default_node_code=PLAN_STAGE, default_node_label=PLAN_LABEL)
                if normalized is None:
                    job.pop("failure", None)
                else:
                    job["failure"] = normalized
            result[str(key)] = job
        return result

    def _save(self) -> None:
        atomic_write(self.path, {"version": 1, "jobs": self._jobs})

    def _recover(self) -> None:
        submit: list[str] = []
        with self._lock:
            for task_id, job in self._jobs.items():
                if str(job.get("status") or "") != "running":
                    continue
                job.update({"status": "queued", "recovered": True, "updated_at": int(time.time())})
                submit.append(task_id)
            if submit:
                self._save()
        for task_id in submit:
            self._submit(task_id)

    def _public(self, job: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: copy.deepcopy(job[key])
            for key in (
                "task_id", "row_id", "email", "status", "created_at", "updated_at",
                "checked_at", "retry_after_until", "http_status", "source", "recovered",
            )
            if key in job
        } | ({"failure": canonical_failure(job["failure"], default_node_code=PLAN_STAGE, default_node_label=PLAN_LABEL)} if isinstance(job.get("failure"), Mapping) else {})

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            jobs = [self._public(job) for job in sorted(self._jobs.values(), key=lambda item: int(item.get("created_at") or 0), reverse=True)]
        active = sum(1 for item in jobs if item.get("status") in ACTIVE_STATUSES)
        return {"running": active > 0, "workers": self.workers, "queue_limit": self.queue_limit, "active": active, "jobs": jobs}

    def _config(self) -> dict[str, Any]:
        try:
            value = self.config_provider() if callable(self.config_provider) else {}
        except Exception:
            value = {}
        return dict(value) if isinstance(value, Mapping) else {}

    def _log(self, task_id: str, message: str, level: str = "info") -> None:
        if self.log_store is not None and callable(getattr(self.log_store, "add", None)):
            try:
                self.log_store.add(f"[{task_id}/{PLAN_LABEL}/{PLAN_STAGE}] {message}", level)
            except Exception:
                pass

    def enqueue(self, row_ids: Sequence[str]) -> dict[str, Any]:
        requested = list(dict.fromkeys(str(value or "").strip().lower() for value in row_ids if str(value or "").strip()))
        if not requested:
            raise FreePlanCheckError("free_plan_queue", "重新查询 Free 套餐", "请先选择要查询的 Free 账号", retryable=False, error_code="free_plan_queue_empty")
        entries = {row.row_id: row for row in self.pool.entries()}
        accepted: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        submit: list[str] = []
        now = int(time.time())
        with self._lock:
            active_rows = {str(job.get("row_id") or "") for job in self._jobs.values() if str(job.get("status") or "") in ACTIVE_STATUSES}
            for row_id in requested:
                entry = entries.get(row_id)
                result = self.pool.result(row_id)
                if entry is None:
                    skipped.append({"row_id": row_id, "reason": "Free 邮箱行不存在或已变化"})
                    continue
                if row_id in active_rows:
                    skipped.append({"row_id": row_id, "reason": "该账号正在查询套餐"})
                    continue
                token = str(result.get("access_token") or "").strip()
                if not token:
                    skipped.append({"row_id": row_id, "reason": "该账号没有已保存 Token"})
                    continue
                cooldown = int(float(result.get("plan_retry_after_until") or 0)) if str(result.get("plan_retry_after_until") or "").strip() else 0
                if cooldown > now:
                    skipped.append({"row_id": row_id, "reason": f"套餐接口冷却中，还需 {cooldown - now} 秒"})
                    continue
                if len(active_rows) >= self.queue_limit:
                    skipped.append({"row_id": row_id, "reason": "套餐查询队列已满"})
                    continue
                task_id = f"free-plan-{now}-{secrets.token_hex(4)}"
                job = {"task_id": task_id, "row_id": row_id, "email": entry.email, "status": "queued", "created_at": now, "updated_at": now}
                self._jobs[task_id] = job
                active_rows.add(row_id)
                accepted.append(self._public(job))
                submit.append(task_id)
                updated = dict(result)
                updated.update({"plan_check_status": "queued", "plan_check_task_id": task_id})
                self.pool.save_result(row_id, updated)
                self._sync_task(row_id, updated, False)
            self._save()
        for task_id in submit:
            self._submit(task_id)
        return {"accepted": accepted, "accepted_count": len(accepted), "skipped": skipped, "skipped_count": len(skipped), "state": self.public_state(), "rows": self.pool.public_rows()}

    def _submit(self, task_id: str) -> None:
        future = self._executor.submit(self._worker, task_id)
        with self._lock:
            self._futures.add(future)
        future.add_done_callback(lambda item: self._futures.discard(item))

    def _set_job(self, task_id: str, **values: Any) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(task_id)
            if not job:
                return {}
            job.update(values)
            job["updated_at"] = int(time.time())
            self._save()
            return dict(job)

    def _request(self, session: Any, url: str, token: str) -> dict[str, Any]:
        headers = {"authorization": f"Bearer {token}", "accept": "application/json"}
        if "/accounts/check/" in url:
            headers["x-openai-target-path"] = "/backend-api/accounts/check/v4-2023-04-27"
            headers["x-openai-target-route"] = "/backend-api/accounts/check/v4-2023-04-27"
        response = session.get(url, headers=headers, timeout=20)
        status = _status(response)
        retry = _retry_after(response)
        if status == 429:
            raise FreePlanCheckError(
                PLAN_STAGE, PLAN_LABEL, "套餐接口触发限流，已记录冷却时间，不自动重放",
                retryable=True, provider_status=429, provider_code="rate_limited",
                error_code="free_plan_rate_limited", action_hint="等待冷却结束后手动重新查询套餐",
                # A missing header still gets a short local guard so a
                # double-click cannot immediately replay the same request.
                retry_after_seconds=retry if retry is not None else 60,
            )
        return {"ok": 200 <= status < 300, "status": status, "payload": _json(response), "retry_after": retry}

    def _query(self, row_id: str) -> dict[str, Any]:
        result = self.pool.result(row_id)
        token = str(result.get("access_token") or "").strip()
        proxy = str(result.get("proxy") or self.pool._row_state(row_id).get("proxy") or "").strip()
        if not token:
            raise FreePlanCheckError(PLAN_STAGE, PLAN_LABEL, "账号没有已保存 Token", retryable=False, error_code="free_plan_token_missing")
        try:
            from curl_cffi import requests as curl_requests
            session = curl_requests.Session(impersonate="chrome")
        except Exception:
            import requests as fallback_requests
            session = fallback_requests.Session()
        session.trust_env = False
        config = self._config()
        transport_proxy = proxy_transport_value(
            proxy,
            driver="protocol",
            socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
        )
        if transport_proxy:
            session.proxies = {"http": transport_proxy, "https": transport_proxy}
        accounts_url = CHATGPT_ACCOUNTS_URL + f"?timezone_offset_min={timezone_offset_minutes()}"
        try:
            accounts = self._request(session, accounts_url, token)
            eligibility = self._request(session, CHATGPT_ELIGIBILITY_URL, token)
            fallbacks: list[tuple[str, Any]] = []
            details = plan_details_with_fallbacks(accounts, eligibility)
            if details.get("plan_check_status") != "success":
                me = self._request(session, CHATGPT_ME_URL, token)
                fallbacks.append(("backend-api/me", me))
                details = plan_details_with_fallbacks(accounts, eligibility, fallbacks)
                if details.get("plan_check_status") != "success":
                    usage = self._request(session, CHATGPT_WHAM_USAGE_URL, token)
                    fallbacks.append(("backend-api/wham/usage", usage))
                    details = plan_details_with_fallbacks(accounts, eligibility, fallbacks)
            if details.get("plan_check_status") != "success":
                raise FreePlanCheckError(
                    PLAN_STAGE, PLAN_LABEL, "套餐接口返回无效或非成功响应", retryable=True,
                    provider_status=details.get("plan_http_status"),
                    provider_code=details.get("plan_provider_code"),
                    error_code=details.get("plan_error_code") or "free_plan_accounts_response_invalid",
                    action_hint="保留已注册账号，稍后重新查询套餐状态",
                    diagnostic=json.dumps({"attempts": details.get("plan_fallback_attempts", [])}, ensure_ascii=False)[:500],
                )
            return dict(details)
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()

    def _save_success(self, row_id: str, values: Mapping[str, Any], task_id: str) -> None:
        current = self.pool.result(row_id)
        current.update({key: copy.deepcopy(values[key]) for key in ("plan_check_status", "plan_type", "subscription_plan", "has_active_subscription", "plus_trial_eligible", "eligible_campaign_id", "plan_checked_at", "plan_http_status", "plan_source") if key in values})
        current.update({"plan_check_task_id": task_id})
        registration_failure = current.get("failure") if isinstance(current.get("failure"), Mapping) else {}
        plan_failure_code = str(registration_failure.get("error_code") or current.get("plan_error_code") or "")
        promoted = str(current.get("status") or "") == "partial_success" and plan_failure_code.startswith("free_plan_")
        for key in ("plan_failure", "plan_error_code", "plan_error_detail", "plan_provider_code", "plan_retry_after_until"):
            current.pop(key, None)
        if promoted:
            current["status"] = "success"
            current.pop("failure", None)
            current.pop("error", None)
        # Result JSON is authoritative.  Write it before publishing the
        # mailbox/task status so a reader can never observe success without
        # the refreshed plan payload.
        self.pool.save_result(row_id, current)
        if promoted:
            self.pool.update(row_id, status="success", stage="free_plan_check", error="", failure=None)
        self._sync_task(row_id, current, promoted)

    def _save_failure(self, row_id: str, task_id: str, exc: BaseException) -> dict[str, Any]:
        failure = exception_to_failure(exc, node_code=PLAN_STAGE, node_label=PLAN_LABEL)
        current = self.pool.result(row_id)
        current.update({"plan_check_status": "failed", "plan_check_task_id": task_id, "plan_error_code": failure.get("error_code"), "plan_http_status": failure.get("http_status"), "plan_failure": failure})
        retry_after = getattr(exc, "retry_after_seconds", None)
        try:
            retry_after = int(retry_after) if retry_after is not None else None
        except (TypeError, ValueError):
            retry_after = None
        if retry_after is not None and retry_after >= 0:
            current["plan_retry_after_until"] = int(time.time()) + retry_after
        self.pool.save_result(row_id, current)
        self._sync_task(row_id, current, False)
        return failure

    def _sync_task(self, row_id: str, result: Mapping[str, Any], promoted: bool) -> None:
        if callable(self.task_updater):
            self.task_updater(row_id, result, promoted)
            return
        if self.task_store is None:
            return
        tasks = self.task_store.load()
        task_id = str(result.get("task_id") or "")
        task = tasks.get(task_id)
        if not isinstance(task, dict):
            return
        task["result"] = copy.deepcopy(dict(result))
        task["updated_at"] = int(time.time())
        if promoted and str(task.get("status") or "") == "partial_success":
            task.update({"status": "success", "stage": PLAN_STAGE, "error": ""})
            task.pop("failure", None)
        self.task_store.save(tasks)

    def _worker(self, task_id: str) -> None:
        job = self._set_job(task_id, status="running")
        if not job:
            return
        row_id = str(job.get("row_id") or "")
        try:
            details = self._query(row_id)
            self._save_success(row_id, details, task_id)
            self._set_job(task_id, status="success", checked_at=int(time.time()), source=details.get("plan_source"), http_status=details.get("plan_http_status"))
            self._log(task_id, "套餐查询成功")
        except Exception as exc:
            failure = self._save_failure(row_id, task_id, exc)
            retry_until = self.pool.result(row_id).get("plan_retry_after_until")
            self._set_job(task_id, status="failed", checked_at=int(time.time()), http_status=failure.get("http_status"), retry_after_until=retry_until, failure=failure)
            self._log(task_id, failure.get("public_message", "套餐查询失败"), "error")

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=False)


def build_free_plan_check_service(data_dir: Any, *, pool: Any, task_store: Any = None, log_store: Any = None, config_provider: Callable[[], Mapping[str, Any]] | None = None, task_updater: Callable[[str, Mapping[str, Any], bool], None] | None = None) -> FreePlanCheckService:
    return FreePlanCheckService(data_dir, pool=pool, task_store=task_store, log_store=log_store, config_provider=config_provider, task_updater=task_updater)


__all__ = ["FreePlanCheckError", "FreePlanCheckService", "build_free_plan_check_service"]
