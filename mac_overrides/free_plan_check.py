"""Independent Free plan refresh queue.

Two modes share the queue: ``token`` keeps the historical narrow semantics
(saved access token only, never logs in and never starts a browser), while
``recheck`` re-establishes the account first when the token is missing or
rejected — pure protocol re-login for protocol rows, the camoufox browser
existing-login flow for browser rows — so any row can get a fresh plan
answer regardless of its token state.  Result files remain the source of
truth; task and mailbox snapshots are updated after each atomic result write.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import copy
import json
import re
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

try:
    from .free_batch_concurrency import ProxyPoolConcurrencyGate
except ImportError:  # pragma: no cover - top-level recovery import
    from free_batch_concurrency import ProxyPoolConcurrencyGate  # type: ignore[no-redef]

try:
    from .free_proxy_maintenance import bind_with_pool_maintenance, pool_empty_error_code
except ImportError:  # pragma: no cover - top-level recovery import
    from free_proxy_maintenance import bind_with_pool_maintenance, pool_empty_error_code  # type: ignore[no-redef]

try:
    from .free_account_service import (
        CHATGPT_ACCOUNTS_URL,
        CHATGPT_ELIGIBILITY_URL,
        CHATGPT_ME_URL,
        CHATGPT_WHAM_USAGE_URL,
        plan_details_with_fallbacks,
    )
    from .free_failure_runtime import canonical_failure, exception_to_failure
    from .free_live_check import delete_deactivated_pool_row
    from .free_mailbox_otp import build_free_mailbox_otp_provider
    from .free_protocol_relogin import (
        ProtocolReloginDeactivated,
        protocol_relogin_proxy,
        run_protocol_relogin,
    )
    from .free_subject_fingerprint import subject_fingerprint
    from .free_register_common import (
        FREE_STAGE_LABELS,
        FreeRegisterError,
        atomic_write,
        fingerprint,
        mask_email,
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
    from free_live_check import delete_deactivated_pool_row  # type: ignore[no-redef]
    from free_mailbox_otp import build_free_mailbox_otp_provider  # type: ignore[no-redef]
    from free_protocol_relogin import (  # type: ignore[no-redef]
        ProtocolReloginDeactivated,
        protocol_relogin_proxy,
        run_protocol_relogin,
    )
    from free_subject_fingerprint import subject_fingerprint  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FREE_STAGE_LABELS,
        FreeRegisterError,
        atomic_write,
        fingerprint,
        mask_email,
        proxy_transport_value,
        timezone_offset_minutes,
    )


ACTIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_PLAN_STATUSES = frozenset({"success", "failed", "partial_success", "stopped"})
PLAN_STAGE = "free_plan_check"
PLAN_LABEL = "查询 Free 套餐资格"
PLAN_MODES = frozenset({"token", "recheck"})
RELOGIN_STAGE = "free_plan_relogin"
RELOGIN_LABEL = "重查套餐重新登录"
_DEACTIVATION_MARKERS = ("account_deactivated", "account_suspended", "account_banned")



try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('free_plan_check', where, exc)


def _recheck_confirmed_deactivation(exc: BaseException, failure: Mapping[str, Any]) -> bool:
    """Recognize the explicit deactivation markers from both relogin paths.

    The protocol core raises ``account_deactivated`` as the error code; the
    browser auth shell surfaces the same account-status marker through the
    page error text. Only these explicit markers count — a bare 403 or a
    security challenge never deletes a row.
    """
    if str(failure.get("error_code") or "") in _DEACTIVATION_MARKERS:
        return True
    text = str(exc)
    return any(marker in text for marker in _DEACTIVATION_MARKERS)


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
        proxies: Any = None,
        proxy_probe: Callable[[str, str], str] | None = None,
        browser_recheck: Callable[[str, Mapping[str, Any], Callable[[str, str], None]], Mapping[str, Any]] | None = None,
        pool_maintainer: Callable[[Mapping[str, Any]], int] | None = None,
        breaker: Any | None = None,
        workers: int = 2,
        max_concurrency: int = 16,
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
        self.proxies = proxies
        self.proxy_probe = proxy_probe
        self.browser_recheck = browser_recheck
        # Injected by the Free manager: an empty pool gets one gated
        # maintenance pass before the job fails, and the breaker reference
        # lets the public error distinguish "reset needed" from "no proxy".
        self.pool_maintainer = pool_maintainer
        self.breaker = breaker
        # ``workers`` is the fallback ceiling; the live ceiling follows the
        # shared healthy pool so plan queries scale with available proxies.
        self.workers = max(1, min(int(workers), 5))
        self.max_concurrency = max(self.workers, min(int(max_concurrency), 64))
        self.queue_limit = max(self.workers, min(int(queue_limit), 5000))
        self._lock = threading.RLock()
        self._jobs = self._load()
        self._executor = ThreadPoolExecutor(max_workers=self.max_concurrency, thread_name_prefix="free-plan-check")
        self._gate = ProxyPoolConcurrencyGate(self._dynamic_concurrency)
        self._futures: set[Future[Any]] = set()
        if recover:
            self._recover()

    def _dynamic_concurrency(self) -> int:
        """In-flight ceiling: one slot per healthy proxy, capped."""
        try:
            healthy = int(self.proxies.healthy_count())
        except Exception:
            return self.workers
        return max(1, min(healthy, self.max_concurrency))

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

    _JOBS_FLUSH_INTERVAL = 0.5

    def _save(self) -> None:
        atomic_write(self.path, {"version": 1, "jobs": self._jobs})
        self._jobs_flushed_at = time.monotonic()

    def _save_coalesced(self, *, force: bool = False) -> None:
        """Write the jobs file at most every half second unless forced.

        Terminal states, enqueue and recovery always flush immediately; a
        crash inside a coalesced window only loses stage-progress rows that
        ``_recover`` re-queues anyway.
        """
        if force or time.monotonic() - getattr(self, "_jobs_flushed_at", 0.0) >= self._JOBS_FLUSH_INTERVAL:
            self._save()

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

    def _subject_fingerprint(self, email: Any) -> str:
        """Use the diagnostic HMAC for public correlation when available."""
        return subject_fingerprint(self.log_store, email)

    def _public(self, job: Mapping[str, Any]) -> dict[str, Any]:
        result = {
            key: copy.deepcopy(job[key])
            for key in (
                "task_id", "row_id", "status", "mode", "created_at", "updated_at",
                "checked_at", "retry_after_until", "http_status", "source", "recovered",
            )
            if key in job
        }
        raw_email = str(job.get("email") or "").strip()
        result["email"] = mask_email(raw_email)
        result["email_masked"] = result["email"]
        result["subject_ref_fingerprint"] = self._subject_fingerprint(raw_email)
        if isinstance(job.get("failure"), Mapping):
            # Preserve the historical optional ``failure`` key (including a
            # canonical ``None`` for malformed snapshots) while keeping the
            # payload strictly redacted.
            result["failure"] = canonical_failure(
                job["failure"], default_node_code=PLAN_STAGE, default_node_label=PLAN_LABEL
            )
        return result

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            jobs = [self._public(job) for job in sorted(self._jobs.values(), key=lambda item: int(item.get("created_at") or 0), reverse=True)]
        active = sum(1 for item in jobs if item.get("status") in ACTIVE_STATUSES)
        return {"running": active > 0, "workers": self._gate.current_limit(), "max_concurrency": self.max_concurrency, "queue_limit": self.queue_limit, "active": active, "jobs": jobs}

    def _config(self) -> dict[str, Any]:
        try:
            value = self.config_provider() if callable(self.config_provider) else {}
        except Exception:
            value = {}
        return dict(value) if isinstance(value, Mapping) else {}

    def _log(self, task_id: str, message: str, level: str = "info") -> None:
        if self.log_store is not None and callable(getattr(self.log_store, "add", None)):
            try:
                text = f"[{task_id}/{PLAN_LABEL}/{PLAN_STAGE}] {message}"
                self.log_store.add(
                    text,
                    level,
                    chain="free",
                    workflow="plan_check",
                    driver="free",
                    task_id=str(task_id or ""),
                    stage=PLAN_STAGE,
                    stage_label=PLAN_LABEL,
                    node_code=PLAN_STAGE,
                    node_label=PLAN_LABEL,
                )
            except TypeError:
                # Older injected sinks only implement ``add(message, level)``;
                # preserve their logging behavior while structured sinks get
                # the explicit plan-check scope above.
                try:
                    self.log_store.add(
                        f"[{task_id}/{PLAN_LABEL}/{PLAN_STAGE}] {message}",
                        level,
                    )
                except Exception as exc:
                    # Log delivery must never break the plan check.
                    _note_stderr("L242", exc)
            except Exception as exc:
                # Log delivery must never break the plan check.
                _note_stderr("L245", exc)

    def enqueue(self, row_ids: Sequence[str], mode: str = "token") -> dict[str, Any]:
        mode = str(mode or "token").strip().lower()
        if mode not in PLAN_MODES:
            raise FreePlanCheckError(
                "free_plan_queue", "重新查询 Free 套餐", f"未知的套餐查询模式：{mode}",
                retryable=False, error_code="free_plan_mode_invalid",
            )
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
                if mode == "recheck":
                    # Recheck re-logins the mailbox, so rows still owned by a
                    # registration or live check must not be double-consumed
                    # (same busy signal the live-check queue enforces).
                    registration_state = self.pool._row_state(row_id)
                    if str(registration_state.get("status") or "") in {"reserved", "queued", "running"}:
                        skipped.append({"row_id": row_id, "reason": "该账号仍在注册中"})
                        continue
                    if str(result.get("live_check_status") or "") in {"queued", "running"}:
                        skipped.append({"row_id": row_id, "reason": "该账号正在测活"})
                        continue
                token = str(result.get("access_token") or "").strip()
                if mode != "recheck" and not token:
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
                job = {"task_id": task_id, "row_id": row_id, "email": entry.email, "status": "queued", "mode": mode, "created_at": now, "updated_at": now}
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
            self._save_coalesced(force=str(values.get("status") or "") in TERMINAL_PLAN_STATUSES)
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

    def _allocate_proxy(self, config: Mapping[str, Any], row_id: str, *, driver: str = "protocol", exclude_proxy_ids: Sequence[str] = ()) -> tuple[str, Any | None]:
        """Allocate one healthy shared-pool proxy for this query.

        The proxy recorded at registration is history only; post-registration
        account queries must not pin it (mirrors rebind and live check).
        Returns ``("", None)`` when no pool is wired so injected/legacy
        managers keep their direct-connection behavior.
        """
        binder = getattr(self.proxies, "bind", None) if self.proxies is not None else None
        if not callable(binder):
            return "", None
        bindings, _empty_error = bind_with_pool_maintenance(
            lambda: binder(
                1,
                probe=self.proxy_probe,
                probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
                driver=driver,
                exclude_proxy_ids=list(exclude_proxy_ids),
                perform_probe=False,
            ),
            config=config,
            maintainer=self.pool_maintainer,
            note_maintain_failure=lambda exc: _note_stderr("pool_maintain", exc),
        )
        if not bindings:
            if pool_empty_error_code(self.breaker) == "free_proxy_breaker_tripped":
                raise FreePlanCheckError(
                    "free_proxy_breaker_tripped",
                    FREE_STAGE_LABELS.get("free_proxy_breaker_tripped", "代理池挑战熔断"),
                    "共享 Free 代理池没有健康代理，且挑战熔断已触发：请先人工确认并重置熔断",
                    retryable=False,
                    error_code="free_proxy_breaker_tripped",
                    action_hint="重置熔断或修正隧道网关模板后，重新查询套餐会自动从健康池分配代理",
                )
            raise FreePlanCheckError(PLAN_STAGE, PLAN_LABEL, "共享 Free 代理池没有健康代理", retryable=True, error_code="free_proxy_pool_empty", action_hint="请导入健康代理，或配置账密隧道模板后重新查询套餐")
        binding = bindings[0]
        lease = getattr(self.proxies, "lease", None)
        if callable(lease) and str(getattr(binding, "proxy_id", "") or ""):
            lease(binding, owner=row_id, batch_id=row_id, task_id=row_id)
        return str(binding.proxy), binding

    def _query(self, row_id: str, *, token_override: str = "") -> dict[str, Any]:
        result = self.pool.result(row_id)
        token = str(token_override or result.get("access_token") or "").strip()
        if not token:
            raise FreePlanCheckError(PLAN_STAGE, PLAN_LABEL, "账号没有已保存 Token", retryable=False, error_code="free_plan_token_missing")
        config = self._config()
        proxy, binding = self._allocate_proxy(config, row_id)
        try:
            try:
                from curl_cffi import requests as curl_requests
                session = curl_requests.Session(impersonate="chrome")
            except Exception:
                import requests as fallback_requests
                session = fallback_requests.Session()
            session.trust_env = False
            transport_proxy = proxy_transport_value(
                proxy,
                driver="protocol",
                socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
            )
            if transport_proxy:
                session.proxies = {"http": transport_proxy, "https": transport_proxy}
            accounts_url = CHATGPT_ACCOUNTS_URL + f"?timezone_offset_min={timezone_offset_minutes()}"
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
            releaser = getattr(self.proxies, "release", None)
            if binding is not None and callable(releaser):
                try:
                    releaser(binding, owner=row_id)
                except Exception as exc:
                    _note_stderr("proxy_release", exc)

    def _recheck_query(self, row_id: str, task_id: str) -> dict[str, Any]:
        """Re-check the plan regardless of the saved token state.

        The saved token is tried first — a still-valid token answers without
        any login. A 401 or a missing token falls back to the row's own
        chain: protocol rows re-login over pure protocol, camoufox rows go
        through the browser existing-login flow.
        """
        result = self.pool.result(row_id)
        if str(result.get("access_token") or "").strip():
            # Direct query first: a still-valid token answers without any
            # login. A transport-level failure gets one more healthy exit; a
            # 401 verdict falls through to the per-chain re-login below.
            for attempt in range(2):
                try:
                    return self._query(row_id)
                except FreePlanCheckError as exc:
                    if exc.error_code == "free_plan_token_missing" or exc.provider_status == 401:
                        break
                    if attempt or not bool(exc.retryable):
                        raise
                except Exception as exc:
                    # Raw transport errors (proxy TLS etc.) must not escape
                    # the swap loop unnamed.
                    if attempt:
                        raise FreePlanCheckError(
                            PLAN_STAGE, PLAN_LABEL, f"套餐查询请求异常（{type(exc).__name__}）",
                            retryable=True, error_code="free_plan_query_transport_failed",
                        ) from exc
                    _note_stderr("plan_direct_query_retry", exc)
        driver = str(result.get("driver") or "protocol").strip().lower()
        try:
            if driver == "camoufox":
                return self._browser_recheck_result(row_id, result, task_id)
            return self._protocol_relogin_query(row_id, result, task_id)
        except FreePlanCheckError as exc:
            # OpenAI answers passwordless existing-account logins with the
            # interactive HTML password shell, which the pure-protocol state
            # machine cannot drive. When no real password is saved, the
            # browser existing-login flow is the only working re-login, so
            # fall back to it instead of failing the row.
            has_saved_password = bool(str(result.get("password") or "").strip())
            if (
                driver != "camoufox"
                and not has_saved_password
                and callable(self.browser_recheck)
                and bool(getattr(exc, "retryable", False))
            ):
                self._log(task_id, "纯协议重登无法推进（OpenAI 交互式登录页），改用浏览器重登", "warn")
                return self._browser_recheck_result(row_id, result, task_id)
            raise

    _RELOGIN_PROXY_ATTEMPTS = 3

    def _protocol_relogin_query(self, row_id: str, result: Mapping[str, Any], task_id: str) -> dict[str, Any]:
        """Re-login over pure protocol, persist the fresh token, re-query the plan.

        Mirrors the deep-check proxy discipline: a retryable failure swaps to
        a fresh, unused pool exit instead of failing the row on one proxy.
        """
        config = self._config()
        tried_proxy_ids: list[str] = []
        last_attempt = self._RELOGIN_PROXY_ATTEMPTS - 1
        for attempt in range(self._RELOGIN_PROXY_ATTEMPTS):
            raw_proxy, binding = self._allocate_proxy(config, row_id, exclude_proxy_ids=tried_proxy_ids)
            tried_proxy_ids.append(str(getattr(binding, "proxy_id", "") or ""))
            try:
                return self._relogin_attempt(row_id, result, config, task_id, raw_proxy, private_state=self.pool._row_state(row_id))
            except FreePlanCheckError as exc:
                if attempt >= last_attempt or not bool(exc.retryable):
                    raise
                self._log(task_id, f"第 {attempt + 1} 次协议重登未通过（{exc.error_code}），换代理重试", "warn")
            except Exception as exc:
                # Provider/OTP construction failures surface as raw transport
                # exceptions; wrap them so the proxy swap and the browser
                # fallback can still act on them.
                if attempt >= last_attempt:
                    raise FreePlanCheckError(
                        RELOGIN_STAGE, RELOGIN_LABEL, f"重新登录异常（{type(exc).__name__}）",
                        retryable=True, error_code="free_plan_relogin_failed",
                    ) from exc
                self._log(task_id, f"第 {attempt + 1} 次协议重登异常（{type(exc).__name__}），换代理重试", "warn")
            finally:
                releaser = getattr(self.proxies, "release", None)
                if binding is not None and callable(releaser):
                    try:
                        releaser(binding, owner=row_id)
                    except Exception as exc:
                        _note_stderr("proxy_release", exc)
        raise FreePlanCheckError(RELOGIN_STAGE, RELOGIN_LABEL, "重新登录未完成", retryable=True, error_code="free_plan_relogin_failed")

    def _relogin_attempt(self, row_id: str, result: Mapping[str, Any], config: Mapping[str, Any], task_id: str, raw_proxy: str, *, private_state: Mapping[str, Any]) -> dict[str, Any]:
        entry = self.pool.entry(row_id)
        if entry is None:
            raise FreePlanCheckError(PLAN_STAGE, PLAN_LABEL, "Free 邮箱行不存在或已变化", retryable=False, error_code="free_plan_row_missing")
        proxy = protocol_relogin_proxy(raw_proxy, config, stage_label="重查套餐")
        log_fn = lambda message, level="info": self._log(task_id, str(message), str(level))

        def stage_fn(*_args: Any) -> None:
            # The re-login's internal stage transitions stay visible in the
            # task log through log_fn; plan jobs carry no stage list.
            return None

        otp = build_free_mailbox_otp_provider(
            entry.mailbox_url, proxy, config,
            log_fn=log_fn, task_id=task_id, stage_fn=stage_fn,
            mailbox_source=str(private_state.get("source") or "url").strip().lower() or "url",
            mailbox_email=entry.email,
            service_token=str(private_state.get("service_token") or private_state.get("serviceToken") or ""),
        )
        context = {
            "email": entry.email,
            "password": str(result.get("password") or ""),
            "totp_secret": str(result.get("totp_secret") or ""),
            "proxy_fingerprint": "",
        }
        try:
            outcome = run_protocol_relogin(
                context,
                config,
                proxy=proxy,
                otp=otp,
                log_fn=log_fn,
                stage_fn=stage_fn,
                node_code=RELOGIN_STAGE,
                node_label=RELOGIN_LABEL,
            )
        except ProtocolReloginDeactivated as exc:
            raise FreePlanCheckError(
                RELOGIN_STAGE, RELOGIN_LABEL, "重新登录明确返回账号已停用",
                retryable=False, error_code="account_deactivated",
                provider_status=exc.http_status,
                action_hint="账号已停用（重新登录明确确认）",
            ) from exc
        except FreeRegisterError as exc:
            raise self._wrap_relogin_error(exc) from exc
        token = str(outcome.get("access_token") or "")
        if not token:
            raise FreePlanCheckError(
                RELOGIN_STAGE, RELOGIN_LABEL, "重新登录完成后未取得新的 access token",
                retryable=True, error_code="free_plan_relogin_token_missing",
            )
        self._save_refreshed_token(row_id, token)
        # The fresh token is proxy-independent: a failed plan query just needs
        # another healthy exit, not a second login. Rate-limited responses
        # keep their cooldown semantics and are never replayed here.
        plan_error: FreePlanCheckError | None = None
        for attempt in range(3):
            try:
                return self._query(row_id, token_override=token)
            except FreePlanCheckError as exc:
                if str(exc.error_code or "") == "free_plan_rate_limited" or not bool(exc.retryable):
                    raise
                plan_error = exc
                if attempt >= 2:
                    raise
            except Exception as exc:
                plan_error = FreePlanCheckError(
                    PLAN_STAGE, PLAN_LABEL, f"套餐查询请求异常（{type(exc).__name__}）",
                    retryable=True, error_code="free_plan_query_transport_failed",
                )
                if attempt >= 2:
                    raise plan_error from exc
                _note_stderr("plan_query_transport_retry", exc)
        if plan_error is not None:
            raise plan_error
        raise FreePlanCheckError(PLAN_STAGE, PLAN_LABEL, "套餐查询未完成", retryable=True)

    def _browser_recheck_result(self, row_id: str, result: Mapping[str, Any], task_id: str) -> dict[str, Any]:
        """Run the camoufox browser existing-login flow and read the plan answer."""
        if self.browser_recheck is None:
            raise FreePlanCheckError(
                PLAN_STAGE, PLAN_LABEL, "Camoufox 浏览器重查能力不可用",
                retryable=False, error_code="free_plan_browser_recheck_unavailable",
                action_hint="Camoufox 链路账号的套餐重查需要浏览器运行时",
            )
        config = self._config()
        raw_proxy, binding = self._allocate_proxy(config, row_id, driver="camoufox")
        try:
            entry = self.pool.entry(row_id)
            if entry is None:
                raise FreePlanCheckError(PLAN_STAGE, PLAN_LABEL, "Free 邮箱行不存在或已变化", retryable=False, error_code="free_plan_row_missing")
            private_state = self.pool._row_state(row_id)
            context: dict[str, Any] = {
                "email": entry.email,
                "mailbox_url": entry.mailbox_url,
                "mailbox_source": str(private_state.get("source") or "url").strip().lower() or "url",
                "service_token": str(private_state.get("service_token") or private_state.get("serviceToken") or ""),
                "proxy": raw_proxy,
                "access_token": str(result.get("access_token") or ""),
                "password": str(result.get("password") or ""),
                "totp_secret": str(result.get("totp_secret") or ""),
                "password_status": str(result.get("password_status") or ""),
                "twofa_status": str(result.get("twofa_status") or ""),
                "device_id": "",
            }
            recheck_result = dict(self.browser_recheck(
                row_id,
                context,
                lambda message, level="info": self._log(task_id, str(message), str(level)),
            ))
        except FreeRegisterError:
            raise
        except Exception as exc:
            raise FreePlanCheckError(
                PLAN_STAGE, PLAN_LABEL, f"Camoufox 浏览器重查套餐异常（{type(exc).__name__}）",
                retryable=True, error_code="free_plan_browser_recheck_failed",
            ) from exc
        finally:
            releaser = getattr(self.proxies, "release", None)
            if binding is not None and callable(releaser):
                try:
                    releaser(binding, owner=row_id)
                except Exception as exc:
                    _note_stderr("proxy_release", exc)
        details = {
            key: copy.deepcopy(recheck_result[key])
            for key in (
                "plan_check_status", "plan_type", "subscription_plan", "has_active_subscription",
                "plus_trial_eligible", "eligible_campaign_id", "plan_checked_at",
                "plan_http_status", "plan_source",
            )
            if key in recheck_result
        }
        if str(details.get("plan_check_status") or "") != "success":
            failure = recheck_result.get("plan_failure") if isinstance(recheck_result.get("plan_failure"), Mapping) else {}
            raise FreePlanCheckError(
                PLAN_STAGE, PLAN_LABEL, "浏览器套餐查询未返回成功结果", retryable=True,
                provider_status=details.get("plan_http_status"),
                error_code=str(failure.get("error_code") or "") or "free_plan_accounts_response_invalid",
                action_hint="保留已注册账号，稍后重新查询套餐状态",
            )
        # The refreshed token and any supplemented credentials ride along
        # with the plan answer; empty values never overwrite the row.
        for key in ("access_token", "has_access_token", "password_status", "password_set_after_registration", "twofa_status"):
            if recheck_result.get(key):
                details[key] = copy.deepcopy(recheck_result[key])
        return details

    @staticmethod
    def _wrap_relogin_error(exc: FreeRegisterError) -> FreePlanCheckError:
        """Relabel re-login failures under the plan re-login node, preserving codes."""
        return FreePlanCheckError(
            RELOGIN_STAGE,
            RELOGIN_LABEL,
            str(exc) or RELOGIN_LABEL,
            retryable=bool(getattr(exc, "retryable", True)),
            provider_status=getattr(exc, "provider_status", None),
            error_code=str(getattr(exc, "error_code", "") or "") or "free_plan_relogin_failed",
            provider_code=str(getattr(exc, "provider_code", "") or "") or None,
            action_hint=str(getattr(exc, "action_hint", "") or "") or None,
            diagnostic=str(getattr(exc, "diagnostic", "") or "") or None,
        )

    def _save_refreshed_token(self, row_id: str, token: str) -> None:
        current = self.pool.result(row_id)
        current.update({"access_token": token, "has_access_token": True})
        self.pool.save_result(row_id, current)

    def _save_success(self, row_id: str, values: Mapping[str, Any], task_id: str) -> None:
        current = self.pool.result(row_id)
        current.update({key: copy.deepcopy(values[key]) for key in ("plan_check_status", "plan_type", "subscription_plan", "has_active_subscription", "plus_trial_eligible", "eligible_campaign_id", "plan_checked_at", "plan_http_status", "plan_source") if key in values})
        # A recheck can refresh the token and supplement credentials; empty
        # values never overwrite what the row already holds.
        for key in ("access_token", "has_access_token", "password_status", "password_set_after_registration", "twofa_status"):
            if values.get(key):
                current[key] = copy.deepcopy(values[key])
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
        # Prefer the exception's own node (e.g. the relogin node) so the
        # recorded failure names the first real failing step, not the queue.
        failure = exception_to_failure(
            exc,
            node_code=str(getattr(exc, "node_code", "") or PLAN_STAGE),
            node_label=str(getattr(exc, "node_label", "") or PLAN_LABEL),
        )
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
        task_id = str(result.get("task_id") or "")
        get_one = getattr(self.task_store, "get_task", None)
        if callable(get_one):
            task = get_one(task_id)
            if not isinstance(task, dict):
                return
            task["result"] = copy.deepcopy(dict(result))
            task["updated_at"] = int(time.time())
            if promoted and str(task.get("status") or "") == "partial_success":
                task.update({"status": "success", "stage": PLAN_STAGE, "error": ""})
                task.pop("failure", None)
            self.task_store.save({task_id: task}, partial_snapshot=True)
            return
        tasks = self.task_store.load()
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
        # One healthy proxy backs each in-flight query; wait outside the
        # running state so queued rows stay visible as queued.
        with self._gate:
            self._worker_locked(task_id)

    def _worker_locked(self, task_id: str) -> None:
        job = self._set_job(task_id, status="running")
        if not job:
            return
        row_id = str(job.get("row_id") or "")
        mode = str(job.get("mode") or "token")
        try:
            details = self._recheck_query(row_id, task_id) if mode == "recheck" else self._query(row_id)
            self._save_success(row_id, details, task_id)
            self._set_job(task_id, status="success", checked_at=int(time.time()), source=details.get("plan_source"), http_status=details.get("plan_http_status"))
            self._log(task_id, "套餐查询成功")
        except Exception as exc:
            failure = self._save_failure(row_id, task_id, exc)
            retry_until = self.pool.result(row_id).get("plan_retry_after_until")
            if mode == "recheck" and _recheck_confirmed_deactivation(exc, failure):
                # Same contract as the deep live check: a confirmed re-login
                # deactivation removes the row, registration results and
                # diagnostic events stay as the audit trail.
                removed = delete_deactivated_pool_row(
                    self.pool,
                    row_id,
                    log_fn=lambda message, level: self._log(task_id, message, str(level)),
                    origin="free_plan_check",
                )
                # The deletion outcome is known by now; the persisted job
                # failure must describe it in completed form, never as a
                # pending promise.
                failure = dict(failure)
                failure["action_hint"] = (
                    "账号已停用，已从 Free 邮箱池移除（注册结果与诊断日志保留）"
                    if removed
                    else "账号已停用，邮箱行移除失败，已标记为不可用"
                )
            self._set_job(task_id, status="failed", checked_at=int(time.time()), http_status=failure.get("http_status"), retry_after_until=retry_until, failure=failure)
            self._log(task_id, failure.get("public_message", "套餐查询失败"), "error")

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=False)


def build_free_plan_check_service(data_dir: Any, *, pool: Any, task_store: Any = None, log_store: Any = None, config_provider: Callable[[], Mapping[str, Any]] | None = None, task_updater: Callable[[str, Mapping[str, Any], bool], None] | None = None, proxies: Any = None, proxy_probe: Callable[[str, str], str] | None = None, browser_recheck: Callable[[str, Mapping[str, Any], Callable[[str, str], None]], Mapping[str, Any]] | None = None, pool_maintainer: Callable[[Mapping[str, Any]], int] | None = None, breaker: Any | None = None) -> FreePlanCheckService:
    return FreePlanCheckService(data_dir, pool=pool, task_store=task_store, log_store=log_store, config_provider=config_provider, task_updater=task_updater, proxies=proxies, proxy_probe=proxy_probe, browser_recheck=browser_recheck, pool_maintainer=pool_maintainer, breaker=breaker)


__all__ = ["FreePlanCheckError", "FreePlanCheckService", "build_free_plan_check_service"]
