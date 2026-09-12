"""Isolated fast and deep liveness checks for registered Free accounts."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import copy
import re
import sys
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
    from .free_failure_runtime import canonical_failure, exception_to_failure
    from .free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider
    from .free_subject_fingerprint import subject_fingerprint
    from .free_register_common import (
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        mask_email,
        plus_trial_from_accounts,
        proxy_error_code,
        proxy_error_label,
        proxy_transport_value,
        safe_log_message,
        timezone_offset_minutes,
    )
except ImportError:
    from free_failure_runtime import canonical_failure, exception_to_failure  # type: ignore[no-redef]
    from free_mailbox_otp import MailboxUrlOtpProvider, build_free_mailbox_otp_provider  # type: ignore[no-redef]
    from free_subject_fingerprint import subject_fingerprint  # type: ignore[no-redef]
    from free_register_common import (  # type: ignore[no-redef]
        FreeRegisterError,
        ProxyBinding,
        atomic_write,
        fingerprint,
        mask_proxy,
        mask_email,
        plus_trial_from_accounts,
        proxy_error_code,
        proxy_error_label,
        proxy_transport_value,
        safe_log_message,
        timezone_offset_minutes,
    )

try:
    from .free_protocol_relogin import (
        ProtocolReloginDeactivated,
        is_deactivated_response as _is_deactivated,
        live_failure_is_transient as _live_failure_is_transient,
        live_response_received as _live_response_received,
        protocol_relogin_proxy,
        run_protocol_relogin,
        wrap_session_transient_retry as _wrap_session_transient_retry,
    )
except ImportError:  # pragma: no cover - top-level recovery import
    from free_protocol_relogin import (  # type: ignore[no-redef]
        ProtocolReloginDeactivated,
        is_deactivated_response as _is_deactivated,
        live_failure_is_transient as _live_failure_is_transient,
        live_response_received as _live_response_received,
        protocol_relogin_proxy,
        run_protocol_relogin,
        wrap_session_transient_retry as _wrap_session_transient_retry,
    )


LIVE_MODES = frozenset({"fast", "deep"})
_ORIGINAL_MAILBOX_URL_OTP_PROVIDER = MailboxUrlOtpProvider
ACTIVE_LIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_LIVE_STATUSES = frozenset({
    "live", "deactivated", "token_expired", "failed",
    "free_live_proxy_blocked", "free_live_session_rejected",
    "free_live_rate_limited", "free_live_upstream_error",
    "free_live_network_error", "free_live_password_required",
})
LIVE_STAGE_LABELS = {
    "free_live_queued": "Free 账号测活排队",
    "free_live_fast": "快速测活",
    "free_live_deep": "深度测活",
    "free_live_email": "深度测活邮箱验证",
    "free_live_mfa": "深度测活动态口令验证",
    "free_live_plan": "刷新套餐与 Plus 资格",
    "free_live_result": "保存 Free 测活结果",
    "free_live_proxy_blocked": "出口或服务端安全策略拒绝",
    "free_live_session_rejected": "深度测活会话被拒绝",
    "free_live_rate_limited": "Free 测活触发限流",
    "free_live_upstream_error": "Free 测活上游服务异常",
    "free_live_network_error": "Free 测活网络异常",
    "free_live_password_required": "深度测活需要真实账号密码",
}



try:
    from .quiet_note import note_stderr
except ImportError:  # pragma: no cover - top-level recovery import
    from quiet_note import note_stderr  # type: ignore[no-redef]

def _live_transport_context(proxy: str, target_url: str, error: BaseException | None = None) -> dict[str, Any]:
    try:
        scheme = str(urlsplit(proxy).scheme or "").lower()
    except (TypeError, ValueError):
        scheme = ""
    try:
        domain = str(urlsplit(target_url).hostname or "").lower()
    except (TypeError, ValueError):
        domain = ""
    code = ""
    if error is not None:
        code = proxy_error_code(error)
        text = str(error).lower()
        if code.startswith("proxy_") and not any(marker in text for marker in ("proxy", "socks", "connect", "407", "curl:")) and any(marker in text for marker in ("tls", "ssl", "handshake", "certificate")):
            code = "tls_connection_failed"
    return {"declared_scheme": scheme, "transport_scheme": scheme, "target_domain": domain, "transport_error_code": code}


_LIVE_ACCOUNT_PATH = "/backend-api/accounts/check/v4-2023-04-27"
_LIVE_ELIGIBILITY_PATH = "/backend-api/aip/first-party/eligibility"
_LIVE_ORIGIN = "https://chatgpt.com"

def _note_stderr(where: str, exc: BaseException) -> None:
    note_stderr('free_live_check', where, exc)

_LIVE_SECURITY_MARKERS = (
    "cloudflare",
    "turnstile",
    "captcha",
    "verify you are human",
    "checking your browser",
    "access denied",
    "cf-chl-",
    "/cdn-cgi/challenge-platform/",
)
_LIVE_FAILURE_STATUSES = frozenset({
    "free_live_proxy_blocked",
    "free_live_session_rejected",
    "free_live_rate_limited",
    "free_live_upstream_error",
    "free_live_network_error",
    "free_live_password_required",
})


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


def _response_content_type(response: Any) -> str:
    headers = getattr(response, "headers", None)
    if not isinstance(headers, Mapping):
        return ""
    for key, value in headers.items():
        if str(key or "").strip().lower() == "content-type":
            return str(value or "").split(";", 1)[0].strip().lower()[:120]
    return ""


def _response_provider_code(response: Any, payload: Mapping[str, Any] | None = None) -> str:
    candidates: list[Mapping[str, Any]] = []
    if isinstance(payload, Mapping):
        candidates.append(payload)
        error = payload.get("error")
        if isinstance(error, Mapping):
            candidates.insert(0, error)
    for candidate in candidates:
        for key in ("error_code", "provider_code", "code", "type", "reason"):
            value = str(candidate.get(key) or "").strip()
            if value:
                return value[:120]
    return ""


def _response_text(response: Any) -> str:
    value = getattr(response, "text", "")
    if isinstance(value, str):
        return value[:32768]
    raw = getattr(response, "content", b"")
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw[:32768]).decode("utf-8", "ignore")
    return str(raw or "")[:32768]


def _live_request_headers(token: str, device_id: str, path: str) -> dict[str, str]:
    """Build the same-origin account headers used by AutoRegister plan checks."""
    normalized_path = str(path or _LIVE_ACCOUNT_PATH).strip() or _LIVE_ACCOUNT_PATH
    return {
        "accept": "*/*",
        "authorization": f"Bearer {token}",
        "referer": f"{_LIVE_ORIGIN}/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-openai-target-path": normalized_path,
        "x-openai-target-route": normalized_path,
        "oai-device-id": str(device_id or "").strip(),
    }


def _prepare_live_session(session: Any, device_id: str) -> Any:
    """Apply task-scoped device cookies and environment isolation to a session."""
    try:
        session.trust_env = False
    except Exception as exc:
        # Session hardening is best-effort; keep the check usable.
        _note_stderr("session_trust_env", exc)
    try:
        session.verify = True
    except Exception as exc:
        # Session hardening is best-effort; keep the check usable.
        _note_stderr("session_verify", exc)
    device = str(device_id or "").strip()
    cookies = getattr(session, "cookies", None)
    setter = getattr(cookies, "set", None)
    if device and callable(setter):
        for domain in ("chatgpt.com", "auth.openai.com"):
            try:
                setter("oai-did", device, domain=domain, path="/")
            except TypeError:
                try:
                    setter("oai-did", device)
                except Exception as exc:
                    # Cookie header pinning is best-effort.
                    _note_stderr("cookie_set_compat", exc)
            except Exception as exc:
                # Fallback cookie APIs may not exist on every session type.
                _note_stderr("cookie_set", exc)
    # Keep the task identity available to adapters that merge default headers.
    try:
        current = getattr(session, "headers", None)
        if hasattr(current, "update") and device:
            current.update({"oai-device-id": device, "referer": f"{_LIVE_ORIGIN}/"})
    except Exception as exc:
        # Header pinning is best-effort; the check proceeds with defaults.
        _note_stderr("header_pinning", exc)
    return session


def _retry_after(response: Any, payload: Mapping[str, Any] | None = None) -> int | None:
    values: list[Any] = []
    if isinstance(payload, Mapping):
        values.extend((payload.get("retry_after_seconds"), payload.get("retry_after")))
        nested_headers = payload.get("headers") or payload.get("_headers")
        if isinstance(nested_headers, Mapping):
            values.extend((nested_headers.get("retry-after"), nested_headers.get("Retry-After")))
    headers = getattr(response, "headers", None)
    if isinstance(headers, Mapping):
        values.extend((headers.get("retry-after"), headers.get("Retry-After")))
    for value in values:
        try:
            parsed = int(float(str(value).strip()))
        except (TypeError, ValueError):
            continue
        if 0 <= parsed <= 86400:
            return parsed
    return None


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


def _failure(exc: BaseException, *, default_code: str, default_label: str) -> dict[str, Any]:
    return exception_to_failure(
        exc,
        node_code=str(getattr(exc, "node_code", "") or default_code),
        node_label=str(getattr(exc, "node_label", "") or default_label),
    )


def delete_deactivated_pool_row(
    pool: Any,
    row_id: str,
    *,
    log_fn: Callable[[str, str], None] | None = None,
    origin: str = "free_live_check",
) -> bool:
    """Remove a row the deep re-login confirmed as deactivated.

    The confirmation uses the same explicit ``account_banned`` classifier
    as the SMS chain (``runtime_policy.is_account_banned_failure`` via
    ``is_deactivated_response``), so ambiguous 403/proxy failures never
    reach this path.  The mailbox row leaves the reusable pool; registration
    results and diagnostic events stay as the audit trail.  When the row
    cannot be removed it is marked unavailable instead, mirroring the SMS
    mark-damaged fallback.
    """
    remover = getattr(pool, "delete", None)
    if not callable(remover):
        return False
    try:
        removed = int(remover([row_id]) or 0)
    except Exception as exc:
        # Deletion must never overwrite the confirmed deactivated result.
        _note_stderr(f"{origin}/deactivated_row_delete", exc)
        removed = 0
    if removed:
        if log_fn is not None:
            log_fn("账号已停用，已自动从 Free 邮箱池移除（注册结果与日志保留）", "warn")
        return True
    marker = getattr(pool, "update", None)
    if callable(marker):
        try:
            marker(row_id, status="unavailable")
            if log_fn is not None:
                log_fn("账号已停用，邮箱行移除失败，已标记为不可用", "warn")
        except Exception as exc:
            _note_stderr(f"{origin}/deactivated_row_mark", exc)
    return False


class FreeLiveCheckService:

    def _note_quiet(self, where: str, exc: BaseException) -> None:
        """Record a swallowed live-check persistence/cleanup fallback on stderr."""
        try:
            print(f"[free_live_check/{where}] {type(exc).__name__}", file=sys.stderr)
        except Exception:
            return

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
        max_concurrency: int = 16,
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
        # ``workers`` is the fallback ceiling for environments where the
        # proxy store cannot answer; the live ceiling follows the shared
        # healthy pool so a larger pool automatically runs more checks.
        self.workers = max(1, min(int(workers), 5))
        self.max_concurrency = max(self.workers, min(int(max_concurrency), 64))
        self.queue_limit = max(self.workers, min(int(queue_limit), 5_000))
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=self.max_concurrency, thread_name_prefix="free-live-check")
        self._gate = ProxyPoolConcurrencyGate(self._dynamic_concurrency)
        self._futures: set[Future[Any]] = set()
        self._jobs = self._load_jobs()
        if recover:
            self._recover_jobs()

    def _dynamic_concurrency(self) -> int:
        """In-flight ceiling: one slot per healthy proxy, capped."""
        try:
            healthy = int(self.proxies.healthy_count())
        except Exception as exc:
            # Pool introspection is advisory; keep the configured fallback
            # ceiling when the store cannot answer.
            _note_stderr("dynamic_concurrency", exc)
            return self.workers
        return max(1, min(healthy, self.max_concurrency))

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

    def _subject_fingerprint(self, email: Any) -> str:
        """Use the diagnostic HMAC for public correlation when available."""
        return subject_fingerprint(self.log_store, email)

    _JOBS_FLUSH_INTERVAL = 0.5

    def _save_jobs(self) -> None:
        atomic_write(self.path, {"version": 1, "jobs": self._jobs})
        self._jobs_flushed_at = time.monotonic()

    def _save_jobs_coalesced(self, *, force: bool = False) -> None:
        """Write the jobs file at most every half second unless forced.

        Stage-only updates used to fsync the whole jobs file per protocol
        node. A crash losing the last coalesced window is harmless for
        recovery: the persisted job is still in an ACTIVE status, so
        ``_recover_jobs`` re-queues it and the check reruns idempotently.
        Terminal states, enqueue and recovery always flush immediately.
        """
        if force or time.monotonic() - getattr(self, "_jobs_flushed_at", 0.0) >= self._JOBS_FLUSH_INTERVAL:
            self._save_jobs()

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
        text = f"[{task_id}/{label}/{stage}] {safe_log_message(message)}"
        fields = {
            "chain": "free",
            "workflow": "live_check",
            "driver": "free",
            "task_id": str(task_id or ""),
            "stage": str(stage or ""),
            "stage_label": str(label or ""),
            "node_code": str(stage or ""),
            "node_label": str(label or ""),
        }
        try:
            self.log_store.add(text, level, **fields)
        except TypeError:
            # Older injected sinks only implement ``add(message, level)``.
            # Keep that compatibility surface while structured sinks receive
            # an explicit workflow scope.
            self.log_store.add(text, level)

    def _public_job(self, job: Mapping[str, Any]) -> dict[str, Any]:
        keys = (
            "task_id", "row_id", "mode", "status", "stage", "created_at",
            "updated_at", "checked_at", "started_at",
            "token_refreshed", "recovered",
        )
        result = {key: copy.deepcopy(job[key]) for key in keys if key in job}
        result["timing"] = self._job_timing(job)
        # Live-check jobs share the same public-state boundary as registration
        # tasks. Keep the historical ``email`` key for existing clients, but
        # expose only a masked value and a short subject reference; the raw
        # address remains in the private mailbox row used by the worker.
        raw_email = str(job.get("email") or "").strip()
        result["email"] = mask_email(raw_email)
        result["email_masked"] = result["email"]
        result["subject_ref_fingerprint"] = self._subject_fingerprint(raw_email)
        result["stage_label"] = LIVE_STAGE_LABELS.get(str(result.get("stage") or ""), str(result.get("stage") or ""))
        if isinstance(job.get("failure"), Mapping):
            result["failure"] = canonical_failure(job["failure"])
        return result

    @staticmethod
    def _job_timing(job: Mapping[str, Any]) -> dict[str, Any]:
        """Project job milestones into the TaskTiming contract used by the UI."""
        created_at = int(job.get("created_at") or 0)
        started_at = int(job.get("started_at") or 0)
        checked_at = job.get("checked_at")
        end = int(checked_at) if checked_at else int(time.time())
        execution_start = started_at or created_at
        stages = job.get("stages") if isinstance(job.get("stages"), list) else []
        stage_rows = []
        for span in stages:
            if not isinstance(span, Mapping):
                continue
            span_start = int(span.get("started_at") or 0)
            span_end = int(span.get("finished_at") or end)
            stage_rows.append({
                "code": str(span.get("code") or ""),
                "label": str(span.get("label") or span.get("code") or ""),
                "elapsed_seconds": max(0, span_end - span_start),
                "visits": 1,
            })
        return {
            "queued_at": created_at,
            "started_at": created_at,
            "execution_started_at": execution_start,
            "finished_at": checked_at,
            "elapsed_seconds": max(0, end - created_at),
            "queue_elapsed_seconds": max(0, execution_start - created_at),
            "execution_elapsed_seconds": max(0, end - execution_start),
            "stages": stage_rows,
        }

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            jobs = [self._public_job(job) for job in sorted(self._jobs.values(), key=lambda item: int(item.get("created_at") or 0), reverse=True)]
        active = sum(1 for job in jobs if job.get("status") in ACTIVE_LIVE_STATUSES)
        return {
            "running": active > 0,
            # Effective parallelism: the dynamic healthy-pool ceiling rather
            # than the static fallback, so the UI reflects real throughput.
            "workers": self._gate.current_limit(),
            "max_concurrency": self.max_concurrency,
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
                    "started_at": 0,
                    "stages": [],
                    "device_id": f"free-live-{secrets.token_hex(16)}",
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
                # Do not place the private mailbox address in free-form log
                # text.  The log facade applies a second redaction pass, but
                # masking at the producer keeps this safe for injected/legacy
                # log sinks as well.
                self._log(task_id, "free_live_queued", f"{mask_email(entry.email) or '<邮箱>'} 已加入{'快速' if selected_mode == 'fast' else '深度'}测活队列")
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
        registration_ip = str(result.get("registration_ip") or private_state.get("registration_ip") or "").strip()
        # The proxy recorded at registration is history only.  Every check
        # allocates a healthy proxy from the shared pool at execution time
        # (see ``_allocate_proxy``); the fields below are placeholders that
        # the executor overwrites with the allocated binding.
        return {
            "task_id": str(job.get("task_id") or ""),
            "row_id": row_id,
            "email": entry.email,
            "mailbox_url": entry.mailbox_url,
            # Remail mailboxes must resolve through the shared OTP provider's
            # remail branch; without these fields the pickup URL is fetched as
            # a plain URL and the provider rejects it with HTTP 400.
            "mailbox_source": str(private_state.get("source") or "url").strip().lower() or "url",
            "service_token": str(private_state.get("service_token") or private_state.get("serviceToken") or ""),
            "proxy": "",
            "proxy_id": "",
            "proxy_scheme": "",
            "proxy_country": "",
            "proxy_group": "",
            "proxy_masked": "",
            "proxy_fingerprint": "",
            "registration_ip": registration_ip,
            "live_check_ip": str(result.get("live_check_ip") or "").strip(),
            "expected_exit_ip": str(result.get("expected_exit_ip") or "").strip(),
            "exit_ip": str(result.get("exit_ip") or "").strip(),
            "device_id": str(job.get("device_id") or "").strip(),
            "access_token": str(result.get("access_token") or ""),
            "password": str(result.get("password") or ""),
            "totp_secret": str(result.get("totp_secret") or ""),
            "saved_result": result,
        }

    def _allocate_proxy(self, config: Mapping[str, Any], owner: str, task_id: str, exclude_proxy_ids: Sequence[str] = ()) -> ProxyBinding:
        """Allocate one healthy proxy from the shared pool for this check.

        Live checks never pin the proxy recorded at registration: that value
        may be stale or rejected by OpenAI edge hosts, while every Free
        workflow shares the same healthy_random pool (mirrors rebind).
        ``exclude_proxy_ids`` keeps proxy-swapping retries off exits that
        already failed in this run.
        """
        binder = getattr(self.proxies, "bind", None)
        if not callable(binder):
            raise FreeRegisterError("free_live_network_error", "Free 账号测活", "共享 Free 代理池不可用", retryable=False)
        bindings = binder(
            1,
            probe=self.proxy_probe,
            probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
            driver="protocol",
            exclude_proxy_ids=exclude_proxy_ids,
            perform_probe=False,
        )
        if not bindings:
            raise FreeRegisterError("free_live_network_error", "Free 账号测活", "共享 Free 代理池没有健康代理", retryable=False)
        binding = bindings[0]
        lease = getattr(self.proxies, "lease", None)
        if callable(lease) and str(getattr(binding, "proxy_id", "") or ""):
            lease(binding, owner=owner, batch_id=owner, task_id=task_id)
        return binding

    def _set_job(self, task_id: str, **values: Any) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(task_id)
            if job is None:
                return {}
            previous_stage = str(job.get("stage") or "")
            job.update(values)
            now = int(time.time())
            job["updated_at"] = now
            # Track per-stage spans so the run-log popover can show the same
            # 节点耗时 breakdown as registration tasks.
            new_stage = str(job.get("stage") or "")
            stages = job.get("stages") if isinstance(job.get("stages"), list) else []
            if new_stage != previous_stage or not stages:
                if stages and isinstance(stages[-1], dict) and stages[-1].get("finished_at") is None:
                    stages[-1]["finished_at"] = now
                stages.append({
                    "code": new_stage or "free_live_queued",
                    "label": LIVE_STAGE_LABELS.get(new_stage, new_stage or "排队"),
                    "started_at": now,
                    "finished_at": None,
                })
            job["stages"] = stages
            if job.get("checked_at") is not None:
                for span in stages:
                    if isinstance(span, dict) and span.get("finished_at") is None:
                        span["finished_at"] = int(job["checked_at"])
            self._save_jobs_coalesced(force=str(values.get("status") or "") in TERMINAL_LIVE_STATUSES)
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
            except Exception as exc:
                # Result persistence remains authoritative if a legacy/test
                # pool does not expose the optional status update API.
                self._note_quiet("pool_status_update", exc)
            task_id = str(current.get("task_id") or "")
            if task_id and self.task_store is not None:
                try:
                    get_one = getattr(self.task_store, "get_task", None)
                    if callable(get_one):
                        # Single-row flip: the dirty-save channel applies the
                        # same per-row CAS without loading the whole table.
                        task = get_one(task_id)
                        if isinstance(task, dict) and str(task.get("status") or "") == "partial_success":
                            task.update({"status": "success", "stage": "free_result_save", "error": ""})
                            task.pop("failure", None)
                            task["result"] = copy.deepcopy(current)
                            self.task_store.save({task_id: task}, partial_snapshot=True)
                    else:
                        tasks = self.task_store.load()
                        task = tasks.get(task_id)
                        if isinstance(task, dict) and str(task.get("status") or "") == "partial_success":
                            task.update({"status": "success", "stage": "free_result_save", "error": ""})
                            task.pop("failure", None)
                            task["result"] = copy.deepcopy(current)
                            self.task_store.save(tasks)
                except Exception as exc:
                    # Keep the result file and mailbox row authoritative when
                    # reading legacy task snapshots is not possible.
                    self._note_quiet("partial_task_flip", exc)
        return current

    def _worker(self, task_id: str) -> None:
        # One healthy proxy backs each in-flight check: queue the job (keep
        # the queued stage visible) until a pool slot frees up.
        with self._gate:
            self._worker_locked(task_id)

    def _worker_locked(self, task_id: str) -> None:
        with self._lock:
            initial_job = dict(self._jobs.get(task_id) or {})
        mode = str(initial_job.get("mode") or "fast")
        job = self._set_job(
            task_id,
            status="running",
            stage="free_live_fast" if mode == "fast" else "free_live_deep",
            started_at=int(time.time()),
        )
        if not job:
            return
        lease_owner = task_id
        context: dict[str, Any] = {}
        try:
            config = self._config()
            context = self._context(job)
            mode = str(job.get("mode") or "fast")
            stage = "free_live_fast" if mode == "fast" else "free_live_deep"
            # Fast and deep checks enter their real authenticated transport
            # directly.  An exit-IP-style observation is neither required
            # for authentication nor evidence of token validity, so it is not
            # a hidden preflight step.
            # Deep re-logins sample the shared pool: one dead or edge-blocked
            # exit must not fail the run while other healthy proxies exist,
            # so retryable failures swap to a fresh, unused proxy (bounded).
            max_attempts = 5 if mode == "deep" else 1
            tried_proxy_ids: list[str] = []
            live_ip = ""
            self._set_job(task_id, stage=stage)
            runner = self.fast_runner if mode == "fast" else self.deep_runner
            checked: dict[str, Any] = {}
            while True:
                binding = self._allocate_proxy(config, lease_owner, task_id, exclude_proxy_ids=tried_proxy_ids)
                tried_proxy_ids.append(str(binding.proxy_id or ""))
                context.update({
                    "proxy": str(binding.proxy),
                    "proxy_id": str(binding.proxy_id or ""),
                    "proxy_scheme": str(binding.scheme or ""),
                    "proxy_country": str(binding.country or ""),
                    "proxy_group": str(binding.group or ""),
                    "proxy_masked": str(binding.masked or ""),
                    "proxy_fingerprint": str(binding.fingerprint or fingerprint(str(binding.proxy))),
                })
                try:
                    checked = dict(runner(context, config))
                    break
                except FreeRegisterError as exc:
                    attempt_failure = _failure(exc, default_code=stage, default_label=LIVE_STAGE_LABELS[stage])
                    if len(tried_proxy_ids) >= max_attempts or not bool(attempt_failure.get("retryable")):
                        raise
                    self._log(
                        task_id, stage,
                        f"第 {len(tried_proxy_ids)} 次尝试未通过（{attempt_failure.get('node_code')}），换代理重试",
                        "warn",
                    )
                finally:
                    if binding.proxy_id:
                        try:
                            self.proxies.release(binding, owner=lease_owner)
                        except Exception as exc:
                            self._note_quiet("proxy_release", exc)
                    binding = None
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
                "expected_exit_ip": context.get("expected_exit_ip", ""),
                "exit_ip": live_ip or context.get("exit_ip", ""),
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
                token_refreshed=token_refreshed,
                failure=copy.deepcopy(failure) if failure else None,
            )
            label = {
                "live": "账号正常",
                "deactivated": "账号已停用",
                "token_expired": "Token 已失效，建议深度测活",
                "free_live_proxy_blocked": "当前出口或服务端安全策略拒绝了快速查询，不等于账号已停用",
                "free_live_session_rejected": "深度测活会话被拒绝，未确认账号停用",
                "failed": "测活失败",
            }.get(status, "测活完成")
            self._log(task_id, "free_live_result", label, "success" if status == "live" else "warn" if status == "token_expired" else "error")
            if mode == "deep" and status == "deactivated":
                # A confirmed re-login deactivation means the account is gone;
                # drop it from the reusable pool per the 401-rerun contract.
                self._delete_deactivated_row(task_id, str(context["row_id"]))
        except Exception as exc:
            self._finish_exception(task_id, exc, row_id=str(context.get("row_id") or job.get("row_id") or ""))

    def _delete_deactivated_row(self, task_id: str, row_id: str) -> None:
        delete_deactivated_pool_row(
            self.pool,
            row_id,
            log_fn=lambda message, level: self._log(task_id, "free_live_result", message, str(level)),
        )

    def _finish_exception(self, task_id: str, exc: BaseException, *, row_id: str = "", code: str = "free_live_check", label: str = "Free 账号测活") -> None:
        failure = _failure(exc, default_code=code, default_label=label)
        checked_at = int(time.time())
        job = self._set_job(task_id, status="failed", stage=failure["node_code"], checked_at=checked_at, failure=failure)
        target_row = row_id or str(job.get("row_id") or "")
        if target_row:
            live_status = str(failure.get("node_code") or "") if str(failure.get("node_code") or "") in _LIVE_FAILURE_STATUSES else "failed"
            result_values: dict[str, Any] = {
                "live_check_status": live_status,
                "live_check_mode": str(job.get("mode") or ""),
                "live_check_task_id": task_id,
                "live_checked_at": checked_at,
                "live_check_token_refreshed": False,
                "live_check_failure": failure,
            }
            self._save_live_result(target_row, result_values)
        self._log(task_id, failure["node_code"], failure["public_message"], "error")

    def _query_account(
        self,
        session: Any,
        token: str,
        *,
        device_id: str = "",
        failure_node: str = "free_live_fast",
        proxy: str = "",
    ) -> dict[str, Any]:
        """Query account state through the shared, same-origin live adapter."""
        _prepare_live_session(session, device_id)
        accounts_url = f"{_LIVE_ORIGIN}{_LIVE_ACCOUNT_PATH}?timezone_offset_min={timezone_offset_minutes()}"
        accounts_headers = _live_request_headers(token, device_id, _LIVE_ACCOUNT_PATH)
        try:
            accounts_response = session.get(
                accounts_url,
                headers=accounts_headers,
                timeout=20,
            )
        except Exception as exc:
            transport_context = _live_transport_context(proxy, accounts_url, exc)
            raise FreeRegisterError(
                "free_live_network_error",
                "Free 测活网络异常",
                f"账号接口请求异常（{type(exc).__name__}）",
                retryable=True,
                error_code=transport_context.get("transport_error_code") or "free_live_network_error",
                action_hint="保留原注册结果，检查当前绑定代理后重试",
                **transport_context,
            ) from exc
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
        if accounts_status == 403:
            content_type = _response_content_type(accounts_response)
            body = _response_text(accounts_response).lower()
            security_page = "html" in content_type or any(marker in body for marker in _LIVE_SECURITY_MARKERS)
            detail = "当前出口或服务端安全策略拒绝了账号查询"
            if security_page:
                detail = "当前出口返回安全挑战或 HTML 拒绝页"
            node_code = failure_node if failure_node in {"free_live_fast", "free_live_session_rejected"} else "free_live_proxy_blocked"
            if node_code == "free_live_fast":
                node_code = "free_live_proxy_blocked"
            node_label = LIVE_STAGE_LABELS[node_code]
            raise FreeRegisterError(
                node_code,
                node_label,
                f"{detail}（HTTP 403）",
                retryable=True,
                provider_status=403,
                provider_code=_response_provider_code(accounts_response, accounts),
                error_code=node_code,
                action_hint=(
                    "可以手动执行深度测活确认；本次结果不等于账号已停用"
                    if node_code == "free_live_proxy_blocked"
                    else "保留原注册结果，检查当前会话和绑定代理后重试"
                ),
                page_type="security_challenge" if security_page else "access_denied",
                content_type=content_type,
            )
        if not 200 <= accounts_status < 300:
            if accounts_status == 429:
                raise FreeRegisterError(
                    "free_live_rate_limited",
                    "Free 测活触发限流",
                    "账号接口触发服务端限流",
                    retryable=True,
                    provider_status=429,
                    provider_code=_response_provider_code(accounts_response, accounts),
                    error_code="free_live_rate_limited",
                    action_hint="等待 Retry-After 冷却后重试",
                    retry_after_seconds=_retry_after(accounts_response, accounts),
                )
            if accounts_status >= 500 or accounts_status == 0:
                raise FreeRegisterError(
                    "free_live_upstream_error" if accounts_status >= 500 else "free_live_network_error",
                    "Free 测活上游服务异常" if accounts_status >= 500 else "Free 测活网络异常",
                    f"账号接口返回 HTTP {accounts_status or '-'}",
                    retryable=True,
                    provider_status=accounts_status or None,
                    provider_code=_response_provider_code(accounts_response, accounts),
                    error_code="free_live_upstream_error" if accounts_status >= 500 else "free_live_network_error",
                    action_hint="保留原注册结果，稍后重试",
                    retry_after_seconds=_retry_after(accounts_response, accounts),
                )
            raise FreeRegisterError(
                "free_live_fast",
                "快速测活",
                f"账号接口返回 HTTP {accounts_status or '-'}",
                provider_status=accounts_status or None,
                error_code="free_live_account_http_failed",
                retryable=False,
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
                f"{_LIVE_ORIGIN}{_LIVE_ELIGIBILITY_PATH}",
                headers=_live_request_headers(token, device_id, _LIVE_ELIGIBILITY_PATH),
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
        device_id = str(context.get("device_id") or f"free-live-{secrets.token_hex(16)}")
        _prepare_live_session(session, device_id)
        _wrap_session_transient_retry(session)
        transport_proxy = proxy_transport_value(
            context["proxy"],
            driver="protocol",
            socks5_dns_mode=str(_config.get("proxy_socks5_dns_mode") or "remote"),
        )
        if not transport_proxy:
            raise FreeRegisterError("free_live_fast", "快速测活", "测活代理格式无效", retryable=False)
        session.proxies = {"http": transport_proxy, "https": transport_proxy}
        try:
            return self._query_account(
                session,
                str(context["access_token"]),
                device_id=device_id,
                failure_node="free_live_fast",
                proxy=transport_proxy,
            )
        except FreeRegisterError:
            raise
        except Exception as exc:
            transport_context = _live_transport_context(transport_proxy, _LIVE_ORIGIN + _LIVE_ACCOUNT_PATH, exc)
            raise FreeRegisterError(
                "free_live_fast",
                "快速测活",
                f"账号在线查询异常（{type(exc).__name__}）",
                error_code=transport_context.get("transport_error_code") or "free_live_network_error",
                **transport_context,
            ) from exc
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()

    def _run_deep(self, context: Mapping[str, Any], config: Mapping[str, Any]) -> Mapping[str, Any]:
        task_id = str(context["task_id"])
        proxy = protocol_relogin_proxy(str(context.get("proxy") or ""), config, stage_label="深度测活")
        device_id = str(context.get("device_id") or f"free-live-{secrets.token_hex(16)}")
        log_fn = lambda message, level="info": self._log(task_id, "free_live_deep", str(message), str(level))

        def stage_fn(code: str) -> None:
            if "mfa" in code:
                self._set_job(task_id, stage="free_live_mfa")
            elif "email" in code:
                self._set_job(task_id, stage="free_live_email")
            else:
                self._set_job(task_id, stage="free_live_deep")

        otp = self._build_deep_otp_provider(context, config, proxy, log_fn, task_id)

        def post_login(transport: Any, token: str) -> Mapping[str, Any]:
            checked = dict(
                self._query_account(
                    getattr(transport, "session", None),
                    token,
                    device_id=device_id,
                    failure_node="free_live_session_rejected",
                    proxy=proxy,
                )
            )
            if checked.get("status") == "live":
                checked["access_token"] = token
            return checked

        try:
            return dict(
                run_protocol_relogin(
                    context,
                    config,
                    proxy=proxy,
                    otp=otp,
                    log_fn=log_fn,
                    stage_fn=stage_fn,
                    device_id=device_id,
                    post_login=post_login,
                    error_context_fn=lambda exc: _live_transport_context(proxy, "https://auth.openai.com/", exc),
                )
            )
        except ProtocolReloginDeactivated as exc:
            return self._deactivated_result(exc.http_status)

    def _build_deep_otp_provider(
        self,
        context: Mapping[str, Any],
        config: Mapping[str, Any],
        proxy: str,
        log_fn: Callable[..., Any],
        task_id: str,
    ) -> Any:
        stage_fn = lambda _task_id, code: self._set_job(task_id, stage="free_live_email" if "email" in code else "free_live_deep")
        if MailboxUrlOtpProvider is _ORIGINAL_MAILBOX_URL_OTP_PROVIDER:
            return build_free_mailbox_otp_provider(
                str(context["mailbox_url"]), proxy, config,
                log_fn=log_fn, task_id=task_id, stage_fn=stage_fn,
                mailbox_source=str(context.get("mailbox_source") or "url"),
                mailbox_email=str(context.get("email") or ""),
                service_token=str(context.get("service_token") or ""),
            )
        # Preserve the historic module-level injection point used by
        # tests and integrations while keeping production on the shared
        # Free mailbox network policy above.
        return MailboxUrlOtpProvider(
            str(context["mailbox_url"]), proxy,
            timeout=int(config.get("email_code_timeout") or 90),
            log_fn=log_fn, task_id=task_id, stage_fn=stage_fn,
        )

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
        with self._lock:
            self._save_jobs()


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
    "delete_deactivated_pool_row",
    "LIVE_MODES",
    "LIVE_STAGE_LABELS",
    "TERMINAL_LIVE_STATUSES",
]
