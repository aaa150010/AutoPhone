"""Rerun / 2FA / password retry queueing mixin for FreeRegisterManager.

Split out of ``free_register_runtime.py``; the manager composes this mixin so
the responsibility band keeps its own module.  Methods rely on attributes and
methods defined by the manager (``self._lock``, ``self.pool``, ``self.proxies``,
``self.public_state`` ...).  Module-level globals referenced by the methods
resolve through the composing runtime module via ``_runtime_module()`` so
existing tests can keep patching ``mac_overrides.free_register_runtime.<name>``.
"""

from __future__ import annotations

import copy
import secrets
import threading
import time
from typing import Any, Mapping, Sequence

try:
    from .free_register_common import (
        ProxyBinding,
        FreeRegisterError,
        fingerprint as _fingerprint,
        mask_proxy as _mask_proxy,
        safe_log_message as _safe_log_message,
    )
    from .free_account_service import password_retry_allowed
    from .free_failure_runtime import (
        has_account_result,
        merge_account_result_fields,
    )
    from .free_runtime_info import runtime_info
except ImportError:  # macOS launcher imports overrides as top-level modules.
    from free_register_common import (  # type: ignore[no-redef]
        ProxyBinding,
        FreeRegisterError,
        fingerprint as _fingerprint,
        mask_proxy as _mask_proxy,
        safe_log_message as _safe_log_message,
    )
    from free_account_service import password_retry_allowed  # type: ignore[no-redef]
    from free_failure_runtime import (  # type: ignore[no-redef]
        has_account_result,
        merge_account_result_fields,
    )
    from free_runtime_info import runtime_info  # type: ignore[no-redef]


def _runtime_module() -> Any:
    """Resolve the composing runtime module lazily.

    Patchable globals such as ``PriorityExecutor`` and ``CamoufoxRunner`` stay
    addressable on ``free_register_runtime`` so existing tests and integrations
    can patch them there; resolving through the module keeps that contract
    intact.
    """
    try:
        from . import free_register_runtime as runtime
    except ImportError:  # macOS launcher imports overrides as top-level modules.
        import free_register_runtime as runtime  # type: ignore[no-redef]
    return runtime


class FreeRegisterRetryMixin:
    """Methods moved verbatim from the FreeRegisterManager band."""





    def rerun(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        """Queue a failed account without starting a competing Free batch."""
        normalized = str(task_id or "").strip()
        with self._lock:
            original = copy.deepcopy(self._tasks.get(normalized))
        if not original:
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "没有找到对应的 Free 任务", retryable=False)
        if str(original.get("status") or "") not in {"failed", "stopped", "pending_rerun"}:
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "只有失败或已停止的 Free 任务可以重跑", retryable=False)
        failure = original.get("failure") if isinstance(original.get("failure"), Mapping) else {}
        node_code = str(failure.get("node_code") or original.get("stage") or "free_rerun")
        return self._enqueue_retry(original, config, retry_node=node_code, twofa_retry=False)

    def _registration_account_exists(
        self,
        row_id: str,
        *snapshots: Mapping[str, Any] | None,
    ) -> bool:
        """Check durable and historical task snapshots before a new signup."""
        candidates: list[Mapping[str, Any] | None] = list(snapshots)
        reader = getattr(self.pool, "result_with_status", None)
        if callable(reader):
            try:
                durable, readable = reader(str(row_id or ""))
            except Exception as exc:
                raise FreeRegisterError(
                    "free_result_store",
                    "读取 Free 账号结果",
                    "Free 账号结果暂时无法确认，为避免重复注册已停止本次操作",
                    retryable=True,
                    error_code="free_result_read_failed",
                    action_hint="检查 Free 结果文件和数据目录权限后重试",
                    provider_code=type(exc).__name__,
                ) from exc
            if not readable:
                raise FreeRegisterError(
                    "free_result_store",
                    "读取 Free 账号结果",
                    "Free 账号结果暂时无法确认，为避免重复注册已停止本次操作",
                    retryable=True,
                    error_code="free_result_read_failed",
                    action_hint="检查 Free 结果文件和数据目录权限后重试",
                )
        else:
            try:
                durable = self.pool.result(str(row_id or ""))
            except Exception as exc:
                raise FreeRegisterError(
                    "free_result_store",
                    "读取 Free 账号结果",
                    "Free 账号结果暂时无法确认，为避免重复注册已停止本次操作",
                    retryable=True,
                    error_code="free_result_read_failed",
                    action_hint="检查 Free 结果文件和数据目录权限后重试",
                    provider_code=type(exc).__name__,
                ) from exc
        candidates.append(durable if isinstance(durable, Mapping) else None)
        # A previous successful task can outlive a later failure task.  Keep
        # that account evidence even when a legacy result file was truncated.
        for task in self._tasks.values():
            if str(task.get("row_id") or "") != str(row_id or ""):
                continue
            candidates.append(task)
            result = task.get("result")
            candidates.append(result if isinstance(result, Mapping) else None)
        return self._has_existing_account_result(*candidates)

    def _enqueue_retry(
        self,
        original: Mapping[str, Any],
        config: Mapping[str, Any],
        *,
        retry_node: str,
        twofa_retry: bool = False,
        password_retry: bool = False,
    ) -> dict[str, Any]:
        if twofa_retry and password_retry:
            raise FreeRegisterError(
                "free_retry",
                "重试 Free 任务",
                "2FA 重试和密码重试不能同时提交",
                retryable=False,
                error_code="free_retry_modes_conflict",
            )
        continuation = bool(twofa_retry or password_retry)
        row_id = str(original.get("row_id") or "").strip()
        if not row_id:
            raise FreeRegisterError("free_rerun", "重跑 Free 账号", "任务没有绑定 Free 邮箱", retryable=False)
        self._ensure_runtime_owner()
        retry_key = f"{row_id}:{retry_node}"
        with self._lock:
            active_id = self._retry_leases.get(retry_key)
            if active_id:
                active = self._tasks.get(active_id)
                if active and str(active.get("status") or "") in {"queued", "running"}:
                    return self._public_task(active)
                self._retry_leases.pop(retry_key, None)
            row_state = self.pool._row_state(row_id)
            pool_status = str(row_state.get("status") or "")
            # Password continuation is a post-registration operation. Read the
            # durable result before touching mailbox/proxy state so a stale
            # task snapshot cannot accidentally replay signup.
            saved_result: dict[str, Any] = {}
            if password_retry:
                stored = self.pool.result(row_id)
                if isinstance(stored, Mapping):
                    saved_result = copy.deepcopy(dict(stored))
                snapshot_result = original.get("result")
                if isinstance(snapshot_result, Mapping):
                    saved_result = merge_account_result_fields(snapshot_result, saved_result)
                if not str(saved_result.get("access_token") or "").strip():
                    raise FreeRegisterError(
                        "free_password_retry",
                        "重试 Free 账号密码设置",
                        "原账号没有可用 access token",
                        retryable=False,
                        error_code="free_password_retry_token_missing",
                    )
                if not password_retry_allowed(saved_result):
                    raise FreeRegisterError(
                        "free_password_retry",
                        "重试 Free 账号密码设置",
                        "该账号当前没有可补设的密码状态",
                        retryable=False,
                        error_code="free_password_retry_not_pending",
                    )
            # This must run before changing a pending row back to available or
            # reserving it again.  Two-factor retries are continuations of an
            # existing account and intentionally bypass this registration guard.
            if not continuation and self._registration_account_exists(row_id, original):
                raise FreeRegisterError(
                    "free_rerun",
                    "重跑 Free 账号",
                    "该邮箱已有已保存的 Free 账号结果，不能再次走整条注册流程；请使用 2FA 重试、已有账号登录或测活",
                    retryable=False,
                    error_code="free_rerun_account_result_exists",
                    action_hint="使用“重试 2FA”、已有账号登录或测活；不要重复提交注册邮箱",
                )
            if not continuation:
                if pool_status == "pending_rerun":
                    self.pool.update(row_id, status="available", batch_id="", stage="", error="", reusable_after_failure=False)
                    pool_status = "available"
                if pool_status != "available" or self.pool.entry(row_id) is None:
                    raise FreeRegisterError("free_rerun", "重跑 Free 账号", "该账号当前不可重跑，请先在 Free 邮箱中心恢复为可用", retryable=False, error_code="free_rerun_mailbox_unavailable")
            elif twofa_retry:
                if pool_status not in {"twofa_pending", "available", "pending_rerun"}:
                    raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该账号当前没有可重试的 2FA 状态", retryable=False)
            else:
                # A password continuation may follow a partial 2FA result or a
                # legacy pending-rerun row. It must never require the mailbox to
                # be reset to ``available`` and must reject an active task.
                if pool_status in {"queued", "running", "reserved"}:
                    raise FreeRegisterError(
                        "free_password_retry",
                        "重试 Free 账号密码设置",
                        "该账号当前已有续跑任务",
                        retryable=False,
                        error_code="free_password_retry_active",
                    )

            active_batch = bool(
                self._executor
                or self._shutdown_pending
                or (
                    self._heartbeat_thread is not None
                    and self._heartbeat_thread.is_alive()
                )
            )
            if active_batch and (self._executor is None or not self._futures):
                # The final callback has begun executor shutdown. Its queue
                # already contains sentinels, so a continuation cannot be
                # submitted safely until the batch is fully drained.
                raise FreeRegisterError(
                    "free_retry",
                    "重试 Free 任务",
                    "Free 批次正在收尾，请稍后重试",
                    retryable=True,
                    error_code="free_batch_shutdown_pending",
                )
            batch_id = str(self._batch_id or "") if active_batch else f"free-retry-{int(time.time())}-{secrets.token_hex(4)}"
            driver = str(original.get("driver") or config.get("driver") or "protocol").strip().lower()
            if driver not in {"protocol", "camoufox"}:
                raise FreeRegisterError("free_rerun", "重跑 Free 账号", "Free 注册链路无效", retryable=False)
            mailbox = self.pool.entry(row_id)
            if mailbox is None:
                raise FreeRegisterError("free_rerun", "重跑 Free 账号", "Free 邮箱记录不存在", retryable=False)
            # The SQLite/legacy mailbox row keeps Remail's service token in
            # its private payload while ``FreeMailbox.mailbox_url`` remains
            # the stable base endpoint.  Preserve that source boundary when
            # creating a retry task; otherwise the Camoufox adapter defaults
            # to the generic URL client and requests the bare Remail endpoint
            # without its email/token query parameters.
            mailbox_source = str(
                row_state.get("source") or original.get("mailbox_source") or "url"
            ).strip().lower()
            if mailbox_source != "remail":
                mailbox_source = "url"
            service_token = str(
                row_state.get("service_token")
                or row_state.get("serviceToken")
                or original.get("service_token")
                or ""
            ).strip()
            reserved = False
            mailbox_lease_acquired = False
            if not continuation:
                self.pool.reserve([mailbox], batch_id)
                reserved = True
            proxy_content = ""
            binding: ProxyBinding | None = None
            retry_id = ""
            submitted = False
            # ``active_batch`` is false when this retry must create its own
            # heartbeat/executor.  Track that intent before starting either so
            # a constructor/thread-start failure can still unwind cleanly.
            created_executor = not active_batch
            previous_batch_id = self._batch_id
            previous_last_config = copy.deepcopy(self._last_config)
            try:
                # Retry tasks may be created without passing through
                # ``start``/``preflight``.  Apply the same transport policy
                # before binding so a production ``remote`` SOCKS5 DNS mode
                # is not accidentally downgraded to local resolution.
                self.proxies.configure_policy(
                    failure_threshold=int(config.get("proxy_failure_threshold") or 2),
                    quarantine_seconds=int(config.get("proxy_quarantine_seconds") or 600),
                    health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
                    tls_verify=bool(config.get("proxy_tls_verify", True)),
                    tls_compat_fallback=bool(config.get("proxy_tls_compat_fallback", True)),
                    socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
                    allocation_mode="healthy_random",
                )
                # Keep a password continuation on the proxy that created the
                # account whenever its durable identity is still present. This
                # avoids changing the authenticated network context and also
                # avoids treating a post-registration retry as a new signup.
                original_proxy = str(
                    original.get("proxy") or row_state.get("proxy") or ""
                ).strip()
                original_proxy_id = str(
                    original.get("proxy_id") or row_state.get("proxy_id") or ""
                ).strip()
                original_proxy_available = False
                matched_proxy_record: Mapping[str, Any] | None = None
                if password_retry and (original_proxy or original_proxy_id):
                    try:
                        records = self.proxies._load()  # type: ignore[attr-defined]
                    except Exception:
                        records = []
                    for record in records if isinstance(records, list) else []:
                        if not isinstance(record, Mapping):
                            continue
                        configured = str(record.get("_normalized") or "").strip()
                        record_id = str(record.get("proxy_id") or "").strip()
                        if (original_proxy_id and record_id == original_proxy_id) or (original_proxy and configured == original_proxy):
                            original_proxy_available = True
                            matched_proxy_record = record
                            # Older task snapshots persisted the address but
                            # not the pool identity. Recover the authoritative
                            # ID so lease/release and health bookkeeping target
                            # the same row.
                            if not original_proxy_id:
                                original_proxy_id = record_id
                            if not original_proxy:
                                original_proxy = configured
                            break
                if password_retry and original_proxy and original_proxy_available:
                    record = matched_proxy_record or {}
                    record_scheme = str(record.get("scheme") or "").strip().lower()
                    record_effective_scheme = str(
                        record.get("effective_scheme") or record_scheme
                    ).strip().lower()
                    binding = ProxyBinding(
                        original_proxy,
                        str(original.get("proxy_fingerprint") or original_proxy_id or _fingerprint(original_proxy)),
                        str(original.get("proxy_masked") or record.get("masked") or _mask_proxy(original_proxy)),
                        str(original.get("expected_exit_ip") or original.get("exit_ip") or row_state.get("exit_ip") or ""),
                        proxy_id=original_proxy_id,
                        scheme=str(original.get("proxy_scheme") or row_state.get("proxy_scheme") or record_scheme),
                        country=str(original.get("proxy_country") or row_state.get("proxy_country") or record.get("country") or ""),
                        group=str(original.get("proxy_group") or row_state.get("proxy_group") or record.get("group") or ""),
                        effective_scheme=str(original.get("proxy_effective_scheme") or original.get("proxy_scheme") or row_state.get("proxy_scheme") or record_effective_scheme),
                    )
                else:
                    bindings = self.proxies.bind(
                        1,
                        content=proxy_content,
                        probe=self.proxy_probe,
                        probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
                        driver=driver,
                        perform_probe=False,
                        health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
                    )
                    if not bindings:
                        raise FreeRegisterError("free_proxy_binding", "绑定 Free 代理", "当前没有可用健康代理", retryable=True)
                    binding = bindings[0]
                now = int(time.time())
                retry_id = f"{batch_id}-{secrets.token_hex(3)}"
                if not continuation and self.mailbox_leases is not None:
                    lease = self.mailbox_leases.acquire(
                        row_id,
                        task_id=retry_id,
                        batch_id=batch_id,
                        driver=driver,
                    )
                    if lease is None:
                        raise FreeRegisterError(
                            "free_mailbox_lease",
                            "预留 Free 邮箱租约",
                            "Free 邮箱租约已被其他任务占用",
                            retryable=True,
                            error_code="free_mailbox_lease_conflict",
                        )
                    mailbox_lease_acquired = True
                workers = max(1, min(int(config.get("concurrency") or self._last_config.get("concurrency") or 3), 16))
                # A task snapshot may intentionally expose only capability
                # flags after restart, while the private result file still
                # contains the account password needed for an existing-login
                # or 2FA retry.  Merge the durable result as a fill-only
                # fallback; never copy secrets into the public task shape.
                original_result = (
                    dict(original.get("result") or {})
                    if isinstance(original.get("result"), Mapping) else {}
                )
                saved_result = self.pool.result(row_id)
                merged_result = merge_account_result_fields(
                    original_result,
                    saved_result if isinstance(saved_result, Mapping) else {},
                )
                if password_retry:
                    # The durable continuation marker is authoritative; a
                    # stale task snapshot must not turn a pending password into
                    # an already-enabled result.
                    merged_result["password_status"] = "pending"
                task = {
                    "task_id": retry_id,
                    "ordinal": int(original.get("ordinal") or 1),
                    "slot_id": f"{batch_id}-retry",
                    "slot_index": 0,
                    "concurrency_limit": workers,
                    "status": "queued",
                    "created_at": now,
                    "updated_at": now,
                    "timing": self._timing_record({"created_at": now}),
                    "batch_id": batch_id,
                    "run_mode": "free_register",
                    "driver": driver,
                    "email": mailbox.email,
                    "row_id": row_id,
                    "mailbox_url": mailbox.mailbox_url,
                    "mailbox_source": mailbox_source,
                    "service_token": service_token if mailbox_source == "remail" else "",
                    "proxy": binding.proxy,
                    "proxy_id": binding.proxy_id,
                    "proxy_scheme": binding.scheme,
                    "proxy_effective_scheme": getattr(binding, "effective_scheme", "") or binding.scheme,
                    "proxy_country": binding.country,
                    "proxy_group": binding.group,
                    "proxy_masked": binding.masked,
                    "proxy_fingerprint": binding.fingerprint,
                    "expected_exit_ip": binding.exit_ip,
                    "registration_ip": "",
                    "exit_ip": binding.exit_ip,
                    "proxy_attempts": [],
                    "cleanup_status": "pending",
                    "retry_of": str(original.get("task_id") or ""),
                    "retry_attempt": int(original.get("retry_attempt") or 0) + 1,
                    "retry_node_code": retry_node,
                    "retry_key": retry_key,
                    "manual_generation": 0,
                    "progress": {"stage": "free_twofa_enroll" if twofa_retry else "free_password_eligibility" if password_retry else "free_oauth_session", "group": "free", "started_at": now, "updated_at": now, "finished_at": None},
                    "result": merged_result or saved_result or {"twofa_status": ""},
                    "retry_mode": "password" if password_retry else "twofa" if twofa_retry else "registration",
                }
                self._tasks[retry_id] = task
                self._retry_leases[retry_key] = retry_id
                self.proxies.lease(binding, owner=retry_id, batch_id=batch_id, task_id=retry_id)
                self.pool.update(row_id, status="queued", batch_id=batch_id, stage=retry_node, driver=driver, proxy=binding.proxy, proxy_masked=binding.masked, proxy_fingerprint=binding.fingerprint, expected_exit_ip=binding.exit_ip, exit_ip=binding.exit_ip, proxy_id=binding.proxy_id, proxy_country=binding.country, proxy_group=binding.group)
                retry_config = dict(config)
                retry_config.setdefault("auto_set_password", False)
                retry_config.setdefault("auto_set_2fa", True)
                # Make the retry durable before a worker can complete.  This
                # is especially important for custom runners that return
                # synchronously from submit().
                self._save_tasks_safely("重试任务初始状态")
                if not active_batch:
                    self._last_config = copy.deepcopy(retry_config)
                    self._batch_id = batch_id
                    self._stop.clear()
                    self._user_stop_requested = False
                    heartbeat_stop = threading.Event()
                    self._heartbeat_stop = heartbeat_stop
                    self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, args=(batch_id, heartbeat_stop), name=f"free-proxy-heartbeat-{batch_id[-8:]}", daemon=True)
                    self._heartbeat_thread.start()
                    self._executor = _runtime_module().PriorityExecutor(max_workers=workers, thread_name_prefix="free-retry")
                self._submit_registered_worker(
                    self._worker,
                    retry_id,
                    retry_config,
                    twofa_retry,
                    password_retry,
                    driver=driver,
                    priority=0,
                )
                submitted = True
                self._save_tasks_safely("重试任务提交后")
                self._log(f"[{retry_id}/Free 重试/{retry_node}] 已排队（第 {task['retry_attempt']} 次）", "info", task_id=retry_id, retry_of=task["retry_of"], retry_node_code=retry_node)
                return self._public_task(task)
            except Exception:
                # After submit the worker owns the task and lease.  Keep the
                # persisted state intact if a later callback/save fails.
                if submitted:
                    raise
                self._tasks.pop(retry_id, None)
                if mailbox_lease_acquired and self.mailbox_leases is not None:
                    try:
                        self.mailbox_leases.release(task_id=retry_id, reusable=True)
                    except Exception:
                        pass
                if binding is not None:
                    try:
                        self.proxies.release(binding, owner=retry_id or batch_id)
                    except Exception:
                        pass
                self._retry_leases.pop(retry_key, None)
                if reserved:
                    try:
                        self.pool.update(row_id, status="available", batch_id="", stage="", driver="", proxy="", proxy_masked="", proxy_fingerprint="", expected_exit_ip="", exit_ip="", proxy_id="", proxy_country="", proxy_group="")
                    except Exception:
                        pass
                if created_executor and not self._futures:
                    try:
                        self._heartbeat_stop.set()
                        if self._heartbeat_thread is not None and self._heartbeat_thread is not threading.current_thread():
                            self._heartbeat_thread.join(timeout=1)
                    except Exception:
                        pass
                    if self._executor is not None:
                        try:
                            # No worker was submitted on this rollback path;
                            # wait for the idle executor threads so a caller
                            # can safely tear down a temporary data directory
                            # immediately after the exception.
                            self._executor.shutdown(wait=True, cancel_futures=True)
                        except Exception:
                            pass
                    self._executor = None
                    self._heartbeat_thread = None
                    self._batch_id = previous_batch_id
                    self._last_config = previous_last_config
                self._save_tasks_safely("重试任务回滚")
                if created_executor and not self._futures:
                    self._release_runtime_owner()
                raise

    def retry_twofa(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        normalized = str(task_id or "").strip()
        with self._lock:
            task = copy.deepcopy(self._tasks.get(normalized))
        if task is None:
            row = self.pool.entry(normalized)
            saved = self.pool.result(normalized) if row is not None else {}
            if row is None or saved.get("twofa_status") != "pending":
                raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该任务当前没有待重试的 2FA", retryable=False)
            row_state = self.pool._row_state(row.row_id)
            source = str(row_state.get("source") or "url").strip().lower()
            task = {"task_id": normalized, "row_id": row.row_id, "email": row.email, "mailbox_url": row.mailbox_url, "mailbox_source": source, "service_token": str(row_state.get("service_token") or "") if source == "remail" else "", "result": saved, "driver": saved.get("driver") or "protocol", "status": "twofa_pending"}
        if str(task.get("status") or "") != "twofa_pending":
            raise FreeRegisterError("free_twofa_retry", "重试 Free 账号 2FA", "该任务当前没有待重试的 2FA", retryable=False)
        return self._enqueue_retry(task, config, retry_node="free_twofa_activate", twofa_retry=True)

    def retry_password(self, task_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
        """Queue only the pending post-registration password operation.

        The continuation is deliberately keyed off the durable result rather
        than the task's public status. A process restart or a later 2FA failure
        can change that status while the account Token and pending password
        marker remain valid.
        """
        normalized = str(task_id or "").strip()
        with self._lock:
            task = copy.deepcopy(self._tasks.get(normalized))
        if task is None:
            row = self.pool.entry(normalized)
            saved = self.pool.result(normalized) if row is not None else {}
            if row is None or not isinstance(saved, Mapping):
                raise FreeRegisterError(
                    "free_password_retry", "重试 Free 账号密码设置",
                    "没有找到对应的 Free 任务", retryable=False,
                )
            task = {
                "task_id": normalized,
                "row_id": row.row_id,
                "email": row.email,
                "mailbox_url": row.mailbox_url,
                "result": dict(saved),
                "driver": saved.get("driver") or "protocol",
                "status": str(saved.get("status") or "partial_success"),
                "proxy": "",
            }
        result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
        durable = self.pool.result(str(task.get("row_id") or normalized))
        merged = merge_account_result_fields(result, durable if isinstance(durable, Mapping) else {})
        if not str(merged.get("access_token") or "").strip():
            raise FreeRegisterError(
                "free_password_retry", "重试 Free 账号密码设置",
                "原账号没有可用 access token", retryable=False,
                error_code="free_password_retry_token_missing",
            )
        if not password_retry_allowed(merged):
            raise FreeRegisterError(
                "free_password_retry", "重试 Free 账号密码设置",
                "该账号当前没有可补设的密码状态", retryable=False,
                error_code="free_password_retry_not_pending",
            )
        task["result"] = merged
        status = str(task.get("status") or "")
        if status in {"queued", "running"}:
            raise FreeRegisterError(
                "free_password_retry", "重试 Free 账号密码设置",
                "该账号当前已有运行中的任务", retryable=False,
                error_code="free_password_retry_active",
            )
        # Historical failed/pending-rerun snapshots are valid continuation
        # sources as long as the durable account evidence above is present.
        return self._enqueue_retry(
            task,
            config,
            retry_node="free_password_enroll",
            password_retry=True,
        )

    def batch_retry(self, task_ids: Sequence[str], config: Mapping[str, Any]) -> dict[str, Any]:
        """Queue selected failed/2FA tasks independently and report each result."""
        selected = list(dict.fromkeys(str(value or "").strip() for value in task_ids if str(value or "").strip()))
        accepted: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for task_id in selected[:200]:
            try:
                with self._lock:
                    task = copy.deepcopy(self._tasks.get(task_id))
                if task is None:
                    rejected.append({"task_id": task_id, "reason": "任务不存在"})
                    continue
                status = str(task.get("status") or "")
                failure = task.get("failure") if isinstance(task.get("failure"), Mapping) else {}
                result = task.get("result") if isinstance(task.get("result"), Mapping) else {}
                if (
                    password_retry_allowed(result)
                    and status in {"success", "partial_success", "twofa_pending", "failed", "pending_rerun"}
                ):
                    queued = self.retry_password(task_id, config)
                elif failure and self._batch_retry_blocked(failure):
                    skipped.append({"task_id": task_id, "reason": "当前失败节点不可自动重试，请按诊断建议处理"})
                    continue
                elif status == "twofa_pending":
                    queued = self.retry_twofa(task_id, config)
                elif status in {"failed", "stopped", "pending_rerun"}:
                    queued = self.rerun(task_id, config)
                else:
                    skipped.append({"task_id": task_id, "reason": "当前状态不可重试"})
                    continue
                accepted.append({"task_id": task_id, "retry_task": queued})
            except Exception as exc:
                rejected.append({"task_id": task_id, "reason": _safe_log_message(exc)[:240]})
        if len(selected) > 200:
            rejected.extend({"task_id": task_id, "reason": "单次最多重试 200 条"} for task_id in selected[200:])
        return {
            "accepted": accepted,
            "accepted_count": len(accepted),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "rejected": rejected,
            "rejected_count": len(rejected),
        }

    @staticmethod
    def _batch_retry_blocked(failure: Mapping[str, Any]) -> bool:
        """Keep known business/security failures out of bulk replay."""
        if failure.get("retryable") is False:
            return True
        try:
            status = int(failure.get("http_status") or 0)
        except (TypeError, ValueError):
            status = 0
        if status in {400, 401, 403, 409, 422, 429}:
            return True
        text = " ".join(
            str(failure.get(key) or "").lower()
            for key in ("node_code", "error_code", "provider_code", "public_message", "technical_summary")
        )
        return any(marker in text for marker in (
            "challenge", "captcha", "security", "account_disabled", "account_banned",
            "suspended", "invalid_totp", "invalid code", "rate_limit", "429",
        ))


__all__ = [
    "FreeRegisterRetryMixin",
]
