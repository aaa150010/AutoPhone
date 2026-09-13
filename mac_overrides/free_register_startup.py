"""Batch startup, rollback and completion callback mixin for FreeRegisterManager.

Split out of ``free_register_runtime.py``; the manager composes this mixin so
the responsibility band keeps its own module.  Methods rely on attributes and
methods defined by the manager (``self._lock``, ``self.pool``, ``self.proxies``,
``self.public_state`` ...).  Module-level globals referenced by the methods
resolve through the composing runtime module via ``_runtime_module()`` so
existing tests can keep patching ``mac_overrides.free_register_runtime.<name>``.
"""

from __future__ import annotations

import copy
from concurrent.futures import Future
import secrets
import threading
import sys
import time
from typing import Any, Callable, Mapping, Sequence

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
    from .free_camoufox.pool_sizing import derive_camoufox_pool_sizing
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
    from free_camoufox.pool_sizing import derive_camoufox_pool_sizing  # type: ignore[no-redef]
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


class FreeRegisterStartupMixin:
    """Methods moved verbatim from the FreeRegisterManager band."""





    def start(self, config: Mapping[str, Any], *, pool_content: str = "", proxy_content: str = "", row_ids: Sequence[str] = ()) -> dict[str, Any]:
        normalized_config = dict(config)
        # Preserve explicit security-step choices at the manager boundary.
        # Older code forced 2FA on here, which made an explicit ``false`` from
        # the UI ineffective and also caused password-only runs to enter MFA.
        normalized_config.setdefault("auto_set_password", False)
        normalized_config.setdefault("auto_set_2fa", True)
        # HTTP callers normally pass a FreeConfigStore-normalized snapshot.
        # Keep direct manager integrations on the same production defaults
        # without changing explicit protocol or DNS choices.
        if not str(normalized_config.get("proxy_default_scheme") or "").strip():
            normalized_config["proxy_default_scheme"] = "socks5"
        if not str(normalized_config.get("proxy_socks5_dns_mode") or "").strip():
            normalized_config["proxy_socks5_dns_mode"] = "remote"
        # Keep the manager boundary strict even when a caller bypasses the
        # HTTP config store. Legacy browser tasks remain readable from history,
        # but a new start request must never reserve rows or touch a removed
        # transport.
        requested_driver = str(normalized_config.get("driver") or "protocol").strip().lower()
        if requested_driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError(
                "free_config", "启动 Free 注册", "Free 注册链路只能选择全协议或 Camoufox", retryable=False,
                error_code="free_driver_unsupported",
            )
        normalized_config["driver"] = requested_driver
        # Auto pool sizing: derive the Camoufox browser-pool parameters from
        # the real worker width so the quick bar only needs target count and
        # concurrency.  Manual values stay authoritative when auto is off.
        if requested_driver == "camoufox":
            sizing = derive_camoufox_pool_sizing(normalized_config)
            if sizing is not None:
                camoufox_config = dict(normalized_config.get("camoufox") or {})
                camoufox_config["pool_size"] = sizing.pool_size
                camoufox_config["max_contexts_per_browser"] = sizing.max_contexts
                normalized_config["camoufox"] = camoufox_config
        start_attempted = False
        try:
            with self._lock:
                # Keep the production manager boundary aligned with the Free
                # contract even for callers that bypass the HTTP config store.
                if self.is_running():
                    raise FreeRegisterError("free_run_start", "启动 Free 注册", "已有 Free 注册任务运行中", retryable=False)
                start_attempted = True
                self._last_config = copy.deepcopy(normalized_config)
                return self._start_locked(
                    normalized_config,
                    pool_content=pool_content,
                    proxy_content=proxy_content,
                    row_ids=row_ids,
                )
        except Exception:
            # ``_start_locked`` owns the manager lock while reserving rows and
            # creating the worker runtime.  Drain any partially-created
            # runtime only after that lock has been released; joining a worker
            # here would deadlock when it is waiting to enter ``_worker``.
            if start_attempted:
                self._rollback_failed_startup()
                with self._lock:
                    idle_owner = not self._futures and self._executor is None
                if idle_owner:
                    self._release_runtime_owner()
            raise
        finally:
            # The state route reads progress lock-free; a finished (or failed)
            # startup must not leave a stale preparation stage behind.
            self._startup_progress_active = False
            self._startup_progress = {}

    def _startup_stage(self, stage: str, label: str, detail: str = "") -> None:
        """Publish one startup preparation stage for the state route.

        Called while ``start`` owns the manager lock; the write itself is a
        plain dict replace so the lock-free reader always sees a consistent
        snapshot.
        """
        self._startup_progress = {
            "stage": stage,
            "label": label,
            "detail": detail,
            "updated_at": int(time.time()),
        }

    def startup_progress(self) -> dict[str, Any]:
        """Lock-free progress read: the state route must not block on the lock."""
        data = getattr(self, "_startup_progress", None)
        return dict(data) if isinstance(data, dict) else {}

    def _startup_mint_progress_callback(self) -> Callable[[int, int], None] | None:
        """Progress sink for tunnel minting; ``None`` outside a startup attempt."""
        if not getattr(self, "_startup_progress_active", False):
            return None

        def _on_mint(minted: int, deficit: int) -> None:
            self._startup_stage("tunnel_mint", "铸造隧道替补代理", f"已铸造 {minted}/{deficit} 条新出口")

        return _on_mint

    def _note_startup_quiet(self, where: str, exc: BaseException) -> None:
        """Record a swallowed startup/shutdown cleanup failure on stderr.

        Cleanup must never mask the surrounding business failure; the note
        keeps the swallowed exception observable during incident review.
        """
        try:
            print(f"[free_register_startup/{where}] {type(exc).__name__}", file=sys.stderr)
        except Exception:
            return

    def _rollback_failed_startup(self) -> None:
        """Drain a batch whose executor/heartbeat could not be assembled.

        A normal worker completion owns its own cleanup path.  Startup is
        different: a constructor or submit failure can happen after only a
        subset of tasks has been registered, so this method first detaches
        Future callbacks, waits for the executor, and then releases every
        task's leases.  It is intentionally idempotent and only acts on the
        batch marker set by the current ``start`` call.
        """
        with self._lock:
            batch_id = str(self._startup_batch_id or "").strip()
            if not batch_id:
                return
            self._stop.set()
            self._user_stop_requested = True
            heartbeat_stop = self._heartbeat_stop
            heartbeat_stop.set()
            heartbeat_thread = self._heartbeat_thread
            executor = self._executor
            # Detach callbacks before cancelling.  ``Future.cancel`` invokes
            # callbacks synchronously for an already-queued future; leaving
            # them in ``_futures`` could recursively enter normal batch
            # teardown while this startup rollback is still collecting rows.
            futures = tuple(self._futures)
            self._futures.clear()
            self._future_drivers.clear()
            task_ids = [
                str(task.get("task_id") or task_id)
                for task_id, task in self._tasks.items()
                if str(task.get("batch_id") or "") == batch_id
            ]
            self._shutdown_pending = True

        for future in futures:
            try:
                future.cancel()
            except Exception as exc:
                # Shutdown cleanup must not mask the original startup failure.
                self._note_startup_quiet("startup_future_cancel", exc)
        if executor is not None:
            try:
                executor.shutdown(wait=True, cancel_futures=True)
            except TypeError:
                try:
                    executor.shutdown(wait=True)
                except Exception as exc:
                    # Executor shutdown must not mask the original startup failure.
                    self._note_startup_quiet("startup_executor_shutdown_compat", exc)
            except Exception as exc:
                # The worker state and lease cleanup below remain authoritative
                # even when an injected/third-party executor cannot shut down
                # cleanly.
                pass
        if heartbeat_thread is not None and heartbeat_thread is not threading.current_thread():
            try:
                heartbeat_thread.join(timeout=5)
            except Exception as exc:
                # Heartbeat shutdown must not mask the original startup failure.
                self._note_startup_quiet("startup_heartbeat_join", exc)

        # A running worker may switch to a replacement proxy or confirm the
        # mailbox while the executor drains.  Refresh the task snapshots after
        # the wait so cleanup targets the worker's latest durable binding.
        with self._lock:
            tasks = [
                copy.deepcopy(self._tasks[task_id])
                for task_id in task_ids
                if task_id in self._tasks
            ]
        for task in tasks:
            try:
                self._release_task_lease(task)
            except Exception as exc:
                self._log(
                    f"[{task.get('task_id', '')}/启动回滚/free_startup_rollback] "
                    f"资源释放失败（{type(exc).__name__}）",
                    "warn",
                    task_id=str(task.get("task_id") or ""),
                    node_code="free_startup_rollback",
                    node_label="Free 启动回滚",
                    outcome="cleanup_failed",
                )
            # The legacy JSON pool has no mailbox lease coordinator.  Its
            # startup rows were not yet submitted to a transport, so return
            # them explicitly after the proxy release above.  SQLite-backed
            # pools use ``MailboxLeaseCoordinator`` as the source of truth.
            if self.mailbox_leases is None and str(task.get("status") or "").strip().lower() in {"queued", "reserved"}:
                row_id = str(task.get("row_id") or "").strip()
                if row_id:
                    try:
                        self.pool.update(
                            row_id,
                            status="available",
                            batch_id="",
                            stage="",
                            driver="",
                            proxy="",
                            proxy_masked="",
                            proxy_fingerprint="",
                            proxy_id="",
                            proxy_scheme="",
                            proxy_country="",
                            proxy_group="",
                            expected_exit_ip="",
                            registration_ip="",
                            exit_ip="",
                        )
                    except Exception as exc:
                        # Startup cleanup must not mask the original failure being handled.
                        self._note_startup_quiet("startup_row_checkpoint", exc)

        with self._lock:
            # Mark rows terminal for one save before removing them.  The
            # SQLite compatibility adapter intentionally deletes only terminal
            # stale rows, so this first checkpoint makes the subsequent empty
            # snapshot eligible to remove a partially-created startup task.
            for task_id, task in list(self._tasks.items()):
                if str(task.get("batch_id") or "") != batch_id:
                    continue
                task["status"] = "stopped"
                task["cleanup_status"] = task.get("cleanup_status") or "released"
                task["updated_at"] = int(time.time())
        self._save_tasks_safely("启动失败回滚终态")
        with self._lock:
            for task_id, task in list(self._tasks.items()):
                if str(task.get("batch_id") or "") == batch_id:
                    self._tasks.pop(task_id, None)
            if self._executor is executor:
                self._executor = None
            if self._heartbeat_thread is heartbeat_thread:
                self._heartbeat_thread = None
            self._shutdown_pending = False
            self._startup_batch_id = ""
            self._batch_id = ""
            self._stage_started_mono = {
                key: value for key, value in self._stage_started_mono.items()
                if key in self._tasks
            }
            self._task_started_mono = {
                key: value for key, value in self._task_started_mono.items()
                if key in self._tasks
            }
            self._timing_checkpoint_mono = {
                key: value for key, value in self._timing_checkpoint_mono.items()
                if key in self._tasks
            }
        self._save_tasks_safely("启动失败回滚")
        self._release_runtime_owner()

    def _start_locked(
        self,
        config: Mapping[str, Any],
        *,
        pool_content: str,
        proxy_content: str,
        row_ids: Sequence[str],
    ) -> dict[str, Any]:
        """Start a batch while ``start`` still owns the manager lock.

        The reservation and executor creation remain one transaction. Releasing
        the lock between
        the running check and mailbox/proxy reservation allowed two concurrent
        start requests to both pass the check.
        """
        # Startup progress rides on the lock-free state read; activate the
        # gate first so tunnel minting inside the sequence also reports.
        self._startup_progress_active = True
        self._startup_stage("owner", "校验熔断与运行归属")
        # A tripped challenge breaker blocks the batch before any ownership,
        # reservation or pool mutation; reset requires operator confirmation.
        if self.proxy_breaker.tripped():
            raise FreeRegisterError(
                "free_proxy_breaker_tripped",
                "Free 代理池熔断",
                "短时间内多个出口连续触发安全挑战，已暂停批量启动；请人工确认后重置熔断",
                retryable=False,
                error_code="free_proxy_breaker_tripped",
                action_hint="多为站点整体收紧或供应商子段被拉黑；请人工确认后重置熔断再恢复任务",
            )
        # Establish process ownership before protocol/Camoufox preflight or
        # any pool mutation.  A second Flask/LaunchAgent instance therefore
        # fails cleanly without touching the old worker's rows.
        self._acquire_runtime_owner()
        # Validate the full-protocol bridge before importing or leasing any
        # mailbox/proxy rows. Custom runners are test/integration adapters
        # and intentionally retain their existing contract.
        requested_driver = str(config.get("driver") or "protocol").strip().lower()
        if requested_driver not in {"protocol", "camoufox"}:
            raise FreeRegisterError(
                "free_config", "启动 Free 注册", "Free 注册链路只能选择全协议或 Camoufox", retryable=False,
                error_code="free_driver_unsupported",
            )
        if requested_driver == "protocol" and not self._custom_runner:
            self._startup_stage("preflight", "网络与链路预检", requested_driver)
            self.protocol_preflight(config)
        if pool_content.strip():
            self.pool.import_text(pool_content)
        # The argument is typed as str; this guard keeps the import conditional
        # while preserving the existing transaction body below.
        if proxy_content is None:
            proxy_content = ""
        if proxy_content is not None:
            # An available pool row is not automatically a new-registration
            # candidate: an operator may have restored a previously completed
            # account to ``available`` by hand.  Check durable and historical
            # account evidence before calculating the batch or touching a
            # proxy lease.  This keeps the guard effective for both explicit
            # selections and automatic pool dispatch.
            self._startup_stage("mailbox", "校验邮箱池与账号证据")
            available_rows = self.pool.available(10_000)
            protected_ids = self._registration_account_exists_bulk(
                row.row_id for row in available_rows
            )
            registration_rows = [
                row for row in available_rows
                if row.row_id not in protected_ids
            ]
            available_count = len(registration_rows)
            configured_free_count = config.get("target_count", config.get("free_target_count"))
            try:
                configured_free_count_value = int(configured_free_count)
            except (TypeError, ValueError):
                configured_free_count_value = 1
            requested_count = max(1, min(configured_free_count_value, 200))
            target_count = max(1, min(requested_count, available_count))
            requested_row_ids = {str(value or "").strip() for value in row_ids if str(value or "").strip()}
            if requested_row_ids:
                if len(requested_row_ids) > 200:
                    raise FreeRegisterError(
                        "free_pool_preflight",
                        "Free 邮箱池预检",
                        "单批次最多选择 200 个 Free 邮箱",
                        retryable=False,
                    )
                # Check explicitly selected rows even when their pool status
                # is currently pending/unavailable; otherwise a completed
                # account could be hidden behind a generic availability error
                # and later replayed after a manual status change.
                requested_protected = {
                    row_id for row_id in requested_row_ids
                    if row_id not in protected_ids
                    and self._registration_account_exists(row_id)
                }
                requested_protected.update(requested_row_ids & protected_ids)
                if requested_protected:
                    raise FreeRegisterError(
                        "free_run_account_result_exists",
                        "启动 Free 注册",
                        "所选邮箱已有已保存的 Free 账号结果，不能再次走整条注册流程；请使用已有账号登录、2FA 重试或测活",
                        retryable=False,
                        error_code="free_run_account_result_exists",
                        action_hint="移除已完成账号，或使用已有账号登录、2FA 重试和测活入口",
                    )
                rows = [row for row in registration_rows if row.row_id in requested_row_ids]
                if len(rows) != len(requested_row_ids):
                    raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", "快捷运行所选邮箱中有记录不存在或当前不可用", retryable=False)
                target_count = len(rows)
            else:
                rows = registration_rows[:target_count]
            if not rows:
                if protected_ids and not requested_row_ids:
                    raise FreeRegisterError(
                        "free_run_account_result_exists",
                        "启动 Free 注册",
                        "可用邮箱均已有已保存的 Free 账号结果，不能再次走整条注册流程；请使用已有账号登录、2FA 重试或测活",
                        retryable=False,
                        error_code="free_run_account_result_exists",
                        action_hint="使用已有账号登录、2FA 重试或测活入口，或导入尚未注册的邮箱",
                    )
                raise FreeRegisterError(
                    "free_pool_preflight",
                    "Free 邮箱池预检",
                    "Free 邮箱池没有可用于新注册的邮箱",
                    retryable=False,
                    error_code="free_pool_empty",
                )
            if len(rows) < target_count:
                raise FreeRegisterError("free_pool_preflight", "Free 邮箱池预检", f"Free 邮箱数量不足：需要 {target_count} 条，当前只有 {len(rows)} 条", retryable=False)
            driver = str(config.get("driver") or "protocol").strip().lower()
            if driver not in {"protocol", "camoufox"}:
                raise FreeRegisterError("free_config", "启动 Free 注册", "Free 注册链路无效", retryable=False)
            if driver == "camoufox" and not self._custom_runner:
                self._startup_stage("preflight", "Camoufox 预检", "camoufox")
                _runtime_module().CamoufoxRunner.preflight(config)
            # Import pasted proxies only after mailbox/result guards pass.  A
            # rejected duplicate-registration attempt must not mutate the
            # shared proxy pool or its health history.
            if proxy_content.strip():
                self.proxies.import_text(proxy_content, scheme=str(config.get("proxy_default_scheme") or "socks5"))
            self.proxies.configure_policy(
                failure_threshold=int(config.get("proxy_failure_threshold") or 2),
                quarantine_seconds=int(config.get("proxy_quarantine_seconds") or 600),
                health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
                tls_verify=bool(config.get("proxy_tls_verify", True)),
                tls_compat_fallback=bool(config.get("proxy_tls_compat_fallback", True)),
                socks5_dns_mode=str(config.get("proxy_socks5_dns_mode") or "remote"),
                allocation_mode="healthy_random",
            )
            # Refill from the credential-tunnel template before binding so a
            # shrunken pool mints back up to target (no-op without a template).
            self._startup_stage("tunnel_mint", "铸造隧道替补代理")
            self._ensure_tunnel_target()
            self._startup_stage("proxy_bind", "分配代理")
            bindings = self.proxies.bind(
                target_count,
                probe=self.proxy_probe,
                probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
                driver=driver,
                perform_probe=False,
                health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
            )
            batch_id = f"free-{int(time.time())}-{secrets.token_hex(4)}"
            self._startup_batch_id = batch_id
            now = int(time.time())
            workers = max(1, min(int(config.get("concurrency") or config.get("free_concurrency") or 3), target_count, 16))
            leased_bindings: list[ProxyBinding] = []
            created_task_ids: list[str] = []
            leased_mailboxes: list[str] = []
            reserved = False
            try:
                self.pool.reserve(rows, batch_id)
                reserved = True
                for ordinal, (row, binding) in enumerate(zip(rows, bindings), 1):
                    task_id = f"{batch_id}-{ordinal}"
                    row_state = self.pool._row_state(row.row_id) if callable(getattr(self.pool, "_row_state", None)) else {}
                    source = str(row_state.get("source") or "url").strip().lower()
                    self._tasks[task_id] = {"task_id": task_id, "ordinal": ordinal, "slot_id": f"{batch_id}-slot-{((ordinal - 1) % workers) + 1}", "slot_index": ((ordinal - 1) % workers) + 1, "concurrency_limit": workers, "status": "queued", "created_at": now, "updated_at": now, "timing": self._timing_record({"created_at": now}), "batch_id": batch_id, "run_mode": "free_register", "driver": driver, "proxy_allocation_mode": str(config.get("proxy_allocation_mode") or "healthy_random"), "email": row.email, "row_id": row.row_id, "mailbox_url": row.mailbox_url, "mailbox_source": source, "service_token": str(row_state.get("service_token") or "") if source == "remail" else "", "proxy": binding.proxy, "proxy_id": binding.proxy_id, "proxy_scheme": binding.scheme, "proxy_effective_scheme": getattr(binding, "effective_scheme", "") or binding.scheme, "proxy_country": binding.country, "proxy_group": binding.group, "proxy_masked": binding.masked, "proxy_fingerprint": binding.fingerprint, "expected_exit_ip": binding.exit_ip, "registration_ip": "", "exit_ip": binding.exit_ip, "proxy_attempts": [], "cleanup_status": "pending", "progress": {"stage": "free_oauth_session", "group": "free", "started_at": now, "updated_at": now, "finished_at": None}, "result": {"twofa_status": "", "driver": driver, "expected_exit_ip": binding.exit_ip, "proxy_country": binding.country, "proxy_group": binding.group}}
                    self._tasks[task_id]["device_id"] = f"free-{secrets.token_hex(16)}"
                    created_task_ids.append(task_id)
                    if self.mailbox_leases is not None:
                        lease = self.mailbox_leases.acquire(
                            row.row_id,
                            task_id=task_id,
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
                        leased_mailboxes.append(task_id)
                    self.proxies.lease(binding, owner=task_id, batch_id=batch_id, task_id=task_id)
                    leased_bindings.append(binding)
                    self.pool.update(row.row_id, status="queued", batch_id=batch_id, driver=driver, proxy=binding.proxy, proxy_masked=binding.masked, proxy_fingerprint=binding.fingerprint, expected_exit_ip=binding.exit_ip, exit_ip=binding.exit_ip, proxy_id=binding.proxy_id, proxy_country=binding.country, proxy_group=binding.group)
                    # Proxy preflight is an internal transport check; do not
                    # expose a successful validation stage in task logs.
                self._save_tasks_safely("启动任务初始状态")
                self._startup_stage("tasks", "创建任务并启动执行器")
            except Exception:
                if self.mailbox_leases is not None:
                    for task_id in reversed(leased_mailboxes):
                        try:
                            self.mailbox_leases.release(task_id=task_id, reusable=True)
                        except Exception as exc:
                            # Lease release must not mask the original startup failure.
                            self._note_startup_quiet("startup_lease_release", exc)
                for index, binding in reversed(list(enumerate(leased_bindings))):
                    try:
                        owner = created_task_ids[index] if index < len(created_task_ids) else batch_id
                        self.proxies.release(binding, owner=owner)
                    except Exception as exc:
                        # Proxy release must not mask the original startup failure.
                        self._note_startup_quiet("startup_proxy_release", exc)
                if reserved:
                    for row in rows:
                        try:
                            self.pool.update(row.row_id, status="available", batch_id="", stage="", driver="", proxy="", proxy_masked="", proxy_fingerprint="", expected_exit_ip="", exit_ip="", proxy_id="", proxy_country="", proxy_group="")
                        except Exception as exc:
                            # Pool reset must not mask the original startup failure.
                            self._note_startup_quiet("startup_pool_reset", exc)
                for task_id in created_task_ids:
                    self._tasks.pop(task_id, None)
                self._save_tasks_safely("启动失败回滚")
                raise
            self._batch_id = batch_id
            self._circuit_stop_requested = False
            self._user_stop_requested = False
            self._stop.clear()
            # Each batch owns its own event. Reusing one shared Event lets a
            # newly started batch clear the stop signal before an old
            # heartbeat thread has observed it, so the old thread can resume
            # renewing released leases.
            heartbeat_stop = threading.Event()
            self._heartbeat_stop = heartbeat_stop
            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, args=(batch_id, heartbeat_stop), name=f"free-proxy-heartbeat-{batch_id[-8:]}", daemon=True)
            self._heartbeat_thread.start()
            self._executor = _runtime_module().PriorityExecutor(max_workers=workers, thread_name_prefix="free-register")
            for task_id in list(self._tasks):
                if self._tasks[task_id].get("batch_id") != batch_id:
                    continue
                self._submit_registered_worker(
                    self._worker,
                    task_id,
                    dict(config),
                    driver=driver,
                    priority=10,
                )
            self._startup_batch_id = ""
            self._log(f"[启动 Free 注册/free_run_start] 已准备 {target_count} 个邮箱，{workers} 并发", "success")
            return {
                "batch_id": batch_id,
                "tasks": self.public_tasks(),
                "state": self.public_state(),
            }

    def _future_done(self, future: Future[Any]) -> None:
        executor: PriorityExecutor | None = None
        completed_batch_id = ""
        heartbeat_thread: threading.Thread | None = None
        heartbeat_stop: threading.Event | None = None
        is_last = False
        with self._lock:
            if future not in self._futures:
                return
            executor = self._executor
            # Remove the completed Future while holding the manager lock so
            # concurrent completion callbacks cannot clean up the same task
            # twice.
            self._futures.discard(future)
            self._future_drivers.pop(future, None)
            completed_task_id = str(self._future_task_ids.pop(future, "") or "")
            is_last = not self._futures
            if is_last:
                self._shutdown_pending = True
                heartbeat_stop = self._heartbeat_stop
                heartbeat_thread = self._heartbeat_thread
                heartbeat_stop.set()
            # Completion callbacks must always continue into Future and
            # executor cleanup even when the task store is temporarily
            # unavailable. Per-task completion only rewrites its own row;
            # the last completion keeps the full snapshot so the adapter's
            # terminal-row pruning still sees every id.
            if is_last:
                self._save_tasks_safely("任务完成回调")
            elif completed_task_id:
                self._mark_task_dirty(completed_task_id)
                self._save_tasks_safely("任务完成回调", only_dirty=True)
        if not is_last:
            return
        # Wait outside the manager lock. Other executor workers may still be
        # unwinding, and the heartbeat can be finishing a diagnostic callback
        # that needs the same lock. Keeping the lock while joining would turn
        # a normal shutdown into a deadlock.
        if executor is not None:
            try:
                executor.shutdown(wait=True, cancel_futures=False)
            except Exception as exc:
                # The worker result and task state are already durable; a
                # best-effort shutdown failure must not strand the manager.
                self._note_startup_quiet("stop_executor_shutdown", exc)
        if heartbeat_thread is not None and heartbeat_thread is not threading.current_thread():
            try:
                heartbeat_thread.join(timeout=2)
            except Exception as exc:
                # Heartbeat shutdown must not block the scheduler stop.
                self._note_startup_quiet("stop_heartbeat_join", exc)
        with self._lock:
            if not self._futures and self._executor is executor:
                completed_batch_id = str(self._batch_id or "")
                # Keep the executor reference (and ``running`` state) visible
                # until the final durable checkpoint has completed.  The
                # checkpoint can still emit a structured storage-warning log;
                # publishing ``None`` first lets callers tear down a temporary
                # data directory while that callback is writing ``tasks.json``
                # or ``logs.json``.
                self._save_tasks_safely("批次完成回调")
                # No new batch/retry may enter while ``_shutdown_pending`` is
                # true.  Re-check ownership after the checkpoint so a future
                # lifecycle change cannot clear a replacement executor.
                if not self._futures and self._executor is executor:
                    self._executor = None
                    if self._heartbeat_thread is heartbeat_thread and (
                        heartbeat_thread is None or not heartbeat_thread.is_alive()
                    ):
                        self._heartbeat_thread = None
                    self._shutdown_pending = False
        if completed_batch_id:
            self._release_runtime_owner()
        if completed_batch_id and self._free_notification is not None:
            try:
                with self._lock:
                    batch_tasks = [
                        copy.deepcopy(task)
                        for task in self._tasks.values()
                        if str(task.get("batch_id") or "") == completed_batch_id
                    ]
                self._free_notification.submit(batch_tasks, batch_id=completed_batch_id)
            except Exception as exc:
                # Notification delivery is advisory and must never affect the
                # persisted registration result or retry queue.
                self._note_startup_quiet("batch_notification", exc)


__all__ = [
    "FreeRegisterStartupMixin",
]
