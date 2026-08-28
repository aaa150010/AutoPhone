"""Scheduling recovery, proxy replacement and Roxy circuit controls for Free runs."""

from __future__ import annotations

import time
from typing import Any, Mapping

try:
    from .free_proxy_health import is_proxy_health_failure
    from .free_register_common import FreeRegisterError, ProxyBinding
except ImportError:
    from free_proxy_health import is_proxy_health_failure  # type: ignore[no-redef]
    from free_register_common import FreeRegisterError, ProxyBinding  # type: ignore[no-redef]


class FreeRegisterSchedulerMixin:
    """Methods shared by the Free manager's worker scheduler."""

    def _recover_interrupted_tasks(self) -> None:
        """Reconcile persisted active work after an unclean process exit."""
        try:
            self.pool.recover_reserved()
        except Exception:
            pass
        changed = False
        for task_id, task in list(self._tasks.items()):
            previous = str(task.get("status") or "")
            if previous not in {"queued", "running"}:
                continue
            failure = {
                "node_code": "free_process_recovery",
                "node_label": "Free 进程恢复",
                "error_code": "free_process_interrupted",
                "public_message": "Free 进程恢复 [Free 进程恢复/free_process_recovery]：进程重启，中断任务未完成",
                "technical_summary": "进程重启，中断任务未完成",
                "retryable": previous == "queued",
            }
            reusable = previous == "queued"
            failure, _ = self._persist_task_failure(
                task_id,
                task,
                status="stopped" if reusable else "failed",
                failure=failure,
            )
            try:
                self.pool.recover_interrupted(str(task.get("row_id") or ""), reusable=reusable, failure=failure)
            except Exception:
                pass
            self._release_task_lease(task)
            self._finish_progress(task_id, "stopped" if reusable else "failed")
            changed = True
        if changed:
            # The production manager exposes a safe persistence helper so a
            # disk outage cannot abort recovery of the remaining leases. Keep
            # the direct fallback for older mixin hosts used by integrations.
            saver = getattr(self, "_save_task_state_safely", None)
            if callable(saver):
                saver("进程恢复任务状态")
            else:
                saver = getattr(self, "_save_tasks_safely", None)
                if callable(saver):
                    saver("进程恢复任务状态")
                else:
                    try:
                        self.task_store.save(self._tasks)
                    except Exception:
                        pass

    def _switch_pre_profile_proxy(self, task: dict[str, Any], config: Mapping[str, Any]) -> bool:
        """Replace a failed pre-profile proxy while the account is still uncommitted."""
        driver = str(task.get("driver") or config.get("driver") or "protocol")
        excluded_proxy_ids = {str(task.get("proxy_id") or "")}
        try:
            bindings = self.proxies.bind(
                1,
                probe=self.proxy_probe,
                probe_url=str(config.get("proxy_probe_url") or "https://chatgpt.com/"),
                driver=driver,
                exclude_proxy_ids=excluded_proxy_ids,
                perform_probe=False,
                health_probe_ttl_seconds=int(config["proxy_health_probe_ttl_seconds"]) if "proxy_health_probe_ttl_seconds" in config else 0,
            )
        except Exception:
            # A replacement is optional recovery. Any pool/transport error is
            # reported by the caller's original failure path; do not mask it
            # with a second exception while attempting the switch.
            return False
        if not bindings:
            return False
        replacement = bindings[0]
        previous = ProxyBinding(
            str(task.get("proxy") or ""), str(task.get("proxy_fingerprint") or ""),
            str(task.get("proxy_masked") or ""), str(task.get("expected_exit_ip") or task.get("exit_ip") or ""),
            proxy_id=str(task.get("proxy_id") or ""),
        )
        owner = str(task.get("task_id") or "")
        task_id = str(task.get("task_id") or "")
        try:
            self.proxies.lease(replacement, owner=owner, batch_id=str(task.get("batch_id") or ""), task_id=task_id)
            self.proxies.release(previous, owner=owner)
        except Exception:
            try:
                self.proxies.release(replacement, owner=owner)
            except Exception:
                pass
            return False
        updates = {
            "proxy": replacement.proxy, "proxy_id": replacement.proxy_id,
            "proxy_scheme": replacement.scheme, "proxy_country": replacement.country,
            "proxy_effective_scheme": getattr(replacement, "effective_scheme", "") or replacement.scheme,
            "proxy_group": replacement.group, "proxy_masked": replacement.masked,
            "proxy_fingerprint": replacement.fingerprint,
            "exit_ip": replacement.exit_ip, "registration_ip": "",
        }
        persist = False
        with self._lock:
            current = self._tasks.get(task_id)
            if current is not None:
                current.update(updates)
                current.setdefault("proxy_attempts", []).append({"proxy_id": replacement.proxy_id, "stage": "free_proxy_binding", "outcome": "switched", "at": int(time.time())})
                current["proxy_attempts"] = current["proxy_attempts"][-10:]
                persist = True
        if persist:
            saver = getattr(self, "_save_task_state_safely", None)
            if callable(saver):
                saver("记录代理切换")
            else:
                saver = getattr(self, "_save_tasks_safely", None)
                if callable(saver):
                    saver("记录代理切换")
                else:
                    try:
                        self.task_store.save(self._tasks)
                    except Exception:
                        pass
        task.update(updates)
        self.pool.update(
            str(task.get("row_id") or ""), status="running", proxy=replacement.proxy,
            proxy_id=replacement.proxy_id, proxy_scheme=replacement.scheme,
            proxy_country=replacement.country, proxy_group=replacement.group,
            proxy_masked=replacement.masked, proxy_fingerprint=replacement.fingerprint,
            exit_ip=replacement.exit_ip,
        )
        return True

    def _verify_pre_registration_proxy(
        self,
        task: dict[str, Any],
        config: Mapping[str, Any],
        retry_limit: int,
    ) -> None:
        """Verify and, on explicit network failure, replace an unconsumed proxy."""
        attempt = 0
        while True:
            try:
                self._verify_binding(task, config)
                return
            except FreeRegisterError as exc:
                if attempt >= retry_limit or not is_proxy_health_failure(exc):
                    raise
                self._record_proxy_failure(task, exc)
                attempt += 1
                switched = self._switch_pre_profile_proxy(task, config)
                node_code = str(getattr(exc, "node_code", "proxy_connect_failed") or "proxy_connect_failed")
                node_label = str(getattr(exc, "node_label", "代理连接失败") or "代理连接失败")
                self._log(
                    f"[{task.get('task_id')}/Free 预注册代理重试/{node_code}] "
                    f"{node_label}，{'已切换备用代理' if switched else '重试当前代理'}"
                    f"（第 {attempt + 1} 次）",
                    "warn",
                )

    def _roxy_failure(self, task: Mapping[str, Any], exc: BaseException) -> None:
        if str(task.get("driver") or "") != "roxybrowser":
            return
        code = str(getattr(exc, "node_code", "") or "")
        if code not in {"free_roxy_api", "free_roxy_create", "free_roxy_open", "free_roxy_connect"}:
            return
        with self._lock:
            self._roxy_failures += 1
            threshold = max(1, int(self._last_config.get("roxy_circuit_failure_threshold") or 3)) if hasattr(self, "_last_config") else 3
            if self._roxy_failures >= threshold:
                self._roxy_circuit_open = True
                self._roxy_circuit_opened_at = time.time()
                self._circuit_stop_requested = True
                self._stop.set()
        if self._roxy_circuit_open:
            self._log(f"[{task.get('task_id')}/RoxyBrowser 熔断/roxy_circuit_open] Roxy 基础设施连续失败，停止启动新的 Free 任务", "error")

    def _maybe_recover_roxy_circuit(self, config: Mapping[str, Any]) -> None:
        """Move an elapsed Roxy circuit into a fresh half-open batch window."""
        with self._lock:
            if not self._roxy_circuit_open:
                return
            configured = config.get("roxy_circuit_recovery_seconds")
            recovery = max(0, int(configured if configured is not None else 30))
            if time.time() - float(self._roxy_circuit_opened_at or 0) < recovery:
                return
            self._roxy_circuit_open = False
            self._roxy_failures = 0
            self._roxy_circuit_opened_at = 0.0
            if self._circuit_stop_requested and not self._user_stop_requested:
                self._stop.clear()
            self._circuit_stop_requested = False
            self._log("[RoxyBrowser/free_roxy_circuit] 熔断恢复，允许新的 Roxy 任务进入半开放探测", "warn")


__all__ = ["FreeRegisterSchedulerMixin"]
