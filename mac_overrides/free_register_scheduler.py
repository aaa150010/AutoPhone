"""Scheduling recovery and proxy replacement for Free runs."""

from __future__ import annotations

import time
from typing import Any, Mapping

try:
    from .free_register_common import FreeRegisterError, ProxyBinding
except ImportError:
    from free_register_common import FreeRegisterError, ProxyBinding  # type: ignore[no-redef]


class FreeRegisterSchedulerMixin:
    """Methods shared by the Free manager's worker scheduler."""

    def _persist_tasks_with_fallback(self, context: str) -> None:
        """Persist task state through the diagnostic-aware saver chain.

        ``_save_task_state_safely`` already falls back to
        ``_save_tasks_safely`` and then to a direct store save; the two
        hand-rolled copies of that chain in this mixin used the same order
        and the same swallow-on-failure semantics.
        """
        saver = getattr(self, "_save_task_state_safely", None)
        if callable(saver):
            saver(context)
            return
        saver = getattr(self, "_save_tasks_safely", None)
        if callable(saver):
            saver(context)
            return
        try:
            self.task_store.save(self._tasks)
        except Exception as exc:
            # Task persistence must not mask the scheduling outcome.
            self._note_quiet("recovery_task_persist" if context == "进程恢复任务状态" else "proxy_switch_persist", exc)

    def _recover_interrupted_tasks(self) -> None:
        """Reconcile persisted active work after an unclean process exit."""
        try:
            self.pool.recover_reserved()
        except Exception as exc:
            # Startup recovery must not block the scheduler from starting.
            self._note_quiet("recover_reserved", exc)
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
            except Exception as exc:
                # Recovery bookkeeping must not mask the original task failure.
                self._note_quiet("recover_interrupted", exc)
            self._release_task_lease(task)
            self._finish_progress(task_id, "stopped" if reusable else "failed")
            changed = True
        if changed:
            # The production manager exposes a safe persistence helper so a
            # disk outage cannot abort recovery of the remaining leases. Keep
            # the direct fallback for older mixin hosts used by integrations.
            self._persist_tasks_with_fallback("进程恢复任务状态")

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
        except Exception as bind_exc:
            try:
                self.proxies.release(replacement, owner=owner)
            except Exception as release_exc:
                # Proxy release must not mask the original admission failure.
                self._note_quiet("proxy_switch_release", release_exc)
            self._note_quiet("proxy_switch_bind", bind_exc)
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
            self._persist_tasks_with_fallback("记录代理切换")
        task.update(updates)
        self.pool.update(
            str(task.get("row_id") or ""), status="running", proxy=replacement.proxy,
            proxy_id=replacement.proxy_id, proxy_scheme=replacement.scheme,
            proxy_country=replacement.country, proxy_group=replacement.group,
            proxy_masked=replacement.masked, proxy_fingerprint=replacement.fingerprint,
            exit_ip=replacement.exit_ip,
        )
        return True


__all__ = ["FreeRegisterSchedulerMixin"]
