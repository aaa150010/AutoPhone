"""Credential-safe public state assembly for the recovered web runtime."""

from __future__ import annotations

import copy
import json
import math
import re
from typing import Any, Callable


_OPENAI_CONNECTIVITY_STATUSES = frozenset(
    {"unknown", "healthy", "outage", "recovering"}
)
_OPENAI_CONNECTIVITY_ORIGINS = (
    "auth.openai.com",
    "sentinel.openai.com",
)
_OPENAI_CONNECTIVITY_REASON_LABELS = {
    "openai_auth_connectivity_outage": "OpenAI \u6388\u6743\u94fe\u8def\u8fde\u63a5\u5f02\u5e38",
    "openai_proxy_connection_failure": "OpenAI \u663e\u5f0f\u4ee3\u7406\u8fde\u63a5\u5931\u8d25",
    "openai_tls_connection_failure": "OpenAI TLS \u63e1\u624b\u5931\u8d25",
    "openai_connection_timeout": "OpenAI \u8fde\u63a5\u8d85\u65f6",
    "openai_remote_disconnect": "OpenAI \u8fdc\u7aef\u8fde\u63a5\u4e2d\u65ad",
    "openai_connection_failure": "OpenAI \u8fde\u63a5\u5efa\u7acb\u5931\u8d25",
}
_OPENAI_CONNECTIVITY_PAUSE_REASONS = frozenset(
    {"", "openai_auth_connectivity_outage"}
)
_OPENAI_CONNECTIVITY_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{16}$")


def _bounded_connectivity_int(value: Any, maximum: int) -> int:
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, min(maximum, parsed))


def _connectivity_runtime_epoch(value: Any) -> int:
    """Keep the process epoch within JavaScript's exact integer range."""
    return _bounded_connectivity_int(value, 9_007_199_254_740_991)


def _bounded_connectivity_number(value: Any) -> int | float:
    if isinstance(value, bool):
        return 0
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    if not math.isfinite(parsed) or not 0 <= parsed <= 10_000_000_000:
        return 0
    return value if isinstance(value, (int, float)) else parsed


def _connectivity_event_id(value: Any) -> str:
    text = str(value or "")
    return text if text.isalnum() and len(text) <= 64 else ""


def _public_openai_connectivity(value: Any) -> dict[str, Any]:
    """Normalize the connectivity snapshot to its credential-safe API contract."""

    candidate = value if isinstance(value, dict) else {}
    raw_status = str(candidate.get("status") or "").strip().lower()
    status = (
        raw_status if raw_status in _OPENAI_CONNECTIVITY_STATUSES else "unknown"
    )
    reason_code = str(candidate.get("reason_code") or "").strip().lower()
    if reason_code not in _OPENAI_CONNECTIVITY_REASON_LABELS:
        reason_code = ""
    pause_reason = str(candidate.get("pause_reason") or "").strip().lower()
    if pause_reason not in _OPENAI_CONNECTIVITY_PAUSE_REASONS:
        pause_reason = ""
    event_id = _connectivity_event_id(
        candidate.get("event_id") or candidate.get("incident_id")
    )
    fingerprint = str(candidate.get("proxy_fingerprint") or "").strip().lower()
    if not _OPENAI_CONNECTIVITY_FINGERPRINT_RE.fullmatch(fingerprint):
        fingerprint = ""

    raw_origins = candidate.get("affected_origins")
    affected_origins = (
        [
            origin
            for origin in _OPENAI_CONNECTIVITY_ORIGINS
            if origin in {
                str(item or "").strip().lower()
                for item in raw_origins
            }
        ]
        if isinstance(raw_origins, list)
        else []
    )
    raw_counts = candidate.get("failure_counts")
    counts = raw_counts if isinstance(raw_counts, dict) else {}
    failure_counts = {
        origin: _bounded_connectivity_int(counts.get(origin), 1_000_000)
        for origin in _OPENAI_CONNECTIVITY_ORIGINS
    }
    required_rounds = _bounded_connectivity_int(
        candidate.get("probe_required_rounds"), 100
    )
    successful_rounds = min(
        _bounded_connectivity_int(candidate.get("probe_successful_rounds"), 100),
        required_rounds,
    )

    return {
        "status": status,
        "runtime_epoch": _connectivity_runtime_epoch(
            candidate.get("runtime_epoch")
        ),
        "enabled": candidate.get("enabled")
        if isinstance(candidate.get("enabled"), bool)
        else False,
        "paused": candidate.get("paused")
        if isinstance(candidate.get("paused"), bool)
        else False,
        "pause_reason": pause_reason,
        "reason_code": reason_code,
        "reason_label": _OPENAI_CONNECTIVITY_REASON_LABELS.get(reason_code, ""),
        "affected_origins": affected_origins,
        "event_id": event_id,
        "incident_id": event_id,
        "revision": _bounded_connectivity_int(candidate.get("revision"), 1_000_000_000),
        "proxy_fingerprint": fingerprint,
        "detected_at": _bounded_connectivity_number(candidate.get("detected_at")),
        "recovered_at": _bounded_connectivity_number(candidate.get("recovered_at")),
        "failure_counts": failure_counts,
        "probe_successful_rounds": successful_rounds,
        "probe_required_rounds": required_rounds,
        "last_probe_at": _bounded_connectivity_number(candidate.get("last_probe_at")),
        "next_probe_at": _bounded_connectivity_number(candidate.get("next_probe_at")),
        "next_probe_in_seconds": _bounded_connectivity_int(
            candidate.get("next_probe_in_seconds"), 86_400
        ),
    }


class PublicStateRuntime:
    """Build public API snapshots without retaining recovered runtime globals."""

    def __init__(
        self,
        *,
        clean: Callable[[Any], Any],
        secret_mask: str,
        sms_runtime: Any,
        sms_provider_pools_from_config: Callable[[Any], list[dict[str, Any]]],
        sms_keys_from_config: Callable[[Any], list[str]],
        read_local_config: Callable[[], dict[str, Any]],
        mailbox_admin: Any,
        error_observability: Any,
        task_progress_runtime: Any,
        sms_provider_registry_getter: Callable[[], Any],
        sms_alerts_getter: Callable[[], Any],
        task_progress_getter: Callable[[], Any],
        current_task_admission_getter: Callable[[], Any],
        inflight_gate_getter: Callable[[], Any] | None = None,
        openai_connectivity_getter: Callable[[], Any] | None = None,
        protocol_gate_getter: Callable[[], Any],
        sms_phone_gate_getter: Callable[[], Any],
        notification_context_for: Callable[[], Any],
        known_task_failure: Callable[[Any], Any],
        historical_success_reasons: frozenset[str],
        task_id_log_re: Any,
        public_log_input_limit: int,
        sms_optimization_guard_getter: Callable[[], Any] | None = None,
        process_resource_snapshot_getter: Callable[[], Any] | None = None,
        transport_registry_getter: Callable[[], Any] | None = None,
        masked_local_config_view: Callable[[Any], dict[str, Any]] | None = None,
        public_task_view: Callable[[Any], dict[str, Any]] | None = None,
        runtime_summary_view: Callable[[Any], dict[str, Any]] | None = None,
        notification_public_status_view: Callable[[], dict[str, Any]] | None = None,
        public_logs_view: Callable[[Any, Any], Any] | None = None,
        phone_binding_metrics_getter: Callable[[], Any] | None = None,
    ) -> None:
        self.clean = clean
        self.secret_mask = secret_mask
        self.sms_runtime = sms_runtime
        self.sms_provider_pools_from_config = sms_provider_pools_from_config
        self.sms_keys_from_config = sms_keys_from_config
        self.read_local_config = read_local_config
        self.mailbox_admin = mailbox_admin
        self.error_observability = error_observability
        self.task_progress_runtime = task_progress_runtime
        self.sms_provider_registry_getter = sms_provider_registry_getter
        self.sms_alerts_getter = sms_alerts_getter
        self.task_progress_getter = task_progress_getter
        self.current_task_admission_getter = current_task_admission_getter
        self.inflight_gate_getter = inflight_gate_getter
        self.openai_connectivity_getter = openai_connectivity_getter
        self.protocol_gate_getter = protocol_gate_getter
        self.sms_phone_gate_getter = sms_phone_gate_getter
        self.sms_optimization_guard_getter = sms_optimization_guard_getter
        self.process_resource_snapshot_getter = process_resource_snapshot_getter
        self.transport_registry_getter = transport_registry_getter
        self.notification_context_for = notification_context_for
        self.known_task_failure = known_task_failure
        self.historical_success_reasons = historical_success_reasons
        self.task_id_log_re = task_id_log_re
        self.public_log_input_limit = public_log_input_limit
        self.masked_local_config_view = masked_local_config_view or self.masked_local_config
        self.public_task_view = public_task_view or self.public_task
        self.runtime_summary_view = runtime_summary_view or self.runtime_summary
        self.notification_public_status_view = (
            notification_public_status_view or self.notification_public_status
        )
        self.public_logs_view = public_logs_view or self.public_logs
        self.phone_binding_metrics_getter = phone_binding_metrics_getter

    def _mask_secret(self, value: Any) -> str:
        return self.secret_mask if self.clean(value) else ""

    def masked_local_config(self, data: Any) -> dict[str, Any]:
        value = json.loads(json.dumps(data if isinstance(data, dict) else {}))
        value.pop("nvtoken", None)
        value.pop("nvtoken_upload", None)
        value.pop("pixel_upload_enabled", None)
        sub2api = dict(value.get("sub2api") or {})
        nv_import = dict(value.get("nv_import") or {})
        email_notification = dict(value.get("email_notification") or {})
        online_mailbox = dict(value.get("online_mailbox") or {})
        sms_pools = self.sms_provider_pools_from_config(value)
        sms_keys = self.sms_runtime.legacy_sms_provider_keys(
            sms_pools,
            value.get("sms_provider") or "smsbower",
        )
        value["sms_provider_pools"] = [
            {
                **pool,
                "api_keys": [self.secret_mask for _key in pool.get("api_keys") or []],
            }
            for pool in sms_pools
        ]
        value["sms_api_keys"] = [self.secret_mask for _key in sms_keys]
        value.pop("sms_api_key", None)
        if "gptmail_api_key" in value:
            value["gptmail_api_key"] = self._mask_secret(value.get("gptmail_api_key"))
        if "proxy" in value:
            value["proxy"] = self._mask_secret(value.get("proxy"))
        if "password" in value:
            value["password"] = self._mask_secret(value.get("password"))
        if sub2api:
            sub2api["password"] = self._mask_secret(sub2api.get("password"))
            value["sub2api"] = sub2api
        if nv_import:
            nv_import["api_key"] = self._mask_secret(nv_import.get("api_key"))
            value["nv_import"] = nv_import
        if email_notification:
            email_notification["password"] = self._mask_secret(
                email_notification.get("password")
            )
            value["email_notification"] = email_notification
        if online_mailbox:
            online_mailbox["api_token"] = self._mask_secret(online_mailbox.get("api_token"))
            value["online_mailbox"] = online_mailbox
        return value

    def public_task(self, task: Any) -> dict[str, Any]:
        if not isinstance(task, dict):
            return {}
        source_row = str(task.get("source_row") or "")
        try:
            secrets = self.mailbox_admin.MailboxAdminService._row_secrets(source_row)
        except Exception:
            secrets = (source_row,) if source_row else ()

        def safe_text(value: Any) -> str:
            redacted = self.mailbox_admin.redact_mailbox_credentials(value, secrets)
            return self.error_observability.sanitize_failure_detail(
                self.sms_provider_registry_getter().safe_error(redacted),
                secrets=secrets,
            )

        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        raw_failure = task.get("failure")
        if not isinstance(raw_failure, dict):
            raw_failure = result.get("failure")
        failure = self.error_observability.public_failure(raw_failure)
        task_status = str(task.get("status") or "").strip().lower()
        if isinstance(failure, dict) and failure.get("node_code") == "oauth_create_node":
            reclassified = self.error_observability.classify_failure(
                result,
                task.get("technical_error")
                or task.get("error")
                or task.get("reason")
                or failure.get("technical_summary")
                or "",
                task.get("progress"),
                status=task_status,
                secrets=secrets,
            )
            if reclassified.get("node_code") != "oauth_create_node":
                failure = reclassified
        failure_statuses = set(
            self.task_progress_runtime.TERMINAL_TASK_STATUSES
        ).difference({"success", "stopped", "stopped_before_start"})
        if failure is None and task_status in failure_statuses:
            failure = self.error_observability.classify_failure(
                result,
                safe_text(
                    task.get("technical_error")
                    or task.get("error")
                    or task.get("reason")
                    or ""
                ),
                task.get("progress"),
                status=task_status,
                secrets=secrets,
            )
        if failure is not None:
            failure["public_message"] = safe_text(failure.get("public_message"))
            failure["technical_summary"] = safe_text(failure.get("technical_summary"))
        safe_result = {
            key: copy.deepcopy(result[key])
            for key in (
                "sms_cost_usd",
                "sms_cost_cny",
                "sms_exchange_rate",
                "sms_exchange_date",
                "timing",
                "run_mode",
                "phone_risk_retry",
                "phone_risk_label",
                "phone_risk_reason_code",
            )
            if key in result
        }
        progress = task.get("progress") if isinstance(task.get("progress"), dict) else None
        safe_progress = None
        if progress is not None:
            safe_progress = {
                key: copy.deepcopy(progress[key])
                for key in ("code", "label", "group", "entered_at", "finished_at", "timing")
                if key in progress
            }
        public = {
            key: copy.deepcopy(task[key])
            for key in (
                "task_id",
                "ordinal",
                "status",
                "created_at",
                "updated_at",
                "batch_id",
                "batch_started_at",
                "run_mode",
            )
            if key in task
        }
        public_email = self.mailbox_admin.public_task_account(task, source_row)
        if public_email:
            public["email"] = public_email
            public["account"] = public_email
        mailbox_url_from_row = getattr(self.mailbox_admin, "mailbox_url_from_row", None)
        if callable(mailbox_url_from_row):
            try:
                public["has_mailbox_url"] = bool(mailbox_url_from_row(source_row))
            except Exception:
                public["has_mailbox_url"] = False
        if failure is not None:
            public["failure"] = failure
            public["error"] = failure["public_message"]
        elif task.get("error"):
            value = str(task.get("error") or "").strip().lower()
            if value not in self.historical_success_reasons:
                public["error"] = safe_text(task.get("error"))
        if task.get("reason"):
            value = str(task.get("reason") or "").strip().lower()
            if value not in self.historical_success_reasons:
                public["reason"] = safe_text(task.get("reason"))
        if safe_result:
            public["result"] = safe_result
        if safe_progress is not None:
            public["progress"] = safe_progress
        return public

    def runtime_summary(self, tasks: Any) -> dict[str, Any]:
        rows = [task for task in tasks if isinstance(task, dict)]
        context = self.notification_context_for()
        value = context if isinstance(context, dict) else {}
        batch_id = str(value.get("batch_id") or "")
        if batch_id:
            rows = [task for task in rows if str(task.get("batch_id") or "") == batch_id]
        terminal = set(self.task_progress_runtime.TERMINAL_TASK_STATUSES)
        success = sum(
            1 for task in rows if str(task.get("status") or "").lower() == "success"
        )
        stopped = sum(
            1
            for task in rows
            if str(task.get("status") or "").lower() in {"stopped", "stopped_before_start"}
        )
        active = sum(
            1
            for task in rows
            if str(task.get("status") or "").lower() not in terminal
        )
        failed = max(0, len(rows) - success - stopped - active)
        cost_usd = 0.0
        cost_cny = 0.0
        last_activity_at = 0
        for task in rows:
            result = task.get("result") if isinstance(task.get("result"), dict) else {}
            try:
                cost_usd += float(result.get("sms_cost_usd") or 0)
                cost_cny += float(result.get("sms_cost_cny") or 0)
            except (TypeError, ValueError):
                pass
            for candidate in (task.get("updated_at"), task.get("created_at")):
                try:
                    last_activity_at = max(last_activity_at, int(candidate or 0))
                except (TypeError, ValueError):
                    pass
        return {
            "run_id": value.get("run_id") or "",
            "batch_id": batch_id,
            "batch_started_at": int(value.get("batch_started_at") or 0) or None,
            "target": int(value.get("target") or len(rows)),
            "total": len(rows),
            "active": active,
            "success": success,
            "failed": failed,
            "stopped": stopped,
            "started_at": int(value.get("started_at") or 0) or None,
            "last_activity_at": last_activity_at
            or int(value.get("last_activity_at") or 0)
            or None,
            "finished_at": int(value.get("finished_at") or 0) or None,
            "sms_cost_usd": round(cost_usd, 6),
            "sms_cost_cny": round(cost_cny, 4),
        }

    def mailbox_pool_summary(self) -> dict[str, Any]:
        try:
            result = self.mailbox_admin.list_mailboxes()
        except Exception:
            return {}
        counts = result.get("counts") if isinstance(result, dict) else {}
        if not isinstance(counts, dict):
            return {}
        return {
            key: copy.deepcopy(counts[key])
            for key in ("total", "available", "running", "success", "failed", "draft")
            if key in counts
        }

    def notification_public_status(self) -> dict[str, Any]:
        context = self.notification_context_for()
        if not isinstance(context, dict):
            return {}
        try:
            status = context["service"].public_status()
        except Exception:
            return {}
        result = {
            "event": str(status.get("event") or ""),
            "status": str(status.get("status") or ""),
            "timestamp": int(status.get("timestamp") or 0),
            "recipient_count": int(status.get("recipient_count") or 0),
        }
        if result["status"] == "failed":
            result["error"] = "SMTP 发送失败或通知队列已满"
        return result

    def public_logs(self, logs: Any, tasks: Any) -> Any:
        if not isinstance(logs, list):
            return logs
        local = self.read_local_config()
        sub2api = dict(local.get("sub2api") or {})
        nv_import = dict(local.get("nv_import") or {})
        notification = dict(local.get("email_notification") or {})
        online_mailbox = dict(local.get("online_mailbox") or {})
        secrets = [
            *self.sms_keys_from_config(local),
            sub2api.get("password"),
            nv_import.get("api_key"),
            notification.get("password"),
            online_mailbox.get("api_token"),
            *self.mailbox_admin.url_credential_secrets(local.get("proxy")),
        ]
        task_failures = {}
        terminal_node_failures = set()
        terminal_statuses = set(
            self.task_progress_runtime.TERMINAL_TASK_STATUSES
        ).difference({"success", "stopped", "stopped_before_start"})
        for task in tasks:
            source_row = str(task.get("source_row") or "") if isinstance(task, dict) else ""
            if source_row:
                try:
                    secrets.extend(self.mailbox_admin.MailboxAdminService._row_secrets(source_row))
                except Exception:
                    secrets.append(source_row)
            if not isinstance(task, dict):
                continue
            task_id = str(task.get("task_id") or "").strip()
            result = task.get("result") if isinstance(task.get("result"), dict) else {}
            structured_failure = self.error_observability.public_failure(
                task.get("failure")
                if isinstance(task.get("failure"), dict)
                else result.get("failure")
            )
            status = str(task.get("status") or "").strip().lower()
            if (
                isinstance(structured_failure, dict)
                and structured_failure.get("node_code") == "oauth_create_node"
            ):
                reclassified = self.error_observability.classify_failure(
                    result,
                    task.get("technical_error")
                    or task.get("error")
                    or task.get("reason")
                    or structured_failure.get("technical_summary")
                    or "",
                    task.get("progress"),
                    status=status,
                )
                if reclassified.get("node_code") != "oauth_create_node":
                    structured_failure = reclassified
            if (
                task_id
                and status in terminal_statuses
                and isinstance(structured_failure, dict)
                and structured_failure.get("node_code") == "oauth_create_node"
            ):
                terminal_node_failures.add(task_id)
            failure = structured_failure
            if failure is None:
                failure = self.known_task_failure(task_id)
            if task_id and failure is not None:
                task_failures[task_id] = failure
        public = []
        for log in logs:
            row = dict(log) if isinstance(log, dict) else {"message": str(log or "")}
            for key in ("message", "text"):
                if key not in row:
                    continue
                raw_message = str(row.get(key) or "")[: self.public_log_input_limit]
                row[key] = self.error_observability.sanitize_failure_detail(
                    self.sms_provider_registry_getter().safe_error(
                        self.mailbox_admin.redact_mailbox_credentials(raw_message, secrets)
                    ),
                    secrets=secrets,
                    limit=800,
                )
                message = str(row[key] or "")
                node_retry = self.error_observability.is_node_retry_log(message)
                task_match = self.task_id_log_re.search(message)
                message_task_id = task_match.group(1) if task_match else ""
                known_failure = self.known_task_failure(message_task_id)
                known_terminal_node = bool(
                    isinstance(known_failure, dict)
                    and known_failure.get("node_code") == "oauth_create_node"
                )
                if (
                    not node_retry
                    and bool(message_task_id)
                    and message_task_id not in terminal_node_failures
                    and not known_terminal_node
                    and self.error_observability.is_retryable_node_failure(message)
                ):
                    row[key] = self.error_observability.format_node_retry_log(
                        message_task_id,
                        message,
                    )
                    row["level"] = "warn"
                    message = str(row[key] or "")
                    node_retry = True
                if node_retry:
                    row["level"] = "warn"
                explicit_node = bool(
                    re.search(r"\[[^\]]+/[a-z0-9_]+\]", message, re.IGNORECASE)
                )
                level = str(row.get("level") or row.get("type") or "").strip().lower()
                if not node_retry and not explicit_node and (
                    level in {"error", "danger"} or "失败" in message
                ):
                    for task_id, failure in task_failures.items():
                        if task_id in message:
                            row[key] = self.error_observability.format_failure_log(
                                task_id,
                                failure,
                            )
                            break
            public.append(row)
        return public

    def masked_state(self, data: Any) -> dict[str, Any]:
        snapshot = json.loads(json.dumps(data if isinstance(data, dict) else {}))
        settings = snapshot.get("settings")
        if isinstance(settings, dict):
            snapshot["settings"] = self.masked_local_config_view(
                {**settings, **self.read_local_config()}
            )
        provider_registry = self.sms_provider_registry_getter()
        statuses = provider_registry.public_statuses()
        alerts = self.sms_alerts_getter().snapshot()
        snapshot["sms_key_statuses"] = statuses
        snapshot["sms_alerts"] = alerts
        guard = (
            self.sms_optimization_guard_getter()
            if callable(self.sms_optimization_guard_getter)
            else None
        )
        guard_snapshot = None
        snapshot_fn = getattr(guard, "snapshot", None)
        if callable(snapshot_fn):
            try:
                candidate = snapshot_fn()
                if isinstance(candidate, dict):
                    guard_snapshot = copy.deepcopy(candidate)
            except Exception:
                pass
        if guard_snapshot is not None:
            snapshot["sms_quality_optimization"] = guard_snapshot
        runtime = snapshot.get("runtime")
        if isinstance(runtime, dict):
            runtime["sms_key_statuses"] = statuses
            runtime["sms_alerts"] = alerts
            if guard_snapshot is not None:
                runtime["sms_quality_optimization"] = guard_snapshot
            runtime["sms_safe_stop"] = provider_registry.is_exhausted()
            self.task_progress_getter().decorate_runtime(runtime)
            concurrency = runtime.get("concurrency")
            if not isinstance(concurrency, dict):
                concurrency = {}
                runtime["concurrency"] = concurrency
            task_capacity = concurrency.get("task")
            admission = self.current_task_admission_getter()
            if admission is not None:
                try:
                    concurrency["task"] = admission.snapshot()
                    task_capacity = concurrency["task"]
                except Exception:
                    pass
            if isinstance(task_capacity, dict):
                task_capacity["waiting"] = sum(
                    1
                    for task in runtime.get("tasks") or []
                    if isinstance(task, dict)
                    and str(task.get("status") or "").strip().lower() == "queued"
                )
                concurrency["core"] = {
                    "baseline_concurrency": task_capacity.get(
                        "base",
                        task_capacity.get("limit"),
                    ),
                    "effective_limit": task_capacity.get("limit"),
                    "active_count": task_capacity.get("active", 0),
                    "waiting_count": task_capacity.get("waiting", 0),
                }
            inflight_getter = self.inflight_gate_getter
            if callable(inflight_getter):
                try:
                    inflight = inflight_getter()
                    inflight_snapshot = getattr(inflight, "snapshot", None)
                    if callable(inflight_snapshot):
                        inflight_state = copy.deepcopy(inflight_snapshot())
                        if isinstance(inflight_state, dict):
                            # Keep the gate's compatibility keys while exposing
                            # the dashboard contract with explicit meanings.
                            inflight_state.update(
                                configured_limit=inflight_state.get(
                                    "requested_limit",
                                    inflight_state.get("effective"),
                                ),
                                baseline_concurrency=inflight_state.get(
                                    "baseline_concurrency",
                                    inflight_state.get("configured"),
                                ),
                                task_inflight_limit=inflight_state.get(
                                    "requested_limit",
                                    inflight_state.get("effective"),
                                ),
                                effective_limit=inflight_state.get("effective"),
                                active_count=inflight_state.get("active", 0),
                                waiting_count=inflight_state.get("waiting", 0),
                                fallback_reason=(
                                    inflight_state.get("reason")
                                    if inflight_state.get("rolled_back")
                                    else ""
                                ),
                            )
                        concurrency["inflight"] = inflight_state
                except Exception:
                    pass
            local_config = self.read_local_config()
            concurrency["protocol"] = self.protocol_gate_getter().snapshot(
                local_config.get("proxy")
            )
            if callable(self.openai_connectivity_getter):
                try:
                    connectivity_runtime = self.openai_connectivity_getter()
                    connectivity_snapshot = getattr(connectivity_runtime, "snapshot", None)
                    candidate = (
                        connectivity_snapshot()
                        if callable(connectivity_snapshot)
                        else connectivity_runtime
                    )
                    if isinstance(candidate, dict):
                        connectivity = runtime.get("connectivity")
                        if not isinstance(connectivity, dict):
                            connectivity = {}
                            runtime["connectivity"] = connectivity
                        connectivity["openai_auth"] = _public_openai_connectivity(
                            candidate
                        )
                except Exception:
                    pass
            concurrency["phone"] = self.sms_phone_gate_getter().status()
            if callable(self.phone_binding_metrics_getter):
                try:
                    metrics_source = self.phone_binding_metrics_getter()
                    metrics_fn = getattr(metrics_source, "snapshot", None)
                    raw_metrics = metrics_fn() if callable(metrics_fn) else metrics_source
                    allowed = {
                        "page_prepare_attempted",
                        "page_prepare_succeeded",
                        "page_prepare_skipped",
                        "page_prepare_failed",
                        "channel_fallback_attempted",
                        "channel_fallback_succeeded",
                        "channel_fallback_failed",
                    }
                    metrics = {
                        key: max(0, int(raw_metrics.get(key) or 0))
                        for key in allowed
                        if isinstance(raw_metrics, dict)
                    }
                    raw_enabled = local_config.get("phone_binding_compatibility")
                    enabled = not (
                        raw_enabled is False
                        or raw_enabled == 0
                        or str(raw_enabled or "").strip().lower()
                        in {"false", "off", "no", "disabled", "0"}
                    )
                    runtime["phone_binding_compatibility"] = {
                        "enabled": enabled,
                        "metrics": metrics,
                    }
                except Exception:
                    pass
            resources: dict[str, Any] = {}
            if callable(self.process_resource_snapshot_getter):
                try:
                    observed = self.process_resource_snapshot_getter()
                    public = getattr(observed, "public", None)
                    candidate = public() if callable(public) else observed
                    if isinstance(candidate, dict):
                        resources.update(copy.deepcopy(candidate))
                except Exception:
                    pass
            if callable(self.transport_registry_getter):
                try:
                    registry = self.transport_registry_getter()
                    candidate = registry.snapshot() if registry is not None else {}
                    if isinstance(candidate, dict):
                        resources.update(copy.deepcopy(candidate))
                except Exception:
                    pass
            if resources:
                runtime["resources"] = resources
            mailbox_pool = self.mailbox_pool_summary()
            if mailbox_pool:
                existing_pool = runtime.get("pool")
                pool = existing_pool if isinstance(existing_pool, dict) else {}
                runtime["pool"] = {**copy.deepcopy(pool), **mailbox_pool}
            raw_tasks = runtime.get("tasks") if isinstance(runtime.get("tasks"), list) else []
            runtime["tasks"] = [self.public_task_view(task) for task in raw_tasks]
            runtime["summary"] = self.runtime_summary_view(runtime["tasks"])
            runtime["notification"] = self.notification_public_status_view()
            if isinstance(runtime.get("logs"), list):
                runtime["logs"] = self.public_logs_view(runtime.get("logs"), raw_tasks)
            if isinstance(snapshot.get("logs"), list):
                snapshot["logs"] = self.public_logs_view(snapshot.get("logs"), raw_tasks)
        return snapshot
