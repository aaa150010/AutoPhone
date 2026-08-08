"""Read-only mailbox URL and run-batch route handlers."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
from typing import Any


class RuntimeInfoRouteController:
    def __init__(
        self,
        *,
        module: Any,
        context: Any,
        mailbox_admin: Any,
        importer: Any,
        logs: Any,
    ) -> None:
        self.module = module
        self.context = context
        self.mailbox_admin = mailbox_admin
        self.importer = importer
        self.logs = logs

    def mailbox_url_test(self):
        module = self.module
        factory = self.context.mailbox_url_test_factory
        if factory is None:
            return module.jsonify(ok=False, error="URL 取件测试尚未启用"), 503
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            local = self.context.read_local_config()
            scope = local.get("proxy_scope")
            scope = scope if isinstance(scope, Mapping) else {}
            proxy = str(local.get("proxy") or "") if bool(scope.get("email")) else ""
            result = factory().test(
                data.get("value") or data.get("url") or "",
                timeout_seconds=60,
                interval_seconds=5,
                resend_after_seconds=15,
                proxy=proxy,
            )
            status = 400 if result.get("code") == "mailbox_url_invalid" else 200
            return module.jsonify(result), status
        except Exception:
            self.logs.add(
                "URL 取件测试失败 [测试取件地址/mailbox_url_test]：未返回可用诊断",
                "error",
            )
            return module.jsonify(
                ok=False,
                code="mailbox_url_test_failed",
                error="URL 取件测试失败：未返回可用诊断",
            ), 500

    def mailbox_url(self):
        module = self.module
        try:
            data = module.request.get_json(silent=True) or {}
            if not isinstance(data, dict):
                return module.jsonify(ok=False, error="请求必须是 JSON 对象"), 400
            result = self.mailbox_admin.reveal_mailbox_url(
                data.get("row_id"),
                data.get("line_no"),
            )
            if result.get("ok"):
                return module.jsonify(result)
            status = 409 if result.get("code") == "mailbox_row_stale" else 400
            return module.jsonify(result), status
        except Exception:
            return module.jsonify(ok=False, error="读取取件 URL 失败"), 500

    def runtime_task_mailbox_url(self):
        module = self.module
        data = module.request.get_json(silent=True) or {}
        if not isinstance(data, dict) or set(data) != {"task_id"}:
            return module.jsonify(ok=False, error="请求只接受 task_id"), 400
        task_id = str(data.get("task_id") or "").strip()
        if not task_id or len(task_id) > 128:
            return module.jsonify(ok=False, error="任务标识无效"), 400
        try:
            importer_lock = getattr(self.importer, "lock", None)
            if importer_lock is None:
                task = dict((getattr(self.importer, "tasks", {}) or {}).get(task_id) or {})
            else:
                with importer_lock:
                    task = dict((getattr(self.importer, "tasks", {}) or {}).get(task_id) or {})
            if not task:
                return module.jsonify(
                    ok=False,
                    code="runtime_task_not_found",
                    error="任务不存在",
                ), 404
            source_row = str(task.get("source_row") or "")
            if not source_row:
                return module.jsonify(
                    ok=False,
                    code="mailbox_row_stale",
                    error="任务绑定的邮箱行已失效",
                ), 409
            expected_row_id = hashlib.sha256(source_row.encode("utf-8")).hexdigest()
            listed = self.mailbox_admin.list_mailboxes()
            rows = listed.get("rows") if isinstance(listed, Mapping) else []
            matches = [
                row
                for row in rows or []
                if isinstance(row, Mapping)
                and hmac.compare_digest(
                    str(row.get("row_id") or "").strip().lower(),
                    expected_row_id,
                )
            ]
            if len(matches) != 1:
                return module.jsonify(
                    ok=False,
                    code="mailbox_row_stale",
                    error="任务绑定的邮箱行已变化，请刷新后重试",
                ), 409
            result = self.mailbox_admin.reveal_mailbox_url(
                expected_row_id,
                matches[0].get("line_no"),
            )
            if result.get("ok"):
                return module.jsonify(ok=True, mailbox_url=result.get("mailbox_url"))
            status = 409 if result.get("code") == "mailbox_row_stale" else 400
            return module.jsonify(dict(result)), status
        except Exception:
            self.logs.add(
                "读取任务取件 URL 失败 [邮箱取件 URL/mailbox_url_reveal]",
                "error",
            )
            return module.jsonify(ok=False, error="读取任务取件 URL 失败"), 500

    def run_batches(self):
        module = self.module
        manifest = self.context.run_batch_manifest
        if manifest is None:
            return module.jsonify(ok=True, items=[], total=0)
        try:
            limit = min(max(1, _safe_int(module.request.args.get("limit"), 100)), 500)
            items = manifest.records(limit=limit, include_members=False)
            return module.jsonify(ok=True, items=items, total=len(items))
        except Exception:
            self.logs.add(
                "运行批次清单查询失败 [运行批次对账/run_batch_manifest]",
                "error",
            )
            return module.jsonify(ok=False, error="运行批次清单查询失败"), 500

    def run_batch(self, batch_id: str):
        module = self.module
        manifest = self.context.run_batch_manifest
        if manifest is None:
            return module.jsonify(ok=False, error="运行批次清单尚未启用"), 503
        try:
            return module.jsonify(
                ok=True,
                batch=manifest.get(batch_id, include_members=True),
            )
        except KeyError:
            return module.jsonify(ok=False, error="运行批次不存在"), 404
        except Exception:
            self.logs.add(
                "运行批次详情查询失败 [运行批次对账/run_batch_manifest]",
                "error",
            )
            return module.jsonify(ok=False, error="运行批次详情查询失败"), 500


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


__all__ = ["RuntimeInfoRouteController"]
